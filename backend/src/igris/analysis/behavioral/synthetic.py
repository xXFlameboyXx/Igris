"""Deterministic synthetic behavior analyzer for Phase 7.0 testing.

This analyzer generates synthetic behavior telemetry WITHOUT reading,
executing, or otherwise processing the uploaded sample binary.  Every
result is explicitly marked ``analysis_mode = "synthetic"`` and carries
a ``synthetic_scenario`` provenance tag.

The analyzer does NOT infer malicious behavior from file format.
Behavior is driven entirely by the selected scenario.

Security guarantees:
- No subprocess execution.
- No shell execution.
- No sample byte access.
- No network calls.
- No external sandbox communication.
"""

import hashlib
from collections.abc import Callable

from igris.schemas.behavior_analysis import (
    BehaviorAnalysisResult,
    BehaviorAnalysisStatus,
    BehaviorEvidence,
    BehaviorEvidenceType,
    DroppedFile,
    FileEvent,
    MutexEvent,
    NetworkEvent,
    ProcessEvent,
    RegistryEvent,
    SandboxMetadata,
    SandboxResourceLimits,
    SyntheticScenario,
)
from igris.schemas.static_analysis import EvidenceSeverity

VERSION = "synthetic-behavior-analyzer/v1"

# SHA-256 of the literal string "igris-synthetic-dropped-file" — deterministic.
_SYNTHETIC_DROPPED_HASH = hashlib.sha256(b"igris-synthetic-dropped-file").hexdigest()

_SCENARIOS = list(SyntheticScenario)

_SYNTHETIC_LIMITATIONS = [
    "This is synthetic behavior data generated for testing. No actual sample execution occurred.",
    "Synthetic scenarios do not represent real observations of the uploaded sample.",
    "A real sandbox environment is required for genuine dynamic analysis.",
]


def select_scenario(sample_id: str) -> SyntheticScenario:
    """Deterministically select a scenario from the sample ID hash."""
    digest = hashlib.sha256(sample_id.encode()).digest()
    return _SCENARIOS[digest[0] % len(_SCENARIOS)]


class SyntheticBehaviorAnalyzer:
    """Generate deterministic synthetic behavior telemetry.

    This analyzer does NOT read or execute uploaded sample bytes.
    It produces scenario-driven synthetic events suitable for
    exercising the Phase 7 service layer and API endpoints.

    Every result is explicitly marked as synthetic via:
    - ``sandbox_metadata.analysis_mode = "synthetic"``
    - ``sandbox_metadata.synthetic_scenario = "<scenario>"``
    """

    def analyze(
        self,
        *,
        sample_id: str,
        scenario: SyntheticScenario | None = None,
        timeout_seconds: int = 120,
    ) -> BehaviorAnalysisResult:
        """Generate synthetic behavior analysis for a scenario.

        Args:
            sample_id: Canonical sample identifier (used for deterministic
                scenario selection when ``scenario`` is None).
            scenario: Explicit scenario override.  When None the scenario
                is derived deterministically from ``sample_id``.
            timeout_seconds: Architectural timeout setting (unused in synthetic
                mode, recorded in metadata for consistency).

        Returns:
            A fully populated BehaviorAnalysisResult marked as synthetic.
        """
        selected = scenario or select_scenario(sample_id)
        builder = _BUILDERS[selected]
        (
            processes,
            file_events,
            registry_events,
            network_events,
            dropped_files,
            mutexes,
            evidence,
        ) = builder()
        return BehaviorAnalysisResult(
            sample_id=sample_id,
            status=BehaviorAnalysisStatus.COMPLETED,
            sandbox_metadata=SandboxMetadata(
                analysis_mode="synthetic",
                analyzer_version=VERSION,
                analysis_duration_seconds=0.0,
                network_policy="deny_all",
                exit_reason="completed",
                os_platform="synthetic",
                os_version="synthetic",
                artifacts_collected=len(dropped_files),
                resource_limits=SandboxResourceLimits(timeout_seconds=timeout_seconds),
                synthetic_scenario=selected.value,
            ),
            processes=processes,
            file_events=file_events,
            registry_events=registry_events,
            network_events=network_events,
            dropped_files=dropped_files,
            mutexes=mutexes,
            evidence=evidence,
            limitations=list(_SYNTHETIC_LIMITATIONS),
        )


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------
# Each builder returns a 7-tuple:
#   (processes, file_events, registry_events, network_events,
#    dropped_files, mutexes, evidence)


def _make_evidence(
    scenario: str,
    evidence_type: BehaviorEvidenceType,
    seq: int,
    *,
    severity: EvidenceSeverity,
    confidence: float,
    description: str,
    related_process: str | None = None,
) -> BehaviorEvidence:
    return BehaviorEvidence(
        evidence_id=f"behavior-synth-{scenario}-{evidence_type.value}-{seq}",
        type=evidence_type,
        source="synthetic_behavior_analysis",
        severity=severity,
        confidence=confidence,
        description=description,
        related_process=related_process,
    )


_BuilderResult = tuple[
    list[ProcessEvent],
    list[FileEvent],
    list[RegistryEvent],
    list[NetworkEvent],
    list[DroppedFile],
    list[MutexEvent],
    list[BehaviorEvidence],
]


def _build_benign() -> _BuilderResult:
    processes = [
        ProcessEvent(timestamp_ms=0, pid=1000, ppid=500, process_name="sample.exe", is_sample=True),
    ]
    file_events = [
        FileEvent(
            timestamp_ms=50,
            pid=1000,
            operation="read",
            path="/synthetic/data/config.ini",
        ),
    ]
    return processes, file_events, [], [], [], [], []


def _build_process_activity() -> _BuilderResult:
    processes = [
        ProcessEvent(timestamp_ms=0, pid=1000, ppid=500, process_name="sample.exe", is_sample=True),
        ProcessEvent(
            timestamp_ms=100,
            pid=1001,
            ppid=1000,
            process_name="child_process.exe",
            command_line="/c echo synthetic test",
        ),
        ProcessEvent(timestamp_ms=200, pid=1002, ppid=1001, process_name="grandchild.exe"),
    ]
    evidence = [
        _make_evidence(
            "process_activity",
            BehaviorEvidenceType.PROCESS_CREATION,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: child process spawned by sample process.",
            related_process="1000",
        ),
    ]
    return processes, [], [], [], [], [], evidence


def _build_file_activity() -> _BuilderResult:
    processes = [
        ProcessEvent(timestamp_ms=0, pid=1000, ppid=500, process_name="sample.exe", is_sample=True),
    ]
    file_events = [
        FileEvent(
            timestamp_ms=50,
            pid=1000,
            operation="create",
            path="/synthetic/data/output.dat",
            size_bytes=256,
        ),
        FileEvent(
            timestamp_ms=100,
            pid=1000,
            operation="write",
            path="/synthetic/data/payload.bin",
            size_bytes=4096,
        ),
        FileEvent(
            timestamp_ms=150,
            pid=1000,
            operation="delete",
            path="/synthetic/data/temp.log",
        ),
    ]
    dropped_files = [
        DroppedFile(
            artifact_id="artifact-synth-file-activity-payload",
            path="/synthetic/data/payload.bin",
            sha256=_SYNTHETIC_DROPPED_HASH,
            size_bytes=4096,
            file_type="application/octet-stream",
            is_executable=True,
            source_process="1000",
            retained=False,
            retention_reason="Synthetic metadata only; no artifact bytes exist.",
        ),
    ]
    evidence = [
        _make_evidence(
            "file_activity",
            BehaviorEvidenceType.FILE_WRITE,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: file written to temporary directory.",
            related_process="1000",
        ),
        _make_evidence(
            "file_activity",
            BehaviorEvidenceType.DROPPED_EXECUTABLE,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: executable file dropped to temporary directory.",
            related_process="1000",
        ),
        _make_evidence(
            "file_activity",
            BehaviorEvidenceType.FILE_DELETE,
            0,
            severity=EvidenceSeverity.INFO,
            confidence=0.3,
            description="Synthetic: temporary file deleted after creation.",
            related_process="1000",
        ),
    ]
    return processes, file_events, [], [], dropped_files, [], evidence


def _build_network_activity() -> _BuilderResult:
    processes = [
        ProcessEvent(timestamp_ms=0, pid=1000, ppid=500, process_name="sample.exe", is_sample=True),
    ]
    # RFC 5737 TEST-NET-2 (198.51.100.0/24) and RFC 2606 (.test / .example)
    network_events = [
        NetworkEvent(
            timestamp_ms=50,
            pid=1000,
            protocol="dns",
            direction="outbound",
            domain="synthetic.example.test",
        ),
        NetworkEvent(
            timestamp_ms=100,
            pid=1000,
            protocol="tcp",
            direction="outbound",
            destination_ip="198.51.100.1",
            destination_port=443,
        ),
        NetworkEvent(
            timestamp_ms=150,
            pid=1000,
            protocol="http",
            direction="outbound",
            destination_ip="198.51.100.1",
            destination_port=80,
            domain="synthetic.example.test",
            url="http://synthetic.example.test/beacon",
        ),
    ]
    evidence = [
        _make_evidence(
            "network_activity",
            BehaviorEvidenceType.DNS_QUERY,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: DNS resolution attempted.",
            related_process="1000",
        ),
        _make_evidence(
            "network_activity",
            BehaviorEvidenceType.NETWORK_CONNECTION,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: outbound TCP connection attempted.",
            related_process="1000",
        ),
    ]
    return processes, [], [], network_events, [], [], evidence


def _build_persistence_activity() -> _BuilderResult:
    processes = [
        ProcessEvent(timestamp_ms=0, pid=1000, ppid=500, process_name="sample.exe", is_sample=True),
    ]
    registry_events = [
        RegistryEvent(
            timestamp_ms=50,
            pid=1000,
            operation="create_key",
            key_path=r"HKCU\Software\SyntheticTest",
        ),
        RegistryEvent(
            timestamp_ms=100,
            pid=1000,
            operation="set_value",
            key_path=r"HKCU\Software\SyntheticTest",
            value_name="RunOnStartup",
            value_data="sample.exe",
        ),
    ]
    mutexes = [
        MutexEvent(timestamp_ms=150, pid=1000, name="SyntheticMutex_IGRIS_TEST"),
    ]
    evidence = [
        _make_evidence(
            "persistence_activity",
            BehaviorEvidenceType.REGISTRY_MODIFICATION,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: registry key created for persistence.",
            related_process="1000",
        ),
        _make_evidence(
            "persistence_activity",
            BehaviorEvidenceType.MUTEX_CREATION,
            0,
            severity=EvidenceSeverity.INFO,
            confidence=0.3,
            description="Synthetic: mutex created.",
            related_process="1000",
        ),
    ]
    return processes, [], registry_events, [], [], mutexes, evidence


def _build_multi_stage_activity() -> _BuilderResult:
    processes = [
        ProcessEvent(timestamp_ms=0, pid=1000, ppid=500, process_name="sample.exe", is_sample=True),
        ProcessEvent(
            timestamp_ms=100,
            pid=1001,
            ppid=1000,
            process_name="stage2.exe",
        ),
    ]
    file_events = [
        FileEvent(
            timestamp_ms=200,
            pid=1000,
            operation="write",
            path="/synthetic/data/stage2.bin",
            size_bytes=2048,
        ),
    ]
    registry_events = [
        RegistryEvent(
            timestamp_ms=400,
            pid=1001,
            operation="set_value",
            key_path=r"HKCU\Software\SyntheticMultiStage",
            value_name="Payload",
            value_data="stage2.exe",
        ),
    ]
    network_events = [
        NetworkEvent(
            timestamp_ms=300,
            pid=1001,
            protocol="tcp",
            direction="outbound",
            destination_ip="198.51.100.2",
            destination_port=8080,
        ),
    ]
    evidence = [
        _make_evidence(
            "multi_stage_activity",
            BehaviorEvidenceType.PROCESS_CREATION,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: second-stage process launched.",
            related_process="1000",
        ),
        _make_evidence(
            "multi_stage_activity",
            BehaviorEvidenceType.FILE_WRITE,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: file written for multi-stage operation.",
            related_process="1000",
        ),
        _make_evidence(
            "multi_stage_activity",
            BehaviorEvidenceType.NETWORK_CONNECTION,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: outbound connection from second stage.",
            related_process="1001",
        ),
        _make_evidence(
            "multi_stage_activity",
            BehaviorEvidenceType.REGISTRY_MODIFICATION,
            0,
            severity=EvidenceSeverity.LOW,
            confidence=0.3,
            description="Synthetic: registry modified by second stage.",
            related_process="1001",
        ),
    ]
    return processes, file_events, registry_events, network_events, [], [], evidence


_BUILDERS: dict[SyntheticScenario, Callable[[], _BuilderResult]] = {
    SyntheticScenario.BENIGN: _build_benign,
    SyntheticScenario.PROCESS_ACTIVITY: _build_process_activity,
    SyntheticScenario.FILE_ACTIVITY: _build_file_activity,
    SyntheticScenario.NETWORK_ACTIVITY: _build_network_activity,
    SyntheticScenario.PERSISTENCE_ACTIVITY: _build_persistence_activity,
    SyntheticScenario.MULTI_STAGE_ACTIVITY: _build_multi_stage_activity,
}
