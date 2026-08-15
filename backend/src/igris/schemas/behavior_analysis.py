"""Normalized Phase 7 behavior-analysis schemas."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from igris.schemas.static_analysis import EvidenceSeverity


class BehaviorAnalysisStatus(StrEnum):
    """Behavior-analysis lifecycle state."""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"


class BehaviorEvidenceType(StrEnum):
    """Comprehensive behavior-evidence taxonomy.

    Extensible by adding new members. Existing values must not be renamed
    once downstream consumers depend on them.
    """

    PROCESS_CREATION = "PROCESS_CREATION"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    REGISTRY_MODIFICATION = "REGISTRY_MODIFICATION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    DNS_QUERY = "DNS_QUERY"
    DROPPED_EXECUTABLE = "DROPPED_EXECUTABLE"
    MUTEX_CREATION = "MUTEX_CREATION"
    SERVICE_CREATION = "SERVICE_CREATION"
    EVASION_ATTEMPT = "EVASION_ATTEMPT"


class SyntheticScenario(StrEnum):
    """Deterministic synthetic behavior scenarios for testing.

    Each scenario produces a fixed set of events and evidence records
    without reading or executing uploaded sample bytes.
    """

    BENIGN = "benign"
    PROCESS_ACTIVITY = "process_activity"
    FILE_ACTIVITY = "file_activity"
    NETWORK_ACTIVITY = "network_activity"
    PERSISTENCE_ACTIVITY = "persistence_activity"
    MULTI_STAGE_ACTIVITY = "multi_stage_activity"


class ProcessEvent(BaseModel):
    """Process creation or termination telemetry."""

    model_config = ConfigDict(extra="forbid")

    timestamp_ms: int
    pid: int
    ppid: int
    process_name: str
    command_line: str | None = None
    is_sample: bool = False


class FileEvent(BaseModel):
    """File operation telemetry."""

    model_config = ConfigDict(extra="forbid")

    timestamp_ms: int
    pid: int
    operation: Literal["create", "write", "read", "delete", "rename"]
    path: str
    size_bytes: int | None = None


class RegistryEvent(BaseModel):
    """Registry operation telemetry."""

    model_config = ConfigDict(extra="forbid")

    timestamp_ms: int
    pid: int
    operation: Literal["create_key", "set_value", "delete_key", "delete_value"]
    key_path: str
    value_name: str | None = None
    value_data: str | None = None


class NetworkEvent(BaseModel):
    """Network connection telemetry."""

    model_config = ConfigDict(extra="forbid")

    timestamp_ms: int
    pid: int
    protocol: Literal["tcp", "udp", "dns", "http", "https", "other"]
    direction: Literal["outbound", "inbound"]
    destination_ip: str | None = None
    destination_port: int | None = None
    domain: str | None = None
    url: str | None = None
    bytes_sent: int = 0
    bytes_received: int = 0


class DroppedFile(BaseModel):
    """File written by the sample during execution."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: str | None = None
    path: str
    sha256: str
    size_bytes: int
    file_type: str | None = None
    is_executable: bool = False
    source_process: str | None = None
    retained: bool = False
    retention_reason: str | None = None


class MutexEvent(BaseModel):
    """Mutex creation telemetry."""

    model_config = ConfigDict(extra="forbid")

    timestamp_ms: int
    pid: int
    name: str


class ArtifactRetentionPolicy(BaseModel):
    """Bounded artifact-retention policy used by behavior analysis."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["metadata_only", "bounded_artifacts"] = "metadata_only"
    max_artifacts: int = Field(default=16, ge=0, le=256)
    max_artifact_bytes: int = Field(default=10 * 1024 * 1024, ge=0)
    hash_algorithm: Literal["sha256"] = "sha256"
    provenance_required: bool = True


class SandboxResourceLimits(BaseModel):
    """Resource limits that a real sandbox controller must enforce."""

    model_config = ConfigDict(extra="forbid")

    timeout_seconds: int = Field(default=120, ge=1, le=600)
    cpu_count: int = Field(default=1, ge=1, le=16)
    memory_mb: int = Field(default=1024, ge=128, le=32768)
    disk_mb: int = Field(default=1024, ge=128, le=102400)
    process_count: int = Field(default=128, ge=1, le=10000)


class SandboxMetadata(BaseModel):
    """Provenance metadata for the analysis environment.

    A future real sandbox result is distinguishable from a synthetic result
    via the ``analysis_mode`` field and the absence of ``synthetic_scenario``.
    """

    model_config = ConfigDict(extra="forbid")

    analysis_mode: Literal["synthetic", "sandbox"]
    analyzer_version: str
    sandbox_image: str | None = None
    analysis_duration_seconds: float
    network_policy: Literal["deny_all", "simulated", "controlled_egress"]
    exit_reason: Literal["completed", "timeout", "crash", "error"]
    os_platform: str
    os_version: str
    artifacts_collected: int = 0
    artifact_retention_policy: ArtifactRetentionPolicy = Field(
        default_factory=ArtifactRetentionPolicy
    )
    resource_limits: SandboxResourceLimits = Field(default_factory=SandboxResourceLimits)
    synthetic_scenario: str | None = None


class BehaviorEvidence(BaseModel):
    """Evidence record derived from observed or synthetic behavior."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    type: BehaviorEvidenceType
    source: str
    severity: EvidenceSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    technical_details: dict[str, Any] = Field(default_factory=dict)
    related_process: str | None = None
    related_events: list[str] = Field(default_factory=list)


class BehaviorAnalysisResult(BaseModel):
    """Persisted Phase 7 behavior-analysis result."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    status: BehaviorAnalysisStatus
    schema_version: str = "behavior-analysis/v1"
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sandbox_metadata: SandboxMetadata
    processes: list[ProcessEvent]
    file_events: list[FileEvent]
    registry_events: list[RegistryEvent]
    network_events: list[NetworkEvent]
    dropped_files: list[DroppedFile]
    mutexes: list[MutexEvent] = Field(default_factory=list)
    evidence: list[BehaviorEvidence]
    limitations: list[str] = Field(default_factory=list)


class BehaviorAnalysisResponse(BaseModel):
    """API response for behavior analysis."""

    model_config = ConfigDict(extra="forbid")

    behavior_analysis: BehaviorAnalysisResult


class BehaviorEventsResponse(BaseModel):
    """API response for behavior event timeline."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    processes: list[ProcessEvent]
    file_events: list[FileEvent]
    registry_events: list[RegistryEvent]
    network_events: list[NetworkEvent]


class BehaviorEvidenceResponse(BaseModel):
    """API response for behavior-derived evidence."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    evidence: list[BehaviorEvidence]
