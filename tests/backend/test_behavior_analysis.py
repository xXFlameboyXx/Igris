"""Phase 7 behavior-analysis tests.

Verifies:
- Schema validation and rejection of unexpected fields.
- SyntheticBehaviorAnalyzer determinism, scenario correctness, and provenance.
- API POST/GET endpoints for behavior-analysis, behavior-events, behavior-evidence.
- Caching behaviour (second POST returns cached result).
- Error handling (missing sample, analysis not yet run).
- Backward compatibility (existing Samples without behavior_analysis deserialize).
- Security: no sample execution, no subprocess, no network.
"""

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from igris.analysis.behavioral.synthetic import SyntheticBehaviorAnalyzer, select_scenario
from igris.core.config import Settings
from igris.main import create_app
from igris.schemas.behavior_analysis import (
    ArtifactRetentionPolicy,
    BehaviorAnalysisResult,
    BehaviorEvidenceType,
    SandboxResourceLimits,
    SyntheticScenario,
)
from igris.schemas.file_intelligence import Sample


def make_client(tmp_path: Path) -> TestClient:
    app = create_app(
        Settings(
            environment="test",
            metadata_backend="memory",
            sample_storage_dir=str(tmp_path / "samples"),
            sample_temp_dir=str(tmp_path / "tmp"),
            detection_rules_path="config/rules/static_rules.json",
        )
    )
    return TestClient(app)


def upload(client: TestClient, content: bytes, filename: str = "sample.bin") -> str:
    response = client.post(
        "/api/v1/samples",
        files={"file": (filename, content, "application/octet-stream")},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["sample_id"])


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def test_behavior_analysis_result_rejects_extra_fields() -> None:
    """extra='forbid' must reject unknown fields."""
    from pydantic import ValidationError

    try:
        BehaviorAnalysisResult(
            sample_id="test",
            status="completed",
            sandbox_metadata={
                "analysis_mode": "synthetic",
                "analyzer_version": "test/v1",
                "analysis_duration_seconds": 0.0,
                "network_policy": "deny_all",
                "exit_reason": "completed",
                "os_platform": "synthetic",
                "os_version": "synthetic",
            },
            processes=[],
            file_events=[],
            registry_events=[],
            network_events=[],
            dropped_files=[],
            evidence=[],
            rogue_field="should fail",  # type: ignore[call-arg]
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("extra='forbid' should have rejected rogue_field")


def test_behavior_evidence_type_has_ten_members() -> None:
    """Verify the approved 10-type taxonomy is defined."""
    assert len(BehaviorEvidenceType) == 10
    expected = {
        "PROCESS_CREATION", "FILE_WRITE", "FILE_DELETE",
        "REGISTRY_MODIFICATION", "NETWORK_CONNECTION", "DNS_QUERY",
        "DROPPED_EXECUTABLE", "MUTEX_CREATION", "SERVICE_CREATION",
        "EVASION_ATTEMPT",
    }
    assert {e.value for e in BehaviorEvidenceType} == expected


# ---------------------------------------------------------------------------
# Synthetic analyzer unit tests
# ---------------------------------------------------------------------------


def test_select_scenario_is_deterministic() -> None:
    """The same sample_id must always produce the same scenario."""
    sid = "determinism-test-id-12345"
    first = select_scenario(sid)
    second = select_scenario(sid)
    assert first == second


def test_select_scenario_uses_sha256_of_sample_id() -> None:
    """Verify the documented selection algorithm."""
    sid = "known-sample-id"
    digest = hashlib.sha256(sid.encode()).digest()
    expected_index = digest[0] % len(list(SyntheticScenario))
    expected = list(SyntheticScenario)[expected_index]
    assert select_scenario(sid) == expected


def test_synthetic_analyzer_marks_results_as_synthetic() -> None:
    """Every result must have analysis_mode='synthetic' and a scenario tag."""
    analyzer = SyntheticBehaviorAnalyzer()
    for scenario in SyntheticScenario:
        result = analyzer.analyze(sample_id="test-id", scenario=scenario)
        assert result.sandbox_metadata.analysis_mode == "synthetic"
        assert result.sandbox_metadata.synthetic_scenario == scenario.value
        assert result.sandbox_metadata.network_policy == "deny_all"
        assert result.sandbox_metadata.exit_reason == "completed"
        assert result.sandbox_metadata.os_platform == "synthetic"
        assert result.status.value == "completed"
        assert result.schema_version == "behavior-analysis/v1"
        assert any("synthetic" in lim.lower() or "no actual" in lim.lower()
                    for lim in result.limitations)


def test_synthetic_analyzer_scenario_override() -> None:
    """Explicit scenario parameter must override hash-based selection."""
    analyzer = SyntheticBehaviorAnalyzer()
    result = analyzer.analyze(
        sample_id="any-id", scenario=SyntheticScenario.NETWORK_ACTIVITY
    )
    assert result.sandbox_metadata.synthetic_scenario == "network_activity"
    assert len(result.network_events) > 0


def test_synthetic_benign_scenario_has_no_evidence() -> None:
    """Benign scenario must generate events but no suspicious evidence."""
    analyzer = SyntheticBehaviorAnalyzer()
    result = analyzer.analyze(sample_id="benign-test", scenario=SyntheticScenario.BENIGN)
    assert result.evidence == []
    assert len(result.processes) >= 1
    assert result.processes[0].is_sample is True


def test_synthetic_process_activity_scenario() -> None:
    """Process activity scenario must produce process creation evidence."""
    analyzer = SyntheticBehaviorAnalyzer()
    result = analyzer.analyze(sample_id="test", scenario=SyntheticScenario.PROCESS_ACTIVITY)
    assert len(result.processes) >= 2
    evidence_types = {e.type for e in result.evidence}
    assert BehaviorEvidenceType.PROCESS_CREATION in evidence_types


def test_synthetic_file_activity_scenario() -> None:
    """File activity scenario must produce file events and dropped file evidence."""
    analyzer = SyntheticBehaviorAnalyzer()
    result = analyzer.analyze(sample_id="test", scenario=SyntheticScenario.FILE_ACTIVITY)
    assert len(result.file_events) >= 2
    assert len(result.dropped_files) >= 1
    evidence_types = {e.type for e in result.evidence}
    assert BehaviorEvidenceType.FILE_WRITE in evidence_types
    assert BehaviorEvidenceType.DROPPED_EXECUTABLE in evidence_types


def test_synthetic_network_activity_scenario() -> None:
    """Network activity must use safe RFC 5737/2606 addresses."""
    analyzer = SyntheticBehaviorAnalyzer()
    result = analyzer.analyze(sample_id="test", scenario=SyntheticScenario.NETWORK_ACTIVITY)
    assert len(result.network_events) >= 2
    evidence_types = {e.type for e in result.evidence}
    assert BehaviorEvidenceType.DNS_QUERY in evidence_types
    assert BehaviorEvidenceType.NETWORK_CONNECTION in evidence_types
    # Verify safe addresses (RFC 5737 TEST-NET-2 and RFC 2606)
    for event in result.network_events:
        if event.destination_ip:
            assert event.destination_ip.startswith("198.51.100.")
        if event.domain:
            assert event.domain.endswith(".test") or event.domain.endswith(".example")


def test_synthetic_persistence_activity_scenario() -> None:
    """Persistence scenario must produce registry and mutex events."""
    analyzer = SyntheticBehaviorAnalyzer()
    result = analyzer.analyze(sample_id="test", scenario=SyntheticScenario.PERSISTENCE_ACTIVITY)
    assert len(result.registry_events) >= 1
    assert len(result.mutexes) >= 1
    evidence_types = {e.type for e in result.evidence}
    assert BehaviorEvidenceType.REGISTRY_MODIFICATION in evidence_types
    assert BehaviorEvidenceType.MUTEX_CREATION in evidence_types


def test_synthetic_multi_stage_scenario() -> None:
    """Multi-stage scenario must produce events across multiple categories."""
    analyzer = SyntheticBehaviorAnalyzer()
    result = analyzer.analyze(sample_id="test", scenario=SyntheticScenario.MULTI_STAGE_ACTIVITY)
    assert len(result.processes) >= 2
    assert len(result.file_events) >= 1
    assert len(result.network_events) >= 1
    assert len(result.registry_events) >= 1
    evidence_types = {e.type for e in result.evidence}
    assert len(evidence_types) >= 3


def test_synthetic_analyzer_evidence_ids_are_deterministic() -> None:
    """Evidence IDs must be stable across invocations."""
    analyzer = SyntheticBehaviorAnalyzer()
    first = analyzer.analyze(sample_id="stable-id", scenario=SyntheticScenario.FILE_ACTIVITY)
    second = analyzer.analyze(sample_id="stable-id", scenario=SyntheticScenario.FILE_ACTIVITY)
    first_ids = [e.evidence_id for e in first.evidence]
    second_ids = [e.evidence_id for e in second.evidence]
    assert first_ids == second_ids


def test_synthetic_evidence_source_is_clearly_synthetic() -> None:
    """Evidence source field must identify synthetic origin."""
    analyzer = SyntheticBehaviorAnalyzer()
    result = analyzer.analyze(sample_id="test", scenario=SyntheticScenario.PROCESS_ACTIVITY)
    for ev in result.evidence:
        assert "synthetic" in ev.source


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


def test_behavior_analysis_requires_existing_sample(tmp_path: Path) -> None:
    """POST /behavior-analysis for a missing sample must return 404."""
    with make_client(tmp_path) as client:
        response = client.post("/api/v1/samples/nonexistent/behavior-analysis")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "sample_not_found"


def test_behavior_analysis_get_before_run_returns_404(tmp_path: Path) -> None:
    """GET /behavior-analysis before POST must return 404."""
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"hello world", "benign.txt")
        response = client.get(f"/api/v1/samples/{sample_id}/behavior-analysis")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "behavior_analysis_not_found"


def test_behavior_analysis_post_returns_synthetic_result(tmp_path: Path) -> None:
    """POST /behavior-analysis must return a complete synthetic result."""
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"test content", "test.bin")
        response = client.post(f"/api/v1/samples/{sample_id}/behavior-analysis")

    assert response.status_code == 200
    data = response.json()["behavior_analysis"]
    assert data["status"] == "completed"
    assert data["schema_version"] == "behavior-analysis/v1"
    assert data["sandbox_metadata"]["analysis_mode"] == "synthetic"
    assert data["sandbox_metadata"]["synthetic_scenario"] is not None
    assert data["sandbox_metadata"]["network_policy"] == "deny_all"
    assert data["sandbox_metadata"]["analyzer_version"] == "synthetic-behavior-analyzer/v1"
    assert data["sandbox_metadata"]["artifact_retention_policy"]["mode"] == "metadata_only"
    assert data["sandbox_metadata"]["resource_limits"]["timeout_seconds"] == 120
    assert data["sample_id"] == sample_id
    assert len(data["limitations"]) > 0


def test_sandbox_boundary_models_have_bounded_defaults() -> None:
    artifact_policy = ArtifactRetentionPolicy()
    limits = SandboxResourceLimits()

    assert artifact_policy.mode == "metadata_only"
    assert artifact_policy.hash_algorithm == "sha256"
    assert artifact_policy.provenance_required is True
    assert limits.timeout_seconds == 120
    assert limits.cpu_count == 1
    assert limits.memory_mb <= 1024


def test_new_behavior_analysis_invalidates_cached_derived_results(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"hello world benign readme", "readme.txt")
        detection_response = client.post(f"/api/v1/samples/{sample_id}/detect")
        assert detection_response.status_code == 200

        behavior_response = client.post(f"/api/v1/samples/{sample_id}/behavior-analysis")
        assert behavior_response.status_code == 200

        stale_detection = client.get(f"/api/v1/samples/{sample_id}/detection")

    assert stale_detection.status_code == 404
    assert stale_detection.json()["error"]["code"] == "detection_not_found"


def test_behavior_analysis_is_cached(tmp_path: Path) -> None:
    """Second POST must return the same cached result."""
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"cache test", "cache.bin")
        first = client.post(f"/api/v1/samples/{sample_id}/behavior-analysis").json()
        second = client.post(f"/api/v1/samples/{sample_id}/behavior-analysis").json()

    assert first == second


def test_behavior_analysis_get_returns_cached(tmp_path: Path) -> None:
    """GET /behavior-analysis after POST must return the same result."""
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"get test", "get.bin")
        post_result = client.post(f"/api/v1/samples/{sample_id}/behavior-analysis").json()
        get_result = client.get(f"/api/v1/samples/{sample_id}/behavior-analysis").json()

    assert post_result == get_result


def test_behavior_events_endpoint(tmp_path: Path) -> None:
    """GET /behavior-events must return the event timeline."""
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"events test", "events.bin")
        client.post(f"/api/v1/samples/{sample_id}/behavior-analysis")
        response = client.get(f"/api/v1/samples/{sample_id}/behavior-events")

    assert response.status_code == 200
    data = response.json()
    assert data["sample_id"] == sample_id
    assert "processes" in data
    assert "file_events" in data
    assert "registry_events" in data
    assert "network_events" in data


def test_behavior_evidence_endpoint(tmp_path: Path) -> None:
    """GET /behavior-evidence must return behavior-derived evidence."""
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"evidence test", "evidence.bin")
        client.post(f"/api/v1/samples/{sample_id}/behavior-analysis")
        response = client.get(f"/api/v1/samples/{sample_id}/behavior-evidence")

    assert response.status_code == 200
    data = response.json()
    assert data["sample_id"] == sample_id
    assert "evidence" in data


def test_behavior_events_before_run_returns_404(tmp_path: Path) -> None:
    """GET /behavior-events before running analysis must return 404."""
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"not analyzed", "notrun.bin")
        response = client.get(f"/api/v1/samples/{sample_id}/behavior-events")

    assert response.status_code == 404


def test_behavior_evidence_before_run_returns_404(tmp_path: Path) -> None:
    """GET /behavior-evidence before running analysis must return 404."""
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"not analyzed", "notrun.bin")
        response = client.get(f"/api/v1/samples/{sample_id}/behavior-evidence")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


def test_sample_without_behavior_analysis_deserializes(tmp_path: Path) -> None:
    """Existing Sample records without behavior_analysis must deserialize."""
    sample_data = {
        "sample_id": "compat-test-id",
        "original_filename": "legacy.exe",
        "safe_filename": "legacy.sample",
        "hashes": {"sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32},
        "storage_ref": "legacy.sample",
        "size_bytes": 100,
        "status": "completed",
    }
    sample = Sample.model_validate(sample_data)
    assert sample.behavior_analysis is None
    assert sample.sample_id == "compat-test-id"
