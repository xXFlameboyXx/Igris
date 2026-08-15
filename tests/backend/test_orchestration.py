"""Backend tests for Phase 14 analysis job orchestration and pipeline coordination."""

from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
from tests.backend.fixtures import static_suspicious_pe_fixture

from igris.core.config import Settings
from igris.main import create_app
from igris.orchestration.service import OrchestrationService
from igris.schemas.orchestration import (
    AnalysisCreateRequest,
    FailureCategory,
    JobStatus,
    PipelineStageName,
    StageStatus,
)


def make_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        environment="test",
        metadata_backend="memory",
        sample_storage_dir=str(tmp_path / "samples"),
        metadata_storage_file=str(tmp_path / "metadata.json"),
        sample_temp_dir=str(tmp_path / "tmp"),
    )
    app = create_app(settings)
    return TestClient(app)


def _upload_sample(client: TestClient, filename: str, content: bytes) -> str:
    res = client.post(
        "/api/v1/samples",
        files={"file": (filename, BytesIO(content), "application/octet-stream")},
    )
    assert res.status_code == 201
    return res.json()["sample_id"]


def test_full_pipeline_orchestration_endpoint(tmp_path: Path) -> None:
    """Verify that submitting an analysis job runs the full pipeline successfully."""
    client = make_client(tmp_path)
    sample_id = _upload_sample(client, "test_malware.exe", static_suspicious_pe_fixture())

    # Trigger analysis job via API
    req_payload = {"sample_id": sample_id, "force_reanalyze": True}
    res = client.post("/api/v1/analyses", json=req_payload)
    assert res.status_code == 201

    data = res.json()["analysis"]
    assert data["sample_id"] == sample_id
    assert data["status"] == "COMPLETED"
    assert data["progress"] == 100
    assert len(data["stages"]) == 11

    # Check all stages completed
    for stg in data["stages"]:
        assert stg["status"] in ("COMPLETED", "SKIPPED")
        if stg["status"] == "COMPLETED":
            assert stg["duration_ms"] is not None
            assert stg["result_available"] is True

    # Verify explainable verdict summary is populated
    assert data["verdict_summary"] is not None
    assert data["verdict_summary"]["verdict"] in (
        "HIGHLY_SUSPICIOUS",
        "SUSPICIOUS",
        "LIKELY_BENIGN",
        "UNKNOWN",
    )


def test_get_analysis_status_endpoint(tmp_path: Path) -> None:
    """Verify the real-time concise status endpoint."""
    client = make_client(tmp_path)
    sample_id = _upload_sample(client, "status_sample.exe", static_suspicious_pe_fixture())

    # Create job
    create_res = client.post("/api/v1/analyses", json={"sample_id": sample_id})
    analysis_id = create_res.json()["analysis"]["analysis_id"]

    # Query concise status
    status_res = client.get(f"/api/v1/analyses/{analysis_id}/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["analysis_id"] == analysis_id
    assert status_data["status"] == "COMPLETED"
    assert status_data["progress"] == 100
    assert len(status_data["stages"]) > 0


def test_idempotency_and_duplicate_submissions(tmp_path: Path) -> None:
    """Verify that duplicate submissions reuse existing completed jobs unless forced."""
    client = make_client(tmp_path)
    sample_id = _upload_sample(client, "idempotent.exe", static_suspicious_pe_fixture())

    # First run
    res1 = client.post("/api/v1/analyses", json={"sample_id": sample_id})
    job1 = res1.json()["analysis"]

    # Second run without force_reanalyze
    res2 = client.post(
        "/api/v1/analyses",
        json={"sample_id": sample_id, "force_reanalyze": False},
    )
    job2 = res2.json()["analysis"]
    assert job1["analysis_id"] == job2["analysis_id"]

    # Third run WITH force_reanalyze
    res3 = client.post(
        "/api/v1/analyses",
        json={"sample_id": sample_id, "force_reanalyze": True},
    )
    job3 = res3.json()["analysis"]
    assert job3["analysis_id"] != job1["analysis_id"]


def test_custom_enabled_stages(tmp_path: Path) -> None:
    """Verify running a custom subset of pipeline stages."""
    client = make_client(tmp_path)
    sample_id = _upload_sample(client, "partial.exe", static_suspicious_pe_fixture())

    custom_stages = ["FILE_INTELLIGENCE", "STATIC_ANALYSIS", "DETECTION"]
    res = client.post(
        "/api/v1/analyses",
        json={"sample_id": sample_id, "enabled_stages": custom_stages, "force_reanalyze": True},
    )
    assert res.status_code == 201
    job = res.json()["analysis"]
    assert len(job["stages"]) == 3
    stage_names = [s["name"] for s in job["stages"]]
    assert stage_names == custom_stages
    assert all(s["status"] == "COMPLETED" for s in job["stages"])


def test_cancellation_endpoint(tmp_path: Path) -> None:
    """Verify cancellation marks active/queued stages as CANCELLED."""
    client = make_client(tmp_path)
    sample_id = _upload_sample(client, "cancel.exe", static_suspicious_pe_fixture())

    app = client.app
    service = OrchestrationService(
        settings=app.state.settings,
        sample_storage=app.state.sample_storage,
        metadata_repository=app.state.metadata_repository,
        job_repository=app.state.jobs_repository,
    )

    # Pre-create a queued job
    from igris.schemas.orchestration import AnalysisJob, PipelineStageRecord

    custom_job = AnalysisJob(
        analysis_id="job-cancel-test",
        sample_id=sample_id,
        status=JobStatus.QUEUED,
        stages=[
            PipelineStageRecord(
                name=PipelineStageName.FILE_INTELLIGENCE,
                status=StageStatus.QUEUED,
            ),
            PipelineStageRecord(
                name=PipelineStageName.STATIC_ANALYSIS,
                status=StageStatus.QUEUED,
            ),
        ],
        idempotency_key="cancel-key-123",
    )
    service.job_repository.upsert(custom_job)

    # Cancel via API
    cancel_res = client.post("/api/v1/analyses/job-cancel-test/cancel")
    assert cancel_res.status_code == 200
    cancel_data = cancel_res.json()
    assert cancel_data["status"] == "CANCELLED"

    # Verify job state
    fetched_job = service.get_analysis_job("job-cancel-test")
    assert fetched_job.status == JobStatus.CANCELLED
    assert fetched_job.cancelled_at is not None
    for stg in fetched_job.stages:
        assert stg.status == StageStatus.CANCELLED


def test_stage_failure_isolation_and_partial_results(tmp_path: Path) -> None:
    """Verify that stage failures isolate cleanly and independent stages still execute."""
    client = make_client(tmp_path)
    sample_id = _upload_sample(client, "fail_iso.exe", static_suspicious_pe_fixture())

    app = client.app
    service = OrchestrationService(
        settings=app.state.settings,
        sample_storage=app.state.sample_storage,
        metadata_repository=app.state.metadata_repository,
        job_repository=app.state.jobs_repository,
    )

    # Mock reverse_service to raise an error
    def failing_reverse_run(s_id: str):
        raise ValueError("Unsupported architecture / Corrupted PE headers")

    service.reverse_service.run = failing_reverse_run  # type: ignore

    job = service.create_and_run_analysis(
        AnalysisCreateRequest(sample_id=sample_id, force_reanalyze=True)
    )

    assert job.status == JobStatus.COMPLETED
    stages_by_name = {s.name: s for s in job.stages}

    # Reverse analysis must be marked as FAILED with non-retryable error
    assert stages_by_name[PipelineStageName.REVERSE_ANALYSIS].status == StageStatus.FAILED
    assert stages_by_name[PipelineStageName.REVERSE_ANALYSIS].error is not None
    assert (
        stages_by_name[PipelineStageName.REVERSE_ANALYSIS].error.error_category
        == FailureCategory.NON_RETRYABLE
    )

    # Independent stages must still have completed!
    assert stages_by_name[PipelineStageName.FILE_INTELLIGENCE].status == StageStatus.COMPLETED
    assert stages_by_name[PipelineStageName.STATIC_ANALYSIS].status == StageStatus.COMPLETED
    assert stages_by_name[PipelineStageName.DETECTION].status == StageStatus.COMPLETED
    assert stages_by_name[PipelineStageName.BEHAVIOR].status == StageStatus.COMPLETED
    assert stages_by_name[PipelineStageName.ASSESSMENT].status == StageStatus.COMPLETED
    assert stages_by_name[PipelineStageName.REPORT].status == StageStatus.COMPLETED

    # Final verdict exists based on remaining independent evidence
    assert job.verdict_summary is not None


def test_list_analyses_endpoint(tmp_path: Path) -> None:
    """Verify listing recent analysis jobs."""
    client = make_client(tmp_path)
    sample_id = _upload_sample(client, "list_test.exe", static_suspicious_pe_fixture())

    client.post("/api/v1/analyses", json={"sample_id": sample_id, "force_reanalyze": True})
    client.post("/api/v1/analyses", json={"sample_id": sample_id, "force_reanalyze": True})

    res = client.get("/api/v1/analyses")
    assert res.status_code == 200
    data = res.json()
    assert data["total_count"] >= 2
    assert len(data["analyses"]) >= 2


def test_retry_behavior_on_transient_failure(tmp_path: Path) -> None:
    """Verify that transient retryable failures retry up to max_retries and can succeed."""
    client = make_client(tmp_path)
    sample_id = _upload_sample(client, "retry_test.exe", static_suspicious_pe_fixture())

    app = client.app
    service = OrchestrationService(
        settings=app.state.settings,
        sample_storage=app.state.sample_storage,
        metadata_repository=app.state.metadata_repository,
        job_repository=app.state.jobs_repository,
    )

    original_run = service.similarity_service.run
    attempts = 0

    def flaky_similarity_run(s_id: str, max_matches: int = 20):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("Temporary socket timeout connecting to indexing cache")
        return original_run(s_id, max_matches=max_matches)

    service.similarity_service.run = flaky_similarity_run  # type: ignore

    job = service.create_and_run_analysis(
        AnalysisCreateRequest(
            sample_id=sample_id,
            enabled_stages=[
                PipelineStageName.FILE_INTELLIGENCE,
                PipelineStageName.STATIC_ANALYSIS,
                PipelineStageName.SIMILARITY,
            ],
            force_reanalyze=True,
            max_retries=2,
        )
    )

    assert job.status == JobStatus.COMPLETED
    stages_by_name = {s.name: s for s in job.stages}
    sim_stage = stages_by_name[PipelineStageName.SIMILARITY]
    assert sim_stage.status == StageStatus.COMPLETED
    assert sim_stage.retry_count == 1
    assert attempts == 2
