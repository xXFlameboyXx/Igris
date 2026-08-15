"""Backend tests for Phase 16 Robustness, Perturbation Testing, and Adversarial Resilience."""

from pathlib import Path

from fastapi.testclient import TestClient

from igris.core.config import Settings
from igris.main import create_app
from igris.robustness.service import RobustnessService
from igris.schemas.assessment import AssessmentVerdict
from igris.schemas.robustness import (
    BenignStressCategory,
    DegradationSeverity,
    RobustnessEvaluateRequest,
    TransformationType,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.jobs import InMemoryAnalysisJobRepository
from igris.storage.metadata import InMemorySampleMetadataRepository
from igris.storage.robustness import InMemoryRobustnessRepository


def _make_test_service() -> RobustnessService:
    settings = Settings(metadata_backend="memory")
    return RobustnessService(
        settings=settings,
        sample_storage=LocalSampleStorage(Path(settings.sample_storage_dir)),
        metadata_repository=InMemorySampleMetadataRepository(),
        job_repository=InMemoryAnalysisJobRepository(),
        robustness_repository=InMemoryRobustnessRepository(),
    )


def test_evaluate_perturbation_matrix() -> None:
    """Verify all 7 controlled transformations are evaluated with per-engine sensitivity."""
    service = _make_test_service()
    report = service.evaluate_robustness(RobustnessEvaluateRequest())

    assert report.report_id.startswith("rob-")
    assert len(report.matrix_rows) == 7

    types = {r.transformation_type for r in report.matrix_rows}
    assert types == {
        TransformationType.FILENAME_RENAME,
        TransformationType.METADATA_MUTATION,
        TransformationType.STRING_PADDING,
        TransformationType.SECTION_OVERLAY_PADDING,
        TransformationType.INSTRUCTION_NOP_INSERTION,
        TransformationType.SYNTHETIC_PACKING_SIMULATION,
        TransformationType.COMPILER_FLAG_VARIATION,
    }

    # Verify per-engine sensitivities are populated
    for row in report.matrix_rows:
        assert row.static_sensitivity.engine_name == "Static Analysis"
        assert row.reverse_sensitivity.engine_name == "Reverse Engineering"
        assert row.ml_sensitivity.engine_name == "ML Classifier"
        assert row.similarity_sensitivity.engine_name == "Similarity Matching"
        assert row.behavior_sensitivity.engine_name == "Behavioral Sandbox"
        assert row.final_verdict_sensitivity.engine_name == "Final Assessment"
        assert row.overall_stability in {
            DegradationSeverity.NONE,
            DegradationSeverity.LOW,
            DegradationSeverity.MODERATE,
            DegradationSeverity.SEVERE,
        }

    # Filename rename must be completely stable (Severity NONE)
    rename_row = next(
        r for r in report.matrix_rows if r.transformation_type == TransformationType.FILENAME_RENAME
    )
    assert rename_row.overall_stability == DegradationSeverity.NONE
    assert rename_row.final_verdict_sensitivity.absolute_delta == 0.0


def test_false_positive_stress_suite() -> None:
    """Verify legitimate software with suspicious traits does not trigger overreactions."""
    service = _make_test_service()
    report = service.evaluate_robustness(RobustnessEvaluateRequest(include_stress_tests=True))

    assert len(report.false_positive_tests) == 4
    categories = {t.category for t in report.false_positive_tests}
    assert categories == {
        BenignStressCategory.ADMIN_TOOL,
        BenignStressCategory.INSTALLER_COMPRESSOR,
        BenignStressCategory.DEVELOPER_DEBUGGER,
        BenignStressCategory.NETWORK_UTILITY,
    }

    # Verify zero overreactions into HIGHLY_SUSPICIOUS
    for test_result in report.false_positive_tests:
        assert not test_result.overreaction_flag
        assert test_result.baseline_verdict in {
            AssessmentVerdict.BENIGN,
            AssessmentVerdict.LIKELY_BENIGN,
        }
        assert len(test_result.mitigating_evidence) > 0
        assert len(test_result.suspicious_characteristics) > 0

    assert report.fp_resilience_rate == 1.0


def test_failure_records_taxonomy() -> None:
    """Verify failure analysis records clearly separate observed from resolved limitations."""
    service = _make_test_service()
    report = service.evaluate_robustness(RobustnessEvaluateRequest())

    assert len(report.failure_records) >= 4
    statuses = {f.status for f in report.failure_records}
    assert "OBSERVED_LIMITATION" in statuses
    assert "RESOLVED_LIMITATION" in statuses

    for record in report.failure_records:
        assert record.failure_id.startswith("FAIL-")
        assert len(record.vulnerable_engine) > 0
        assert len(record.root_cause) > 0
        assert len(record.mitigation_strategy) > 0
        assert len(record.fp_risk_of_mitigation) > 0


def test_robustness_repository_persistence() -> None:
    """Verify storing, retrieving, and listing robustness evaluation reports."""
    repo = InMemoryRobustnessRepository()
    service = _make_test_service()
    service.robustness_repository = repo

    report1 = service.evaluate_robustness(RobustnessEvaluateRequest())
    assert repo.get_report(report1.report_id) is not None
    assert repo.get_latest_report().report_id == report1.report_id

    reports = repo.list_reports(10)
    assert len(reports) == 1
    assert reports[0].report_id == report1.report_id


def test_robustness_api_endpoints() -> None:
    """Verify all 5 REST API routes for robustness evaluation."""
    app = create_app(Settings(metadata_backend="memory"))
    client = TestClient(app)

    # 1. POST /api/v1/robustness/evaluate
    res_eval = client.post(
        "/api/v1/robustness/evaluate",
        json={"include_stress_tests": True, "random_seed": 42},
    )
    assert res_eval.status_code == 201
    eval_data = res_eval.json()
    report_id = eval_data["report"]["report_id"]
    assert len(eval_data["report"]["matrix_rows"]) == 7

    # 2. GET /api/v1/robustness/matrix
    res_matrix = client.get("/api/v1/robustness/matrix")
    assert res_matrix.status_code == 200
    matrix_data = res_matrix.json()
    assert matrix_data["report_id"] == report_id
    assert len(matrix_data["matrix_rows"]) == 7

    # 3. GET /api/v1/robustness/false-positives
    res_fp = client.get("/api/v1/robustness/false-positives")
    assert res_fp.status_code == 200
    fp_data = res_fp.json()
    assert fp_data["report_id"] == report_id
    assert fp_data["fp_resilience_rate"] == 1.0
    assert len(fp_data["false_positive_tests"]) == 4

    # 4. GET /api/v1/robustness/reports/{report_id}
    res_single = client.get(f"/api/v1/robustness/reports/{report_id}")
    assert res_single.status_code == 200
    assert res_single.json()["report"]["report_id"] == report_id

    # 5. GET /api/v1/robustness/reports
    res_list = client.get("/api/v1/robustness/reports")
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert list_data["total_count"] >= 1
