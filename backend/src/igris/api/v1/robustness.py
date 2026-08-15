"""API routes for Phase 16 Robustness, Perturbation Testing, and Adversarial Resilience."""

from fastapi import APIRouter, Request, status

from igris.robustness.service import RobustnessService
from igris.schemas.robustness import (
    FalsePositiveTestsResponse,
    RobustnessEvaluateRequest,
    RobustnessMatrixResponse,
    RobustnessReportListResponse,
    RobustnessReportResponse,
)

router = APIRouter()


def _service_from_request(request: Request) -> RobustnessService:
    """Instantiate RobustnessService from application state repositories."""
    return RobustnessService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
        job_repository=request.app.state.jobs_repository,
        robustness_repository=request.app.state.robustness_repository,
    )


@router.post(
    "/evaluate",
    response_model=RobustnessReportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def evaluate_robustness(
    request: Request, body: RobustnessEvaluateRequest
) -> RobustnessReportResponse:
    """Execute a controlled safe robustness perturbation evaluation."""
    service = _service_from_request(request)
    report = service.evaluate_robustness(body)
    return RobustnessReportResponse(report=report)


@router.get("/matrix", response_model=RobustnessMatrixResponse)
async def get_robustness_matrix(request: Request) -> RobustnessMatrixResponse:
    """Retrieve the latest empirical perturbation matrix across all 7 transformation types."""
    service = _service_from_request(request)
    report = service.get_latest_report()
    return RobustnessMatrixResponse(
        report_id=report.report_id,
        matrix_rows=report.matrix_rows,
        mean_stability_score=report.mean_stability_score,
    )


@router.get("/false-positives", response_model=FalsePositiveTestsResponse)
async def get_false_positive_tests(request: Request) -> FalsePositiveTestsResponse:
    """Retrieve stress-test results for complex legitimate software."""
    service = _service_from_request(request)
    report = service.get_latest_report()
    return FalsePositiveTestsResponse(
        report_id=report.report_id,
        false_positive_tests=report.false_positive_tests,
        fp_resilience_rate=report.fp_resilience_rate,
    )


@router.get("/reports/{report_id}", response_model=RobustnessReportResponse)
async def get_robustness_report(request: Request, report_id: str) -> RobustnessReportResponse:
    """Retrieve a specific historical robustness report by ID."""
    service = _service_from_request(request)
    report = service.get_report(report_id)
    return RobustnessReportResponse(report=report)


@router.get("/reports", response_model=RobustnessReportListResponse)
async def list_robustness_reports(
    request: Request, limit: int = 50
) -> RobustnessReportListResponse:
    """List historical robustness evaluation reports."""
    service = _service_from_request(request)
    reports = service.list_reports(limit=limit)
    return RobustnessReportListResponse(
        reports=reports,
        total_count=len(reports),
    )
