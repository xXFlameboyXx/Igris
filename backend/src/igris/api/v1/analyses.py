"""API routes for Phase 14 analysis job orchestration and pipeline tracking."""

from fastapi import APIRouter, Request, status

from igris.orchestration.service import OrchestrationService
from igris.schemas.orchestration import (
    AnalysisCancelResponse,
    AnalysisCreateRequest,
    AnalysisJobResponse,
    AnalysisListResponse,
    AnalysisStatusResponse,
)

router = APIRouter(prefix="/analyses", tags=["analyses"])


def _orchestration_service_from_request(request: Request) -> OrchestrationService:
    return OrchestrationService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
        job_repository=request.app.state.jobs_repository,
    )


@router.post(
    "",
    response_model=AnalysisJobResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_analysis(request: Request, body: AnalysisCreateRequest) -> AnalysisJobResponse:
    """Initiate a full or partial multi-stage analysis pipeline."""
    service = _orchestration_service_from_request(request)
    job = service.create_and_run_analysis(body)
    return AnalysisJobResponse(analysis=job)


@router.get("", response_model=AnalysisListResponse)
async def list_analyses(
    request: Request,
    sample_id: str | None = None,
    limit: int = 50,
) -> AnalysisListResponse:
    """List recent analysis pipeline jobs."""
    service = _orchestration_service_from_request(request)
    jobs = service.list_analysis_jobs(sample_id=sample_id, limit=limit)
    return AnalysisListResponse(analyses=jobs, total_count=len(jobs))


@router.get("/{analysis_id}", response_model=AnalysisJobResponse)
async def get_analysis(request: Request, analysis_id: str) -> AnalysisJobResponse:
    """Fetch complete analysis job details, stage metrics, and error classifications."""
    service = _orchestration_service_from_request(request)
    job = service.get_analysis_job(analysis_id)
    return AnalysisJobResponse(analysis=job)


@router.get("/{analysis_id}/status", response_model=AnalysisStatusResponse)
async def get_analysis_status(request: Request, analysis_id: str) -> AnalysisStatusResponse:
    """Return real-time stage progress and overall status."""
    service = _orchestration_service_from_request(request)
    job = service.get_analysis_job(analysis_id)
    return AnalysisStatusResponse(
        analysis_id=job.analysis_id,
        sample_id=job.sample_id,
        status=job.status,
        progress=job.progress,
        current_stage=job.current_stage,
        stages=job.stages,
        verdict_summary=job.verdict_summary,
        report_id=job.report_id,
        error=job.error,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
    )


@router.post("/{analysis_id}/cancel", response_model=AnalysisCancelResponse)
async def cancel_analysis(request: Request, analysis_id: str) -> AnalysisCancelResponse:
    """Cancel an active or queued analysis job."""
    service = _orchestration_service_from_request(request)
    job = service.cancel_analysis_job(analysis_id)
    return AnalysisCancelResponse(
        analysis_id=job.analysis_id,
        status=job.status,
        cancelled_at=job.cancelled_at or job.created_at,
        message=job.cancellation_reason or "Analysis job cancelled.",
    )
