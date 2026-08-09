"""Sample upload and file-intelligence endpoints."""

from typing import Annotated

from fastapi import APIRouter, File, Request, UploadFile, status

from igris.analysis.file_intelligence.service import FileIntelligenceService
from igris.analysis.reverse_analysis.service import ReverseAnalysisService
from igris.analysis.static_analysis.service import StaticAnalysisService
from igris.detection.service import DetectionService
from igris.schemas.detection import DetectionResponse
from igris.schemas.file_intelligence import FileInfoResponse, SampleCreateResponse, SampleResponse
from igris.schemas.reverse_analysis import (
    CFGResponse,
    FunctionResponse,
    FunctionsResponse,
    ReverseAnalysisResponse,
)
from igris.schemas.static_analysis import IndicatorsResponse, StaticAnalysisResponse

router = APIRouter()


@router.post("", response_model=SampleCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_sample(
    request: Request,
    file: Annotated[UploadFile, File()],
) -> SampleCreateResponse:
    """Upload a hostile sample as inert data and return its canonical sample ID."""

    service = _service_from_request(request)
    return await service.ingest(file)


@router.get("/{sample_id}", response_model=SampleResponse)
async def get_sample(request: Request, sample_id: str) -> SampleResponse:
    """Return basic metadata and current analysis state."""

    service = _service_from_request(request)
    return service.get_sample(sample_id)


@router.get("/{sample_id}/file-info", response_model=FileInfoResponse)
async def get_sample_file_info(request: Request, sample_id: str) -> FileInfoResponse:
    """Return detailed normalized Phase 1 file intelligence."""

    service = _service_from_request(request)
    return service.get_file_info(sample_id)


@router.post("/{sample_id}/static-analysis", response_model=StaticAnalysisResponse)
async def create_static_analysis(request: Request, sample_id: str) -> StaticAnalysisResponse:
    """Run deterministic static analysis or return the existing result."""

    service = _static_service_from_request(request)
    return service.run(sample_id)


@router.get("/{sample_id}/static-analysis", response_model=StaticAnalysisResponse)
async def get_static_analysis(request: Request, sample_id: str) -> StaticAnalysisResponse:
    """Return a previously generated static-analysis result."""

    service = _static_service_from_request(request)
    return service.get(sample_id)


@router.get("/{sample_id}/indicators", response_model=IndicatorsResponse)
async def get_indicators(request: Request, sample_id: str) -> IndicatorsResponse:
    """Return normalized static-analysis evidence only."""

    service = _static_service_from_request(request)
    analysis = service.get(sample_id).analysis
    return IndicatorsResponse(sample_id=sample_id, indicators=analysis.evidence)


@router.post("/{sample_id}/detect", response_model=DetectionResponse)
async def create_detection(request: Request, sample_id: str) -> DetectionResponse:
    """Run evidence-based detection or return the existing result."""

    service = _detection_service_from_request(request)
    return service.run(sample_id)


@router.get("/{sample_id}/detection", response_model=DetectionResponse)
async def get_detection(request: Request, sample_id: str) -> DetectionResponse:
    """Return a previously generated detection result."""

    service = _detection_service_from_request(request)
    return service.get(sample_id)


@router.post("/{sample_id}/reverse-analysis", response_model=ReverseAnalysisResponse)
async def create_reverse_analysis(request: Request, sample_id: str) -> ReverseAnalysisResponse:
    """Run safe offline reverse analysis or return the existing result."""

    service = _reverse_service_from_request(request)
    return service.run(sample_id)


@router.get("/{sample_id}/reverse-analysis", response_model=ReverseAnalysisResponse)
async def get_reverse_analysis(request: Request, sample_id: str) -> ReverseAnalysisResponse:
    """Return a previously generated reverse-analysis result."""

    service = _reverse_service_from_request(request)
    return service.get(sample_id)


@router.get("/{sample_id}/functions", response_model=FunctionsResponse)
async def get_functions(request: Request, sample_id: str) -> FunctionsResponse:
    """Return reverse-engineered functions for a sample."""

    service = _reverse_service_from_request(request)
    return service.list_functions(sample_id)


@router.get("/{sample_id}/functions/{function_id}", response_model=FunctionResponse)
async def get_function(
    request: Request, sample_id: str, function_id: str
) -> FunctionResponse:
    """Return a single reverse-engineered function."""

    service = _reverse_service_from_request(request)
    return service.get_function(sample_id, function_id)


@router.get("/{sample_id}/cfg/{function_id}", response_model=CFGResponse)
async def get_cfg(request: Request, sample_id: str, function_id: str) -> CFGResponse:
    """Return the JSON control-flow graph for a function."""

    service = _reverse_service_from_request(request)
    return service.get_cfg(sample_id, function_id)


def _service_from_request(request: Request) -> FileIntelligenceService:
    return FileIntelligenceService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )


def _static_service_from_request(request: Request) -> StaticAnalysisService:
    return StaticAnalysisService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )


def _detection_service_from_request(request: Request) -> DetectionService:
    return DetectionService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )


def _reverse_service_from_request(request: Request) -> ReverseAnalysisService:
    return ReverseAnalysisService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )
