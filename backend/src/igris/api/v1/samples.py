"""Sample upload and file-intelligence endpoints."""

from typing import Annotated

from fastapi import APIRouter, File, Request, UploadFile, status

from igris.analysis.file_intelligence.service import FileIntelligenceService
from igris.schemas.file_intelligence import FileInfoResponse, SampleCreateResponse, SampleResponse

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


def _service_from_request(request: Request) -> FileIntelligenceService:
    return FileIntelligenceService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )
