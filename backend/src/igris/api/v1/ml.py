"""Phase 6 ML metadata and experiment endpoints."""

from fastapi import APIRouter, Request

from igris.ml.service import MLService
from igris.schemas.ml import ExperimentResultsResponse, ModelMetadataResponse

router = APIRouter()


@router.get("/model-metadata", response_model=ModelMetadataResponse)
async def get_model_metadata(request: Request) -> ModelMetadataResponse:
    """Return versioned metadata for available ML models."""

    service = _ml_service_from_request(request)
    return service.model_metadata()


@router.get("/experiments", response_model=ExperimentResultsResponse)
async def get_experiment_results(request: Request) -> ExperimentResultsResponse:
    """Return tracked baseline experiment results."""

    service = _ml_service_from_request(request)
    return service.experiment_results()


def _ml_service_from_request(request: Request) -> MLService:
    return MLService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )
