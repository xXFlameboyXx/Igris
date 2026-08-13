"""Sample upload and file-intelligence endpoints."""

from typing import Annotated

from fastapi import APIRouter, File, Request, UploadFile, status

from igris.analysis.behavioral.service import BehaviorAnalysisService
from igris.analysis.file_intelligence.service import FileIntelligenceService
from igris.analysis.reverse_analysis.service import ReverseAnalysisService
from igris.analysis.static_analysis.service import StaticAnalysisService
from igris.detection.service import DetectionService
from igris.intelligence.threat.service import ThreatIntelligenceService
from igris.ml.service import MLService
from igris.schemas.behavior_analysis import (
    BehaviorAnalysisResponse,
    BehaviorEventsResponse,
    BehaviorEvidenceResponse,
)
from igris.schemas.detection import DetectionResponse
from igris.schemas.file_intelligence import FileInfoResponse, SampleCreateResponse, SampleResponse
from igris.schemas.ml import MLPredictionResponse
from igris.schemas.reverse_analysis import (
    CFGResponse,
    FunctionResponse,
    FunctionsResponse,
    ReverseAnalysisResponse,
)
from igris.schemas.static_analysis import IndicatorsResponse, StaticAnalysisResponse
from igris.schemas.threat_intelligence import (
    CapabilitiesResponse,
    EvidenceRelationshipsResponse,
    NarrativeResponse,
    TechniquesResponse,
    ThreatAssessmentResponse,
)

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


@router.post("/{sample_id}/threat-assessment", response_model=ThreatAssessmentResponse)
async def create_threat_assessment(
    request: Request, sample_id: str
) -> ThreatAssessmentResponse:
    """Run evidence-driven threat-intelligence mapping or return the cached result."""

    service = _threat_service_from_request(request)
    return service.run(sample_id)


@router.get("/{sample_id}/threat-assessment", response_model=ThreatAssessmentResponse)
async def get_threat_assessment(request: Request, sample_id: str) -> ThreatAssessmentResponse:
    """Return a previously generated threat-intelligence assessment."""

    service = _threat_service_from_request(request)
    return service.get(sample_id)


@router.get("/{sample_id}/capabilities", response_model=CapabilitiesResponse)
async def get_capabilities(request: Request, sample_id: str) -> CapabilitiesResponse:
    """Return normalized capability hypotheses for a sample."""

    service = _threat_service_from_request(request)
    return service.capabilities(sample_id)


@router.get("/{sample_id}/attack-mappings", response_model=TechniquesResponse)
async def get_attack_mappings(request: Request, sample_id: str) -> TechniquesResponse:
    """Return evidence-driven ATT&CK technique mappings for a sample."""

    service = _threat_service_from_request(request)
    return service.techniques(sample_id)


@router.get("/{sample_id}/evidence-relationships", response_model=EvidenceRelationshipsResponse)
async def get_evidence_relationships(
    request: Request, sample_id: str
) -> EvidenceRelationshipsResponse:
    """Return the observation-to-technique evidence graph."""

    service = _threat_service_from_request(request)
    return service.relationships(sample_id)


@router.get("/{sample_id}/narrative", response_model=NarrativeResponse)
async def get_narrative(request: Request, sample_id: str) -> NarrativeResponse:
    """Return the preliminary behavior narrative for a sample."""

    service = _threat_service_from_request(request)
    return service.narrative(sample_id)


@router.post("/{sample_id}/ml-prediction", response_model=MLPredictionResponse)
async def create_ml_prediction(
    request: Request, sample_id: str, model_version: str | None = None
) -> MLPredictionResponse:
    """Run ML inference as an additional evidence source."""

    service = _ml_service_from_request(request)
    return service.predict(sample_id, model_version=model_version)


@router.get("/{sample_id}/ml-prediction", response_model=MLPredictionResponse)
async def get_ml_prediction(request: Request, sample_id: str) -> MLPredictionResponse:
    """Return a cached ML prediction."""

    service = _ml_service_from_request(request)
    return service.get_prediction(sample_id)


# ---------------------------------------------------------------------------
# Phase 7: Behavior analysis (explicit POST only — never auto-triggered)
# ---------------------------------------------------------------------------


@router.post("/{sample_id}/behavior-analysis", response_model=BehaviorAnalysisResponse)
async def create_behavior_analysis(
    request: Request, sample_id: str
) -> BehaviorAnalysisResponse:
    """Run synthetic behavior analysis or return the cached result.

    Phase 7.0: uses SyntheticBehaviorAnalyzer. No sample execution occurs.
    """

    service = _behavior_service_from_request(request)
    return service.run(sample_id)


@router.get("/{sample_id}/behavior-analysis", response_model=BehaviorAnalysisResponse)
async def get_behavior_analysis(
    request: Request, sample_id: str
) -> BehaviorAnalysisResponse:
    """Return a previously generated behavior-analysis result."""

    service = _behavior_service_from_request(request)
    return service.get(sample_id)


@router.get("/{sample_id}/behavior-events", response_model=BehaviorEventsResponse)
async def get_behavior_events(request: Request, sample_id: str) -> BehaviorEventsResponse:
    """Return the behavior event timeline from a cached result."""

    service = _behavior_service_from_request(request)
    return service.events(sample_id)


@router.get("/{sample_id}/behavior-evidence", response_model=BehaviorEvidenceResponse)
async def get_behavior_evidence(request: Request, sample_id: str) -> BehaviorEvidenceResponse:
    """Return behavior-derived evidence from a cached result."""

    service = _behavior_service_from_request(request)
    return service.evidence(sample_id)


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


def _threat_service_from_request(request: Request) -> ThreatIntelligenceService:
    return ThreatIntelligenceService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )


def _ml_service_from_request(request: Request) -> MLService:
    return MLService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )


def _behavior_service_from_request(request: Request) -> BehaviorAnalysisService:
    return BehaviorAnalysisService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )
