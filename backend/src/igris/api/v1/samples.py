"""Sample upload and file-intelligence endpoints."""

from typing import Annotated

from fastapi import APIRouter, File, Request, Response, UploadFile, status

from igris.analysis.behavioral.service import BehaviorAnalysisService
from igris.analysis.file_intelligence.service import FileIntelligenceService
from igris.analysis.reverse_analysis.service import ReverseAnalysisService
from igris.analysis.similarity.service import SimilarityService
from igris.analysis.static_analysis.service import StaticAnalysisService
from igris.detection.service import DetectionService
from igris.intelligence.assessment.service import AssessmentService
from igris.intelligence.investigation.service import InvestigationService
from igris.intelligence.threat.service import ThreatIntelligenceService
from igris.ml.service import MLService
from igris.reporting.service import ReportingService
from igris.schemas.assessment import (
    EvidenceSummaryResponse,
    ExplanationResponse,
    VerdictResponse,
)
from igris.schemas.behavior_analysis import (
    BehaviorAnalysisResponse,
    BehaviorEventsResponse,
    BehaviorEvidenceResponse,
)
from igris.schemas.detection import DetectionResponse
from igris.schemas.file_intelligence import (
    FileInfoResponse,
    SampleCreateResponse,
    SampleListResponse,
    SampleResponse,
)
from igris.schemas.investigation import (
    BookmarkCreateRequest,
    BookmarkResponse,
    BookmarksListResponse,
    EvidenceFilterQuery,
    EvidenceListResponse,
    InvestigationWorkspaceResponse,
    NoteCreateRequest,
    NoteResponse,
    NotesListResponse,
    NoteUpdateRequest,
    ReportCreateResponse,
)
from igris.schemas.ml import MLPredictionResponse
from igris.schemas.reverse_analysis import (
    CFGResponse,
    FunctionResponse,
    FunctionsResponse,
    ReverseAnalysisResponse,
)
from igris.schemas.similarity import SimilarityResponse, SimilarityResultsResponse
from igris.schemas.static_analysis import IndicatorsResponse, StaticAnalysisResponse
from igris.schemas.threat_intelligence import (
    CapabilitiesResponse,
    EvidenceRelationshipsResponse,
    NarrativeResponse,
    TechniquesResponse,
    ThreatAssessmentResponse,
)

router = APIRouter()


@router.get("", response_model=SampleListResponse)
async def list_samples(request: Request) -> SampleListResponse:
    """Return all stored sample metadata records."""

    service = _service_from_request(request)
    return SampleListResponse(samples=service.list_samples())


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
async def get_function(request: Request, sample_id: str, function_id: str) -> FunctionResponse:
    """Return a single reverse-engineered function."""

    service = _reverse_service_from_request(request)
    return service.get_function(sample_id, function_id)


@router.get("/{sample_id}/cfg/{function_id}", response_model=CFGResponse)
async def get_cfg(request: Request, sample_id: str, function_id: str) -> CFGResponse:
    """Return the JSON control-flow graph for a function."""

    service = _reverse_service_from_request(request)
    return service.get_cfg(sample_id, function_id)


@router.post("/{sample_id}/threat-assessment", response_model=ThreatAssessmentResponse)
async def create_threat_assessment(request: Request, sample_id: str) -> ThreatAssessmentResponse:
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
async def create_behavior_analysis(request: Request, sample_id: str) -> BehaviorAnalysisResponse:
    """Run synthetic behavior analysis or return the cached result.

    Phase 7.0: uses SyntheticBehaviorAnalyzer. No sample execution occurs.
    """

    service = _behavior_service_from_request(request)
    return service.run(sample_id)


@router.get("/{sample_id}/behavior-analysis", response_model=BehaviorAnalysisResponse)
async def get_behavior_analysis(request: Request, sample_id: str) -> BehaviorAnalysisResponse:
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


# ---------------------------------------------------------------------------
# Phase 10: Sample Similarity Analysis
# ---------------------------------------------------------------------------


@router.post("/{sample_id}/similarity", response_model=SimilarityResponse)
async def create_similarity_analysis(
    request: Request, sample_id: str, max_matches: int = 20
) -> SimilarityResponse:
    """Run deterministic multi-level sample similarity analysis against indexed candidates."""

    service = _similarity_service_from_request(request)
    return service.run(sample_id, max_matches=max_matches)


@router.get("/{sample_id}/similarity/results", response_model=SimilarityResultsResponse)
async def get_similarity_results(request: Request, sample_id: str) -> SimilarityResultsResponse:
    """Return previously generated similarity analysis results."""

    service = _similarity_service_from_request(request)
    return service.get(sample_id)


# ---------------------------------------------------------------------------
# Phase 11: Explainable Malware Assessment
# ---------------------------------------------------------------------------


@router.get("/{sample_id}/verdict", response_model=VerdictResponse)
async def get_assessment_verdict(request: Request, sample_id: str) -> VerdictResponse:
    """Return structured verdict, risk score, and multi-dimensional confidence."""

    service = _assessment_service_from_request(request)
    return service.get_verdict(sample_id)


@router.get("/{sample_id}/explanation", response_model=ExplanationResponse)
async def get_assessment_explanation(request: Request, sample_id: str) -> ExplanationResponse:
    """Return structured narrative explanation separating findings."""

    service = _assessment_service_from_request(request)
    return service.get_explanation(sample_id)


@router.get("/{sample_id}/evidence-summary", response_model=EvidenceSummaryResponse)
async def get_assessment_evidence_summary(
    request: Request, sample_id: str
) -> EvidenceSummaryResponse:
    """Return aggregated multi-layer evidence breakdown, contradictions, and uncertainties."""

    service = _assessment_service_from_request(request)
    return service.get_evidence_summary(sample_id)


# =============================================================================
# Phase 13: Investigation Workspace, Evidence Filtering, Bookmarks, Notes & Reports
# =============================================================================


@router.get("/{sample_id}/investigation", response_model=InvestigationWorkspaceResponse)
async def get_investigation_workspace(
    request: Request, sample_id: str
) -> InvestigationWorkspaceResponse:
    """Return aggregated investigation workspace containing sample, verdict,
    coverage, notes, and bookmarks.
    """

    service = _investigation_service_from_request(request)
    workspace = service.get_workspace(sample_id)
    return InvestigationWorkspaceResponse(workspace=workspace)


@router.get("/{sample_id}/evidence", response_model=EvidenceListResponse)
async def get_filtered_evidence(
    request: Request,
    sample_id: str,
    source: str | None = None,
    severity: str | None = None,
    role: str | None = None,
    observation_level: str | None = None,
    process: str | None = None,
    function: str | None = None,
    technique: str | None = None,
    query: str | None = None,
) -> EvidenceListResponse:
    """Return filtered multi-dimensional evidence items without mutating underlying evidence."""

    service = _investigation_service_from_request(request)
    filter_query = EvidenceFilterQuery(
        source=source,
        severity=severity,
        role=role,
        observation_level=observation_level,
        process=process,
        function=function,
        technique=technique,
        query=query,
    )
    return service.filter_evidence(sample_id, filter_query)


@router.post(
    "/{sample_id}/bookmarks",
    response_model=BookmarkResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_bookmark(
    request: Request,
    sample_id: str,
    body: BookmarkCreateRequest,
) -> BookmarkResponse:
    """Create and attach an analyst bookmark to a finding or telemetry artifact."""

    service = _investigation_service_from_request(request)
    bookmark = service.create_bookmark(sample_id, body)
    return BookmarkResponse(bookmark=bookmark)


@router.get("/{sample_id}/bookmarks", response_model=BookmarksListResponse)
async def list_bookmarks(request: Request, sample_id: str) -> BookmarksListResponse:
    """List all analyst bookmarks for a sample."""

    service = _investigation_service_from_request(request)
    bookmarks = service.list_bookmarks(sample_id)
    return BookmarksListResponse(sample_id=sample_id, bookmarks=bookmarks)


@router.delete("/{sample_id}/bookmarks/{bookmark_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_bookmark(request: Request, sample_id: str, bookmark_id: str) -> Response:
    """Delete an analyst bookmark by ID."""

    service = _investigation_service_from_request(request)
    service.delete_bookmark(sample_id, bookmark_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{sample_id}/notes",
    response_model=NoteResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_note(
    request: Request,
    sample_id: str,
    body: NoteCreateRequest,
) -> NoteResponse:
    """Create an analyst-authored note strictly separated from automated evidence."""

    service = _investigation_service_from_request(request)
    note = service.create_note(sample_id, body)
    return NoteResponse(note=note)


@router.get("/{sample_id}/notes", response_model=NotesListResponse)
async def list_notes(request: Request, sample_id: str) -> NotesListResponse:
    """List all analyst notes for a sample."""

    service = _investigation_service_from_request(request)
    notes = service.list_notes(sample_id)
    return NotesListResponse(sample_id=sample_id, notes=notes)


@router.patch("/{sample_id}/notes/{note_id}", response_model=NoteResponse)
async def update_note(
    request: Request,
    sample_id: str,
    note_id: str,
    body: NoteUpdateRequest,
) -> NoteResponse:
    """Update an analyst note's title, content, attachments, or tags."""

    service = _investigation_service_from_request(request)
    note = service.update_note(sample_id, note_id, body)
    return NoteResponse(note=note)


@router.delete("/{sample_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_note(request: Request, sample_id: str, note_id: str) -> Response:
    """Delete an analyst note by ID."""

    service = _investigation_service_from_request(request)
    service.delete_note(sample_id, note_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{sample_id}/report", response_model=ReportCreateResponse)
async def generate_report(request: Request, sample_id: str) -> ReportCreateResponse:
    """Generate a structured, machine-readable investigation report."""

    service = _reporting_service_from_request(request)
    report = service.generate_report(sample_id)
    return ReportCreateResponse(report=report)


@router.get("/{sample_id}/report/json")
async def get_report_json(request: Request, sample_id: str) -> Response:
    """Export machine-readable deterministic investigation report as JSON."""

    service = _reporting_service_from_request(request)
    json_str = service.get_report_json(sample_id)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="igris-report-{sample_id}.json"'},
    )


@router.get("/{sample_id}/report/pdf")
async def get_report_pdf(request: Request, sample_id: str) -> Response:
    """Export investigation report as a sanitized, multi-page PDF document."""

    service = _reporting_service_from_request(request)
    pdf_bytes = service.get_report_pdf(sample_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="igris-report-{sample_id}.pdf"'},
    )


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


def _similarity_service_from_request(request: Request) -> SimilarityService:
    return SimilarityService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )


def _assessment_service_from_request(request: Request) -> AssessmentService:
    return AssessmentService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )


def _investigation_service_from_request(request: Request) -> InvestigationService:
    return InvestigationService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )


def _reporting_service_from_request(request: Request) -> ReportingService:
    return ReportingService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
    )
