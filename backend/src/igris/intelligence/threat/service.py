"""Application service for Phase 5 threat-intelligence assessment."""

from datetime import UTC, datetime
from pathlib import Path

from igris.analysis.reverse_analysis.service import ReverseAnalysisService
from igris.analysis.static_analysis.service import StaticAnalysisService
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.intelligence.threat.mapper import build_threat_assessment, load_mapping_dataset
from igris.schemas.threat_intelligence import (
    CapabilitiesResponse,
    EvidenceRelationshipsResponse,
    NarrativeResponse,
    TechniquesResponse,
    ThreatAssessmentResponse,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class ThreatIntelligenceService:
    """Build and cache Phase 5 intelligence from existing analyses."""

    def __init__(
        self,
        *,
        settings: Settings,
        sample_storage: LocalSampleStorage,
        metadata_repository: SampleMetadataRepository,
    ) -> None:
        self.settings = settings
        self.sample_storage = sample_storage
        self.metadata_repository = metadata_repository

    def run(self, sample_id: str) -> ThreatAssessmentResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.threat_assessment is not None:
            return ThreatAssessmentResponse(threat_assessment=sample.threat_assessment)

        static_service = StaticAnalysisService(
            settings=self.settings,
            sample_storage=self.sample_storage,
            metadata_repository=self.metadata_repository,
        )
        reverse_service = ReverseAnalysisService(
            settings=self.settings,
            sample_storage=self.sample_storage,
            metadata_repository=self.metadata_repository,
        )
        static_analysis = static_service.run(sample_id).analysis
        reverse_analysis = reverse_service.run(sample_id).reverse_analysis
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)

        dataset = load_mapping_dataset(Path(self.settings.intelligence_mapping_path))
        assessment = build_threat_assessment(
            sample_id=sample_id,
            engine_version=self.settings.intelligence_engine_version,
            dataset=dataset,
            static_evidence=static_analysis.evidence,
            strings=static_analysis.strings,
            imports=static_analysis.imports,
            reverse_evidence=reverse_analysis.evidence,
        )
        sample.threat_assessment = assessment
        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return ThreatAssessmentResponse(threat_assessment=assessment)

    def get(self, sample_id: str) -> ThreatAssessmentResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.threat_assessment is None:
            raise AppError(
                "Threat assessment has not been run for this sample",
                code="threat_assessment_not_found",
                status_code=404,
            )
        return ThreatAssessmentResponse(threat_assessment=sample.threat_assessment)

    def capabilities(self, sample_id: str) -> CapabilitiesResponse:
        assessment = self.get(sample_id).threat_assessment
        return CapabilitiesResponse(sample_id=sample_id, capabilities=assessment.capabilities)

    def techniques(self, sample_id: str) -> TechniquesResponse:
        assessment = self.get(sample_id).threat_assessment
        return TechniquesResponse(sample_id=sample_id, techniques=assessment.techniques)

    def relationships(self, sample_id: str) -> EvidenceRelationshipsResponse:
        assessment = self.get(sample_id).threat_assessment
        return EvidenceRelationshipsResponse(
            sample_id=sample_id, evidence_graph=assessment.evidence_graph
        )

    def narrative(self, sample_id: str) -> NarrativeResponse:
        assessment = self.get(sample_id).threat_assessment
        return NarrativeResponse(sample_id=sample_id, narrative=assessment.narrative)
