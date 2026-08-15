"""Phase 11: Explainable Malware Assessment Application Service."""

from igris.core.config import Settings
from igris.core.errors import AppError
from igris.intelligence.assessment.engine import AssessmentEngine
from igris.schemas.assessment import (
    EvidenceSummaryResponse,
    ExplainableAssessment,
    ExplanationResponse,
    VerdictResponse,
    VerdictSummary,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class AssessmentService:
    """Orchestrates explainable malware assessment generation, caching, and querying."""

    def __init__(
        self,
        settings: Settings,
        sample_storage: LocalSampleStorage,
        metadata_repository: SampleMetadataRepository,
        engine: AssessmentEngine | None = None,
    ) -> None:
        self.settings = settings
        self.sample_storage = sample_storage
        self.metadata_repository = metadata_repository
        self.engine = engine or AssessmentEngine()

    def get_or_run_assessment(self, sample_id: str) -> ExplainableAssessment:
        """Run or retrieve cached explainable malware assessment for a sample."""
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError(
                code="sample_not_found",
                message=f"Sample '{sample_id}' not found.",
                status_code=404,
            )

        if sample.malware_assessment is not None:
            return sample.malware_assessment

        assessment = self.engine.assess(sample)
        sample.malware_assessment = assessment
        self.metadata_repository.upsert(sample)
        return assessment

    def get_verdict(self, sample_id: str) -> VerdictResponse:
        """Return the structured verdict, risk score, and confidence breakdown."""
        assessment = self.get_or_run_assessment(sample_id)
        verdict_summary = VerdictSummary(
            sample_id=assessment.sample_id,
            sha256=assessment.sha256,
            verdict=assessment.verdict,
            risk_level=assessment.risk_level,
            risk_score=assessment.risk_score,
            confidence=assessment.confidence,
            summary=assessment.explanation.summary,
            limitations=assessment.limitations,
            created_at=assessment.created_at,
        )
        return VerdictResponse(verdict=verdict_summary)

    def get_explanation(self, sample_id: str) -> ExplanationResponse:
        """Return the structured narrative explanation separating epistemology."""
        assessment = self.get_or_run_assessment(sample_id)
        return ExplanationResponse(
            sample_id=assessment.sample_id,
            sha256=assessment.sha256,
            verdict=assessment.verdict,
            explanation=assessment.explanation,
            created_at=assessment.created_at,
        )

    def get_evidence_summary(self, sample_id: str) -> EvidenceSummaryResponse:
        """Return the complete aggregated evidence breakdown, contradictions, and uncertainties."""
        assessment = self.get_or_run_assessment(sample_id)
        return EvidenceSummaryResponse(evidence_summary=assessment.evidence_summary)
