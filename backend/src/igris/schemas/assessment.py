"""Phase 11: Explainable Malware Assessment Schemas."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AssessmentVerdict(StrEnum):
    """Explainable overall assessment verdict without absolute safe claims."""

    BENIGN = "BENIGN"
    LIKELY_BENIGN = "LIKELY_BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGHLY_SUSPICIOUS = "HIGHLY_SUSPICIOUS"
    UNKNOWN = "UNKNOWN"


class RiskLevel(StrEnum):
    """Categorical risk tier corresponding to the evidence-backed risk score."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class ObservationLevel(StrEnum):
    """Strict epistemological classification of analytical statements."""

    OBSERVED = "OBSERVED"  # Directly supported by raw artifact/telemetry observation
    INFERRED = "INFERRED"  # Derived conclusion or behavioral interpretation
    POSSIBLE = "POSSIBLE"  # Unproven hypothesis or structural cluster suggestion


class EvidenceRole(StrEnum):
    """Directional contribution of an evidence item toward suspiciousness."""

    SUPPORTING = "SUPPORTING"  # Supports malicious / suspicious assessment
    CONTRADICTING = "CONTRADICTING"  # Contradicts suspiciousness (supports benignity / cleanliness)
    NEUTRAL = "NEUTRAL"  # Informational or contextual without strong directional bias


class EvidenceCategory(StrEnum):
    """Originating subsystem category for an evidence item."""

    STATIC = "static"
    REVERSE = "reverse"
    BEHAVIOR = "behavior"
    RULES = "rules"
    ML = "ml"
    SIMILARITY = "similarity"


class EvidenceStrength(StrEnum):
    """Weight and qualitative conviction of an individual evidence finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ConfidenceLevel(StrEnum):
    """Distinct multi-dimensional confidence rating."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNAVAILABLE = "UNAVAILABLE"


class AssessmentEvidenceItem(BaseModel):
    """Traceable, normalized evidence record from an analysis engine."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    category: EvidenceCategory
    source: str
    source_id: str | None = None
    statement: str
    evidence_type: str
    observation_level: ObservationLevel
    role: EvidenceRole
    strength: EvidenceStrength
    weight: float = Field(ge=0.0, le=1.0)
    provenance: str
    technical_details: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


class ConfidenceBreakdown(BaseModel):
    """Multi-dimensional confidence metrics separating detection from attribution."""

    model_config = ConfigDict(extra="forbid")

    detection_confidence: ConfidenceLevel
    evidence_quality: ConfidenceLevel
    behavioral_confidence: ConfidenceLevel
    similarity_confidence: ConfidenceLevel
    attribution_confidence: ConfidenceLevel
    attribution_scope: str = "cluster_only"
    explanation: str


class UncertaintyItem(BaseModel):
    """Explicitly tracked gap or limitation in available analysis artifacts."""

    model_config = ConfigDict(extra="forbid")

    category: str
    reason: str
    impact: str


class RiskFactor(BaseModel):
    """Contributing factor in the deterministic evidence score formula."""

    model_config = ConfigDict(extra="forbid")

    name: str
    category: EvidenceCategory
    points: float
    description: str
    observation_level: ObservationLevel


class RiskScoreDetails(BaseModel):
    """Deterministic evidence-backed risk score (not a probability)."""

    model_config = ConfigDict(extra="forbid")

    score: int = Field(ge=0, le=100)
    formula: str
    contributing_factors: list[RiskFactor]
    mitigating_factors: list[RiskFactor]
    unknown_factors: list[str]


class HumanExplanation(BaseModel):
    """Structured analyst-readable narrative separating epistemological categories."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    observed_findings: list[str]
    inferred_findings: list[str]
    possible_hypotheses: list[str]
    supporting_arguments: list[str]
    contradicting_arguments: list[str]
    uncertainty_and_unknowns: list[str]
    limitations: list[str]


class VerdictSummary(BaseModel):
    """Compact verdict summary for quick triage."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    verdict: AssessmentVerdict
    risk_level: RiskLevel
    risk_score: RiskScoreDetails
    confidence: ConfidenceBreakdown
    summary: str
    limitations: list[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvidenceSummary(BaseModel):
    """Aggregated evidence catalog and contradiction report."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    total_evidence_count: int
    supporting_count: int
    contradicting_count: int
    neutral_count: int
    observed_count: int
    inferred_count: int
    possible_count: int
    evidence_items: list[AssessmentEvidenceItem]
    disagreements: list[str]
    uncertainties: list[UncertaintyItem]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExplainableAssessment(BaseModel):
    """Complete Phase 11 explainable malware assessment report."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    schema_version: str = "assessment/v1"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    verdict: AssessmentVerdict
    risk_level: RiskLevel
    risk_score: RiskScoreDetails
    confidence: ConfidenceBreakdown
    explanation: HumanExplanation
    evidence_summary: EvidenceSummary
    limitations: list[str]
    provenance: str = "explainable_assessment_engine:v1"


class VerdictResponse(BaseModel):
    """API response for GET /api/v1/samples/{id}/verdict."""

    model_config = ConfigDict(extra="forbid")

    verdict: VerdictSummary


class ExplanationResponse(BaseModel):
    """API response for GET /api/v1/samples/{id}/explanation."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    verdict: AssessmentVerdict
    explanation: HumanExplanation
    created_at: datetime


class EvidenceSummaryResponse(BaseModel):
    """API response for GET /api/v1/samples/{id}/evidence-summary."""

    model_config = ConfigDict(extra="forbid")

    evidence_summary: EvidenceSummary


class AssessmentResponse(BaseModel):
    """API response for complete assessment."""

    model_config = ConfigDict(extra="forbid")

    assessment: ExplainableAssessment
