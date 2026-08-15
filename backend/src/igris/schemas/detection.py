"""Normalized Phase 3 detection schemas."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from igris.schemas.behavior_analysis import BehaviorEvidence
from igris.schemas.static_analysis import EvidenceSeverity, StaticEvidence


class DetectionStatus(StrEnum):
    """Evidence-based detection assessment status."""

    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGHLY_SUSPICIOUS = "HIGHLY_SUSPICIOUS"
    UNKNOWN = "UNKNOWN"


class DetectionRunStatus(StrEnum):
    """Lifecycle status for the detection engine."""

    COMPLETED = "completed"
    FAILED = "failed"


class RuleSeverity(StrEnum):
    """Rule severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RuleCondition(BaseModel):
    """Declarative rule condition."""

    model_config = ConfigDict(extra="forbid")

    field: str
    operator: str
    value: str | int | float | bool | list[str] | None = None


class DetectionRule(BaseModel):
    """Versioned declarative detection rule."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    name: str
    description: str
    severity: RuleSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    conditions: list[RuleCondition]
    evidence: str
    version: str
    contribution: float = Field(ge=0.0, le=10.0)


class TriggeredRule(BaseModel):
    """Rule that matched the sample."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    name: str
    version: str
    severity: RuleSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    contribution: float
    explanation: str
    matched_conditions: list[RuleCondition]


class HeuristicFinding(BaseModel):
    """Deterministic heuristic finding."""

    model_config = ConfigDict(extra="forbid")

    heuristic_id: str
    name: str
    category: str
    severity: EvidenceSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    contribution: float
    explanation: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)


class ScoreContribution(BaseModel):
    """A transparent contribution to the heuristic risk score."""

    model_config = ConfigDict(extra="forbid")

    source: str
    label: str
    contribution: float
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class ScoreBreakdown(BaseModel):
    """Score details for explainable detection."""

    model_config = ConfigDict(extra="forbid")

    rule_contributions: list[ScoreContribution]
    heuristic_contributions: list[ScoreContribution]
    evidence_contributions: list[ScoreContribution]
    total: float
    maximum: float = 10.0


class DetectionResult(BaseModel):
    """Evidence-based Phase 3 detection assessment."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    status: DetectionStatus
    run_status: DetectionRunStatus
    heuristic_score: float = Field(ge=0.0, le=10.0)
    triggered_rules: list[TriggeredRule]
    heuristics: list[HeuristicFinding]
    evidence: list[StaticEvidence]
    behavior_evidence: list[BehaviorEvidence] = Field(default_factory=list)
    severity: EvidenceSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    score_breakdown: ScoreBreakdown
    engine_version: str
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    limitations: list[str] = Field(default_factory=list)


class DetectionResponse(BaseModel):
    """API response for detection assessment."""

    model_config = ConfigDict(extra="forbid")

    detection: DetectionResult
