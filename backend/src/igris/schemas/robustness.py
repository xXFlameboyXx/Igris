"""Schemas for Phase 16 Robustness, Perturbation Testing, and Adversarial Resilience."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from igris.schemas.assessment import AssessmentVerdict


class TransformationType(StrEnum):
    """Controlled, safe binary/metadata transformation types for robustness evaluation."""

    FILENAME_RENAME = "FILENAME_RENAME"
    METADATA_MUTATION = "METADATA_MUTATION"
    STRING_PADDING = "STRING_PADDING"
    SECTION_OVERLAY_PADDING = "SECTION_OVERLAY_PADDING"
    INSTRUCTION_NOP_INSERTION = "INSTRUCTION_NOP_INSERTION"
    SYNTHETIC_PACKING_SIMULATION = "SYNTHETIC_PACKING_SIMULATION"
    COMPILER_FLAG_VARIATION = "COMPILER_FLAG_VARIATION"


class DegradationSeverity(StrEnum):
    """Categorical severity of analytical metric or score degradation."""

    NONE = "NONE"  # Zero delta or <= 1% variation
    LOW = "LOW"  # Minor score fluctuation, verdict completely unaffected
    MODERATE = "MODERATE"  # Noticeable score drift, verdict remains accurate with wider uncertainty
    SEVERE = "SEVERE"  # Detection bypassed or operational verdict flipped


class EngineSensitivity(BaseModel):
    """Empirical sensitivity measurement of an individual analysis engine under transformation."""

    model_config = ConfigDict(extra="forbid")

    engine_name: str
    baseline_score: float
    transformed_score: float
    absolute_delta: float
    degradation_severity: DegradationSeverity
    notes: str = ""


class RobustnessMatrixRow(BaseModel):
    """Row in the empirical robustness matrix mapping transformation to per-engine sensitivity."""

    model_config = ConfigDict(extra="forbid")

    transformation_type: TransformationType
    transformation_description: str
    static_sensitivity: EngineSensitivity
    reverse_sensitivity: EngineSensitivity
    ml_sensitivity: EngineSensitivity
    similarity_sensitivity: EngineSensitivity
    behavior_sensitivity: EngineSensitivity
    final_verdict_sensitivity: EngineSensitivity
    overall_stability: DegradationSeverity


class BenignStressCategory(StrEnum):
    """Categories of legitimate software containing suspicious-looking characteristics."""

    ADMIN_TOOL = "ADMIN_TOOL"
    INSTALLER_COMPRESSOR = "INSTALLER_COMPRESSOR"
    DEVELOPER_DEBUGGER = "DEVELOPER_DEBUGGER"
    NETWORK_UTILITY = "NETWORK_UTILITY"


class FalsePositiveStressTestResult(BaseModel):
    """Evaluation result for complex benign software containing suspicious characteristics."""

    model_config = ConfigDict(extra="forbid")

    sample_name: str
    category: BenignStressCategory
    suspicious_characteristics: list[str]
    baseline_verdict: AssessmentVerdict
    risk_score: int
    overreaction_flag: bool  # True if incorrectly judged HIGHLY_SUSPICIOUS
    mitigating_evidence: list[str]
    epistemological_reasoning: str


class FailureAnalysisRecord(BaseModel):
    """Structured root-cause diagnosis of discovered engine failure or sensitivity limitation."""

    model_config = ConfigDict(extra="forbid")

    failure_id: str
    vulnerable_engine: str
    transformation_or_scenario: str
    observed_failure: str
    root_cause: str
    mitigation_strategy: str
    fp_risk_of_mitigation: str
    status: Literal["OBSERVED_LIMITATION", "RESOLVED_LIMITATION"]


class RobustnessEvaluationReport(BaseModel):
    """Complete, machine-readable robustness and perturbation evaluation report."""

    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(default_factory=lambda: f"rob-{uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    matrix_rows: list[RobustnessMatrixRow] = Field(default_factory=list)
    false_positive_tests: list[FalsePositiveStressTestResult] = Field(default_factory=list)
    failure_records: list[FailureAnalysisRecord] = Field(default_factory=list)
    mean_stability_score: float = 0.0  # 0.0 - 1.0 (1.0 = completely stable)
    fp_resilience_rate: float = 1.0  # Proportion of benign stress samples correctly cleared
    summary: str = ""
    threats_to_validity: list[str] = Field(default_factory=list)


# =============================================================================
# API Request / Response Schemas
# =============================================================================


class RobustnessEvaluateRequest(BaseModel):
    """Request payload to initiate a controlled robustness evaluation."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str | None = None
    include_stress_tests: bool = True
    random_seed: int = 42


class RobustnessReportResponse(BaseModel):
    """API response containing full robustness evaluation report."""

    model_config = ConfigDict(extra="forbid")

    report: RobustnessEvaluationReport


class RobustnessMatrixResponse(BaseModel):
    """API response containing the empirical robustness matrix rows."""

    model_config = ConfigDict(extra="forbid")

    report_id: str
    matrix_rows: list[RobustnessMatrixRow]
    mean_stability_score: float


class FalsePositiveTestsResponse(BaseModel):
    """API response containing benign stress test results."""

    model_config = ConfigDict(extra="forbid")

    report_id: str
    false_positive_tests: list[FalsePositiveStressTestResult]
    fp_resilience_rate: float


class RobustnessReportListResponse(BaseModel):
    """API response listing registered robustness reports."""

    model_config = ConfigDict(extra="forbid")

    reports: list[RobustnessEvaluationReport]
    total_count: int
