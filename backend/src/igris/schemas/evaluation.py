"""Schemas for Phase 15 Experimental Evaluation, Datasets, Metrics, and Ablation Studies."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from igris.schemas.assessment import AssessmentVerdict, ObservationLevel
from igris.schemas.orchestration import JobStatus, PipelineStageName


class GroundTruthLabel(StrEnum):
    """Ground truth classification for evaluated samples."""

    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class EvaluationSplit(StrEnum):
    """Dataset partition splits."""

    TRAIN = "TRAIN"
    VALIDATION = "VALIDATION"
    TEST = "TEST"
    HELD_OUT_FAMILY = "HELD_OUT_FAMILY"


class SplitStrategy(StrEnum):
    """Methodology used to partition datasets without data leakage."""

    RANDOM = "RANDOM"
    STRATIFIED = "STRATIFIED"
    FAMILY_AWARE = "FAMILY_AWARE"
    TEMPORAL = "TEMPORAL"


class AblationConfigName(StrEnum):
    """Standardized ablation configurations for controlled research comparisons."""

    STATIC_ONLY = "STATIC_ONLY"
    STATIC_HEURISTICS = "STATIC_HEURISTICS"
    STATIC_REVERSE = "STATIC_REVERSE"
    STATIC_REVERSE_ML = "STATIC_REVERSE_ML"
    STATIC_REVERSE_BEHAVIOR = "STATIC_REVERSE_BEHAVIOR"
    FULL_IGRIS = "FULL_IGRIS"


class DatasetSampleRecord(BaseModel):
    """Individual sample metadata record within an evaluation dataset."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    label: GroundTruthLabel
    family: str | None = None
    split: EvaluationSplit = EvaluationSplit.TEST
    source: str = "Synthetic Fixture"
    format: str = "pe"
    file_size_bytes: int = 0
    tags: list[str] = Field(default_factory=list)


class EvaluationDataset(BaseModel):
    """Structured evaluation dataset manifest with provenance and inclusion criteria."""

    model_config = ConfigDict(extra="forbid")

    dataset_id: str
    dataset_version: str
    name: str
    description: str
    source: str
    license: str
    collection_methodology: str
    class_distribution: dict[str, int] = Field(default_factory=dict)
    family_distribution: dict[str, int] = Field(default_factory=dict)
    samples: list[DatasetSampleRecord] = Field(default_factory=list)
    inclusion_criteria: list[str] = Field(default_factory=list)
    exclusion_criteria: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ConfusionMatrix(BaseModel):
    """Confusion matrix tracking operational verdict alignment with ground truth."""

    model_config = ConfigDict(extra="forbid")

    tp: int = 0  # True Positives (Malicious classified as HIGHLY_SUSPICIOUS / SUSPICIOUS)
    fp: int = 0  # False Positives (Benign classified as SUSPICIOUS / HIGHLY_SUSPICIOUS)
    tn: int = 0  # True Negatives (Benign classified as BENIGN / LIKELY_BENIGN)
    fn: int = 0  # False Negatives (Malicious classified as BENIGN / LIKELY_BENIGN)
    unknown_count: int = 0  # Unclassified / UNKNOWN verdicts (preserved, never converted)


class ConfidenceInterval(BaseModel):
    """Statistical confidence interval for a metric (e.g. Wilson score interval)."""

    model_config = ConfigDict(extra="forbid")

    low: float
    high: float
    confidence_level: float = 0.95


class EvaluationMetrics(BaseModel):
    """Complete statistical evaluation metrics computed over a dataset split."""

    model_config = ConfigDict(extra="forbid")

    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    fpr: float | None = None  # False Positive Rate
    fnr: float | None = None  # False Negative Rate
    accuracy: float | None = None
    total_samples: int = 0
    evaluated_samples: int = 0
    unknown_verdicts: int = 0
    confusion_matrix: ConfusionMatrix
    confidence_intervals: dict[str, ConfidenceInterval] = Field(default_factory=dict)


class PerformanceMetrics(BaseModel):
    """Computational efficiency and throughput metrics collected during evaluation."""

    model_config = ConfigDict(extra="forbid")

    total_duration_ms: float = 0.0
    mean_sample_latency_ms: float = 0.0
    median_sample_latency_ms: float = 0.0
    p95_sample_latency_ms: float = 0.0
    per_stage_latency_ms: dict[str, float] = Field(default_factory=dict)
    throughput_samples_per_sec: float = 0.0
    successful_analyses: int = 0
    failed_analyses: int = 0
    timed_out_analyses: int = 0
    cancelled_analyses: int = 0


class ErrorRecord(BaseModel):
    """Structured diagnostic record for an individual false positive or false negative."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    ground_truth: GroundTruthLabel
    igris_verdict: AssessmentVerdict
    risk_score: int
    error_type: Literal["FALSE_POSITIVE", "FALSE_NEGATIVE", "UNKNOWN_VERDICT"]
    likely_cause_category: str
    explanation: str
    contributing_evidence: list[str] = Field(default_factory=list)
    available_stages: list[PipelineStageName] = Field(default_factory=list)
    observation_level: ObservationLevel = ObservationLevel.INFERRED


class AblationResult(BaseModel):
    """Evaluation result for a specific ablation pipeline configuration."""

    model_config = ConfigDict(extra="forbid")

    configuration_name: AblationConfigName
    enabled_stages: list[PipelineStageName]
    metrics: EvaluationMetrics
    performance: PerformanceMetrics
    error_count: int = 0


class ExperimentConfig(BaseModel):
    """Configuration specifying the parameters and research question of an experiment."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str = Field(default_factory=lambda: f"exp-{uuid4().hex[:12]}")
    research_question: str
    dataset_id: str
    dataset_version: str
    split_strategy: SplitStrategy = SplitStrategy.FAMILY_AWARE
    ablation_configurations: list[AblationConfigName] = Field(
        default_factory=lambda: [
            AblationConfigName.STATIC_ONLY,
            AblationConfigName.STATIC_HEURISTICS,
            AblationConfigName.STATIC_REVERSE,
            AblationConfigName.STATIC_REVERSE_ML,
            AblationConfigName.STATIC_REVERSE_BEHAVIOR,
            AblationConfigName.FULL_IGRIS,
        ]
    )
    random_seed: int = 42
    max_samples: int | None = None
    description: str = ""


class ExperimentReproducibilityMetadata(BaseModel):
    """Reproducibility parameters, code versions, and engine hashes."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str
    dataset_id: str
    dataset_version: str
    dataset_hash: str
    code_version: str
    pipeline_version: str
    engine_versions: dict[str, str] = Field(default_factory=dict)
    random_seed: int
    split_strategy: SplitStrategy
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExperimentRecord(BaseModel):
    """Persistent, machine-readable record of an executed research experiment."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str
    config: ExperimentConfig
    reproducibility: ExperimentReproducibilityMetadata
    status: JobStatus = JobStatus.QUEUED
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    ablation_results: list[AblationResult] = Field(default_factory=list)
    overall_metrics: EvaluationMetrics | None = None
    overall_performance: PerformanceMetrics | None = None
    error_analysis: list[ErrorRecord] = Field(default_factory=list)
    threats_to_validity: list[str] = Field(default_factory=list)
    conclusions: list[str] = Field(default_factory=list)


# =============================================================================
# API Request / Response Schemas
# =============================================================================


class ExperimentCreateRequest(BaseModel):
    """API request payload to define and execute an experiment."""

    model_config = ConfigDict(extra="forbid")

    research_question: str
    dataset_id: str
    dataset_version: str = "v1.0"
    split_strategy: SplitStrategy = SplitStrategy.FAMILY_AWARE
    ablation_configurations: list[AblationConfigName] | None = None
    random_seed: int = 42
    max_samples: int | None = None
    description: str = ""


class ExperimentResponse(BaseModel):
    """API response containing full experiment record."""

    model_config = ConfigDict(extra="forbid")

    experiment: ExperimentRecord


class ExperimentListResponse(BaseModel):
    """API response listing registered experiments."""

    model_config = ConfigDict(extra="forbid")

    experiments: list[ExperimentRecord]
    total_count: int


class ExperimentResultsResponse(BaseModel):
    """API response containing detailed ablation results and error taxonomy."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str
    ablation_results: list[AblationResult]
    error_analysis: list[ErrorRecord]
    overall_metrics: EvaluationMetrics | None = None
    overall_performance: PerformanceMetrics | None = None


class ExperimentArtifactsResponse(BaseModel):
    """API response providing downloadable JSON research artifacts."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str
    reproducibility_metadata: ExperimentReproducibilityMetadata
    json_report: str
    summary_markdown: str
