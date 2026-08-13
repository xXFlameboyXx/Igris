"""Normalized Phase 6 machine-learning schemas."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ML_FEATURE_SCHEMA_VERSION = "ml-static-reverse-feature-vector/v1"


class MLLabel(StrEnum):
    """Dataset and prediction labels."""

    BENIGN = "benign"
    MALWARE = "malware"


class MLFeatureSet(StrEnum):
    """Ablation-ready feature set definitions."""

    STATIC_ONLY = "static_only"
    STATIC_REVERSE = "static_reverse"
    STATIC_FUTURE_BEHAVIOR = "static_future_behavior"


class MLModelKind(StrEnum):
    """Supported baseline model families."""

    LOGISTIC_REGRESSION = "logistic_regression"
    RANDOM_FOREST = "random_forest"
    GRADIENT_BOOSTING = "gradient_boosting"


class DatasetSplit(StrEnum):
    """Dataset split assignment."""

    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


class MLFeatureVector(BaseModel):
    """Versioned ML feature vector derived from previous analysis phases."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    feature_schema_version: str = ML_FEATURE_SCHEMA_VERSION
    feature_set: MLFeatureSet
    features: dict[str, float]
    missing_features: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class LabeledFeatureRecord(BaseModel):
    """One labeled dataset row for reproducible experiments."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    label: MLLabel
    split: DatasetSplit | None = None
    family: str | None = None
    source: str
    license: str
    feature_schema_version: str
    feature_set: MLFeatureSet
    features: dict[str, float]


class DatasetManifest(BaseModel):
    """Versioned dataset manifest for Phase 6 experiments."""

    model_config = ConfigDict(extra="forbid")

    dataset_version: str
    name: str
    description: str
    provenance: str
    license: str
    records: list[LabeledFeatureRecord]
    limitations: list[str] = Field(default_factory=list)


class SplitSummary(BaseModel):
    """Count summary for a split."""

    model_config = ConfigDict(extra="forbid")

    train: int
    validation: int
    test: int
    family_aware: bool
    duplicate_sha256_removed: int
    leakage_warnings: list[str] = Field(default_factory=list)


class ConfusionMatrix(BaseModel):
    """Binary confusion matrix using malware as the positive class."""

    model_config = ConfigDict(extra="forbid")

    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int


class EvaluationMetrics(BaseModel):
    """Baseline model evaluation metrics."""

    model_config = ConfigDict(extra="forbid")

    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    roc_auc: float | None = None
    inference_time_ms_per_sample: float
    confusion_matrix: ConfusionMatrix


class ExperimentModelResult(BaseModel):
    """One model's result inside an experiment."""

    model_config = ConfigDict(extra="forbid")

    model_kind: MLModelKind
    hyperparameters: dict[str, Any]
    validation_metrics: EvaluationMetrics
    test_metrics: EvaluationMetrics
    selected: bool = False
    important_features: list[tuple[str, float]] = Field(default_factory=list)


class MLExperimentResult(BaseModel):
    """Reproducible baseline experiment summary."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str
    dataset_version: str
    feature_schema_version: str
    feature_set: MLFeatureSet
    trained_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    split_summary: SplitSummary
    models: list[ExperimentModelResult]
    selected_model_version: str
    limitations: list[str] = Field(default_factory=list)


class ModelMetadata(BaseModel):
    """Versioned trained model metadata."""

    model_config = ConfigDict(extra="forbid")

    model_version: str
    model_kind: MLModelKind
    feature_schema_version: str
    feature_set: MLFeatureSet
    dataset_version: str
    trained_at: datetime
    hyperparameters: dict[str, Any]
    metrics: EvaluationMetrics
    feature_names: list[str]
    important_features: list[tuple[str, float]]
    artifact_path: str
    limitations: list[str] = Field(default_factory=list)


class ModelRegistry(BaseModel):
    """Model registry document exposed by the metadata endpoint."""

    model_config = ConfigDict(extra="forbid")

    registry_version: str
    active_model_version: str
    models: list[ModelMetadata]
    experiments: list[MLExperimentResult]
    limitations: list[str] = Field(default_factory=list)


class MLPrediction(BaseModel):
    """ML prediction as one evidence source, not a malware verdict."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    model_version: str
    feature_schema_version: str
    feature_set: MLFeatureSet
    prediction: MLLabel
    calibrated_probability: None = None
    score: float
    uncertainty: Literal["low", "medium", "high"]
    important_contributing_features: list[tuple[str, float]]
    explanation: str
    limitations: list[str] = Field(default_factory=list)


class ModelMetadataResponse(BaseModel):
    """API response for model registry metadata."""

    model_config = ConfigDict(extra="forbid")

    registry: ModelRegistry


class MLPredictionResponse(BaseModel):
    """API response for model inference."""

    model_config = ConfigDict(extra="forbid")

    prediction: MLPrediction


class ExperimentResultsResponse(BaseModel):
    """API response for experiment results."""

    model_config = ConfigDict(extra="forbid")

    experiments: list[MLExperimentResult]
