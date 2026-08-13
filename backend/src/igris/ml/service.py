"""Application service for Phase 6 ML metadata and inference."""

from datetime import UTC, datetime
from math import exp
from pathlib import Path
from typing import Any

from sklearn.pipeline import Pipeline

from igris.analysis.reverse_analysis.service import ReverseAnalysisService
from igris.analysis.static_analysis.service import StaticAnalysisService
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.ml.features import build_ml_feature_vector, vectorize_features
from igris.ml.registry import get_model_metadata, load_model_artifact, load_model_registry
from igris.schemas.ml import (
    ExperimentResultsResponse,
    MLLabel,
    MLPrediction,
    MLPredictionResponse,
    ModelMetadata,
    ModelMetadataResponse,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class MLService:
    """Expose ML registry metadata, experiment results, and sample inference."""

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

    def model_metadata(self) -> ModelMetadataResponse:
        registry = load_model_registry(Path(self.settings.ml_model_registry_path))
        return ModelMetadataResponse(registry=registry)

    def experiment_results(self) -> ExperimentResultsResponse:
        registry = load_model_registry(Path(self.settings.ml_model_registry_path))
        return ExperimentResultsResponse(experiments=registry.experiments)

    def predict(
        self, sample_id: str, model_version: str | None = None
    ) -> MLPredictionResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)

        registry = load_model_registry(Path(self.settings.ml_model_registry_path))
        metadata = get_model_metadata(registry, model_version)
        if sample.ml_prediction is not None:
            if sample.ml_prediction.model_version == metadata.model_version:
                return MLPredictionResponse(prediction=sample.ml_prediction)
            if model_version is None:
                raise AppError(
                    "Cached ML prediction was produced by a different model version",
                    code="ml_model_version_mismatch",
                    status_code=409,
                    details={
                        "cached": sample.ml_prediction.model_version,
                        "active": metadata.model_version,
                    },
                )

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

        feature_vector = build_ml_feature_vector(
            sample=sample,
            static_analysis=static_analysis,
            reverse_analysis=reverse_analysis,
            feature_set=metadata.feature_set,
        )
        prediction = predict_from_features(
            model=load_model_artifact(metadata),
            metadata=metadata,
            sample_id=sample_id,
            features=feature_vector.features,
            feature_schema_version=feature_vector.feature_schema_version,
        )
        sample.ml_prediction = prediction
        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return MLPredictionResponse(prediction=prediction)

    def get_prediction(self, sample_id: str) -> MLPredictionResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.ml_prediction is None:
            raise AppError(
                "ML prediction has not been run for this sample",
                code="ml_prediction_not_found",
                status_code=404,
            )
        return MLPredictionResponse(prediction=sample.ml_prediction)


def predict_from_features(
    *,
    model: Any,
    metadata: ModelMetadata,
    sample_id: str,
    features: dict[str, float],
    feature_schema_version: str,
) -> MLPrediction:
    """Run model inference against a validated feature vector."""

    if feature_schema_version != metadata.feature_schema_version:
        raise AppError(
            "ML feature schema does not match the selected model",
            code="ml_feature_schema_mismatch",
            status_code=409,
            details={
                "features": feature_schema_version,
                "model": metadata.feature_schema_version,
            },
        )

    values, missing = vectorize_features(features, metadata.feature_names)
    if missing:
        raise AppError(
            "ML feature vector is missing features required by the model",
            code="ml_missing_features",
            status_code=422,
            details={"missing": missing},
        )

    raw_prediction = int(model.predict([values])[0])
    score = _model_score(model, values)
    label = MLLabel.MALWARE if raw_prediction == 1 else MLLabel.BENIGN
    return MLPrediction(
        sample_id=sample_id,
        model_version=metadata.model_version,
        feature_schema_version=metadata.feature_schema_version,
        feature_set=metadata.feature_set,
        prediction=label,
        calibrated_probability=None,
        score=score,
        uncertainty=_uncertainty(score),
        important_contributing_features=_contributing_features(metadata, features),
        explanation=(
            "The ML classifier is an additional evidence source. The score is an "
            "uncalibrated model score, not a calibrated probability or standalone verdict."
        ),
        limitations=[
            "No probability calibration has been performed, so calibrated_probability is null.",
            "Feature importance is not causal proof.",
            "Training data provenance and split methodology limit how metrics should be read.",
        ],
    )


def _model_score(model: Any, values: list[float]) -> float:
    classifier = model.named_steps["classifier"] if isinstance(model, Pipeline) else model
    scorer = model if hasattr(model, "predict_proba") else classifier
    if hasattr(scorer, "predict_proba"):
        return float(scorer.predict_proba([values])[0][1])
    if hasattr(scorer, "decision_function"):
        raw = float(scorer.decision_function([values])[0])
        return 1.0 / (1.0 + exp(-raw))
    return 0.5


def _uncertainty(score: float) -> str:
    margin = abs(score - 0.5)
    if margin >= 0.35:
        return "low"
    if margin >= 0.15:
        return "medium"
    return "high"


def _contributing_features(
    metadata: ModelMetadata, features: dict[str, float]
) -> list[tuple[str, float]]:
    contributions: list[tuple[str, float]] = []
    for feature_name, importance in metadata.important_features:
        value = features.get(feature_name, 0.0)
        if value != 0.0:
            contributions.append((feature_name, float(value * importance)))
    return contributions[:10]
