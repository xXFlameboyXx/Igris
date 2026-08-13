"""Reproducible baseline training and evaluation for Phase 6."""

from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

import joblib
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from igris.ml.dataset import prepare_dataset_splits
from igris.ml.features import ML_FEATURE_NAMES, vectorize_features
from igris.schemas.ml import (
    ConfusionMatrix,
    DatasetManifest,
    DatasetSplit,
    EvaluationMetrics,
    ExperimentModelResult,
    MLExperimentResult,
    MLFeatureSet,
    MLLabel,
    MLModelKind,
    ModelMetadata,
    ModelRegistry,
)

MODEL_BUILDERS: dict[MLModelKind, tuple[Any, dict[str, Any]]] = {
    MLModelKind.LOGISTIC_REGRESSION: (
        Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=1_000,
                        class_weight="balanced",
                        random_state=13,
                    ),
                ),
            ]
        ),
        {"max_iter": 1_000, "class_weight": "balanced", "random_state": 13},
    ),
    MLModelKind.RANDOM_FOREST: (
        RandomForestClassifier(
            n_estimators=64,
            max_depth=4,
            class_weight="balanced",
            random_state=13,
        ),
        {
            "n_estimators": 64,
            "max_depth": 4,
            "class_weight": "balanced",
            "random_state": 13,
        },
    ),
    MLModelKind.GRADIENT_BOOSTING: (
        GradientBoostingClassifier(
            n_estimators=64,
            learning_rate=0.05,
            max_depth=2,
            random_state=13,
        ),
        {
            "n_estimators": 64,
            "learning_rate": 0.05,
            "max_depth": 2,
            "random_state": 13,
        },
    ),
}


def run_baseline_experiment(
    *,
    dataset: DatasetManifest,
    output_dir: Path,
    feature_set: MLFeatureSet = MLFeatureSet.STATIC_REVERSE,
) -> ModelRegistry:
    """Train baseline models and persist the selected versioned model artifact."""

    output_dir.mkdir(parents=True, exist_ok=True)
    records = [record for record in dataset.records if record.feature_set == feature_set]
    splits, split_summary = prepare_dataset_splits(records, family_aware=True)
    feature_names = ML_FEATURE_NAMES
    train_x, train_y = _matrix(splits[DatasetSplit.TRAIN], feature_names)
    validation_x, validation_y = _matrix(splits[DatasetSplit.VALIDATION], feature_names)
    test_x, test_y = _matrix(splits[DatasetSplit.TEST], feature_names)

    results: list[ExperimentModelResult] = []
    trained_models: dict[MLModelKind, Any] = {}
    trained_at = datetime.now(UTC)
    for model_kind, (model, hyperparameters) in MODEL_BUILDERS.items():
        model.fit(train_x, train_y)
        trained_models[model_kind] = model
        validation_metrics = _evaluate(model, validation_x, validation_y)
        test_metrics = _evaluate(model, test_x, test_y)
        results.append(
            ExperimentModelResult(
                model_kind=model_kind,
                hyperparameters=hyperparameters,
                validation_metrics=validation_metrics,
                test_metrics=test_metrics,
                important_features=_important_features(model, feature_names),
            )
        )

    selected_kind = _select_model(results)
    safe_dataset_version = dataset.dataset_version.replace("/", "-")
    selected_version = f"{safe_dataset_version}-{selected_kind.value}-v1"
    selected_model = trained_models[selected_kind]
    selected_result = next(item for item in results if item.model_kind == selected_kind)
    artifact_path = output_dir / f"{selected_version}.joblib"
    joblib.dump(selected_model, artifact_path)

    selected_results = [
        item.model_copy(update={"selected": item.model_kind == selected_kind}) for item in results
    ]
    experiment = MLExperimentResult(
        experiment_id=f"{dataset.dataset_version}-{feature_set.value}-baseline",
        dataset_version=dataset.dataset_version,
        feature_schema_version=dataset.records[0].feature_schema_version,
        feature_set=feature_set,
        trained_at=trained_at,
        split_summary=split_summary,
        models=selected_results,
        selected_model_version=selected_version,
        limitations=[
            "Synthetic development data is not representative of real malware prevalence.",
            "Metrics are for pipeline validation and do not establish operational performance.",
            "Feature importance indicates model influence, not causal proof.",
        ],
    )
    model_metadata = ModelMetadata(
        model_version=selected_version,
        model_kind=selected_kind,
        feature_schema_version=dataset.records[0].feature_schema_version,
        feature_set=feature_set,
        dataset_version=dataset.dataset_version,
        trained_at=trained_at,
        hyperparameters=selected_result.hyperparameters,
        metrics=selected_result.test_metrics,
        feature_names=feature_names,
        important_features=selected_result.important_features,
        artifact_path=str(artifact_path),
        limitations=experiment.limitations,
    )
    return ModelRegistry(
        registry_version="ml-model-registry/v1",
        active_model_version=selected_version,
        models=[model_metadata],
        experiments=[experiment],
        limitations=[
            "Models are additional evidence sources and do not replace deterministic analysis.",
            "Calibrated probabilities are not exposed because probability calibration is not run.",
        ],
    )


def write_registry(registry: ModelRegistry, path: Path) -> None:
    """Persist a registry document next to model artifacts."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(registry.model_dump_json(indent=2), encoding="utf-8")


def _matrix(records: list[Any], feature_names: list[str]) -> tuple[list[list[float]], list[int]]:
    x: list[list[float]] = []
    y: list[int] = []
    for record in records:
        values, _missing = vectorize_features(record.features, feature_names)
        x.append(values)
        y.append(1 if record.label == MLLabel.MALWARE else 0)
    return x, y


def _evaluate(model: Any, x: list[list[float]], y: list[int]) -> EvaluationMetrics:
    started = perf_counter()
    predictions = list(model.predict(x))
    elapsed_ms = (perf_counter() - started) * 1000
    tn, fp, fn, tp = confusion_matrix(y, predictions, labels=[0, 1]).ravel()
    roc_auc: float | None = None
    if hasattr(model, "predict_proba") and len(set(y)) == 2:
        scores = [row[1] for row in model.predict_proba(x)]
        roc_auc = float(roc_auc_score(y, scores))
    denominator = fp + tn
    false_positive_rate = float(fp / denominator) if denominator else 0.0
    return EvaluationMetrics(
        precision=float(precision_score(y, predictions, zero_division=0)),
        recall=float(recall_score(y, predictions, zero_division=0)),
        f1=float(f1_score(y, predictions, zero_division=0)),
        false_positive_rate=false_positive_rate,
        roc_auc=roc_auc,
        inference_time_ms_per_sample=float(elapsed_ms / max(len(x), 1)),
        confusion_matrix=ConfusionMatrix(
            true_negative=int(tn),
            false_positive=int(fp),
            false_negative=int(fn),
            true_positive=int(tp),
        ),
    )


def _select_model(results: list[ExperimentModelResult]) -> MLModelKind:
    selected = max(
        results,
        key=lambda item: (
            item.validation_metrics.f1,
            -item.validation_metrics.false_positive_rate,
            item.test_metrics.f1,
        ),
    )
    return selected.model_kind


def _important_features(
    model: Any, feature_names: list[str], limit: int = 10
) -> list[tuple[str, float]]:
    classifier = model.named_steps["classifier"] if isinstance(model, Pipeline) else model
    if hasattr(classifier, "coef_"):
        raw_scores = list(abs(float(value)) for value in classifier.coef_[0])
    elif hasattr(classifier, "feature_importances_"):
        raw_scores = [float(value) for value in classifier.feature_importances_]
    else:
        raw_scores = [0.0 for _name in feature_names]
    pairs = sorted(
        zip(feature_names, raw_scores, strict=True),
        key=lambda item: item[1],
        reverse=True,
    )
    return [(name, score) for name, score in pairs[:limit] if score > 0.0]
