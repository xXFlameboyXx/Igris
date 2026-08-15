from pathlib import Path

from fastapi.testclient import TestClient

from igris.analysis.behavioral.synthetic import SyntheticBehaviorAnalyzer
from igris.analysis.reverse_analysis.service import ReverseAnalysisService
from igris.analysis.static_analysis.service import StaticAnalysisService
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.main import create_app
from igris.ml.dataset import load_dataset_manifest, prepare_dataset_splits
from igris.ml.features import build_ml_feature_vector, vectorize_features
from igris.ml.registry import get_model_metadata, load_model_artifact, load_model_registry
from igris.ml.service import predict_from_features
from igris.schemas.behavior_analysis import SyntheticScenario
from igris.schemas.ml import DatasetSplit, MLFeatureSet, MLLabel, MLModelKind

from .fixtures import static_suspicious_pe_fixture


def make_client(tmp_path: Path) -> TestClient:
    app = create_app(
        Settings(
            environment="test",
            metadata_backend="memory",
            sample_storage_dir=str(tmp_path / "samples"),
            sample_temp_dir=str(tmp_path / "tmp"),
            ml_dataset_manifest_path="config/ml/synthetic_dataset.json",
            ml_model_registry_path="config/ml/model_registry.json",
            ml_model_dir="config/ml/models",
            reverse_max_instructions=200,
            reverse_max_functions=16,
            static_high_entropy_threshold=6.0,
        )
    )
    return TestClient(app)


def upload(client: TestClient, content: bytes, filename: str = "sample.bin") -> str:
    response = client.post(
        "/api/v1/samples",
        files={"file": (filename, content, "application/octet-stream")},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["sample_id"])


def test_dataset_ingestion_labeling_and_splitting() -> None:
    dataset = load_dataset_manifest(Path("config/ml/synthetic_dataset.json"))
    splits, summary = prepare_dataset_splits(dataset.records, family_aware=True)

    assert dataset.dataset_version == "synthetic-phase6/v1"
    assert {record.label for record in dataset.records} == {MLLabel.BENIGN, MLLabel.MALWARE}
    assert len(splits[DatasetSplit.TRAIN]) == 4
    assert len(splits[DatasetSplit.VALIDATION]) == 4
    assert len(splits[DatasetSplit.TEST]) == 4
    assert summary.duplicate_sha256_removed == 0
    assert summary.leakage_warnings == []


def test_feature_extraction_is_deterministic(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "synthetic.exe")
        settings = client.app.state.settings
        storage = client.app.state.sample_storage
        repository = client.app.state.metadata_repository
        static = (
            StaticAnalysisService(
                settings=settings,
                sample_storage=storage,
                metadata_repository=repository,
            )
            .run(sample_id)
            .analysis
        )
        reverse = (
            ReverseAnalysisService(
                settings=settings,
                sample_storage=storage,
                metadata_repository=repository,
            )
            .run(sample_id)
            .reverse_analysis
        )
        sample = repository.get(sample_id)
        assert sample is not None
        first = build_ml_feature_vector(
            sample=sample,
            static_analysis=static,
            reverse_analysis=reverse,
            feature_set=MLFeatureSet.STATIC_REVERSE,
        )
        second = build_ml_feature_vector(
            sample=sample,
            static_analysis=static,
            reverse_analysis=reverse,
            feature_set=MLFeatureSet.STATIC_REVERSE,
        )

    assert first == second
    assert first.feature_schema_version == "ml-static-reverse-feature-vector/v1"
    assert first.features["file_size_bytes"] > 0
    assert first.features["string_count.url"] >= 1
    assert first.features["api_category_count.networking"] >= 1


def test_future_behavior_feature_set_uses_cached_behavior_only(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "synthetic.exe")
        settings = client.app.state.settings
        storage = client.app.state.sample_storage
        repository = client.app.state.metadata_repository
        static = (
            StaticAnalysisService(
                settings=settings,
                sample_storage=storage,
                metadata_repository=repository,
            )
            .run(sample_id)
            .analysis
        )
        reverse = (
            ReverseAnalysisService(
                settings=settings,
                sample_storage=storage,
                metadata_repository=repository,
            )
            .run(sample_id)
            .reverse_analysis
        )
        sample = repository.get(sample_id)
        assert sample is not None
        without_behavior = build_ml_feature_vector(
            sample=sample,
            static_analysis=static,
            reverse_analysis=reverse,
            feature_set=MLFeatureSet.STATIC_FUTURE_BEHAVIOR,
        )
        sample.behavior_analysis = SyntheticBehaviorAnalyzer().analyze(
            sample_id=sample_id,
            scenario=SyntheticScenario.MULTI_STAGE_ACTIVITY,
        )
        with_behavior = build_ml_feature_vector(
            sample=sample,
            static_analysis=static,
            reverse_analysis=reverse,
            feature_set=MLFeatureSet.STATIC_FUTURE_BEHAVIOR,
        )

    assert without_behavior.features["behavior.event_count"] == 0.0
    assert with_behavior.features["behavior.event_count"] > 0.0
    assert with_behavior.features["behavior.network_connection_count"] == 1.0
    assert with_behavior.features["behavior.process_creation_count"] == 1.0


def test_model_registry_and_artifact_loading() -> None:
    registry = load_model_registry(Path("config/ml/model_registry.json"))
    metadata = get_model_metadata(registry)
    model = load_model_artifact(metadata)

    assert metadata.model_version == registry.active_model_version
    assert metadata.model_kind in {
        MLModelKind.LOGISTIC_REGRESSION,
        MLModelKind.RANDOM_FOREST,
        MLModelKind.GRADIENT_BOOSTING,
    }
    assert hasattr(model, "predict")
    assert metadata.metrics.f1 >= 0.0


def test_ml_metadata_and_experiment_endpoints(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        metadata_response = client.get("/api/v1/ml/model-metadata")
        experiments_response = client.get("/api/v1/ml/experiments")

    assert metadata_response.status_code == 200
    assert experiments_response.status_code == 200
    registry = metadata_response.json()["registry"]
    assert registry["active_model_version"]
    model_kinds = {
        item["model_kind"] for item in experiments_response.json()["experiments"][0]["models"]
    }
    assert {
        "logistic_regression",
        "random_forest",
        "gradient_boosting",
    } == model_kinds


def test_ml_inference_and_cached_prediction(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "synthetic.exe")
        run_response = client.post(f"/api/v1/samples/{sample_id}/ml-prediction")
        get_response = client.get(f"/api/v1/samples/{sample_id}/ml-prediction")

    assert run_response.status_code == 200, run_response.text
    assert get_response.status_code == 200
    prediction = run_response.json()["prediction"]
    assert prediction == get_response.json()["prediction"]
    assert prediction["feature_schema_version"] == "ml-static-reverse-feature-vector/v1"
    assert prediction["prediction"] in {"benign", "malware"}
    assert prediction["calibrated_probability"] is None
    assert prediction["important_contributing_features"]
    assert "additional evidence source" in prediction["explanation"]


def test_model_version_mismatch_fails_closed(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "synthetic.exe")
        response = client.post(
            f"/api/v1/samples/{sample_id}/ml-prediction?model_version=missing-model"
        )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ml_model_version_mismatch"


def test_missing_features_and_schema_mismatch_fail_closed() -> None:
    registry = load_model_registry(Path("config/ml/model_registry.json"))
    metadata = get_model_metadata(registry)
    model = load_model_artifact(metadata)

    try:
        predict_from_features(
            model=model,
            metadata=metadata,
            sample_id="sample",
            features={"file_size_bytes": 1.0},
            feature_schema_version=metadata.feature_schema_version,
        )
    except AppError as exc:
        assert exc.code == "ml_missing_features"
    else:
        raise AssertionError("missing model features should fail closed")

    try:
        predict_from_features(
            model=model,
            metadata=metadata,
            sample_id="sample",
            features=dict.fromkeys(metadata.feature_names, 0.0),
            feature_schema_version="wrong-schema/v1",
        )
    except AppError as exc:
        assert exc.code == "ml_feature_schema_mismatch"
    else:
        raise AssertionError("schema mismatch should fail closed")


def test_vectorize_reports_missing_features() -> None:
    values, missing = vectorize_features({"file_size_bytes": 12.0}, ["file_size_bytes", "x"])

    assert values == [12.0, 0.0]
    assert missing == ["x"]
