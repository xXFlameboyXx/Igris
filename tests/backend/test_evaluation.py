"""Backend tests for Phase 15 experimental evaluation and research infrastructure."""

from pathlib import Path

from fastapi.testclient import TestClient

from igris import __version__
from igris.core.config import Settings
from igris.evaluation.service import EvaluationService
from igris.main import create_app
from igris.schemas.assessment import AssessmentVerdict
from igris.schemas.evaluation import (
    AblationConfigName,
    DatasetSampleRecord,
    EvaluationDataset,
    EvaluationSplit,
    ExperimentConfig,
    GroundTruthLabel,
    SplitStrategy,
)


def make_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        environment="test",
        metadata_backend="memory",
        sample_storage_dir=str(tmp_path / "samples"),
        metadata_storage_file=str(tmp_path / "metadata.json"),
        sample_temp_dir=str(tmp_path / "tmp"),
    )
    app = create_app(settings)
    return TestClient(app)


def test_dataset_manifest_seeding_and_retrieval(tmp_path: Path) -> None:
    """Verify that default synthetic evaluation dataset can be seeded and loaded."""
    client = make_client(tmp_path)
    app = client.app
    service = EvaluationService(
        settings=app.state.settings,
        sample_storage=app.state.sample_storage,
        metadata_repository=app.state.metadata_repository,
        job_repository=app.state.jobs_repository,
        experiment_repository=app.state.experiment_repository,
        dataset_repository=app.state.dataset_repository,
    )

    dataset = service.get_dataset("igris-synthetic-benchmark-v1")
    assert dataset.dataset_id == "igris-synthetic-benchmark-v1"
    assert len(dataset.samples) >= 10
    assert "BENIGN" in dataset.class_distribution
    assert "MALICIOUS" in dataset.class_distribution


def test_family_aware_split_prevents_leakage(tmp_path: Path) -> None:
    """Verify that family-aware splitting keeps all samples of a family in exactly one split."""
    client = make_client(tmp_path)
    app = client.app
    service = EvaluationService(
        settings=app.state.settings,
        sample_storage=app.state.sample_storage,
        metadata_repository=app.state.metadata_repository,
        job_repository=app.state.jobs_repository,
        experiment_repository=app.state.experiment_repository,
        dataset_repository=app.state.dataset_repository,
    )

    dataset = service.get_dataset("igris-synthetic-benchmark-v1")
    splits = service.generate_splits(dataset, SplitStrategy.FAMILY_AWARE, seed=123)

    train_families = {s.family for s in splits[EvaluationSplit.TRAIN] if s.family}
    val_families = {s.family for s in splits[EvaluationSplit.VALIDATION] if s.family}
    test_families = {s.family for s in splits[EvaluationSplit.TEST] if s.family}

    # Verify zero family overlap across splits
    assert train_families.isdisjoint(val_families)
    assert train_families.isdisjoint(test_families)
    assert val_families.isdisjoint(test_families)


def test_duplicate_sample_deduplication(tmp_path: Path) -> None:
    """Verify that duplicate samples with identical SHA256 do not leak or double count."""
    client = make_client(tmp_path)
    app = client.app
    service = EvaluationService(
        settings=app.state.settings,
        sample_storage=app.state.sample_storage,
        metadata_repository=app.state.metadata_repository,
        job_repository=app.state.jobs_repository,
        experiment_repository=app.state.experiment_repository,
        dataset_repository=app.state.dataset_repository,
    )

    custom_dataset = EvaluationDataset(
        dataset_id="test-dup-dataset",
        dataset_version="v1",
        name="Duplicate Test",
        description="Dataset with duplicates",
        source="Synthetic",
        license="MIT",
        collection_methodology="Test",
        samples=[
            DatasetSampleRecord(
                sample_id="s1",
                sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                label=GroundTruthLabel.MALICIOUS,
                family="fam1",
            ),
            # Duplicate SHA256 test sample
            DatasetSampleRecord(
                sample_id="s2",
                sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                label=GroundTruthLabel.MALICIOUS,
                family="fam1",
            ),
            DatasetSampleRecord(
                sample_id="s3",
                sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                label=GroundTruthLabel.BENIGN,
                family="fam2",
            ),
        ],
    )

    splits = service.generate_splits(custom_dataset, SplitStrategy.RANDOM)
    total_split_samples = sum(len(items) for items in splits.values())
    assert total_split_samples == 2  # Deduplicated from 3 to 2


def test_metric_calculation_and_wilson_confidence_intervals(tmp_path: Path) -> None:
    """Verify calculation of precision, recall, F1, FPR, FNR, and Wilson score intervals."""
    client = make_client(tmp_path)
    app = client.app
    service = EvaluationService(
        settings=app.state.settings,
        sample_storage=app.state.sample_storage,
        metadata_repository=app.state.metadata_repository,
        job_repository=app.state.jobs_repository,
        experiment_repository=app.state.experiment_repository,
        dataset_repository=app.state.dataset_repository,
    )

    # Simulated predictions: (GroundTruth, Verdict, Score)
    records = [
        (GroundTruthLabel.MALICIOUS, AssessmentVerdict.HIGHLY_SUSPICIOUS, 90),  # TP
        (GroundTruthLabel.MALICIOUS, AssessmentVerdict.SUSPICIOUS, 75),  # TP
        (GroundTruthLabel.MALICIOUS, AssessmentVerdict.LIKELY_BENIGN, 20),  # FN
        (GroundTruthLabel.BENIGN, AssessmentVerdict.BENIGN, 10),  # TN
        (GroundTruthLabel.BENIGN, AssessmentVerdict.LIKELY_BENIGN, 15),  # TN
        (GroundTruthLabel.BENIGN, AssessmentVerdict.SUSPICIOUS, 60),  # FP
        (GroundTruthLabel.MALICIOUS, AssessmentVerdict.UNKNOWN, 0),  # UNKNOWN
    ]

    metrics = service.calculate_metrics(records)  # type: ignore

    # TP=2, FP=1, TN=2, FN=1, Unknown=1
    assert metrics.confusion_matrix.tp == 2
    assert metrics.confusion_matrix.fp == 1
    assert metrics.confusion_matrix.tn == 2
    assert metrics.confusion_matrix.fn == 1
    assert metrics.confusion_matrix.unknown_count == 1

    # Precision = 2/3 ≈ 0.6667
    assert metrics.precision == 0.6667
    # Recall = 2/3 ≈ 0.6667
    assert metrics.recall == 0.6667
    # F1 = 0.6667
    assert metrics.f1_score == 0.6667
    # FPR = 1/3 ≈ 0.3333
    assert metrics.fpr == 0.3333
    # FNR = 1/3 ≈ 0.3333
    assert metrics.fnr == 0.3333

    # Check Wilson intervals exist
    assert "precision" in metrics.confidence_intervals
    assert "recall" in metrics.confidence_intervals
    assert metrics.confidence_intervals["precision"].low < metrics.precision
    assert metrics.confidence_intervals["precision"].high > metrics.precision


def test_controlled_ablation_experiment_run(tmp_path: Path) -> None:
    """Verify running a complete research ablation study across configurations A-F."""
    client = make_client(tmp_path)
    app = client.app
    service = EvaluationService(
        settings=app.state.settings,
        sample_storage=app.state.sample_storage,
        metadata_repository=app.state.metadata_repository,
        job_repository=app.state.jobs_repository,
        experiment_repository=app.state.experiment_repository,
        dataset_repository=app.state.dataset_repository,
    )

    config = ExperimentConfig(
        research_question="RQ1: How does detection evolve across ablation stages?",
        dataset_id="igris-synthetic-benchmark-v1",
        dataset_version="v1.0",
        split_strategy=SplitStrategy.STRATIFIED,
        ablation_configurations=[
            AblationConfigName.STATIC_ONLY,
            AblationConfigName.STATIC_HEURISTICS,
            AblationConfigName.FULL_IGRIS,
        ],
        random_seed=42,
    )

    experiment = service.run_experiment(config)

    assert experiment.status == "COMPLETED"
    assert len(experiment.ablation_results) == 3
    assert experiment.reproducibility.code_version == __version__
    assert len(experiment.threats_to_validity) > 0
    assert len(experiment.conclusions) > 0

    # Ensure results are stored in repository
    stored_exp = service.get_experiment(experiment.experiment_id)
    assert stored_exp.experiment_id == experiment.experiment_id


def test_experiment_api_endpoints(tmp_path: Path) -> None:
    """Verify API routes for creating, querying, and exporting experiments."""
    client = make_client(tmp_path)

    # 1. Create experiment
    payload = {
        "research_question": "RQ3: Does behavioral evidence improve detection?",
        "dataset_id": "igris-synthetic-benchmark-v1",
        "dataset_version": "v1.0",
        "split_strategy": "FAMILY_AWARE",
        "random_seed": 42,
    }
    create_res = client.post("/api/v1/experiments", json=payload)
    assert create_res.status_code == 201
    exp_data = create_res.json()["experiment"]
    exp_id = exp_data["experiment_id"]

    # 2. Get experiment
    get_res = client.get(f"/api/v1/experiments/{exp_id}")
    assert get_res.status_code == 200
    assert get_res.json()["experiment"]["experiment_id"] == exp_id

    # 3. Get results
    res_res = client.get(f"/api/v1/experiments/{exp_id}/results")
    assert res_res.status_code == 200
    assert len(res_res.json()["ablation_results"]) > 0

    # 4. Get artifacts
    art_res = client.get(f"/api/v1/experiments/{exp_id}/artifacts")
    assert art_res.status_code == 200
    art_data = art_res.json()
    assert "json_report" in art_data
    assert "summary_markdown" in art_data

    # 5. List experiments
    list_res = client.get("/api/v1/experiments")
    assert list_res.status_code == 200
    assert list_res.json()["total_count"] >= 1
