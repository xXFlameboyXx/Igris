"""Storage factory helpers."""

from pathlib import Path

from igris.core.config import Settings
from igris.storage.binary import LocalSampleStorage
from igris.storage.experiments import (
    EvaluationDatasetRepository,
    ExperimentRepository,
    InMemoryEvaluationDatasetRepository,
    InMemoryExperimentRepository,
    JsonEvaluationDatasetRepository,
    JsonExperimentRepository,
)
from igris.storage.jobs import (
    AnalysisJobRepository,
    InMemoryAnalysisJobRepository,
    JsonAnalysisJobRepository,
)
from igris.storage.metadata import (
    InMemorySampleMetadataRepository,
    JsonSampleMetadataRepository,
    PostgresSampleMetadataRepository,
    SampleMetadataRepository,
)
from igris.storage.robustness import (
    InMemoryRobustnessRepository,
    JsonRobustnessRepository,
    RobustnessRepository,
)


def build_sample_storage(settings: Settings) -> LocalSampleStorage:
    return LocalSampleStorage(Path(settings.sample_storage_dir))


def build_metadata_repository(settings: Settings) -> SampleMetadataRepository:
    if settings.metadata_backend == "memory":
        return InMemorySampleMetadataRepository()
    if settings.metadata_backend == "postgres":
        if settings.database_url is None:
            msg = "IGRIS_DATABASE_URL is required when IGRIS_METADATA_BACKEND=postgres"
            raise ValueError(msg)
        return PostgresSampleMetadataRepository(settings.database_url.get_secret_value())
    return JsonSampleMetadataRepository(Path(settings.metadata_storage_file))


def build_jobs_repository(settings: Settings) -> AnalysisJobRepository:
    if settings.metadata_backend == "memory":
        return InMemoryAnalysisJobRepository()
    jobs_path = Path(settings.metadata_storage_file).parent / "jobs.json"
    return JsonAnalysisJobRepository(jobs_path)


def build_experiment_repository(settings: Settings) -> ExperimentRepository:
    if settings.metadata_backend == "memory":
        return InMemoryExperimentRepository()
    exp_path = Path(settings.metadata_storage_file).parent / "experiments.json"
    return JsonExperimentRepository(exp_path)


def build_dataset_repository(settings: Settings) -> EvaluationDatasetRepository:
    if settings.metadata_backend == "memory":
        return InMemoryEvaluationDatasetRepository()
    ds_path = Path(settings.metadata_storage_file).parent / "evaluation_datasets.json"
    return JsonEvaluationDatasetRepository(ds_path)


def build_robustness_repository(settings: Settings) -> RobustnessRepository:
    if settings.metadata_backend == "memory":
        return InMemoryRobustnessRepository()
    rob_path = Path(settings.metadata_storage_file).parent / "robustness_reports.json"
    return JsonRobustnessRepository(rob_path)
