"""Storage repositories for Phase 15 experiments and evaluation datasets."""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from threading import RLock

from pydantic import TypeAdapter

from igris.schemas.evaluation import EvaluationDataset, ExperimentRecord

EXPERIMENT_ADAPTER = TypeAdapter(ExperimentRecord)
DATASET_ADAPTER = TypeAdapter(EvaluationDataset)


class ExperimentRepository(ABC):
    """Repository boundary for research experiment records."""

    @abstractmethod
    def upsert(self, experiment: ExperimentRecord) -> None:
        """Store or update an experiment record."""

    @abstractmethod
    def get(self, experiment_id: str) -> ExperimentRecord | None:
        """Return an experiment by ID."""

    @abstractmethod
    def list_all(self, limit: int = 100) -> list[ExperimentRecord]:
        """Return recent experiments."""


class InMemoryExperimentRepository(ExperimentRepository):
    """In-memory experiment repository for tests."""

    def __init__(self) -> None:
        self._experiments: dict[str, ExperimentRecord] = {}
        self._lock = RLock()

    def upsert(self, experiment: ExperimentRecord) -> None:
        with self._lock:
            self._experiments[experiment.experiment_id] = experiment

    def get(self, experiment_id: str) -> ExperimentRecord | None:
        with self._lock:
            return self._experiments.get(experiment_id)

    def list_all(self, limit: int = 100) -> list[ExperimentRecord]:
        with self._lock:
            all_exp = list(self._experiments.values())
            all_exp.sort(key=lambda e: e.created_at, reverse=True)
            return all_exp[:limit]


class JsonExperimentRepository(ExperimentRepository):
    """File-backed JSON repository for experiment persistence."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

    def upsert(self, experiment: ExperimentRecord) -> None:
        with self._lock:
            experiments = self._load()
            experiments[experiment.experiment_id] = experiment
            self.path.write_text(
                json.dumps(
                    {k: v.model_dump(mode="json") for k, v in experiments.items()},
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

    def get(self, experiment_id: str) -> ExperimentRecord | None:
        with self._lock:
            return self._load().get(experiment_id)

    def list_all(self, limit: int = 100) -> list[ExperimentRecord]:
        with self._lock:
            all_exp = list(self._load().values())
            all_exp.sort(key=lambda e: e.created_at, reverse=True)
            return all_exp[:limit]

    def _load(self) -> dict[str, ExperimentRecord]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return {k: EXPERIMENT_ADAPTER.validate_python(v) for k, v in raw.items()}
        except Exception:
            return {}


# =============================================================================
# Dataset Repository
# =============================================================================


class EvaluationDatasetRepository(ABC):
    """Repository boundary for evaluation dataset manifests."""

    @abstractmethod
    def upsert(self, dataset: EvaluationDataset) -> None:
        """Store or update an evaluation dataset manifest."""

    @abstractmethod
    def get(self, dataset_id: str) -> EvaluationDataset | None:
        """Return dataset manifest by ID."""

    @abstractmethod
    def list_all(self) -> list[EvaluationDataset]:
        """Return all registered datasets."""


class InMemoryEvaluationDatasetRepository(EvaluationDatasetRepository):
    """In-memory dataset repository for tests."""

    def __init__(self) -> None:
        self._datasets: dict[str, EvaluationDataset] = {}
        self._lock = RLock()

    def upsert(self, dataset: EvaluationDataset) -> None:
        with self._lock:
            self._datasets[dataset.dataset_id] = dataset

    def get(self, dataset_id: str) -> EvaluationDataset | None:
        with self._lock:
            return self._datasets.get(dataset_id)

    def list_all(self) -> list[EvaluationDataset]:
        with self._lock:
            return list(self._datasets.values())


class JsonEvaluationDatasetRepository(EvaluationDatasetRepository):
    """File-backed JSON dataset repository."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

    def upsert(self, dataset: EvaluationDataset) -> None:
        with self._lock:
            datasets = self._load()
            datasets[dataset.dataset_id] = dataset
            self.path.write_text(
                json.dumps(
                    {k: v.model_dump(mode="json") for k, v in datasets.items()},
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

    def get(self, dataset_id: str) -> EvaluationDataset | None:
        with self._lock:
            return self._load().get(dataset_id)

    def list_all(self) -> list[EvaluationDataset]:
        with self._lock:
            return list(self._load().values())

    def _load(self) -> dict[str, EvaluationDataset]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return {k: DATASET_ADAPTER.validate_python(v) for k, v in raw.items()}
        except Exception:
            return {}
