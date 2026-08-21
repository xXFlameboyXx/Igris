"""Analysis job repository implementations for Phase 14 pipeline orchestration."""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from threading import RLock

from pydantic import TypeAdapter

from igris.schemas.orchestration import AnalysisJob

JOB_ADAPTER = TypeAdapter(AnalysisJob)


class AnalysisJobRepository(ABC):
    """Repository boundary for analysis job tracking and persistence."""

    @abstractmethod
    def upsert(self, job: AnalysisJob) -> None:
        """Insert or update an analysis job."""

    @abstractmethod
    def get(self, analysis_id: str) -> AnalysisJob | None:
        """Return an analysis job by ID."""

    @abstractmethod
    def get_by_idempotency_key(self, idempotency_key: str) -> AnalysisJob | None:
        """Return an analysis job matching an idempotency key."""

    @abstractmethod
    def list_for_sample(self, sample_id: str) -> list[AnalysisJob]:
        """Return all analysis jobs executed for a specific sample."""

    @abstractmethod
    def list_all(self, limit: int = 100) -> list[AnalysisJob]:
        """Return all stored analysis jobs up to limit."""

    @abstractmethod
    def delete_for_sample(self, sample_id: str) -> int:
        """Delete all analysis jobs associated with a specific sample. Return deleted count."""


class InMemoryAnalysisJobRepository(AnalysisJobRepository):
    """In-memory repository for tests and lightweight executions."""

    def __init__(self) -> None:
        self._jobs: dict[str, AnalysisJob] = {}
        self._lock = RLock()

    def upsert(self, job: AnalysisJob) -> None:
        with self._lock:
            self._jobs[job.analysis_id] = job

    def get(self, analysis_id: str) -> AnalysisJob | None:
        with self._lock:
            return self._jobs.get(analysis_id)

    def get_by_idempotency_key(self, idempotency_key: str) -> AnalysisJob | None:
        with self._lock:
            for job in self._jobs.values():
                if job.idempotency_key == idempotency_key:
                    return job
            return None

    def list_for_sample(self, sample_id: str) -> list[AnalysisJob]:
        with self._lock:
            return [j for j in self._jobs.values() if j.sample_id == sample_id]

    def list_all(self, limit: int = 100) -> list[AnalysisJob]:
        with self._lock:
            # Sorted by created_at descending
            all_jobs = list(self._jobs.values())
            all_jobs.sort(key=lambda j: j.created_at, reverse=True)
            return all_jobs[:limit]

    def delete_for_sample(self, sample_id: str) -> int:
        with self._lock:
            to_delete = [k for k, j in self._jobs.items() if j.sample_id == sample_id]
            for k in to_delete:
                del self._jobs[k]
            return len(to_delete)


class JsonAnalysisJobRepository(AnalysisJobRepository):
    """File-backed JSON job repository for development and persistence."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

    def upsert(self, job: AnalysisJob) -> None:
        with self._lock:
            jobs = self._load()
            jobs[job.analysis_id] = job
            self.path.write_text(
                json.dumps(
                    {k: v.model_dump(mode="json") for k, v in jobs.items()},
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

    def get(self, analysis_id: str) -> AnalysisJob | None:
        with self._lock:
            return self._load().get(analysis_id)

    def get_by_idempotency_key(self, idempotency_key: str) -> AnalysisJob | None:
        with self._lock:
            for job in self._load().values():
                if job.idempotency_key == idempotency_key:
                    return job
            return None

    def list_for_sample(self, sample_id: str) -> list[AnalysisJob]:
        with self._lock:
            return [j for j in self._load().values() if j.sample_id == sample_id]

    def list_all(self, limit: int = 100) -> list[AnalysisJob]:
        with self._lock:
            all_jobs = list(self._load().values())
            all_jobs.sort(key=lambda j: j.created_at, reverse=True)
            return all_jobs[:limit]

    def delete_for_sample(self, sample_id: str) -> int:
        with self._lock:
            jobs = self._load()
            to_delete = [k for k, j in jobs.items() if j.sample_id == sample_id]
            for k in to_delete:
                del jobs[k]
            if to_delete:
                self.path.write_text(
                    json.dumps(
                        {k: v.model_dump(mode="json") for k, v in jobs.items()},
                        indent=2,
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
            return len(to_delete)

    def _load(self) -> dict[str, AnalysisJob]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return {k: JOB_ADAPTER.validate_python(v) for k, v in raw.items()}
        except Exception:
            return {}
