"""Metadata repository implementations for Phase 1 samples."""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import TypeAdapter

from igris.schemas.file_intelligence import Sample

SAMPLE_ADAPTER = TypeAdapter(Sample)


class SampleMetadataRepository(ABC):
    """Repository boundary for sample metadata."""

    @abstractmethod
    def upsert(self, sample: Sample) -> None:
        """Insert or replace sample metadata."""

    @abstractmethod
    def get(self, sample_id: str) -> Sample | None:
        """Return a sample by ID."""

    @abstractmethod
    def get_by_sha256(self, sha256: str) -> Sample | None:
        """Return a sample by canonical SHA-256."""

    @abstractmethod
    def list_all(self) -> list[Sample]:
        """Return all stored samples."""

    @abstractmethod
    def delete(self, sample_id: str) -> bool:
        """Delete a sample metadata record by ID. Return True if deleted, False otherwise."""


class InMemorySampleMetadataRepository(SampleMetadataRepository):
    """In-memory repository for tests."""

    def __init__(self) -> None:
        self._samples: dict[str, Sample] = {}

    def upsert(self, sample: Sample) -> None:
        self._samples[sample.sample_id] = sample

    def get(self, sample_id: str) -> Sample | None:
        return self._samples.get(sample_id)

    def get_by_sha256(self, sha256: str) -> Sample | None:
        for sample in self._samples.values():
            if sample.hashes.sha256 == sha256:
                return sample
        return None

    def list_all(self) -> list[Sample]:
        return list(self._samples.values())

    def delete(self, sample_id: str) -> bool:
        return self._samples.pop(sample_id, None) is not None


class JsonSampleMetadataRepository(SampleMetadataRepository):
    """Small local metadata repository for development without PostgreSQL."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

    def upsert(self, sample: Sample) -> None:
        with self._lock:
            samples = self._load()
            samples[sample.sample_id] = sample
            self.path.write_text(
                json.dumps(
                    {key: value.model_dump(mode="json") for key, value in samples.items()},
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

    def get(self, sample_id: str) -> Sample | None:
        with self._lock:
            return self._load().get(sample_id)

    def get_by_sha256(self, sha256: str) -> Sample | None:
        with self._lock:
            for sample in self._load().values():
                if sample.hashes.sha256 == sha256:
                    return sample
        return None

    def list_all(self) -> list[Sample]:
        with self._lock:
            return list(self._load().values())

    def delete(self, sample_id: str) -> bool:
        with self._lock:
            samples = self._load()
            if sample_id in samples:
                del samples[sample_id]
                self.path.write_text(
                    json.dumps(
                        {key: value.model_dump(mode="json") for key, value in samples.items()},
                        indent=2,
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
                return True
            return False

    def _load(self) -> dict[str, Sample]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return {key: SAMPLE_ADAPTER.validate_python(value) for key, value in raw.items()}


class PostgresSampleMetadataRepository(SampleMetadataRepository):
    """PostgreSQL metadata repository using JSONB for normalized Phase 1 results."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self._ensure_schema()

    def upsert(self, sample: Sample) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO samples (sample_id, sha256, metadata)
                VALUES (%s, %s, %s::jsonb)
                ON CONFLICT (sample_id)
                DO UPDATE SET sha256 = EXCLUDED.sha256, metadata = EXCLUDED.metadata
                """,
                (
                    sample.sample_id,
                    sample.hashes.sha256,
                    json.dumps(sample.model_dump(mode="json")),
                ),
            )

    def get(self, sample_id: str) -> Sample | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT metadata FROM samples WHERE sample_id = %s",
                (sample_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_sample(row[0])

    def get_by_sha256(self, sha256: str) -> Sample | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT metadata FROM samples WHERE sha256 = %s ORDER BY created_at LIMIT 1",
                (sha256,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_sample(row[0])

    def list_all(self) -> list[Sample]:
        with self._connect() as connection:
            rows = connection.execute("SELECT metadata FROM samples ORDER BY created_at").fetchall()
        return [self._row_to_sample(row[0]) for row in rows]

    def delete(self, sample_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM samples WHERE sample_id = %s",
                (sample_id,),
            )
            return bool(cursor.rowcount and cursor.rowcount > 0)

    def _ensure_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS samples (
                    sample_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    metadata JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples (sha256)")

    def _connect(self) -> Any:
        import psycopg

        return psycopg.connect(self.database_url)

    def _row_to_sample(self, value: Any) -> Sample:
        if isinstance(value, str):
            return SAMPLE_ADAPTER.validate_json(value)
        return SAMPLE_ADAPTER.validate_python(value)
