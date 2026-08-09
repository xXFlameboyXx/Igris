"""Interfaces for future sample and evidence storage."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StoredSample:
    """Metadata for a hostile sample stored in controlled storage."""

    sample_id: str
    storage_path: Path
    sha256: str
    size_bytes: int


class SampleRepository(ABC):
    """Future interface for storing sample metadata and references."""

    @abstractmethod
    async def get(self, sample_id: str) -> StoredSample | None:
        """Return sample metadata without exposing raw file contents."""

