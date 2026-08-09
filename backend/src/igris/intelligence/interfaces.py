"""Interfaces for future evidence correlation and intelligence enrichment."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceItem:
    """Normalized evidence item produced by future analysis components."""

    sample_id: str
    source: str
    value: str


class EvidenceCorrelator(ABC):
    """Future interface for correlating evidence into explainable intelligence."""

    @abstractmethod
    async def correlate(self, sample_id: str) -> tuple[EvidenceItem, ...]:
        """Correlate evidence for a sample."""

