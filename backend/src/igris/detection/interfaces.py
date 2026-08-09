"""Interfaces for future detection engines."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionFinding:
    """Future detection finding envelope."""

    rule_id: str
    title: str
    confidence: float


class DetectionEngine(ABC):
    """Future interface for rules, heuristics, and ML detectors."""

    @abstractmethod
    async def evaluate(self, sample_id: str) -> tuple[DetectionFinding, ...]:
        """Evaluate previously generated analysis evidence."""

