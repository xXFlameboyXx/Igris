"""Interfaces for future explainable report generation."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class ReportSummary:
    """Future report summary envelope."""

    sample_id: str
    title: str
    executive_summary: str


class ReportRenderer(ABC):
    """Future interface for rendering analyst-facing reports."""

    @abstractmethod
    async def render(self, sample_id: str) -> ReportSummary:
        """Render a report from stored analysis evidence."""
