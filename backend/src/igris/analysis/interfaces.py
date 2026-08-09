"""Shared interfaces for future analysis components."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

AnalysisKind = Literal["static", "reverse", "behavioral", "similarity"]


@dataclass(frozen=True)
class AnalysisInput:
    """Metadata-only handle for a hostile sample stored in controlled storage."""

    sample_id: str
    storage_path: Path
    declared_filename: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class AnalysisResult:
    """Generic result envelope for future analysis modules."""

    sample_id: str
    kind: AnalysisKind
    success: bool
    findings: tuple[dict[str, Any], ...]


class Analyzer(ABC):
    """Interface implemented by future isolated analysis components."""

    kind: AnalysisKind

    @abstractmethod
    async def analyze(self, analysis_input: AnalysisInput) -> AnalysisResult:
        """Analyze a hostile sample handle inside the appropriate security boundary."""

