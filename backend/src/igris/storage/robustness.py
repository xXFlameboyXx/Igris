"""Storage repositories for Phase 16 robustness and perturbation evaluation reports."""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from threading import RLock

from pydantic import TypeAdapter

from igris.schemas.robustness import RobustnessEvaluationReport

REPORT_ADAPTER = TypeAdapter(RobustnessEvaluationReport)


class RobustnessRepository(ABC):
    """Repository boundary for robustness evaluation reports."""

    @abstractmethod
    def upsert_report(self, report: RobustnessEvaluationReport) -> None:
        """Store or update a robustness evaluation report."""

    @abstractmethod
    def get_report(self, report_id: str) -> RobustnessEvaluationReport | None:
        """Retrieve a specific robustness report by ID."""

    @abstractmethod
    def get_latest_report(self) -> RobustnessEvaluationReport | None:
        """Retrieve the most recently executed robustness evaluation report."""

    @abstractmethod
    def list_reports(self, limit: int = 50) -> list[RobustnessEvaluationReport]:
        """List historical robustness reports."""


class InMemoryRobustnessRepository(RobustnessRepository):
    """Thread-safe in-memory robustness report repository for testing."""

    def __init__(self) -> None:
        self._reports: dict[str, RobustnessEvaluationReport] = {}
        self._lock = RLock()

    def upsert_report(self, report: RobustnessEvaluationReport) -> None:
        with self._lock:
            self._reports[report.report_id] = report

    def get_report(self, report_id: str) -> RobustnessEvaluationReport | None:
        with self._lock:
            return self._reports.get(report_id)

    def get_latest_report(self) -> RobustnessEvaluationReport | None:
        with self._lock:
            if not self._reports:
                return None
            reports = list(self._reports.values())
            reports.sort(key=lambda r: r.timestamp, reverse=True)
            return reports[0]

    def list_reports(self, limit: int = 50) -> list[RobustnessEvaluationReport]:
        with self._lock:
            reports = list(self._reports.values())
            reports.sort(key=lambda r: r.timestamp, reverse=True)
            return reports[:limit]


class JsonRobustnessRepository(RobustnessRepository):
    """File-backed JSON robustness repository for persistent reports."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

    def upsert_report(self, report: RobustnessEvaluationReport) -> None:
        with self._lock:
            reports = self._load()
            reports[report.report_id] = report
            self.path.write_text(
                json.dumps(
                    {k: v.model_dump(mode="json") for k, v in reports.items()},
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

    def get_report(self, report_id: str) -> RobustnessEvaluationReport | None:
        with self._lock:
            return self._load().get(report_id)

    def get_latest_report(self) -> RobustnessEvaluationReport | None:
        with self._lock:
            reports = list(self._load().values())
            if not reports:
                return None
            reports.sort(key=lambda r: r.timestamp, reverse=True)
            return reports[0]

    def list_reports(self, limit: int = 50) -> list[RobustnessEvaluationReport]:
        with self._lock:
            reports = list(self._load().values())
            reports.sort(key=lambda r: r.timestamp, reverse=True)
            return reports[:limit]

    def _load(self) -> dict[str, RobustnessEvaluationReport]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return {k: REPORT_ADAPTER.validate_python(v) for k, v in raw.items()}
        except Exception:
            return {}
