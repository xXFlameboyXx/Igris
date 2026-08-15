"""Interfaces for future background workers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class WorkItem:
    """Future background work item envelope."""

    work_id: str
    sample_id: str
    queue: str


class WorkerQueue(ABC):
    """Future interface for queueing isolated analysis work."""

    @abstractmethod
    async def enqueue(self, work_item: WorkItem) -> None:
        """Queue work without executing analysis in the API process."""
