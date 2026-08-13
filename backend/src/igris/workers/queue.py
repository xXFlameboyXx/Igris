"""Concrete job queue implementations for development and testing.

Phase 7.0 provides InProcessJobQueue as a synchronous, in-memory queue
that exercises the queue architecture with SyntheticBehaviorAnalyzer.

WARNING — InProcessJobQueue must NOT be used for real sandbox execution.
Real sandbox execution must occur in an external, isolated worker process
via a distributed queue (e.g., Redis + Celery/ARQ + dedicated worker).
The API process must never execute uploaded sample binaries.

Phase 7.1+ migration path:
- Replace InProcessJobQueue with a Redis-backed distributed queue.
- Deploy a separate worker process that pulls SandboxWorkItems.
- The worker process communicates with the disposable sandbox runtime.
- The API process enqueues work and polls/receives completion callbacks.
"""

from igris.workers.interfaces import WorkerQueue, WorkItem


class InProcessJobQueue(WorkerQueue):
    """Synchronous in-process job queue for development and testing.

    This queue stores work items in memory within the API process.
    It exists only to exercise the architecture with SyntheticBehaviorAnalyzer.

    This queue must NOT be used with real sandbox execution.
    The sandbox execution boundary must remain external to the API process.
    """

    def __init__(self) -> None:
        self._items: list[WorkItem] = []

    async def enqueue(self, work_item: WorkItem) -> None:
        """Record a work item in memory without external dispatch.

        No external process, subprocess, or sandbox is launched.
        Items are stored for the BehaviorAnalysisService to inspect.
        """
        self._items.append(work_item)

    def drain(self) -> list[WorkItem]:
        """Return and clear all pending items."""
        items = list(self._items)
        self._items.clear()
        return items
