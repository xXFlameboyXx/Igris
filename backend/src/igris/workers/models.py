"""Job state models for sandbox analysis work items."""

from dataclasses import dataclass, field
from enum import StrEnum

from igris.schemas.behavior_analysis import ArtifactRetentionPolicy, SandboxResourceLimits
from igris.workers.interfaces import WorkItem


class SandboxJobStatus(StrEnum):
    """Lifecycle status for a sandbox analysis job."""

    PENDING = "pending"
    SUBMITTED = "submitted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class SandboxWorkItem(WorkItem):
    """Work item for sandbox analysis with execution constraints.

    Extends WorkItem with sandbox-specific configuration fields.
    These fields are architectural preparation only; real sandbox
    execution remains outside the API process.
    """

    analysis_timeout_seconds: int = 120
    network_policy: str = "deny_all"
    resource_limits: SandboxResourceLimits = field(default_factory=SandboxResourceLimits)
    artifact_policy: ArtifactRetentionPolicy = field(default_factory=ArtifactRetentionPolicy)
