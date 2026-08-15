"""Schemas for Phase 14 Analysis Job Orchestration and Pipeline Coordination."""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from igris.schemas.assessment import VerdictSummary


class PipelineStageName(StrEnum):
    """Explicit pipeline stages executed by the Igris orchestrator."""

    FILE_INTELLIGENCE = "FILE_INTELLIGENCE"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    DETECTION = "DETECTION"
    REVERSE_ANALYSIS = "REVERSE_ANALYSIS"
    ML = "ML"
    BEHAVIOR = "BEHAVIOR"
    SIMILARITY = "SIMILARITY"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    EVIDENCE_CORRELATION = "EVIDENCE_CORRELATION"
    ASSESSMENT = "ASSESSMENT"
    REPORT = "REPORT"


class JobStatus(StrEnum):
    """Overall analysis job execution state."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


class StageStatus(StrEnum):
    """Individual stage execution state."""

    NOT_STARTED = "NOT_STARTED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


class FailureCategory(StrEnum):
    """Failure classification for error isolation and retry policies."""

    RETRYABLE = "RETRYABLE"
    NON_RETRYABLE = "NON_RETRYABLE"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    VALIDATION = "VALIDATION"


class StageError(BaseModel):
    """Isolated, safe error record for stage execution failures."""

    model_config = ConfigDict(extra="forbid")

    error_category: FailureCategory
    safe_message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    attempt_number: int = 1


class PipelineStageRecord(BaseModel):
    """Execution status and metrics for an individual pipeline stage."""

    model_config = ConfigDict(extra="forbid")

    name: PipelineStageName
    status: StageStatus = StageStatus.NOT_STARTED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: float | None = None
    dependencies: list[PipelineStageName] = Field(default_factory=list)
    retry_count: int = 0
    error: StageError | None = None
    result_available: bool = False


class AnalysisJob(BaseModel):
    """Asynchronous analysis job tracking full pipeline coordination and partial results."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(default_factory=lambda: f"job-{uuid4().hex[:12]}")
    sample_id: str
    status: JobStatus = JobStatus.QUEUED
    current_stage: PipelineStageName | None = None
    progress: int = Field(default=0, ge=0, le=100)
    stages: list[PipelineStageRecord] = Field(default_factory=list)
    idempotency_key: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    cancelled_at: datetime | None = None
    cancellation_reason: str | None = None
    error: str | None = None
    engine_versions: dict[str, str] = Field(default_factory=dict)
    partial_results_preserved: bool = True
    verdict_summary: VerdictSummary | None = None
    report_id: str | None = None


# =============================================================================
# API Request / Response Schemas
# =============================================================================


class AnalysisCreateRequest(BaseModel):
    """Payload to initiate or schedule a pipeline analysis job."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    enabled_stages: list[PipelineStageName] | None = None
    force_reanalyze: bool = False
    max_retries: int | None = Field(default=None, ge=0, le=5)
    timeout_seconds: int | None = Field(default=None, ge=1, le=600)


class AnalysisJobResponse(BaseModel):
    """API response envelope containing the complete analysis job model."""

    model_config = ConfigDict(extra="forbid")

    analysis: AnalysisJob


class AnalysisStatusResponse(BaseModel):
    """Concise real-time status and stage progress API response."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    sample_id: str
    status: JobStatus
    progress: int
    current_stage: PipelineStageName | None
    stages: list[PipelineStageRecord]
    verdict_summary: VerdictSummary | None = None
    report_id: str | None = None
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class AnalysisCancelResponse(BaseModel):
    """API response after cancelling an active or queued analysis job."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    status: JobStatus
    cancelled_at: datetime
    message: str


class AnalysisListResponse(BaseModel):
    """API response listing analysis jobs."""

    model_config = ConfigDict(extra="forbid")

    analyses: list[AnalysisJob]
    total_count: int
