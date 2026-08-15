"""Schemas for Phase 13 Investigation Workspace, Bookmarks, Analyst Notes, and Reports."""

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from igris.schemas.assessment import (
    AssessmentEvidenceItem,
    ExplainableAssessment,
    VerdictSummary,
)

BookmarkTargetType = Literal[
    "evidence",
    "function",
    "timeline_event",
    "cfg_block",
    "network_event",
    "registry_event",
    "process",
    "dropped_file",
    "attack_technique",
    "similarity_match",
    "custom",
]


class Bookmark(BaseModel):
    """Analyst bookmark pointing to an automated finding or telemetry artifact."""

    model_config = ConfigDict(extra="forbid")

    bookmark_id: str
    sample_id: str
    target_type: BookmarkTargetType
    target_id: str
    title: str
    description: str | None = None
    category: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BookmarkCreateRequest(BaseModel):
    """Request payload to create an analyst bookmark."""

    model_config = ConfigDict(extra="forbid")

    target_type: BookmarkTargetType
    target_id: str
    title: str
    description: str | None = None
    category: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BookmarkResponse(BaseModel):
    """Response containing a single bookmark."""

    model_config = ConfigDict(extra="forbid")

    bookmark: Bookmark


class BookmarksListResponse(BaseModel):
    """Response containing all bookmarks for a sample."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    bookmarks: list[Bookmark]


class AnalystNote(BaseModel):
    """Human analyst-authored investigation note, strictly separate from automated evidence."""

    model_config = ConfigDict(extra="forbid")

    note_id: str
    sample_id: str
    author: str = "Analyst"
    title: str
    content: str
    attached_evidence_ids: list[str] = Field(default_factory=list)
    attached_bookmark_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime | None = None


class NoteCreateRequest(BaseModel):
    """Request payload to create a new analyst note."""

    model_config = ConfigDict(extra="forbid")

    author: str = "Analyst"
    title: str
    content: str
    attached_evidence_ids: list[str] = Field(default_factory=list)
    attached_bookmark_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class NoteUpdateRequest(BaseModel):
    """Request payload to update an existing analyst note."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    content: str | None = None
    attached_evidence_ids: list[str] | None = None
    attached_bookmark_ids: list[str] | None = None
    tags: list[str] | None = None


class NoteResponse(BaseModel):
    """Response containing a single analyst note."""

    model_config = ConfigDict(extra="forbid")

    note: AnalystNote


class NotesListResponse(BaseModel):
    """Response containing all analyst notes for a sample."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    notes: list[AnalystNote]


class EvidenceFilterQuery(BaseModel):
    """Query parameters for filtering normalized evidence items."""

    model_config = ConfigDict(extra="forbid")

    source: str | None = None
    severity: str | None = None
    role: str | None = None
    observation_level: str | None = None
    process: str | None = None
    function: str | None = None
    technique: str | None = None
    query: str | None = None


class EvidenceListResponse(BaseModel):
    """Response envelope for filtered evidence items."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    total_count: int
    filtered_count: int
    items: list[AssessmentEvidenceItem]


class ReportVersionMetadata(BaseModel):
    """Version and engine provenance metadata for investigation reports."""

    model_config = ConfigDict(extra="forbid")

    igris_version: str = "0.1.0"
    report_schema_version: str = "report/v1"
    engine_versions: dict[str, str] = Field(default_factory=dict)
    rule_version: str = "v1.2"
    attack_dataset_version: str = "v14.1"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class InvestigationReport(BaseModel):
    """Structured, reproducible, and machine-readable investigation report."""

    model_config = ConfigDict(extra="forbid")

    report_id: str
    sample_id: str
    sha256: str
    version_metadata: ReportVersionMetadata
    executive_summary: str
    sample_identification: dict[str, Any]
    verdict_assessment: dict[str, Any]
    epistemology_summary: dict[str, list[str]]
    subsystem_summaries: dict[str, Any]
    evidence_items: list[AssessmentEvidenceItem]
    analyst_notes: list[AnalystNote]
    analyst_bookmarks: list[Bookmark]
    uncertainties: list[dict[str, str]]
    limitations: list[str]


class ReportCreateResponse(BaseModel):
    """Response containing the generated investigation report."""

    model_config = ConfigDict(extra="forbid")

    report: InvestigationReport


class InvestigationWorkspace(BaseModel):
    """Aggregated investigation workspace combining raw sample, assessment, notes, and bookmarks."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    original_filename: str
    safe_filename: str
    status: str
    size_bytes: int
    verdict_summary: VerdictSummary | None = None
    explainable_assessment: ExplainableAssessment | None = None
    coverage: dict[str, bool]
    bookmarks: list[Bookmark] = Field(default_factory=list)
    notes: list[AnalystNote] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class InvestigationWorkspaceResponse(BaseModel):
    """Response containing the complete investigation workspace."""

    model_config = ConfigDict(extra="forbid")

    workspace: InvestigationWorkspace
