"""Phase 13: Investigation Workspace, Evidence Filtering, Bookmarks, and Notes Service."""

from datetime import UTC, datetime
from uuid import uuid4

from igris.core.config import Settings
from igris.core.errors import AppError
from igris.intelligence.assessment.service import AssessmentService
from igris.schemas.assessment import AssessmentEvidenceItem, VerdictSummary
from igris.schemas.file_intelligence import Sample
from igris.schemas.investigation import (
    AnalystNote,
    Bookmark,
    BookmarkCreateRequest,
    EvidenceFilterQuery,
    EvidenceListResponse,
    InvestigationWorkspace,
    NoteCreateRequest,
    NoteUpdateRequest,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class InvestigationService:
    """Manages investigation workspaces, evidence filtering, bookmarks, and analyst notes."""

    def __init__(
        self,
        settings: Settings,
        sample_storage: LocalSampleStorage,
        metadata_repository: SampleMetadataRepository,
        assessment_service: AssessmentService | None = None,
    ) -> None:
        self.settings = settings
        self.sample_storage = sample_storage
        self.metadata_repository = metadata_repository
        self.assessment_service = assessment_service or AssessmentService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )

    def _get_sample(self, sample_id: str) -> Sample:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError(
                code="sample_not_found",
                message=f"Sample '{sample_id}' not found.",
                status_code=404,
            )
        return sample

    def get_workspace(self, sample_id: str) -> InvestigationWorkspace:
        """Return the aggregated investigation workspace for an analyst."""
        sample = self._get_sample(sample_id)
        assessment = self.assessment_service.get_or_run_assessment(sample_id)

        coverage = {
            "file_intelligence": sample.file_metadata is not None,
            "static_analysis": sample.static_analysis is not None,
            "detection": sample.detection is not None,
            "reverse_analysis": sample.reverse_analysis is not None,
            "threat_assessment": sample.threat_assessment is not None,
            "ml_prediction": sample.ml_prediction is not None,
            "behavior_analysis": sample.behavior_analysis is not None,
            "similarity_analysis": sample.similarity_analysis is not None,
            "malware_assessment": sample.malware_assessment is not None,
        }

        verdict_summary = VerdictSummary(
            sample_id=assessment.sample_id,
            sha256=assessment.sha256,
            verdict=assessment.verdict,
            risk_level=assessment.risk_level,
            risk_score=assessment.risk_score,
            confidence=assessment.confidence,
            summary=assessment.explanation.summary,
            limitations=assessment.limitations,
            created_at=assessment.created_at,
        )

        return InvestigationWorkspace(
            sample_id=sample.sample_id,
            sha256=sample.hashes.sha256,
            original_filename=sample.original_filename,
            safe_filename=sample.safe_filename,
            status=sample.status,
            size_bytes=sample.size_bytes,
            verdict_summary=verdict_summary,
            explainable_assessment=assessment,
            coverage=coverage,
            bookmarks=sample.bookmarks,
            notes=sample.notes,
            created_at=sample.created_at,
            updated_at=sample.updated_at,
        )

    def filter_evidence(
        self,
        sample_id: str,
        query: EvidenceFilterQuery,
    ) -> EvidenceListResponse:
        """Filter normalized evidence items by multi-dimensional criteria."""
        assessment = self.assessment_service.get_or_run_assessment(sample_id)
        all_items = assessment.evidence_summary.evidence_items

        filtered: list[AssessmentEvidenceItem] = []
        for item in all_items:
            if query.source and query.source.upper() not in (
                item.category.upper(),
                item.source.upper(),
            ):
                continue

            if query.severity and query.severity.upper() != item.strength.upper():
                continue

            if query.role and query.role.upper() != item.role.upper():
                continue

            if (
                query.observation_level
                and query.observation_level.upper() != item.observation_level.upper()
            ):
                continue

            if query.process:
                proc_str = str(item.technical_details.get("command_line", "")) + str(
                    item.technical_details.get("pid", "")
                )
                if (
                    query.process.lower() not in proc_str.lower()
                    and query.process.lower() not in item.statement.lower()
                ):
                    continue

            if query.function:
                src_id = (item.source_id or "").lower()
                stmt = (item.statement or "").lower()
                if query.function.lower() not in src_id and query.function.lower() not in stmt:
                    continue

            if query.technique:
                src_id = (item.source_id or "").lower()
                stmt = (item.statement or "").lower()
                if query.technique.lower() not in src_id and query.technique.lower() not in stmt:
                    continue

            if query.query:
                q = query.query.lower()
                text_corpus = (
                    f"{item.statement or ''} {item.source or ''} {item.source_id or ''} "
                    f"{item.provenance or ''} {item.evidence_type or ''}"
                ).lower()
                if q not in text_corpus:
                    continue

            filtered.append(item)

        return EvidenceListResponse(
            sample_id=sample_id,
            total_count=len(all_items),
            filtered_count=len(filtered),
            items=filtered,
        )

    # -------------------------------------------------------------------------
    # Bookmarks Management
    # -------------------------------------------------------------------------
    def create_bookmark(self, sample_id: str, request: BookmarkCreateRequest) -> Bookmark:
        """Create and attach an analyst bookmark to a finding or telemetry item."""
        sample = self._get_sample(sample_id)
        bookmark = Bookmark(
            bookmark_id=f"bmk-{uuid4().hex[:12]}",
            sample_id=sample_id,
            target_type=request.target_type,
            target_id=request.target_id,
            title=request.title,
            description=request.description,
            category=request.category,
            metadata=request.metadata,
            created_at=datetime.now(UTC),
        )

        sample.bookmarks.append(bookmark)
        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return bookmark

    def list_bookmarks(self, sample_id: str) -> list[Bookmark]:
        """List all bookmarks for a sample."""
        sample = self._get_sample(sample_id)
        return sample.bookmarks

    def delete_bookmark(self, sample_id: str, bookmark_id: str) -> bool:
        """Delete an existing bookmark by ID."""
        sample = self._get_sample(sample_id)
        original_count = len(sample.bookmarks)
        sample.bookmarks = [b for b in sample.bookmarks if b.bookmark_id != bookmark_id]

        if len(sample.bookmarks) == original_count:
            raise AppError(
                code="bookmark_not_found",
                message=f"Bookmark '{bookmark_id}' not found.",
                status_code=404,
            )

        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return True

    # -------------------------------------------------------------------------
    # Analyst Notes Management
    # -------------------------------------------------------------------------
    def create_note(self, sample_id: str, request: NoteCreateRequest) -> AnalystNote:
        """Create an analyst-authored note separate from automated evidence."""
        sample = self._get_sample(sample_id)
        note = AnalystNote(
            note_id=f"note-{uuid4().hex[:12]}",
            sample_id=sample_id,
            author=request.author,
            title=request.title,
            content=request.content,
            attached_evidence_ids=request.attached_evidence_ids,
            attached_bookmark_ids=request.attached_bookmark_ids,
            tags=request.tags,
            created_at=datetime.now(UTC),
        )

        sample.notes.append(note)
        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return note

    def list_notes(self, sample_id: str) -> list[AnalystNote]:
        """List all analyst notes for a sample."""
        sample = self._get_sample(sample_id)
        return sample.notes

    def update_note(
        self,
        sample_id: str,
        note_id: str,
        request: NoteUpdateRequest,
    ) -> AnalystNote:
        """Update an analyst note's title, content, attachments, or tags."""
        sample = self._get_sample(sample_id)
        for note in sample.notes:
            if note.note_id == note_id:
                if request.title is not None:
                    note.title = request.title
                if request.content is not None:
                    note.content = request.content
                if request.attached_evidence_ids is not None:
                    note.attached_evidence_ids = request.attached_evidence_ids
                if request.attached_bookmark_ids is not None:
                    note.attached_bookmark_ids = request.attached_bookmark_ids
                if request.tags is not None:
                    note.tags = request.tags
                note.updated_at = datetime.now(UTC)

                sample.updated_at = datetime.now(UTC)
                self.metadata_repository.upsert(sample)
                return note

        raise AppError(
            code="note_not_found",
            message=f"Analyst note '{note_id}' not found.",
            status_code=404,
        )

    def delete_note(self, sample_id: str, note_id: str) -> bool:
        """Delete an analyst note by ID."""
        sample = self._get_sample(sample_id)
        original_count = len(sample.notes)
        sample.notes = [n for n in sample.notes if n.note_id != note_id]

        if len(sample.notes) == original_count:
            raise AppError(
                code="note_not_found",
                message=f"Analyst note '{note_id}' not found.",
                status_code=404,
            )

        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return True
