"""Application service for Phase 2 static analysis."""

from datetime import UTC, datetime

from igris.analysis.static_analysis.analyzer import analyze_static
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.schemas.static_analysis import StaticAnalysisResponse
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class StaticAnalysisService:
    """Coordinate idempotent static analysis over stored hostile samples."""

    def __init__(
        self,
        *,
        settings: Settings,
        sample_storage: LocalSampleStorage,
        metadata_repository: SampleMetadataRepository,
    ) -> None:
        self.settings = settings
        self.sample_storage = sample_storage
        self.metadata_repository = metadata_repository

    def run(self, sample_id: str) -> StaticAnalysisResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.static_analysis is not None:
            return StaticAnalysisResponse(analysis=sample.static_analysis)
        path = self.sample_storage.resolve(sample.storage_ref)
        analysis = analyze_static(sample, path, self.settings)
        sample.static_analysis = analysis
        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return StaticAnalysisResponse(analysis=analysis)

    def get(self, sample_id: str) -> StaticAnalysisResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.static_analysis is None:
            raise AppError(
                "Static analysis has not been run for this sample",
                code="static_analysis_not_found",
                status_code=404,
            )
        return StaticAnalysisResponse(analysis=sample.static_analysis)
