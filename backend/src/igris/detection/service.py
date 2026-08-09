"""Application service for Phase 3 detection."""

from datetime import UTC, datetime
from pathlib import Path

from igris.analysis.static_analysis.service import StaticAnalysisService
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.detection.engine import DetectionEngine
from igris.detection.rules import RuleEngine
from igris.schemas.detection import DetectionResponse
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class DetectionService:
    """Coordinate idempotent detection over static-analysis evidence."""

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

    def run(self, sample_id: str) -> DetectionResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.detection is not None:
            return DetectionResponse(detection=sample.detection)

        static_service = StaticAnalysisService(
            settings=self.settings,
            sample_storage=self.sample_storage,
            metadata_repository=self.metadata_repository,
        )
        static_analysis = static_service.run(sample_id).analysis
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)

        engine = DetectionEngine(
            settings=self.settings,
            rule_engine=RuleEngine.from_path(Path(self.settings.detection_rules_path)),
        )
        detection = engine.assess(static_analysis)
        sample.detection = detection
        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return DetectionResponse(detection=detection)

    def get(self, sample_id: str) -> DetectionResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.detection is None:
            raise AppError(
                "Detection has not been run for this sample",
                code="detection_not_found",
                status_code=404,
            )
        return DetectionResponse(detection=sample.detection)
