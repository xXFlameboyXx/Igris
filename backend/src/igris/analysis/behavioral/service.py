"""Application service for Phase 7 behavior analysis.

The current implementation uses SyntheticBehaviorAnalyzer, which generates
deterministic telemetry without reading or executing uploaded sample bytes.

Behavior analysis is triggered only by explicit analyst request:
POST /api/v1/samples/{id}/behavior-analysis. It is never triggered
automatically during upload or by other analysis phases. Once a behavior
result exists, downstream engines may consume the cached evidence without
launching execution or sandbox infrastructure.
"""

from datetime import UTC, datetime

from igris.analysis.behavioral.synthetic import SyntheticBehaviorAnalyzer
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.schemas.behavior_analysis import (
    BehaviorAnalysisResponse,
    BehaviorEventsResponse,
    BehaviorEvidenceResponse,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class BehaviorAnalysisService:
    """Orchestrate behavior analysis with caching and provenance."""

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

    def run(self, sample_id: str) -> BehaviorAnalysisResponse:
        """Run behavior analysis or return the cached result."""

        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.behavior_analysis is not None:
            return BehaviorAnalysisResponse(behavior_analysis=sample.behavior_analysis)

        analyzer = SyntheticBehaviorAnalyzer()
        result = analyzer.analyze(
            sample_id=sample_id,
            timeout_seconds=self.settings.sandbox_timeout_seconds,
        )
        sample.behavior_analysis = result
        sample.detection = None
        sample.threat_assessment = None
        sample.ml_prediction = None
        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return BehaviorAnalysisResponse(behavior_analysis=result)

    def get(self, sample_id: str) -> BehaviorAnalysisResponse:
        """Return a previously generated behavior-analysis result."""

        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.behavior_analysis is None:
            raise AppError(
                "Behavior analysis has not been run for this sample",
                code="behavior_analysis_not_found",
                status_code=404,
            )
        return BehaviorAnalysisResponse(behavior_analysis=sample.behavior_analysis)

    def events(self, sample_id: str) -> BehaviorEventsResponse:
        """Return the behavior event timeline from a cached result."""

        result = self.get(sample_id).behavior_analysis
        return BehaviorEventsResponse(
            sample_id=sample_id,
            processes=result.processes,
            file_events=result.file_events,
            registry_events=result.registry_events,
            network_events=result.network_events,
        )

    def evidence(self, sample_id: str) -> BehaviorEvidenceResponse:
        """Return behavior-derived evidence from a cached result."""

        result = self.get(sample_id).behavior_analysis
        return BehaviorEvidenceResponse(
            sample_id=sample_id,
            evidence=result.evidence,
        )
