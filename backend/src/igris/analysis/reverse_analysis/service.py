"""Application service for Phase 4 reverse analysis."""

from datetime import UTC, datetime

from igris.analysis.reverse_analysis.analyzer import analyze_reverse
from igris.analysis.static_analysis.service import StaticAnalysisService
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.schemas.reverse_analysis import (
    CFGResponse,
    FunctionResponse,
    FunctionsResponse,
    ReverseAnalysisResponse,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class ReverseAnalysisService:
    """Coordinate cached reverse engineering over stored samples."""

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

    def run(self, sample_id: str) -> ReverseAnalysisResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.reverse_analysis is not None:
            return ReverseAnalysisResponse(reverse_analysis=sample.reverse_analysis)

        static_service = StaticAnalysisService(
            settings=self.settings,
            sample_storage=self.sample_storage,
            metadata_repository=self.metadata_repository,
        )
        static_service.run(sample_id)
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)

        path = self.sample_storage.resolve(sample.storage_ref)
        result = analyze_reverse(sample, path, self.settings)
        sample.reverse_analysis = result
        sample.updated_at = datetime.now(UTC)
        self.metadata_repository.upsert(sample)
        return ReverseAnalysisResponse(reverse_analysis=result)

    def get(self, sample_id: str) -> ReverseAnalysisResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.reverse_analysis is None:
            raise AppError(
                "Reverse analysis has not been run for this sample",
                code="reverse_analysis_not_found",
                status_code=404,
            )
        return ReverseAnalysisResponse(reverse_analysis=sample.reverse_analysis)

    def list_functions(self, sample_id: str) -> FunctionsResponse:
        analysis = self.get(sample_id).reverse_analysis
        return FunctionsResponse(sample_id=sample_id, functions=analysis.functions)

    def get_function(self, sample_id: str, function_id: str) -> FunctionResponse:
        analysis = self.get(sample_id).reverse_analysis
        for function in analysis.functions:
            if function.function_id == function_id:
                return FunctionResponse(sample_id=sample_id, function=function)
        raise AppError("Function not found", code="function_not_found", status_code=404)

    def get_cfg(self, sample_id: str, function_id: str) -> CFGResponse:
        analysis = self.get(sample_id).reverse_analysis
        cfg = analysis.cfgs.get(function_id)
        if cfg is None:
            raise AppError("CFG not found", code="cfg_not_found", status_code=404)
        return CFGResponse(sample_id=sample_id, cfg=cfg)
