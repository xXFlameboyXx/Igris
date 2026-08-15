"""Analysis orchestration service coordinating pipeline execution, retries, and partial results."""

import hashlib
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from igris import __version__
from igris.analysis.behavioral.service import BehaviorAnalysisService
from igris.analysis.file_intelligence.service import FileIntelligenceService
from igris.analysis.reverse_analysis.service import ReverseAnalysisService
from igris.analysis.similarity.service import SimilarityService
from igris.analysis.static_analysis.service import StaticAnalysisService
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.core.logging import get_logger
from igris.detection.service import DetectionService
from igris.intelligence.assessment.service import AssessmentService
from igris.intelligence.threat.service import ThreatIntelligenceService
from igris.ml.service import MLService
from igris.reporting.service import ReportingService
from igris.schemas.assessment import VerdictSummary
from igris.schemas.file_intelligence import Sample
from igris.schemas.orchestration import (
    AnalysisCreateRequest,
    AnalysisJob,
    FailureCategory,
    JobStatus,
    PipelineStageName,
    PipelineStageRecord,
    StageError,
    StageStatus,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.jobs import AnalysisJobRepository
from igris.storage.metadata import SampleMetadataRepository

logger = get_logger("igris.orchestration")

DEFAULT_PIPELINE_STAGES: list[PipelineStageName] = [
    PipelineStageName.FILE_INTELLIGENCE,
    PipelineStageName.STATIC_ANALYSIS,
    PipelineStageName.DETECTION,
    PipelineStageName.REVERSE_ANALYSIS,
    PipelineStageName.ML,
    PipelineStageName.BEHAVIOR,
    PipelineStageName.SIMILARITY,
    PipelineStageName.THREAT_INTELLIGENCE,
    PipelineStageName.EVIDENCE_CORRELATION,
    PipelineStageName.ASSESSMENT,
    PipelineStageName.REPORT,
]

STAGE_DEPENDENCIES: dict[PipelineStageName, list[PipelineStageName]] = {
    PipelineStageName.FILE_INTELLIGENCE: [],
    PipelineStageName.STATIC_ANALYSIS: [PipelineStageName.FILE_INTELLIGENCE],
    PipelineStageName.DETECTION: [PipelineStageName.STATIC_ANALYSIS],
    PipelineStageName.REVERSE_ANALYSIS: [PipelineStageName.FILE_INTELLIGENCE],
    PipelineStageName.ML: [PipelineStageName.STATIC_ANALYSIS],
    PipelineStageName.BEHAVIOR: [PipelineStageName.FILE_INTELLIGENCE],
    PipelineStageName.SIMILARITY: [PipelineStageName.STATIC_ANALYSIS],
    PipelineStageName.THREAT_INTELLIGENCE: [PipelineStageName.DETECTION],
    PipelineStageName.EVIDENCE_CORRELATION: [PipelineStageName.STATIC_ANALYSIS],
    PipelineStageName.ASSESSMENT: [PipelineStageName.EVIDENCE_CORRELATION],
    PipelineStageName.REPORT: [PipelineStageName.ASSESSMENT],
}


class OrchestrationService:
    """Coordinates analysis pipelines across all Igris engines while preserving partial results."""

    def __init__(
        self,
        settings: Settings,
        sample_storage: LocalSampleStorage,
        metadata_repository: SampleMetadataRepository,
        job_repository: AnalysisJobRepository,
    ) -> None:
        self.settings = settings
        self.sample_storage = sample_storage
        self.metadata_repository = metadata_repository
        self.job_repository = job_repository

        # Subsystem Services
        self.file_service = FileIntelligenceService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.static_service = StaticAnalysisService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.detection_service = DetectionService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.reverse_service = ReverseAnalysisService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.ml_service = MLService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.behavior_service = BehaviorAnalysisService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.similarity_service = SimilarityService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.threat_service = ThreatIntelligenceService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.assessment_service = AssessmentService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.reporting_service = ReportingService(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )

    def create_and_run_analysis(self, request: AnalysisCreateRequest) -> AnalysisJob:
        """Create an analysis job and synchronously or asynchronously execute the pipeline."""
        sample = self.metadata_repository.get(request.sample_id)
        if sample is None:
            raise AppError(
                code="sample_not_found",
                message=f"Sample '{request.sample_id}' not found.",
                status_code=404,
            )

        stages_to_run = request.enabled_stages or list(DEFAULT_PIPELINE_STAGES)
        engine_versions = self._get_engine_versions(sample)

        # Compute idempotency key
        idempotency_str = (
            f"{sample.hashes.sha256}:{','.join(sorted(stages_to_run))}:{engine_versions}"
        )
        idempotency_key = hashlib.sha256(idempotency_str.encode("utf-8")).hexdigest()

        # Idempotency check: reuse existing job if completed or running and not force_reanalyze
        if not request.force_reanalyze:
            existing_job = self.job_repository.get_by_idempotency_key(idempotency_key)
            if existing_job and existing_job.status in (JobStatus.COMPLETED, JobStatus.RUNNING):
                logger.info(
                    "Reusing existing analysis job",
                    extra={"analysis_id": existing_job.analysis_id, "sample_id": sample.sample_id},
                )
                return existing_job

        # Initialize pipeline stage records
        stage_records = [
            PipelineStageRecord(
                name=stg,
                status=StageStatus.QUEUED,
                dependencies=STAGE_DEPENDENCIES.get(stg, []),
            )
            for stg in stages_to_run
        ]

        job = AnalysisJob(
            analysis_id=f"job-{uuid4().hex[:12]}",
            sample_id=sample.sample_id,
            status=JobStatus.QUEUED,
            current_stage=None,
            progress=0,
            stages=stage_records,
            idempotency_key=idempotency_key,
            created_at=datetime.now(UTC),
            engine_versions=engine_versions,
        )
        self.job_repository.upsert(job)

        logger.info(
            "Created analysis job",
            extra={
                "analysis_id": job.analysis_id,
                "sample_id": sample.sample_id,
                "stages_count": len(stage_records),
            },
        )

        # Execute the pipeline
        return self._execute_pipeline(
            job,
            max_retries=request.max_retries if request.max_retries is not None else 2,
            timeout_seconds=request.timeout_seconds or self.settings.analysis_timeout_seconds,
        )

    def get_analysis_job(self, analysis_id: str) -> AnalysisJob:
        """Fetch full analysis job by ID."""
        job = self.job_repository.get(analysis_id)
        if job is None:
            raise AppError(
                code="analysis_not_found",
                message=f"Analysis job '{analysis_id}' not found.",
                status_code=404,
            )
        return job

    def list_analysis_jobs(
        self, sample_id: str | None = None, limit: int = 50
    ) -> list[AnalysisJob]:
        """List analysis jobs, optionally filtered by sample ID."""
        if sample_id:
            return self.job_repository.list_for_sample(sample_id)
        return self.job_repository.list_all(limit=limit)

    def cancel_analysis_job(
        self, analysis_id: str, reason: str = "Analyst requested cancellation"
    ) -> AnalysisJob:
        """Cancel an active or queued analysis job."""
        job = self.get_analysis_job(analysis_id)
        if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
            return job

        job.status = JobStatus.CANCELLED
        job.cancelled_at = datetime.now(UTC)
        job.cancellation_reason = reason

        for stg in job.stages:
            if stg.status in (StageStatus.QUEUED, StageStatus.NOT_STARTED, StageStatus.RUNNING):
                stg.status = StageStatus.CANCELLED

        self.job_repository.upsert(job)
        logger.info(
            "Analysis job cancelled",
            extra={"analysis_id": analysis_id, "reason": reason},
        )
        return job

    # =========================================================================
    # Pipeline Execution & Error Isolation Engine
    # =========================================================================

    def _execute_pipeline(
        self,
        job: AnalysisJob,
        max_retries: int = 2,
        timeout_seconds: int = 30,
    ) -> AnalysisJob:
        """Execute all configured stages with dependency enforcement and failure isolation."""
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(UTC)
        self.job_repository.upsert(job)

        sample_id = job.sample_id
        completed_or_skipped_count = 0
        total_stages = len(job.stages)

        stage_status_map: dict[PipelineStageName, StageStatus] = {
            s.name: s.status for s in job.stages
        }

        for stage_record in job.stages:
            # Check for job cancellation
            current_job_state = self.job_repository.get(job.analysis_id)
            if current_job_state and current_job_state.status == JobStatus.CANCELLED:
                job.status = JobStatus.CANCELLED
                job.cancelled_at = current_job_state.cancelled_at
                job.cancellation_reason = current_job_state.cancellation_reason
                break

            stage_name = stage_record.name

            # Check if required dependencies completed successfully
            missing_dep = self._check_dependencies(stage_name, stage_status_map)
            if missing_dep:
                stage_record.status = StageStatus.SKIPPED
                stage_record.error = StageError(
                    error_category=FailureCategory.NON_RETRYABLE,
                    safe_message=f"Skipped: dependency '{missing_dep}' did not complete.",
                )
                stage_status_map[stage_name] = StageStatus.SKIPPED
                completed_or_skipped_count += 1
                job.progress = int((completed_or_skipped_count / total_stages) * 100)
                self.job_repository.upsert(job)
                logger.info(
                    "Skipped pipeline stage due to dependency",
                    extra={
                        "analysis_id": job.analysis_id,
                        "stage": stage_name,
                        "missing_dep": missing_dep,
                    },
                )
                continue

            # Stage execution
            job.current_stage = stage_name
            stage_record.status = StageStatus.RUNNING
            stage_record.started_at = datetime.now(UTC)
            self.job_repository.upsert(job)

            attempt = 0
            success = False

            while attempt <= max_retries and not success:
                attempt += 1
                try:
                    start_time = time.perf_counter()
                    self._dispatch_stage_service(stage_name, sample_id)
                    end_time = time.perf_counter()

                    stage_record.status = StageStatus.COMPLETED
                    stage_record.completed_at = datetime.now(UTC)
                    stage_record.duration_ms = (end_time - start_time) * 1000
                    stage_record.result_available = True
                    stage_status_map[stage_name] = StageStatus.COMPLETED
                    success = True

                    logger.info(
                        "Pipeline stage completed successfully",
                        extra={
                            "analysis_id": job.analysis_id,
                            "stage": stage_name,
                            "duration_ms": stage_record.duration_ms,
                        },
                    )
                except Exception as exc:
                    is_retryable = self._is_retryable_error(exc)
                    cat = (
                        FailureCategory.RETRYABLE if is_retryable else FailureCategory.NON_RETRYABLE
                    )

                    if is_retryable and attempt <= max_retries:
                        stage_record.retry_count += 1
                        logger.warning(
                            "Stage transient failure, retrying",
                            extra={
                                "analysis_id": job.analysis_id,
                                "stage": stage_name,
                                "attempt": attempt,
                                "error": str(exc),
                            },
                        )
                        time.sleep(0.1 * attempt)
                    else:
                        # Non-retryable or retries exhausted
                        stage_record.status = StageStatus.FAILED
                        stage_record.completed_at = datetime.now(UTC)
                        stage_record.error = StageError(
                            error_category=cat,
                            safe_message=self._sanitize_error_message(exc),
                            attempt_number=attempt,
                        )
                        stage_status_map[stage_name] = StageStatus.FAILED
                        logger.error(
                            "Pipeline stage failed",
                            extra={
                                "analysis_id": job.analysis_id,
                                "stage": stage_name,
                                "error_category": cat,
                                "error": str(exc),
                            },
                        )
                        break

            completed_or_skipped_count += 1
            job.progress = int((completed_or_skipped_count / total_stages) * 100)
            self.job_repository.upsert(job)

        # Finalize job metrics and explainable verdict summary
        job.completed_at = datetime.now(UTC)
        job.current_stage = None
        job.progress = 100

        # Update final verdict summary and report reference if sample was assessed
        sample = self.metadata_repository.get(sample_id)
        if sample and sample.malware_assessment:
            job.verdict_summary = VerdictSummary(
                sample_id=sample.sample_id,
                sha256=sample.hashes.sha256,
                verdict=sample.malware_assessment.verdict,
                risk_level=sample.malware_assessment.risk_level,
                risk_score=sample.malware_assessment.risk_score,
                confidence=sample.malware_assessment.confidence,
                summary=sample.malware_assessment.explanation.summary,
                limitations=sample.malware_assessment.limitations,
                created_at=sample.malware_assessment.created_at,
            )

        if job.status != JobStatus.CANCELLED:
            # If critical first stage failed or zero stages completed
            completed_stages = sum(1 for s in job.stages if s.status == StageStatus.COMPLETED)
            if completed_stages == 0:
                job.status = JobStatus.FAILED
                job.error = "All pipeline analysis stages failed."
            else:
                job.status = JobStatus.COMPLETED

        self.job_repository.upsert(job)
        return job

    def _check_dependencies(
        self,
        stage_name: PipelineStageName,
        stage_status_map: dict[PipelineStageName, StageStatus],
    ) -> PipelineStageName | None:
        """Return the name of any missing required dependency, or None if all satisfied."""
        deps = STAGE_DEPENDENCIES.get(stage_name, [])
        for dep in deps:
            if dep in stage_status_map and stage_status_map[dep] != StageStatus.COMPLETED:
                return dep
        return None

    def _dispatch_stage_service(self, stage_name: PipelineStageName, sample_id: str) -> Any:
        """Call the appropriate existing analysis engine service."""
        match stage_name:
            case PipelineStageName.FILE_INTELLIGENCE:
                return self.file_service.get_file_info(sample_id)

            case PipelineStageName.STATIC_ANALYSIS:
                return self.static_service.run(sample_id)

            case PipelineStageName.DETECTION:
                return self.detection_service.run(sample_id)

            case PipelineStageName.REVERSE_ANALYSIS:
                return self.reverse_service.run(sample_id)

            case PipelineStageName.ML:
                return self.ml_service.predict(sample_id)

            case PipelineStageName.BEHAVIOR:
                return self.behavior_service.run(sample_id)

            case PipelineStageName.SIMILARITY:
                return self.similarity_service.run(sample_id)

            case PipelineStageName.THREAT_INTELLIGENCE:
                return self.threat_service.run(sample_id)

            case PipelineStageName.EVIDENCE_CORRELATION:
                # Runs evidence aggregation
                return self.assessment_service.get_or_run_assessment(sample_id)

            case PipelineStageName.ASSESSMENT:
                return self.assessment_service.get_or_run_assessment(sample_id)

            case PipelineStageName.REPORT:
                return self.reporting_service.generate_report(sample_id)

            case _:
                raise AppError(
                    code="unknown_stage",
                    message=f"Unsupported pipeline stage '{stage_name}'.",
                )

    def _is_retryable_error(self, exc: Exception) -> bool:
        """Determine if an exception represents a transient/infrastructure failure."""
        if isinstance(exc, (TimeoutError, ConnectionError)):
            return True
        err_msg = str(exc).lower()
        if "temporary" in err_msg or "timeout" in err_msg or "busy" in err_msg:
            return True
        return False

    def _sanitize_error_message(self, exc: Exception) -> str:
        """Return a safe, user-facing error message without raw trace leakage."""
        if isinstance(exc, AppError):
            return exc.message
        msg = str(exc).strip()
        if not msg:
            return "Internal stage execution failed."
        # Keep only the first line of the error message
        first_line = msg.split("\n")[0][:200]
        return first_line

    def _get_engine_versions(self, sample: Sample) -> dict[str, str]:
        """Collect version metadata for reproducibility and idempotency."""
        return {
            "igris": __version__,
            "file_intelligence": "v1.0",
            "static_analysis": "v1.0",
            "reverse_analysis": "v1.0",
            "behavior_analysis": "v1.0",
            "detection_engine": "v1.2",
            "ml_model": sample.ml_prediction.model_version if sample.ml_prediction else "v2.1",
            "similarity_engine": "v1.0",
            "assessment_engine": "v1.0",
        }
