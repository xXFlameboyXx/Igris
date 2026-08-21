"""Report generation engine synthesizing multi-layer evidence into structured dossiers."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from igris import __version__
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.intelligence.assessment.service import AssessmentService
from igris.schemas.file_intelligence import Sample
from igris.schemas.investigation import (
    InvestigationReport,
    ReportVersionMetadata,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class ReportGenerator:
    """Synthesizes sample telemetry, explainable assessments, and analyst notes into dossiers."""

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

    def generate(self, sample_id: str) -> InvestigationReport:
        """Generate a complete, structured investigation report."""
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError(
                code="sample_not_found",
                message=f"Sample '{sample_id}' not found.",
                status_code=404,
            )

        assessment = self.assessment_service.get_or_run_assessment(sample_id)

        # Version and engine provenance metadata
        engine_versions = {
            "file_intelligence": "v1.0",
            "static_analysis": "v1.0",
            "reverse_analysis": "v1.0",
            "behavior_analysis": "v1.0",
            "detection_engine": "v1.2",
            "ml_model": sample.ml_prediction.model_version if sample.ml_prediction else "v2.1",
            "similarity_engine": "v1.0",
            "assessment_engine": "v1.0",
        }

        version_metadata = ReportVersionMetadata(
            igris_version=__version__,
            report_schema_version="report/v1",
            engine_versions=engine_versions,
            rule_version="v1.2",
            attack_dataset_version="v14.1",
            generated_at=datetime.now(UTC),
        )

        # Sample Identification
        sample_ident: dict[str, Any] = {
            "sample_id": sample.sample_id,
            "original_filename": sample.original_filename,
            "safe_filename": sample.safe_filename,
            "size_bytes": sample.size_bytes,
            "sha256": sample.hashes.sha256,
            "sha1": sample.hashes.sha1,
            "md5": sample.hashes.md5,
            "detected_format": sample.file_metadata.detected_format
            if sample.file_metadata
            else "unknown",
            "architecture": sample.file_metadata.architecture
            if sample.file_metadata
            else "unknown",
            "mime_type": sample.file_metadata.mime_type
            if sample.file_metadata
            else "application/octet-stream",
            "status": sample.status,
            "created_at": sample.created_at.isoformat(),
        }

        # Verdict Assessment
        verdict_data: dict[str, Any] = {
            "verdict": assessment.verdict,
            "risk_level": assessment.risk_level,
            "risk_score": assessment.risk_score.model_dump(mode="json"),
            "confidence_breakdown": assessment.confidence.model_dump(mode="json"),
        }

        # Epistemology Summary
        epistemology_data: dict[str, list[str]] = {
            "observed_facts": assessment.explanation.observed_findings,
            "inferred_conclusions": assessment.explanation.inferred_findings,
            "possible_hypotheses": assessment.explanation.possible_hypotheses,
            "supporting_arguments": assessment.explanation.supporting_arguments,
            "contradicting_arguments": assessment.explanation.contradicting_arguments,
        }

        # Subsystem Summaries
        subsystem_data = self._summarize_subsystems(sample)

        # Tracked Uncertainties
        uncertainties = [
            {"category": u.category, "reason": u.reason, "impact": u.impact}
            for u in assessment.evidence_summary.uncertainties
        ]
        if not uncertainties and assessment.explanation.uncertainty_and_unknowns:
            uncertainties = [
                {"category": "general", "reason": u, "impact": "Telemetry unobserved"}
                for u in assessment.explanation.uncertainty_and_unknowns
            ]

        return InvestigationReport(
            report_id=f"rpt-{uuid4().hex[:12]}",
            sample_id=sample.sample_id,
            sha256=sample.hashes.sha256,
            version_metadata=version_metadata,
            executive_summary=assessment.explanation.summary,
            sample_identification=sample_ident,
            verdict_assessment=verdict_data,
            epistemology_summary=epistemology_data,
            subsystem_summaries=subsystem_data,
            evidence_items=assessment.evidence_summary.evidence_items,
            analyst_notes=sample.notes,
            analyst_bookmarks=sample.bookmarks,
            uncertainties=uncertainties,
            limitations=assessment.limitations,
        )

    def _summarize_subsystems(self, sample: Sample) -> dict[str, Any]:
        """Produce clean, summarized digests of all subsystem outputs."""
        summaries: dict[str, Any] = {}

        # Static Analysis Summary
        if sample.static_analysis:
            summaries["static_analysis"] = {
                "status": sample.static_analysis.status,
                "entropy_mean": sample.static_analysis.feature_vector.entropy_mean,
                "entropy_max": sample.static_analysis.feature_vector.entropy_max,
                "strings_count": len(sample.static_analysis.strings),
                "imported_dlls_count": len(sample.static_analysis.imports),
                "evidence_count": len(sample.static_analysis.evidence),
            }
        else:
            summaries["static_analysis"] = {"status": "not_performed"}

        # Reverse Analysis Summary
        if sample.reverse_analysis:
            summaries["reverse_analysis"] = {
                "status": sample.reverse_analysis.status,
                "functions_count": len(sample.reverse_analysis.functions),
                "suspicious_functions_count": sum(
                    1 for f in sample.reverse_analysis.functions if len(f.evidence) > 0
                ),
                "evidence_count": len(sample.reverse_analysis.evidence),
            }
        else:
            summaries["reverse_analysis"] = {"status": "not_performed"}

        # Behavioral Analysis Summary
        if sample.behavior_analysis:
            summaries["behavior_analysis"] = {
                "status": sample.behavior_analysis.status,
                "analysis_mode": sample.behavior_analysis.sandbox_metadata.analysis_mode,
                "processes_count": len(sample.behavior_analysis.processes),
                "registry_events_count": len(sample.behavior_analysis.registry_events),
                "network_events_count": len(sample.behavior_analysis.network_events),
                "dropped_files_count": len(sample.behavior_analysis.dropped_files),
                "evidence_count": len(sample.behavior_analysis.evidence),
            }
        else:
            summaries["behavior_analysis"] = {"status": "not_performed"}

        # Threat Assessment Summary
        if sample.threat_assessment:
            techniques_list = [
                {
                    "technique_id": t.technique_id,
                    "technique_name": t.technique_name,
                    "tactic": str(t.tactic),
                    "subtechnique_id": t.subtechnique_id,
                    "subtechnique_name": t.subtechnique_name,
                    "description": t.description,
                    "how_it_works": t.how_it_works,
                    "why_igris_mapped": t.why_igris_mapped,
                    "hypothesis": t.hypothesis,
                    "classification": str(t.label),
                    "confidence": t.confidence,
                    "supporting_evidence": [e.model_dump() for e in t.supporting_evidence],
                }
                for t in sample.threat_assessment.techniques
            ]
            summaries["threat_assessment"] = {
                "status": "completed",
                "capabilities_count": len(sample.threat_assessment.capabilities),
                "attack_techniques_count": len(sample.threat_assessment.techniques),
                "narrative": sample.threat_assessment.narrative,
                "techniques": techniques_list,
            }
        else:
            summaries["threat_assessment"] = {"status": "not_performed"}

        # ML Prediction Summary
        if sample.ml_prediction:
            summaries["ml_prediction"] = {
                "status": "completed",
                "prediction": sample.ml_prediction.prediction,
                "score": sample.ml_prediction.score,
                "uncertainty": sample.ml_prediction.uncertainty,
                "model_version": sample.ml_prediction.model_version,
            }
        else:
            summaries["ml_prediction"] = {"status": "not_performed"}

        # Similarity Summary
        if sample.similarity_analysis:
            summaries["similarity_analysis"] = {
                "status": "completed",
                "candidates_evaluated": sample.similarity_analysis.total_candidates_evaluated,
                "matches_count": len(sample.similarity_analysis.matches),
                "summary": sample.similarity_analysis.summary,
                "attribution_guardrail": "cluster_only",
            }
        else:
            summaries["similarity_analysis"] = {"status": "not_performed"}

        return summaries
