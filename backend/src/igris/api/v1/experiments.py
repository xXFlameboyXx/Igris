"""API routes for Phase 15 evaluation experiments and research infrastructure."""

from typing import Any

from fastapi import APIRouter, Request, status

from igris.evaluation.service import EvaluationService
from igris.schemas.evaluation import (
    ExperimentArtifactsResponse,
    ExperimentConfig,
    ExperimentCreateRequest,
    ExperimentListResponse,
    ExperimentRecord,
    ExperimentResponse,
    ExperimentResultsResponse,
)

router = APIRouter(prefix="/experiments", tags=["experiments"])


def _evaluation_service_from_request(request: Request) -> EvaluationService:
    return EvaluationService(
        settings=request.app.state.settings,
        sample_storage=request.app.state.sample_storage,
        metadata_repository=request.app.state.metadata_repository,
        job_repository=request.app.state.jobs_repository,
        experiment_repository=request.app.state.experiment_repository,
        dataset_repository=request.app.state.dataset_repository,
    )


@router.post(
    "",
    response_model=ExperimentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_experiment(request: Request, body: ExperimentCreateRequest) -> ExperimentResponse:
    """Define, configure, and execute a controlled empirical research experiment."""
    service = _evaluation_service_from_request(request)
    config_kwargs: dict[str, Any] = {
        "research_question": body.research_question,
        "dataset_id": body.dataset_id,
        "dataset_version": body.dataset_version,
        "split_strategy": body.split_strategy,
        "random_seed": body.random_seed,
        "max_samples": body.max_samples,
        "description": body.description,
    }
    if body.ablation_configurations is not None:
        config_kwargs["ablation_configurations"] = body.ablation_configurations

    config = ExperimentConfig(**config_kwargs)
    experiment = service.run_experiment(config)
    return ExperimentResponse(experiment=experiment)


@router.get("", response_model=ExperimentListResponse)
async def list_experiments(request: Request, limit: int = 100) -> ExperimentListResponse:
    """List registered research experiments."""
    service = _evaluation_service_from_request(request)
    experiments = service.list_experiments(limit=limit)
    return ExperimentListResponse(experiments=experiments, total_count=len(experiments))


@router.get("/{experiment_id}", response_model=ExperimentResponse)
async def get_experiment(request: Request, experiment_id: str) -> ExperimentResponse:
    """Fetch complete metadata and reproducibility parameters for an experiment."""
    service = _evaluation_service_from_request(request)
    experiment = service.get_experiment(experiment_id)
    return ExperimentResponse(experiment=experiment)


@router.get("/{experiment_id}/results", response_model=ExperimentResultsResponse)
async def get_experiment_results(request: Request, experiment_id: str) -> ExperimentResultsResponse:
    """Retrieve detailed ablation comparisons, confusion matrices, and error taxonomy records."""
    service = _evaluation_service_from_request(request)
    exp = service.get_experiment(experiment_id)
    return ExperimentResultsResponse(
        experiment_id=exp.experiment_id,
        ablation_results=exp.ablation_results,
        error_analysis=exp.error_analysis,
        overall_metrics=exp.overall_metrics,
        overall_performance=exp.overall_performance,
    )


@router.get("/{experiment_id}/artifacts", response_model=ExperimentArtifactsResponse)
async def get_experiment_artifacts(
    request: Request, experiment_id: str
) -> ExperimentArtifactsResponse:
    """Export machine-readable JSON research artifacts and summary markdown."""
    service = _evaluation_service_from_request(request)
    exp = service.get_experiment(experiment_id)

    json_str = exp.model_dump_json(indent=2)
    summary_md = _generate_experiment_markdown_summary(exp)

    return ExperimentArtifactsResponse(
        experiment_id=exp.experiment_id,
        reproducibility_metadata=exp.reproducibility,
        json_report=json_str,
        summary_markdown=summary_md,
    )


def _generate_experiment_markdown_summary(exp: ExperimentRecord) -> str:
    """Generate structured markdown summary of the experiment."""
    f1 = exp.overall_metrics.f1_score if exp.overall_metrics else "N/A"
    prec = exp.overall_metrics.precision if exp.overall_metrics else "N/A"
    rec = exp.overall_metrics.recall if exp.overall_metrics else "N/A"

    lines = [
        f"# Evaluation Experiment Report: {exp.experiment_id}",
        f"**Research Question:** {exp.config.research_question}",
        f"**Dataset:** {exp.config.dataset_id} ({exp.config.dataset_version})",
        f"**Split Strategy:** {exp.config.split_strategy}",
        f"**Execution Timestamp:** {exp.created_at.isoformat()}",
        "",
        "## Summary Metrics",
        f"- **F1 Score:** {f1}",
        f"- **Precision:** {prec}",
        f"- **Recall:** {rec}",
        "",
        "## Ablation Configurations Evaluated",
    ]

    for ab in exp.ablation_results:
        lat = ab.performance.mean_sample_latency_ms
        lines.append(
            f"- **{ab.configuration_name}:** F1={ab.metrics.f1_score}, "
            f"Latency={lat:.1f}ms, Errors={ab.error_count}"
        )

    lines.extend(
        [
            "",
            "## Threats to Validity",
            *[f"- {t}" for t in exp.threats_to_validity],
            "",
            "## Evidence-Supported Conclusions",
            *[f"- {c}" for c in exp.conclusions],
        ]
    )

    return "\n".join(lines)
