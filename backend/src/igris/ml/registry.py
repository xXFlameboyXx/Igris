"""Versioned model registry loading for Phase 6."""

import json
from pathlib import Path
from typing import Any

import joblib
from pydantic import TypeAdapter, ValidationError

from igris.core.errors import AppError
from igris.schemas.ml import ModelMetadata, ModelRegistry

REGISTRY_ADAPTER = TypeAdapter(ModelRegistry)


def load_model_registry(path: Path) -> ModelRegistry:
    """Load and validate the JSON model registry."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return REGISTRY_ADAPTER.validate_python(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise AppError(
            "ML model registry failed validation",
            code="ml_registry_invalid",
            status_code=500,
            details={"path": str(path), "reason": str(exc)},
        ) from exc


def get_model_metadata(registry: ModelRegistry, model_version: str | None = None) -> ModelMetadata:
    """Return active or requested model metadata."""

    selected_version = model_version or registry.active_model_version
    for model in registry.models:
        if model.model_version == selected_version:
            return model
    raise AppError(
        "Requested ML model version is not available",
        code="ml_model_version_mismatch",
        status_code=409,
        details={"requested": selected_version, "active": registry.active_model_version},
    )


def load_model_artifact(metadata: ModelMetadata) -> Any:
    """Load the trained model artifact referenced by metadata."""

    try:
        return joblib.load(metadata.artifact_path)
    except OSError as exc:
        raise AppError(
            "ML model artifact could not be loaded",
            code="ml_model_load_failed",
            status_code=500,
            details={"model_version": metadata.model_version, "path": metadata.artifact_path},
        ) from exc
