"""Versioned deterministic feature extraction for Phase 6 ML."""

from collections import Counter
from statistics import mean

from igris.schemas.behavior_analysis import BehaviorEvidenceType
from igris.schemas.file_intelligence import Sample, SectionMetadata
from igris.schemas.ml import ML_FEATURE_SCHEMA_VERSION, MLFeatureSet, MLFeatureVector
from igris.schemas.reverse_analysis import ReverseAnalysisResult, ReverseEvidenceType
from igris.schemas.static_analysis import (
    EvidenceType,
    ImportCategory,
    StaticAnalysisResult,
    StringCategory,
)

BASE_FEATURE_NAMES = [
    "file_size_bytes",
    "section_count",
    "entropy_min",
    "entropy_max",
    "entropy_mean",
    "import_count",
    "resource_count",
    "overlay_size",
    "executable_section_count",
    "writable_executable_section_count",
]

API_FEATURE_NAMES = [f"api_category_count.{item.value}" for item in ImportCategory]
STRING_FEATURE_NAMES = [f"string_count.{item.value}" for item in StringCategory]
EVIDENCE_FEATURE_NAMES = [f"static_evidence_count.{item.value}" for item in EvidenceType]
REVERSE_FEATURE_NAMES = [
    "reverse.function_count",
    "reverse.instruction_count",
    "reverse.basic_block_count",
    "reverse.cyclomatic_complexity_max",
    "reverse.cyclomatic_complexity_mean",
    *[f"reverse_evidence_count.{item.value}" for item in ReverseEvidenceType],
]
FUTURE_BEHAVIOR_FEATURE_NAMES = [
    "behavior.event_count",
    "behavior.network_connection_count",
    "behavior.process_creation_count",
]

ML_FEATURE_NAMES = [
    *BASE_FEATURE_NAMES,
    *API_FEATURE_NAMES,
    *STRING_FEATURE_NAMES,
    *EVIDENCE_FEATURE_NAMES,
    *REVERSE_FEATURE_NAMES,
    *FUTURE_BEHAVIOR_FEATURE_NAMES,
]


def build_ml_feature_vector(
    *,
    sample: Sample,
    static_analysis: StaticAnalysisResult,
    reverse_analysis: ReverseAnalysisResult | None,
    feature_set: MLFeatureSet,
) -> MLFeatureVector:
    """Build a stable numeric vector without executing or mutating the sample."""

    features = {name: 0.0 for name in ML_FEATURE_NAMES}
    sections = _sections(sample)
    entropies = [section.entropy for section in sections if section.entropy is not None]

    features["file_size_bytes"] = float(sample.size_bytes)
    features["section_count"] = float(len(sections))
    features["entropy_min"] = float(min(entropies)) if entropies else 0.0
    features["entropy_max"] = float(max(entropies)) if entropies else 0.0
    features["entropy_mean"] = float(mean(entropies)) if entropies else 0.0
    features["import_count"] = float(len(static_analysis.imports))
    features["resource_count"] = float(len(static_analysis.resources))

    if static_analysis.pe_features is not None:
        pe_features = static_analysis.pe_features
        features["overlay_size"] = float(pe_features.overlay_size)
        features["executable_section_count"] = float(pe_features.executable_section_count)
        features["writable_executable_section_count"] = float(
            pe_features.writable_executable_section_count
        )

    _copy_count_features(
        target=features,
        prefix="api_category_count",
        counts=static_analysis.feature_vector.api_category_counts,
    )
    _copy_count_features(
        target=features,
        prefix="string_count",
        counts=static_analysis.feature_vector.string_counts,
    )
    _copy_count_features(
        target=features,
        prefix="static_evidence_count",
        counts=static_analysis.feature_vector.evidence_counts,
    )

    if feature_set in {
        MLFeatureSet.STATIC_REVERSE,
        MLFeatureSet.STATIC_FUTURE_BEHAVIOR,
    } and reverse_analysis is not None:
        complexities = [item.cyclomatic_complexity for item in reverse_analysis.functions]
        features["reverse.function_count"] = float(len(reverse_analysis.functions))
        features["reverse.instruction_count"] = float(
            reverse_analysis.disassembly.instruction_count
        )
        features["reverse.basic_block_count"] = float(
            sum(item.basic_block_count for item in reverse_analysis.functions)
        )
        features["reverse.cyclomatic_complexity_max"] = (
            float(max(complexities)) if complexities else 0.0
        )
        features["reverse.cyclomatic_complexity_mean"] = (
            float(mean(complexities)) if complexities else 0.0
        )
        reverse_counts = Counter(str(item.type) for item in reverse_analysis.evidence)
        _copy_count_features(
            target=features,
            prefix="reverse_evidence_count",
            counts=reverse_counts,
        )

    if feature_set == MLFeatureSet.STATIC_FUTURE_BEHAVIOR and sample.behavior_analysis is not None:
        behavior = sample.behavior_analysis
        features["behavior.event_count"] = float(
            len(behavior.processes)
            + len(behavior.file_events)
            + len(behavior.registry_events)
            + len(behavior.network_events)
            + len(behavior.mutexes)
        )
        behavior_counts = Counter(str(item.type) for item in behavior.evidence)
        features["behavior.network_connection_count"] = float(
            behavior_counts.get(str(BehaviorEvidenceType.NETWORK_CONNECTION), 0)
        )
        features["behavior.process_creation_count"] = float(
            behavior_counts.get(str(BehaviorEvidenceType.PROCESS_CREATION), 0)
        )

    limitations = [
        "Feature extraction never executes the sample.",
        "Behavior features are populated only from cached behavior-analysis results.",
    ]
    return MLFeatureVector(
        sample_id=sample.sample_id,
        feature_schema_version=ML_FEATURE_SCHEMA_VERSION,
        feature_set=feature_set,
        features=features,
        missing_features=[],
        limitations=limitations,
    )


def vectorize_features(
    features: dict[str, float], feature_names: list[str]
) -> tuple[list[float], list[str]]:
    """Return values in model order plus any missing feature names."""

    missing = [name for name in feature_names if name not in features]
    values = [float(features.get(name, 0.0)) for name in feature_names]
    return values, missing


def _copy_count_features(
    *,
    target: dict[str, float],
    prefix: str,
    counts: dict[str, int] | Counter[str],
) -> None:
    for key, value in counts.items():
        feature_name = f"{prefix}.{key}"
        if feature_name in target:
            target[feature_name] = float(value)


def _sections(sample: Sample) -> list[SectionMetadata]:
    metadata = sample.file_metadata
    if metadata is None:
        return []
    if metadata.pe is not None:
        return metadata.pe.sections
    if metadata.elf is not None:
        return metadata.elf.sections
    return []
