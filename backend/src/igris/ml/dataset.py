"""Dataset ingestion, labeling, and leakage-aware splitting for Phase 6."""

import hashlib
import json
from collections import defaultdict
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from igris.core.errors import AppError
from igris.schemas.ml import DatasetManifest, DatasetSplit, LabeledFeatureRecord, SplitSummary

DATASET_ADAPTER = TypeAdapter(DatasetManifest)


def load_dataset_manifest(path: Path) -> DatasetManifest:
    """Load and validate a versioned dataset manifest."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return DATASET_ADAPTER.validate_python(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise AppError(
            "ML dataset manifest failed validation",
            code="ml_dataset_invalid",
            status_code=500,
            details={"path": str(path), "reason": str(exc)},
        ) from exc


def prepare_dataset_splits(
    records: list[LabeledFeatureRecord],
    *,
    family_aware: bool = True,
    seed: int = 13,
) -> tuple[dict[DatasetSplit, list[LabeledFeatureRecord]], SplitSummary]:
    """Deduplicate by SHA-256 and assign deterministic train/validation/test splits."""

    unique_records, duplicate_count = _deduplicate(records)
    if all(record.split is not None for record in unique_records):
        splits = {
            split: [record for record in unique_records if record.split == split]
            for split in DatasetSplit
        }
    else:
        splits = _assign_splits(unique_records, family_aware=family_aware, seed=seed)

    warnings = _leakage_warnings(splits)
    summary = SplitSummary(
        train=len(splits[DatasetSplit.TRAIN]),
        validation=len(splits[DatasetSplit.VALIDATION]),
        test=len(splits[DatasetSplit.TEST]),
        family_aware=family_aware,
        duplicate_sha256_removed=duplicate_count,
        leakage_warnings=warnings,
    )
    return splits, summary


def _deduplicate(
    records: list[LabeledFeatureRecord],
) -> tuple[list[LabeledFeatureRecord], int]:
    seen: set[str] = set()
    unique: list[LabeledFeatureRecord] = []
    duplicate_count = 0
    for record in records:
        if record.sha256 in seen:
            duplicate_count += 1
            continue
        seen.add(record.sha256)
        unique.append(record)
    return unique, duplicate_count


def _assign_splits(
    records: list[LabeledFeatureRecord],
    *,
    family_aware: bool,
    seed: int,
) -> dict[DatasetSplit, list[LabeledFeatureRecord]]:
    grouped: defaultdict[str, list[LabeledFeatureRecord]] = defaultdict(list)
    for record in records:
        group_key = record.family if family_aware and record.family else record.sha256
        grouped[group_key].append(record)

    splits: dict[DatasetSplit, list[LabeledFeatureRecord]] = {
        DatasetSplit.TRAIN: [],
        DatasetSplit.VALIDATION: [],
        DatasetSplit.TEST: [],
    }
    for group_key, group_records in grouped.items():
        bucket = _bucket(group_key, seed)
        if bucket < 70:
            split = DatasetSplit.TRAIN
        elif bucket < 85:
            split = DatasetSplit.VALIDATION
        else:
            split = DatasetSplit.TEST
        splits[split].extend(group_records)
    return splits


def _leakage_warnings(splits: dict[DatasetSplit, list[LabeledFeatureRecord]]) -> list[str]:
    warnings: list[str] = []
    sha_to_splits: defaultdict[str, set[str]] = defaultdict(set)
    family_to_splits: defaultdict[str, set[str]] = defaultdict(set)
    for split, records in splits.items():
        for record in records:
            sha_to_splits[record.sha256].add(split.value)
            if record.family:
                family_to_splits[record.family].add(split.value)
    for sha256, split_names in sha_to_splits.items():
        if len(split_names) > 1:
            warnings.append(f"Duplicate sample {sha256} appears in {sorted(split_names)}.")
    for family, split_names in family_to_splits.items():
        if len(split_names) > 1:
            warnings.append(f"Family {family} appears in {sorted(split_names)}.")
    return warnings


def _bucket(value: str, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}:{value}".encode()).hexdigest()
    return int(digest[:8], 16) % 100
