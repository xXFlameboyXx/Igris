"""Behavior-analysis contributions for explainable detection."""

from collections import Counter

from igris.schemas.behavior_analysis import (
    BehaviorAnalysisResult,
    BehaviorEvidence,
    BehaviorEvidenceType,
)
from igris.schemas.detection import HeuristicFinding
from igris.schemas.static_analysis import EvidenceSeverity

_CATEGORY_WEIGHTS = {
    "behavior_process_activity": 0.55,
    "behavior_file_activity": 0.65,
    "behavior_persistence_activity": 0.9,
    "behavior_network_activity": 0.75,
    "behavior_evasion_activity": 1.1,
}

_TYPE_TO_CATEGORY = {
    BehaviorEvidenceType.PROCESS_CREATION: "behavior_process_activity",
    BehaviorEvidenceType.FILE_WRITE: "behavior_file_activity",
    BehaviorEvidenceType.FILE_DELETE: "behavior_file_activity",
    BehaviorEvidenceType.DROPPED_EXECUTABLE: "behavior_file_activity",
    BehaviorEvidenceType.REGISTRY_MODIFICATION: "behavior_persistence_activity",
    BehaviorEvidenceType.SERVICE_CREATION: "behavior_persistence_activity",
    BehaviorEvidenceType.MUTEX_CREATION: "behavior_persistence_activity",
    BehaviorEvidenceType.NETWORK_CONNECTION: "behavior_network_activity",
    BehaviorEvidenceType.DNS_QUERY: "behavior_network_activity",
    BehaviorEvidenceType.EVASION_ATTEMPT: "behavior_evasion_activity",
}

_CATEGORY_NAMES = {
    "behavior_process_activity": "Behavior: process activity",
    "behavior_file_activity": "Behavior: file-system activity",
    "behavior_persistence_activity": "Behavior: persistence-like activity",
    "behavior_network_activity": "Behavior: network activity",
    "behavior_evasion_activity": "Behavior: evasion-like activity",
}


def behavior_heuristics(
    behavior_analysis: BehaviorAnalysisResult | None,
) -> list[HeuristicFinding]:
    """Convert cached behavior evidence into conservative detection findings.

    This function never runs behavior analysis. It only consumes a result that
    already exists on the sample record, preserving the Phase 7 boundary that
    behavior analysis must be requested explicitly.
    """

    if behavior_analysis is None:
        return []

    grouped: dict[str, list[BehaviorEvidence]] = {}
    for item in behavior_analysis.evidence:
        grouped.setdefault(_TYPE_TO_CATEGORY[item.type], []).append(item)

    synthetic = behavior_analysis.sandbox_metadata.analysis_mode == "synthetic"
    findings: list[HeuristicFinding] = []
    for category, items in sorted(grouped.items()):
        if not items:
            continue
        type_counts = Counter(str(item.type) for item in items)
        confidence = _combined_confidence(items, synthetic=synthetic)
        contribution = _CATEGORY_WEIGHTS[category]
        if len(type_counts) > 1:
            contribution += 0.25
        finding = HeuristicFinding(
            heuristic_id=f"HEUR-BEH-{category.upper()}",
            name=_CATEGORY_NAMES[category],
            category="behavior_analysis",
            severity=_max_severity(items),
            confidence=confidence,
            contribution=round(contribution, 3),
            explanation=_explanation(category, items, synthetic=synthetic),
            supporting_evidence_ids=sorted(item.evidence_id for item in items),
        )
        findings.append(finding)
    return findings


def _combined_confidence(items: list[BehaviorEvidence], *, synthetic: bool) -> float:
    base = max(item.confidence for item in items)
    if len({item.type for item in items}) > 1:
        base += 0.05
    if synthetic:
        base = min(base, 0.35)
    return round(min(base, 0.9), 3)


def _max_severity(items: list[BehaviorEvidence]) -> EvidenceSeverity:
    rank = {
        EvidenceSeverity.INFO: 0,
        EvidenceSeverity.LOW: 1,
        EvidenceSeverity.MEDIUM: 2,
        EvidenceSeverity.HIGH: 3,
    }
    return max((item.severity for item in items), key=lambda value: rank[value])


def _explanation(category: str, items: list[BehaviorEvidence], *, synthetic: bool) -> str:
    source_note = (
        "The behavior result is synthetic, so it is used only as low-confidence "
        "pipeline exercise evidence."
        if synthetic
        else "The behavior result is sandbox telemetry and should still be read as "
        "evidence, not proof of malicious intent."
    )
    type_list = ", ".join(sorted({str(item.type) for item in items}))
    return (
        f"{_CATEGORY_NAMES[category]} triggered from behavior evidence types: "
        f"{type_list}. {source_note}"
    )
