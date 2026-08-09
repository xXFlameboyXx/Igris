"""Transparent heuristic risk scoring."""

from statistics import mean

from igris.schemas.detection import (
    DetectionStatus,
    HeuristicFinding,
    ScoreBreakdown,
    ScoreContribution,
    TriggeredRule,
)
from igris.schemas.static_analysis import EvidenceSeverity, StaticEvidence

SEVERITY_POINTS = {
    EvidenceSeverity.INFO: 0.0,
    EvidenceSeverity.LOW: 0.05,
    EvidenceSeverity.MEDIUM: 0.12,
    EvidenceSeverity.HIGH: 0.2,
}


def score_detection(
    *,
    rules: list[TriggeredRule],
    heuristics: list[HeuristicFinding],
    evidence: list[StaticEvidence],
) -> tuple[float, ScoreBreakdown]:
    rule_contributions = [
        ScoreContribution(
            source="rule",
            label=rule.name,
            contribution=round(rule.contribution * rule.confidence, 3),
            confidence=rule.confidence,
            rationale=rule.explanation,
        )
        for rule in rules
    ]
    heuristic_contributions = [
        ScoreContribution(
            source="heuristic",
            label=heuristic.name,
            contribution=round(heuristic.contribution * heuristic.confidence, 3),
            confidence=heuristic.confidence,
            rationale=heuristic.explanation,
        )
        for heuristic in heuristics
    ]
    evidence_contributions = [
        ScoreContribution(
            source="evidence",
            label=str(item.type),
            contribution=round(SEVERITY_POINTS[item.severity] * item.confidence, 3),
            confidence=item.confidence,
            rationale=item.description,
        )
        for item in evidence
        if item.severity != EvidenceSeverity.INFO
    ]
    total = sum(item.contribution for item in rule_contributions)
    total += sum(item.contribution for item in heuristic_contributions)
    total += min(1.5, sum(item.contribution for item in evidence_contributions))
    total = round(min(total, 10.0), 3)
    return total, ScoreBreakdown(
        rule_contributions=rule_contributions,
        heuristic_contributions=heuristic_contributions,
        evidence_contributions=evidence_contributions,
        total=total,
    )


def status_from_score(score: float, evidence_count: int) -> DetectionStatus:
    if evidence_count == 0:
        return DetectionStatus.BENIGN
    if score >= 5.0:
        return DetectionStatus.HIGHLY_SUSPICIOUS
    if score >= 1.5:
        return DetectionStatus.SUSPICIOUS
    return DetectionStatus.UNKNOWN


def severity_from_score(score: float) -> EvidenceSeverity:
    if score >= 5.0:
        return EvidenceSeverity.HIGH
    if score >= 1.5:
        return EvidenceSeverity.MEDIUM
    if score > 0:
        return EvidenceSeverity.LOW
    return EvidenceSeverity.INFO


def confidence_from_inputs(
    rules: list[TriggeredRule], heuristics: list[HeuristicFinding], evidence: list[StaticEvidence]
) -> float:
    values = [item.confidence for item in rules]
    values.extend(item.confidence for item in heuristics)
    values.extend(item.confidence for item in evidence)
    if not values:
        return 0.35
    return round(min(0.95, mean(values)), 3)
