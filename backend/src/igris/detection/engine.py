"""Phase 3 evidence-based detection engine."""

from igris.core.config import Settings
from igris.detection.heuristics import HeuristicEngine
from igris.detection.rules import RuleEngine
from igris.detection.scoring import (
    confidence_from_inputs,
    score_detection,
    severity_from_score,
    status_from_score,
)
from igris.schemas.detection import DetectionResult, DetectionRunStatus
from igris.schemas.static_analysis import StaticAnalysisResult


class DetectionEngine:
    """Combine rules, heuristics, and static evidence into an explainable assessment."""

    def __init__(
        self,
        *,
        settings: Settings,
        rule_engine: RuleEngine,
        heuristic_engine: HeuristicEngine | None = None,
    ) -> None:
        self.settings = settings
        self.rule_engine = rule_engine
        self.heuristic_engine = heuristic_engine or HeuristicEngine()

    def assess(self, analysis: StaticAnalysisResult) -> DetectionResult:
        triggered_rules = self.rule_engine.evaluate(analysis)
        heuristics = self.heuristic_engine.evaluate(analysis)
        score, breakdown = score_detection(
            rules=triggered_rules,
            heuristics=heuristics,
            evidence=analysis.evidence,
        )
        status = status_from_score(score, len(analysis.evidence))
        severity = severity_from_score(score)
        confidence = confidence_from_inputs(triggered_rules, heuristics, analysis.evidence)
        return DetectionResult(
            sample_id=analysis.sample_id,
            status=status,
            run_status=DetectionRunStatus.COMPLETED,
            heuristic_score=score,
            triggered_rules=triggered_rules,
            heuristics=heuristics,
            evidence=analysis.evidence,
            severity=severity,
            confidence=confidence,
            explanation=_explain(score, status, triggered_rules, heuristics),
            score_breakdown=breakdown,
            engine_version=self.settings.detection_engine_version,
            limitations=[
                "This is a deterministic heuristic risk score, not a statistical probability.",
                "Benign installers, debuggers, administration tools, security tools, and "
                "development tools can trigger similar evidence.",
                "No sample execution, sandboxing, network lookups, or machine learning are used.",
            ],
        )


def _explain(score: float, status: object, rules: object, heuristics: object) -> str:
    rule_count = len(rules) if isinstance(rules, list) else 0
    heuristic_count = len(heuristics) if isinstance(heuristics, list) else 0
    return (
        f"Detection status {status} is based on a heuristic risk score of {score}/10, "
        f"{rule_count} triggered rule(s), and {heuristic_count} heuristic finding(s). "
        "The assessment combines evidence rather than treating any single API, string, "
        "or section property as proof of maliciousness."
    )
