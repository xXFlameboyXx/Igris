"""Declarative rule loading and evaluation for Phase 3 detection."""

import json
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError

from igris.core.errors import AppError
from igris.schemas.detection import DetectionRule, RuleCondition, TriggeredRule
from igris.schemas.static_analysis import StaticAnalysisResult

RULES_ADAPTER = TypeAdapter(list[DetectionRule])


class RuleEngine:
    """Evaluate versioned declarative rules without executing arbitrary code."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self.rules = rules

    @classmethod
    def from_path(cls, path: Path) -> "RuleEngine":
        if not path.exists():
            return cls(rules=[])
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            rules = RULES_ADAPTER.validate_python(raw)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise AppError(
                "Detection rules failed validation",
                code="detection_rules_invalid",
                status_code=500,
                details={"path": str(path), "reason": str(exc)},
            ) from exc
        return cls(rules=rules)

    def evaluate(self, analysis: StaticAnalysisResult) -> list[TriggeredRule]:
        triggered: list[TriggeredRule] = []
        context = _context_from_analysis(analysis)
        for rule in self.rules:
            matched = [
                condition for condition in rule.conditions if _condition_matches(condition, context)
            ]
            if len(matched) != len(rule.conditions):
                continue
            triggered.append(
                TriggeredRule(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    version=rule.version,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    contribution=rule.contribution,
                    explanation=rule.evidence,
                    matched_conditions=matched,
                )
            )
        return triggered


def _context_from_analysis(analysis: StaticAnalysisResult) -> dict[str, Any]:
    vector = analysis.feature_vector
    return {
        "file_size": vector.file_size,
        "number_of_sections": vector.number_of_sections,
        "entropy_min": vector.entropy_min,
        "entropy_max": vector.entropy_max,
        "entropy_mean": vector.entropy_mean,
        "import_count": vector.import_count,
        "api_category_counts": vector.api_category_counts,
        "string_counts": vector.string_counts,
        "resource_count": vector.resource_count,
        "overlay_size": vector.overlay_size,
        "executable_section_count": vector.executable_section_count,
        "writable_executable_section_count": vector.writable_executable_section_count,
        "evidence_counts": vector.evidence_counts,
    }


def _condition_matches(condition: RuleCondition, context: dict[str, Any]) -> bool:
    actual = _resolve_field(condition.field, context)
    expected = condition.value
    if condition.operator == "exists":
        return actual is not None
    if condition.operator == "==":
        return bool(actual == expected)
    if condition.operator == "!=":
        return bool(actual != expected)
    if condition.operator in {">=", ">", "<=", "<"}:
        if not isinstance(actual, int | float) or not isinstance(expected, int | float):
            return False
        if condition.operator == ">=":
            return actual >= expected
        if condition.operator == ">":
            return actual > expected
        if condition.operator == "<=":
            return actual <= expected
        return actual < expected
    if condition.operator == "contains":
        if isinstance(actual, list | set | tuple):
            return expected in actual
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
    if condition.operator == "in":
        if isinstance(expected, list):
            return actual in expected
    return False


def _resolve_field(field: str, context: dict[str, Any]) -> Any:
    current: Any = context
    for part in field.split("."):
        if isinstance(current, dict):
            current = current.get(part, 0)
        else:
            return None
    return current
