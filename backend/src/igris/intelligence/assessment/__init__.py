"""Phase 11: Explainable Malware Assessment package."""

from igris.intelligence.assessment.engine import AssessmentEngine
from igris.intelligence.assessment.explanation import generate_human_explanation
from igris.intelligence.assessment.service import AssessmentService

__all__ = [
    "AssessmentEngine",
    "AssessmentService",
    "generate_human_explanation",
]
