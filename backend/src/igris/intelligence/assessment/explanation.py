"""Phase 11: Human-readable narrative explanation generator.

Strictly separates epistemological categories (Observed vs Inferred vs Possible),
preserves both supporting and contradicting arguments, and exposes uncertainties.
"""

from igris.schemas.assessment import (
    AssessmentVerdict,
    ConfidenceBreakdown,
    EvidenceRole,
    EvidenceSummary,
    HumanExplanation,
    ObservationLevel,
    RiskLevel,
    RiskScoreDetails,
)


def generate_human_explanation(
    verdict: AssessmentVerdict,
    risk_level: RiskLevel,
    risk_score: RiskScoreDetails,
    confidence: ConfidenceBreakdown,
    evidence_summary: EvidenceSummary,
    disagreements: list[str],
) -> HumanExplanation:
    """Construct an analyst-facing, structured narrative explanation."""
    # 1. Summary Narrative
    if verdict == AssessmentVerdict.HIGHLY_SUSPICIOUS:
        summary = (
            f"The sample is assessed as HIGHLY SUSPICIOUS (Risk Score: {risk_score.score}/100, "
            f"Risk Level: {risk_level.value}) because multiple independent analysis layers "
            f"corroborate high-severity malicious indicators such as process injection, "
            f"persistence, or active command-and-control communication."
        )
    elif verdict == AssessmentVerdict.SUSPICIOUS:
        summary = (
            f"The sample is assessed as SUSPICIOUS (Risk Score: {risk_score.score}/100, "
            f"Risk Level: {risk_level.value}) based on observed technical indicators "
            f"suggesting hostile or unauthorized capabilities."
        )
    elif verdict == AssessmentVerdict.LIKELY_BENIGN:
        summary = (
            f"The sample is assessed as LIKELY BENIGN (Risk Score: {risk_score.score}/100, "
            f"Risk Level: {risk_level.value}) with predominantly clean technical characteristics, "
            f"though complete absence of risk cannot be guaranteed."
        )
    elif verdict == AssessmentVerdict.BENIGN:
        summary = (
            f"The sample is assessed as BENIGN (Risk Score: {risk_score.score}/100, "
            f"Risk Level: {risk_level.value}) following comprehensive multi-layer analysis "
            f"that confirmed the absence of malicious indicators or anomalous runtime behavior."
        )
    else:  # UNKNOWN
        summary = (
            "The sample is assessed as UNKNOWN due to insufficient evidence or unexecuted "
            "analysis subsystems. Unknown telemetry is not treated as benign proof."
        )

    # 2. Epistemological Breakdown
    observed: list[str] = [
        e.statement
        for e in evidence_summary.evidence_items
        if e.observation_level == ObservationLevel.OBSERVED
    ]
    inferred: list[str] = [
        e.statement
        for e in evidence_summary.evidence_items
        if e.observation_level == ObservationLevel.INFERRED
    ]
    possible: list[str] = [
        e.statement
        for e in evidence_summary.evidence_items
        if e.observation_level == ObservationLevel.POSSIBLE
    ]

    # 3. Supporting & Contradicting Arguments
    supporting: list[str] = [
        f"[{e.category.value.upper()}] {e.statement}"
        for e in evidence_summary.evidence_items
        if e.role == EvidenceRole.SUPPORTING
    ]
    contradicting: list[str] = [
        f"[{e.category.value.upper()}] {e.statement}"
        for e in evidence_summary.evidence_items
        if e.role == EvidenceRole.CONTRADICTING
    ]
    if not contradicting:
        contradicting.append("No explicit contradictory or mitigating evidence identified.")

    # 4. Uncertainty & Unknowns
    uncertainties: list[str] = [
        f"[{u.category}] {u.reason} -> {u.impact}" for u in evidence_summary.uncertainties
    ]
    if disagreements:
        for dis in disagreements:
            uncertainties.append(f"[DISAGREEMENT] {dis}")

    # 5. Guardrail Limitations
    limitations: list[str] = [
        "Assessment is evidence-backed and does NOT constitute mathematical proof of intent.",
        (
            "Attribution confidence reflects technical similarity clustering only and NEVER "
            "implies confirmed malware family, actor, or campaign membership."
        ),
        (
            "Missing or unexecuted analysis categories are explicitly marked as unknown "
            "factors rather than negative evidence."
        ),
    ]

    return HumanExplanation(
        summary=summary,
        observed_findings=observed,
        inferred_findings=inferred,
        possible_hypotheses=possible,
        supporting_arguments=supporting,
        contradicting_arguments=contradicting,
        uncertainty_and_unknowns=uncertainties,
        limitations=limitations,
    )
