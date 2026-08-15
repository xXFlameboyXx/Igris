import React from "react";
import type { Sample } from "../../types/api";
import {
  CategoryBadge,
  ConfidenceBadge,
  ObservationLevelBadge,
  RiskLevelBadge,
  VerdictBadge,
} from "../common/Badge";
import { EmptyState, EpistemologyReminder, UnavailableState } from "../common/StateViews";

interface VerdictExplainabilityViewProps {
  sample: Sample | null;
  onRunAssessment?: () => void;
  isRunning?: boolean;
}

export function VerdictExplainabilityView({
  sample,
  onRunAssessment,
  isRunning = false,
}: VerdictExplainabilityViewProps) {
  if (!sample) {
    return <EmptyState title="No Sample Selected" message="Please select a sample to inspect explainable assessment." />;
  }

  const assessment = sample.malware_assessment;
  if (!assessment) {
    return (
      <UnavailableState
        layerName="Explainable Malware Assessment"
        description="The Phase 11 explainability synthesis engine has not evaluated the current evidence."
        onRun={onRunAssessment}
        running={isRunning}
      />
    );
  }

  const { verdict, risk_level, risk_score, confidence, explanation, limitations } = assessment;

  return (
    <div className="view-container explainability-view" role="main" aria-label="Explainable Malware Assessment">
      <div className="view-header-row">
        <div>
          <h2 className="view-title">Explainable Malware Assessment</h2>
          <p className="view-subtitle">
            Epistemologically structured, uncertainty-aware reasoning explaining the assessment verdict.
          </p>
        </div>
        <div className="view-header-badges">
          <VerdictBadge verdict={verdict} size="lg" />
          <RiskLevelBadge level={risk_level} size="lg" />
        </div>
      </div>

      <EpistemologyReminder />

      {/* 1. Core Verdict Narrative */}
      <section className="narrative-card" aria-labelledby="narrative-heading">
        <div className="narrative-header">
          <span className="narrative-icon" aria-hidden="true">💡</span>
          <h3 id="narrative-heading" className="narrative-title">
            Executive Assessment Narrative
          </h3>
        </div>
        <p className="narrative-body">{explanation.summary}</p>
        <div className="confidence-grid" style={{ marginTop: "14px", display: "flex", gap: "10px", flexWrap: "wrap" }}>
          <ConfidenceBadge label="Detection" level={confidence.detection_confidence} />
          <ConfidenceBadge label="Evidence Quality" level={confidence.evidence_quality} />
          <ConfidenceBadge label="Behavioral" level={confidence.behavioral_confidence} />
          <ConfidenceBadge label="Similarity" level={confidence.similarity_confidence} />
          <ConfidenceBadge label="Attribution" level={confidence.attribution_confidence} />
        </div>
      </section>

      {/* 2. Three Column Epistemology Grid: Observed vs Inferred vs Possible */}
      <div className="epistemology-tri-grid">
        {/* Observed */}
        <section className="ep-card ep-card-observed" aria-labelledby="observed-heading">
          <div className="ep-card-header">
            <span className="ep-icon" aria-hidden="true">👁️</span>
            <div>
              <h4 id="observed-heading" className="ep-title">Observed Facts</h4>
              <small className="ep-sub">Direct binary structure & telemetry</small>
            </div>
            <span className="count-pill">{explanation.observed_findings.length}</span>
          </div>

          <ul className="ep-list">
            {explanation.observed_findings.map((item, idx) => (
              <li key={idx} className="ep-list-item">
                <span className="bullet-dot" aria-hidden="true">•</span>
                <span>{item}</span>
              </li>
            ))}
            {explanation.observed_findings.length === 0 && (
              <li className="subdued-text">Zero raw observations recorded.</li>
            )}
          </ul>
        </section>

        {/* Inferred */}
        <section className="ep-card ep-card-inferred" aria-labelledby="inferred-heading">
          <div className="ep-card-header">
            <span className="ep-icon" aria-hidden="true">🧠</span>
            <div>
              <h4 id="inferred-heading" className="ep-title">Inferred Conclusions</h4>
              <small className="ep-sub">Rule matches & analytical models</small>
            </div>
            <span className="count-pill">{explanation.inferred_findings.length}</span>
          </div>

          <ul className="ep-list">
            {explanation.inferred_findings.map((item, idx) => (
              <li key={idx} className="ep-list-item">
                <span className="bullet-dot" aria-hidden="true">•</span>
                <span>{item}</span>
              </li>
            ))}
            {explanation.inferred_findings.length === 0 && (
              <li className="subdued-text">Zero inferred deductions recorded.</li>
            )}
          </ul>
        </section>

        {/* Possible */}
        <section className="ep-card ep-card-possible" aria-labelledby="possible-heading">
          <div className="ep-card-header">
            <span className="ep-icon" aria-hidden="true">💡</span>
            <div>
              <h4 id="possible-heading" className="ep-title">Possible Hypotheses</h4>
              <small className="ep-sub">Similarity clusters (unproven)</small>
            </div>
            <span className="count-pill">{explanation.possible_hypotheses.length}</span>
          </div>

          <ul className="ep-list">
            {explanation.possible_hypotheses.map((item, idx) => (
              <li key={idx} className="ep-list-item">
                <span className="bullet-dot" aria-hidden="true">•</span>
                <span>{item}</span>
              </li>
            ))}
            {explanation.possible_hypotheses.length === 0 && (
              <li className="subdued-text">No hypothetical clusters matched.</li>
            )}
          </ul>
        </section>
      </div>

      {/* 3. Supporting vs Contradicting Evidence Grid */}
      <div className="arguments-split-grid">
        <section className="argument-card argument-supporting" aria-labelledby="supporting-heading">
          <div className="arg-header">
            <span className="arg-icon" aria-hidden="true">🔺</span>
            <h4 id="supporting-heading">Supporting Evidence Arguments ({explanation.supporting_arguments.length})</h4>
          </div>
          <ul className="arg-list">
            {explanation.supporting_arguments.map((arg, idx) => (
              <li key={idx} className="arg-item">
                <span className="arg-bullet">✓</span>
                <span>{arg}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="argument-card argument-contradicting" aria-labelledby="contradicting-heading">
          <div className="arg-header">
            <span className="arg-icon" aria-hidden="true">🔻</span>
            <h4 id="contradicting-heading">Contradicting & Mitigating Arguments ({explanation.contradicting_arguments.length})</h4>
          </div>
          <ul className="arg-list">
            {explanation.contradicting_arguments.map((arg, idx) => (
              <li key={idx} className="arg-item">
                <span className="arg-bullet">ℹ</span>
                <span>{arg}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      {/* 4. Risk Score Calculation Breakdown */}
      <section className="risk-score-details-card" aria-labelledby="score-breakdown-heading">
        <div className="score-details-header">
          <div>
            <h3 id="score-breakdown-heading" className="card-title">
              Deterministic Evidence Risk Score Breakdown: <strong>{risk_score.score} / 100</strong>
            </h3>
            <p className="formula-desc">
              Calculated via: <code>{risk_score.formula}</code>
            </p>
          </div>
        </div>

        <div className="factors-tables-grid">
          {/* Contributing Factors */}
          <div className="factors-col">
            <h4 className="factors-heading positive">
              Contributing Factors (+{risk_score.contributing_factors.reduce((acc, f) => acc + f.points, 0)} pts)
            </h4>
            {risk_score.contributing_factors.length > 0 ? (
              <ul className="factors-list">
                {risk_score.contributing_factors.map((factor, idx) => (
                  <li key={idx} className="factor-row factor-pos">
                    <span className="factor-points">+{factor.points}</span>
                    <div className="factor-body">
                      <div className="factor-tags">
                        <CategoryBadge category={factor.category} />
                        <ObservationLevelBadge level={factor.observation_level} />
                      </div>
                      <span className="factor-desc">{factor.description}</span>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="subdued-text">Zero positive risk factors observed.</p>
            )}
          </div>

          {/* Mitigating Factors */}
          <div className="factors-col">
            <h4 className="factors-heading mitigating">
              Mitigating Factors (-{risk_score.mitigating_factors.reduce((acc, f) => acc + f.points, 0)} pts)
            </h4>
            {risk_score.mitigating_factors.length > 0 ? (
              <ul className="factors-list">
                {risk_score.mitigating_factors.map((factor, idx) => (
                  <li key={idx} className="factor-row factor-mit">
                    <span className="factor-points mitigating-points">-{factor.points}</span>
                    <div className="factor-body">
                      <div className="factor-tags">
                        <CategoryBadge category={factor.category} />
                        <ObservationLevelBadge level={factor.observation_level} />
                      </div>
                      <span className="factor-desc">{factor.description}</span>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="subdued-text">Zero mitigating factors identified.</p>
            )}
          </div>
        </div>
      </section>

      {/* 5. Uncertainty & Unknowns */}
      <section className="uncertainties-card" aria-labelledby="uncertainties-heading">
        <div className="card-header">
          <div className="header-with-icon">
            <span className="header-icon" aria-hidden="true">⏳</span>
            <h3 id="uncertainties-heading" className="card-title">
              Tracked Uncertainties & Unobserved Telemetry
            </h3>
          </div>
        </div>
        <p className="card-sub">
          The following telemetry sources or analytical categories remain unobserved. Missing evidence is explicitly treated as uncertainty rather than negative/benign findings.
        </p>

        <ul className="uncertainties-list">
          {explanation.uncertainty_and_unknowns.map((unc, idx) => (
            <li key={idx} className="uncertainty-item">
              <span className="unc-icon" aria-hidden="true">○</span>
              <span>{unc}</span>
            </li>
          ))}
          {explanation.uncertainty_and_unknowns.length === 0 && (
            <li className="subdued-text">All telemetry and analysis subsystems fully executed.</li>
          )}
        </ul>
      </section>

      {/* 6. Analytical Limitations & Attribution Guardrails */}
      <section className="limitations-card" aria-labelledby="limitations-heading">
        <div className="card-header">
          <h3 id="limitations-heading" className="card-title">
            Analytical Bounds & Attribution Guardrails
          </h3>
        </div>
        <ul className="limitations-list">
          {limitations.map((lim, idx) => (
            <li key={idx} className="limitation-item">
              <span className="lim-icon" aria-hidden="true">🔒</span>
              <span>{lim}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
