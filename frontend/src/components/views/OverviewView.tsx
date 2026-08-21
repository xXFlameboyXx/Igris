import React from "react";
import type { InvestigationTab, Sample } from "../../types/api";
import {
  CategoryBadge,
  ConfidenceBadge,
  EvidenceRoleBadge,
  ObservationLevelBadge,
  RiskLevelBadge,
  VerdictBadge,
} from "../common/Badge";
import { EmptyState } from "../common/StateViews";

interface OverviewViewProps {
  sample: Sample | null;
  onNavigateTab: (tab: InvestigationTab) => void;
  onRunAnalysis: (layer: string) => Promise<void>;
  runningLayers: Record<string, boolean>;
  onOpenUpload?: () => void;
}

export function OverviewView({
  sample,
  onNavigateTab,
  onRunAnalysis,
  runningLayers,
  onOpenUpload,
}: OverviewViewProps) {
  if (!sample) {
    return (
      <EmptyState
        icon="🛡️"
        title="No Specimens Available"
        message="No binary specimens have been ingested for analysis yet. Upload an executable (PE or ELF) to begin automated static, reverse, behavioral, and threat-intelligence inspection."
        action={
          onOpenUpload ? (
            <button
              type="button"
              className="btn btn-primary"
              onClick={onOpenUpload}
            >
              ⬆ Upload Specimen
            </button>
          ) : undefined
        }
      />
    );
  }

  const assessment = sample.malware_assessment;
  const verdict = assessment?.verdict || (sample.status === "completed" ? "UNKNOWN" : "UNKNOWN");
  const riskScore = assessment?.risk_score?.score ?? 0;
  const riskLevel = assessment?.risk_level || "UNKNOWN";
  const confidence = assessment?.confidence;

  const supportingItems = (assessment?.evidence_summary?.evidence_items || []).filter((e) => e.role === "SUPPORTING");
  const contradictingItems = (assessment?.evidence_summary?.evidence_items || []).filter((e) => e.role === "CONTRADICTING");
  const disagreements = assessment?.evidence_summary?.disagreements || [];

  return (
    <div className="view-container overview-view" role="main" aria-label="Investigation Overview">
      {/* Top Banner: Verdict & Core Assessment Card */}
      <section className="overview-hero-card" aria-labelledby="assessment-summary-heading">
        <div className="hero-verdict-section">
          <div className="verdict-header-row">
            <span className="section-eyebrow">MALWARE ASSESSMENT VERDICT</span>
            <div className="badges-row">
              <VerdictBadge verdict={verdict} size="lg" />
              <RiskLevelBadge level={riskLevel} size="lg" />
            </div>
          </div>

          <div className="score-meter-row">
            <div className="score-number-box">
              <span className="score-val">{riskScore}</span>
              <span className="score-max">/100</span>
              <span className="score-label">EVIDENCE RISK SCORE</span>
            </div>
            <div className="score-bar-wrapper">
              <div className="score-bar-track">
                <div
                  className={`score-bar-fill ${riskScore >= 75 ? "fill-critical" : riskScore >= 45 ? "fill-high" : riskScore >= 20 ? "fill-medium" : "fill-low"}`}
                  style={{ width: `${Math.min(100, Math.max(2, riskScore))}%` }}
                />
              </div>
              <p className="score-formula-caption">
                Formula: <code>{assessment?.risk_score?.formula || "min(100, max(0, sum(positive) - 0.5 * sum(mitigating)))"}</code>
                {" "}(Deterministic evidence weight — <em>not a probability</em>)
              </p>
            </div>
          </div>

          <p id="assessment-summary-heading" className="assessment-narrative-summary">
            {assessment?.explanation?.summary || "Assessment unperformed or sample pending analysis. Run analysis layers below."}
          </p>
        </div>

        {/* Confidence Breakdown Panel */}
        <div className="hero-confidence-section">
          <h3 className="subheading">Multi-Dimensional Confidence</h3>
          <div className="confidence-grid">
            <div className="conf-item">
              <span className="conf-label">Detection Confidence</span>
              <ConfidenceBadge label="Detection" level={confidence?.detection_confidence || "UNAVAILABLE"} />
            </div>
            <div className="conf-item">
              <span className="conf-label">Evidence Quality</span>
              <ConfidenceBadge label="Evidence" level={confidence?.evidence_quality || "UNAVAILABLE"} />
            </div>
            <div className="conf-item">
              <span className="conf-label">Behavioral Telemetry</span>
              <ConfidenceBadge label="Behavior" level={confidence?.behavioral_confidence || "UNAVAILABLE"} />
            </div>
            <div className="conf-item">
              <span className="conf-label">Similarity Index</span>
              <ConfidenceBadge label="Similarity" level={confidence?.similarity_confidence || "UNAVAILABLE"} />
            </div>
            <div className="conf-item">
              <span className="conf-label">Attribution Scope</span>
              <span className="badge badge-neutral badge-sm" title="Attribution is strictly restricted to technical clusters">
                CLUSTER ONLY (Safe)
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* Disagreements / Contradictions Alert */}
      {disagreements.length > 0 && (
        <section className="disagreement-alert-card" role="alert" aria-label="Evidence Disagreement Alert">
          <div className="alert-header">
            <span className="alert-icon" aria-hidden="true">⚡</span>
            <strong>Cross-Layer Evidence Disagreement Detected</strong>
          </div>
          <ul className="disagreement-list">
            {disagreements.map((dis, idx) => (
              <li key={idx} className="disagreement-item">
                {dis}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Two Column Grid: Evidence Breakdown & Subsystem Status */}
      <div className="overview-two-col-grid">
        {/* Left Column: Key Supporting & Contradicting Findings */}
        <section className="dashboard-card" aria-labelledby="key-findings-heading">
          <div className="card-header">
            <h3 id="key-findings-heading" className="card-title">
              Key Traceable Findings ({supportingItems.length} Supporting, {contradictingItems.length} Contradicting)
            </h3>
            <button
              type="button"
              className="btn btn-sm btn-outline"
              onClick={() => onNavigateTab("evidence")}
            >
              Open Evidence Explorer ›
            </button>
          </div>

          <div className="findings-stream">
            {supportingItems.slice(0, 5).map((item) => (
              <div key={item.evidence_id} className="finding-row finding-supporting">
                <div className="finding-meta">
                  <CategoryBadge category={item.category} />
                  <ObservationLevelBadge level={item.observation_level} />
                  <EvidenceRoleBadge role={item.role} />
                </div>
                <p className="finding-text">{item.statement}</p>
                <span className="finding-source">Provenance: <code>{item.provenance}</code></span>
              </div>
            ))}

            {contradictingItems.slice(0, 3).map((item) => (
              <div key={item.evidence_id} className="finding-row finding-contradicting">
                <div className="finding-meta">
                  <CategoryBadge category={item.category} />
                  <ObservationLevelBadge level={item.observation_level} />
                  <EvidenceRoleBadge role={item.role} />
                </div>
                <p className="finding-text">{item.statement}</p>
                <span className="finding-source">Provenance: <code>{item.provenance}</code></span>
              </div>
            ))}

            {supportingItems.length === 0 && contradictingItems.length === 0 && (
              <p className="subdued-text">No evidence items extracted yet. Run analysis below.</p>
            )}
          </div>
        </section>

        {/* Right Column: Subsystems & Capabilities Preview */}
        <div className="right-col-stack">
          {/* Capabilities & Techniques Card */}
          <section className="dashboard-card" aria-labelledby="capabilities-preview-heading">
            <div className="card-header">
              <h3 id="capabilities-preview-heading" className="card-title">
                Inferred Capabilities & Techniques
              </h3>
              <button
                type="button"
                className="btn btn-sm btn-outline"
                onClick={() => onNavigateTab("attack")}
              >
                View ATT&CK Matrix ›
              </button>
            </div>

            {sample.threat_assessment?.capabilities && sample.threat_assessment.capabilities.length > 0 ? (
              <ul className="capabilities-chip-list">
                {sample.threat_assessment.capabilities.map((cap) => (
                  <li key={cap.capability_id} className="capability-chip">
                    <span className="chip-name">{cap.name}</span>
                    <span className="chip-conf">{Math.round(cap.confidence * 100)}%</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="subdued-text">No behavioral capabilities mapped yet.</p>
            )}

            {(sample.threat_assessment?.attack_techniques || []).length > 0 && (
              <div className="technique-tags-row">
                {(sample.threat_assessment?.attack_techniques || []).slice(0, 4).map((tech) => (
                  <span key={tech.technique_id} className="technique-tag" title={tech.technique_name}>
                    <strong>{tech.technique_id}</strong>: {tech.technique_name}
                  </span>
                ))}
              </div>
            )}
          </section>

          {/* Quick Analysis Actions */}
          <section className="dashboard-card" aria-labelledby="actions-heading">
            <h3 id="actions-heading" className="card-title">Analysis Subsystem Controls</h3>
            <p className="subdued-text small">
              Execute individual analysis layers to enrich evidence, update the risk score, and generate explanations.
            </p>

            <div className="action-buttons-grid">
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onRunAnalysis("static")}
                disabled={runningLayers.static}
              >
                {sample.static_analysis ? "✓ Re-Run Static" : "▶ Run Static"}
              </button>

              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onRunAnalysis("reverse")}
                disabled={runningLayers.reverse}
              >
                {sample.reverse_analysis ? "✓ Re-Run Reverse" : "▶ Run Reverse"}
              </button>

              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onRunAnalysis("behavior")}
                disabled={runningLayers.behavior}
              >
                {sample.behavior_analysis ? "✓ Re-Run Sandbox" : "▶ Run Sandbox"}
              </button>

              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onRunAnalysis("detection")}
                disabled={runningLayers.detection}
              >
                {sample.detection ? "✓ Re-Run Rules" : "▶ Run Rules"}
              </button>

              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onRunAnalysis("ml")}
                disabled={runningLayers.ml}
              >
                {sample.ml_prediction ? "✓ Re-Run ML" : "▶ Run ML"}
              </button>

              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onRunAnalysis("similarity")}
                disabled={runningLayers.similarity}
              >
                {sample.similarity_analysis ? "✓ Re-Run Similarity" : "▶ Run Similarity"}
              </button>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
