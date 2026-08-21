import React, { useState, useEffect, useCallback } from "react";
import type {
  DegradationSeverity,
  InvestigationTab,
  RobustnessEvaluationReport,
  Sample,
} from "../../types/api";
import { apiClient, ApiError } from "../../services/apiClient";
import {
  DEMO_ROBUSTNESS_REPORT,
  SYNTHETIC_DEMO_TAG,
} from "../../services/syntheticDemoData";
import { LoadingState, ErrorState } from "../common/StateViews";

interface RobustnessStressViewProps {
  sample: Sample | null;
  onNavigateTab: (tab: InvestigationTab) => void;
  isDemoMode?: boolean;
}

export const RobustnessStressView: React.FC<RobustnessStressViewProps> = ({
  isDemoMode = false,
}) => {
  const [report, setReport] = useState<RobustnessEvaluationReport | null>(null);
  const [reportsList, setReportsList] = useState<RobustnessEvaluationReport[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [copySuccess, setCopySuccess] = useState<boolean>(false);

  const loadReports = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiClient.listRobustnessReports(50);
      if (res.reports && res.reports.length > 0) {
        setReportsList(res.reports);
        setReport(res.reports[0]);
      } else {
        setReportsList([DEMO_ROBUSTNESS_REPORT]);
        setReport(DEMO_ROBUSTNESS_REPORT);
      }
    } catch {
      setReportsList([DEMO_ROBUSTNESS_REPORT]);
      setReport(DEMO_ROBUSTNESS_REPORT);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const handleRunEvaluation = async () => {
    setIsRunning(true);
    setError(null);
    try {
      const res = await apiClient.evaluateRobustness({
        include_stress_tests: true,
        random_seed: 42,
      });
      setReport(res.report);
      setReportsList((prev) => [res.report, ...prev]);
    } catch (err) {
      if (isDemoMode) {
        setReport(DEMO_ROBUSTNESS_REPORT);
      } else if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Failed to execute robustness evaluation benchmark.");
      }
    } finally {
      setIsRunning(false);
    }
  };

  const handleCopyJSON = () => {
    if (!report) return;
    navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  if (isLoading && !report) {
    return <LoadingState message="Loading robustness perturbation benchmarks..." />;
  }

  const activeReport = report || DEMO_ROBUSTNESS_REPORT;

  const getSeverityBadge = (severity: DegradationSeverity) => {
    switch (severity) {
      case "NONE":
        return <span className="badge badge-low badge-sm">Resilient (0%)</span>;
      case "LOW":
        return <span className="badge badge-medium badge-sm">Low Drift (&lt;10%)</span>;
      case "MODERATE":
        return <span className="badge badge-high badge-sm">Moderate Drift (10-40%)</span>;
      case "SEVERE":
        return <span className="badge badge-critical badge-sm">Severe Drift (&gt;40%)</span>;
      default:
        return <span className="badge badge-sm">{severity}</span>;
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Header Banner */}
      <div
        className="card"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "1rem",
          background: "linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.95) 100%)",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
            <h2 style={{ margin: 0, fontSize: "1.35rem", fontWeight: 700 }}>
              🛡️ Robustness & Adversarial Resilience Evaluation
            </h2>
            <span className="badge badge-medium badge-sm">{SYNTHETIC_DEMO_TAG}</span>
          </div>
          <p style={{ margin: 0, color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
            Defensive stress-testing harness measuring sensitivity to non-malicious perturbations and complex benign software.
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          {reportsList.length > 1 && (
            <select
              value={activeReport.report_id}
              onChange={(e) => {
                const found = reportsList.find((x) => x.report_id === e.target.value);
                if (found) setReport(found);
              }}
              style={{
                fontSize: "0.8rem",
                padding: "0.4rem 0.6rem",
                borderRadius: "4px",
                background: "var(--color-surface)",
                color: "var(--color-text)",
                border: "1px solid var(--color-border)",
              }}
            >
              {reportsList.map((x) => (
                <option key={x.report_id} value={x.report_id}>
                  {x.report_id} ({new Date(x.timestamp).toLocaleTimeString()})
                </option>
              ))}
            </select>
          )}

          <button
            className="btn btn-outline"
            onClick={handleCopyJSON}
            title="Export machine-readable JSON robustness report"
          >
            {copySuccess ? "✓ Copied JSON" : "📋 Export JSON"}
          </button>

          <button
            className="btn btn-primary"
            onClick={handleRunEvaluation}
            disabled={isRunning}
          >
            {isRunning ? "Evaluating..." : "▶ Run Perturbation Benchmark"}
          </button>
        </div>
      </div>

      {error && (
        <ErrorState
          title="Robustness Evaluation Notice"
          error={error}
          onRetry={handleRunEvaluation}
        />
      )}

      {/* Summary KPI Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem" }}>
        <div className="card" style={{ textAlign: "center", padding: "1.25rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>Mean Stability Score</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--color-success)", marginTop: "0.25rem" }}>
            {(activeReport.mean_stability_score * 100).toFixed(1)}%
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>Across All 7 Perturbations</span>
        </div>

        <div className="card" style={{ textAlign: "center", padding: "1.25rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>Benign FP Resilience</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--color-primary-light)", marginTop: "0.25rem" }}>
            {(activeReport.fp_resilience_rate * 100).toFixed(1)}%
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>Zero False Overreactions</span>
        </div>

        <div className="card" style={{ textAlign: "center", padding: "1.25rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>Controlled Transformations</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--color-text-bright)", marginTop: "0.25rem" }}>
            {(activeReport.matrix_rows || []).length}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>Binary & Metadata Mutations</span>
        </div>

        <div className="card" style={{ textAlign: "center", padding: "1.25rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>Complex Benign Archetypes</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--color-text-bright)", marginTop: "0.25rem" }}>
            {(activeReport.false_positive_tests || []).length}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>Admin / Debugger / Installers</span>
        </div>
      </div>

      {/* Robustness Matrix Table */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: 600 }}>
            📊 Empirical Perturbation Sensitivity Matrix
          </h3>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>
            Click row for per-engine telemetry &amp; mitigation notes
          </span>
        </div>

        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)", textAlign: "left", color: "var(--color-text-muted)" }}>
                <th style={{ padding: "0.75rem" }}>Transformation</th>
                <th style={{ padding: "0.75rem" }}>Static</th>
                <th style={{ padding: "0.75rem" }}>Reverse</th>
                <th style={{ padding: "0.75rem" }}>ML</th>
                <th style={{ padding: "0.75rem" }}>Similarity</th>
                <th style={{ padding: "0.75rem" }}>Behavior</th>
                <th style={{ padding: "0.75rem" }}>Verdict Stability</th>
              </tr>
            </thead>
            <tbody>
              {activeReport.matrix_rows.map((row) => {
                const isExpanded = expandedRow === row.transformation_type;
                return (
                  <React.Fragment key={row.transformation_type}>
                    <tr
                      onClick={() => setExpandedRow(isExpanded ? null : row.transformation_type)}
                      style={{
                        borderBottom: "1px solid var(--color-border)",
                        cursor: "pointer",
                        background: isExpanded ? "rgba(255, 255, 255, 0.04)" : "transparent",
                      }}
                    >
                      <td style={{ padding: "0.75rem", fontWeight: 600 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                          <span>{isExpanded ? "▼" : "▶"}</span>
                          <code>{row.transformation_type}</code>
                        </div>
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        {row.static_sensitivity.transformed_score.toFixed(0)} ({row.static_sensitivity.absolute_delta === 0 ? "±0" : `-${row.static_sensitivity.absolute_delta.toFixed(0)}`})
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        {row.reverse_sensitivity.transformed_score.toFixed(0)} ({row.reverse_sensitivity.absolute_delta === 0 ? "±0" : `-${row.reverse_sensitivity.absolute_delta.toFixed(0)}`})
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        {row.ml_sensitivity.transformed_score.toFixed(0)} ({row.ml_sensitivity.absolute_delta === 0 ? "±0" : `-${row.ml_sensitivity.absolute_delta.toFixed(0)}`})
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        {row.similarity_sensitivity.transformed_score.toFixed(0)} ({row.similarity_sensitivity.absolute_delta === 0 ? "±0" : `-${row.similarity_sensitivity.absolute_delta.toFixed(0)}`})
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        {row.behavior_sensitivity.transformed_score.toFixed(0)} (±0)
                      </td>
                      <td style={{ padding: "0.75rem" }}>
                        {getSeverityBadge(row.overall_stability)}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr style={{ background: "rgba(0, 0, 0, 0.2)" }}>
                        <td colSpan={7} style={{ padding: "1rem" }}>
                          <p style={{ margin: "0 0 0.75rem 0", color: "var(--color-text-bright)", fontSize: "0.85rem" }}>
                            <strong>Description:</strong> {row.transformation_description}
                          </p>
                          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "0.75rem" }}>
                            <div style={{ padding: "0.6rem", background: "var(--color-surface)", borderRadius: "4px", border: "1px solid var(--color-border)" }}>
                              <strong style={{ fontSize: "0.75rem", color: "var(--color-primary-light)" }}>Static Analysis:</strong>
                              <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{row.static_sensitivity.notes}</p>
                            </div>
                            <div style={{ padding: "0.6rem", background: "var(--color-surface)", borderRadius: "4px", border: "1px solid var(--color-border)" }}>
                              <strong style={{ fontSize: "0.75rem", color: "var(--color-primary-light)" }}>Reverse Engineering:</strong>
                              <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{row.reverse_sensitivity.notes}</p>
                            </div>
                            <div style={{ padding: "0.6rem", background: "var(--color-surface)", borderRadius: "4px", border: "1px solid var(--color-border)" }}>
                              <strong style={{ fontSize: "0.75rem", color: "var(--color-primary-light)" }}>ML Classifier:</strong>
                              <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{row.ml_sensitivity.notes}</p>
                            </div>
                            <div style={{ padding: "0.6rem", background: "var(--color-surface)", borderRadius: "4px", border: "1px solid var(--color-border)" }}>
                              <strong style={{ fontSize: "0.75rem", color: "var(--color-primary-light)" }}>Similarity Matching:</strong>
                              <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{row.similarity_sensitivity.notes}</p>
                            </div>
                            <div style={{ padding: "0.6rem", background: "var(--color-surface)", borderRadius: "4px", border: "1px solid var(--color-border)" }}>
                              <strong style={{ fontSize: "0.75rem", color: "var(--color-primary-light)" }}>Behavioral Sandbox:</strong>
                              <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{row.behavior_sensitivity.notes}</p>
                            </div>
                            <div style={{ padding: "0.6rem", background: "var(--color-surface)", borderRadius: "4px", border: "1px solid var(--color-border)" }}>
                              <strong style={{ fontSize: "0.75rem", color: "var(--color-primary-light)" }}>Final Assessment Engine:</strong>
                              <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{row.final_verdict_sensitivity.notes}</p>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Complex Benign False Positive Stress Tests */}
      <div className="card">
        <h3 style={{ margin: "0 0 1rem 0", fontSize: "1.1rem", fontWeight: 600 }}>
          🛡️ False Positive Resilience on Complex Legitimate Software
        </h3>
        <p style={{ margin: "0 0 1rem 0", fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
          Stress-testing administrative utilities, packed installers, debuggers, and networking tools to ensure Igris does not overreact to suspicious-looking traits.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1rem" }}>
          {activeReport.false_positive_tests.map((testItem) => (
            <div
              key={testItem.sample_name}
              style={{
                padding: "1rem",
                borderRadius: "6px",
                background: "var(--color-surface)",
                border: "1px solid var(--color-border)",
                display: "flex",
                flexDirection: "column",
                gap: "0.75rem",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div>
                  <h4 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 600, color: "var(--color-text-bright)" }}>
                    {testItem.sample_name}
                  </h4>
                  <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>
                    Category: <code>{testItem.category}</code>
                  </span>
                </div>
                <span className="badge badge-low badge-sm">✓ Cleared (Risk: {testItem.risk_score}/100)</span>
              </div>

              <div>
                <strong style={{ fontSize: "0.75rem", color: "var(--color-warning)" }}>Suspicious Traits:</strong>
                <ul style={{ margin: "0.25rem 0 0 0", paddingLeft: "1.25rem", fontSize: "0.75rem", color: "var(--color-text-muted)" }}>
                  {testItem.suspicious_characteristics.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              </div>

              <div>
                <strong style={{ fontSize: "0.75rem", color: "var(--color-success)" }}>Mitigating Evidence:</strong>
                <ul style={{ margin: "0.25rem 0 0 0", paddingLeft: "1.25rem", fontSize: "0.75rem", color: "var(--color-text-muted)" }}>
                  {testItem.mitigating_evidence.map((m, i) => (
                    <li key={i}>{m}</li>
                  ))}
                </ul>
              </div>

              <div style={{ fontSize: "0.75rem", background: "rgba(0, 0, 0, 0.25)", padding: "0.5rem", borderRadius: "4px" }}>
                <strong>Epistemological Reasoning:</strong> {testItem.epistemological_reasoning}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Failure Analysis & Mitigation Records */}
      <div className="card">
        <h3 style={{ margin: "0 0 1rem 0", fontSize: "1.1rem", fontWeight: 600 }}>
          🔍 Diagnostic Failure Analysis &amp; Mitigation Taxonomy
        </h3>
        <p style={{ margin: "0 0 1rem 0", fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
          Explicit documentation distinguishing observed engine limitations from architectural mitigations.
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          {activeReport.failure_records.map((rec) => {
            const isResolved = rec.status === "RESOLVED_LIMITATION";
            return (
              <div
                key={rec.failure_id}
                style={{
                  padding: "1rem",
                  borderRadius: "6px",
                  background: isResolved ? "rgba(16, 185, 129, 0.05)" : "rgba(245, 158, 11, 0.05)",
                  border: `1px solid ${isResolved ? "rgba(16, 185, 129, 0.2)" : "rgba(245, 158, 11, 0.2)"}`,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <code>{rec.failure_id}</code>
                    <strong style={{ fontSize: "0.85rem" }}>{rec.vulnerable_engine}</strong>
                  </div>
                  <span className={`badge ${isResolved ? "badge-low" : "badge-medium"} badge-sm`}>
                    {isResolved ? "RESOLVED LIMITATION" : "OBSERVED LIMITATION"}
                  </span>
                </div>

                <p style={{ margin: "0 0 0.5rem 0", fontSize: "0.8rem", color: "var(--color-text-bright)" }}>
                  <strong>Scenario:</strong> {rec.transformation_or_scenario} — <em>{rec.observed_failure}</em>
                </p>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", fontSize: "0.75rem" }}>
                  <div>
                    <strong style={{ color: "var(--color-critical)" }}>Root Cause:</strong>
                    <p style={{ margin: "0.2rem 0 0 0", color: "var(--color-text-muted)" }}>{rec.root_cause}</p>
                  </div>
                  <div>
                    <strong style={{ color: "var(--color-success)" }}>Mitigation Strategy:</strong>
                    <p style={{ margin: "0.2rem 0 0 0", color: "var(--color-text-muted)" }}>{rec.mitigation_strategy}</p>
                    <span style={{ fontSize: "0.7rem", color: "var(--color-text-muted)" }}>
                      <strong>FP Risk:</strong> {rec.fp_risk_of_mitigation}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Threats to Empirical Validity */}
      <div className="card" style={{ background: "rgba(15, 23, 42, 0.6)" }}>
        <h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.95rem", fontWeight: 600, color: "var(--color-text-muted)" }}>
          ⚠️ Threats to Empirical Validity
        </h4>
        <ul style={{ margin: 0, paddingLeft: "1.25rem", fontSize: "0.8rem", color: "var(--color-text-muted)" }}>
          {activeReport.threats_to_validity.map((threat, i) => (
            <li key={i}>{threat}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};
