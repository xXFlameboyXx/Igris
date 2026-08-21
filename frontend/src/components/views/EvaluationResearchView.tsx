import React, { useState, useEffect, useCallback } from "react";
import type {
  AblationConfigName,
  AblationResult,
  ExperimentRecord,
  InvestigationTab,
  Sample,
  SplitStrategy,
} from "../../types/api";
import { apiClient, ApiError } from "../../services/apiClient";
import {
  DEMO_EVALUATION_EXPERIMENT,
  SYNTHETIC_DEMO_TAG,
} from "../../services/syntheticDemoData";
import { LoadingState, ErrorState } from "../common/StateViews";

interface EvaluationResearchViewProps {
  sample: Sample | null;
  onNavigateTab: (tab: InvestigationTab) => void;
  isDemoMode?: boolean;
}

const RQ_PRESETS = [
  {
    id: "RQ1",
    title: "RQ1: Static Analysis Baseline",
    question: "How effective is static analysis alone without dynamic telemetry?",
    ablation: ["STATIC_ONLY", "STATIC_HEURISTICS"] as AblationConfigName[],
  },
  {
    id: "RQ2",
    title: "RQ2: Reverse Engineering Impact",
    question: "Does linear disassembly and control-flow recovery improve detection fidelity?",
    ablation: ["STATIC_HEURISTICS", "STATIC_REVERSE"] as AblationConfigName[],
  },
  {
    id: "RQ3",
    title: "RQ3: Behavioral Sandbox Impact",
    question: "Does dynamic behavioral telemetry catch evasive and packed payloads?",
    ablation: ["STATIC_REVERSE", "STATIC_REVERSE_BEHAVIOR"] as AblationConfigName[],
  },
  {
    id: "RQ4",
    title: "RQ4: ML & Evidence Correlation",
    question: "Does cross-engine evidence correlation and ML scoring reduce false positives?",
    ablation: ["STATIC_REVERSE", "STATIC_REVERSE_ML", "FULL_IGRIS"] as AblationConfigName[],
  },
  {
    id: "RQ5",
    title: "RQ5: Family-Aware Generalization",
    question: "How well does Igris generalize across unseen threat families without data leakage?",
    ablation: ["FULL_IGRIS"] as AblationConfigName[],
  },
  {
    id: "RQ6",
    title: "RQ6: Computational Efficiency",
    question: "What is the per-stage latency overhead across the complete pipeline?",
    ablation: [
      "STATIC_ONLY",
      "STATIC_HEURISTICS",
      "STATIC_REVERSE",
      "STATIC_REVERSE_ML",
      "STATIC_REVERSE_BEHAVIOR",
      "FULL_IGRIS",
    ] as AblationConfigName[],
  },
];

export const EvaluationResearchView: React.FC<EvaluationResearchViewProps> = ({
  isDemoMode = false,
}) => {
  const [activeExperiment, setActiveExperiment] = useState<ExperimentRecord | null>(null);
  const [experimentsList, setExperimentsList] = useState<ExperimentRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedRQ, setSelectedRQ] = useState<string>("RQ6");
  const [splitStrategy, setSplitStrategy] = useState<SplitStrategy>("FAMILY_AWARE");
  const [copySuccess, setCopySuccess] = useState<boolean>(false);

  // Load registered experiments or fallback to demo record
  const loadExperiments = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiClient.listExperiments(50);
      if (res.experiments && res.experiments.length > 0) {
        setExperimentsList(res.experiments);
        setActiveExperiment(res.experiments[0]);
      } else {
        setExperimentsList([DEMO_EVALUATION_EXPERIMENT]);
        setActiveExperiment(DEMO_EVALUATION_EXPERIMENT);
      }
    } catch {
      // In demo mode or if API is unreachable, load preloaded benchmark experiment
      setExperimentsList([DEMO_EVALUATION_EXPERIMENT]);
      setActiveExperiment(DEMO_EVALUATION_EXPERIMENT);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadExperiments();
  }, [loadExperiments]);

  const handleRunExperiment = async () => {
    setIsRunning(true);
    setError(null);
    const rqObj = RQ_PRESETS.find((r) => r.id === selectedRQ) || RQ_PRESETS[5];

    try {
      const res = await apiClient.createExperiment({
        research_question: `${rqObj.id}: ${rqObj.question}`,
        dataset_id: "igris-synthetic-benchmark-v1",
        dataset_version: "v1.0",
        split_strategy: splitStrategy,
        ablation_configurations: rqObj.ablation,
        random_seed: 42,
      });
      setActiveExperiment(res.experiment);
      setExperimentsList((prev) => [res.experiment, ...prev]);
    } catch (err) {
      if (isDemoMode) {
        setActiveExperiment(DEMO_EVALUATION_EXPERIMENT);
      } else if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Failed to execute research benchmark experiment.");
      }
    } finally {
      setIsRunning(false);
    }
  };

  const handleCopyReportJSON = () => {
    if (!activeExperiment) return;
    navigator.clipboard.writeText(JSON.stringify(activeExperiment, null, 2));
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  if (isLoading && !activeExperiment) {
    return <LoadingState message="Loading research evaluation benchmarks..." />;
  }

  const exp = activeExperiment || DEMO_EVALUATION_EXPERIMENT;
  const metrics = exp.overall_metrics;
  const cm = metrics?.confusion_matrix;

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
              🧪 Experimental Evaluation & Research Platform
            </h2>
            <span className="badge badge-medium badge-sm">{SYNTHETIC_DEMO_TAG}</span>
          </div>
          <p style={{ margin: 0, color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
            Empirical benchmark harness for multi-stage ablation studies, error taxonomies, and computational profiling.
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          {experimentsList.length > 1 && (
            <select
              value={activeExperiment?.experiment_id || ""}
              onChange={(e) => {
                const found = experimentsList.find((x) => x.experiment_id === e.target.value);
                if (found) setActiveExperiment(found);
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
              {experimentsList.map((x) => (
                <option key={x.experiment_id} value={x.experiment_id}>
                  {x.experiment_id} ({x.status})
                </option>
              ))}
            </select>
          )}

          <button
            className="btn btn-outline"
            onClick={handleCopyReportJSON}
            title="Copy machine-readable JSON experiment artifact to clipboard"
          >
            {copySuccess ? "✓ Copied JSON" : "📋 Export JSON"}
          </button>

          <button
            className="btn btn-primary"
            onClick={handleRunExperiment}
            disabled={isRunning}
          >
            {isRunning ? "Executing..." : "▶ Run Experiment"}
          </button>
        </div>
      </div>

      {error && <ErrorState error={error} onRetry={loadExperiments} />}

      {/* Research Question Selector & Experiment Setup */}
      <div className="card" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        <h3 style={{ margin: 0, fontSize: "1.05rem", fontWeight: 600 }}>
          🎯 Research Question & Protocol Selection
        </h3>

        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          {RQ_PRESETS.map((rq) => (
            <button
              key={rq.id}
              className={`btn btn-outline ${selectedRQ === rq.id ? "active" : ""}`}
              onClick={() => setSelectedRQ(rq.id)}
              style={{
                fontSize: "0.85rem",
                padding: "0.45rem 0.85rem",
                borderColor: selectedRQ === rq.id ? "var(--color-primary)" : "var(--color-border)",
                backgroundColor: selectedRQ === rq.id ? "rgba(59, 130, 246, 0.15)" : "transparent",
              }}
            >
              {rq.title}
            </button>
          ))}
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
            gap: "1rem",
            padding: "1rem",
            background: "rgba(15, 23, 42, 0.5)",
            borderRadius: "6px",
            fontSize: "0.85rem",
          }}
        >
          <div>
            <span style={{ color: "var(--color-text-muted)" }}>Target Question:</span>
            <p style={{ margin: "0.25rem 0 0 0", fontWeight: 500 }}>
              {RQ_PRESETS.find((r) => r.id === selectedRQ)?.question}
            </p>
          </div>
          <div>
            <span style={{ color: "var(--color-text-muted)" }}>Split Strategy:</span>
            <select
              value={splitStrategy}
              onChange={(e) => setSplitStrategy(e.target.value as SplitStrategy)}
              style={{
                display: "block",
                marginTop: "0.25rem",
                width: "100%",
                padding: "0.4rem",
                borderRadius: "4px",
                background: "var(--color-surface)",
                color: "var(--color-text)",
                border: "1px solid var(--color-border)",
              }}
            >
              <option value="FAMILY_AWARE">FAMILY_AWARE (Zero Leakage)</option>
              <option value="STRATIFIED">STRATIFIED (Balanced Classes)</option>
              <option value="RANDOM">RANDOM (Uniform Split)</option>
            </select>
          </div>
          <div>
            <span style={{ color: "var(--color-text-muted)" }}>Dataset Manifest:</span>
            <p style={{ margin: "0.25rem 0 0 0", fontWeight: 500 }}>
              <code>{exp.config.dataset_id} ({exp.config.dataset_version})</code>
            </p>
          </div>
        </div>
      </div>

      {/* Primary KPI Overview Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "1rem" }}>
        <div className="card" style={{ textAlign: "center", padding: "1.25rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>F1-Score</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--color-primary-light)", marginTop: "0.25rem" }}>
            {metrics?.f1_score != null ? `${(metrics.f1_score * 100).toFixed(1)}%` : "N/A"}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>Harmonic Mean (P & R)</span>
        </div>

        <div className="card" style={{ textAlign: "center", padding: "1.25rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>Precision</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--color-success)", marginTop: "0.25rem" }}>
            {metrics?.precision != null ? `${(metrics.precision * 100).toFixed(1)}%` : "N/A"}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>TP / (TP + FP)</span>
        </div>

        <div className="card" style={{ textAlign: "center", padding: "1.25rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>Recall (Sensitivity)</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--color-warning)", marginTop: "0.25rem" }}>
            {metrics?.recall != null ? `${(metrics.recall * 100).toFixed(1)}%` : "N/A"}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>TP / (TP + FN)</span>
        </div>

        <div className="card" style={{ textAlign: "center", padding: "1.25rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>False Positive Rate</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--color-critical)", marginTop: "0.25rem" }}>
            {metrics?.fpr != null ? `${(metrics.fpr * 100).toFixed(1)}%` : "N/A"}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>FP / (FP + TN)</span>
        </div>

        <div className="card" style={{ textAlign: "center", padding: "1.25rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>Mean Latency</span>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "var(--color-text-bright)", marginTop: "0.25rem" }}>
            {exp.overall_performance ? `${exp.overall_performance.mean_sample_latency_ms.toFixed(1)}ms` : "N/A"}
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>Per-Sample End-to-End</span>
        </div>
      </div>

      {/* Controlled Ablation Comparison Matrix */}
      <div className="card" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: 600 }}>
              🔬 Controlled Ablation Study Comparison
            </h3>
            <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
              Isolates the empirical contribution of each analysis engine under identical split conditions.
            </p>
          </div>
        </div>

        <div style={{ overflowX: "auto" }}>
          <table className="table" style={{ width: "100%", fontSize: "0.85rem" }}>
            <thead>
              <tr>
                <th>Configuration</th>
                <th>Enabled Stages</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1-Score</th>
                <th>FPR</th>
                <th>Mean Latency</th>
                <th>Errors</th>
              </tr>
            </thead>
            <tbody>
              {exp.ablation_results.map((ab: AblationResult) => (
                <tr key={ab.configuration_name}>
                  <td>
                    <strong style={{ color: "var(--color-primary-light)" }}>
                      {ab.configuration_name}
                    </strong>
                  </td>
                  <td>
                    <span style={{ color: "var(--color-text-muted)", fontSize: "0.78rem" }}>
                      {ab.enabled_stages.join(" → ")}
                    </span>
                  </td>
                  <td>
                    {ab.metrics.precision !== null && ab.metrics.precision !== undefined
                      ? `${(ab.metrics.precision * 100).toFixed(1)}%`
                      : "—"}
                  </td>
                  <td>
                    {ab.metrics.recall !== null && ab.metrics.recall !== undefined
                      ? `${(ab.metrics.recall * 100).toFixed(1)}%`
                      : "—"}
                  </td>
                  <td>
                    <strong
                      style={{
                        color:
                          (ab.metrics.f1_score || 0) >= 0.9
                            ? "var(--color-success)"
                            : (ab.metrics.f1_score || 0) >= 0.75
                            ? "var(--color-warning)"
                            : "var(--color-critical)",
                      }}
                    >
                      {ab.metrics.f1_score !== null && ab.metrics.f1_score !== undefined
                        ? `${(ab.metrics.f1_score * 100).toFixed(1)}%`
                        : "—"}
                    </strong>
                  </td>
                  <td>
                    {ab.metrics.fpr !== null && ab.metrics.fpr !== undefined
                      ? `${(ab.metrics.fpr * 100).toFixed(1)}%`
                      : "—"}
                  </td>
                  <td>{ab.performance.mean_sample_latency_ms.toFixed(1)} ms</td>
                  <td>
                    <span
                      className={`badge badge-sm ${
                        ab.error_count === 0 ? "badge-success" : "badge-medium"
                      }`}
                    >
                      {ab.error_count}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Confusion Matrix & Error Taxonomy Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1.5rem" }}>
        {/* Confusion Matrix Card */}
        <div className="card" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <h3 style={{ margin: 0, fontSize: "1.05rem", fontWeight: 600 }}>
            🔲 Empirical Confusion Matrix
          </h3>
          <p style={{ margin: 0, fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
            Ground truth vs operational assessment verdict mappings.
          </p>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "0.75rem",
              marginTop: "0.5rem",
            }}
          >
            <div
              style={{
                background: "rgba(16, 185, 129, 0.1)",
                border: "1px solid rgba(16, 185, 129, 0.3)",
                padding: "1rem",
                borderRadius: "6px",
                textAlign: "center",
              }}
            >
              <span style={{ fontSize: "0.75rem", color: "var(--color-success)", fontWeight: 600 }}>
                TRUE POSITIVES (TP)
              </span>
              <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "var(--color-success)" }}>
                {cm?.tp ?? 0}
              </div>
              <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>
                Malicious correctly flagged
              </span>
            </div>

            <div
              style={{
                background: "rgba(239, 68, 68, 0.1)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                padding: "1rem",
                borderRadius: "6px",
                textAlign: "center",
              }}
            >
              <span style={{ fontSize: "0.75rem", color: "var(--color-critical)", fontWeight: 600 }}>
                FALSE POSITIVES (FP)
              </span>
              <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "var(--color-critical)" }}>
                {cm?.fp ?? 0}
              </div>
              <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>
                Benign incorrectly flagged
              </span>
            </div>

            <div
              style={{
                background: "rgba(239, 68, 68, 0.1)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                padding: "1rem",
                borderRadius: "6px",
                textAlign: "center",
              }}
            >
              <span style={{ fontSize: "0.75rem", color: "var(--color-critical)", fontWeight: 600 }}>
                FALSE NEGATIVES (FN)
              </span>
              <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "var(--color-critical)" }}>
                {cm?.fn ?? 0}
              </div>
              <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>
                Malicious missed as benign
              </span>
            </div>

            <div
              style={{
                background: "rgba(16, 185, 129, 0.1)",
                border: "1px solid rgba(16, 185, 129, 0.3)",
                padding: "1rem",
                borderRadius: "6px",
                textAlign: "center",
              }}
            >
              <span style={{ fontSize: "0.75rem", color: "var(--color-success)", fontWeight: 600 }}>
                TRUE NEGATIVES (TN)
              </span>
              <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "var(--color-success)" }}>
                {cm?.tn ?? 0}
              </div>
              <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>
                Benign correctly cleared
              </span>
            </div>
          </div>

          <div
            style={{
              padding: "0.75rem",
              background: "rgba(15, 23, 42, 0.5)",
              borderRadius: "4px",
              fontSize: "0.8rem",
              color: "var(--color-text-muted)",
              display: "flex",
              justifyContent: "space-between",
            }}
          >
            <span>Indeterminate / UNKNOWN Verdicts:</span>
            <strong>{cm?.unknown_count ?? 0} (Preserved, never converted)</strong>
          </div>
        </div>

        {/* Error Taxonomy & Diagnostic Records */}
        <div className="card" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <h3 style={{ margin: 0, fontSize: "1.05rem", fontWeight: 600 }}>
            ⚠️ Diagnostic Error Taxonomy
          </h3>
          <p style={{ margin: 0, fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
            Root cause analysis of misclassifications under strict evidence categorization.
          </p>

          {(!exp.error_analysis || exp.error_analysis.length === 0) ? (
            <div style={{ textAlign: "center", padding: "2rem", color: "var(--color-text-muted)" }}>
              No classification errors identified in the evaluated test split.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {(exp.error_analysis || []).map((err) => (
                <div
                  key={err.sample_id}
                  style={{
                    padding: "0.85rem",
                    borderRadius: "6px",
                    background: "rgba(15, 23, 42, 0.6)",
                    borderLeft: `4px solid ${
                      err.error_type === "FALSE_POSITIVE"
                        ? "var(--color-critical)"
                        : "var(--color-warning)"
                    }`,
                    fontSize: "0.82rem",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.35rem" }}>
                    <strong>{err.sample_id}</strong>
                    <span className="badge badge-critical badge-sm">{err.error_type}</span>
                  </div>
                  <div style={{ color: "var(--color-text-muted)", marginBottom: "0.35rem" }}>
                    Category: <strong style={{ color: "var(--color-primary-light)" }}>{err.likely_cause_category}</strong> (Observation: {err.observation_level})
                  </div>
                  <p style={{ margin: 0, color: "var(--color-text-muted)" }}>
                    {err.explanation}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Reproducibility & Threats to Validity */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1.5rem" }}>
        {/* Reproducibility Parameters */}
        <div className="card" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          <h3 style={{ margin: 0, fontSize: "1.05rem", fontWeight: 600 }}>
            🔒 Reproducibility Parameters
          </h3>
          <ul style={{ margin: 0, paddingLeft: "1.25rem", fontSize: "0.85rem", color: "var(--color-text-muted)", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
            <li><strong>Experiment ID:</strong> <code>{exp.reproducibility?.experiment_id || "N/A"}</code></li>
            <li><strong>Code Version:</strong> <code>{exp.reproducibility?.code_version || "1.0.0"}</code></li>
            <li><strong>Pipeline Version:</strong> <code>{exp.reproducibility?.pipeline_version || "v1"}</code></li>
            <li><strong>Dataset SHA-256:</strong> <code style={{ fontSize: "0.75rem" }}>{(exp.reproducibility?.dataset_hash || "").slice(0, 16)}...</code></li>
            <li><strong>Random Seed:</strong> <code>{exp.reproducibility?.random_seed ?? 42}</code></li>
            <li><strong>Split Strategy:</strong> <code>{exp.reproducibility?.split_strategy || "stratified"}</code></li>
          </ul>
        </div>

        {/* Threats to Empirical Validity */}
        <div className="card" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          <h3 style={{ margin: 0, fontSize: "1.05rem", fontWeight: 600 }}>
            🛡️ Threats to Empirical Validity
          </h3>
          <ul style={{ margin: 0, paddingLeft: "1.25rem", fontSize: "0.85rem", color: "var(--color-text-muted)", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
            {(exp.threats_to_validity || []).map((threat, idx) => (
              <li key={idx}>{threat}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
