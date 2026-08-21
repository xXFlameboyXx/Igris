import React, { useState, useEffect, useCallback } from "react";
import type {
  AnalysisJob,
  InvestigationTab,
  PipelineStageName,
  Sample,
  StageStatus,
} from "../../types/api";
import { apiClient, ApiError } from "../../services/apiClient";
import {
  DEMO_COMPLETE_PIPELINE_JOB,
  DEMO_PARTIAL_PIPELINE_JOB,
} from "../../services/syntheticDemoData";
import { EmptyState, LoadingState, ErrorState } from "../common/StateViews";

interface AnalysisPipelineViewProps {
  sample: Sample | null;
  onNavigateTab: (tab: InvestigationTab) => void;
  isDemoMode?: boolean;
}

const STAGE_CONFIG: Record<
  PipelineStageName,
  { label: string; description: string; tab: InvestigationTab; icon: string }
> = {
  FILE_INTELLIGENCE: {
    label: "File Intelligence",
    description: "Format detection, hashing, entropy calculation & binary header parsing",
    tab: "overview",
    icon: "📄",
  },
  STATIC_ANALYSIS: {
    label: "Static Analysis",
    description: "Imports, exports, strings, entropy spikes & packer heuristics",
    tab: "static",
    icon: "🔍",
  },
  DETECTION: {
    label: "Detection Rules",
    description: "Evidence-driven rule matching against static signatures & IOCs",
    tab: "evidence",
    icon: "🛡️",
  },
  REVERSE_ANALYSIS: {
    label: "Reverse Engineering",
    description: "Safe linear disassembler, function discovery & control-flow graphs",
    tab: "reverse",
    icon: "⚙️",
  },
  ML: {
    label: "ML Inference",
    description: "Machine learning classifier score with SHAP explainability",
    tab: "ml",
    icon: "🧠",
  },
  BEHAVIOR: {
    label: "Behavioral Sandbox",
    description: "Process execution trees, file system modifications & network telemetry",
    tab: "behavior",
    icon: "🧪",
  },
  SIMILARITY: {
    label: "Sample Similarity",
    description: "Multi-level code, TLSH, SSDEEP & capability clustering",
    tab: "similarity",
    icon: "🧬",
  },
  THREAT_INTELLIGENCE: {
    label: "Threat Intelligence",
    description: "MITRE ATT&CK technique mapping & preliminary behavior narrative",
    tab: "attack",
    icon: "🌐",
  },
  EVIDENCE_CORRELATION: {
    label: "Evidence Correlation",
    description: "Multi-engine evidence synthesis and observation mapping",
    tab: "evidence",
    icon: "🔗",
  },
  ASSESSMENT: {
    label: "Explainable Assessment",
    description: "Multi-dimensional confidence, verdict synthesis & limitation tracking",
    tab: "verdict",
    icon: "⚖️",
  },
  REPORT: {
    label: "Investigation Report",
    description: "Deterministic structured dossier compiling JSON and PDF exports",
    tab: "report",
    icon: "📑",
  },
};

export const AnalysisPipelineView: React.FC<AnalysisPipelineViewProps> = ({
  sample,
  onNavigateTab,
  isDemoMode = false,
}) => {
  const [activeJob, setActiveJob] = useState<AnalysisJob | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isTriggering, setIsTriggering] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  // Load existing or recent analysis job for sample
  const loadJob = useCallback(async () => {
    if (!sample) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiClient.listAnalyses(sample.sample_id);
      if (res.analyses && res.analyses.length > 0) {
        setActiveJob(res.analyses[0]);
      } else if (isDemoMode) {
        // Fallback to synthetic demo job in demo mode
        if (sample.sample_id.includes("disagreement") || sample.sample_id.includes("33c")) {
          setActiveJob(DEMO_PARTIAL_PIPELINE_JOB);
        } else {
          setActiveJob(DEMO_COMPLETE_PIPELINE_JOB);
        }
      } else {
        setActiveJob(null);
      }
    } catch (err) {
      if (isDemoMode) {
        if (sample.sample_id.includes("disagreement") || sample.sample_id.includes("33c")) {
          setActiveJob(DEMO_PARTIAL_PIPELINE_JOB);
        } else {
          setActiveJob(DEMO_COMPLETE_PIPELINE_JOB);
        }
      } else if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Failed to fetch pipeline job history.");
      }
    } finally {
      setIsLoading(false);
    }
  }, [sample, isDemoMode]);

  useEffect(() => {
    loadJob();
  }, [loadJob]);

  // Polling when job is RUNNING or QUEUED
  useEffect(() => {
    if (!activeJob || !autoRefresh) return;
    if (activeJob.status !== "RUNNING" && activeJob.status !== "QUEUED") return;

    const interval = setInterval(async () => {
      try {
        const res = await apiClient.getAnalysisStatus(activeJob.analysis_id);
        setActiveJob((prev) => (prev ? { ...prev, ...res } : null));
      } catch (err) {
        console.error("Failed to poll analysis status", err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [activeJob, autoRefresh]);

  const handleStartPipeline = async (force: boolean = false) => {
    if (!sample) return;
    setIsTriggering(true);
    setError(null);
    try {
      const res = await apiClient.startAnalysis({
        sample_id: sample.sample_id,
        force_reanalyze: force,
      });
      setActiveJob(res.analysis);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Failed to trigger pipeline orchestration.");
      }
    } finally {
      setIsTriggering(false);
    }
  };

  const handleCancelPipeline = async () => {
    if (!activeJob) return;
    try {
      const res = await apiClient.cancelAnalysis(activeJob.analysis_id);
      setActiveJob((prev) => (prev ? { ...prev, status: res.status } : null));
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Failed to cancel active job.");
      }
    }
  };

  const getStatusBadge = (status: StageStatus) => {
    switch (status) {
      case "COMPLETED":
        return <span className="badge badge-success badge-sm">COMPLETED</span>;
      case "RUNNING":
        return <span className="badge badge-high badge-sm">RUNNING</span>;
      case "QUEUED":
        return <span className="badge badge-neutral badge-sm">QUEUED</span>;
      case "FAILED":
        return <span className="badge badge-critical badge-sm">FAILED</span>;
      case "SKIPPED":
        return <span className="badge badge-medium badge-sm">SKIPPED</span>;
      case "CANCELLED":
        return <span className="badge badge-neutral badge-sm">CANCELLED</span>;
      case "TIMEOUT":
        return <span className="badge badge-critical badge-sm">TIMEOUT</span>;
      default:
        return <span className="badge badge-neutral badge-sm">NOT STARTED</span>;
    }
  };

  if (!sample) {
    return (
      <EmptyState
        icon="⚡"
        title="No Specimen Selected"
        message="Please upload a binary specimen or select one from the top bar to inspect or trigger pipeline orchestration."
      />
    );
  }

  if (isLoading && !activeJob) {
    return <LoadingState message="Fetching orchestration pipeline jobs..." />;
  }

  const stagesList = activeJob?.stages || [];
  const completedStagesCount = stagesList.filter((s) => s.status === "COMPLETED").length;
  const failedStagesCount = stagesList.filter((s) => s.status === "FAILED").length;
  const totalStagesCount = stagesList.length > 0 ? stagesList.length : 11;

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
          background: "linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%)",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
            <h2 style={{ margin: 0, fontSize: "1.35rem", fontWeight: 700 }}>
              ⚡ Analysis Pipeline & Job Orchestration
            </h2>
            {activeJob && (
              <span
                className={`badge badge-sm ${
                  activeJob.status === "COMPLETED"
                    ? "badge-success"
                    : activeJob.status === "RUNNING"
                    ? "badge-high"
                    : activeJob.status === "FAILED"
                    ? "badge-critical"
                    : "badge-neutral"
                }`}
              >
                {activeJob.status}
              </span>
            )}
          </div>
          <p style={{ margin: 0, color: "var(--color-text-muted)", fontSize: "0.875rem" }}>
            Orchestrates independent analysis engines into a coherent, reproducible pipeline with stage-level failure isolation.
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          {activeJob && (activeJob.status === "RUNNING" || activeJob.status === "QUEUED") ? (
            <button
              className="btn btn-outline"
              onClick={handleCancelPipeline}
              style={{ borderColor: "var(--color-critical)", color: "var(--color-critical)" }}
            >
              🛑 Cancel Pipeline
            </button>
          ) : (
            <>
              <button
                className="btn btn-primary"
                onClick={() => handleStartPipeline(false)}
                disabled={isTriggering}
              >
                {isTriggering ? "Starting..." : activeJob ? "⚡ Re-run Pipeline" : "▶ Run Analysis Pipeline"}
              </button>
              <button
                className="btn btn-outline"
                onClick={() => handleStartPipeline(true)}
                disabled={isTriggering}
                title="Bypass idempotency cache and force complete re-analysis"
              >
                🔄 Force Re-run
              </button>
            </>
          )}

          <button
            className={`btn btn-outline ${autoRefresh ? "active" : ""}`}
            onClick={() => setAutoRefresh((prev) => !prev)}
            title="Toggle live auto-polling"
            style={{ fontSize: "0.8rem", padding: "0.4rem 0.75rem" }}
          >
            {autoRefresh ? "● Live Polling" : "○ Polling Paused"}
          </button>

          <button
            className="btn btn-outline"
            onClick={loadJob}
            title="Refresh job state"
          >
            ↻
          </button>
        </div>
      </div>

      {error && <ErrorState error={error} onRetry={loadJob} />}

      {/* Active Pipeline Status & Progress Bar */}
      {activeJob && (
        <div className="card" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "0.5rem" }}>
            <div>
              <span style={{ fontSize: "0.85rem", color: "var(--color-text-muted)", marginRight: "0.5rem" }}>Job ID:</span>
              <code style={{ fontSize: "0.85rem", color: "var(--color-primary-light)" }}>{activeJob.analysis_id}</code>
            </div>
            <div style={{ display: "flex", gap: "1.5rem", fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
              <span>Completed: <strong style={{ color: "var(--color-success)" }}>{completedStagesCount}</strong> / {totalStagesCount}</span>
              {failedStagesCount > 0 && (
                <span>Failed (Isolated): <strong style={{ color: "var(--color-critical)" }}>{failedStagesCount}</strong></span>
              )}
              <span>Progress: <strong style={{ color: "var(--color-text-bright)" }}>{activeJob.progress}%</strong></span>
            </div>
          </div>

          {/* Animated Progress Bar */}
          <div
            style={{
              width: "100%",
              height: "8px",
              backgroundColor: "rgba(255, 255, 255, 0.08)",
              borderRadius: "4px",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                width: `${activeJob.progress}%`,
                height: "100%",
                backgroundColor:
                  activeJob.status === "FAILED"
                    ? "var(--color-critical)"
                    : activeJob.status === "COMPLETED"
                    ? "var(--color-success)"
                    : "var(--color-primary)",
                transition: "width 0.4s ease-in-out",
              }}
            />
          </div>

          {/* Partial Results Callout */}
          {failedStagesCount > 0 && (
            <div
              style={{
                padding: "0.75rem 1rem",
                borderRadius: "var(--radius-sm)",
                backgroundColor: "rgba(234, 179, 8, 0.12)",
                border: "1px solid rgba(234, 179, 8, 0.3)",
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
                fontSize: "0.85rem",
              }}
            >
              <span>⚠️</span>
              <div>
                <strong>Partial Results Preserved:</strong> {failedStagesCount} stage(s) encountered isolated errors. Independent analysis stages and final explainable assessment continued without fabricating missing evidence.
              </div>
            </div>
          )}
        </div>
      )}

      {/* Pipeline Stage Sequence Flow */}
      <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: 600 }}>Pipeline Execution Graph</h3>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: "1rem" }}>
          {(activeJob?.stages || []).map((stageRecord, idx) => {
            const config = STAGE_CONFIG[stageRecord.name] || {
              label: stageRecord.name,
              description: "Subsystem analysis stage",
              tab: "overview" as InvestigationTab,
              icon: "📦",
            };

            return (
              <div
                key={stageRecord.name}
                className="card"
                style={{
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-between",
                  gap: "0.75rem",
                  padding: "1.25rem",
                  borderLeft: `4px solid ${
                    stageRecord.status === "COMPLETED"
                      ? "var(--color-success)"
                      : stageRecord.status === "FAILED"
                      ? "var(--color-critical)"
                      : stageRecord.status === "RUNNING"
                      ? "var(--color-primary)"
                      : stageRecord.status === "SKIPPED"
                      ? "var(--color-warning)"
                      : "rgba(255, 255, 255, 0.2)"
                  }`,
                }}
              >
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <span style={{ fontSize: "1.2rem" }}>{config.icon}</span>
                      <strong style={{ fontSize: "0.95rem", color: "var(--color-text-bright)" }}>
                        {idx + 1}. {config.label}
                      </strong>
                    </div>
                    {getStatusBadge(stageRecord.status)}
                  </div>

                  <p style={{ margin: 0, fontSize: "0.8rem", color: "var(--color-text-muted)", lineHeight: 1.4 }}>
                    {config.description}
                  </p>

                  {/* Stage Metrics */}
                  <div
                    style={{
                      display: "flex",
                      gap: "1rem",
                      fontSize: "0.75rem",
                      color: "var(--color-text-muted)",
                      marginTop: "0.75rem",
                      paddingTop: "0.5rem",
                      borderTop: "1px solid rgba(255, 255, 255, 0.05)",
                    }}
                  >
                    {stageRecord.duration_ms !== null && stageRecord.duration_ms !== undefined && (
                      <span>⏱️ <strong>{stageRecord.duration_ms.toFixed(1)} ms</strong></span>
                    )}
                    {stageRecord.retry_count > 0 && (
                      <span>🔄 Retries: <strong>{stageRecord.retry_count}</strong></span>
                    )}
                  </div>

                  {/* Stage Error details if present */}
                  {stageRecord.error && (
                    <div
                      style={{
                        marginTop: "0.5rem",
                        padding: "0.5rem",
                        borderRadius: "var(--radius-sm)",
                        backgroundColor: "rgba(239, 68, 68, 0.1)",
                        border: "1px solid rgba(239, 68, 68, 0.25)",
                        fontSize: "0.75rem",
                        color: "#fca5a5",
                      }}
                    >
                      <strong>{stageRecord.error.error_category}:</strong> {stageRecord.error.safe_message}
                    </div>
                  )}
                </div>

                {/* Jump to Subsystem Tab Button */}
                <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "0.25rem" }}>
                  <button
                    className="btn btn-outline"
                    onClick={() => onNavigateTab(config.tab)}
                    style={{ fontSize: "0.75rem", padding: "0.3rem 0.6rem" }}
                  >
                    Inspect Stage Output →
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Reproducibility & Engine Versions Card */}
      {activeJob && (
        <div className="card" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          <h4 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 600 }}>Reproducibility & Engine Provenance</h4>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: "0.75rem", fontSize: "0.8rem" }}>
            <div>
              <span style={{ color: "var(--color-text-muted)" }}>Idempotency Hash:</span>
              <div style={{ fontFamily: "monospace", color: "var(--color-primary-light)", overflow: "hidden", textOverflow: "ellipsis" }}>
                {activeJob.idempotency_key}
              </div>
            </div>
            {Object.entries(activeJob.engine_versions || {}).map(([engine, ver]) => (
              <div key={engine}>
                <span style={{ color: "var(--color-text-muted)", textTransform: "capitalize" }}>
                  {engine.replace(/_/g, " ")}:
                </span>{" "}
                <strong style={{ color: "var(--color-text-bright)" }}>{ver}</strong>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
