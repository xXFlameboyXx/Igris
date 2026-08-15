import React from "react";
import { DEMO_SAMPLES_LIST, SYNTHETIC_DEMO_TAG } from "../../services/syntheticDemoData";
import type { InvestigationTab, Sample } from "../../types/api";
import { RiskLevelBadge, VerdictBadge } from "../common/Badge";
import { SyntheticBanner } from "../common/StateViews";

interface SyntheticDemoViewProps {
  currentSample: Sample | null;
  onSelectSample: (sample: Sample) => void;
  onNavigateTab: (tab: InvestigationTab) => void;
}

export function SyntheticDemoView({
  currentSample,
  onSelectSample,
  onNavigateTab,
}: SyntheticDemoViewProps) {
  const steps = [
    {
      step: 1,
      title: "Sample Ingestion & File Hashing",
      desc: "Computes cryptographic hashes (SHA-256, SHA-1, MD5), detects MIME format, and checks executable headers.",
      tab: "static" as InvestigationTab,
    },
    {
      step: 2,
      title: "Multi-Engine Independent Analysis",
      desc: "Executes static PE/ELF inspection, function disassembly, dynamic sandbox emulation, detection rules, and ML inference.",
      tab: "behavior" as InvestigationTab,
    },
    {
      step: 3,
      title: "Cross-Layer Evidence Extraction",
      desc: "Normalizes raw telemetry into traceable evidence items with explicit source IDs, weights, and provenance metadata.",
      tab: "evidence" as InvestigationTab,
    },
    {
      step: 4,
      title: "Phase 11 Epistemological Classification",
      desc: "Categorizes findings into OBSERVED (direct facts), INFERRED (rule deductions), and POSSIBLE (cluster hypotheses).",
      tab: "verdict" as InvestigationTab,
    },
    {
      step: 5,
      title: "Contradiction & Disagreement Check",
      desc: "Identifies conflicts across independent subsystems (e.g. static packed indicators vs clean runtime execution).",
      tab: "overview" as InvestigationTab,
    },
    {
      step: 6,
      title: "Explainable Verdict & Traceability",
      desc: "Produces multi-dimensional confidence breakdown, deterministic risk score (0–100), and human-readable reasoning.",
      tab: "report" as InvestigationTab,
    },
  ];

  return (
    <div className="view-container synthetic-demo-view" role="main" aria-label="Synthetic Demonstration Lab">
      <SyntheticBanner />

      <div className="view-header-row">
        <div>
          <h2 className="view-title">Synthetic Demonstration Lab & Walkthrough</h2>
          <p className="view-subtitle">
            Controlled demonstration workflows showcasing the complete IGRIS explainable assessment and pipeline orchestration.
          </p>
        </div>
        <div>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => onNavigateTab("pipeline")}
          >
            ⚡ Open Pipeline Orchestrator
          </button>
        </div>
      </div>

      {/* Demonstration Scenario Cards */}
      <section className="demo-scenarios-section">
        <h3 className="subheading">Select Controlled Demonstration Scenario</h3>
        <div className="demo-scenarios-grid">
          {DEMO_SAMPLES_LIST.map((demo) => {
            const isSelected = currentSample?.sample_id === demo.sample_id;
            const verdict = demo.malware_assessment?.verdict || "UNKNOWN";
            const riskLevel = demo.malware_assessment?.risk_level || "UNKNOWN";
            const score = demo.malware_assessment?.risk_score.score ?? 0;

            return (
              <div
                key={demo.sample_id}
                className={`demo-scenario-card ${isSelected ? "selected-scenario" : ""}`}
                onClick={() => onSelectSample(demo)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onSelectSample(demo)}
              >
                <div className="demo-card-header">
                  <span className="demo-tag">{SYNTHETIC_DEMO_TAG}</span>
                  <div className="scenario-badges">
                    <VerdictBadge verdict={verdict} size="sm" />
                    <RiskLevelBadge level={riskLevel} size="sm" />
                  </div>
                </div>

                <h4 className="scenario-title">{demo.original_filename}</h4>
                <p className="scenario-desc">
                  {demo.malware_assessment?.explanation.summary.slice(0, 140)}…
                </p>

                <div className="scenario-footer">
                  <span className="scenario-score">Risk Score: <strong>{score}/100</strong></span>
                  <button
                    type="button"
                    className={`btn btn-sm ${isSelected ? "btn-primary" : "btn-outline"}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectSample(demo);
                    }}
                  >
                    {isSelected ? "Active Scenario ✓" : "Load Scenario"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Investigation Pipeline Walkthrough Steps */}
      <section className="demo-pipeline-section">
        <h3 className="subheading">The 6-Stage Explainable Assessment Pipeline</h3>
        <div className="pipeline-steps-stack">
          {steps.map((st) => (
            <div key={st.step} className="pipeline-step-row">
              <div className="step-number-badge">{st.step}</div>
              <div className="step-details">
                <h4 className="step-title">{st.title}</h4>
                <p className="step-desc">{st.desc}</p>
              </div>
              <div className="step-action">
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => onNavigateTab(st.tab)}
                >
                  Inspect {st.tab.toUpperCase()} View ›
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
