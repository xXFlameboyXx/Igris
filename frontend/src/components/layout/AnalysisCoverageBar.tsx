import React from "react";
import type { Sample } from "../../types/api";

interface AnalysisCoverageBarProps {
  sample: Sample | null;
  onNavigateTab?: (tab: string) => void;
}

export function AnalysisCoverageBar({ sample, onNavigateTab }: AnalysisCoverageBarProps) {
  if (!sample) return null;

  const layers = [
    {
      id: "static",
      label: "Static Analysis",
      isComplete: !!sample.static_analysis,
      tab: "static",
    },
    {
      id: "reverse",
      label: "Reverse Eng",
      isComplete: !!sample.reverse_analysis,
      tab: "reverse",
    },
    {
      id: "behavior",
      label: "Behavior Sandbox",
      isComplete: !!sample.behavior_analysis,
      tab: "behavior",
    },
    {
      id: "detection",
      label: "Detection Rules",
      isComplete: !!sample.detection,
      tab: "overview",
    },
    {
      id: "ml",
      label: "ML Classifier",
      isComplete: !!sample.ml_prediction,
      tab: "ml",
    },
    {
      id: "similarity",
      label: "Similarity Index",
      isComplete: !!sample.similarity_analysis,
      tab: "similarity",
    },
    {
      id: "assessment",
      label: "Explainable Assessment",
      isComplete: !!sample.malware_assessment,
      tab: "verdict",
    },
  ];

  const completedCount = layers.filter((l) => l.isComplete).length;
  const coveragePct = Math.round((completedCount / layers.length) * 100);

  return (
    <div className="coverage-bar-container" role="region" aria-label="Analysis Coverage">
      <div className="coverage-header">
        <span className="coverage-title">
          Analysis Coverage: <strong>{completedCount} / {layers.length} Subsystems ({coveragePct}%)</strong>
        </span>
        <div className="coverage-progress-track" aria-hidden="true">
          <div
            className="coverage-progress-fill"
            style={{ width: `${coveragePct}%` }}
          />
        </div>
      </div>

      <div className="coverage-pills" role="list">
        {layers.map((layer) => (
          <button
            key={layer.id}
            type="button"
            className={`coverage-pill ${layer.isComplete ? "pill-completed" : "pill-missing"}`}
            onClick={() => onNavigateTab && onNavigateTab(layer.tab)}
            role="listitem"
            title={`${layer.label}: ${layer.isComplete ? "Completed" : "Unperformed / Unavailable"}`}
          >
            <span className="pill-dot" aria-hidden="true">
              {layer.isComplete ? "✓" : "○"}
            </span>
            <span className="pill-name">{layer.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
