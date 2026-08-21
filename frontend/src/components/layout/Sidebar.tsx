import React from "react";
import type { InvestigationTab, Sample } from "../../types/api";

interface SidebarProps {
  activeTab: InvestigationTab;
  onSelectTab: (tab: InvestigationTab) => void;
  sample: Sample | null;
}

export function Sidebar({ activeTab, onSelectTab, sample }: SidebarProps) {
  const navItems: Array<{
    id: InvestigationTab;
    label: string;
    icon: string;
    badge?: string | number;
    badgeClass?: string;
  }> = [
    {
      id: "overview",
      label: "Overview",
      icon: "📊",
      badge: sample?.malware_assessment?.verdict || undefined,
      badgeClass:
        sample?.malware_assessment?.verdict === "HIGHLY_SUSPICIOUS"
          ? "badge-critical"
          : sample?.malware_assessment?.verdict === "SUSPICIOUS"
          ? "badge-high"
          : "badge-neutral",
    },
    {
      id: "pipeline",
      label: "Pipeline & Jobs",
      icon: "⚡",
    },
    {
      id: "verdict",
      label: "Verdict & Explainability",
      icon: "⚖️",
      badge:
        sample?.malware_assessment?.risk_score?.score != null
          ? `${sample.malware_assessment.risk_score.score}/100`
          : undefined,
    },
    {
      id: "evidence",
      label: "Evidence Explorer",
      icon: "🔎",
      badge: sample?.malware_assessment?.evidence_summary?.total_evidence_count,
    },
    {
      id: "static",
      label: "Static Analysis",
      icon: "📑",
      badge: sample?.static_analysis
        ? `${(sample.static_analysis.strings_found?.length ?? sample.static_analysis.strings?.length ?? 0)} str`
        : undefined,
    },
    {
      id: "reverse",
      label: "Reverse Engineering",
      icon: "⚙️",
      badge: sample?.reverse_analysis?.functions?.length,
    },
    {
      id: "behavior",
      label: "Behavior Sandbox",
      icon: "🏃",
      badge: sample?.behavior_analysis
        ? (sample.behavior_analysis.processes?.length || 0) +
          (sample.behavior_analysis.network_events?.length || 0)
        : undefined,
    },
    {
      id: "similarity",
      label: "Sample Similarity",
      icon: "🧬",
      badge: sample?.similarity_analysis?.matches?.length,
    },
    {
      id: "attack",
      label: "ATT&CK Mapping",
      icon: "🎯",
      badge: sample?.threat_assessment?.capabilities?.length,
    },
    {
      id: "ml",
      label: "ML Classifier",
      icon: "🤖",
      badge:
        sample?.ml_prediction?.score != null
          ? `${Math.round((sample.ml_prediction.score ?? 0) * 100)}%`
          : undefined,
    },
    {
      id: "report",
      label: "Investigation Report",
      icon: "📝",
    },
  ];

  return (
    <aside className="app-sidebar" role="navigation" aria-label="Investigation Navigation">
      <div className="sidebar-section-title">INVESTIGATION VIEWS</div>
      <ul className="nav-list" role="list">
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <li key={item.id} role="listitem">
              <button
                type="button"
                className={`nav-item ${isActive ? "active" : ""}`}
                onClick={() => onSelectTab(item.id)}
                aria-current={isActive ? "page" : undefined}
              >
                <span className="nav-icon" aria-hidden="true">
                  {item.icon}
                </span>
                <span className="nav-label">{item.label}</span>
                {item.badge !== undefined && item.badge !== null && (
                  <span className={`nav-badge ${item.badgeClass || "badge-default"}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ul>

      <div className="sidebar-footer-note">
        <small>IGRIS v0.1.0 • Phase 12 Analyst Console</small>
      </div>
    </aside>
  );
}
