import React from "react";
import type {
  AssessmentVerdict,
  ConfidenceLevel,
  EvidenceCategory,
  EvidenceRole,
  EvidenceStrength,
  ObservationLevel,
  RiskLevel,
  SimilarityHypothesis,
} from "../../types/api";

export function VerdictBadge({ verdict, size = "md" }: { verdict: AssessmentVerdict; size?: "sm" | "md" | "lg" }) {
  let styleClass = "badge-unknown";
  let icon = "❓";
  let label = "UNKNOWN";

  if (verdict === "HIGHLY_SUSPICIOUS") {
    styleClass = "badge-critical";
    icon = "⛔";
    label = "HIGHLY SUSPICIOUS";
  } else if (verdict === "SUSPICIOUS") {
    styleClass = "badge-high";
    icon = "⚠️";
    label = "SUSPICIOUS";
  } else if (verdict === "LIKELY_BENIGN") {
    styleClass = "badge-low";
    icon = "🛡️";
    label = "LIKELY BENIGN";
  } else if (verdict === "BENIGN") {
    styleClass = "badge-success";
    icon = "✅";
    label = "BENIGN";
  }

  return (
    <span className={`badge ${styleClass} badge-${size}`} role="status" aria-label={`Verdict: ${label}`}>
      <span className="badge-icon" aria-hidden="true">{icon}</span>
      <span className="badge-text">{label}</span>
    </span>
  );
}

export function RiskLevelBadge({ level, size = "md" }: { level: RiskLevel; size?: "sm" | "md" | "lg" }) {
  const styles: Record<RiskLevel, { cls: string; icon: string }> = {
    CRITICAL: { cls: "badge-critical", icon: "💥" },
    HIGH: { cls: "badge-high", icon: "🔥" },
    MEDIUM: { cls: "badge-medium", icon: "⚡" },
    LOW: { cls: "badge-low", icon: "🔹" },
    NONE: { cls: "badge-success", icon: "✔️" },
    UNKNOWN: { cls: "badge-unknown", icon: "❓" },
  };

  const current = styles[level] || styles.UNKNOWN;

  return (
    <span className={`badge ${current.cls} badge-${size}`} aria-label={`Risk Level: ${level}`}>
      <span className="badge-icon" aria-hidden="true">{current.icon}</span>
      <span className="badge-text">RISK: {level}</span>
    </span>
  );
}

export function ObservationLevelBadge({ level }: { level: ObservationLevel }) {
  const meta: Record<ObservationLevel, { cls: string; icon: string; title: string }> = {
    OBSERVED: { cls: "badge-observed", icon: "👁️", title: "Directly observed in binary structure or telemetry" },
    INFERRED: { cls: "badge-inferred", icon: "🧠", title: "Derived analytical interpretation or rule match" },
    POSSIBLE: { cls: "badge-possible", icon: "💡", title: "Potential hypothesis or similarity cluster overlap" },
  };

  const item = meta[level] || meta.OBSERVED;

  return (
    <span className={`badge ${item.cls} badge-sm`} title={item.title} aria-label={`Epistemological level: ${level}`}>
      <span className="badge-icon" aria-hidden="true">{item.icon}</span>
      <span className="badge-text">[{level}]</span>
    </span>
  );
}

export function EvidenceRoleBadge({ role }: { role: EvidenceRole }) {
  const meta: Record<EvidenceRole, { cls: string; icon: string }> = {
    SUPPORTING: { cls: "badge-supporting", icon: "🔺" },
    CONTRADICTING: { cls: "badge-contradicting", icon: "🔻" },
    NEUTRAL: { cls: "badge-neutral", icon: "➖" },
  };

  const item = meta[role] || meta.NEUTRAL;

  return (
    <span className={`badge ${item.cls} badge-sm`} aria-label={`Evidence Role: ${role}`}>
      <span className="badge-icon" aria-hidden="true">{item.icon}</span>
      <span className="badge-text">{role}</span>
    </span>
  );
}

export function StrengthBadge({ strength }: { strength: EvidenceStrength | "INFO" | "CRITICAL" }) {
  const meta: Record<string, string> = {
    CRITICAL: "badge-critical",
    HIGH: "badge-high",
    MEDIUM: "badge-medium",
    LOW: "badge-low",
    INFO: "badge-info",
  };

  const cls = meta[strength] || "badge-medium";

  return (
    <span className={`badge ${cls} badge-sm`}>
      <span className="badge-text">{strength}</span>
    </span>
  );
}

export function ConfidenceBadge({ label, level }: { label: string; level: ConfidenceLevel }) {
  const meta: Record<ConfidenceLevel, { cls: string; icon: string }> = {
    HIGH: { cls: "badge-success", icon: "🟢" },
    MEDIUM: { cls: "badge-medium", icon: "🟡" },
    LOW: { cls: "badge-low", icon: "🟠" },
    UNAVAILABLE: { cls: "badge-unknown", icon: "⚪" },
  };

  const item = meta[level] || meta.UNAVAILABLE;

  return (
    <span className={`badge ${item.cls} badge-sm`} title={`${label}: ${level}`}>
      <span className="badge-icon" aria-hidden="true">{item.icon}</span>
      <span className="badge-text">{label}: {level}</span>
    </span>
  );
}

export function CategoryBadge({ category }: { category: EvidenceCategory | string }) {
  return (
    <span className="badge badge-category badge-sm">
      <span className="badge-text">{category.toUpperCase()}</span>
    </span>
  );
}

export function SimilarityHypothesisBadge({ hypothesis }: { hypothesis: SimilarityHypothesis }) {
  const meta: Record<SimilarityHypothesis, { cls: string; label: string }> = {
    identical: { cls: "badge-critical", label: "IDENTICAL (Exact Match)" },
    renamed_identical: { cls: "badge-critical", label: "RENAMED IDENTICAL" },
    modified_variant: { cls: "badge-high", label: "MODIFIED VARIANT" },
    possible_related_cluster: { cls: "badge-medium", label: "POSSIBLE RELATED CLUSTER" },
    unrelated: { cls: "badge-neutral", label: "UNRELATED" },
  };

  const item = meta[hypothesis] || { cls: "badge-unknown", label: hypothesis.toUpperCase() };

  return (
    <span className={`badge ${item.cls} badge-sm`} aria-label={`Similarity Hypothesis: ${item.label}`}>
      <span className="badge-text">{item.label}</span>
    </span>
  );
}
