import React, { useState } from "react";
import type { Sample } from "../../types/api";
import {
  CategoryBadge,
  EvidenceRoleBadge,
  ObservationLevelBadge,
  RiskLevelBadge,
  VerdictBadge,
} from "../common/Badge";
import { EmptyState } from "../common/StateViews";

interface InvestigationReportViewProps {
  sample: Sample | null;
}

export function InvestigationReportView({ sample }: InvestigationReportViewProps) {
  const [copySuccess, setCopySuccess] = useState(false);

  if (!sample) {
    return <EmptyState icon="📝" title="No Specimen Selected" message="Upload or select a specimen from the top bar to view its full investigation report." />;
  }

  const assessment = sample.malware_assessment;
  const verdict = assessment?.verdict || "UNKNOWN";
  const riskLevel = assessment?.risk_level || "UNKNOWN";
  const riskScore = assessment?.risk_score?.score ?? 0;
  const confidence = assessment?.confidence;
  const explanation = assessment?.explanation;
  const evidenceSummary = assessment?.evidence_summary;

  const handlePrint = () => {
    window.print();
  };

  const handleCopyReportMarkdown = () => {
    const reportMd = `
# IGRIS MALWARE ASSESSMENT REPORT

**Sample:** ${sample.original_filename || sample.safe_filename || sample.sample_id}
**SHA-256:** ${sample.hashes?.sha256 || "N/A"}
**Assessment Verdict:** ${verdict} (Risk Level: ${riskLevel}, Evidence Risk Score: ${riskScore}/100)
**Generated:** ${assessment?.created_at || new Date().toISOString()}

---

## 1. Executive Summary
${explanation?.summary || "No assessment generated."}

## 2. File Identification
- **Original Filename:** ${sample.original_filename || sample.safe_filename || sample.sample_id}
- **Safe Filename:** ${sample.safe_filename || "N/A"}
- **Size:** ${sample.size_bytes || 0} bytes (${((sample.size_bytes || 0) / 1024).toFixed(1)} KB)
- **SHA-256:** ${sample.hashes?.sha256 || "N/A"}
- **SHA-1:** ${sample.hashes?.sha1 || "N/A"}
- **MD5:** ${sample.hashes?.md5 || "N/A"}
- **File Format:** ${sample.file_metadata?.file_format || "Unknown"} (${sample.file_metadata?.architecture || "x86_64"})

## 3. Confidence Metrics
- **Detection Confidence:** ${confidence?.detection_confidence || "UNAVAILABLE"}
- **Evidence Quality:** ${confidence?.evidence_quality || "UNAVAILABLE"}
- **Behavioral Telemetry:** ${confidence?.behavioral_confidence || "UNAVAILABLE"}
- **Similarity Confidence:** ${confidence?.similarity_confidence || "UNAVAILABLE"}
- **Attribution Scope:** ${confidence?.attribution_scope || "cluster_only"}

## 4. Epistemological Findings
### Observed Facts
${(explanation?.observed_findings || []).map((f) => `- [OBSERVED] ${f}`).join("\n") || "- None"}

### Inferred Deductions
${(explanation?.inferred_findings || []).map((f) => `- [INFERRED] ${f}`).join("\n") || "- None"}

### Possible Hypotheses
${(explanation?.possible_hypotheses || []).map((f) => `- [POSSIBLE] ${f}`).join("\n") || "- None"}

## 5. Traceable Evidence Items (${(evidenceSummary?.evidence_items || []).length})
${(evidenceSummary?.evidence_items || []).map((e) => `- [${e.category}] [${e.observation_level}] [${e.role}] ${e.statement} (Provenance: ${e.provenance})`).join("\n") || "- None"}

## 6. Analytical Limitations & Attribution Guardrails
${(assessment?.limitations || []).map((l) => `- ${l}`).join("\n") || "- None"}
    `.trim();

    navigator.clipboard.writeText(reportMd);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  return (
    <div className="view-container report-view" role="main" aria-label="Investigation Report">
      {/* Report Action Toolbar */}
      <div className="report-toolbar no-print">
        <div className="report-toolbar-info">
          <h2 className="view-title">Formal Investigation Report</h2>
          <p className="view-subtitle">Consolidated, evidence-backed malware intelligence dossier.</p>
        </div>
        <div className="report-actions" style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          <a
            href={`/api/v1/samples/${encodeURIComponent(sample.sample_id)}/report/json`}
            download={`igris-report-${sample.sample_id}.json`}
            className="btn btn-secondary"
            title="Download machine-readable JSON dossier"
          >
            📦 Download JSON
          </a>
          <a
            href={`/api/v1/samples/${encodeURIComponent(sample.sample_id)}/report/pdf`}
            download={`igris-report-${sample.sample_id}.pdf`}
            className="btn btn-secondary"
            title="Download multi-page sanitized PDF dossier"
          >
            📄 Download PDF
          </a>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleCopyReportMarkdown}
          >
            {copySuccess ? "✓ Copied Markdown" : "📋 Copy Markdown"}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handlePrint}
          >
            🖨 Print / Export
          </button>
        </div>
      </div>

      {/* Printable Report Document Sheet */}
      <article className="report-document-sheet" aria-label="Assessment Dossier Document">
        {/* Document Header */}
        <header className="report-doc-header">
          <div className="report-brand">
            <span className="brand-logo-print">IGRIS</span>
            <div>
              <h1 className="report-doc-title">Malware Assessment Dossier</h1>
              <span className="report-meta-line">
                Confidential Security Intelligence Report • Generated: {assessment?.created_at || "N/A"}
              </span>
            </div>
          </div>

          <div className="report-verdict-stamp">
            <VerdictBadge verdict={verdict} size="lg" />
            <RiskLevelBadge level={riskLevel} size="lg" />
          </div>
        </header>

        {/* Section 1: Executive Summary */}
        <section className="report-section">
          <h2 className="report-section-title">1. Executive Summary & Assessment</h2>
          <p className="report-narrative-text">
            {explanation?.summary || "No executive summary available for this sample."}
          </p>

          <div className="report-kpi-summary-row">
            <div className="report-kpi-box">
              <span className="kpi-label">EVIDENCE RISK SCORE</span>
              <strong className="kpi-score">{riskScore} / 100</strong>
            </div>
            <div className="report-kpi-box">
              <span className="kpi-label">SUPPORTING EVIDENCE</span>
              <strong className="kpi-supporting">+{evidenceSummary?.supporting_count || 0}</strong>
            </div>
            <div className="report-kpi-box">
              <span className="kpi-label">CONTRADICTING FINDINGS</span>
              <strong className="kpi-contradicting">-{evidenceSummary?.contradicting_count || 0}</strong>
            </div>
            <div className="report-kpi-box">
              <span className="kpi-label">ATTRIBUTION SCOPE</span>
              <strong className="kpi-scope">CLUSTER ONLY</strong>
            </div>
          </div>
        </section>

        {/* Section 2: Sample Identification */}
        <section className="report-section">
          <h2 className="report-section-title">2. Sample Artifact Identification</h2>
          <table className="report-meta-table">
            <tbody>
              <tr>
                <th>Original Filename</th>
                <td><code>{sample.original_filename || sample.safe_filename || sample.sample_id}</code></td>
                <th>Safe Storage Ref</th>
                <td><code>{sample.safe_filename || "N/A"}</code></td>
              </tr>
              <tr>
                <th>SHA-256 Hash</th>
                <td colSpan={3}>
                  <code className="break-all">{sample.hashes?.sha256 || "N/A"}</code>
                </td>
              </tr>
              <tr>
                <th>SHA-1 Hash</th>
                <td><code>{sample.hashes?.sha1 || "N/A"}</code></td>
                <th>MD5 Hash</th>
                <td><code>{sample.hashes?.md5 || "N/A"}</code></td>
              </tr>
              <tr>
                <th>File Size</th>
                <td>{(sample.size_bytes || 0).toLocaleString()} bytes ({((sample.size_bytes || 0) / 1024).toFixed(1)} KB)</td>
                <th>Format & Architecture</th>
                <td className="uppercase">{sample.file_metadata?.file_format || "PE"} ({sample.file_metadata?.architecture || "x86_64"})</td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* Section 3: Epistemological Evidence Analysis */}
        <section className="report-section">
          <h2 className="report-section-title">3. Epistemological Findings Breakdown</h2>

          <div className="report-ep-block">
            <h3>3.1 Directly Observed Telemetry Facts ({(explanation?.observed_findings || []).length})</h3>
            <ul className="report-list">
              {(explanation?.observed_findings || []).map((f, i) => (
                <li key={i}>
                  <ObservationLevelBadge level="OBSERVED" /> <span>{f}</span>
                </li>
              ))}
              {(!explanation?.observed_findings || explanation.observed_findings.length === 0) && (
                <li className="subdued-text">Zero raw observations recorded.</li>
              )}
            </ul>
          </div>

          <div className="report-ep-block">
            <h3>3.2 Analytical Inferences & Rule Detections ({(explanation?.inferred_findings || []).length})</h3>
            <ul className="report-list">
              {(explanation?.inferred_findings || []).map((f, i) => (
                <li key={i}>
                  <ObservationLevelBadge level="INFERRED" /> <span>{f}</span>
                </li>
              ))}
              {(!explanation?.inferred_findings || explanation.inferred_findings.length === 0) && (
                <li className="subdued-text">Zero rule inferences recorded.</li>
              )}
            </ul>
          </div>

          <div className="report-ep-block">
            <h3>3.3 Potential Cluster Hypotheses ({(explanation?.possible_hypotheses || []).length})</h3>
            <ul className="report-list">
              {(explanation?.possible_hypotheses || []).map((f, i) => (
                <li key={i}>
                  <ObservationLevelBadge level="POSSIBLE" /> <span>{f}</span>
                </li>
              ))}
              {(!explanation?.possible_hypotheses || explanation.possible_hypotheses.length === 0) && (
                <li className="subdued-text">Zero cluster hypotheses identified.</li>
              )}
            </ul>
          </div>
        </section>

        {/* Section 4: Complete Traceable Evidence Table */}
        <section className="report-section">
          <h2 className="report-section-title">
            4. Multi-Layer Traceable Evidence Matrix ({(evidenceSummary?.evidence_items || []).length})
          </h2>
          <table className="report-evidence-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Level</th>
                <th>Role</th>
                <th>Finding Statement</th>
                <th>Provenance Source</th>
              </tr>
            </thead>
            <tbody>
              {(evidenceSummary?.evidence_items || []).map((e) => (
                <tr key={e.evidence_id}>
                  <td><CategoryBadge category={e.category} /></td>
                  <td><ObservationLevelBadge level={e.observation_level} /></td>
                  <td><EvidenceRoleBadge role={e.role} /></td>
                  <td>
                    <strong>{e.statement}</strong>
                  </td>
                  <td><code>{e.provenance}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* Section 5: Analyst-Authored Notes */}
        <section className="report-section">
          <h2 className="report-section-title">
            5. Analyst-Authored Notes & Curated Bookmarks ({(sample.notes || []).length} notes, {(sample.bookmarks || []).length} bookmarks)
          </h2>
          <div className="report-analyst-notice">
            <small>
              ⚠️ <strong>Human Analyst Input:</strong> The entries below are authored by security analysts and curated separately from automated telemetry and ML inferences.
            </small>
          </div>

          {(sample.notes || []).length > 0 ? (
            <div className="report-notes-list" style={{ marginTop: "12px", display: "flex", flexDirection: "column", gap: "10px" }}>
              {(sample.notes || []).map((note) => (
                <div key={note.note_id} className="report-note-item" style={{ background: "rgba(255, 255, 255, 0.03)", padding: "10px", borderRadius: "4px", borderLeft: "3px solid var(--accent-orange, #f59e0b)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                    <strong>{note.title}</strong>
                    <span style={{ fontSize: "12px", opacity: 0.7 }}>👤 {note.author} • {new Date(note.created_at).toLocaleDateString()}</span>
                  </div>
                  <p style={{ margin: "4px 0 6px 0" }}>{note.content}</p>
                  {(note.attached_evidence_ids || []).length > 0 && (
                    <small style={{ opacity: 0.8 }}>Attached: {(note.attached_evidence_ids || []).join(", ")}</small>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="subdued-text" style={{ marginTop: "8px" }}>Zero analyst notes attached to this sample.</p>
          )}
        </section>

        {/* Section 6: Analytical Limitations */}
        <section className="report-section">
          <h2 className="report-section-title">6. Analytical Guardrails & Boundary Conditions</h2>
          <ul className="report-limitations-list">
            {(assessment?.limitations || []).map((lim, idx) => (
              <li key={idx}>🔒 {lim}</li>
            ))}
          </ul>
        </section>

        <footer className="report-doc-footer">
          <span>IGRIS Explainable Malware Analysis Platform</span>
          <span>Dossier Key: {(sample.hashes?.sha256 || sample.sample_id).slice(0, 16)}</span>
        </footer>
      </article>
    </div>
  );
}
