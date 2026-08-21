import React, { useMemo, useState } from "react";
import type { AttackTechniqueMapping, CapabilityHypothesis, InvestigationTab, Sample } from "../../types/api";
import { EmptyState, UnavailableState } from "../common/StateViews";

interface AttackMatrixViewProps {
  sample: Sample | null;
  onNavigateTab?: (tab: InvestigationTab) => void;
  onRunThreat?: () => void;
  isRunning?: boolean;
}

export function AttackMatrixView({
  sample,
  onNavigateTab,
  onRunThreat,
  isRunning = false,
}: AttackMatrixViewProps) {
  const [selectedTactic, setSelectedTactic] = useState<string>("ALL");
  const [selectedLevel, setSelectedLevel] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [copiedEvidenceId, setCopiedEvidenceId] = useState<string | null>(null);

  const threat = sample?.threat_assessment;
  const rawTechniques: AttackTechniqueMapping[] = useMemo(
    () => threat?.attack_techniques || threat?.techniques || [],
    [threat]
  );
  const capabilities: CapabilityHypothesis[] = useMemo(
    () => threat?.capabilities || [],
    [threat]
  );

  // Extract all unique tactics
  const tactics = useMemo(() => {
    const set = new Set<string>();
    rawTechniques.forEach((t) => {
      if (t.tactic) {
        t.tactic.split("/").forEach((tac) => set.add(tac.trim()));
      }
    });
    return Array.from(set).sort();
  }, [rawTechniques]);

  // Filter techniques
  const filteredTechniques = useMemo(() => {
    return rawTechniques.filter((t) => {
      // Tactic filter
      if (selectedTactic !== "ALL") {
        const matchesTactic = (t.tactic || "")
          .toLowerCase()
          .includes(selectedTactic.toLowerCase());
        if (!matchesTactic) return false;
      }

      // Observation Level filter
      const level = (t.label || t.classification || "POSSIBLE").toUpperCase();
      if (selectedLevel !== "ALL" && level !== selectedLevel) {
        return false;
      }

      // Search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesId = (t.technique_id || "").toLowerCase().includes(q);
        const matchesName = (t.technique_name || "").toLowerCase().includes(q);
        const matchesTactic = (t.tactic || "").toLowerCase().includes(q);
        const matchesDesc = (t.description || "").toLowerCase().includes(q);
        const matchesWhy = (t.why_igris_mapped || "").toLowerCase().includes(q);
        const matchesHypothesis = (t.hypothesis || "").toLowerCase().includes(q);
        const matchesEvidence = (t.supporting_evidence || []).some(
          (e) =>
            (e.statement || "").toLowerCase().includes(q) ||
            (e.value || "").toLowerCase().includes(q) ||
            (e.evidence_id || "").toLowerCase().includes(q)
        );
        const matchesEvidenceIds = (t.supporting_evidence_ids || t.evidence_ids || []).some((id) =>
          id.toLowerCase().includes(q)
        );

        if (
          !matchesId &&
          !matchesName &&
          !matchesTactic &&
          !matchesDesc &&
          !matchesWhy &&
          !matchesHypothesis &&
          !matchesEvidence &&
          !matchesEvidenceIds
        ) {
          return false;
        }
      }

      return true;
    });
  }, [rawTechniques, selectedTactic, selectedLevel, searchQuery]);

  const handleCopyValue = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedEvidenceId(id);
    setTimeout(() => setCopiedEvidenceId(null), 2000);
  };

  if (!sample) {
    return (
      <EmptyState
        icon="🎯"
        title="No Specimen Selected"
        message="Upload or select a specimen from the top bar to inspect ATT&CK mappings."
      />
    );
  }

  if (!threat) {
    return (
      <UnavailableState
        layerName="Threat Assessment & ATT&CK Mapping"
        description="Behavioral capability inference and MITRE ATT&CK technique mapping have not been executed."
        onRun={onRunThreat}
        running={isRunning}
      />
    );
  }

  // Count telemetry categories
  const observedCount = rawTechniques.filter(
    (t) => (t.label || t.classification || "").toUpperCase() === "OBSERVED"
  ).length;
  const inferredCount = rawTechniques.filter(
    (t) => (t.label || t.classification || "").toUpperCase() === "INFERRED"
  ).length;
  const possibleCount = rawTechniques.filter(
    (t) => (t.label || t.classification || "POSSIBLE").toUpperCase() === "POSSIBLE"
  ).length;

  return (
    <div className="view-container attack-view" role="main" aria-label="MITRE ATT&CK Investigation View">
      {/* Header & Subtitle */}
      <div className="view-header-row">
        <div>
          <h2 className="view-title">MITRE ATT&CK® Evidence-Driven Mapping</h2>
          <p className="view-subtitle">
            Observed specimen evidence correlated to MITRE adversary techniques, analytical reasoning, and epistemological hypotheses.
          </p>
        </div>
      </div>

      {/* KPI Metrics Row */}
      <div className="attack-kpi-grid">
        <div className="attack-kpi-card">
          <span className="kpi-label">Mapped Techniques</span>
          <span className="kpi-value">{rawTechniques.length}</span>
        </div>
        <div className="attack-kpi-card">
          <span className="kpi-label">Direct Telemetry (OBSERVED)</span>
          <span className="kpi-value" style={{ color: "#38bdf8" }}>{observedCount}</span>
        </div>
        <div className="attack-kpi-card">
          <span className="kpi-label">Reasoned Hypotheses (INFERRED)</span>
          <span className="kpi-value" style={{ color: "#a78bfa" }}>{inferredCount}</span>
        </div>
        <div className="attack-kpi-card">
          <span className="kpi-label">Potential Clusters (POSSIBLE)</span>
          <span className="kpi-value" style={{ color: "#818cf8" }}>{possibleCount}</span>
        </div>
        <div className="attack-kpi-card">
          <span className="kpi-label">Tactics Covered</span>
          <span className="kpi-value">{tactics.length}</span>
        </div>
      </div>

      {/* Threat Assessment Narrative */}
      {threat.narrative && (
        <section className="threat-narrative-card">
          <div className="card-header">
            <span className="narrative-icon" aria-hidden="true">🎯</span>
            <h3 className="card-title">Threat Assessment Narrative</h3>
          </div>
          <p className="narrative-body">{threat.narrative}</p>
        </section>
      )}

      {/* Main ATT&CK Investigation Cards Section */}
      <section className="attack-investigation-section">
        <div className="section-header-with-filter">
          <h3 className="subheading">
            Mapped ATT&CK Techniques ({filteredTechniques.length} of {rawTechniques.length})
          </h3>
        </div>

        {/* Filter and Search Toolbar */}
        <div className="attack-filter-toolbar">
          <div className="search-box">
            <span className="search-icon" aria-hidden="true">🔍</span>
            <input
              type="text"
              placeholder="Search by Technique ID, name, tactic, why mapped, or extracted evidence..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="attack-search-input"
              aria-label="Search mapped techniques"
            />
            {searchQuery && (
              <button
                type="button"
                className="clear-search-btn"
                onClick={() => setSearchQuery("")}
                aria-label="Clear search"
              >
                ✕
              </button>
            )}
          </div>

          <div className="filter-group">
            <label htmlFor="tactic-select" className="filter-label">Tactic:</label>
            <select
              id="tactic-select"
              value={selectedTactic}
              onChange={(e) => setSelectedTactic(e.target.value)}
              className="attack-select"
            >
              <option value="ALL">All Tactics ({rawTechniques.length})</option>
              {tactics.map((tac) => (
                <option key={tac} value={tac}>
                  {tac}
                </option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <label htmlFor="level-select" className="filter-label">Epistemology:</label>
            <select
              id="level-select"
              value={selectedLevel}
              onChange={(e) => setSelectedLevel(e.target.value)}
              className="attack-select"
            >
              <option value="ALL">All Levels ({rawTechniques.length})</option>
              <option value="OBSERVED">Directly Observed ({observedCount})</option>
              <option value="INFERRED">Inferred Hypotheses ({inferredCount})</option>
              <option value="POSSIBLE">Possible Relationships ({possibleCount})</option>
            </select>
          </div>
        </div>

        {/* Zero Results State */}
        {rawTechniques.length === 0 ? (
          <div className="attack-empty-card" role="region" aria-label="No ATT&CK Techniques Mapped">
            <span className="empty-icon" aria-hidden="true">🛡️</span>
            <h4>No ATT&CK Techniques Mapped</h4>
            <p className="empty-msg">
              No ATT&CK techniques were mapped for this specimen. IGRIS did not identify sufficient evidence to associate this specimen with a known ATT&CK technique.
            </p>
            <span className="empty-subtext">
              All analysis layers executed normally, but no static strings, imported APIs, or behavior signatures met the threshold for adversary capability mapping.
            </span>
          </div>
        ) : filteredTechniques.length === 0 ? (
          <div className="attack-no-match-card">
            <span className="no-match-icon" aria-hidden="true">🔎</span>
            <p>No ATT&CK techniques match the selected filters or search query.</p>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => {
                setSelectedTactic("ALL");
                setSelectedLevel("ALL");
                setSearchQuery("");
              }}
            >
              Reset Filters
            </button>
          </div>
        ) : (
          /* List of Structured Investigation Cards */
          <div className="attack-cards-list">
            {filteredTechniques.map((technique) => {
              const level = (technique.label || technique.classification || "POSSIBLE").toUpperCase();
              const levelBadgeClass =
                level === "OBSERVED"
                  ? "badge-observed"
                  : level === "INFERRED"
                  ? "badge-inferred"
                  : "badge-possible";

              const evidenceItems = technique.supporting_evidence || [];
              const fallbackEvidenceIds = technique.supporting_evidence_ids || technique.evidence_ids || [];

              return (
                <article
                  key={technique.technique_id}
                  className="attack-investigation-card"
                  aria-labelledby={`technique-title-${technique.technique_id}`}
                >
                  {/* Card Top Header */}
                  <header className="attack-card-header">
                    <div className="attack-title-group">
                      <div className="attack-id-row">
                        <a
                          href={`https://attack.mitre.org/techniques/${technique.technique_id.replace(".", "/")}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="attack-link-code"
                          title={`View MITRE ATT&CK definition for ${technique.technique_id}`}
                        >
                          <code>{technique.technique_id} ↗</code>
                        </a>
                        <span className="badge badge-tactic">{technique.tactic || "Unknown Tactic"}</span>
                        <span className={`badge ${levelBadgeClass}`}>{level}</span>
                      </div>
                      <h4 id={`technique-title-${technique.technique_id}`} className="attack-technique-title">
                        {technique.technique_name}
                      </h4>
                      {technique.subtechnique_id && technique.subtechnique_name && (
                        <div className="attack-subtechnique-banner">
                          <span className="subtechnique-label">Sub-technique:</span>{" "}
                          <code>{technique.subtechnique_id}</code> — <strong>{technique.subtechnique_name}</strong>
                        </div>
                      )}
                    </div>

                    <div className="attack-card-confidence">
                      <span className="confidence-label">Mapping Confidence</span>
                      <span className="confidence-value">{Math.round((technique.confidence || 0) * 100)}%</span>
                      <div className="confidence-meter-bg">
                        <div
                          className="confidence-meter-fill"
                          style={{ width: `${Math.round((technique.confidence || 0) * 100)}%` }}
                        />
                      </div>
                    </div>
                  </header>

                  {/* Card Content Grid */}
                  <div className="attack-card-body">
                    {/* Description Block */}
                    {technique.description && (
                      <div className="attack-info-block">
                        <h5 className="block-title">Technique Overview</h5>
                        <p className="block-text">{technique.description}</p>
                      </div>
                    )}

                    {/* How It Works Block */}
                    {technique.how_it_works && (
                      <div className="attack-info-block attack-how-it-works-box">
                        <h5 className="block-title">
                          <span className="block-icon" aria-hidden="true">⚙️</span> How Adversaries Use This
                        </h5>
                        <p className="block-text">{technique.how_it_works}</p>
                      </div>
                    )}

                    {/* Why IGRIS Mapped This Block */}
                    <div className="attack-info-block attack-why-mapped-box">
                      <h5 className="block-title">
                        <span className="block-icon" aria-hidden="true">🔬</span> Why IGRIS Mapped This
                      </h5>
                      <p className="block-text">
                        {technique.why_igris_mapped || technique.explanation || "Mapped from observed telemetry matching technique heuristics."}
                      </p>

                      {/* Supporting Evidence Breakdown */}
                      <div className="supporting-evidence-wrapper">
                        <div className="evidence-header-row">
                          <span className="evidence-heading">
                            Observed Supporting Evidence ({evidenceItems.length > 0 ? evidenceItems.length : fallbackEvidenceIds.length})
                          </span>
                          {onNavigateTab && (
                            <button
                              type="button"
                              className="btn btn-text-link"
                              onClick={() => onNavigateTab("evidence")}
                              title="Jump to Evidence Explorer tab"
                            >
                              Open in Evidence Explorer ›
                            </button>
                          )}
                        </div>

                        {evidenceItems.length > 0 ? (
                          <div className="evidence-items-table-wrapper">
                            <table className="evidence-items-table">
                              <thead>
                                <tr>
                                  <th>Origin</th>
                                  <th>Type</th>
                                  <th>Evidence Statement</th>
                                  <th>Extracted Concrete Value</th>
                                  <th>Level</th>
                                </tr>
                              </thead>
                              <tbody>
                                {evidenceItems.map((item, idx) => (
                                  <tr key={item.evidence_id || idx}>
                                    <td>
                                      <span className="badge badge-category badge-xs">
                                        {item.category || item.source || "static"}
                                      </span>
                                    </td>
                                    <td>
                                      <code className="evidence-type-code">{item.evidence_type}</code>
                                    </td>
                                    <td className="evidence-statement-cell">
                                      {item.statement}
                                    </td>
                                    <td className="evidence-value-cell">
                                      {item.value ? (
                                        <div className="copyable-value-container">
                                          <code className="extracted-value-code">{item.value}</code>
                                          <button
                                            type="button"
                                            className="btn-copy-sm"
                                            onClick={() => handleCopyValue(item.value || "", item.evidence_id || `${idx}`)}
                                            title="Copy extracted value"
                                            aria-label="Copy extracted value"
                                          >
                                            {copiedEvidenceId === (item.evidence_id || `${idx}`) ? "✓" : "📋"}
                                          </button>
                                        </div>
                                      ) : (
                                        <span className="subdued-text">—</span>
                                      )}
                                    </td>
                                    <td>
                                      <span className={`badge badge-xs ${
                                        item.observation_level === "OBSERVED"
                                          ? "badge-observed"
                                          : item.observation_level === "INFERRED"
                                          ? "badge-inferred"
                                          : "badge-possible"
                                      }`}>
                                        {item.observation_level || "OBSERVED"}
                                      </span>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : fallbackEvidenceIds.length > 0 ? (
                          <div className="evidence-chips-container">
                            {fallbackEvidenceIds.map((id) => (
                              <button
                                key={id}
                                type="button"
                                className="ev-chip-interactive"
                                onClick={() => onNavigateTab?.("evidence")}
                                title="Click to view in Evidence Explorer"
                              >
                                <code>{id}</code>
                              </button>
                            ))}
                          </div>
                        ) : (
                          <p className="subdued-text">No technical evidence items recorded.</p>
                        )}
                      </div>
                    </div>

                    {/* Analyst Hypothesis Block */}
                    {technique.hypothesis && (
                      <div className={`attack-hypothesis-callout ${levelBadgeClass}-callout`}>
                        <div className="hypothesis-header">
                          <span className="hypothesis-icon" aria-hidden="true">💡</span>
                          <span className="hypothesis-title">Analyst Hypothesis ({level})</span>
                        </div>
                        <p className="hypothesis-statement">{technique.hypothesis}</p>
                      </div>
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>

      {/* Inferred Capabilities Section */}
      {capabilities.length > 0 && (
        <section className="capabilities-section">
          <h3 className="subheading">Inferred Capability Hypotheses ({capabilities.length})</h3>
          <div className="capabilities-grid">
            {capabilities.map((cap) => {
              const capLevel = (cap.label || "INFERRED").toUpperCase();
              const capBadgeClass =
                capLevel === "OBSERVED"
                  ? "badge-observed"
                  : capLevel === "INFERRED"
                  ? "badge-inferred"
                  : "badge-possible";

              return (
                <div key={cap.capability_id} className="capability-card">
                  <div className="capability-card-header">
                    <div className="cap-title-row">
                      <span className={`badge ${capBadgeClass}`}>{capLevel}</span>
                      <h4 className="capability-title">{cap.name || cap.category || cap.capability_id}</h4>
                    </div>
                    <span className="cap-confidence">{Math.round((cap.confidence || 0) * 100)}%</span>
                  </div>
                  <p className="capability-desc">{cap.description || cap.explanation || "Inferred capability from sample telemetry."}</p>
                  {(cap.supporting_evidence_ids || cap.evidence_ids || []).length > 0 && (
                    <div className="capability-evidence-row">
                      <span className="cap-evidence-label">Evidence IDs:</span>
                      <div className="cap-evidence-chips">
                        {(cap.supporting_evidence_ids || cap.evidence_ids || []).map((id) => (
                          <code key={id} className="ev-chip-sm">{id}</code>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
}

