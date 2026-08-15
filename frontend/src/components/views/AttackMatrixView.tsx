import React, { useMemo, useState } from "react";
import type { AttackTechniqueMapping, CapabilityHypothesis, Sample } from "../../types/api";
import { Column, DataTable } from "../common/DataTable";
import { EmptyState, UnavailableState } from "../common/StateViews";

interface AttackMatrixViewProps {
  sample: Sample | null;
  onRunThreat?: () => void;
  isRunning?: boolean;
}

export function AttackMatrixView({
  sample,
  onRunThreat,
  isRunning = false,
}: AttackMatrixViewProps) {
  const [selectedTactic, setSelectedTactic] = useState<string>("ALL");

  const threat = sample?.threat_assessment;
  const techniques = useMemo(() => threat?.attack_techniques || [], [threat]);
  const capabilities = useMemo(() => threat?.capabilities || [], [threat]);

  // Group by tactic
  const tactics = useMemo(() => {
    const set = new Set<string>();
    techniques.forEach((t) => {
      t.tactic.split("/").forEach((tac) => set.add(tac.trim()));
    });
    return Array.from(set);
  }, [techniques]);

  const filteredTechniques = useMemo(() => {
    if (selectedTactic === "ALL") return techniques;
    return techniques.filter((t) => t.tactic.toLowerCase().includes(selectedTactic.toLowerCase()));
  }, [techniques, selectedTactic]);

  if (!sample) {
    return <EmptyState title="No Sample Selected" message="Select a sample to inspect ATT&CK mappings." />;
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

  const techniqueColumns: Column<AttackTechniqueMapping>[] = [
    {
      id: "id",
      header: "Technique ID",
      accessor: (t) => t.technique_id,
      render: (t) => (
        <a
          href={`https://attack.mitre.org/techniques/${t.technique_id.replace(".", "/")}`}
          target="_blank"
          rel="noopener noreferrer"
          className="attack-link"
          onClick={(e) => e.stopPropagation()}
        >
          <code>{t.technique_id} ↗</code>
        </a>
      ),
      width: "140px",
    },
    {
      id: "name",
      header: "Technique Name",
      accessor: (t) => t.technique_name,
      render: (t) => <strong>{t.technique_name}</strong>,
      width: "220px",
    },
    {
      id: "tactic",
      header: "ATT&CK Tactic",
      accessor: (t) => t.tactic,
      render: (t) => (
        <span className="badge badge-category badge-sm">{t.tactic}</span>
      ),
    },
    {
      id: "confidence",
      header: "Confidence",
      accessor: (t) => t.confidence,
      render: (t) => `${Math.round(t.confidence * 100)}%`,
      width: "100px",
      align: "center",
    },
    {
      id: "evidence",
      header: "Supporting Evidence IDs",
      accessor: (t) => t.supporting_evidence_ids.join(", "),
      render: (t) => (
        <div className="ev-chips-row">
          {t.supporting_evidence_ids.map((id) => (
            <code key={id} className="ev-chip-sm">{id}</code>
          ))}
          {t.supporting_evidence_ids.length === 0 && <span className="subdued-text">—</span>}
        </div>
      ),
    },
  ];

  const capabilityColumns: Column<CapabilityHypothesis>[] = [
    {
      id: "name",
      header: "Inferred Capability",
      accessor: (c) => c.name,
      render: (c) => <strong>{c.name}</strong>,
      width: "220px",
    },
    {
      id: "desc",
      header: "Hypothesis Description",
      accessor: (c) => c.description,
    },
    {
      id: "confidence",
      header: "Confidence",
      accessor: (c) => c.confidence,
      render: (c) => `${Math.round(c.confidence * 100)}%`,
      width: "110px",
      align: "center",
    },
  ];

  return (
    <div className="view-container attack-view" role="main" aria-label="MITRE ATT&CK Matrix View">
      <div className="view-header-row">
        <div>
          <h2 className="view-title">MITRE ATT&CK® Technique Mappings</h2>
          <p className="view-subtitle">
            Correlated behavioral telemetry mapped to adversary tactics, techniques, and capability hypotheses.
          </p>
        </div>
      </div>

      {/* Threat Narrative */}
      {threat.narrative && (
        <section className="threat-narrative-card">
          <div className="card-header">
            <span className="narrative-icon" aria-hidden="true">🎯</span>
            <h3 className="card-title">Threat Assessment Narrative</h3>
          </div>
          <p className="narrative-body">{threat.narrative}</p>
        </section>
      )}

      {/* Inferred Capabilities */}
      <section className="capabilities-section">
        <h3 className="subheading">Inferred Capability Hypotheses ({capabilities.length})</h3>
        <DataTable
          columns={capabilityColumns}
          data={capabilities}
          keyExtractor={(c) => c.capability_id}
          caption="Inferred behavioral capabilities"
        />
      </section>

      {/* ATT&CK Matrix Filter & Table */}
      <section className="attack-techniques-section">
        <div className="section-header-with-filter">
          <h3 className="subheading">Mapped ATT&CK Techniques ({filteredTechniques.length})</h3>
          <div className="tactic-filter-row">
            <label htmlFor="tactic-select">Filter by Tactic:</label>
            <select
              id="tactic-select"
              value={selectedTactic}
              onChange={(e) => setSelectedTactic(e.target.value)}
            >
              <option value="ALL">All Tactics ({techniques.length})</option>
              {tactics.map((tac) => (
                <option key={tac} value={tac}>
                  {tac}
                </option>
              ))}
            </select>
          </div>
        </div>

        <DataTable
          columns={techniqueColumns}
          data={filteredTechniques}
          keyExtractor={(t) => t.technique_id}
          searchPlaceholder="Search technique IDs, names, or tactics..."
          caption="MITRE ATT&CK mapped techniques"
        />
      </section>
    </div>
  );
}
