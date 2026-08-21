import React, { useMemo, useState } from "react";
import type {
  AssessmentEvidenceItem,
  EvidenceCategory,
  InvestigationTab,
  Sample,
} from "../../types/api";
import {
  CategoryBadge,
  EvidenceRoleBadge,
  ObservationLevelBadge,
  StrengthBadge,
} from "../common/Badge";
import { Column, CopyButton, DataTable } from "../common/DataTable";
import { EmptyState, EpistemologyReminder, UnavailableState } from "../common/StateViews";

interface EvidenceExplorerViewProps {
  sample: Sample | null;
  onNavigateTab: (tab: InvestigationTab) => void;
  onRunAssessment?: () => void;
  isRunning?: boolean;
  onBookmarkItem?: (item: AssessmentEvidenceItem) => void;
  onAddNoteForItem?: (item: AssessmentEvidenceItem) => void;
}

export function EvidenceExplorerView({
  sample,
  onNavigateTab,
  onRunAssessment,
  isRunning = false,
  onBookmarkItem,
  onAddNoteForItem,
}: EvidenceExplorerViewProps) {
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");
  const [selectedRole, setSelectedRole] = useState<string>("ALL");
  const [selectedLevel, setSelectedLevel] = useState<string>("ALL");
  const [selectedStrength, setSelectedStrength] = useState<string>("ALL");
  const [selectedItem, setSelectedItem] = useState<AssessmentEvidenceItem | null>(null);

  const assessment = sample?.malware_assessment;
  const allItems = useMemo(() => assessment?.evidence_summary?.evidence_items || [], [assessment]);

  // Filter evidence
  const filteredEvidence = useMemo(() => {
    return allItems.filter((item) => {
      if (selectedCategory !== "ALL" && item.category !== selectedCategory) return false;
      if (selectedRole !== "ALL" && item.role !== selectedRole) return false;
      if (selectedLevel !== "ALL" && item.observation_level !== selectedLevel) return false;
      if (selectedStrength !== "ALL" && item.strength !== selectedStrength) return false;
      return true;
    });
  }, [allItems, selectedCategory, selectedRole, selectedLevel, selectedStrength]);

  if (!sample) {
    return <EmptyState icon="🔎" title="No Specimen Selected" message="Upload or select a specimen from the top bar to explore aggregated evidence." />;
  }

  if (!assessment) {
    return (
      <UnavailableState
        layerName="Evidence Explorer"
        description="Explainable assessment has not synthesized evidence for this sample."
        onRun={onRunAssessment}
        running={isRunning}
      />
    );
  }

  const mapCategoryToTab = (cat: EvidenceCategory): InvestigationTab => {
    switch (cat) {
      case "STATIC":
        return "static";
      case "REVERSE":
        return "reverse";
      case "BEHAVIOR":
        return "behavior";
      case "RULES":
        return "overview";
      case "ML":
        return "ml";
      case "SIMILARITY":
        return "similarity";
      default:
        return "overview";
    }
  };

  const columns: Column<AssessmentEvidenceItem>[] = [
    {
      id: "category",
      header: "Category",
      accessor: (r) => r.category,
      render: (r) => <CategoryBadge category={r.category} />,
      width: "110px",
    },
    {
      id: "level",
      header: "Epistemology",
      accessor: (r) => r.observation_level,
      render: (r) => <ObservationLevelBadge level={r.observation_level} />,
      width: "130px",
    },
    {
      id: "role",
      header: "Role",
      accessor: (r) => r.role,
      render: (r) => <EvidenceRoleBadge role={r.role} />,
      width: "140px",
    },
    {
      id: "statement",
      header: "Evidence Statement & Finding",
      accessor: (r) => r.statement,
      render: (r) => (
        <div className="table-statement-cell">
          <span className="statement-text">{r.statement}</span>
          <div className="statement-meta-row">
            <span className="provenance-tag">Provenance: <code>{r.provenance}</code></span>
            {r.source_id && <span className="source-id-tag">ID: <code>{r.source_id}</code></span>}
          </div>
        </div>
      ),
    },
    {
      id: "strength",
      header: "Strength",
      accessor: (r) => r.strength,
      render: (r) => <StrengthBadge strength={r.strength} />,
      width: "100px",
      align: "center",
    },
    {
      id: "actions",
      header: "Navigate",
      render: (r) => (
        <div className="row-action-btns">
          <button
            type="button"
            className="btn btn-xs btn-outline"
            onClick={(e) => {
              e.stopPropagation();
              onNavigateTab(mapCategoryToTab(r.category));
            }}
            title={`Jump to ${r.category} View`}
          >
            Jump ›
          </button>
        </div>
      ),
      width: "85px",
      align: "right",
    },
  ];

  return (
    <div className="view-container evidence-explorer-view" role="main" aria-label="Evidence Explorer">
      <div className="view-header-row">
        <div>
          <h2 className="view-title">Evidence Explorer & Traceability</h2>
          <p className="view-subtitle">
            Explore, filter, and trace every multi-layer evidence artifact back to its originating analysis engine.
          </p>
        </div>
        <div className="evidence-summary-pills">
          <span className="summary-pill total">
            Total: <strong>{allItems.length}</strong>
          </span>
          <span className="summary-pill supporting">
            Supporting: <strong>{assessment.evidence_summary?.supporting_count ?? 0}</strong>
          </span>
          <span className="summary-pill contradicting">
            Contradicting: <strong>{assessment.evidence_summary?.contradicting_count ?? 0}</strong>
          </span>
          <span className="summary-pill observed">
            Observed: <strong>{assessment.evidence_summary?.observed_count ?? 0}</strong>
          </span>
        </div>
      </div>

      <EpistemologyReminder />

      {/* Filter Control Bar */}
      <div className="evidence-filter-bar">
        <div className="filter-group">
          <label htmlFor="cat-filter">Category:</label>
          <select
            id="cat-filter"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
          >
            <option value="ALL">All Categories ({allItems.length})</option>
            <option value="STATIC">Static Analysis</option>
            <option value="REVERSE">Reverse Engineering</option>
            <option value="BEHAVIOR">Behavioral Sandbox</option>
            <option value="RULES">Detection Rules</option>
            <option value="ML">Machine Learning</option>
            <option value="SIMILARITY">Sample Similarity</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="role-filter">Role:</label>
          <select
            id="role-filter"
            value={selectedRole}
            onChange={(e) => setSelectedRole(e.target.value)}
          >
            <option value="ALL">All Roles</option>
            <option value="SUPPORTING">Supporting (Malware Hypothesis)</option>
            <option value="CONTRADICTING">Contradicting / Mitigating</option>
            <option value="NEUTRAL">Neutral / Informational</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="level-filter">Epistemology:</label>
          <select
            id="level-filter"
            value={selectedLevel}
            onChange={(e) => setSelectedLevel(e.target.value)}
          >
            <option value="ALL">All Levels</option>
            <option value="OBSERVED">Observed (Physical Telemetry)</option>
            <option value="INFERRED">Inferred (Rule Deductions)</option>
            <option value="POSSIBLE">Possible (Cluster Hypotheses)</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="strength-filter">Strength:</label>
          <select
            id="strength-filter"
            value={selectedStrength}
            onChange={(e) => setSelectedStrength(e.target.value)}
          >
            <option value="ALL">All Strengths</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        {(selectedCategory !== "ALL" || selectedRole !== "ALL" || selectedLevel !== "ALL" || selectedStrength !== "ALL") && (
          <button
            type="button"
            className="btn btn-sm btn-outline clear-filters-btn"
            onClick={() => {
              setSelectedCategory("ALL");
              setSelectedRole("ALL");
              setSelectedLevel("ALL");
              setSelectedStrength("ALL");
            }}
          >
            Reset Filters
          </button>
        )}
      </div>

      {/* Main Evidence Table */}
      <DataTable
        columns={columns}
        data={filteredEvidence}
        keyExtractor={(item) => item.evidence_id}
        searchPlaceholder="Search evidence statements, IDs, or provenance..."
        onRowClick={(item) => setSelectedItem(item)}
        selectedRowKey={selectedItem?.evidence_id}
        caption="Multi-layer traceable evidence items"
      />

      {/* Selected Item Detail Inspector Drawer / Modal */}
      {selectedItem && (
        <section className="evidence-detail-inspector" aria-labelledby="inspector-heading">
          <div className="inspector-header">
            <div className="header-tags">
              <CategoryBadge category={selectedItem.category} />
              <ObservationLevelBadge level={selectedItem.observation_level} />
              <EvidenceRoleBadge role={selectedItem.role} />
              <StrengthBadge strength={selectedItem.strength} />
            </div>
            <button
              type="button"
              className="inspector-close-btn"
              onClick={() => setSelectedItem(null)}
              aria-label="Close detail inspector"
            >
              ✕
            </button>
          </div>

          <h3 id="inspector-heading" className="inspector-statement">
            {selectedItem.statement}
          </h3>

          <dl className="inspector-grid">
            <div>
              <dt>Evidence ID</dt>
              <dd>
                <code>{selectedItem.evidence_id}</code>
                <CopyButton text={selectedItem.evidence_id} label="Evidence ID" />
              </dd>
            </div>
            <div>
              <dt>Engine Source</dt>
              <dd><code>{selectedItem.source}</code></dd>
            </div>
            <div>
              <dt>Source ID</dt>
              <dd><code>{selectedItem.source_id || "N/A"}</code></dd>
            </div>
            <div>
              <dt>Provenance</dt>
              <dd><code>{selectedItem.provenance}</code></dd>
            </div>
            <div>
              <dt>Evidence Type</dt>
              <dd><code>{selectedItem.evidence_type}</code></dd>
            </div>
            <div>
              <dt>Evidence Weight</dt>
              <dd>{selectedItem.weight.toFixed(2)}</dd>
            </div>
          </dl>

          {Object.keys(selectedItem.technical_details).length > 0 && (
            <div className="inspector-json-block">
              <h4>Technical Details</h4>
              <pre className="code-block">
                {JSON.stringify(selectedItem.technical_details, null, 2)}
              </pre>
            </div>
          )}

          {(selectedItem.limitations || []).length > 0 && (
            <div className="inspector-limitations">
              <h4>Specific Analytical Limitations</h4>
              <ul>
                {(selectedItem.limitations || []).map((lim, idx) => (
                  <li key={idx}>🔒 {lim}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="inspector-footer" style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            {onBookmarkItem && (
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => onBookmarkItem(selectedItem)}
              >
                🔖 Bookmark Finding
              </button>
            )}
            {onAddNoteForItem && (
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => onAddNoteForItem(selectedItem)}
              >
                📝 Add Analyst Note
              </button>
            )}
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onNavigateTab(mapCategoryToTab(selectedItem.category))}
            >
              Jump to {selectedItem.category} Analysis Engine View ›
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
