import React, { useState } from "react";
import type { Sample, SimilarityMatch } from "../../types/api";
import { ConfidenceBadge, SimilarityHypothesisBadge } from "../common/Badge";
import { Column, CopyButton, DataTable } from "../common/DataTable";
import { EmptyState, UnavailableState } from "../common/StateViews";

interface SimilarityViewProps {
  sample: Sample | null;
  onRunSimilarity?: () => void;
  isRunning?: boolean;
}

export function SimilarityView({
  sample,
  onRunSimilarity,
  isRunning = false,
}: SimilarityViewProps) {
  const [selectedMatch, setSelectedMatch] = useState<SimilarityMatch | null>(null);

  if (!sample) {
    return <EmptyState icon="🧬" title="No Specimen Selected" message="Upload or select a specimen from the top bar to inspect similarity cluster analysis." />;
  }

  const similarity = sample.similarity_analysis;
  if (!similarity) {
    return (
      <UnavailableState
        layerName="Sample Similarity Analysis (Phase 10)"
        description="Candidate indexing, feature hashing, and multi-category similarity scoring have not been executed."
        onRun={onRunSimilarity}
        running={isRunning}
      />
    );
  }

  const matches = similarity.matches || [];

  const columns: Column<SimilarityMatch>[] = [
    {
      id: "candidate",
      header: "Candidate Sample",
      accessor: (m) => m.target_filename,
      render: (m) => (
        <div className="candidate-name-cell">
          <strong>{m.target_filename}</strong>
          <code className="candidate-sha">{m.target_sha256.slice(0, 16)}…</code>
        </div>
      ),
      width: "240px",
    },
    {
      id: "similarity",
      header: "Overall Similarity",
      accessor: (m) => m.overall_similarity,
      render: (m) => {
        const pct = Math.round(m.overall_similarity * 100);
        return (
          <div className="similarity-meter-cell">
            <div className="sim-bar-track">
              <div
                className={`sim-bar-fill ${pct >= 85 ? "fill-critical" : pct >= 60 ? "fill-high" : "fill-medium"}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <strong>{pct}%</strong>
          </div>
        );
      },
      width: "180px",
    },
    {
      id: "hypothesis",
      header: "Hypothesis",
      accessor: (m) => m.hypothesis,
      render: (m) => <SimilarityHypothesisBadge hypothesis={m.hypothesis} />,
      width: "220px",
    },
    {
      id: "confidence",
      header: "Confidence",
      accessor: (m) => m.confidence || "LOW",
      render: (m) => <ConfidenceBadge label="Match" level={(m.confidence || "LOW").toUpperCase() as "HIGH"} />,
      width: "140px",
      align: "center",
    },
    {
      id: "actions",
      header: "Inspect",
      render: (m) => (
        <button
          type="button"
          className="btn btn-xs btn-outline"
          onClick={(e) => {
            e.stopPropagation();
            setSelectedMatch(m);
          }}
        >
          Details ›
        </button>
      ),
      width: "90px",
      align: "right",
    },
  ];

  return (
    <div className="view-container similarity-view" role="main" aria-label="Sample Similarity Analysis">
      <div className="view-header-row">
        <div>
          <h2 className="view-title">Sample Similarity Analysis (Phase 10)</h2>
          <p className="view-subtitle">
            Multi-category technical feature comparison, clustering hypotheses, and structural overlap metrics.
          </p>
        </div>
        <div className="candidates-counter-badge">
          Candidates Evaluated: <strong>{similarity.total_candidates_evaluated.toLocaleString()}</strong>
        </div>
      </div>

      {/* Critical Attribution Safety Banner */}
      <div className="attribution-guardrail-banner" role="alert">
        <div className="banner-title-row">
          <span className="banner-icon" aria-hidden="true">🔒</span>
          <strong>STRICT ATTRIBUTION SAFETY GUARDRAIL:</strong>
        </div>
        <p className="banner-text">
          Similarity indicates technical feature and structural overlap. It <strong>NEVER</strong> establishes confirmed malware family, threat actor, or campaign attribution. All matched candidates represent a <em>possible related cluster hypothesis</em> only.
        </p>
      </div>

      {/* Summary Narrative */}
      <section className="similarity-summary-card">
        <h3 className="card-title">Clustering Summary</h3>
        <p>{similarity.summary || "No similarity matches exceeded the candidate clustering threshold."}</p>
      </section>

      {/* Matches Table */}
      <DataTable
        columns={columns}
        data={matches}
        keyExtractor={(m) => m.target_sample_id}
        searchPlaceholder="Filter candidate samples by name or SHA-256..."
        onRowClick={(m) => setSelectedMatch(m)}
        selectedRowKey={selectedMatch?.target_sample_id}
        caption="Matched similarity candidates and cluster hypotheses"
      />

      {/* Selected Match Detail Drawer */}
      {selectedMatch && (
        <section className="similarity-match-inspector" aria-labelledby="match-inspector-heading">
          <div className="inspector-header">
            <div>
              <span className="section-eyebrow">CANDIDATE CLUSTER MATCH</span>
              <h3 id="match-inspector-heading" className="match-title">
                {selectedMatch.target_filename}
              </h3>
            </div>
            <button
              type="button"
              className="inspector-close-btn"
              onClick={() => setSelectedMatch(null)}
              aria-label="Close match inspector"
            >
              ✕
            </button>
          </div>

          <div className="match-meta-grid">
            <div>
              <span className="meta-label">Candidate SHA-256</span>
              <div className="hash-copy-cell">
                <code>{selectedMatch.target_sha256}</code>
                <CopyButton text={selectedMatch.target_sha256} label="Target SHA-256" />
              </div>
            </div>
            <div>
              <span className="meta-label">Clustering Hypothesis</span>
              <SimilarityHypothesisBadge hypothesis={selectedMatch.hypothesis} />
            </div>
            <div>
              <span className="meta-label">Overall Similarity</span>
              <strong className="sim-pct">{Math.round(selectedMatch.overall_similarity * 100)}%</strong>
            </div>
          </div>

          {/* Category Scores Breakdown */}
          <div className="category-scores-section">
            <h4 className="subheading">Feature Category Breakdown</h4>
            <div className="category-scores-grid">
              {(selectedMatch.category_scores || []).map((cat) => {
                const scorePct = Math.round(cat.score * 100);
                return (
                  <div key={cat.category} className="cat-score-card">
                    <div className="cat-score-header">
                      <span className="cat-name">{cat.category.replace("_", " ").toUpperCase()}</span>
                      <strong className="cat-val">{scorePct}%</strong>
                    </div>
                    <div className="cat-bar-track">
                      <div className="cat-bar-fill" style={{ width: `${scorePct}%` }} />
                    </div>
                    {(cat.contributing_elements || []).length > 0 && (
                      <small className="cat-elements">
                        {cat.contributing_elements.join(" • ")}
                      </small>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Shared Indicators vs Discriminating Differences */}
          <div className="match-diff-grid">
            <div className="diff-col shared-col">
              <h4>Shared Technical Indicators ({(selectedMatch.shared_indicators || []).length})</h4>
              <ul>
                {(selectedMatch.shared_indicators || []).map((ind, idx) => (
                  <li key={idx}>✓ {ind}</li>
                ))}
              </ul>
            </div>

            <div className="diff-col diffs-col">
              <h4>Discriminating Differences ({(selectedMatch.discriminating_differences || []).length})</h4>
              <ul>
                {(selectedMatch.discriminating_differences || []).map((diff, idx) => (
                  <li key={idx}>≠ {diff}</li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
