import React from "react";
import type { Sample } from "../../types/api";
import { EmptyState, UnavailableState } from "../common/StateViews";

interface MLClassifierViewProps {
  sample: Sample | null;
  onRunML?: () => void;
  isRunning?: boolean;
}

export function MLClassifierView({
  sample,
  onRunML,
  isRunning = false,
}: MLClassifierViewProps) {
  if (!sample) {
    return <EmptyState icon="🤖" title="No Specimen Selected" message="Upload or select a specimen from the top bar to inspect ML classifier predictions." />;
  }

  const ml = sample.ml_prediction;
  if (!ml) {
    return (
      <UnavailableState
        layerName="Machine Learning Classifier"
        description="Statistical Random Forest inference on static and reverse features has not been executed."
        onRun={onRunML}
        running={isRunning}
      />
    );
  }

  const scorePct = Math.round((ml.score ?? 0) * 100);
  const isMalware = ml.prediction === "malware";

  return (
    <div className="view-container ml-classifier-view" role="main" aria-label="Machine Learning Classifier">
      <div className="view-header-row">
        <div>
          <h2 className="view-title">Machine Learning Classification</h2>
          <p className="view-subtitle">
            Statistical Random Forest inference, calibrated prediction scores, and top contributing feature rankings.
          </p>
        </div>
        <div className="model-version-tag">
          Model: <code>{ml.model_version || "default"}</code> (Schema: <code>{ml.feature_schema_version || "v1"}</code>)
        </div>
      </div>

      {/* Model Prediction Hero Card */}
      <section className="ml-hero-card">
        <div className="ml-prediction-badge-col">
          <span className="section-eyebrow">STATISTICAL PREDICTION</span>
          <div className="prediction-tag-row">
            <span
              className={`badge badge-lg ${isMalware ? "badge-critical" : "badge-success"}`}
              role="status"
            >
              {isMalware ? "⛔ MALWARE" : "✅ BENIGN"}
            </span>
            <span className="badge badge-neutral badge-sm">
              Uncertainty: {(ml.uncertainty || "unknown").toUpperCase()}
            </span>
          </div>

          <div className="ml-score-box">
            <div className="ml-score-number">
              <span className="score-big">{scorePct}%</span>
              <span className="score-label">Malware Likelihood Score</span>
            </div>
            <div className="ml-meter-track">
              <div
                className={`ml-meter-fill ${scorePct >= 70 ? "fill-critical" : scorePct >= 40 ? "fill-medium" : "fill-success"}`}
                style={{ width: `${scorePct}%` }}
              />
            </div>
          </div>
        </div>

        <div className="ml-explanation-col">
          <h3 className="subheading">Model Explanation</h3>
          <p className="ml-explanation-text">{ml.explanation || "No explanation provided."}</p>
        </div>
      </section>

      {/* Feature Importance Table */}
      <section className="dashboard-card" aria-labelledby="features-heading">
        <h3 id="features-heading" className="card-title">
          Top Contributing Features & Feature Importance
        </h3>
        <p className="subdued-text small">
          Ranked by absolute contribution weight to the final classification decision tree ensemble.
        </p>

        <div className="features-ranking-table">
          <table className="analyst-table">
            <thead>
              <tr>
                <th>Rank</th>
                <th>Feature Name</th>
                <th>Importance Weight</th>
                <th>Relative Contribution</th>
              </tr>
            </thead>
            <tbody>
              {(ml.important_contributing_features || []).map(([featureName, weight], idx) => {
                const weightPct = Math.round((weight ?? 0) * 100);
                return (
                  <tr key={featureName}>
                    <td style={{ width: "60px", textAlign: "center" }}>#{idx + 1}</td>
                    <td>
                      <code>{featureName}</code>
                    </td>
                    <td style={{ width: "160px" }}>
                      <strong>{((weight ?? 0) * 100).toFixed(1)}%</strong>
                    </td>
                    <td style={{ width: "240px" }}>
                      <div className="feature-bar-track">
                        <div
                          className="feature-bar-fill"
                          style={{ width: `${Math.min(100, weightPct * 2.5)}%` }}
                        />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* Model Limitations Card */}
      <section className="limitations-card" aria-labelledby="ml-limitations-heading">
        <h3 id="ml-limitations-heading" className="card-title">
          Machine Learning Safety Constraints & Boundaries
        </h3>
        <ul className="limitations-list">
          {(ml.limitations || []).map((lim, idx) => (
            <li key={idx} className="limitation-item">
              <span className="lim-icon" aria-hidden="true">🔒</span>
              <span>{lim}</span>
            </li>
          ))}
          <li className="limitation-item">
            <span className="lim-icon" aria-hidden="true">🔒</span>
            <span>
              Statistical ML prediction is an inferred analytical signal and NEVER overrides contradictory physical observations.
            </span>
          </li>
        </ul>
      </section>
    </div>
  );
}
