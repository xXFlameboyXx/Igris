import React from "react";
import { SYNTHETIC_DEMO_TAG } from "../../services/syntheticDemoData";

export function LoadingState({ message = "Loading analysis data..." }: { message?: string }) {
  return (
    <div className="state-view loading-state" role="status" aria-live="polite">
      <div className="spinner" aria-hidden="true" />
      <p className="state-message">{message}</p>
    </div>
  );
}

export function UnavailableState({
  layerName,
  description,
  onRun,
  running = false,
}: {
  layerName: string;
  description?: string;
  onRun?: () => void;
  running?: boolean;
}) {
  return (
    <div className="state-view unavailable-state" role="region" aria-label={`${layerName} unavailable`}>
      <div className="state-icon" aria-hidden="true">⏳</div>
      <h3>{layerName} Has Not Been Executed</h3>
      <p className="state-desc">
        {description || `${layerName} telemetry has not been collected or executed for this sample.`}
      </p>
      <div className="state-note" role="note">
        <strong>Important:</strong> Missing or unexecuted analysis is treated as an unknown factor, <em>never</em> as benign proof.
      </div>
      {onRun && (
        <button
          type="button"
          className="btn btn-primary run-btn"
          onClick={onRun}
          disabled={running}
          aria-busy={running}
        >
          {running ? "Executing Analysis..." : `Run ${layerName}`}
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  title = "No Data Available",
  message = "No records matching the current filter criteria were found.",
  icon = "📭",
}: {
  title?: string;
  message?: string;
  icon?: string;
}) {
  return (
    <div className="state-view empty-state" role="status">
      <div className="state-icon" aria-hidden="true">{icon}</div>
      <h3>{title}</h3>
      <p className="state-desc">{message}</p>
    </div>
  );
}

export function ErrorState({
  title = "Analysis Query Failed",
  error,
  onRetry,
}: {
  title?: string;
  error?: string | Error;
  onRetry?: () => void;
}) {
  const errMsg = error instanceof Error ? error.message : String(error || "An unexpected error occurred.");

  return (
    <div className="state-view error-state" role="alert">
      <div className="state-icon" aria-hidden="true">⚠️</div>
      <h3>{title}</h3>
      <p className="error-text">{errMsg}</p>
      {onRetry && (
        <button type="button" className="btn btn-secondary" onClick={onRetry}>
          Retry Request
        </button>
      )}
    </div>
  );
}

export function SyntheticBanner() {
  return (
    <div className="synthetic-banner" role="banner" aria-label="Demonstration mode indicator">
      <span className="banner-icon" aria-hidden="true">🔬</span>
      <span className="banner-text">
        <strong>{SYNTHETIC_DEMO_TAG}:</strong> Displaying preloaded synthetic telemetry for offline capability validation and UI testing. Not real malware data.
      </span>
    </div>
  );
}

export function EpistemologyReminder() {
  return (
    <div className="epistemology-bar" role="complementary" aria-label="Evidence Epistemology Guide">
      <span className="ep-item"><span className="tag tag-obs">[OBSERVED]</span> Physical artifact/telemetry facts</span>
      <span className="ep-item"><span className="tag tag-inf">[INFERRED]</span> Analytical deductions/rule matches</span>
      <span className="ep-item"><span className="tag tag-pos">[POSSIBLE]</span> Cluster hypotheses without attribution proof</span>
    </div>
  );
}
