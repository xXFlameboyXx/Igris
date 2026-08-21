import React, { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  fallbackMessage?: string;
  level?: "global" | "view" | "component";
  onReset?: () => void;
  onNavigateHome?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public override state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public override componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    // Log error securely to console without crashing the entire application tree
    console.error("[IGRIS ErrorBoundary caught error]:", error, errorInfo);
  }

  private handleReset = (): void => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  private sanitizeErrorMessage(msg?: string): string {
    if (!msg) return "An unexpected client render exception occurred.";
    // Strip local filesystem paths if present
    const sanitized = msg.replace(/[a-zA-Z]:\\[^\s:;]+/g, "[redacted path]").replace(/\/[\w.-]+(\/[\w.-]+)+/g, "[redacted path]");
    return sanitized;
  }

  public override render(): ReactNode {
    if (this.state.hasError) {
      const level = this.props.level || "view";
      const title = this.props.fallbackTitle || (level === "global" ? "Application Render Error" : "View Render Error");
      const userMessage =
        this.props.fallbackMessage ||
        (level === "global"
          ? "A critical client exception prevented the interface from rendering."
          : "An unexpected error occurred while rendering this investigation view.");
      const safeErrorMsg = this.sanitizeErrorMessage(this.state.error?.message);

      if (level === "global") {
        return (
          <div className="error-boundary-global" role="alert" style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem", background: "var(--color-bg, #0b0f19)", color: "var(--color-text, #f3f4f6)" }}>
            <div className="error-boundary-card" style={{ maxWidth: "560px", background: "var(--color-surface, #111827)", border: "1px solid var(--color-border, #1f2937)", borderRadius: "12px", padding: "2rem", textAlign: "center" }}>
              <div className="error-icon" aria-hidden="true" style={{ fontSize: "2.5rem", marginBottom: "1rem" }}>🛡️</div>
              <h1 className="error-title" style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "0.5rem" }}>{title}</h1>
              <p className="error-desc" style={{ color: "var(--color-text-muted, #9ca3af)", marginBottom: "1.5rem" }}>{userMessage}</p>
              <div className="error-details-box" style={{ background: "rgba(0,0,0,0.3)", padding: "0.75rem 1rem", borderRadius: "8px", border: "1px solid var(--color-border, #374151)", marginBottom: "1.5rem", textAlign: "left", wordBreak: "break-word" }}>
                <code style={{ fontSize: "0.85rem", color: "#f87171" }}>{safeErrorMsg}</code>
              </div>
              <div className="error-actions-row" style={{ display: "flex", gap: "1rem", justifyContent: "center" }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => window.location.reload()}
                >
                  Reload Application
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={this.handleReset}
                >
                  Try Recovering View
                </button>
              </div>
            </div>
          </div>
        );
      }

      return (
        <div className="error-boundary-view" role="alert" style={{ padding: "2rem" }}>
          <div className="state-view error-state">
            <div className="state-icon" aria-hidden="true">⚠️</div>
            <h3>{title}</h3>
            <p className="state-desc">{userMessage}</p>
            <div className="error-details-box" style={{ margin: "1rem 0", maxWidth: "600px" }}>
              <code style={{ fontSize: "0.85rem", color: "var(--color-critical, #ef4444)" }}>
                {safeErrorMsg}
              </code>
            </div>
            <div style={{ display: "flex", gap: "0.75rem", marginTop: "1rem" }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={this.handleReset}
              >
                Reload This View
              </button>
              {this.props.onNavigateHome && (
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => {
                    this.handleReset();
                    this.props.onNavigateHome?.();
                  }}
                >
                  Return to Overview
                </button>
              )}
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
