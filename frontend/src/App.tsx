import { useEffect, useState } from "react";

type HealthState =
  | { status: "loading" }
  | { status: "ready"; service: string; version: string; environment: string }
  | { status: "error"; message: string };

type HealthResponse = {
  status: "ok";
  service: string;
  version: string;
  environment: string;
  components: Record<string, "ok" | "degraded" | "unavailable">;
};

async function fetchHealth(signal: AbortSignal): Promise<HealthResponse> {
  const response = await fetch("/api/v1/health", {
    headers: { Accept: "application/json" },
    signal
  });

  if (!response.ok) {
    throw new Error(`Health check failed with HTTP ${response.status}`);
  }

  return response.json() as Promise<HealthResponse>;
}

export default function App() {
  const [health, setHealth] = useState<HealthState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();

    fetchHealth(controller.signal)
      .then((result) => {
        setHealth({
          status: "ready",
          service: result.service,
          version: result.version,
          environment: result.environment
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setHealth({
          status: "error",
          message: error instanceof Error ? error.message : "Unable to reach the API"
        });
      });

    return () => controller.abort();
  }, []);

  return (
    <main className="shell">
      <section className="status-panel" aria-labelledby="page-title">
        <div className="brand-row">
          <span className="mark" aria-hidden="true">
            IG
          </span>
          <div>
            <h1 id="page-title">Igris</h1>
            <p>Engineering foundation for explainable malware analysis.</p>
          </div>
        </div>

        <dl className="status-grid">
          <div>
            <dt>API</dt>
            <dd>{health.status === "ready" ? "Reachable" : health.status}</dd>
          </div>
          <div>
            <dt>Version</dt>
            <dd>{health.status === "ready" ? health.version : "0.1.0"}</dd>
          </div>
          <div>
            <dt>Environment</dt>
            <dd>{health.status === "ready" ? health.environment : "unknown"}</dd>
          </div>
        </dl>

        {health.status === "error" ? (
          <p className="error" role="status">
            {health.message}
          </p>
        ) : null}
      </section>
    </main>
  );
}

