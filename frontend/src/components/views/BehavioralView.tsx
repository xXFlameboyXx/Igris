import React, { useMemo, useState } from "react";
import type {
  DroppedFileEvent,
  NetworkEvent,
  ProcessEvent,
  RegistryEvent,
  Sample,
} from "../../types/api";
import { Column, CopyButton, DataTable } from "../common/DataTable";
import { GraphEdge, GraphNode, InteractiveGraph } from "../common/InteractiveGraph";
import { EmptyState, UnavailableState } from "../common/StateViews";

interface BehavioralViewProps {
  sample: Sample | null;
  onRunBehavior?: () => void;
  isRunning?: boolean;
}

export function BehavioralView({
  sample,
  onRunBehavior,
  isRunning = false,
}: BehavioralViewProps) {
  const [activeTab, setActiveTab] = useState<"processes" | "files" | "registry" | "network" | "graph" | "timeline">("processes");

  const behavior = sample?.behavior_analysis;

  // Build Behavior Graph (Processes, Registry, Network, Dropped Files)
  const behaviorNodes: GraphNode[] = useMemo(() => {
    if (!behavior) return [];
    const nodes: GraphNode[] = [];

    // Process nodes
    behavior.processes.forEach((p) => {
      nodes.push({
        id: `proc-${p.pid}`,
        label: `${p.process_name} (PID: ${p.pid})`,
        sublabel: p.command_line,
        category: "PROCESS",
        isEntry: p.ppid === 1024 || p.pid === behavior.processes[0]?.pid,
        hasSuspiciousPattern: p.process_name.includes("powershell") || p.process_name.includes("cmd"),
      });
    });

    // Registry nodes
    behavior.registry_events.forEach((r, idx) => {
      nodes.push({
        id: `reg-${idx}`,
        label: `Registry: ${r.value_name || "Key"}`,
        sublabel: r.key_path,
        category: "REGISTRY",
        hasSuspiciousPattern: r.key_path.includes("Run"),
      });
    });

    // Network nodes
    behavior.network_events.forEach((n, idx) => {
      nodes.push({
        id: `net-${idx}`,
        label: n.domain || `${n.destination_ip}:${n.destination_port}`,
        sublabel: `${n.protocol.toUpperCase()} ${n.direction}`,
        category: "NETWORK",
        hasSuspiciousPattern: true,
      });
    });

    // Dropped file nodes
    behavior.dropped_files.forEach((f, idx) => {
      nodes.push({
        id: `file-${idx}`,
        label: `Dropped: ${f.path.split("\\").pop() || f.path}`,
        sublabel: f.path,
        category: "FILE",
      });
    });

    return nodes;
  }, [behavior]);

  const behaviorEdges: GraphEdge[] = useMemo(() => {
    if (!behavior) return [];
    const edges: GraphEdge[] = [];

    // Process tree edges
    behavior.processes.forEach((p) => {
      if (behavior.processes.some((parent) => parent.pid === p.ppid)) {
        edges.push({
          id: `proc-edge-${p.ppid}-${p.pid}`,
          source: `proc-${p.ppid}`,
          target: `proc-${p.pid}`,
          label: "spawns",
          type: "call",
        });
      }
    });

    // Connect first process to registry, network, files
    const rootProcId = `proc-${behavior.processes[0]?.pid || 2048}`;
    behavior.registry_events.forEach((_, idx) => {
      edges.push({
        id: `edge-reg-${idx}`,
        source: rootProcId,
        target: `reg-${idx}`,
        label: "writes_key",
        type: "behavior",
      });
    });

    behavior.network_events.forEach((_, idx) => {
      edges.push({
        id: `edge-net-${idx}`,
        source: rootProcId,
        target: `net-${idx}`,
        label: "connects",
        type: "behavior",
      });
    });

    behavior.dropped_files.forEach((_, idx) => {
      edges.push({
        id: `edge-file-${idx}`,
        source: rootProcId,
        target: `file-${idx}`,
        label: "drops",
        type: "behavior",
      });
    });

    return edges;
  }, [behavior]);

  // Combined Timeline Events
  const timelineEvents = useMemo(() => {
    if (!behavior) return [];
    type TimelineItem = {
      id: string;
      timestamp_ms: number;
      type: "PROCESS" | "REGISTRY" | "NETWORK" | "FILE";
      summary: string;
      details: string;
      isSuspicious: boolean;
    };

    const items: TimelineItem[] = [];

    behavior.processes.forEach((p, idx) => {
      items.push({
        id: `tl-p-${idx}`,
        timestamp_ms: p.timestamp_ms,
        type: "PROCESS",
        summary: `Spawned process: ${p.process_name} (PID: ${p.pid})`,
        details: p.command_line,
        isSuspicious: p.process_name.includes("powershell"),
      });
    });

    behavior.registry_events.forEach((r, idx) => {
      items.push({
        id: `tl-r-${idx}`,
        timestamp_ms: r.timestamp_ms,
        type: "REGISTRY",
        summary: `Registry ${r.operation}: ${r.value_name || ""}`,
        details: `${r.key_path} -> ${r.data || ""}`,
        isSuspicious: r.key_path.includes("Run"),
      });
    });

    behavior.network_events.forEach((n, idx) => {
      items.push({
        id: `tl-n-${idx}`,
        timestamp_ms: n.timestamp_ms,
        type: "NETWORK",
        summary: `Network ${n.direction.toUpperCase()} socket: ${n.protocol.toUpperCase()} ${n.destination_ip || n.domain}:${n.destination_port || ""}`,
        details: `Source: ${n.source_ip || "local"} -> Dest: ${n.destination_ip || n.domain}`,
        isSuspicious: true,
      });
    });

    behavior.dropped_files.forEach((f, idx) => {
      items.push({
        id: `tl-f-${idx}`,
        timestamp_ms: f.timestamp_ms,
        type: "FILE",
        summary: `Dropped artifact: ${f.path}`,
        details: `SHA-256: ${f.sha256} (${f.size_bytes} B)`,
        isSuspicious: true,
      });
    });

    return items.sort((a, b) => a.timestamp_ms - b.timestamp_ms);
  }, [behavior]);

  if (!sample) {
    return <EmptyState icon="🏃" title="No Specimen Selected" message="Upload or select a specimen from the top bar to inspect behavioral telemetry." />;
  }

  if (!behavior) {
    return (
      <UnavailableState
        layerName="Behavioral Sandbox Analysis"
        description="Dynamic sandbox emulation, process monitoring, and network telemetry have not been executed."
        onRun={onRunBehavior}
        running={isRunning}
      />
    );
  }

  // Tables Columns
  const processColumns: Column<ProcessEvent>[] = [
    {
      id: "pid",
      header: "PID / PPID",
      accessor: (p) => `${p.pid} / ${p.ppid}`,
      render: (p) => <code>{p.pid} / {p.ppid}</code>,
      width: "120px",
    },
    {
      id: "name",
      header: "Process Name",
      accessor: (p) => p.process_name,
      render: (p) => (
        <div className="proc-name-cell">
          <strong>{p.process_name}</strong>
          {p.process_name.includes("powershell") && (
            <span className="badge badge-critical badge-sm">⚠️ Suspicious</span>
          )}
        </div>
      ),
      width: "200px",
    },
    {
      id: "command",
      header: "Command Line",
      accessor: (p) => p.command_line,
      render: (p) => <code className="cmd-code">{p.command_line}</code>,
    },
    {
      id: "time",
      header: "Offset",
      accessor: (p) => `+${p.timestamp_ms}ms`,
      width: "100px",
      align: "right",
    },
  ];

  const registryColumns: Column<RegistryEvent>[] = [
    {
      id: "op",
      header: "Operation",
      accessor: (r) => r.operation,
      render: (r) => <span className="badge badge-neutral badge-sm">{r.operation}</span>,
      width: "120px",
    },
    {
      id: "key",
      header: "Key Path",
      accessor: (r) => r.key_path,
      render: (r) => (
        <div className="reg-key-cell">
          <code>{r.key_path}</code>
          {r.key_path.includes("Run") && <span className="badge badge-high badge-sm">⚠️ Autostart Run Key</span>}
        </div>
      ),
    },
    {
      id: "value",
      header: "Value / Data",
      accessor: (r) => `${r.value_name || ""} = ${r.data || ""}`,
      render: (r) => (
        <div>
          {r.value_name && <strong>{r.value_name}: </strong>}
          <code>{r.data || "—"}</code>
        </div>
      ),
    },
    {
      id: "time",
      header: "Offset",
      accessor: (r) => `+${r.timestamp_ms}ms`,
      width: "100px",
      align: "right",
    },
  ];

  const networkColumns: Column<NetworkEvent>[] = [
    {
      id: "proto",
      header: "Protocol",
      accessor: (n) => n.protocol.toUpperCase(),
      render: (n) => <span className="badge badge-info badge-sm">{n.protocol.toUpperCase()}</span>,
      width: "100px",
    },
    {
      id: "dest",
      header: "Destination",
      accessor: (n) => n.domain || `${n.destination_ip}:${n.destination_port}`,
      render: (n) => (
        <div>
          <strong>{n.domain || n.destination_ip}</strong>
          {n.destination_port && <span>:{n.destination_port}</span>}
        </div>
      ),
    },
    {
      id: "dir",
      header: "Direction",
      accessor: (n) => n.direction,
      render: (n) => <span className="badge badge-neutral badge-sm">{n.direction}</span>,
      width: "110px",
      align: "center",
    },
    {
      id: "time",
      header: "Offset",
      accessor: (n) => `+${n.timestamp_ms}ms`,
      width: "100px",
      align: "right",
    },
  ];

  const fileColumns: Column<DroppedFileEvent>[] = [
    {
      id: "path",
      header: "File Path",
      accessor: (f) => f.path,
      render: (f) => <code>{f.path}</code>,
    },
    {
      id: "size",
      header: "Size",
      accessor: (f) => `${(f.size_bytes / 1024).toFixed(1)} KB`,
      width: "120px",
    },
    {
      id: "hash",
      header: "SHA-256 Hash",
      accessor: (f) => f.sha256,
      render: (f) => (
        <div className="hash-copy-cell">
          <code>{f.sha256.slice(0, 16)}…{f.sha256.slice(-8)}</code>
          <CopyButton text={f.sha256} label="Dropped SHA-256" />
        </div>
      ),
      width: "220px",
    },
    {
      id: "time",
      header: "Offset",
      accessor: (f) => `+${f.timestamp_ms}ms`,
      width: "100px",
      align: "right",
    },
  ];

  return (
    <div className="view-container behavioral-view" role="main" aria-label="Behavioral Analysis View">
      <div className="view-header-row">
        <div>
          <h2 className="view-title">Dynamic Behavioral Telemetry</h2>
          <p className="view-subtitle">
            Observed runtime process hierarchies, file system modifications, registry persistence hooks, and network connections.
          </p>
        </div>
        <div className="provenance-badge-box">
          <span className="badge badge-category">PROVENANCE: {behavior.provenance.toUpperCase()}</span>
        </div>
      </div>

      {/* KPI Stats */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <span className="kpi-label">Processes Spawned</span>
          <strong className="kpi-value">{behavior.processes.length}</strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Registry Mutations</span>
          <strong className="kpi-value">{behavior.registry_events.length}</strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Network Sockets</span>
          <strong className="kpi-value">{behavior.network_events.length}</strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Dropped Artifacts</span>
          <strong className="kpi-value">{behavior.dropped_files.length}</strong>
        </div>
      </div>

      {/* Subtab Navigation */}
      <div className="subtab-bar" role="tablist" aria-label="Behavior Subsections">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "processes"}
          className={`subtab-btn ${activeTab === "processes" ? "active" : ""}`}
          onClick={() => setActiveTab("processes")}
        >
          Process Tree ({behavior.processes.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "registry"}
          className={`subtab-btn ${activeTab === "registry" ? "active" : ""}`}
          onClick={() => setActiveTab("registry")}
        >
          Registry Activity ({behavior.registry_events.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "network"}
          className={`subtab-btn ${activeTab === "network" ? "active" : ""}`}
          onClick={() => setActiveTab("network")}
        >
          Network Activity ({behavior.network_events.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "files"}
          className={`subtab-btn ${activeTab === "files" ? "active" : ""}`}
          onClick={() => setActiveTab("files")}
        >
          Dropped Files ({behavior.dropped_files.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "graph"}
          className={`subtab-btn ${activeTab === "graph" ? "active" : ""}`}
          onClick={() => setActiveTab("graph")}
        >
          Behavior Graph
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "timeline"}
          className={`subtab-btn ${activeTab === "timeline" ? "active" : ""}`}
          onClick={() => setActiveTab("timeline")}
        >
          Timeline ({timelineEvents.length})
        </button>
      </div>

      {/* 1. Processes */}
      {activeTab === "processes" && (
        <section className="subtab-content" aria-label="Process Tree Table">
          {behavior.processes.length > 0 ? (
            <DataTable
              columns={processColumns}
              data={behavior.processes}
              keyExtractor={(p, idx) => `proc-${p.pid}-${idx}`}
              searchPlaceholder="Filter processes by name or command line..."
              caption="Spawned processes and command line arguments"
            />
          ) : (
            <EmptyState title="No Processes Spawned" message="Zero child processes observed during sandbox execution." />
          )}
        </section>
      )}

      {/* 2. Registry */}
      {activeTab === "registry" && (
        <section className="subtab-content" aria-label="Registry Activity Table">
          {behavior.registry_events.length > 0 ? (
            <DataTable
              columns={registryColumns}
              data={behavior.registry_events}
              keyExtractor={(r, idx) => `reg-${idx}`}
              searchPlaceholder="Filter registry operations or keys..."
              caption="Registry modifications and persistence keys"
            />
          ) : (
            <EmptyState title="No Registry Mutations" message="Zero registry modifications observed during execution." />
          )}
        </section>
      )}

      {/* 3. Network */}
      {activeTab === "network" && (
        <section className="subtab-content" aria-label="Network Activity Table">
          {behavior.network_events.length > 0 ? (
            <DataTable
              columns={networkColumns}
              data={behavior.network_events}
              keyExtractor={(n, idx) => `net-${idx}`}
              searchPlaceholder="Filter network protocols, IPs, or domains..."
              caption="Outbound and inbound network telemetry"
            />
          ) : (
            <EmptyState title="No Network Traffic" message="Zero socket connections or DNS requests initiated." />
          )}
        </section>
      )}

      {/* 4. Files */}
      {activeTab === "files" && (
        <section className="subtab-content" aria-label="Dropped Files Table">
          {behavior.dropped_files.length > 0 ? (
            <DataTable
              columns={fileColumns}
              data={behavior.dropped_files}
              keyExtractor={(f, idx) => `file-${idx}`}
              searchPlaceholder="Filter dropped files by path or hash..."
              caption="Dropped filesystem artifacts"
            />
          ) : (
            <EmptyState title="No Files Dropped" message="Zero files written to disk during sandbox execution." />
          )}
        </section>
      )}

      {/* 5. Behavior Graph */}
      {activeTab === "graph" && (
        <section className="subtab-content" aria-label="Behavior Graph View">
          <InteractiveGraph
            title="Behavioral Interaction Graph"
            nodes={behaviorNodes}
            edges={behaviorEdges}
            height={520}
          />
        </section>
      )}

      {/* 6. Chronological Timeline */}
      {activeTab === "timeline" && (
        <section className="subtab-content" aria-label="Behavioral Timeline">
          <div className="timeline-stream">
            {timelineEvents.map((ev) => (
              <div
                key={ev.id}
                className={`timeline-entry ${ev.isSuspicious ? "entry-suspicious" : ""}`}
              >
                <div className="timeline-time-badge">+{ev.timestamp_ms}ms</div>
                <div className="timeline-marker" aria-hidden="true" />
                <div className="timeline-content-card">
                  <div className="timeline-card-header">
                    <span className="badge badge-category badge-sm">{ev.type}</span>
                    <strong>{ev.summary}</strong>
                  </div>
                  <code className="timeline-details-code">{ev.details}</code>
                </div>
              </div>
            ))}
            {timelineEvents.length === 0 && (
              <EmptyState title="No Timeline Events" message="Zero behavioral events recorded." />
            )}
          </div>
        </section>
      )}
    </div>
  );
}
