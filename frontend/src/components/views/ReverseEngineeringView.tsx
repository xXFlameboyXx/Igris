import React, { useEffect, useState } from "react";
import type { ControlFlowGraph, FunctionSummary, Sample } from "../../types/api";
import { Column, DataTable } from "../common/DataTable";
import { GraphEdge, GraphNode, InteractiveGraph } from "../common/InteractiveGraph";
import { EmptyState, UnavailableState } from "../common/StateViews";

interface ReverseEngineeringViewProps {
  sample: Sample | null;
  onRunReverse?: () => void;
  isRunning?: boolean;
  onFetchCFG?: (functionId: string) => Promise<ControlFlowGraph | null>;
  demoCFG?: ControlFlowGraph;
}

export function ReverseEngineeringView({
  sample,
  onRunReverse,
  isRunning = false,
  onFetchCFG,
  demoCFG,
}: ReverseEngineeringViewProps) {
  const [activeTab, setActiveTab] = useState<"functions" | "cfg" | "callgraph" | "evidence">("functions");
  const [selectedFunction, setSelectedFunction] = useState<FunctionSummary | null>(null);
  const [cfg, setCfg] = useState<ControlFlowGraph | null>(demoCFG || null);
  const [loadingCFG, setLoadingCFG] = useState(false);
  const [selectedBlockId, setSelectedBlockId] = useState<string | null>(null);

  const reverse = sample?.reverse_analysis;

  useEffect(() => {
    if (reverse?.functions && reverse.functions.length > 0 && !selectedFunction) {
      const suspiciousFn = reverse.functions.find((f) => f.has_suspicious_patterns) || reverse.functions[0];
      setSelectedFunction(suspiciousFn);
    }
  }, [reverse, selectedFunction]);

  useEffect(() => {
    if (selectedFunction && onFetchCFG) {
      setLoadingCFG(true);
      onFetchCFG(selectedFunction.function_id)
        .then((res) => {
          if (res) setCfg(res);
        })
        .catch(() => {
          // Fall back to demo CFG if available
          if (demoCFG) setCfg(demoCFG);
        })
        .finally(() => setLoadingCFG(false));
    }
  }, [selectedFunction, onFetchCFG, demoCFG]);

  if (!sample) {
    return <EmptyState title="No Sample Selected" message="Select a sample to inspect reverse engineering analysis." />;
  }

  if (!reverse) {
    return (
      <UnavailableState
        layerName="Reverse Engineering"
        description="Linear disassembly, function identification, and CFG extraction have not been run."
        onRun={onRunReverse}
        running={isRunning}
      />
    );
  }

  // Convert CFG blocks and edges into GraphNode and GraphEdge format
  const cfgNodes: GraphNode[] = (cfg?.blocks || []).map((b) => ({
    id: b.block_id,
    label: `${b.block_id} (0x${b.start_address.toString(16).toUpperCase()})`,
    sublabel: `${b.instructions.length} instrs • ${b.instructions[0]?.mnemonic || ""} ...`,
    category: b.is_entry ? "ENTRY" : b.is_exit ? "EXIT" : "BLOCK",
    isEntry: b.is_entry,
    isExit: b.is_exit,
    hasSuspiciousPattern: b.instructions.some((i) => i.mnemonic === "call" && i.operands.includes("VirtualAlloc")),
  }));

  const cfgEdges: GraphEdge[] = (cfg?.edges || []).map((e, idx) => ({
    id: `edge-${idx}`,
    source: e.source_block_id,
    target: e.target_block_id,
    label: e.edge_type === "conditional_true" ? "true" : e.edge_type === "conditional_false" ? "false" : undefined,
    type: e.edge_type,
  }));

  // Build Call Graph from all functions
  const callGraphNodes: GraphNode[] = (reverse.functions || []).map((fn) => ({
    id: fn.function_id,
    label: fn.name,
    sublabel: `0x${fn.address.toString(16).toUpperCase()} • Complexity: ${fn.cyclomatic_complexity}`,
    category: fn.has_suspicious_patterns ? "SUSPICIOUS" : "FUNCTION",
    hasSuspiciousPattern: fn.has_suspicious_patterns,
  }));

  const callGraphEdges: GraphEdge[] = [];
  reverse.functions.forEach((fn, idx) => {
    if (idx < reverse.functions.length - 1) {
      callGraphEdges.push({
        id: `call-edge-${idx}`,
        source: fn.function_id,
        target: reverse.functions[idx + 1].function_id,
        label: "calls",
        type: "call",
      });
    }
  });

  const selectedBlock = cfg?.blocks.find((b) => b.block_id === selectedBlockId);

  // Functions Table Columns
  const functionColumns: Column<FunctionSummary>[] = [
    {
      id: "name",
      header: "Function Name",
      accessor: (f) => f.name,
      render: (f) => (
        <div className="function-name-cell">
          <code>{f.name}</code>
          {f.has_suspicious_patterns && <span className="badge badge-critical badge-sm">⚠️ Suspicious</span>}
        </div>
      ),
      width: "240px",
    },
    {
      id: "address",
      header: "Address",
      accessor: (f) => f.address,
      render: (f) => <code>0x{f.address.toString(16).toUpperCase()}</code>,
      width: "120px",
    },
    {
      id: "complexity",
      header: "Cyclomatic Complexity",
      accessor: (f) => f.cyclomatic_complexity,
      render: (f) => (
        <span className={f.cyclomatic_complexity >= 6 ? "high-complexity" : ""}>
          {f.cyclomatic_complexity} {f.cyclomatic_complexity >= 6 ? "⚠️ (Complex)" : ""}
        </span>
      ),
      width: "160px",
      align: "center",
    },
    {
      id: "blocks",
      header: "Blocks",
      accessor: (f) => f.block_count,
      width: "90px",
      align: "center",
    },
    {
      id: "apis",
      header: "API Calls",
      accessor: (f) => f.api_calls.join(", "),
      render: (f) => (
        <div className="fn-apis-chips">
          {f.api_calls.map((api, idx) => (
            <code key={idx} className="api-chip-sm">{api}</code>
          ))}
          {f.api_calls.length === 0 && <span className="subdued-text">—</span>}
        </div>
      ),
    },
    {
      id: "actions",
      header: "CFG",
      render: (f) => (
        <button
          type="button"
          className="btn btn-xs btn-primary"
          onClick={(e) => {
            e.stopPropagation();
            setSelectedFunction(f);
            setActiveTab("cfg");
          }}
        >
          View CFG ›
        </button>
      ),
      width: "90px",
      align: "right",
    },
  ];

  return (
    <div className="view-container reverse-eng-view" role="main" aria-label="Reverse Engineering View">
      <div className="view-header-row">
        <div>
          <h2 className="view-title">Reverse Engineering & Control Flow</h2>
          <p className="view-subtitle">
            Disassembled functions, cyclomatic complexity metrics, control-flow graph (CFG) block structures, and call hierarchies.
          </p>
        </div>
      </div>

      {/* Subtab Navigation */}
      <div className="subtab-bar" role="tablist" aria-label="Reverse Engineering Views">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "functions"}
          className={`subtab-btn ${activeTab === "functions" ? "active" : ""}`}
          onClick={() => setActiveTab("functions")}
        >
          Functions Table ({reverse.functions.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "cfg"}
          className={`subtab-btn ${activeTab === "cfg" ? "active" : ""}`}
          onClick={() => setActiveTab("cfg")}
        >
          CFG Viewer {selectedFunction && `(${selectedFunction.name})`}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "callgraph"}
          className={`subtab-btn ${activeTab === "callgraph" ? "active" : ""}`}
          onClick={() => setActiveTab("callgraph")}
        >
          Call Graph
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "evidence"}
          className={`subtab-btn ${activeTab === "evidence" ? "active" : ""}`}
          onClick={() => setActiveTab("evidence")}
        >
          Reverse Indicators ({reverse.evidence.length})
        </button>
      </div>

      {/* 1. Functions Table */}
      {activeTab === "functions" && (
        <section className="subtab-content" aria-label="Functions Table">
          <DataTable
            columns={functionColumns}
            data={reverse.functions}
            keyExtractor={(f) => f.function_id}
            searchPlaceholder="Filter functions by name, address, or API call..."
            onRowClick={(f) => {
              setSelectedFunction(f);
              setActiveTab("cfg");
            }}
            selectedRowKey={selectedFunction?.function_id}
            caption="Disassembled function list with complexity metrics"
          />
        </section>
      )}

      {/* 2. CFG Graph Viewer */}
      {activeTab === "cfg" && (
        <section className="subtab-content cfg-viewer-section" aria-label="Control Flow Graph Viewer">
          <div className="cfg-header-bar">
            <div>
              <span className="context-label">FUNCTION:</span>
              <strong className="active-fn-name">{selectedFunction?.name || "Entrypoint"}</strong>
              <code className="active-fn-addr">
                (0x{(selectedFunction?.address || 0).toString(16).toUpperCase()})
              </code>
            </div>
            <div className="fn-switch-controls">
              <label htmlFor="fn-switch-select">Switch function:</label>
              <select
                id="fn-switch-select"
                value={selectedFunction?.function_id || ""}
                onChange={(e) => {
                  const fn = reverse.functions.find((f) => f.function_id === e.target.value);
                  if (fn) setSelectedFunction(fn);
                }}
              >
                {reverse.functions.map((f) => (
                  <option key={f.function_id} value={f.function_id}>
                    {f.name} ({f.block_count} blocks)
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="cfg-workspace-grid">
            <div className="cfg-graph-col">
              {loadingCFG ? (
                <div className="state-view loading-state">
                  <div className="spinner" />
                  <p>Rendering Control Flow Graph...</p>
                </div>
              ) : cfg && cfg.blocks.length > 0 ? (
                <InteractiveGraph
                  title={`CFG: ${selectedFunction?.name || "Selected Function"}`}
                  nodes={cfgNodes}
                  edges={cfgEdges}
                  onNodeSelect={(node) => setSelectedBlockId(node?.id || null)}
                  selectedNodeId={selectedBlockId || undefined}
                  height={500}
                />
              ) : (
                <EmptyState title="No CFG Blocks" message="Control-flow graph is unavailable for this function." />
              )}
            </div>

            {/* Block Disassembly Inspector Drawer */}
            <div className="cfg-inspector-col">
              <h3 className="subheading">Basic Block Disassembly</h3>
              {selectedBlock ? (
                <div className="block-details-card">
                  <div className="block-header">
                    <strong>Block: {selectedBlock.block_id}</strong>
                    <span>
                      0x{selectedBlock.start_address.toString(16).toUpperCase()} – 0x{selectedBlock.end_address.toString(16).toUpperCase()}
                    </span>
                  </div>

                  <div className="disassembly-listing">
                    <table className="asm-table">
                      <thead>
                        <tr>
                          <th>Address</th>
                          <th>Mnemonic</th>
                          <th>Operands</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedBlock.instructions.map((ins, idx) => (
                          <tr key={idx} className={ins.mnemonic === "call" ? "call-instruction-row" : ""}>
                            <td className="asm-addr">0x{ins.address.toString(16).toUpperCase()}</td>
                            <td className="asm-mnemonic"><code>{ins.mnemonic}</code></td>
                            <td className="asm-operands"><code>{ins.operands}</code></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <div className="block-footer">
                    <span className="context-label">Outgoing branches:</span>
                    <span>{selectedBlock.outgoing_edges.join(", ") || "None (Terminal Exit)"}</span>
                  </div>
                </div>
              ) : (
                <p className="subdued-text">Click a basic block in the graph to inspect its disassembled instructions.</p>
              )}
            </div>
          </div>
        </section>
      )}

      {/* 3. Call Graph */}
      {activeTab === "callgraph" && (
        <section className="subtab-content" aria-label="Call Graph View">
          <InteractiveGraph
            title="Function Call Graph"
            nodes={callGraphNodes}
            edges={callGraphEdges}
            height={520}
          />
        </section>
      )}

      {/* 4. Reverse Heuristics */}
      {activeTab === "evidence" && (
        <section className="subtab-content" aria-label="Reverse engineering evidence items">
          {reverse.evidence.length > 0 ? (
            <div className="evidence-cards-stack">
              {reverse.evidence.map((ev) => (
                <div key={ev.evidence_id} className="reverse-evidence-card">
                  <div className="rev-ev-header">
                    <span className="badge badge-inferred badge-sm">[INFERRED]</span>
                    <strong>{ev.type}</strong>
                    <span className="fn-tag">Function: <code>{ev.function_id}</code></span>
                  </div>
                  <p className="rev-ev-desc">{ev.description}</p>
                  {ev.related_apis.length > 0 && (
                    <div className="related-apis-row">
                      <span className="context-label">Related APIs:</span>
                      {ev.related_apis.map((api, idx) => (
                        <code key={idx} className="api-chip-sm">{api}</code>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No Reverse Indicators" message="No structural code patterns or suspicious injection routines flagged." />
          )}
        </section>
      )}
    </div>
  );
}
