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
    return <EmptyState icon="⚙️" title="No Specimen Selected" message="Upload or select a specimen from the top bar to inspect reverse engineering analysis." />;
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
  const cfgNodes: GraphNode[] = (cfg?.blocks || []).map((b) => {
    const instrs = (b.instructions || []) as Array<{ address: number; mnemonic: string; operands: string }>;
    const addrList = b.instruction_addresses || [];
    const count = instrs.length > 0 ? instrs.length : addrList.length;
    const firstMnemonic = instrs.length > 0 && typeof instrs[0] === "object" ? instrs[0]?.mnemonic : "";
    const hasSuspicious = instrs.some(
      (i) => i && typeof i === "object" && i.mnemonic === "call" && (i.operands || "").includes("VirtualAlloc")
    );
    return {
      id: b.block_id,
      label: `${b.block_id} (0x${(b.start_address || 0).toString(16).toUpperCase()})`,
      sublabel: `${count} instrs${firstMnemonic ? ` • ${firstMnemonic} ...` : ""}`,
      category: b.is_entry ? "ENTRY" : b.is_exit ? "EXIT" : "BLOCK",
      isEntry: b.is_entry,
      isExit: b.is_exit,
      hasSuspiciousPattern: hasSuspicious,
    };
  });

  const cfgEdges: GraphEdge[] = (cfg?.edges || []).map((e, idx) => ({
    id: `edge-${idx}`,
    source: e.source || e.source_block_id || "",
    target: e.target || e.target_block_id || "",
    label: e.edge_type === "conditional_true" ? "true" : e.edge_type === "conditional_false" ? "false" : undefined,
    type: (e.edge_type as GraphEdge["type"]) || "unconditional",
  }));

  // Build Call Graph from backend call_graph or functions
  const callGraphNodes: GraphNode[] = (reverse.call_graph?.nodes && reverse.call_graph.nodes.length > 0)
    ? reverse.call_graph.nodes.map((n) => ({
        id: n.node_id,
        label: n.label || n.node_id,
        sublabel: n.node_type || "FUNCTION",
        category: n.node_type === "imported_api" ? "SUSPICIOUS" : "FUNCTION",
      }))
    : (reverse.functions || []).map((fn) => {
        const fnName = fn.name || fn.function_id;
        const isSuspicious = fn.has_suspicious_patterns ?? ((fn.evidence || []).length > 0);
        return {
          id: fn.function_id,
          label: fnName,
          sublabel: `0x${(fn.address || 0).toString(16).toUpperCase()} • Complexity: ${fn.cyclomatic_complexity || 1}`,
          category: isSuspicious ? "SUSPICIOUS" : "FUNCTION",
          hasSuspiciousPattern: isSuspicious,
        };
      });

  const callGraphEdges: GraphEdge[] = (reverse.call_graph?.edges && reverse.call_graph.edges.length > 0)
    ? reverse.call_graph.edges.map((e, idx) => ({
        id: `call-edge-${idx}`,
        source: e.source,
        target: e.target,
        label: e.call_type || "calls",
        type: "call",
      }))
    : [];

  if (callGraphEdges.length === 0 && (reverse.functions || []).length > 1) {
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
  }

  const selectedBlock = cfg?.blocks?.find((b) => b.block_id === selectedBlockId);

  // Functions Table Columns
  const functionColumns: Column<FunctionSummary>[] = [
    {
      id: "name",
      header: "Function Name",
      accessor: (f) => f.name || f.function_id,
      render: (f) => {
        const fnName = f.name || f.function_id;
        const isSuspicious = f.has_suspicious_patterns ?? ((f.evidence || []).length > 0);
        return (
          <div className="function-name-cell">
            <code>{fnName}</code>
            {isSuspicious && <span className="badge badge-critical badge-sm">⚠️ Suspicious</span>}
          </div>
        );
      },
      width: "240px",
    },
    {
      id: "address",
      header: "Address",
      accessor: (f) => f.address,
      render: (f) => <code>0x{(f.address || 0).toString(16).toUpperCase()}</code>,
      width: "120px",
    },
    {
      id: "complexity",
      header: "Cyclomatic Complexity",
      accessor: (f) => f.cyclomatic_complexity,
      render: (f) => (
        <span className={(f.cyclomatic_complexity || 0) >= 6 ? "high-complexity" : ""}>
          {f.cyclomatic_complexity} {(f.cyclomatic_complexity || 0) >= 6 ? "⚠️ (Complex)" : ""}
        </span>
      ),
      width: "160px",
      align: "center",
    },
    {
      id: "blocks",
      header: "Blocks",
      accessor: (f) => f.basic_block_count ?? f.block_count ?? 0,
      width: "90px",
      align: "center",
    },
    {
      id: "apis",
      header: "API Calls",
      accessor: (f) => (f.referenced_apis || f.api_calls || []).join(", "),
      render: (f) => {
        const apis = f.referenced_apis || f.api_calls || [];
        return (
          <div className="fn-apis-chips">
            {apis.map((api, idx) => (
              <code key={idx} className="api-chip-sm">{api}</code>
            ))}
            {apis.length === 0 && <span className="subdued-text">—</span>}
          </div>
        );
      },
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
          Functions Table ({(reverse.functions || []).length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "cfg"}
          className={`subtab-btn ${activeTab === "cfg" ? "active" : ""}`}
          onClick={() => setActiveTab("cfg")}
        >
          CFG Viewer {selectedFunction && `(${selectedFunction.name || selectedFunction.function_id})`}
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
          Reverse Indicators ({(reverse.evidence || []).length})
        </button>
      </div>

      {/* 1. Functions Table */}
      {activeTab === "functions" && (
        <section className="subtab-content" aria-label="Functions Table">
          <DataTable
            columns={functionColumns}
            data={reverse.functions || []}
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
              <strong className="active-fn-name">{selectedFunction?.name || selectedFunction?.function_id || "Entrypoint"}</strong>
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
                  const fn = (reverse.functions || []).find((f) => f.function_id === e.target.value);
                  if (fn) setSelectedFunction(fn);
                }}
              >
                {(reverse.functions || []).map((f) => (
                  <option key={f.function_id} value={f.function_id}>
                    {f.name || f.function_id} ({f.basic_block_count ?? f.block_count ?? 0} blocks)
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
              ) : cfg && (cfg.blocks || []).length > 0 ? (
                <InteractiveGraph
                  title={`CFG: ${selectedFunction?.name || selectedFunction?.function_id || "Selected Function"}`}
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
                      0x{(selectedBlock.start_address || 0).toString(16).toUpperCase()} – 0x{(selectedBlock.end_address || 0).toString(16).toUpperCase()}
                    </span>
                  </div>

                  <div className="disassembly-listing">
                    {selectedBlock.instructions && selectedBlock.instructions.length > 0 ? (
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
                              <td className="asm-addr">0x{(ins.address || 0).toString(16).toUpperCase()}</td>
                              <td className="asm-mnemonic"><code>{ins.mnemonic}</code></td>
                              <td className="asm-operands"><code>{ins.operands}</code></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : selectedBlock.instruction_addresses && selectedBlock.instruction_addresses.length > 0 ? (
                      <div style={{ padding: "8px 0", fontSize: "12px" }}>
                        <p style={{ marginBottom: "6px", color: "var(--text-muted)" }}>
                          {selectedBlock.instruction_addresses.length} instruction addresses in block:
                        </p>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                          {selectedBlock.instruction_addresses.map((addr, idx) => (
                            <code key={idx} style={{ background: "var(--bg-tertiary)", padding: "2px 6px", borderRadius: "4px" }}>
                              0x{addr.toString(16).toUpperCase()}
                            </code>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <p className="subdued-text" style={{ padding: "12px 0" }}>No disassembled instructions in this block.</p>
                    )}
                  </div>

                  <div className="block-footer">
                    <span className="context-label">Outgoing branches:</span>
                    <span>{(selectedBlock.successors || selectedBlock.outgoing_edges || []).join(", ") || "None (Terminal Exit)"}</span>
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
          {(reverse.evidence || []).length > 0 ? (
            <div className="evidence-cards-stack">
              {(reverse.evidence || []).map((ev) => (
                <div key={ev.evidence_id} className="reverse-evidence-card">
                  <div className="rev-ev-header">
                    <span className="badge badge-inferred badge-sm">[INFERRED]</span>
                    <strong>{ev.type}</strong>
                    <span className="fn-tag">Function: <code>{ev.function_id}</code></span>
                  </div>
                  <p className="rev-ev-desc">{ev.description}</p>
                  {(ev.related_apis || []).length > 0 && (
                    <div className="related-apis-row">
                      <span className="context-label">Related APIs:</span>
                      {(ev.related_apis || []).map((api, idx) => (
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
