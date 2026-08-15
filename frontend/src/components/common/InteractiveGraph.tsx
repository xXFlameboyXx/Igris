import React, { useMemo, useRef, useState } from "react";

export interface GraphNode {
  id: string;
  label: string;
  sublabel?: string;
  category?: string;
  data?: Record<string, unknown>;
  color?: string;
  borderColor?: string;
  isEntry?: boolean;
  isExit?: boolean;
  hasSuspiciousPattern?: boolean;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  type?: "unconditional" | "conditional_true" | "conditional_false" | "indirect" | "call" | "behavior" | "evidences";
}

interface InteractiveGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeSelect?: (node: GraphNode | null) => void;
  selectedNodeId?: string;
  title?: string;
  maxNodesLimit?: number;
  height?: number;
}

export function InteractiveGraph({
  nodes,
  edges,
  onNodeSelect,
  selectedNodeId,
  title = "Graph Visualization",
  maxNodesLimit = 120,
  height = 520,
}: InteractiveGraphProps) {
  const [zoom, setZoom] = useState(1.0);
  const [pan, setPan] = useState({ x: 40, y: 40 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [searchQuery, setSearchQuery] = useState("");
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Apply node limits for browser performance
  const isTruncated = nodes.length > maxNodesLimit;
  const activeNodes = useMemo(() => {
    return isTruncated ? nodes.slice(0, maxNodesLimit) : nodes;
  }, [nodes, isTruncated, maxNodesLimit]);

  const activeNodeIds = useMemo(() => new Set(activeNodes.map((n) => n.id)), [activeNodes]);
  const activeEdges = useMemo(() => {
    return edges.filter((e) => activeNodeIds.has(e.source) && activeNodeIds.has(e.target));
  }, [edges, activeNodeIds]);

  // Deterministic DAG layout computation
  const nodePositions = useMemo(() => {
    const pos = new Map<string, { x: number; y: number; width: number; height: number }>();
    if (activeNodes.length === 0) return pos;

    // Build adjacency and compute depth levels
    const inDegree = new Map<string, number>();
    const adj = new Map<string, string[]>();
    activeNodes.forEach((n) => {
      inDegree.set(n.id, 0);
      adj.set(n.id, []);
    });

    activeEdges.forEach((e) => {
      if (adj.has(e.source)) {
        adj.get(e.source)!.push(e.target);
      }
      inDegree.set(e.target, (inDegree.get(e.target) || 0) + 1);
    });

    // Level assignment via topological BFS
    const levels = new Map<string, number>();
    const queue: string[] = [];

    activeNodes.forEach((n) => {
      if ((inDegree.get(n.id) || 0) === 0 || n.isEntry) {
        levels.set(n.id, 0);
        queue.push(n.id);
      }
    });

    if (queue.length === 0 && activeNodes.length > 0) {
      levels.set(activeNodes[0].id, 0);
      queue.push(activeNodes[0].id);
    }

    let head = 0;
    while (head < queue.length) {
      const u = queue[head++];
      const currLevel = levels.get(u) || 0;
      const neighbors = adj.get(u) || [];
      for (const v of neighbors) {
        const nextLevel = Math.max(levels.get(v) || 0, currLevel + 1);
        levels.set(v, nextLevel);
        if (!queue.includes(v)) {
          queue.push(v);
        }
      }
    }

    // Assign any unvisited nodes to fallback levels
    activeNodes.forEach((n, idx) => {
      if (!levels.has(n.id)) {
        levels.set(n.id, Math.floor(idx / 4));
      }
    });

    // Group nodes by level
    const levelGroups = new Map<number, GraphNode[]>();
    activeNodes.forEach((n) => {
      const lvl = levels.get(n.id) || 0;
      if (!levelGroups.has(lvl)) levelGroups.set(lvl, []);
      levelGroups.get(lvl)!.push(n);
    });

    const NODE_WIDTH = 220;
    const NODE_HEIGHT = 85;
    const LEVEL_SPACING = 140;
    const SIBLING_SPACING = 40;

    levelGroups.forEach((group, lvl) => {
      const levelY = 60 + lvl * (NODE_HEIGHT + LEVEL_SPACING);
      const totalWidth = group.length * NODE_WIDTH + (group.length - 1) * SIBLING_SPACING;
      const startX = Math.max(60, 400 - totalWidth / 2);

      group.forEach((node, idx) => {
        const x = startX + idx * (NODE_WIDTH + SIBLING_SPACING);
        pos.set(node.id, { x, y: levelY, width: NODE_WIDTH, height: NODE_HEIGHT });
      });
    });

    return pos;
  }, [activeNodes, activeEdges]);

  // Pan & Drag Handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.target === svgRef.current || (e.target as HTMLElement).tagName === "svg") {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };

  const handleMouseUp = () => setIsDragging(false);

  const handleZoom = (delta: number) => {
    setZoom((z) => Math.min(2.5, Math.max(0.3, Number((z + delta).toFixed(2)))));
  };

  const handleReset = () => {
    setZoom(1.0);
    setPan({ x: 40, y: 40 });
  };

  const filteredMatches = useMemo(() => {
    if (!searchQuery.trim()) return new Set<string>();
    const q = searchQuery.toLowerCase().trim();
    return new Set(
      activeNodes
        .filter(
          (n) =>
            n.label.toLowerCase().includes(q) ||
            (n.sublabel && n.sublabel.toLowerCase().includes(q)) ||
            (n.category && n.category.toLowerCase().includes(q))
        )
        .map((n) => n.id)
    );
  }, [activeNodes, searchQuery]);

  return (
    <div className="interactive-graph-card">
      <div className="graph-toolbar">
        <div className="graph-title-group">
          <span className="graph-icon" aria-hidden="true">🕸️</span>
          <strong>{title}</strong>
          <span className="graph-node-count">
            ({activeNodes.length} nodes, {activeEdges.length} edges)
          </span>
        </div>

        <div className="graph-actions">
          <div className="graph-search">
            <input
              type="text"
              className="graph-search-input"
              placeholder="Search nodes..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search graph nodes"
            />
            {searchQuery && (
              <button
                type="button"
                className="clear-search-btn"
                onClick={() => setSearchQuery("")}
                aria-label="Clear search"
              >
                ✕
              </button>
            )}
          </div>

          <div className="zoom-controls">
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={() => handleZoom(0.15)}
              title="Zoom In"
              aria-label="Zoom in graph"
            >
              ＋
            </button>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={() => handleZoom(-0.15)}
              title="Zoom Out"
              aria-label="Zoom out graph"
            >
              －
            </button>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={handleReset}
              title="Reset View"
              aria-label="Reset graph view"
            >
              Reset ({Math.round(zoom * 100)}%)
            </button>
          </div>
        </div>
      </div>

      {isTruncated && (
        <div className="graph-warning-banner" role="status">
          ⚠️ Displaying {maxNodesLimit} of {nodes.length} nodes to preserve interactive browser performance.
        </div>
      )}

      <div
        className="graph-canvas-wrapper"
        style={{ height }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <svg
          ref={svgRef}
          className="graph-svg"
          width="100%"
          height="100%"
          aria-label={title}
          role="img"
        >
          <defs>
            <marker
              id="arrow-unconditional"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
            </marker>
            <marker
              id="arrow-true"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981" />
            </marker>
            <marker
              id="arrow-false"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444" />
            </marker>
            <marker
              id="arrow-call"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#3b82f6" />
            </marker>
          </defs>

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Edges */}
            {activeEdges.map((edge) => {
              const srcPos = nodePositions.get(edge.source);
              const tgtPos = nodePositions.get(edge.target);
              if (!srcPos || !tgtPos) return null;

              const x1 = srcPos.x + srcPos.width / 2;
              const y1 = srcPos.y + srcPos.height;
              const x2 = tgtPos.x + tgtPos.width / 2;
              const y2 = tgtPos.y;

              const midY = (y1 + y2) / 2;
              const pathD = `M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`;

              let strokeColor = "#64748b";
              let markerId = "arrow-unconditional";

              if (edge.type === "conditional_true") {
                strokeColor = "#10b981";
                markerId = "arrow-true";
              } else if (edge.type === "conditional_false") {
                strokeColor = "#ef4444";
                markerId = "arrow-false";
              } else if (edge.type === "call") {
                strokeColor = "#3b82f6";
                markerId = "arrow-call";
              }

              return (
                <g key={edge.id} className="graph-edge-group">
                  <path
                    d={pathD}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={2}
                    markerEnd={`url(#${markerId})`}
                    className="graph-edge-path"
                  />
                  {edge.label && (
                    <text
                      x={(x1 + x2) / 2}
                      y={midY - 6}
                      fill="#94a3b8"
                      fontSize={10}
                      textAnchor="middle"
                      className="graph-edge-label"
                    >
                      {edge.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {activeNodes.map((node) => {
              const pos = nodePositions.get(node.id);
              if (!pos) return null;

              const isSelected = selectedNodeId === node.id;
              const isSearchMatch = searchQuery.trim() && filteredMatches.has(node.id);

              let nodeClass = "graph-node-rect";
              if (node.isEntry) nodeClass += " node-entry";
              if (node.isExit) nodeClass += " node-exit";
              if (node.hasSuspiciousPattern) nodeClass += " node-suspicious";
              if (isSelected) nodeClass += " node-selected";
              if (isSearchMatch) nodeClass += " node-highlighted";

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onClick={() => {
                    if (onNodeSelect) onNodeSelect(node);
                  }}
                  tabIndex={0}
                  role="button"
                  aria-label={`Node ${node.label}: ${node.sublabel || ""}`}
                  onKeyDown={(e) => {
                    if ((e.key === "Enter" || e.key === " ") && onNodeSelect) {
                      onNodeSelect(node);
                    }
                  }}
                >
                  <rect
                    width={pos.width}
                    height={pos.height}
                    rx={6}
                    className={nodeClass}
                  />
                  <text x={12} y={24} className="node-text-title" fill="#f8fafc">
                    {node.label.length > 24 ? node.label.slice(0, 24) + "…" : node.label}
                  </text>
                  {node.sublabel && (
                    <text x={12} y={44} className="node-text-sub" fill="#94a3b8">
                      {node.sublabel.length > 28 ? node.sublabel.slice(0, 28) + "…" : node.sublabel}
                    </text>
                  )}
                  {node.category && (
                    <text x={12} y={64} className="node-text-cat" fill="#64748b">
                      [{node.category.toUpperCase()}]
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      </div>
    </div>
  );
}
