import React, { useState } from "react";
import type { PESection, Sample, StaticEvidence } from "../../types/api";
import { StrengthBadge } from "../common/Badge";
import { Column, CopyButton, DataTable } from "../common/DataTable";
import { EmptyState, UnavailableState } from "../common/StateViews";

interface StaticAnalysisViewProps {
  sample: Sample | null;
  onRunStatic?: () => void;
  isRunning?: boolean;
}

export function StaticAnalysisView({
  sample,
  onRunStatic,
  isRunning = false,
}: StaticAnalysisViewProps) {
  const [activeSubtab, setActiveSubtab] = useState<"sections" | "imports" | "strings" | "indicators">("sections");

  if (!sample) {
    return <EmptyState icon="📑" title="No Specimen Selected" message="Upload or select a specimen from the top bar to inspect static analysis data." />;
  }

  const staticAnalysis = sample.static_analysis;
  const pe = sample.file_metadata?.pe;
  const elf = sample.file_metadata?.elf;

  if (!staticAnalysis && !pe && !elf) {
    return (
      <UnavailableState
        layerName="Static Analysis"
        description="Static ingestion, PE/ELF header extraction, and string analysis have not been run for this sample."
        onRun={onRunStatic}
        running={isRunning}
      />
    );
  }

  // Sections Table Columns
  const sectionColumns: Column<PESection>[] = [
    {
      id: "name",
      header: "Section Name",
      accessor: (s) => s.name,
      render: (s) => <code>{s.name}</code>,
      width: "120px",
    },
    {
      id: "raw_size",
      header: "Raw Size",
      accessor: (s) => s.raw_size,
      render: (s) => `${(s.raw_size / 1024).toFixed(1)} KB (${s.raw_size.toLocaleString()} B)`,
      width: "140px",
    },
    {
      id: "virtual_size",
      header: "Virtual Size",
      accessor: (s) => s.virtual_size,
      render: (s) => `${(s.virtual_size / 1024).toFixed(1)} KB`,
      width: "130px",
    },
    {
      id: "entropy",
      header: "Entropy (0–8.0)",
      accessor: (s) => s.entropy ?? 0,
      render: (s) => {
        const ent = s.entropy ?? 0;
        const isHigh = ent >= 7.2;
        return (
          <div className="entropy-cell">
            <div className="entropy-bar-track">
              <div
                className={`entropy-bar-fill ${isHigh ? "fill-critical" : "fill-normal"}`}
                style={{ width: `${(ent / 8) * 100}%` }}
              />
            </div>
            <span className={`entropy-val ${isHigh ? "high-entropy" : ""}`}>
              {ent.toFixed(2)} {isHigh && "⚠️ (Packed/Encrypted)"}
            </span>
          </div>
        );
      },
    },
    {
      id: "permissions",
      header: "Permissions",
      accessor: (s) => s.permissions || "—",
      render: (s) => {
        const perms = (s.permissions || "").toLowerCase();
        const isWX = (perms.includes("w") || perms.includes("write")) && (perms.includes("x") || perms.includes("exec"));
        return (
          <span className={`permission-tag ${isWX ? "perm-wx-danger" : ""}`}>
            <code>{s.permissions || "r-x"}</code> {isWX && "⛔ (W+X Danger)"}
          </span>
        );
      },
      width: "180px",
    },
  ];

  // Strings Table
  const extractedStringsList: string[] = Array.isArray(staticAnalysis?.strings_found)
    ? staticAnalysis.strings_found
    : Array.isArray(staticAnalysis?.strings)
    ? staticAnalysis.strings.map((s) => (typeof s === "string" ? s : s?.value || String(s)))
    : [];

  const stringRows = extractedStringsList.map((str, idx) => ({ id: idx, value: str }));
  const stringColumns: Column<{ id: number; value: string }>[] = [
    {
      id: "index",
      header: "#",
      accessor: (r) => r.id + 1,
      width: "60px",
      align: "center",
    },
    {
      id: "string",
      header: "Extracted String",
      accessor: (r) => r.value,
      render: (r) => <code className="string-code">{r.value}</code>,
    },
    {
      id: "action",
      header: "Copy",
      render: (r) => <CopyButton text={r.value} label="String" />,
      width: "80px",
      align: "right",
    },
  ];

  // Indicators Table
  const indicatorColumns: Column<StaticEvidence>[] = [
    {
      id: "category",
      header: "Category",
      accessor: (e) => e.category,
      width: "120px",
    },
    {
      id: "description",
      header: "Finding Description",
      accessor: (e) => e.description,
    },
    {
      id: "severity",
      header: "Severity",
      accessor: (e) => e.severity || "MEDIUM",
      render: (e) => <StrengthBadge strength={(e.severity || "MEDIUM").toUpperCase() as "HIGH"} />,
      width: "100px",
      align: "center",
    },
    {
      id: "confidence",
      header: "Confidence",
      accessor: (e) => e.confidence,
      render: (e) => `${Math.round(e.confidence * 100)}%`,
      width: "100px",
      align: "center",
    },
  ];

  return (
    <div className="view-container static-analysis-view" role="main" aria-label="Static Analysis View">
      <div className="view-header-row">
        <div>
          <h2 className="view-title">Static File Intelligence</h2>
          <p className="view-subtitle">
            Format headers, section permissions, entropy analysis, imported libraries, and extracted strings.
          </p>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <span className="kpi-label">File Format / Arch</span>
          <strong className="kpi-value uppercase">
            {sample.file_metadata?.file_format || "PE"} ({sample.file_metadata?.architecture || "x86_64"})
          </strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Overall Entropy</span>
          <strong className="kpi-value">
            {staticAnalysis?.entropy !== undefined && staticAnalysis.entropy !== null ? staticAnalysis.entropy.toFixed(2) : "N/A"} / 8.00
          </strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Packing Indicator</span>
          <strong className={`kpi-value ${staticAnalysis?.is_packed ? "text-critical" : "text-success"}`}>
            {staticAnalysis?.is_packed ? "⚠️ PACKED" : "✓ Standard"}
          </strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Extracted Strings</span>
          <strong className="kpi-value">
            {extractedStringsList.length.toLocaleString()}
          </strong>
        </div>
      </div>

      {/* Subtab Navigation */}
      <div className="subtab-bar" role="tablist" aria-label="Static Analysis Subsections">
        <button
          type="button"
          role="tab"
          aria-selected={activeSubtab === "sections"}
          className={`subtab-btn ${activeSubtab === "sections" ? "active" : ""}`}
          onClick={() => setActiveSubtab("sections")}
        >
          Header & Sections ({pe?.sections?.length || 0})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeSubtab === "imports"}
          className={`subtab-btn ${activeSubtab === "imports" ? "active" : ""}`}
          onClick={() => setActiveSubtab("imports")}
        >
          Imports & DLLs ({pe?.imported_dlls?.length || Object.keys(staticAnalysis?.imports || {}).length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeSubtab === "strings"}
          className={`subtab-btn ${activeSubtab === "strings" ? "active" : ""}`}
          onClick={() => setActiveSubtab("strings")}
        >
          Extracted Strings ({extractedStringsList.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeSubtab === "indicators"}
          className={`subtab-btn ${activeSubtab === "indicators" ? "active" : ""}`}
          onClick={() => setActiveSubtab("indicators")}
        >
          Static Indicators ({staticAnalysis?.evidence?.length || 0})
        </button>
      </div>

      {/* Subtab 1: Sections */}
      {activeSubtab === "sections" && (
        <section className="subtab-content" aria-labelledby="sections-subtab-heading">
          {pe && (
            <div className="pe-headers-box">
              <h3 id="sections-subtab-heading" className="subheading">PE Header Parameters</h3>
              <dl className="header-meta-grid">
                <div><dt>Entry Point</dt><dd><code>0x{pe.entry_point.toString(16).toUpperCase()}</code></dd></div>
                <div><dt>Image Base</dt><dd><code>0x{pe.image_base.toString(16).toUpperCase()}</code></dd></div>
                <div><dt>Subsystem</dt><dd>{pe.subsystem}</dd></div>
                <div><dt>Machine Architecture</dt><dd>{pe.machine}</dd></div>
              </dl>
            </div>
          )}

          {pe?.sections && pe.sections.length > 0 ? (
            <DataTable
              columns={sectionColumns}
              data={pe.sections}
              keyExtractor={(s, idx) => s.name || String(idx)}
              searchPlaceholder="Filter sections by name or permissions..."
              caption="Executable section permissions and entropy distribution"
            />
          ) : (
            <p className="subdued-text">No section headers available for this format.</p>
          )}
        </section>
      )}

      {/* Subtab 2: Imports */}
      {activeSubtab === "imports" && (
        <section className="subtab-content" aria-label="Imported DLLs and APIs">
          {staticAnalysis?.imports && Object.keys(staticAnalysis.imports).length > 0 ? (
            <div className="imports-accordion-stack">
              {Object.entries(staticAnalysis.imports).map(([dll, apis]) => {
                const safeApis = Array.isArray(apis) ? apis : [];
                return (
                  <div key={dll} className="import-dll-card">
                    <div className="import-dll-header">
                      <span className="dll-icon" aria-hidden="true">📦</span>
                      <strong className="dll-name">{dll}</strong>
                      <span className="dll-count">({safeApis.length} functions)</span>
                    </div>
                    <div className="dll-apis-grid">
                      {safeApis.map((api, idx) => (
                        <code key={idx} className="api-chip">
                          {api}
                        </code>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="subdued-text">No import table entries detected.</p>
          )}
        </section>
      )}

      {/* Subtab 3: Strings */}
      {activeSubtab === "strings" && (
        <section className="subtab-content" aria-label="Extracted strings table">
          <DataTable
            columns={stringColumns}
            data={stringRows}
            keyExtractor={(r) => String(r.id)}
            searchPlaceholder="Search extracted ASCII/Unicode strings..."
            initialPageSize={25}
            caption="Extracted binary strings"
          />
        </section>
      )}

      {/* Subtab 4: Static Indicators */}
      {activeSubtab === "indicators" && (
        <section className="subtab-content" aria-label="Static heuristic indicators">
          {staticAnalysis?.evidence && staticAnalysis.evidence.length > 0 ? (
            <DataTable
              columns={indicatorColumns}
              data={staticAnalysis.evidence}
              keyExtractor={(e) => e.evidence_id}
              searchPlaceholder="Filter static indicators..."
              caption="Static heuristic findings"
            />
          ) : (
            <EmptyState title="No Static Indicators" message="Static analysis found zero suspicious header or import anomalies." />
          )}
        </section>
      )}
    </div>
  );
}
