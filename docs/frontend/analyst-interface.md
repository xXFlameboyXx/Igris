# IGRIS Phase 12: Professional Analyst Interface

## 1. Executive Summary

Phase 12 delivers the professional cybersecurity analyst investigation console for **IGRIS** (*Intelligence-Guided Reverse Inspection System*). Built as an evidence-driven, epistemologically structured presentation layer, it consumes the complete suite of IGRIS backend analysis engines across Phases 1–11:

- **Phase 1 & 2:** File Ingestion, Metadata, and Static Analysis
- **Phase 3 & 4:** Detection Rules, Heuristics, Linear Disassembly, and Control Flow Graphs (CFG)
- **Phase 5:** Threat Assessment, Capability Inferences, and MITRE ATT&CK® Mappings
- **Phase 6:** Machine Learning Classification and Feature Importance Rankings
- **Phase 7 & 8:** Dynamic Behavioral Telemetry, Process Trees, Network Logs, and Behavior Graphs
- **Phase 10:** Multi-Category Sample Similarity Analysis and Cluster Hypotheses
- **Phase 11:** Explainable Malware Assessment with Epistemological Traceability (`[OBSERVED]`, `[INFERRED]`, `[POSSIBLE]`)

---

## 2. Core Architectural Principles

### 2.1 Presentation & Investigation Layer (No Logic Duplication)
The frontend serves strictly as an analyst presentation and workflow layer. It communicates with the backend via strongly typed REST API clients (`apiClient`) and does not duplicate backend detection engines, scoring algorithms, or heuristic evaluations.

### 2.2 Strict Epistemological Integrity
Every piece of data is categorized according to its empirical confidence level:
- **`[OBSERVED]`**: Physical facts directly visible in raw binary headers or sandbox telemetry (e.g. section permissions, spawned process IDs, outbound socket connections).
- **`[INFERRED]`**: Analytical conclusions drawn by rule evaluation, heuristic triggers, or machine learning models (e.g. detection rule matches, ML scores).
- **`[POSSIBLE]`**: Technical cluster hypotheses and similarity correlations without absolute attribution proof.

### 2.3 Strict Attribution Safety Guardrails
In adherence with Phase 10 and Phase 11 safety rules:
- Technical similarity is **NEVER** presented as confirmed threat actor, campaign, or malware family attribution.
- The UI explicitly renders `attribution_scope: "cluster_only"` and displays warning banners on all similarity views.

### 2.4 Traceability Chain
Analysts can navigate seamlessly through the investigation hierarchy:
$$\text{Verdict} \longrightarrow \text{Executive Reasoning} \longrightarrow \text{Evidence Item} \longrightarrow \text{Observation} \longrightarrow \text{Originating Subsystem Artifact}$$

### 2.5 State Robustness
Every view gracefully handles all runtime states:
- **Loading:** Non-blocking spinners and indicators.
- **Unavailable / Unperformed:** Actionable panels explaining unperformed telemetry and offering single-click execution triggers.
- **Empty:** Clean messages when zero anomalies are found.
- **Error:** Diagnostic error banners with retry triggers.

---

## 3. Investigation Views Catalog

```
┌──────────────────────────────────────────────────────────────────────────┐
│                             IGRIS SHELL                                  │
│  [Brand / Selector]  [Upload Binary]  [Demo Data Toggle]  [Health Status]│
├──────────────────────────────────────────────────────────────────────────┤
│  Coverage Bar: Static [✓]  Reverse [✓]  Behavior [✓]  Rules [✓]  ML [✓]  │
├───────────────┬──────────────────────────────────────────────────────────┤
│ SIDEBAR       │ ACTIVE VIEW PANE                                         │
│ • Overview    │  - Hero Verdict Card (Score: 92/100, CRITICAL)           │
│ • Explainable │  - Epistemological Grid (Observed vs Inferred vs Possible)│
│ • Evidence    │  - Supporting vs Contradicting Findings                  │
│ • Static      │  - Interactive Graph (CFG / Behavior DAG)                │
│ • Reverse/CFG │  - Filterable Data Tables with Search & Pagination       │
│ • Behavior    │  - MITRE ATT&CK Matrix & Technique Links                 │
│ • Similarity  │  - Machine Learning Feature Importance Ranking           │
│ • ATT&CK      │  - Formal Dossier Report (Print / PDF / Markdown)        │
│ • ML Model    │  - Synthetic Demonstration Walkthrough Lab               │
│ • Report      │                                                          │
│ • Demo Lab    │                                                          │
└───────────────┴──────────────────────────────────────────────────────────┘
```

### 3.1 Overview View (`OverviewView.tsx`)
- **Verdict Hero Panel:** Prominent verdict badge (`HIGHLY_SUSPICIOUS`, `SUSPICIOUS`, `LIKELY_BENIGN`, `BENIGN`, `UNKNOWN`), risk level badge (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`, `UNKNOWN`), and evidence risk score ($0\text{--}100$).
- **Multi-Dimensional Confidence:** Multi-factor confidence ratings for Detection, Evidence Quality, Behavioral Telemetry, Similarity, and Attribution Scope.
- **Cross-Layer Disagreement Alerts:** Highlighted conflict warnings whenever independent layers diverge (e.g. static packing indicators vs clean dynamic execution).
- **Subsystem Controls:** Action buttons to trigger or re-run static, reverse, sandbox, detection, ML, or similarity subsystems.

### 3.2 Verdict & Explainability View (`VerdictExplainabilityView.tsx`)
- **Executive Assessment Narrative:** Human-readable assessment summary generated by Phase 11.
- **Three-Column Epistemology Grid:** Direct categorization of raw observed facts, inferred deductions, and potential hypotheses.
- **Supporting vs Contradicting Arguments:** Explicit contrast of arguments reinforcing or mitigating the malware hypothesis.
- **Deterministic Risk Breakdown:** Transparent point allocation for positive contributing factors and mitigating factors with formula explanation.
- **Uncertainty & Unknowns:** Tracked unobserved telemetry categories, reinforcing that missing data is not negative proof.
- **Analytical Limitations:** Documented boundary conditions and attribution constraints.

### 3.3 Evidence Explorer View (`EvidenceExplorerView.tsx`)
- Comprehensive searchable, filterable, and sortable evidence matrix.
- Filters by Category (Static, Reverse, Behavior, Rules, ML, Similarity), Role (Supporting, Contradicting, Neutral), and Epistemology Level (Observed, Inferred, Possible).
- Interactive Detail Inspector displaying provenance paths, source IDs, evidence weights, technical metadata JSON, and one-click jump buttons to originating analysis views.

### 3.4 Static File Intelligence View (`StaticAnalysisView.tsx`)
- Sub-tabs for **PE/ELF Headers & Sections**, **Imported DLLs & APIs**, **Extracted Strings**, and **Static Indicators**.
- Section entropy visualization bar ($0.0\text{--}8.0$) with automated high-entropy ($> 7.2$) packing alerts.
- Permission flags with critical highlights for dangerous Writable + Executable ($\text{W+X}$) sections.

### 3.5 Reverse Engineering & CFG View (`ReverseEngineeringView.tsx`)
- **Functions Table:** Cyclomatic complexity metrics, basic block counts, and API calls.
- **Interactive Control Flow Graph (CFG):** High-performance SVG graph renderer with pan, zoom, reset, node selection, and conditional true/false edge formatting.
- **Disassembly Inspector:** Assembly instruction listing with address, mnemonic, operands, and outgoing branch targets for the selected basic block.
- **Function Call Graph:** Caller-to-callee relationship visualization across disassembled routines.

### 3.6 Behavioral Sandbox View (`BehavioralView.tsx`)
- **Process Tree:** Process hierarchy displaying PID, PPID, process name, and full command line arguments.
- **Registry Activity:** Real-time modification logs highlighting autostart `Run` persistence keys.
- **Network Activity:** Inbound and outbound TCP, UDP, and DNS socket telemetry with protocol badges.
- **Dropped Artifacts:** Filesystem writes with SHA-256 hashes and file sizes.
- **Interactive Behavior Graph:** Visual DAG linking processes to spawned child tasks, registry mutations, network destinations, and dropped files.
- **Chronological Timeline:** Unified millisecond-offset timeline stream of all dynamic events.

### 3.7 Sample Similarity View (`SimilarityView.tsx`)
- Evaluated candidates counter and matched candidate ranking.
- Overall similarity percentage meter, clustering hypothesis badge, and match confidence.
- Feature category breakdown (File metadata, Sections, Imports, Strings, Functions, Behavior).
- Side-by-side comparison of shared technical indicators and discriminating differences.
- Strict attribution disclaimer: *"Similarity indicates technical feature overlap and NEVER implies confirmed malware family, actor, or campaign attribution."*

### 3.8 MITRE ATT&CK® Matrix View (`AttackMatrixView.tsx`)
- Mapped technique table with Tactic grouping, Technique IDs (with direct links to attack.mitre.org), Technique Names, Confidence ratings, and supporting evidence IDs.
- Inferred high-level capability hypotheses (e.g. Process Injection, Persistence, C2 Communication).
- Threat assessment narrative synthesis.

### 3.9 Machine Learning Classifier View (`MLClassifierView.tsx`)
- Random Forest model prediction status (`MALWARE` / `BENIGN`) and calibrated likelihood score ($0\text{--}100\%$).
- Feature importance ranking table with normalized relative contribution bars.
- Model explanation text and model schema provenance metadata (`rf-static-reverse-v2.1`).
- Clear ML safety notice: *"Statistical prediction is an inferred analytical signal and NEVER overrides contradictory physical observations."*

### 3.10 Investigation Report View (`InvestigationReportView.tsx`)
- Complete formal intelligence dossier ready for analyst review, markdown export, or printable PDF generation (`window.print()`).
- Responsive printable CSS (`@media print`) rendering high-contrast, clean black-and-white documentation sheets with verdict stamps, hash tables, epistemological findings, evidence matrices, and analytical limitations.

### 3.11 Synthetic Demonstration Lab (`SyntheticDemoView.tsx`)
- Controlled offline demonstration environment with 4 preloaded test scenarios:
  1. **Multi-Layer Corroborated Trojan Dropper** (`DEMO_MALICIOUS_SAMPLE`): Full evidence convergence, W+X section, hidden PowerShell child process, Run key persistence, and HIGHLY_SUSPICIOUS verdict.
  2. **Clean GUI Calculator Utility** (`DEMO_CLEAN_SAMPLE`): Clean execution, zero rule matches, and BENIGN verdict.
  3. **Packed vs Clean Sandbox Disagreement** (`DEMO_DISAGREEMENT_SAMPLE`): UPX packing vs clean runtime execution, surfacing cross-layer disagreement alerts.
  4. **Raw Unanalyzed Upload** (`DEMO_UNANALYZED_SAMPLE`): Demonstrating UNKNOWN verdict and unobserved telemetry tracking.
- Interactive 6-stage investigation pipeline walkthrough guide.
- Unambiguous `SYNTHETIC / DEMONSTRATION DATA` banners.

---

## 4. Verification & Testing

The Phase 12 implementation has undergone end-to-end verification:

| Verification Target | Tool | Result |
| :--- | :--- | :--- |
| Frontend TypeScript Typecheck | `npm test` (`tsc --noEmit`) | **Passed (0 errors)** |
| Frontend ESLint Rules & Hooks | `npm run lint` (`eslint .`) | **Passed (0 errors, 0 warnings)** |
| Frontend Production Build | `npm run build` (`vite build`) | **Passed (0 errors)** |
| Backend Pytest Test Suite | `pytest` | **108 Passed (0 errors, 0 warnings)** |
| Backend Ruff Format & Lint | `ruff check .` | **Passed (0 errors)** |
| Backend Mypy Static Typing | `mypy` | **Passed (97 source files)** |
