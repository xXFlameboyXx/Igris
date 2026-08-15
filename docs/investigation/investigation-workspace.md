# Phase 13: Investigation Workspace & Dossier Generation Architecture

## Overview

Phase 13 establishes the **Professional Analyst Investigation Workspace** for Igris. It transforms the explainability and analysis layers from Phases 1–12 into an active, evidence-driven workspace where human analysts can:
- Explore and filter multi-layered evidence across subsystems
- Bookmark suspicious findings, functions, timeline events, and network connections
- Author notes and hypotheses while maintaining **strict epistemological separation** from automated algorithms
- Generate formal malware dossiers
- Export sanitized, professional multi-page PDF reports and machine-readable JSON dossiers

---

## 1. Core Design Principles & Epistemological Boundaries

### Strict Epistemological Separation
- **Automated Evidence vs. Analyst Notes:** Automated verdicts, ML confidence scores, heuristic risk scores, and telemetry observations are immutable outputs of deterministic analysis engines. Analyst-authored notes and bookmarks are **never** permitted to alter automated scores or masquerade as automated facts.
- **Attribution Guardrails:** Technical similarity clustering is explicitly identified as candidate overlap and is **never** presented as confirmed threat actor, campaign, or malware family attribution.
- **Loading & Partial States:** The workspace handles missing telemetry, unexecuted engines, or partial runs by rendering explicit unavailable/unknown states rather than interpreting missing data as benign proof.

---

## 2. Investigation Workspace Subsystems

```
                                  ┌──────────────────────────┐
                                  │   Investigation Service  │
                                  └─────────────┬────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 │                              │                              │
                 ▼                              ▼                              ▼
     ┌───────────────────────┐      ┌───────────────────────┐      ┌───────────────────────┐
     │  Evidence Filtering   │      │  Bookmarks & Notes    │      │   Report Generator    │
     │  - Source / Category  │      │  - Target References  │      │   - Executive Summary │
     │  - Epistemology Level │      │  - Analyst Metadata   │      │   - Epistemology Tree │
     │  - Role / Strength    │      │  - Separate Store     │      │   - Subsystem Digests │
     │  - Target / Text Query│      │  - Native Persistence │      │   - Limitations Matrix│
     └───────────────────────┘      └───────────────────────┘      └───────────┬───────────┘
                                                                               │
                                                                 ┌─────────────┴─────────────┐
                                                                 ▼                           ▼
                                                     ┌───────────────────────┐   ┌───────────────────────┐
                                                     │  Pure Python PDF Gen  │   │  JSON Dossier Export  │
                                                     │  - Multi-page PDF 1.4 │   │  - Machine-readable   │
                                                     │  - Text Sanitization  │   │  - Strict Versioned   │
                                                     │  - Path / XSS Safety  │   │  - Deterministic      │
                                                     └───────────────────────┘   └───────────────────────┘
```

### A. Investigation Workspaces (`/api/v1/samples/{id}/investigation`)
Provides an aggregated snapshot of an active investigation including:
- Sample metadata and file format details
- Subsystem coverage matrix (`static`, `reverse`, `behavior`, `detection`, `ml`, `similarity`, `assessment`)
- Explainable verdict summary and confidence breakdown
- Curated bookmarks and human analyst notes

### B. Evidence Filtering Engine (`/api/v1/samples/{id}/evidence`)
Enables multi-dimensional slicing across all synthesized evidence items without mutating underlying evidence provenance:
- **`source`**: Filter by analysis layer (`STATIC`, `REVERSE`, `BEHAVIOR`, `RULES`, `ML`, `SIMILARITY`)
- **`role`**: Filter by hypothesis support (`SUPPORTING`, `CONTRADICTING`, `NEUTRAL`)
- **`observation_level`**: Filter by epistemological certainty (`OBSERVED`, `INFERRED`, `POSSIBLE`)
- **`process` / `function` / `technique`**: Filter by specific technical entity
- **`query`**: Full-text search across finding statements, source IDs, and provenance references

### C. Bookmarks Subsystem (`/api/v1/samples/{id}/bookmarks`)
Allows analysts to bookmark specific findings across analysis layers:
- Supported target types: `evidence`, `function`, `timeline_event`, `cfg_block`, `network_event`, `registry_event`, `process`, `dropped_file`, `attack_technique`, `similarity_match`, `custom`.
- Provides jump navigation directly from bookmarks to relevant analysis views.

### D. Analyst Notes Subsystem (`/api/v1/samples/{id}/notes`)
Provides full CRUD capabilities for human notes:
- Properties: `note_id`, `author`, `title`, `content`, `attached_evidence_ids`, `attached_bookmark_ids`, `tags`, `created_at`, `updated_at`.
- Strict UI and export labeling: Clearly demarcated with `[HUMAN ANALYST NOTE]` disclaimers.

---

## 3. Dossier Generation & Export Engine

### Report Synthesis Pipeline (`ReportGenerator`)
Consolidates all analysis layers into a structured dossier schema:
1. **Report Version Metadata:** IGRIS version (`0.1.0`), schema version (`1.0.0`), engine versions, rule engine version (`v1.2`), ATT&CK dataset version (`v14.1`).
2. **Executive Summary:** Epistemologically structured narrative.
3. **Sample Identification:** Multi-algorithm cryptographic hashes, detected format, architecture, and file size.
4. **Verdict & Risk Assessment:** Primary verdict (`HIGHLY_SUSPICIOUS`, `SUSPICIOUS`, `LIKELY_BENIGN`, `UNKNOWN`), categorical risk level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), mathematical risk score formula and factor breakdown, multi-factor confidence ratings.
5. **Epistemological Findings:** Observed facts, inferred rule deductions, and cluster hypotheses.
6. **Subsystem Summaries:** Digest of static features, decompiled functions, behavioral process trees, network sockets, ATT&CK techniques, ML classifications, and similarity matches.
7. **Traceable Evidence Matrix:** Complete table of evidence items with provenance sources.
8. **Analyst Notes & Bookmarks:** Curation section with explicit provenance disclaimer.
9. **Analytical Limitations:** Boundary conditions and attribution guardrails.

### Pure Python Zero-Dependency PDF Engine (`PurePDFRenderer`)
- Implements standard `%PDF-1.4` binary generation with cross-reference tables, font definitions, and dynamic multi-page flow.
- Features:
  - Header & footer pagination (`Page X of Y`)
  - Verdict stamp boxes color-coded by severity
  - Word wrapping for narratives and multi-line technical statements
  - **Export Security:** Rejects path traversal, strips unsafe control characters (`\x00-\x1f`), escapes PDF syntax delimiters (`(`, `)`, `\`), and sanitizes untrusted sample-derived strings.

---

## 4. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/samples/{id}/investigation` | Get aggregated investigation workspace |
| `GET` | `/api/v1/samples/{id}/evidence` | Query and filter multi-layered evidence items |
| `POST` | `/api/v1/samples/{id}/bookmarks` | Create a new finding bookmark |
| `GET` | `/api/v1/samples/{id}/bookmarks` | List bookmarks for a sample |
| `DELETE` | `/api/v1/samples/{id}/bookmarks/{bmk_id}` | Delete a bookmark |
| `POST` | `/api/v1/samples/{id}/notes` | Create an analyst note |
| `GET` | `/api/v1/samples/{id}/notes` | List analyst notes for a sample |
| `PATCH` | `/api/v1/samples/{id}/notes/{note_id}` | Update an analyst note |
| `DELETE` | `/api/v1/samples/{id}/notes/{note_id}` | Delete an analyst note |
| `POST` | `/api/v1/samples/{id}/report` | Generate complete investigation dossier |
| `GET` | `/api/v1/samples/{id}/report/json` | Download machine-readable JSON dossier |
| `GET` | `/api/v1/samples/{id}/report/pdf` | Download sanitized multi-page PDF report |
