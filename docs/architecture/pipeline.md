# End-to-End Analysis Pipeline & Epistemological Evidence Architecture

## 1. Architectural Overview

The **Igris Malware Analysis & Intelligence Platform** organizes analysis across a directed acyclic graph (DAG) of specialized engines. Rather than treating detection as an opaque black box, Igris structures all analytical outputs as discrete, attributable **Evidence Items** classified by epistemological certainty.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               ANALYSIS PIPELINE DAG                                    │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                             [ 1. Sample Upload ]
                        (Multipart Stream, SHA256 Ingest)
                                      │
                                      ▼
                          [ 2. File Intelligence ]
                     (PE/ELF Headers, Hashes, Entropy)
                                      │
                   ┌──────────────────┴──────────────────┐
                   ▼                                     ▼
         [ 3. Static Analysis ]                 [ 4. Reverse Eng ]
     (Strings, Sections, Imports)           (Capstone Linear Sweep, CFG)
                   │                                     │
                   ▼                                     ▼
         [ 5. Detection Rules ]                 [ 6. Machine Learning ]
       (YAML Rules, Heuristics)              (Baseline Classifiers, SHAP)
                   │                                     │
                   └──────────────────┬──────────────────┘
                                      ▼
                         [ 7. Behavioral Telemetry ]
                     (Process, Registry, Network Traces)
                                      │
                                      ▼
                        [ 8. Similarity Clustering ]
                            (SSDEEP, TLSH Hashes)
                                      │
                                      ▼
                        [ 9. Threat Intelligence ]
                     (MITRE ATT&CK Technique Mapping)
                                      │
                                      ▼
                      [ 10. Epistemology Correlation ]
                     (OBSERVED / INFERRED / POSSIBLE)
                                      │
                                      ▼
                      [ 11. Explainable Assessment ]
                     (Risk Score Formula, Verdict)
                                      │
                   ┌──────────────────┴──────────────────┐
                   ▼                                     ▼
      [ 12. Investigation Workspace ]          [ 13. PDF / JSON Dossier ]
       (Bookmarks, Timeline, Notes)           (Pure Python In-Memory PDF)
```

---

## 2. Fault-Tolerant Partial-Result Execution

In real-world security operations, binaries may be corrupted, stripped, encrypted, or packed, causing individual analysis stages to fail.

The [`OrchestrationService`](file:///e:/IGRIS/backend/src/igris/orchestration/service.py) guarantees **partial-result preservation**:
- If an individual engine fails (e.g. Capstone encounters non-executable data or an ELF parser encounters malformed section counts), the error is recorded within that stage's status.
- Downstream stages execute using available upstream metadata.
- Assessment engines compute verdicts based on accumulated valid evidence, explicitly noting missing, skipped, or failed stages under `uncertainties` and `limitations`.

---

## 3. Epistemology Framework: Certainty & Provenance

To eliminate hallucinated verdicts and ungrounded threat actor claims, Igris enforces a three-tier epistemological model:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              EPISTEMOLOGICAL CERTAINTY                                 │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. OBSERVED  │ Immutable cryptographic and structural facts:                           │
│              │ • SHA-256 / MD5 digests, file size, whole-file Shannon entropy          │
│              │ • Parsed PE/ELF header boundaries, section tables, raw bytes            │
│              │ • Linear disassembly instructions extracted at verified entry points    │
│              │ • Literal ASCII / UTF-8 strings extracted from binary sections          │
├──────────────┼─────────────────────────────────────────────────────────────────────────┤
│ 2. INFERRED  │ Logical deductions and deterministic structural mappings:               │
│              │ • Function call graphs and basic block control flow structures (CFGs)   │
│              │ • API capability categorizations (e.g. Process Injection, Encryption)   │
│              │ • MITRE ATT&CK technique associations mapped from verified indicators   │
├──────────────┼─────────────────────────────────────────────────────────────────────────┤
│ 3. POSSIBLE  │ Probabilistic predictions, heuristic signals, and similarity matches:   │
│              │ • Static detection rule hits and heuristic scoring flags                │
│              │ • Machine learning classifier predictions and probability scores        │
│              │ • Fuzzy hash similarity clusters (SSDEEP / TLSH)                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Evidence Item Schema
Every finding produced by any analysis engine is formatted as a standardized `EvidenceItem`:
- `evidence_id`: Unique identifier (e.g. `ev-pe-header-001`, `ev-rule-hit-042`).
- `source_component`: Subsystem emitting the evidence (e.g. `file_intelligence`, `static_analysis`, `reverse_engineering`).
- `epistemology`: `OBSERVED`, `INFERRED`, or `POSSIBLE`.
- `confidence`: Qualitative confidence level (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, `TENTATIVE`).
- `weight`: Numerical impact on risk scoring (`[-10.0, +10.0]`).
- `rationale`: Human-readable explanation of why this evidence matters.
- `data`: Machine-readable dictionary of underlying telemetry.

---

## 4. Explainable Assessment & Verdict Synthesis

Downstream components (reporting, UI, investigation workspaces) **never independently invent or alter verdicts**. All verdicts are synthesized centrally by [`AssessmentEngine`](file:///e:/IGRIS/backend/src/igris/intelligence/assessment/explanation.py).

### 4.1 Risk Score Formula
The total evidence risk score $S \in [0, 100]$ is computed deterministically:
$$S = \min\left(100, \max\left(0, \sum_{i \in E_{\text{pos}}} w_i - 0.5 \times \sum_{j \in E_{\text{mit}}} w_j\right)\right)$$
where:
- $E_{\text{pos}}$ is the set of suspicious/malicious evidence weights.
- $E_{\text{mit}}$ is the set of benign/mitigating evidence weights (e.g. valid digital signatures, standard runtime metadata).

### 4.2 Monotonic Verdict Mapping
The risk score maps monotonically to discrete verdicts:
- **`BENIGN`:** $S < 20$ (with zero high-severity detection hits)
- **`SUSPICIOUS`:** $20 \le S < 60$
- **`HIGHLY_SUSPICIOUS`:** $60 \le S < 85$
- **`MALICIOUS`:** $S \ge 85$ (or confirmed high-confidence malicious capability)
- **`INCONCLUSIVE`:** Insufficient evidence (e.g. encrypted payload with all parsers failing)
