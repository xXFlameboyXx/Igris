# Phase 14: Analysis Job Orchestration & Pipeline Architecture

## 1. Overview & Objective

The **Igris Orchestration Subsystem** acts as the central coordination plane across all 10 independent analysis engines developed throughout Phases 1–13. Rather than introducing duplicated analysis logic or monolithic assumptions, the orchestration layer coordinates execution through an asynchronous, stage-aware pipeline that enforces:

- **Strict Evidence Provenance:** Preserves exact source identifiers, detection rules, function IDs, and timestamps.
- **Stage Failure Isolation:** An unexpected failure in one stage (e.g. reverse disassembly of an encrypted section) never blocks independent pipelines (e.g. behavioral sandbox or ML scoring).
- **Preservation of Partial Results:** Downstream explainable assessment and reporting consume all successful telemetry and explicitly document failed/skipped subsystems as analytical limitations rather than fabricating negative evidence.
- **Idempotency & Reproducibility:** Jobs are tracked by deterministic idempotency keys derived from sample hashes, engine versions, and stage configurations.
- **Epistemological Integrity:** Reuses the Phase 11 explainability engine and Phase 13 reporting dossiers without creating second verdict calculators.

---

## 2. Pipeline Stages

The pipeline comprises 11 explicit stages:

```
Upload Sample
     │
     ▼
[FILE_INTELLIGENCE]
     │
     ├───────────────────────────┬───────────────────────────┐
     ▼                           ▼                           ▼
[STATIC_ANALYSIS]        [REVERSE_ANALYSIS]             [BEHAVIOR]
     │                           │                           │
     ├──────────────┬────────────┤                           │
     ▼              ▼            ▼                           │
[DETECTION]        [ML]     [SIMILARITY]                     │
     │              │            │                           │
     ▼              │            │                           │
[THREAT_INTEL]      │            │                           │
     │              │            │                           │
     └──────────────┴─────┬──────┴───────────────────────────┘
                          ▼
                [EVIDENCE_CORRELATION]
                          ▼
                    [ASSESSMENT]
                          ▼
                       [REPORT]
```

### Stage Summary Table

| Stage Name | Dependencies | Primary Engine Service | Output Artifact |
|---|---|---|---|
| `FILE_INTELLIGENCE` | None | `FileIntelligenceService` | Formats, hashes, entropy, PE/ELF headers |
| `STATIC_ANALYSIS` | `[FILE_INTELLIGENCE]` | `StaticAnalysisService` | Imports, exports, strings, entropy spikes |
| `DETECTION` | `[STATIC_ANALYSIS]` | `DetectionService` | Heuristics, signatures, detection rules |
| `REVERSE_ANALYSIS` | `[FILE_INTELLIGENCE]` | `ReverseAnalysisService` | Disassembly, function graphs (CFG) |
| `ML` | `[STATIC_ANALYSIS]` | `MLService` | ML probability score + SHAP explainability |
| `BEHAVIOR` | `[FILE_INTELLIGENCE]` | `BehaviorAnalysisService` | Process trees, registry keys, network events |
| `SIMILARITY` | `[STATIC_ANALYSIS]` | `SimilarityService` | TLSH, SSDEEP, clustering (cluster_only) |
| `THREAT_INTELLIGENCE` | `[DETECTION]` | `ThreatIntelligenceService` | ATT&CK techniques, behavior narratives |
| `EVIDENCE_CORRELATION` | `[STATIC_ANALYSIS]` | `AssessmentService` | Cross-engine evidence correlation |
| `ASSESSMENT` | `[EVIDENCE_CORRELATION]` | `AssessmentService` | Explainable verdict, confidence breakdown |
| `REPORT` | `[ASSESSMENT]` | `ReportingService` | Deterministic JSON dossier & PDF document |

---

## 3. Job Lifecycle & State Machine

An analysis job progresses through explicit states:

```
[QUEUED] ──► [RUNNING] ──► [COMPLETED] (All or partial stages successful)
    │            │
    │            ├──► [FAILED] (Critical initial stage or all stages failed)
    │            │
    │            ├──► [TIMEOUT] (Execution exceeded stage or job limits)
    │            │
    └────────────┴──► [CANCELLED] (Explicitly stopped by analyst)
```

### Stage States
- `NOT_STARTED`: Stage initialized in definition graph.
- `QUEUED`: Ready for execution in the job queue.
- `RUNNING`: Actively executing service analysis.
- `COMPLETED`: Completed successfully with `result_available: true`.
- `FAILED`: Failed with recorded safe error message and failure category.
- `SKIPPED`: Skipped because a required hard dependency did not complete.
- `CANCELLED`: Cancelled due to job-level cancellation.
- `TIMEOUT`: Exceeded configured execution deadline.

---

## 4. Failure Isolation & Retry Semantics

### Error Classification
Errors encountered during stage dispatch are classified as:
1. **`RETRYABLE`**: Transient infrastructure faults, socket connection timeouts, or temporary lock contentions. Retried up to `max_retries` (default: 2) with backoff.
2. **`NON_RETRYABLE`**: Deterministic parser failures, unsupported architectures, corrupted binary headers, or validation errors. Fails immediately on attempt 1 without creating infinite loops.
3. **`TIMEOUT`**: Execution exceeded the configured timeout threshold.
4. **`CANCELLED`**: Job was aborted by the analyst.

### Safe Error Sanitation
Internal stack traces are never exposed over standard REST API responses. All errors are sanitized into high-level safe messages (e.g., `"Corrupted section header or unsupported packer encryption"`) while full diagnostics remain in structured server logs.

---

## 5. Partial Results & Epistemological Safety

When an optional subsystem encounters a failure (for example, `REVERSE_ANALYSIS` fails due to packing obfuscation):
1. The orchestrator isolates the failure to that stage and records `status: FAILED`.
2. Independent stages (`BEHAVIOR`, `STATIC_ANALYSIS`, `DETECTION`, `ML`) continue execution uninterrupted.
3. `AssessmentService` generates the final explainable verdict based on observed and inferred facts from the completed stages.
4. Missing stages are automatically recorded as `uncertainties` and `limitations` in the report, adjusting `confidence_breakdown` accordingly without fabricating negative proof.

---

## 6. Idempotency & Resource Limits

### Idempotency Key Computation
```
idempotency_key = sha256(sample_sha256 + ":" + sorted(enabled_stages) + ":" + engine_versions)
```
- When a job with an identical key exists in `COMPLETED` or `RUNNING` state, the orchestrator returns the existing job record unless `force_reanalyze: true` is explicitly requested.

### Configurable Limits
- `max_upload_bytes`: Maximum sample size (default 50 MB).
- `analysis_timeout_seconds`: Per-stage and per-job analysis timeout.
- `max_retries`: Maximum retry attempts for transient failures (default 2, clamped 0–5).
- `sandbox_timeout_seconds`: Execution limit for behavioral sandboxing.

---

## 7. REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/analyses` | Initiates or schedules an analysis job pipeline. |
| `GET` | `/api/v1/analyses` | Lists recent pipeline jobs (filterable by `sample_id`). |
| `GET` | `/api/v1/analyses/{id}` | Returns complete analysis job details, stage metrics, and errors. |
| `GET` | `/api/v1/analyses/{id}/status` | Concise real-time status and progress percentage. |
| `POST` | `/api/v1/analyses/{id}/cancel` | Aborts an active or queued analysis job. |

---

## 8. Frontend Integration

The Analyst Console includes a dedicated **Pipeline & Jobs View** (`AnalysisPipelineView.tsx`) featuring:
- Real-time animated progress bar and stage counter.
- Stage-by-stage execution cards with metrics (`duration_ms`, `retry_count`, error summaries).
- Interactive navigation jump links to inspect subsystem evidence in dedicated views.
- Job control toolbar (Run Pipeline, Force Re-run, Cancel Pipeline, Live Polling Toggle).
- Preloaded synthetic demonstrations for both complete (11/11 stages) and partial failure scenarios.
