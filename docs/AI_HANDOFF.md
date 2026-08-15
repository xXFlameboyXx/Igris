# Igris AI Engineering Handoff

Last reviewed from repository state: current working tree, complete through Phase 7.

This handoff is based on direct inspection of the repository. It documents what is actually implemented, including known gaps and inconsistencies. It does not describe planned features as complete.

## 1. Project Overview

Igris is the Intelligent Graph-based Reverse-engineering and Inspection System. It is an explainable malware-analysis research platform with a FastAPI backend and a minimal React/Vite frontend.

The implemented backend accepts files as inert data, stores them in controlled local storage, extracts file metadata, runs deterministic static analysis, applies rule/heuristic detection, performs limited offline reverse-engineering analysis, maps evidence into higher-level threat-intelligence hypotheses, runs a reproducible synthetic ML baseline as an additional evidence source, and provides a behavioral-analysis subsystem with deterministic synthetic telemetry and sandbox abstractions.

Igris currently does not execute uploaded samples. It does not implement real VM/sandbox execution, live dynamic analysis, authentication, RBAC, production-grade authorization, malware-family attribution, similarity analysis, or a full analyst UI.

## 2. Current Implementation Status

### Phase 0: Foundation

Implemented:

- FastAPI app factory in `backend/src/igris/main.py`.
- Versioned API router under `/api/v1`.
- Health endpoints at `/health` and `/api/v1/health`.
- Central settings via Pydantic Settings in `backend/src/igris/core/config.py`.
- Structured JSON logging in `backend/src/igris/core/logging.py`.
- Request ID middleware in `backend/src/igris/middleware/request_id.py`.
- Centralized error envelope in `backend/src/igris/core/errors.py`.
- Storage and repository abstractions.
- Docker files and compose file.
- Minimal React/Vite frontend health shell.
- Security/threat-model docs.

Not implemented:

- Authentication/authorization.
- Background worker runtime.
- Queue implementation.
- Production deployment hardening.

### Phase 1: File Intelligence

Implemented:

- Upload endpoint stores files as inert `.sample` blobs.
- Streaming upload hashing and size enforcement.
- SHA-256, SHA-1, MD5.
- Whole-file entropy.
- Filename sanitization.
- PE, ELF, text, empty, unknown format detection.
- Basic PE metadata: headers, sections, imports/exports/resources status, entry point, architecture.
- Basic ELF metadata: headers, sections, program headers, entry point, architecture.
- Metadata persisted in repository JSONB/JSON/in-memory.

Key files:

- `backend/src/igris/analysis/file_intelligence/service.py`
- `backend/src/igris/analysis/file_intelligence/analyzer.py`
- `backend/src/igris/analysis/file_intelligence/pe.py`
- `backend/src/igris/analysis/file_intelligence/elf.py`
- `backend/src/igris/schemas/file_intelligence.py`

Not implemented:

- Archive extraction.
- Rich resource parsing.
- Authenticated sample ownership.
- Malware execution or sandboxing.

### Phase 2: Static Analysis

Implemented:

- String extraction for ASCII and UTF-16LE.
- String categorization: URL, IP, domain, email, paths, registry paths, command interpreters, suspicious keywords, generic.
- Import/API category normalization.
- API-like string references.
- PE-only static features: resources, overlay, TLS callback directory, executable/writable sections, suspicious entry point section.
- Static evidence records with severity, confidence, descriptions, technical details, locations, related objects.
- Versioned static feature vector: `static-feature-vector/v1`.

Key files:

- `backend/src/igris/analysis/static_analysis/analyzer.py`
- `backend/src/igris/analysis/static_analysis/strings.py`
- `backend/src/igris/analysis/static_analysis/taxonomy.py`
- `backend/src/igris/analysis/static_analysis/pe_features.py`
- `backend/src/igris/schemas/static_analysis.py`

Not implemented:

- Archive analysis.
- Rich import reconstruction beyond current parser.
- Dynamic or behavioral features.

### Phase 3: Detection

Implemented:

- Declarative rule engine loading JSON rules from `config/rules/static_rules.json`.
- Deterministic heuristic engine.
- Transparent scoring with rule, heuristic, and evidence contributions.
- Statuses: `BENIGN`, `SUSPICIOUS`, `HIGHLY_SUSPICIOUS`, `UNKNOWN`.
- Detection result cached on the `Sample`.
- Rule validation fails closed on invalid rule files.

Key files:

- `backend/src/igris/detection/engine.py`
- `backend/src/igris/detection/rules.py`
- `backend/src/igris/detection/heuristics.py`
- `backend/src/igris/detection/scoring.py`
- `backend/src/igris/schemas/detection.py`
- `config/rules/static_rules.json`

Implemented rules:

- `IGRIS-RULE-0001`: networking indicators with suspicious strings.
- `IGRIS-RULE-0002`: process manipulation with writable executable section.
- `IGRIS-RULE-0003`: multiple packing indicators.

Not implemented:

- YARA dependency/runtime.
- Malware verdict guarantees.
- Runtime rule authoring API.

### Phase 4: Reverse Engineering

Implemented:

- Capstone-backed disassembly for supported architectures.
- Entry-point and direct-call-oriented function recovery.
- Basic blocks, CFGs, call graph.
- Referenced string/API correlation.
- Function evidence: string/API correlation, suspicious API call, executable memory operation, unusual control flow, encoded constants, suspicious string reference, sensitive capability call.
- Graceful unsupported status for unsupported architectures or malformed input.

Key files:

- `backend/src/igris/analysis/reverse_analysis/analyzer.py`
- `backend/src/igris/analysis/reverse_analysis/service.py`
- `backend/src/igris/schemas/reverse_analysis.py`

Not implemented:

- Full binary lifting.
- Decompilation.
- Full recursive traversal.
- Symbolic execution.
- Execution of samples.

### Phase 5: Threat Intelligence

Implemented:

- Capability taxonomy.
- ATT&CK mapping dataset in `config/intelligence/attack_mappings.json`.
- Evidence-driven mapper.
- Evidence graph: Observation -> Indicator -> Capability -> ATT&CK Technique.
- Behavior hypotheses and narrative generation.
- Attribution placeholder that explicitly does not perform attribution.
- Endpoints for threat assessment, capabilities, ATT&CK mappings, evidence relationships, and narrative.

Key files:

- `backend/src/igris/intelligence/threat/mapper.py`
- `backend/src/igris/intelligence/threat/service.py`
- `backend/src/igris/schemas/threat_intelligence.py`
- `config/intelligence/attack_mappings.json`

Implemented ATT&CK mappings include:

- `T1547.001` Registry Run Keys / Startup Folder.
- `T1059` Command and Scripting Interpreter.
- `T1027` Obfuscated Files or Information.
- `T1055` Process Injection.
- `T1071` Application Layer Protocol.
- `T1555` Credentials from Password Stores.

Not implemented:

- Strong actor attribution.
- Malware family attribution.
- External threat-intelligence feeds.
- Similarity engine.

### Phase 6: Machine Learning

Implemented:

- ML feature schema: `ml-static-reverse-feature-vector/v1`.
- Deterministic ML feature extraction from static and reverse-analysis results.
- Ablation feature-set labels: `static_only`, `static_reverse`, `static_future_behavior`.
- Synthetic legally safe dataset manifest at `config/ml/synthetic_dataset.json`.
- Dataset ingestion and leakage-aware split helper.
- Baseline training for Logistic Regression, Random Forest, Gradient Boosting.
- Evaluation metrics: precision, recall, F1, confusion matrix, false-positive rate, ROC-AUC, inference time.
- Model registry: `config/ml/model_registry.json`.
- Model artifact: `config/ml/models/synthetic-phase6-v1-random_forest-v1.joblib`.
- Inference service with model/version/schema checks.
- `MLPrediction` with uncalibrated score and `calibrated_probability = null`.
- Experiment metadata endpoint and inference endpoints.

Key files:

- `backend/src/igris/ml/features.py`
- `backend/src/igris/ml/dataset.py`
- `backend/src/igris/ml/training.py`
- `backend/src/igris/ml/registry.py`
- `backend/src/igris/ml/service.py`
- `backend/src/igris/schemas/ml.py`
- `config/ml/*`

Not implemented:

- Real malware/benign corpus ingestion.
- Probability calibration.
- Model retraining endpoint.
- Production model registry backend.
- Claim of operational ML performance.

### Phase 7: Behavior Analysis

Implemented:

- Comprehensive behavior Pydantic schemas: `BehaviorAnalysisResult`, `ProcessEvent`, `FileEvent`, `RegistryEvent`, `NetworkEvent`, `DroppedFile`, `MutexEvent`, `SandboxMetadata`, `SandboxResourceLimits`, `ArtifactRetentionPolicy`, and `BehaviorEvidence` with 10-type taxonomy.
- Deterministic `SyntheticBehaviorAnalyzer` implementing 6 fixed scenarios: `benign`, `process_activity`, `file_activity`, `network_activity`, `persistence_activity`, `multi_stage_activity`.
- `BehaviorAnalysisService` coordinating sample state, executing synthetic simulation on explicit analyst request, caching on `Sample.behavior_analysis`, and invalidating downstream derived results upon re-analysis.
- Sample-scoped endpoints:
  - `POST /api/v1/samples/{sample_id}/behavior-analysis`
  - `GET /api/v1/samples/{sample_id}/behavior-analysis`
  - `GET /api/v1/samples/{sample_id}/behavior-events`
  - `GET /api/v1/samples/{sample_id}/behavior-evidence`
- Sandbox abstractions for future external execution: `SandboxController` abstract base class, `SandboxWorkItem`, `SandboxJobStatus`, and `InProcessJobQueue` for dev/test.
- Downstream evidence consumption in Phase 3 detection scoring heuristics, Phase 5 threat intelligence mapping, and Phase 6 ML feature extraction (`static_future_behavior` slots).
- 26 backend unit tests in `tests/backend/test_behavior_analysis.py`.
- Documentation: `docs/behavior-analysis.md` and `docs/sandbox-threat-model.md`.

Key files:

- `backend/src/igris/schemas/behavior_analysis.py`
- `backend/src/igris/analysis/behavioral/synthetic.py`
- `backend/src/igris/analysis/behavioral/service.py`
- `backend/src/igris/sandbox/controller.py`
- `backend/src/igris/workers/models.py`
- `backend/src/igris/workers/queue.py`
- `backend/src/igris/detection/behavior.py`

Not implemented:

- Real disposable VM / microVM / container sandbox runner.
- Live malware or sample binary execution.
- Subprocess or network activity from analyzer.
- Distributed worker runtime (e.g., Celery/Redis).
- Real network simulation or sinkholing.

## 3. Technology Stack

### Backend Runtime

| Package | Locked version | Purpose | Where used |
| --- | ---: | --- | --- |
| Python | `>=3.11`; current environment is Python 3.12 | Backend runtime | Entire backend |
| FastAPI | `0.141.1` | API framework | `igris.main`, `igris.api.v1.*` |
| Starlette | transitive | ASGI foundation and middleware | FastAPI, request middleware |
| Pydantic | `2.13.4` | Data models and validation | `backend/src/igris/schemas/*` |
| pydantic-settings | `2.15.0` | Environment-driven settings | `igris.core.config` |
| python-multipart | `0.0.32` | File upload parsing | `UploadFile` endpoint |
| Uvicorn | `0.52.1` | ASGI server | dev server, Docker backend command |
| psycopg[binary] | `3.3.4` | PostgreSQL access | `PostgresSampleMetadataRepository` |
| Capstone | `5.0.9` | Disassembly engine | Phase 4 reverse analysis |
| scikit-learn | `1.9.0` | ML baselines and inference | Phase 6 training/service |
| joblib | `1.5.3` | Model artifact serialization | Phase 6 registry/training |
| numpy | `2.5.2` for Python >= 3.12 | ML numeric dependency | scikit-learn |
| scipy | `1.18.0` for Python >= 3.12 | ML numeric dependency | scikit-learn |

### Backend Development

| Package | Locked version | Purpose |
| --- | ---: | --- |
| pytest | `8.4.2` | Backend tests |
| pytest-cov | `5.0.0` | Coverage support, not currently required in default command |
| mypy | `1.20.2` | Static type checking |
| ruff | `0.16.2` | Linting |
| httpx | `0.28.1` | FastAPI TestClient dependency |
| hatchling | build dependency | Python package build backend |

### Frontend

Important versions from `frontend/package-lock.json`:

| Package | Locked version | Purpose |
| --- | ---: | --- |
| React | `19.2.8` | UI |
| react-dom | `19.2.8` | DOM renderer |
| Vite | `6.4.3` | Dev/build tooling |
| @vitejs/plugin-react | installed via package lock | React/Vite integration |
| TypeScript | `5.9.3` | Type checking |
| ESLint | `9.39.5` | Linting |
| eslint-plugin-react-hooks | `5.2.0` | React hook lint rules |
| eslint-plugin-react-refresh | `0.4.26` | Vite/React refresh linting |
| typescript-eslint | `8.66.0` | TS lint support |
| globals | `15.15.0` | ESLint globals |

### Infrastructure

- Docker backend: `python:3.12-slim`.
- Docker frontend build: `node:22-alpine`.
- Docker frontend runtime: `nginx:1.27-alpine`.
- Docker compose Postgres: `postgres:17-alpine`.

## 4. Repository Structure

Important top-level files:

- `pyproject.toml`: Python package metadata, dependencies, pytest/ruff/mypy configuration.
- `uv.lock`: locked Python dependency graph.
- `README.md`: user-facing project overview.
- `.env.example`: environment variable template.
- `docker-compose.yml`: local Postgres/backend/frontend services.
- `docker/`: backend/frontend Dockerfiles.
- `frontend/`: React/Vite frontend.
- `backend/src/igris/`: backend package.
- `tests/backend/`: backend tests and binary fixtures.
- `docs/`: architecture, development, security, phase-specific documentation.
- `config/`: non-secret rule, ATT&CK mapping, and ML artifacts.

Important backend directories:

- `api/v1/`: FastAPI routers.
- `core/`: config, errors, logging, request context.
- `middleware/`: request ID middleware.
- `storage/`: sample binary and metadata repositories.
- `analysis/file_intelligence/`: Phase 1.
- `analysis/static_analysis/`: Phase 2.
- `detection/`: Phase 3.
- `analysis/reverse_analysis/`: Phase 4.
- `intelligence/threat/`: Phase 5.
- `ml/`: Phase 6.
- `schemas/`: Pydantic response/internal models.
- `workers/`, `reporting/`, `analysis/behavioral/`, `analysis/similarity/`: placeholder interfaces only.

## 5. Backend Architecture

### Application Entry Point

- `backend/src/igris/main.py`
- `create_app(settings: Settings | None = None)` creates the FastAPI app.
- App state stores:
  - `settings`
  - `sample_storage`
  - `metadata_repository`
- Routers:
  - `/api/v1` via `igris.api.v1.router`
  - root `/health` via health router
- Middleware:
  - `RequestIdMiddleware`
- Exception handlers:
  - `AppError`
  - generic `Exception`
  - Starlette HTTP exceptions
  - request validation errors

### Routers

- `backend/src/igris/api/v1/health.py`: health endpoint.
- `backend/src/igris/api/v1/samples.py`: sample upload and sample-scoped analysis endpoints.
- `backend/src/igris/api/v1/ml.py`: global ML metadata/experiments.
- `backend/src/igris/api/v1/router.py`: router composition.

### Services

Services coordinate repositories, storage, analyzers, and caching on `Sample`:

- `FileIntelligenceService`
- `StaticAnalysisService`
- `DetectionService`
- `ReverseAnalysisService`
- `ThreatIntelligenceService`
- `MLService`

### Analysis Engines

- Phase 1 file intelligence reads file bytes and parses metadata safely.
- Phase 2 static analysis reads sample bytes and metadata, then emits strings/imports/evidence/feature vector.
- Phase 3 detection consumes `StaticAnalysisResult`.
- Phase 4 reverse analysis consumes stored sample plus static results.
- Phase 5 intelligence consumes static and reverse evidence.
- Phase 6 ML consumes static and reverse-derived features.

### Workers

There is no implemented worker runtime. `backend/src/igris/workers/interfaces.py` defines only:

- `WorkItem`
- `WorkerQueue`

### Models

All important API/internal models are Pydantic models in `backend/src/igris/schemas/`.

### Repositories

Metadata repository interface:

- `SampleMetadataRepository`

Implementations:

- `InMemorySampleMetadataRepository`: tests.
- `JsonSampleMetadataRepository`: local development JSON file.
- `PostgresSampleMetadataRepository`: PostgreSQL table storing entire `Sample` as JSONB.

Binary storage:

- `LocalSampleStorage` stores binaries under `settings.sample_storage_dir` using generated UUID `.sample` filenames.

### Configuration

Settings are in `backend/src/igris/core/config.py` and use `IGRIS_` env prefix.

Important settings:

- `metadata_backend`: `json`, `memory`, or `postgres`.
- `database_url`.
- `sample_storage_dir`.
- `metadata_storage_file`.
- `sample_temp_dir`.
- `max_upload_bytes`.
- `static_*`.
- `detection_rules_path`.
- `reverse_*`.
- `intelligence_mapping_path`.
- `ml_dataset_manifest_path`.
- `ml_model_registry_path`.
- `ml_model_dir`.

### Utilities

- `core/errors.py`: structured errors.
- `core/logging.py`: JSON logs.
- `core/request_context.py`: request ID context variable.
- `middleware/request_id.py`: request ID propagation/sanitization.

## 6. Frontend Architecture

The frontend is minimal and does not yet expose sample upload or analysis workflows.

Files:

- `frontend/src/main.tsx`: React root.
- `frontend/src/App.tsx`: only page/component.
- `frontend/src/styles.css`: page styling.
- `frontend/vite.config.ts`: dev server and proxy config.

Routes:

- No client-side router is implemented.
- Single app shell at `/`.

Components:

- `App` renders a status panel.

State management:

- Local React `useState` and `useEffect` only.
- No global state library.

API layer:

- No dedicated API client.
- `fetchHealth()` calls `GET /api/v1/health`.
- Vite proxies `/api` and `/health` to `http://localhost:8000`.

Important pages:

- Only health/status page.

## 7. Database

### Implemented Storage Backends

1. In-memory repository for tests.
2. JSON file repository for local development.
3. PostgreSQL repository for local Docker/development.

### PostgreSQL Schema

Created imperatively in `PostgresSampleMetadataRepository._ensure_schema()`:

```sql
CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples (sha256);
```

Relationships:

- No relational child tables.
- All nested analysis results are stored inside `samples.metadata` JSONB.

Migrations:

- No migration system exists.
- Schema creation is done at repository initialization.

Important indexes:

- Primary key on `sample_id`.
- `idx_samples_sha256` on `sha256`.

Sample storage references:

- `Sample.storage_ref` points to a generated filename in local binary storage.
- Stored binary files are not kept in Postgres.

## 8. API Endpoints

No authentication is implemented. All endpoints are unauthenticated.

Error responses use:

```json
{
  "success": false,
  "error": {
    "code": "...",
    "message": "..."
  },
  "request_id": "..."
}
```

### Health

| Method | Path | Purpose | Request | Response | Auth |
| --- | --- | --- | --- | --- | --- |
| GET | `/health` | Root health check | none | `HealthResponse` | none |
| GET | `/api/v1/health` | Versioned health check | none | `HealthResponse` | none |

### Samples and File Intelligence

| Method | Path | Purpose | Request | Response | Auth |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/samples` | Upload file as inert sample | multipart form field `file` | `SampleCreateResponse` | none |
| GET | `/api/v1/samples/{sample_id}` | Get sample metadata summary | path `sample_id` | `SampleResponse` | none |
| GET | `/api/v1/samples/{sample_id}/file-info` | Get file metadata/details | path `sample_id` | `FileInfoResponse` | none |

### Static Analysis

| Method | Path | Purpose | Request | Response | Auth |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/samples/{sample_id}/static-analysis` | Run or return cached static analysis | path `sample_id` | `StaticAnalysisResponse` | none |
| GET | `/api/v1/samples/{sample_id}/static-analysis` | Get cached static analysis | path `sample_id` | `StaticAnalysisResponse` | none |
| GET | `/api/v1/samples/{sample_id}/indicators` | Get static evidence only | path `sample_id` | `IndicatorsResponse` | none |

### Detection

| Method | Path | Purpose | Request | Response | Auth |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/samples/{sample_id}/detect` | Run or return cached detection | path `sample_id` | `DetectionResponse` | none |
| GET | `/api/v1/samples/{sample_id}/detection` | Get cached detection | path `sample_id` | `DetectionResponse` | none |

### Reverse Analysis

| Method | Path | Purpose | Request | Response | Auth |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/samples/{sample_id}/reverse-analysis` | Run or return cached reverse analysis | path `sample_id` | `ReverseAnalysisResponse` | none |
| GET | `/api/v1/samples/{sample_id}/reverse-analysis` | Get cached reverse analysis | path `sample_id` | `ReverseAnalysisResponse` | none |
| GET | `/api/v1/samples/{sample_id}/functions` | List reverse-engineered functions | path `sample_id` | `FunctionsResponse` | none |
| GET | `/api/v1/samples/{sample_id}/functions/{function_id}` | Get one function | path `sample_id`, `function_id` | `FunctionResponse` | none |
| GET | `/api/v1/samples/{sample_id}/cfg/{function_id}` | Get function CFG | path `sample_id`, `function_id` | `CFGResponse` | none |

### Threat Intelligence

| Method | Path | Purpose | Request | Response | Auth |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/samples/{sample_id}/threat-assessment` | Run or return cached Phase 5 assessment | path `sample_id` | `ThreatAssessmentResponse` | none |
| GET | `/api/v1/samples/{sample_id}/threat-assessment` | Get cached assessment | path `sample_id` | `ThreatAssessmentResponse` | none |
| GET | `/api/v1/samples/{sample_id}/capabilities` | Get capability hypotheses | path `sample_id` | `CapabilitiesResponse` | none |
| GET | `/api/v1/samples/{sample_id}/attack-mappings` | Get ATT&CK mappings | path `sample_id` | `TechniquesResponse` | none |
| GET | `/api/v1/samples/{sample_id}/evidence-relationships` | Get evidence graph | path `sample_id` | `EvidenceRelationshipsResponse` | none |
| GET | `/api/v1/samples/{sample_id}/narrative` | Get behavior narrative | path `sample_id` | `NarrativeResponse` | none |

### ML

| Method | Path | Purpose | Request | Response | Auth |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/ml/model-metadata` | Get model registry metadata | none | `ModelMetadataResponse` | none |
| GET | `/api/v1/ml/experiments` | Get tracked experiment results | none | `ExperimentResultsResponse` | none |
| POST | `/api/v1/samples/{sample_id}/ml-prediction` | Run or return cached ML inference | path `sample_id`, optional query `model_version` | `MLPredictionResponse` | none |
| GET | `/api/v1/samples/{sample_id}/ml-prediction` | Get cached ML prediction | path `sample_id` | `MLPredictionResponse` | none |

## 9. Analysis Pipeline

Current sample flow:

1. Client uploads a file to `POST /api/v1/samples`.
2. `FileIntelligenceService.ingest()` streams upload to temp storage under `sample_temp_dir`.
3. Upload is hashed during streaming and rejected if it exceeds `max_upload_bytes`.
4. If SHA-256 already exists, the existing sample ID is returned.
5. New sample is moved into `LocalSampleStorage` under a generated `.sample` filename.
6. File intelligence runs immediately and creates `FileMetadata`.
7. Sample record is persisted in metadata repository.
8. Static analysis runs lazily via `POST /static-analysis`, or automatically when later phases need it.
9. Detection runs lazily via `POST /detect`; it ensures static analysis exists first.
10. Reverse analysis runs lazily via `POST /reverse-analysis`; it ensures static analysis exists first.
11. Threat intelligence runs lazily via `POST /threat-assessment`; it ensures static and reverse analysis exist first.
12. ML prediction runs lazily via `POST /ml-prediction`; it ensures static and reverse analysis exist first, builds an ML vector, loads model metadata/artifact, and stores the prediction.

All analysis results are cached on the `Sample` model. Re-running the same endpoint generally returns cached results unless model-version mismatch logic applies for ML.

## 10. Data Models

Important models:

- `Sample`: internal sample record. Contains upload metadata, hashes, storage reference, file metadata, static analysis, detection, reverse analysis, threat assessment, ML prediction, timestamps.
- `FileMetadata`: file size, detected format, architecture, MIME type, entropy, timestamps, entry point, PE/ELF details, parse errors.
- `PEMetadata`: PE headers, architecture, image base, entry point, subsystem, sections, imports, exports, resources, parse warnings.
- `ELFMetadata`: ELF class, architecture, endianness, entry point, program headers, sections, dynamic libraries status, symbols status.
- `StaticAnalysisResult`: strings, normalized imports, resources, PE static features, static evidence, feature vector, limitations.
- `StaticEvidence`: evidence ID, type, source, severity, confidence, description, technical details, location, related object.
- `DetectionResult`: status, run status, heuristic score, triggered rules, heuristics, evidence, severity, confidence, explanation, score breakdown, engine version, limitations.
- `ReverseAnalysisResult`: status, schema version, disassembly metadata, functions, CFGs, call graph, function evidence, limitations.
- `FunctionEvidence`: function-level evidence type, function ID, description, confidence, details, related strings/APIs.
- `ThreatAssessment`: capabilities, techniques, evidence mappings, behavior hypotheses, graph, narrative, attribution placeholder, limitations.
- `Capability`: capability category, label, confidence, evidence IDs, source engines, explanation.
- `Technique`: ATT&CK technique ID/name, tactic, evidence IDs, confidence, source engine, mapping version.
- `EvidenceGraph`: nodes and edges linking observations to indicators to capabilities to techniques.
- `MLFeatureVector`: schema version, feature set, numeric features, missing features, limitations.
- `ModelRegistry`: active model version, model metadata list, experiment results.
- `ModelMetadata`: model version, kind, feature schema version, dataset version, hyperparameters, metrics, feature names, important features, artifact path.
- `MLPrediction`: sample ID, model version, prediction, uncalibrated score, no calibrated probability, uncertainty, contributing features, explanation, limitations.

## 11. Evidence Architecture

Evidence creation:

- Phase 2 creates `StaticEvidence` from strings, imports/API categories, section properties, and PE characteristics.
- Phase 4 creates `FunctionEvidence` from function-level disassembly, strings, APIs, control flow, and constants.
- Phase 3 consumes `StaticEvidence` for rules, heuristics, and score breakdowns.
- Phase 5 consumes static and reverse evidence, plus strings/imports, to create capabilities, techniques, mappings, and graph nodes.
- Phase 6 consumes static and reverse outputs as numeric features, not as causal proof.

Evidence storage:

- Evidence is nested inside `Sample.static_analysis`, `Sample.reverse_analysis`, `Sample.detection`, and `Sample.threat_assessment`.
- There is no separate evidence table or graph database.

Evidence linking:

- Phase 2 static evidence has deterministic IDs assigned from order/type context.
- Phase 4 function evidence is tied to `function_id`.
- Phase 5 builds graph relationships:
  - Observation -> Indicator
  - Indicator -> Capability
  - Capability -> ATT&CK Technique

Evidence consumption:

- Detection scoring consumes rules, heuristics, and static evidence severity/confidence.
- Threat intelligence consumes combinations and does not assert ATT&CK mappings from single weak signals unless rule data allows cautious possible mapping.
- ML consumes numeric features and returns an additional evidence source.

## 12. ML Architecture

Feature extraction:

- Implemented in `backend/src/igris/ml/features.py`.
- Feature schema: `ml-static-reverse-feature-vector/v1`.
- Features include file size, section count, entropy stats, import counts, API category counts, string counts, resource count, PE characteristics, static evidence counts, reverse function/instruction/CFG/complexity features, reverse evidence counts.
- Behavior feature placeholders exist and are zero until a future behavior phase exists.

Feature sets:

- `static_only`
- `static_reverse`
- `static_future_behavior`

Training pipeline:

- Implemented in `backend/src/igris/ml/training.py`.
- Loads `DatasetManifest`.
- Deduplicates by SHA-256.
- Uses provided splits or deterministic family-aware split helper.
- Trains:
  - Logistic Regression
  - Random Forest
  - Gradient Boosting
- Selects model by validation F1, then lower false-positive rate, then test F1.

Inference:

- Implemented in `backend/src/igris/ml/service.py`.
- Loads registry from `settings.ml_model_registry_path`.
- Loads joblib artifact from model metadata.
- Ensures model feature schema matches generated feature schema.
- Fails closed on missing features or model-version mismatch.
- Returns `MLPrediction` with uncalibrated score and no calibrated probability.

Model storage:

- Registry JSON: `config/ml/model_registry.json`.
- Artifact: `config/ml/models/synthetic-phase6-v1-random_forest-v1.joblib`.

Model versioning:

- Active version: `synthetic-phase6-v1-random_forest-v1`.
- Dataset version: `synthetic-phase6/v1`.
- Feature schema version: `ml-static-reverse-feature-vector/v1`.

Evaluation:

- Precision, recall, F1, false-positive rate, ROC-AUC, inference time, confusion matrix.
- Current metrics are synthetic pipeline-validation metrics only.

## 13. Existing Security Boundaries

File upload handling:

- Uploads stream to temp file.
- Max size enforced by `max_upload_bytes`.
- Hashes computed during streaming.
- Duplicate SHA-256 returns existing sample.
- Original filename stored as data; safe filename is sanitized.

Temporary storage:

- Temp files under `sample_temp_dir`.
- Temp file permissions set to `0600` on non-Windows.
- Temp files removed on failure.

Execution restrictions:

- Uploaded samples are never executed by implemented code.
- Reverse engineering disassembles bytes with Capstone only.
- ML uses extracted features only.

Parser safety:

- Parsers are custom conservative PE/ELF parsers.
- Malformed inputs are expected to return parse errors or unsupported results instead of crashing tests.
- No external command-line analysis tools are invoked.

API security:

- No authentication.
- No authorization.
- No rate limiting.
- No tenant isolation.
- Request IDs are sanitized and added to responses.
- Validation errors avoid echoing whole payloads.

Secrets:

- `.env` and `.env.*` ignored except `.env.example`.
- `IGRIS_DATABASE_URL` is secret-capable via `SecretStr`.
- Docker compose uses local development Postgres credentials only.

Database security:

- psycopg parameterized queries are used.
- Entire sample metadata stored as JSONB.
- No row-level security.
- No encryption-at-rest configuration in app.

## 14. Testing

Framework:

- pytest for backend.
- FastAPI TestClient.
- TypeScript compiler as frontend test.
- ESLint for frontend lint.
- mypy and ruff for backend quality.

Test locations:

- `tests/backend/test_health.py`
- `tests/backend/test_errors.py`
- `tests/backend/test_config.py`
- `tests/backend/test_file_intelligence.py`
- `tests/backend/test_static_analysis.py`
- `tests/backend/test_detection.py`
- `tests/backend/test_reverse_analysis.py`
- `tests/backend/test_threat_intelligence.py`
- `tests/backend/test_ml.py`
- `tests/backend/fixtures.py`

Fixture strategy:

- Synthetic PE/ELF/malformed bytes are generated in Python.
- No real malware fixtures.
- Phase 6 synthetic dataset is JSON feature data, not binary malware.

How to run:

```powershell
uv --cache-dir E:\IGRIS\.uv-cache run ruff check .
uv --cache-dir E:\IGRIS\.uv-cache run mypy
uv --cache-dir E:\IGRIS\.uv-cache run pytest
```

If Windows temp permissions fail:

```powershell
.\.venv\Scripts\pytest.exe --basetemp E:\IGRIS\.pytest-tmp
```

Current observed backend test count:

- `60 passed` using repo-local pytest temp.

Coverage:

- `pytest-cov` is installed, but default commands do not collect/report coverage.

Frontend checks:

```powershell
cd frontend
npm.cmd run lint
npm.cmd run test
npm.cmd run build
```

On this Windows host, `npm run ...` may fail due PowerShell script policy. Use `npm.cmd`.

## 15. Development Commands

Setup:

```powershell
uv --cache-dir E:\IGRIS\.uv-cache sync --extra dev
Copy-Item .env.example .env
cd frontend
npm install
```

Backend dev server:

```powershell
uv --cache-dir E:\IGRIS\.uv-cache run uvicorn igris.main:app --app-dir backend/src --reload --host 127.0.0.1 --port 8001
```

Use a different port if Windows blocks `8000` with `[WinError 10013]`.

Frontend dev server:

```powershell
cd frontend
npm.cmd run dev
```

Backend lint/type/tests:

```powershell
uv --cache-dir E:\IGRIS\.uv-cache run ruff check .
uv --cache-dir E:\IGRIS\.uv-cache run mypy
uv --cache-dir E:\IGRIS\.uv-cache run pytest
```

Frontend lint/type/build:

```powershell
cd frontend
npm.cmd run lint
npm.cmd run test
npm.cmd run build
```

Database:

```powershell
docker compose up postgres
```

With Postgres backend:

```powershell
$env:IGRIS_METADATA_BACKEND="postgres"
$env:IGRIS_DATABASE_URL="postgresql://igris:igris-dev-password@localhost:5432/igris"
uv --cache-dir E:\IGRIS\.uv-cache run uvicorn igris.main:app --app-dir backend/src --reload
```

Docker:

```powershell
docker compose up --build
```

Important Docker caveat: current backend Dockerfile copies `pyproject.toml`, `README.md`, and `backend/`, but not `config/`. Endpoints that depend on `config/rules`, `config/intelligence`, or `config/ml` may fail inside the container unless the image or compose setup is adjusted.

Reproduce Phase 6 baseline:

```powershell
uv --cache-dir E:\IGRIS\.uv-cache run python -c "from pathlib import Path; from igris.ml.dataset import load_dataset_manifest; from igris.ml.training import run_baseline_experiment, write_registry; dataset=load_dataset_manifest(Path('config/ml/synthetic_dataset.json')); registry=run_baseline_experiment(dataset=dataset, output_dir=Path('config/ml/models')); write_registry(registry, Path('config/ml/model_registry.json'))"
```

## 16. Known Limitations

- No authentication or authorization.
- No tenant model or sample ownership.
- No rate limiting.
- No API pagination.
- No sandboxing or dynamic execution.
- No background worker implementation.
- No queue implementation.
- No migration framework.
- No production database schema management.
- Docker backend image likely lacks required `config/` runtime files.
- Frontend is only a health/status shell.
- All analysis is synchronous in API process.
- File parsers are intentionally minimal.
- Reverse analysis is limited and not a full RE platform.
- Detection scoring is heuristic, not calibrated probability.
- Threat-intelligence mapping is local and limited.
- ML dataset is synthetic and not representative.
- ML probabilities are not calibrated; `calibrated_probability` is null.
- Model artifact is a joblib file in repo config, not a production registry.
- No report generation.
- No similarity analysis.
- No malware family attribution.
- No external threat-intelligence integrations.

## 17. Technical Debt

- Add migrations before evolving Postgres schema further.
- Decide whether metadata should stay JSONB-only or be normalized into tables.
- Move long-running analysis out of the API process.
- Build an actual worker queue and analysis job state model.
- Add authentication, authorization, and audit logging before multi-user use.
- Decide a safe object-store abstraction for binary samples.
- Harden Docker packaging so `config/` and ML artifacts are available at runtime.
- Add test coverage metrics and CI enforcement if desired.
- Replace or supplement minimal parsers with isolated parser workers before broad hostile intake.
- Improve frontend into actual analyst workflow or keep it intentionally minimal.
- Add model registry/version-management practices beyond JSON/joblib files.
- Clarify whether root-level `package-lock.json` should exist; frontend already has its own `frontend/package-lock.json`.
- Remove or justify tracked `tmp/demo-samples/c81c02d0ef7c4f93b1f48da0037bce7b.sample`.

## 18. Phase 7 Integration Summary

Phase 7 integrated behavioral analysis as a synthetic, evidence-producing subsystem without breaking existing static, detection, intelligence, or ML contracts.

Completed in Phase 7:

- Concrete synthetic analyzer implemented under `backend/src/igris/analysis/behavioral/synthetic.py`.
- Behavior schemas and response models in `backend/src/igris/schemas/behavior_analysis.py`.
- Nullable `behavior_analysis` field on `Sample`.
- `BehaviorAnalysisService` in `backend/src/igris/analysis/behavioral/service.py`.
- Sample-scoped endpoints in `backend/src/igris/api/v1/samples.py` (`POST`/`GET` `/behavior-analysis`, `GET` `/behavior-events`, `GET` `/behavior-evidence`).
- Queue and sandbox abstractions in `backend/src/igris/workers/` and `backend/src/igris/sandbox/controller.py`.
- Behavior evidence feeding into Phase 3 detection heuristics, Phase 5 threat intelligence, and Phase 6 ML feature extraction.
- Strict provenance tracking (`analysis_mode = "synthetic"`, `synthetic_scenario`, `network_policy = "deny_all"`).
- Complete test suite in `tests/backend/test_behavior_analysis.py` (26 tests).

## 19. DO NOT BREAK

Future agents must not break:

- Uploaded samples must remain inert data in the API/application environment.
- Do not execute uploaded binaries in backend tests, dev server, API process, or frontend.
- Existing API response models and endpoint paths.
- Existing error envelope shape.
- Request ID propagation.
- Existing `Sample` persistence compatibility unless a migration strategy exists.
- Deterministic static evidence IDs/tests.
- Detection principle: combinations of evidence, not single-signal verdicts.
- Detection wording: heuristic score, not probability.
- Threat intelligence principle: ATT&CK mappings are evidence-driven hypotheses, not proof.
- ML principle: ML is one evidence source, not "AI says malware."
- `calibrated_probability` must remain null unless actual calibration is implemented and evaluated.
- Synthetic tests must remain benign/safe and not include live malware.
- Rule and mapping loaders must validate declarative data and not execute arbitrary rule code.
- `config/rules/static_rules.json`, `config/intelligence/attack_mappings.json`, and `config/ml/model_registry.json` runtime availability.
- No secrets in `.env.example`, logs, docs, or committed config.

## 20. Recommended Next Step: Phase 8

With Phase 7 behavior schemas, synthetic engine, and sandbox abstractions verified and complete, the project is ready for Phase 8.

Recommended Phase 8 scope:

1. Expand analyst-facing frontend workflows and reporting interfaces to visualize static, reverse, detection, threat graph, ML, and behavior timelines.
2. Maintain strict security boundaries — never execute binaries in developer or application containers.

## Files Inspected

Key files inspected for this handoff:

- `README.md`
- `.env.example`
- `.gitignore`
- `pyproject.toml`
- `uv.lock`
- `docker-compose.yml`
- `docker/backend.Dockerfile`
- `docker/frontend.Dockerfile`
- `SECURITY.md`
- `scripts/check.ps1`
- `frontend/package.json`
- `frontend/package-lock.json`
- `frontend/src/App.tsx`
- `frontend/src/main.tsx`
- `frontend/src/styles.css`
- `frontend/vite.config.ts`
- `backend/src/igris/main.py`
- `backend/src/igris/api/v1/router.py`
- `backend/src/igris/api/v1/health.py`
- `backend/src/igris/api/v1/samples.py`
- `backend/src/igris/api/v1/ml.py`
- `backend/src/igris/core/config.py`
- `backend/src/igris/core/errors.py`
- `backend/src/igris/core/logging.py`
- `backend/src/igris/middleware/request_id.py`
- `backend/src/igris/storage/binary.py`
- `backend/src/igris/storage/metadata.py`
- `backend/src/igris/storage/factory.py`
- `backend/src/igris/analysis/file_intelligence/*`
- `backend/src/igris/analysis/static_analysis/*`
- `backend/src/igris/detection/*`
- `backend/src/igris/analysis/reverse_analysis/*`
- `backend/src/igris/intelligence/threat/*`
- `backend/src/igris/ml/*`
- `backend/src/igris/schemas/*`
- `backend/src/igris/workers/interfaces.py`
- `backend/src/igris/analysis/behavioral/interface.py`
- `config/rules/static_rules.json`
- `config/intelligence/attack_mappings.json`
- `config/ml/synthetic_dataset.json`
- `config/ml/model_registry.json`
- `tests/backend/*`
- `docs/analysis/*`
- `docs/detection/*`
- `docs/reverse-engineering/*`
- `docs/intelligence/*`
- `docs/ml/*`

## Inconsistencies Found

- Working tree is dirty with Phase 6 changes uncommitted at time of inspection.
- `package-lock.json` exists at repository root and is untracked; the actual frontend lockfile is `frontend/package-lock.json`.
- `tmp/demo-samples/c81c02d0ef7c4f93b1f48da0037bce7b.sample` appears tracked even though `tmp/` looks like generated data.
- Docker backend image does not copy `config/`, but detection, threat intelligence, and ML defaults rely on files under `config/`.
- `scripts/check.ps1` uses `uv run` and `npm run`; on this Windows environment project-local uv cache and `npm.cmd` were more reliable.
- `main.py` FastAPI summary still says "Phase 0 foundation API for Igris" despite phases through 6 being implemented.
- There is no database migration system despite Postgres support.
- Docs and README describe Docker usage, but Docker runtime may not have required config/model artifacts.

## Recommended Integration Points

- Behavioral schemas: `backend/src/igris/schemas/behavior_analysis.py`.
- Behavioral implementation: `backend/src/igris/analysis/behavioral/`.
- Service: `backend/src/igris/analysis/behavioral/service.py`.
- API: add endpoints in `backend/src/igris/api/v1/samples.py`.
- Persistence: add nullable cached result field on `Sample`.
- Queue boundary: build on `backend/src/igris/workers/interfaces.py`.
- Detection: add behavior evidence contributions in `backend/src/igris/detection/scoring.py` only after schema is stable.
- Threat graph: extend Phase 5 mapper to ingest behavior observations as graph Observations.
- ML: populate `static_future_behavior` feature slots only from stable behavior features.
