# Igris

Igris is the Intelligent Graph-based Reverse-engineering and Inspection System.
It is intended to become an explainable malware-analysis and threat-intelligence
platform. The repository currently includes Phase 0 foundation work, Phase 1
file intelligence, Phase 2 static-analysis evidence extraction, Phase 3
transparent heuristic detection, Phase 4 offline reverse engineering, Phase 5
evidence-driven threat-intelligence mapping, Phase 6 reproducible ML
baselines, and Phase 7 behavioral analysis abstractions and synthetic
telemetry simulation.

Implemented foundation:

- A FastAPI backend with versioned APIs, centralized settings, structured logging, request IDs, and normalized errors.
- A React, TypeScript, and Vite frontend shell.
- Clear module boundaries for future analysis, detection, intelligence, reporting, storage, and worker components.
- Security documentation for handling hostile files without executing them on developer or application hosts.
- Test, lint, type-check, Docker, and CI scaffolding.
- Safe upload of untrusted files as inert data.
- Content-based file identification for PE, ELF, text, empty, and unknown files.
- SHA-256, SHA-1, MD5, whole-file entropy, and foundational PE/ELF metadata.
- PostgreSQL metadata repository support plus local JSON/in-memory development options.
- Static string extraction and categorization.
- API capability taxonomy for imports and API-like string references.
- Section, resource, overlay, and conservative packing indicators.
- Versioned static feature vector for future ML consumers.
- Evidence-based detection results with declarative rules, deterministic
  heuristics, and transparent score breakdowns.
- Capstone-backed entry-point and direct-call disassembly with normalized
  functions, basic blocks, CFGs, call graphs, and string/API correlation.
- Capability, behavior, and ATT&CK mapping from static and reverse-engineering
  evidence, with explicit Observation -> Indicator -> Capability -> Technique
  relationships.
- A reproducible ML baseline pipeline with synthetic dataset ingestion,
  leakage-aware splitting, Logistic Regression, Random Forest, Gradient
  Boosting, experiment tracking, model metadata, and explainable inference.
- Phase 7 behavioral analysis subsystem with normalized Pydantic schemas,
  deterministic SyntheticBehaviorAnalyzer across 6 scenarios, job queue and
  SandboxController abstractions, and analyst-triggered REST endpoints.

No real sandbox execution, live sample execution, similarity analysis, or actor attribution
is implemented. Real sample execution is strictly isolated to future disposable environments.
Detection, intelligence mapping, and ML predictions are evidence sources, not final malware
verdicts.

## Repository Layout

```text
.
|-- backend/                 FastAPI package source
|-- frontend/                React/Vite frontend
|-- tests/                   Backend tests
|-- docs/                    Architecture, development, and lab documentation
|-- config/                  Configuration notes and non-secret examples
|-- docker/                  Dockerfiles
|-- scripts/                 Local helper scripts
|-- .github/workflows/       CI workflow
|-- .env.example             Environment variable template
|-- pyproject.toml           Python package and tool configuration
`-- docker-compose.yml       Local development services
```

## Quick Start

Prerequisites:

- Python 3.11 or newer
- Node.js 20 or newer
- uv for Python dependency management
- Docker Desktop or compatible Docker engine, optional for local services

Install backend dependencies:

```powershell
uv sync --extra dev
```

Run backend:

```powershell
uv run uvicorn igris.main:app --app-dir backend/src --reload
```

Upload a safe local file:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Uri http://127.0.0.1:8000/api/v1/samples `
  -Method Post `
  -Form @{ file = Get-Item .\README.md }
```

Inspect file intelligence:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Uri http://127.0.0.1:8000/api/v1/samples/<sample_id>/file-info
```

Run static analysis:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Uri http://127.0.0.1:8000/api/v1/samples/<sample_id>/static-analysis `
  -Method Post
```

Run detection:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Uri http://127.0.0.1:8000/api/v1/samples/<sample_id>/detect `
  -Method Post
```

Run reverse analysis:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Uri http://127.0.0.1:8000/api/v1/samples/<sample_id>/reverse-analysis `
  -Method Post
```

Run threat-intelligence mapping:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Uri http://127.0.0.1:8000/api/v1/samples/<sample_id>/threat-assessment `
  -Method Post
```

Run ML inference:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Uri http://127.0.0.1:8000/api/v1/samples/<sample_id>/ml-prediction `
  -Method Post
```

Run synthetic behavior analysis:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Uri http://127.0.0.1:8000/api/v1/samples/<sample_id>/behavior-analysis `
  -Method Post
```

Install and run frontend:

```powershell
cd frontend
npm install
npm run dev
```

Run checks:

```powershell
uv run ruff check .
uv run mypy
uv run pytest
cd frontend
npm run lint
npm run test
npm run build
```

## Security Posture

Treat every submitted file, filename, archive, metadata field, and derived artifact as hostile input.
Development and application environments must never execute arbitrary uploaded binaries.
Future dynamic behavior analysis belongs only in isolated, disposable environments with strict containment.

See [SECURITY.md](SECURITY.md), [docs/lab-design.md](docs/lab-design.md),
[docs/sandbox-threat-model.md](docs/sandbox-threat-model.md),
[docs/behavior-analysis.md](docs/behavior-analysis.md),
[docs/analysis/file-intelligence.md](docs/analysis/file-intelligence.md), and
[docs/analysis/static-analysis.md](docs/analysis/static-analysis.md). Detection
is documented under [docs/detection](docs/detection).
Reverse engineering is documented under [docs/reverse-engineering](docs/reverse-engineering).
Threat-intelligence mapping is documented in
[docs/intelligence/overview.md](docs/intelligence/overview.md).
ML is documented under [docs/ml](docs/ml).
