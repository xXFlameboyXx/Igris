# Igris

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6.svg)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-146%20passed-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Status](https://img.shields.io/badge/Security-Hardened%20(Phase%2017)-brightgreen.svg)](docs/security/hardening.md)

**Igris** (*Intelligent Graph-based Reverse-engineering and Inspection System*) is a multi-engine malware analysis and cybersecurity research platform for examining suspicious files through static analysis, reverse engineering, behavioral evidence, machine learning, similarity clustering, threat intelligence, and explainable assessment.

Unlike opaque black-box classifiers, Igris structures all analytical outputs into discrete, traceable **Evidence Items** classified by epistemological certainty (`OBSERVED`, `INFERRED`, `POSSIBLE`). It combines deterministic PE/ELF parsing, linear sweep disassembly, control-flow graph (CFG) construction, heuristic detection, fuzzy hash clustering, and SHAP feature explainability into a unified, fault-tolerant orchestration pipeline.

> [!NOTE]
> **Defensive Research Notice:**
> Igris is an open-source cybersecurity research platform and educational tool. It does **not** replace commercial antivirus, EDR, or cloud sandbox platforms. Default behavioral analysis uses safe synthetic simulation without executing live malware on the host system.

---

## Features

- **File Intelligence:** Content-addressed SHA-256 inert storage, Shannon entropy calculation, and bounds-checked PE and ELF header parsing.
- **Static Analysis:** ASCII/UTF-16 string extraction, import capability taxonomy (Process Injection, Persistence, Evasion), section entropy, and overlay detection.
- **Heuristic Detection:** Declarative YAML detection rules, severity weighting, and rule-hit breakdowns.
- **Safe Reverse Engineering:** Linear sweep disassembly with [Capstone](http://www.capstone-engine.org/), basic block recovery, and interactive Control Flow Graph (CFG) generation.
- **Machine Learning & SHAP:** Baseline classifiers (Random Forest, Gradient Boosting) with tree-based SHAP explainability showing top contributing features per prediction.
- **Behavioral Simulation:** Deterministic synthetic telemetry engine simulating process trees, registry changes, and network sockets safely offline.
- **Similarity Clustering:** SSDEEP and TLSH fuzzy hash generation and locality-sensitive distance clustering.
- **Threat Intelligence & ATT&CK:** Automated mapping of capabilities to MITRE ATT&CK enterprise techniques.
- **Epistemological Assessment:** Transparent evidence classification (`OBSERVED` facts vs. `INFERRED` graphs vs. `POSSIBLE` heuristics) with monotonic mathematical risk scoring.
- **Investigation Workspace & Dossiers:** Evidence bookmarking, analyst notes, timeline filters, and standalone, pure-Python in-memory PDF dossier generation.
- **Analysis Orchestration:** Fault-tolerant directed acyclic graph (DAG) pipeline with stage timeouts, cancellation, and partial-result preservation.
- **Research Benchmarking & Robustness:** Automated evaluation harness (Accuracy, Precision, Recall, F1, ROC-AUC) and adversarial perturbation matrix testing.
- **Security Hardening:** Streaming upload size caps (50MB), path-traversal sanitization, traceback error masking, and defensive ASGI security headers (CSP, nosniff, DENY).
- **Analyst Web UI:** Clean, responsive React 19 interface for interactive sample inspection and dossier export.

---

## High-Level Architecture

Igris coordinates independent analysis engines through a central orchestration DAG. If an individual parser or engine fails on a corrupted or packed binary, downstream assessment continues gracefully using accumulated valid evidence.

```
                    ┌────────────────────────┐
                    │     Sample Upload      │
                    │ (Multipart / SHA-256)  │
                    └───────────┬────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │   File Intelligence    │
                    │ (PE/ELF Headers/Hash)  │
                    └───────────┬────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│Static Analysis│       │Reverse Eng/CFG│       │Behavioral Sim │
└───────┬───────┘       └───────┬───────┘       └───────┬───────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│Detection Rules│       │  ML Baseline  │       │Similarity/TLSH│
└───────┬───────┘       └───────┬───────┘       └───────┬───────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │  Evidence Correlation  │
                    │ (OBSERVED/INFERRED/POS)│
                    └───────────┬────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │ Explainable Assessment │
                    │ (Risk Formula/Verdict) │
                    └───────────┬────────────┘
                                │
                    ┌───────────┴────────────┐
                    ▼                        ▼
        ┌───────────────────────┐┌───────────────────────┐
        │Investigation Workspace││  PDF / JSON Dossier   │
        └───────────────────────┘└───────────────────────┘
```

---

## System Requirements

- **Python:** 3.11 or newer
- **Node.js:** 20 or newer (`npm` included)
- **Package Manager:** `uv` (recommended) or `pip`
- **Operating System:** Linux, macOS, or Windows (PowerShell supported)

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/xXFlameboyXx/Igris.git
cd Igris
```

### 2. Set Up Python Backend
```bash
# Install backend dependencies using uv
uv sync --extra dev
```

*(Alternatively, using standard `pip`: `python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]" `)*

### 3. Set Up React Frontend
```bash
cd frontend
npm install
cd ..
```

---

## Configuration

Copy the example environment configuration template:
```bash
cp .env.example .env
```

Key configuration variables:

| Variable | Default | Description |
|---|---|---|
| `IGRIS_ENVIRONMENT` | `development` | Application runtime environment (`development`, `test`, `production`). |
| `IGRIS_STORAGE_DIR` | `data/samples` | Root directory for inert, content-addressed binary sample storage. |
| `IGRIS_METADATA_BACKEND` | `memory` | Metadata storage backend (`memory`, `json`, `postgres`). |
| `IGRIS_MAX_UPLOAD_BYTES` | `52428800` | Maximum upload file size in bytes (50MB default). |
| `IGRIS_ENABLE_DOCS` | `true` | Enable interactive OpenAPI Swagger docs at `/docs`. |

---

## Quick Start

### 1. Start Backend API Server
```bash
# Starts FastAPI server on http://127.0.0.1:8000
uv run uvicorn igris.main:app --app-dir backend/src --reload --port 8000
```

### 2. Start Frontend Analyst UI
In a separate terminal window:
```bash
# Starts Vite dev server on http://127.0.0.1:5173
cd frontend
npm run dev
```

Open your browser to `http://127.0.0.1:5173` to access the Igris analyst workspace.

---

## Usage Walkthrough

### 1. Upload a Sample (CLI Example)

Upload a safe local test file using PowerShell:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/samples" `
  -Method Post `
  -Form @{ file = Get-Item .\README.md }
```

Or using cURL:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/samples" \
  -F "file=@README.md"
```

Response returns the canonical content-addressed SHA-256 sample ID:
```json
{
  "sample_id": "88a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef",
  "filename": "README.md",
  "safe_filename": "README.bin",
  "size_bytes": 1024,
  "sha256": "88a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef",
  "detected_format": "text",
  "status": "completed"
}
```

### 2. Run Orchestrated Multi-Engine Analysis
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyses" \
  -H "Content-Type: application/json" \
  -d '{"sample_id": "<SAMPLE_SHA256>"}'
```

### 3. Generate and Download PDF Dossier
```bash
# Downloads standalone formatted PDF dossier
curl -O "http://127.0.0.1:8000/api/v1/reports/<REPORT_ID>/pdf"
```

---

## REST API Overview

When the backend is running, full interactive OpenAPI documentation is available at:
- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **OpenAPI Schema:** `http://127.0.0.1:8000/openapi.json`

Key endpoint groups:
- `POST /api/v1/samples`: Ingest untrusted binary as inert file.
- `GET /api/v1/samples/{sample_id}/file-info`: Detailed PE/ELF headers and entropy.
- `POST /api/v1/analyses`: Create and execute multi-stage DAG analysis job.
- `GET /api/v1/analyses/{analysis_id}/status`: Polling stage progress and verdicts.
- `POST /api/v1/investigation/{sample_id}/workspace`: Manage analyst notes and bookmarks.
- `GET /api/v1/reports/{report_id}/pdf`: Generate in-memory pure Python PDF dossier.
- `POST /api/v1/experiments/run`: Execute benchmark evaluation harness.
- `POST /api/v1/robustness/evaluate`: Run adversarial perturbation matrix evaluation.

For the complete endpoint reference, see [`docs/api/endpoints.md`](docs/api/endpoints.md).

---

## Testing & Code Quality

Run the complete verification suite across the codebase:

```bash
# 1. Backend Pytest Suite (146 automated tests)
uv run pytest

# 2. Ruff Security Linter (Bandit rules enabled)
uv run ruff check .

# 3. Ruff Code Formatter Check
uv run ruff format --check .

# 4. Strict Mypy Type Checking (120 source files)
uv run mypy

# 5. Frontend Type Check & ESLint
cd frontend
npm test          # TypeScript type checking
npm run lint      # ESLint code quality
npm run build     # Production bundle build
cd ..
```

---

## Repository Structure

```text
.
├── backend/
│   └── src/igris/
│       ├── analysis/        # File intelligence, static, reverse, detection, ML, behavioral, similarity
│       ├── api/v1/          # FastAPI REST endpoints
│       ├── core/            # Config, error handling, structured logging, request IDs
│       ├── intelligence/    # ATT&CK mapping, epistemology, explainable assessment
│       ├── middleware/      # Security headers, request tracking
│       ├── orchestration/   # DAG pipeline orchestrator
│       ├── reporting/       # In-memory pure Python PDF and JSON report generator
│       ├── research/        # Experimental benchmark harness & robustness engine
│       ├── schemas/         # Pydantic models (evidence, verdicts, reports, security)
│       └── storage/         # Content-addressed sample and metadata storage
├── frontend/
│   └── src/
│       ├── components/      # UI views (Static, Reverse/CFG, Behavioral, Investigation, Dossier)
│       └── services/        # API client & synthetic demo data fixtures
├── config/                  # Configuration templates and review records
├── docs/                    # Architecture, API, research, security, and developer guides
├── tests/                   # Automated backend pytest test cases
├── CHANGELOG.md             # Semantic version release notes
├── CONTRIBUTING.md          # Contributor guide and pull request rules
├── LICENSE                  # MIT License
├── README.md                # Project manual (this document)
└── SECURITY.md              # Vulnerability reporting policy & threat model
```

---

## Security Model & Boundaries

Igris is built on defense-in-depth principles:
- **Zero Host Execution:** The backend inspects binaries strictly as passive data using bounds-checked parsers. It never executes samples on the host system.
- **Inert Content-Addressed Storage:** Files are stored as `data/samples/{sha256}.bin`, neutralizing path traversal (`../../evil.exe`).
- **Resource Limits:** Upload streaming caps (50MB default), linear sweep instruction limits, and string extraction quotas prevent resource exhaustion.
- **Defensive HTTP Headers:** Enforces `Content-Security-Policy: default-src 'self'`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.
- **Pure Python PDF Generation:** Formats reports in-memory without external command-line binaries or shell invocations.

For the full defensive review and threat model, see [`SECURITY.md`](SECURITY.md) and [`docs/security/hardening.md`](docs/security/hardening.md).

---

## Known Limitations

- **Single-Tenant Application:** Igris does not implement multi-user RBAC or OAuth2/OIDC. Network exposure requires an authenticating reverse proxy (Nginx, Envoy) with TLS termination.
- **Synthetic Behavioral Default:** The built-in dynamic analysis subsystem uses deterministic synthetic simulation. Live execution of untrusted malware requires external, isolated hypervisor VMs with sinkholed networking.
- **Parser Coverage:** Disassembly focuses on x86/x86_64 PE and ELF binaries; non-standard architectures and heavily packed formats may result in partial static extraction.

---

## Responsible Use

Igris is intended strictly for:
- Authorized malware analysis and digital forensics investigations.
- Defensive cybersecurity research and reverse engineering education.
- Controlled, isolated laboratory environments.

Do not analyze files or systems without explicit authorization. For full laboratory guidelines, see [`docs/responsible-use.md`](docs/responsible-use.md).

---

## Contributing

Contributions are welcome! Please review [`CONTRIBUTING.md`](CONTRIBUTING.md) for branch conventions, Conventional Commits standards, and our pre-commit verification checklist.

---

## Roadmap

- [ ] External hypervisor agent connector (QEMU/KVM isolated execution).
- [ ] Authenticode digital signature validation and certificate chain verification.
- [ ] Multi-tenant reverse proxy reference configuration with OAuth2/OIDC.
- [ ] Advanced dynamic memory dump and string deobfuscation helpers.

---

## License

This project is licensed under the **MIT License**. See the [`LICENSE`](LICENSE) file for details.
