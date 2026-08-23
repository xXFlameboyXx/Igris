<img width="800" height="450" alt="dm9i677-d695ade6-68e6-45da-98c9-7ecdc0f50acb" src="https://github.com/user-attachments/assets/bc3ec933-92c1-48dc-8e3e-2bef00c130d3" />

# IGRIS

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6.svg)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-158%20passed-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Status](https://img.shields.io/badge/Security-Hardened-brightgreen.svg)](SECURITY.md)

**IGRIS** (*Intelligent Graph-based Reverse-engineering and Inspection System*) is an explainable malware analysis and threat intelligence GUI application for inspecting and evaluating suspicious binary samples.

---

## What is IGRIS?

Igris is a local, web-based cybersecurity analysis platform designed for malware analysts, security engineers, and researchers. It provides a visual analyst interface for examining untrusted binaries across multiple independent analysis engines—combining static file intelligence, linear sweep disassembly, control flow graphs, heuristic detection, machine learning explainability, synthetic behavioral simulation, and MITRE ATT&CK mapping into transparent, evidence-backed verdicts.

---

## Features

- **File Intelligence:** Content-addressed SHA-256 inert storage, Shannon entropy calculation, and bounds-checked PE and ELF header parsing.
- **Static Analysis:** Categorized string extraction, import capability taxonomy (Process Injection, Persistence, Evasion), section entropy, and overlay detection.
- **Heuristic Detection:** Declarative YAML detection rules, severity weighting, and rule-hit breakdowns.
- **Safe Reverse Engineering:** Linear sweep disassembly with [Capstone](http://www.capstone-engine.org/), basic block recovery, and interactive Control Flow Graph (CFG) rendering.
- **Machine Learning & SHAP:** Baseline classifiers (Random Forest, Gradient Boosting) with tree-based SHAP explainability showing top contributing features per prediction.
- **Behavioral Simulation:** Deterministic synthetic telemetry engine simulating process trees, registry changes, and network sockets safely offline.
- **Similarity Clustering:** SSDEEP and TLSH fuzzy hash generation and locality-sensitive distance clustering.
- **Threat Intelligence & ATT&CK:** Automated mapping of extracted capabilities to MITRE ATT&CK enterprise techniques.
- **Epistemological Assessment:** Transparent evidence classification (`OBSERVED` facts vs. `INFERRED` graphs vs. `POSSIBLE` heuristics) with monotonic mathematical risk scoring.
- **Investigation Workspace & Dossiers:** Evidence bookmarking, analyst notes, timeline filtering, and standalone in-memory PDF dossier generation.
- **Global CLI Launcher:** Simple single-command startup (`igris`) from any directory with automatic browser launching and process lifecycle management.

---

## Installation

### Prerequisites
- **Python:** 3.11 or newer ([python.org](https://python.org))
- **Node.js:** 18+ *(optional to pre-install; the automated installer will automatically install Node.js & npm if not detected)*
- **Git:** ([git-scm.com](https://git-scm.com))

### 1. Clone the Repository
```bash
git clone https://github.com/xXFlameboyXx/Igris.git
cd Igris
```

### 2. Run the Installer

**Windows (PowerShell):**
```powershell
.\install.ps1
```

**Linux / macOS (Bash):**
```bash
chmod +x install.sh && ./install.sh
```

The installer automatically ensures Node.js & npm are present, configures the Python virtual environment, compiles the frontend bundle, and registers the global `igris` command on your user `PATH`.

---

## Run Igris

Once installed, simply open Command Prompt, PowerShell, or your terminal from **ANY** directory and type:

```bash
igris
```

Expected output:
```text
Starting Igris...
Backend: ready (http://127.0.0.1:8000)
Frontend: ready
Opening Igris in your browser: http://127.0.0.1:8000

Igris is running. Press Ctrl+C to stop.
```

Your default web browser opens the Igris GUI automatically.

---

## GUI & Usage Workflow

1. **Upload a Sample:** Drop an executable file (PE or ELF) or test sample into the Ingestion panel.
2. **Run Analysis Pipeline:** The central DAG orchestrates File Intelligence, Static Analysis, Disassembly, Heuristics, ML Inference, and Threat Mapping.
3. **Inspect Evidence:** Examine categorized strings, import capabilities, control flow graphs, and MITRE ATT&CK technique alignments.
4. **Review Verdict:** Check the explainable assessment score with segregated `OBSERVED`, `INFERRED`, and `POSSIBLE` evidence breakdowns.
5. **Investigate & Bookmark:** Add analyst notes and bookmark key findings in the Investigation Workspace.
6. **Export Dossier:** Download a formatted, printable PDF dossier for reporting.

---

## CLI Commands

| Command | Description |
|---|---|
| `igris` | Launch the Igris server and open the GUI in your default browser. |
| `igris --status` | Check if an Igris server is currently running. |
| `igris --stop` | Stop any running Igris background instance. |
| `igris --repair` | Rebuild frontend assets and verify dependencies. |
| `igris --port <PORT>` | Run Igris on a custom port (default: `8000`). |
| `igris --no-browser` | Start the server without opening the browser automatically. |
| `igris --dev` | Start in development mode with active Vite dev server. |
| `igris --version` | Display the installed version (`Igris v0.1.0`). |
| `igris --help` | Show all available command-line options. |

---

## Uninstallation

To remove the global launcher and PATH configuration while preserving your analysis samples and workspace data:

**Windows (PowerShell):**
```powershell
.\uninstall.ps1
```

**Linux / macOS (Bash):**
```bash
./uninstall.sh
```

---

## Troubleshooting

- **Port already in use:**
  If port 8000 is occupied by another application, launch on a different port:
  ```bash
  igris --port 8080
  ```
- **Igris is already running:**
  Running `igris` when an instance is already active detects the running service and brings up the existing GUI in your browser without spawning duplicate processes.
- **Frontend assets missing or outdated:**
  Run the repair command to rebuild the frontend production bundle:
  ```bash
  igris --repair
  ```
- **Browser does not open automatically:**
  Access the GUI manually by navigating to `http://127.0.0.1:8000` in your web browser.

---

## Developer Setup

For developers modifying the Igris codebase:

```bash
# 1. Install backend development dependencies
uv sync --extra dev

# 2. Run backend test suite (158 tests)
uv run pytest

# 3. Static analysis & linters
uv run ruff check .
uv run ruff format --check .
uv run mypy backend/src

# 4. Frontend development server
cd frontend
npm install
npm test          # TypeScript typecheck
npm run lint      # ESLint
npm run dev       # Start Vite dev server on http://localhost:5173
```

---

## Security & Responsible Use

- **Defensive Laboratory Tool:** Igris is built for defensive cybersecurity research, educational analysis, and authorized binary inspection.
- **Zero Host Execution:** The application statically inspects binary formats and simulates dynamic behavior. Untrusted sample binaries are never executed directly on the host operating system.
- **Single-Tenant Local Architecture:** By default, Igris binds strictly to `127.0.0.1`. Exposing the platform over untrusted networks requires an authenticating reverse proxy with TLS termination.

---

## License

Igris is licensed under the [MIT License](LICENSE).
