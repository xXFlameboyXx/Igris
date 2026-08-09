# Igris

Igris is the Intelligent Graph-based Reverse-engineering and Inspection System.
It is intended to become an explainable malware-analysis and threat-intelligence
platform, but this repository is currently Phase 0 only.

Phase 0 establishes the engineering foundation:

- A FastAPI backend with versioned APIs, centralized settings, structured logging, request IDs, and normalized errors.
- A React, TypeScript, and Vite frontend shell.
- Clear module boundaries for future analysis, detection, intelligence, reporting, storage, and worker components.
- Security documentation for handling hostile files without executing them on developer or application hosts.
- Test, lint, type-check, Docker, and CI scaffolding.

No malware detector, sandbox, disassembler, parser, or dynamic execution feature is implemented in this phase.

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

See [SECURITY.md](SECURITY.md) and [docs/lab-design.md](docs/lab-design.md).

