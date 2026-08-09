# Development

## Prerequisites

- Python 3.11 or newer
- uv
- Node.js 20 or newer
- npm
- Docker Desktop or compatible Docker engine, optional

## Backend Setup

```powershell
uv sync --extra dev
Copy-Item .env.example .env
uv run uvicorn igris.main:app --app-dir backend/src --reload
```

The backend serves:

- `GET /health`
- `GET /api/v1/health`
- `POST /api/v1/samples`
- `GET /api/v1/samples/{sample_id}`
- `GET /api/v1/samples/{sample_id}/file-info`
- `POST /api/v1/samples/{sample_id}/static-analysis`
- `GET /api/v1/samples/{sample_id}/static-analysis`
- `GET /api/v1/samples/{sample_id}/indicators`
- `POST /api/v1/samples/{sample_id}/detect`
- `GET /api/v1/samples/{sample_id}/detection`
- `GET /docs` when `IGRIS_ENABLE_DOCS=true`

## Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/api` and `/health` to `http://localhost:8000`.

## Tests and Checks

Backend:

```powershell
uv run ruff check .
uv run mypy
uv run pytest
```

Frontend:

```powershell
cd frontend
npm run lint
npm run test
npm run build
```

## Environment Variables

All backend settings use the `IGRIS_` prefix. See `.env.example`.

Do not commit `.env` files or real secrets. `IGRIS_DATABASE_URL` is required when
`IGRIS_METADATA_BACKEND=postgres`. Local development can use
`IGRIS_METADATA_BACKEND=json`; tests use an in-memory repository.

## Docker Usage

Build and run local services:

```powershell
docker compose up --build
```

The compose file is for local development only. It is not a production deployment
pipeline.
