$ErrorActionPreference = "Stop"

uv run ruff check .
uv run mypy
uv run pytest

Push-Location frontend
try {
    npm run lint
    npm run test
    npm run build
}
finally {
    Pop-Location
}

