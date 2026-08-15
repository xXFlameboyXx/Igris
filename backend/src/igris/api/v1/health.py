"""Health endpoint."""

from fastapi import APIRouter, Request

from igris import __version__
from igris.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Return structured application health."""

    settings = request.app.state.settings
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=__version__,
        environment=settings.environment,
        components={"api": "ok"},
    )
