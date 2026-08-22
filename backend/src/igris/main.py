"""FastAPI application factory for Igris."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.staticfiles import StaticFiles

from igris import __version__
from igris.api.v1.health import router as health_router
from igris.api.v1.router import router as api_v1_router
from igris.core.config import Settings, get_settings
from igris.core.errors import (
    AppError,
    app_error_handler,
    http_exception_handler,
    validation_exception_handler,
)
from igris.core.logging import configure_logging, get_logger
from igris.middleware.request_id import RequestIdMiddleware
from igris.middleware.security_headers import SecurityHeadersMiddleware
from igris.storage.factory import (
    build_dataset_repository,
    build_experiment_repository,
    build_jobs_repository,
    build_metadata_repository,
    build_robustness_repository,
    build_sample_storage,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    logger = get_logger("igris.lifecycle")
    logger.info(
        "application_startup",
        extra={"component": "api", "environment": settings.environment},
    )
    yield
    logger.info("application_shutdown", extra={"component": "api"})


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the Igris API application."""

    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings)

    app = FastAPI(
        title="Igris API",
        summary="Explainable malware-analysis and threat-intelligence API for Igris.",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if resolved_settings.enable_docs else None,
        redoc_url="/redoc" if resolved_settings.enable_docs else None,
        openapi_url="/openapi.json" if resolved_settings.enable_docs else None,
    )
    app.state.settings = resolved_settings
    app.state.sample_storage = build_sample_storage(resolved_settings)
    app.state.metadata_repository = build_metadata_repository(resolved_settings)
    app.state.jobs_repository = build_jobs_repository(resolved_settings)
    app.state.experiment_repository = build_experiment_repository(resolved_settings)
    app.state.dataset_repository = build_dataset_repository(resolved_settings)
    app.state.robustness_repository = build_robustness_repository(resolved_settings)

    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(Exception, app_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)

    app.include_router(api_v1_router, prefix="/api/v1")
    app.include_router(health_router)

    if resolved_settings.environment != "test":
        dist_path = Path(resolved_settings.frontend_dist_dir)
        if not dist_path.is_absolute():
            for candidate in [
                Path.cwd() / dist_path,
                Path(__file__).resolve().parents[3] / dist_path,
            ]:
                if candidate.is_dir() and (candidate / "index.html").is_file():
                    dist_path = candidate
                    break

        if dist_path.is_dir() and (dist_path / "index.html").is_file():
            public_dir = dist_path.parent / "public"

            @app.get("/assets/igris-logo.png", include_in_schema=False)
            async def serve_custom_logo() -> FileResponse:
                for candidate in [
                    public_dir / "assets" / "igris-logo.png",
                    dist_path / "assets" / "igris-logo.png",
                ]:
                    if candidate.is_file():
                        return FileResponse(
                            candidate,
                            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
                        )
                raise StarletteHTTPException(status_code=404, detail="Logo not found")

            assets_dir = dist_path / "assets"
            if assets_dir.is_dir():
                app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="frontend_assets")

            @app.get("/{full_path:path}", include_in_schema=False)
            async def serve_spa(full_path: str) -> FileResponse:
                if (
                    full_path.startswith("api/")
                    or full_path.startswith("api")
                    or full_path.startswith("health")
                    or full_path.startswith("docs")
                    or full_path.startswith("redoc")
                    or full_path.startswith("openapi")
                ):
                    raise StarletteHTTPException(status_code=404, detail="Not Found")

                target_file = dist_path / full_path
                if full_path and target_file.is_file():
                    return FileResponse(target_file)
                return FileResponse(dist_path / "index.html")

    return app


app = create_app()
