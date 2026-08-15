"""Error response conventions for the Igris API."""

from typing import Any

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from igris.core.request_context import get_request_id


class AppError(Exception):
    """Base application error for expected failures."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "application_error",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


def error_payload(
    *,
    code: str,
    message: str,
    details: dict[str, Any] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a consistent API error response."""

    payload: dict[str, Any] = {
        "success": False,
        "error": {
            "code": code,
            "message": message,
        },
        "request_id": get_request_id(),
    }
    if details:
        payload["error"]["details"] = details
    return payload


async def app_error_handler(_: Request, exc: Exception) -> JSONResponse:
    """Handle expected and unexpected application exceptions."""

    if isinstance(exc, AppError):
        return JSONResponse(
            status_code=exc.status_code,
            content=error_payload(code=exc.code, message=exc.message, details=exc.details),
        )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_payload(code="internal_server_error", message="Unexpected server error"),
    )


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Normalize Starlette/FastAPI HTTP exceptions."""

    if not isinstance(exc, StarletteHTTPException):
        return await app_error_handler(request, exc)

    code = "not_found" if exc.status_code == status.HTTP_404_NOT_FOUND else "http_error"
    message = str(exc.detail) if exc.detail else "HTTP error"
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(code=code, message=message),
    )


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Normalize request validation errors without echoing sensitive payloads."""

    if not isinstance(exc, RequestValidationError):
        return await app_error_handler(request, exc)

    details = [
        {
            "loc": list(error["loc"]),
            "msg": error["msg"],
            "type": error["type"],
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=error_payload(
            code="validation_error",
            message="Request validation failed",
            details=details,
        ),
    )
