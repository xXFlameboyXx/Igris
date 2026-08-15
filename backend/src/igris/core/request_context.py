"""Request-scoped context helpers."""

from contextvars import ContextVar

request_id_context: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    """Return the request ID for the current request, when available."""

    return request_id_context.get()
