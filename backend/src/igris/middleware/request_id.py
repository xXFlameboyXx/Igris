"""Request ID propagation middleware."""

import re
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from igris.core.request_context import request_id_context

REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
DEFAULT_REQUEST_ID_HEADER = "X-Request-ID"


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a safe request ID to every request and response."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        incoming_request_id = request.headers.get(DEFAULT_REQUEST_ID_HEADER)
        request_id = (
            incoming_request_id
            if incoming_request_id and REQUEST_ID_PATTERN.fullmatch(incoming_request_id)
            else str(uuid.uuid4())
        )

        token = request_id_context.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_context.reset(token)

        response.headers[DEFAULT_REQUEST_ID_HEADER] = request_id
        return response
