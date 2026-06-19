"""
ASGI middleware for the SecureCloud-BD Threat API.

Two middleware classes are provided:

``RequestIDMiddleware``
    Reads or generates a UUID request identifier, stores it on
    ``request.state.request_id``, and echoes it in the ``X-Request-ID``
    response header.  Must be added *before* ``StructuredLoggingMiddleware``
    so the request ID is available when the log line is emitted.

``StructuredLoggingMiddleware``
    Emits one JSON log line per HTTP request to stdout via the
    ``api.access`` logger.  Each line contains method, path, status code,
    end-to-end latency (ms), request ID, and client IP.

Starlette's ``BaseHTTPMiddleware`` serialises dispatch around a single
request, which is acceptable for the workloads this API serves (no
streaming, no long-lived connections).
"""
from __future__ import annotations

import json
import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger("api.access")


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject a unique request identifier into state and response headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """
    Emit one structured JSON log line per request.

    Log format (all fields present on every line)::

        {
          "event":      "http_request",
          "method":     "POST",
          "path":       "/score",
          "status":     200,
          "latency_ms": 4.72,
          "request_id": "3fa85f64-...",
          "client_ip":  "10.0.0.1"
        }
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        http_status = 500
        try:
            response = await call_next(request)
            http_status = response.status_code
            return response
        finally:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            log.info(
                json.dumps(
                    {
                        "event"      : "http_request",
                        "method"     : request.method,
                        "path"       : request.url.path,
                        "status"     : http_status,
                        "latency_ms" : elapsed_ms,
                        "request_id" : getattr(request.state, "request_id", None),
                        "client_ip"  : (
                            request.client.host if request.client else None
                        ),
                    }
                )
            )
