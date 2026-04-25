"""Structured JSON logging configuration.

Replaces uvicorn's default text logs with one-record-per-line JSON to
stdout, per SPEC.md §Observability. Fields:

* ``ts``         — ISO 8601 timestamp (UTC)
* ``level``      — log level name
* ``logger``     — logger name (e.g. ``uvicorn.access``)
* ``message``    — the log message
* ``request_id`` — per-request correlation id (set by middleware)
* ``method``     — HTTP method (request-scoped)
* ``path``       — request path
* ``status``     — response status code
* ``duration_ms``— wall time spent in handler

No third-party dep — stdlib ``logging`` + a ~20-line formatter does it.

Two pieces wire together:

* :class:`JsonFormatter` formats every record as JSON
* :func:`configure_logging` swaps it onto the root + uvicorn loggers at
  app startup
* :func:`request_logging_middleware` adds request-scoped context
  (request_id / duration / status) to access logs
"""

from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

# Fields we never want to leak into logs even if a record carries them.
# Rule contents (titles, descriptions, detection items) must not be
# logged per CLAUDE.md and SPEC.md §Observability.
_DROPPED_FIELDS = frozenset({"rule", "rule_state", "rule_yaml", "draft"})

# Standard LogRecord attributes we serialize specially or skip entirely;
# anything else attached to a record (e.g. via ``extra=``) is included.
_RESERVED_LOGRECORD_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)


class JsonFormatter(logging.Formatter):
    """Format every record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Pass through any caller-attached fields, except the dropped ones.
        for key, value in record.__dict__.items():
            if key in _RESERVED_LOGRECORD_ATTRS or key in _DROPPED_FIELDS:
                continue
            payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Install :class:`JsonFormatter` on the root + uvicorn loggers.

    Idempotent — safe to call from a worker that re-imports the app.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    for logger_name in ("", "uvicorn", "uvicorn.access", "uvicorn.error"):
        logger = logging.getLogger(logger_name)
        # Replace existing handlers so uvicorn's default text logger doesn't
        # double-emit alongside ours.
        logger.handlers = [handler]
        logger.setLevel(level)
        # Don't bubble up to the root logger after we've already attached
        # our handler — would log every line twice.
        logger.propagate = False


async def request_logging_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Attach a request_id, time the handler, and log one access line.

    The request_id flows back to the client as the ``X-Request-Id`` header
    so a tester reporting a bug can quote a single id and ops can find the
    matching log line.
    """
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    request.state.request_id = request_id
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        duration_ms = (time.perf_counter() - start) * 1000
        logging.getLogger("intel2sigma.web").exception(
            "Unhandled exception",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "duration_ms": round(duration_ms, 1),
            },
        )
        raise
    duration_ms = (time.perf_counter() - start) * 1000
    logging.getLogger("intel2sigma.web.access").info(
        "request",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": round(duration_ms, 1),
        },
    )
    response.headers["X-Request-Id"] = request_id
    return response


__all__ = [
    "JsonFormatter",
    "configure_logging",
    "request_logging_middleware",
]
