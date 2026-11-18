"""Structured logging setup with secret redaction.

Uses structlog with a JSON renderer. A processor redacts secret-looking
values from every event before rendering, so API keys can never reach
log sinks.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from .redaction import redact

_CONFIGURED = False

REDACTED_FIELDS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "token",
        "secret",
        "password",
        "passwd",
    }
)


def _redact_values(logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key in list(event_dict):
        value = event_dict[key]
        if isinstance(value, str):
            value = redact(value)
            if key.lower() in REDACTED_FIELDS and value:
                value = "[REDACTED]"
            event_dict[key] = value
    return event_dict


class _StderrPrintLogger(structlog.PrintLogger):
    """PrintLogger that writes to sys.stderr resolved at emit time."""

    def __init__(self) -> None:
        # Bypass PrintLogger.__init__ so no stream object is captured.
        self._file = None
        self._lock = __import__("threading").Lock()

    def msg(self, message: str) -> None:

        with self._lock:
            print(message, file=sys.stderr, flush=True)

    # Rebind level aliases to this subclass's msg.
    err = error = exception = failure = fatal = info = log = msg
    warn = warning = debug = critical = msg


class _DynamicStderrLoggerFactory:
    """Logger factory that avoids capturing sys.stderr at configure time.

    Capturing the stream object at configure time breaks under pytest's
    capfd/capsys redirection.
    """

    def __call__(self, *args: Any) -> structlog.PrintLogger:
        return _StderrPrintLogger()


def configure_logging(verbose: bool = False, json_output: bool = True) -> None:
    """Configure structlog exactly once per process."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = logging.DEBUG if verbose else logging.INFO

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_values,
    ]

    if json_output:
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=_DynamicStderrLoggerFactory(),
        cache_logger_on_first_use=False,
    )
    _CONFIGURED = True


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
