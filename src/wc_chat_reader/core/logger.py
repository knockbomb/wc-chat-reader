"""Loguru-based structured logging.

Design choices:
- Loguru instead of stdlib logging: no boilerplate, better performance,
  automatic exception tracebacks, and file rotation out of the box.
- All output goes to stderr so stdout stays clean for piped CLI output.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from loguru import logger as _logger

_configured: bool = False


def configure_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    *,
    json: bool = False,
) -> None:
    """Configure the global logger. Safe to call multiple times."""
    global _configured

    _logger.remove()

    fmt = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> "
        "<level>{level:<8}</level> "
        "<cyan>{name}:{function}:{line}</cyan> "
        "<level>{message}</level>"
    )

    _logger.add(
        sys.stderr,
        level=level,
        format=fmt,
        colorize=True,
        backtrace=True,
        diagnose=False,
    )

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        _logger.add(
            log_file,
            level=level,
            format=fmt if not json else "{message}",
            rotation="10 MB",
            retention="7 days",
            compression="zip",
            enqueue=True,
            serialize=json,
        )

    _configured = True


def get_logger(name: str | None = None) -> Any:
    """Return a logger bound to ``name`` (usually ``__name__``)."""
    if not _configured:
        configure_logging()
    if name is None:
        return _logger
    return _logger.bind(module=name)
