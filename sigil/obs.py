"""Structured logging for SIGIL (production-hardening OBS).

App entry points (the CLI, daemons) call `configure_logging()` ONCE at startup to install a
single root handler; library modules just use `logging.getLogger(__name__)` (or `get_logger`)
and inherit that handler. Logs go to stderr so they never pollute stdout / CLI data output.

Discipline: a log line is diagnostic, never a secret sink. NEVER pass an API key, token, or any
credential to a logger — this module deliberately provides no "log everything" helper, and
`config.effective_config()` is the redacted way to surface configuration.
"""
from __future__ import annotations

import logging
import os
import sys

_HANDLER_NAME = "sigil"
_DEFAULT_LEVEL = "INFO"
_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%dT%H:%M:%S"
_configured = False


def _resolve_level(level=None) -> int:
    """Level from explicit arg → env SIGIL_LOG_LEVEL → INFO. Accepts an int or a name
    ('DEBUG'/'info'/…); an unknown name falls back to INFO rather than raising."""
    raw = level if level is not None else os.environ.get("SIGIL_LOG_LEVEL", _DEFAULT_LEVEL)
    if isinstance(raw, int):
        return raw
    return getattr(logging, str(raw).strip().upper(), logging.INFO)


def configure_logging(level=None, *, stream=None, force: bool = False) -> logging.Logger:
    """Install SIGIL's single root log handler and return the root logger. Idempotent: a second
    call only adjusts the level unless `force=True` (which rebuilds the handler — used by tests to
    capture into a StringIO). Concise timestamped format; writes to `stream` (default stderr)."""
    global _configured
    root = logging.getLogger()
    lvl = _resolve_level(level)
    if _configured and not force:
        root.setLevel(lvl)
        return root
    # drop any handler we previously installed so re-configuring never double-emits
    for h in list(root.handlers):
        if getattr(h, "name", None) == _HANDLER_NAME:
            root.removeHandler(h)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.set_name(_HANDLER_NAME)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
    root.addHandler(handler)
    root.setLevel(lvl)
    _configured = True
    return root


def get_logger(name: str) -> logging.Logger:
    """Convenience wrapper around `logging.getLogger`. Library modules may call this or use
    `logging.getLogger(__name__)` directly — both inherit the root handler `configure_logging`
    installs at app startup."""
    return logging.getLogger(name)
