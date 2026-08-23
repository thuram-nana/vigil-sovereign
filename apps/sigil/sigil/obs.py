"""Structured logging for SIGIL (production-hardening OBS; unified by W6-5).

App entry points (the CLI, daemons) call `configure_logging()` ONCE at startup to install a single root
handler; library modules just use `logging.getLogger(__name__)` (or `get_logger`) and inherit it.

The setup itself now lives in ONE shared home — `vigil_core.logging_setup` — so the sovereign plane emits
the SAME structured JSON, through the SAME redaction processor, governed by the SAME `VIGIL_LOG_LEVEL`,
as the offense engine and the host gateway. This closed the old three-stack split where SIGIL logged
plain text to stderr with no redaction. `vigil_core` imports no `framework.*` / `strix.*`, so reusing it
keeps SIGIL offense-free by construction. Logs go to stderr so they never pollute stdout / CLI data.

Discipline: a log line is diagnostic. The shared redaction processor masks a secret that slips into a
message or a structured field, but you should still never deliberately pass a credential to a logger —
`config.effective_config()` is the redacted way to surface configuration.
"""
from __future__ import annotations

import logging

from vigil_core import logging_setup as _shared

_HANDLER_NAME = "sigil"


def configure_logging(level=None, *, stream=None, force: bool = False) -> logging.Logger:
    """Install SIGIL's single root log handler (structured JSON + shared redaction) and return the root
    logger. The level is resolved by the shared resolver: VIGIL_LOG_LEVEL, then the deprecated
    SIGIL_LOG_LEVEL (honoured with a one-time deprecation warning), then INFO — an explicit `level` still
    wins. Idempotent: a second call only adjusts the level unless `force=True` (which rebuilds the handler,
    e.g. for a test capturing into a StringIO)."""
    return _shared.configure_logging(
        level, stream=stream, handler_name=_HANDLER_NAME, force=force
    )


def get_logger(name: str) -> logging.Logger:
    """Convenience wrapper around `logging.getLogger`. Library modules may call this or use
    `logging.getLogger(__name__)` directly — both inherit the root handler `configure_logging` installs
    at app startup."""
    return logging.getLogger(name)
