"""
common.logging — structured JSON-lines logs per engagement.

Every subsystem logs through this. The planner's audit trail (when
ACP ships in a later session) depends on these logs being complete
and machine-parseable.

When no engagement is bound, logs go to a process-level file under
`framework/v2/.crucible-v2.log`. After `bind_engagement(slug)`, logs
go to `targets/<slug>/.crucible-v2.log`.
"""

from __future__ import annotations

import json
import logging as _stdlib_logging
import os
from pathlib import Path
from typing import Any

import structlog

from . import paths, redact

# X2: an engagement log is rotated once when it exceeds this, bounding disk to
# ~2x this size (the live file + a single .1 backup). Generous so the Ops Console
# live-tail is never disrupted in a normal run.
_LOG_MAX_BYTES = 64 * 1024 * 1024

# Log paths already permission-tightened this process, so the pre-existing-file
# chmod (upgrade path) runs once per path, not per line.
_SECURED_LOGS: set[str] = set()


# Module-level mutable holder for the current engagement slug. We use a
# module-level variable instead of contextvars because v2 today is
# single-threaded; switching is rare and explicit.
_BOUND_SLUG: str | None = None


def _engagement_log_path() -> Path:
    if _BOUND_SLUG is not None:
        try:
            return paths.crucible_v2_log(_BOUND_SLUG)
        except Exception:
            pass  # fall through to ambient
    return paths.v2_root() / ".crucible-v2.log"


def _scrub(_logger: Any, _name: str, event_dict: Any) -> Any:
    """Processor: mask secret-keyed fields (token/cookie/authorization/password/…)
    BEFORE the event is serialised to disk (X2). Deterministic + total — an
    unrecognised field passes through unchanged, so log shape is preserved and no
    determinism/replay property is affected. Runs just before `_emit_json`."""
    return redact.scrub_log_event(dict(event_dict))


def _append_capped(p: Path, line: str) -> None:
    """Append one line to the owner-only engagement log, rotating once if it has
    grown past the cap. The file is created 0600 with NO world-readable window (via
    os.open with the mode, mirroring secure_write) — not created-then-chmod'd. The
    parent is ensured to exist but is NEVER re-permissioned: for the ambient log the
    parent is the framework source root, which must not be locked down. A
    pre-existing looser log (e.g. written by a pre-X2 build) is tightened once per
    path, so there is no per-line permission cost on the hot path."""
    paths.secure_dir(p.parent)                       # ensure-exists; chmods only a dir it creates
    try:
        if p.exists() and p.stat().st_size >= _LOG_MAX_BYTES:
            rotated = p.with_suffix(p.suffix + ".1")     # bounded: one .1 backup
            os.replace(p, rotated)
            # os.replace preserves the inode's mode, so a pre-X2 (0644) log stays
            # world-readable as the backup — tighten the rotated file too.
            paths.secure_existing(rotated)
    except OSError:
        pass
    first_touch = str(p) not in _SECURED_LOGS
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, paths.SECURE_FILE_MODE)  # 0600, no window
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    if first_touch:
        paths.secure_existing(p)                     # tighten a pre-existing loose file, once per path
        _SECURED_LOGS.add(str(p))


def _emit_json(_logger: Any, _name: str, event_dict: Any) -> Any:
    """Final processor: write the event to disk and stop the chain.

    Signature is intentionally `Any` to satisfy structlog's
    Processor protocol (which uses MutableMapping in typeshed). We
    raise DropEvent before any return so the type erasure is moot.
    """
    p = _engagement_log_path()
    line = json.dumps(dict(event_dict), default=str, separators=(",", ":"), sort_keys=True)
    _append_capped(p, line)
    raise structlog.DropEvent


def configure(level: str = "INFO") -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _scrub,
            _emit_json,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(_stdlib_logging, level.upper())
        ),
        cache_logger_on_first_use=False,
    )


def bind_engagement(slug: str | None) -> None:
    """Route subsequent logs to this engagement's file. None resets to ambient."""
    global _BOUND_SLUG
    _BOUND_SLUG = slug


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)


# Initial configuration so importing this module is enough to log.
configure()
