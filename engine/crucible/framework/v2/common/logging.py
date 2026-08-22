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

import contextvars
import json
import logging as _stdlib_logging
import os
from pathlib import Path
from typing import Any

import structlog

from . import paths, redact

# W16-STD-6(a): an engagement log ROTATES with RETENTION when it exceeds the size
# cap — it is NEVER truncated in place, so no audit history is silently discarded.
# The live file is renamed to ``.1`` and the existing backups shift up
# (``.1`` -> ``.2`` -> … -> ``.N``); only the record PAST the explicit, documented
# retention window (``_LOG_BACKUP_COUNT`` backups) is pruned — and that pruning is
# a stated policy, not a silent 128 MiB cliff. Disk is bounded to
# ~``(_LOG_BACKUP_COUNT + 1) * _LOG_MAX_BYTES``. Both are read at rotation time so a
# deployment can widen retention via ``VIGIL_LOG_MAX_BYTES`` /
# ``VIGIL_LOG_BACKUP_COUNT`` (and tests can monkeypatch them). The cap is generous
# so the Ops Console live-tail is never disrupted in a normal run.
try:
    _LOG_MAX_BYTES = max(1, int(os.environ.get("VIGIL_LOG_MAX_BYTES", str(64 * 1024 * 1024))))
except (TypeError, ValueError):
    _LOG_MAX_BYTES = 64 * 1024 * 1024
try:
    _LOG_BACKUP_COUNT = max(1, int(os.environ.get("VIGIL_LOG_BACKUP_COUNT", "16")))
except (TypeError, ValueError):
    _LOG_BACKUP_COUNT = 16

# Log paths already permission-tightened this process, so the pre-existing-file
# chmod (upgrade path) runs once per path, not per line.
_SECURED_LOGS: set[str] = set()


# W16-STD-6(b): the current engagement slug is held in a ContextVar, NOT a bare
# module global. Two engagements running concurrently in the same process (each on
# its own thread/context — the console's ThreadingHTTPServer, a worker pool) each
# get their OWN bound slug, so their structured logs route to separate
# ``targets/<slug>/.crucible-v2.log`` files instead of cross-logging into whichever
# engagement bound last. A fresh thread starts from the default (ambient), which is
# the correct fail-safe: an unbound context logs to the process-level file, never
# into an unrelated engagement's audit trail.
_BOUND_SLUG: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "vigil_engagement_slug", default=None
)


def _engagement_log_path() -> Path:
    slug = _BOUND_SLUG.get()
    if slug is not None:
        try:
            return paths.crucible_v2_log(slug)
        except Exception:
            pass  # fall through to ambient
    return paths.v2_root() / ".crucible-v2.log"


def _scrub(_logger: Any, _name: str, event_dict: Any) -> Any:
    """Processor: mask secret-keyed fields (token/cookie/authorization/password/…)
    BEFORE the event is serialised to disk (X2). Deterministic + total — an
    unrecognised field passes through unchanged, so log shape is preserved and no
    determinism/replay property is affected. Runs just before `_emit_json`."""
    return redact.scrub_log_event(dict(event_dict))


def _rotate_with_retention(p: Path) -> None:
    """Roll the over-cap log ``p`` into a numbered backup ring, RETAINING history
    (W16-STD-6(a)). The oldest backup beyond the retention window is dropped FIRST
    (an explicit, documented policy — never the old silent 128 MiB truncation), then
    each surviving backup shifts up one (``.N-1`` -> ``.N`` … ``.1`` -> ``.2``), then
    the live file becomes ``.1``. ``os.replace`` is atomic per step and preserves the
    inode mode, so a pre-existing loose (0644) backup is re-tightened after each move.
    Any per-file OSError is swallowed so a single stuck backup never blocks the
    append hot path (the live file still rolls to ``.1``)."""
    keep = _LOG_BACKUP_COUNT if _LOG_BACKUP_COUNT >= 1 else 1
    oldest = p.with_suffix(p.suffix + f".{keep}")
    try:
        if oldest.exists():
            oldest.unlink()                          # prune only PAST the retention window
    except OSError:
        pass
    for k in range(keep - 1, 0, -1):
        src = p.with_suffix(p.suffix + f".{k}")
        dst = p.with_suffix(p.suffix + f".{k + 1}")
        try:
            if src.exists():
                os.replace(src, dst)
                paths.secure_existing(dst)
        except OSError:
            pass
    rotated = p.with_suffix(p.suffix + ".1")
    os.replace(p, rotated)
    paths.secure_existing(rotated)


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
            _rotate_with_retention(p)
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
    """Route subsequent logs from THIS context (thread/task) to this engagement's
    file. None resets this context to ambient. The binding is per-context
    (ContextVar), so concurrent engagements in the same process do not cross-log."""
    _BOUND_SLUG.set(slug)


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)


# Initial configuration so importing this module is enough to log.
configure()
