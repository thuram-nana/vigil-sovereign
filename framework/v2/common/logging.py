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
from pathlib import Path
from typing import Any

import structlog

from . import paths


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


def _emit_json(_logger: Any, _name: str, event_dict: dict[str, Any]) -> str:
    """Final processor: write the event to disk and stop the chain."""
    p = _engagement_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event_dict, default=str, separators=(",", ":"), sort_keys=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    raise structlog.DropEvent


def configure(level: str = "INFO") -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
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
