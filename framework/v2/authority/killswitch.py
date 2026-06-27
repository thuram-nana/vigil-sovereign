"""
authority.killswitch — the persistent, fail-closed hard stop.

A KillSwitch is a file on disk. Tripping it writes the file; the gate
refuses every action while the file exists. Because the state lives on
disk, a tripped switch survives a process crash or restart — there is no
in-memory-only "halt" that a reboot could quietly undo. That persistence
is the point: when an operator hits stop, it stays stopped until a human
deliberately clears it.

Clearing is intentionally a separate, explicit operator act (not
something the framework does on its own), and it is logged.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..common import logging as clog
from ..common import paths

_log = clog.get_logger("authority.killswitch")


class KillSwitch:
    """File-backed hard stop for one engagement."""

    def __init__(self, slug: str, *, path: Path | None = None) -> None:
        self._slug = slug
        self._path = path if path is not None else paths.killswitch_path(slug)

    @property
    def path(self) -> Path:
        return self._path

    def is_tripped(self) -> bool:
        return self._path.is_file()

    def trip(self, reason: str) -> None:
        """Halt the engagement. Idempotent: the first reason is preserved
        so the original cause is not overwritten by a later trip."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.is_file():
            _log.warning("authority.killswitch.already_tripped", slug=self._slug)
            return
        payload = {
            "slug": self._slug,
            "reason": reason,
            "tripped_at": datetime.now(timezone.utc).isoformat(),
        }
        self._path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _log.warning("authority.killswitch.tripped", slug=self._slug, reason=reason)

    def reason(self) -> str | None:
        if not self._path.is_file():
            return None
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # A present-but-unreadable kill-switch file still means HALTED.
            return "kill-switch file present but unreadable"
        value = data.get("reason")
        return str(value) if value is not None else ""

    def clear(self, cleared_by: str) -> None:
        """Deliberately lift the halt. Logged. A no-op if not tripped."""
        if not self._path.is_file():
            return
        self._path.unlink()
        _log.warning("authority.killswitch.cleared", slug=self._slug, cleared_by=cleared_by)
