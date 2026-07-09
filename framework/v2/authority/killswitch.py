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

import errno
import json
import os
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

    # errno values that positively prove the switch file is absent. Any
    # other stat error is ambiguous and must fail closed (TRIPPED).
    _ABSENT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ENAMETOOLONG})

    def is_tripped(self) -> bool:
        """Return True (HALTED) unless the switch file can be positively
        determined to be absent.

        ``Path.is_file()`` swallows every ``OSError`` and reports ``False``,
        so an unreadable parent directory or a broken symlink would read as
        CLEAR — the opposite of what a fail-closed hard stop must do. Here,
        only an errno that proves the file is genuinely absent (ENOENT and
        friends) is treated as CLEAR; any other error (permission denied,
        symlink loop, I/O error) is treated as TRIPPED."""
        try:
            os.stat(self._path)
        except OSError as e:
            if e.errno in self._ABSENT_ERRNOS:
                # The switch file is genuinely absent -> CLEAR.
                return False
            # Ambiguous (permission denied, symlink loop, I/O error, ...):
            # cannot prove absence, so fail closed -> TRIPPED.
            _log.warning(
                "authority.killswitch.stat_ambiguous",
                slug=self._slug,
                errno=e.errno,
                error=str(e),
            )
            return True
        # The path exists (regular file = normal tripped state, or any
        # other node) -> TRIPPED.
        return True

    def trip(self, reason: str) -> None:
        """Halt the engagement. Idempotent: the first reason is preserved
        so the original cause is not overwritten by a later trip."""
        paths.secure_dir(self._path.parent)          # X2: owner-only authority dir
        if self._path.is_file():
            _log.warning("authority.killswitch.already_tripped", slug=self._slug)
            return
        payload = {
            "slug": self._slug,
            "reason": reason,
            "tripped_at": datetime.now(timezone.utc).isoformat(),
        }
        paths.secure_write(self._path, json.dumps(payload, indent=2))   # X2: owner-only
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
