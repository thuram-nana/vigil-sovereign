"""voice.hud_status (S4) — the EPHEMERAL on-screen HUD status file.

The voice FSM churns idle→listening→thinking→speaking many times per interaction; that telemetry must
NEVER hit the append-only, signed audit spine (the same telemetry-vs-audit split the gesture layer enforces
for 30 fps frames). So the FSM state is written to a small, owner-only (0600) status FILE that the cockpit
reads and fans out over ``/api/sigil/hud``. The file is ephemeral state, not a record of truth.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

_MAX = 4096


def status_path() -> Path:
    """The 0600 HUD status file, under the sovereign runtime home both the voice daemon (writer) and the
    cockpit (reader) resolve identically."""
    from ..config import SIGIL_HOME
    return SIGIL_HOME / "sigil-hud.json"


class StatusSink:
    """A pipeline ``on_state`` observer that writes the FSM state to the 0600 status file (atomic, unique
    temp + replace). Pure output; a write error is swallowed so it never breaks the voice loop."""

    def __init__(self, path: Optional[Path] = None):
        self._path = Path(path) if path is not None else status_path()

    def __call__(self, status: dict) -> None:
        try:
            rec = {"state": str(status.get("state", "idle")),
                   "transcript": str(status.get("transcript", ""))[:200],
                   "feedback": str(status.get("feedback", ""))[:200]}
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".sigil-hud.", dir=str(self._path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(rec, fh, ensure_ascii=False)
                os.chmod(tmp, 0o600)
                os.replace(tmp, self._path)
            except OSError:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        except OSError:
            pass                                       # HUD telemetry is best-effort; never raise


def read_status(path: Optional[Path] = None) -> Optional[dict]:
    """The last-written HUD status (``{state, transcript, feedback}``), or None if absent/unreadable."""
    p = Path(path) if path is not None else status_path()
    try:
        if p.stat().st_size > _MAX:
            return None
        data: Any = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None
