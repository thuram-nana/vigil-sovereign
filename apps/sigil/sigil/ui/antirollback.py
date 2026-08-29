"""Wave 8 (parity) — surface the sovereign ANTI-ROLLBACK status (the durable external floor + the spine's
segment-rotation state) in the browser, read-only. Shells THIS venv's `sigil <verb> status` (fixed argv,
no request input, shell=False) and returns its text. Viewer+ (the status is metadata — last_seq / anchor /
segment set — no key or secret). The floor `reset` / spine `rotate|compact` mutations stay CLI/owner-only
(deferred); this is the status half only. FATAL-2: pure sovereign — spawns `python -m sigil`, imports no
framework/strix.
"""
from __future__ import annotations

import subprocess
import sys


def _status(verb: str, timeout: int = 30) -> dict:
    # FIXED argv — the verb is a literal here (never request-controlled); action is always "status".
    try:
        proc = subprocess.run([sys.executable, "-m", "sigil", verb, "status"],   # noqa: S603 — fixed argv, shell=False
                              capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": proc.returncode == 0, "verb": verb, "exit_code": proc.returncode,
            "text": (proc.stdout or "")[:6000], "stderr": (proc.stderr or "")[:1000]}


def floor_status() -> dict:
    """`sigil floor status` — the durable external anti-rollback floor (last_seq, external anchors, witness)."""
    return _status("floor")


def spine_status() -> dict:
    """`sigil spine status` — the spine's segment-rotation state (segment set, boundaries, sealed heads)."""
    return _status("spine")
