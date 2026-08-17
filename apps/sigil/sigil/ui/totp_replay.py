"""Per-account TOTP replay ledger (Slice S4) — refuses a second-factor code already spent for its step.

A TOTP code is valid for its whole 30 s step (and, with the ±1-step skew window, briefly on either side),
so a code sniffed once could be replayed inside that window. This ledger records the ``(username, step)`` of
every SUCCESSFULLY-verified code and refuses a repeat: ``consume(username, step)`` is an ATOMIC
first-writer-wins create — the first login for a ``(username, step)`` wins, and any later attempt presenting
the same code (which necessarily matches the same step) is refused.

Mirrors the atomic single-use discipline of ``login_challenges.ChallengeLedger``: one marker file per
``(username, step)`` where the filesystem's ``O_CREAT | O_EXCL`` IS the serialization point (no lock held).
The marker name is ``{step}-{sha256(username)}`` — the step is an int and the username half a fixed
``[0-9a-f]{64}`` digest, so a marker can neither traverse the directory (no separators / ``..``) nor collide
across users, and a per-consume sweep drops markers older than a few steps so the directory stays bounded.

Fail-CLOSED: any I/O fault (unwritable dir, etc.) makes ``consume`` return ``False`` (a refusal), so a
broken ledger can never silently DISABLE the replay guard — it can only over-refuse, never under-refuse.

Stdlib only — no ``framework`` / ``strix`` / ``vigil_core``. Offense-free by construction.
"""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

# Keep markers this many steps behind the one being consumed, then reap. 4 steps (≈2 min) comfortably covers
# the ±1-step verify window plus slack, while bounding the directory so it never grows without limit.
_DEFAULT_KEEP_STEPS = 4


class TotpReplayLedger:
    """A durable, atomic single-use ledger of spent ``(username, step)`` TOTP codes. ``path`` is the marker
    directory (one per spine, so a test's temp spine gets its own isolated ledger)."""

    def __init__(self, path: "str | os.PathLike", *, keep_steps: int = _DEFAULT_KEEP_STEPS) -> None:
        self.dir = Path(path)
        self.keep_steps = int(keep_steps)

    def _marker(self, username: str, step: int) -> Path:
        uh = hashlib.sha256(str(username).encode("utf-8")).hexdigest()   # fixed [0-9a-f]{64}: no traversal
        return self.dir / f"{int(step)}-{uh}"

    def _sweep(self, floor_step: int) -> None:
        """Remove every marker whose step is strictly below ``floor_step`` (dead — outside any live verify
        window). Only ever ``os.unlink`` (atomic; a marker a concurrent consumer already removed just raises
        and is ignored), so a sweep can never resurrect or double-spend a step."""
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return
        for entry in entries:
            try:
                step = int(entry.name.split("-", 1)[0])
            except (ValueError, IndexError):
                continue                                    # not one of our markers — leave it alone
            if step < floor_step:
                try:
                    os.unlink(entry.path)
                except OSError:
                    pass                                    # already gone (race) → fine

    def consume(self, username: str, step: int) -> bool:
        """ATOMICALLY record ``(username, step)`` as spent. Returns True iff THIS was the first use (the code
        is fresh); False if the same ``(username, step)`` was already recorded (a replay) OR on any I/O error
        (fail-closed to a refusal). The ``O_CREAT | O_EXCL`` create is the serialization point: of N
        concurrent consumers of one code EXACTLY ONE wins and the rest get ``FileExistsError`` → refused."""
        try:
            self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            return False                                    # fail-closed: cannot record ⇒ refuse
        self._sweep(int(step) - self.keep_steps)
        marker = self._marker(username, step)
        try:
            fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False                                    # already spent for this step → replay refused
        except OSError:
            return False                                    # fail-closed on any other I/O fault
        try:
            os.write(fd, repr(time.time()).encode("ascii"))  # the spend time, for audit / any future TTL
            os.fsync(fd)
        finally:
            os.close(fd)
        return True
