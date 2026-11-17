"""W5 — orgs on a BILLING HOLD, as a durable alarm the owner's tools read without the spine.

An org that owes credits after a chargeback or refund (``governor.billing_reversal``) is on a billing hold. The hold
itself is the reversal fold; this module mirrors it into ``$SIGIL_HOME/alarms/billing-hold.json`` — the alarm
directory ``vigil doctor`` reads (a HARD issue while the file names an org) and ``vigil alerts`` pushes (one
``billing-hold`` alarm per held org per cycle) — so the owner is alerted from processes that never fold the spine:

* every reversal step and every repay calls :func:`sync_hold` with what the org owes after it: an org that owes is
  named (with the amount, kept up to date; ``since`` is the time it was first named), an org that owes nothing is
  dropped, and the file is removed when it names none;
* :func:`sync_all` rewrites the record from the fold (``sigil billing-reversal status --sync``).

The record is written atomically (0600, under a per-file lock). A record that cannot be read is never overwritten (an
unreadable record is itself a hard issue in ``vigil doctor``). Every function here is total: a failure is logged
CRITICAL and reported through the return value, never raised into a money step — the hold is enforced from the spine
whatever this file says.

SOVEREIGN PLANE ONLY (FATAL-2): ``assert_no_offense()`` at import; the integration plane reads the JSON only.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..reuse import assert_no_offense

assert_no_offense()

_log = logging.getLogger(__name__)

#: The alarm file ``vigil doctor`` and ``vigil alerts`` read (``integration/vigil_integration`` names the same file).
HOLD_ALARM_NAME = "billing-hold.json"
_MAX_RECORD = 4 * 1024 * 1024


class _Unreadable(Exception):
    """The alarm record exists but cannot be read or parsed."""


def hold_alarm_path() -> Path:
    """``$SIGIL_HOME/alarms/billing-hold.json`` (resolved at call time; doctor and the alert monitor read the same)."""
    home = Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))
    return home / "alarms" / HOLD_ALARM_NAME


@contextlib.contextmanager
def _locked(p: Path) -> Iterator[None]:
    import fcntl
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(p.parent / (p.name + ".lock")), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _load(p: Path) -> "list[dict]":
    try:
        if p.is_symlink():
            raise _Unreadable("the alarm record is a symlink")
        if not p.exists():
            return []
        if p.stat().st_size > _MAX_RECORD:
            raise _Unreadable("the alarm record is too large")
        rec = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise _Unreadable(type(e).__name__) from e
    held = rec.get("held") if isinstance(rec, dict) else None
    if not isinstance(held, list) or not all(isinstance(h, dict) and isinstance(h.get("org_id"), str) for h in held):
        raise _Unreadable("the alarm record is malformed")
    return held


def _store(p: Path, held: "list[dict]") -> None:
    if not held:
        p.unlink(missing_ok=True)
        return
    tmp = p.parent / (p.name + ".tmp")
    tmp.write_text(json.dumps({"v": 1, "held": sorted(held, key=lambda h: h["org_id"]), "at": time.time()},
                              sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def _merge(held: "list[dict]", org_id: str, owed: int) -> "list[dict]":
    kept = [h for h in held if h.get("org_id") != org_id]
    if owed > 0:
        prev = next((h for h in held if h.get("org_id") == org_id), None)
        since = prev.get("since") if isinstance(prev, dict) and isinstance(prev.get("since"), (int, float)) else None
        kept.append({"org_id": str(org_id), "owed": int(owed), "since": float(since) if since else time.time()})
    return kept


def sync_hold(org_id: str, owed: int) -> bool:
    """Name ``org_id`` as on hold owing ``owed`` credits, or drop it when it owes nothing. True when the record now says
    so; never raises (an unreadable record is left as it is)."""
    try:
        p = hold_alarm_path()
        if owed <= 0 and not p.exists() and not p.is_symlink():
            return True
        with _locked(p):
            held = _load(p)
            merged = _merge(held, str(org_id), int(owed))
            if merged != held:
                _store(p, merged)
        return True
    except Exception:  # noqa: BLE001 — an alarm write never breaks a money step; doctor reports an unreadable record
        _log.critical("could not record the billing hold of %s in %s", org_id, HOLD_ALARM_NAME, exc_info=True)
        return False


def sync_all(holds: "Iterable[tuple[str, int]]") -> bool:
    """Rewrite the record to name exactly ``holds`` (``(org_id, owed)``, from the reversal fold), keeping each named
    org's ``since``. Never raises."""
    try:
        p = hold_alarm_path()
        with _locked(p):
            try:
                held = _load(p)
            except _Unreadable:
                held = []                             # a deliberate rebuild from the fold replaces an unreadable record
            want = {str(o): int(n) for o, n in holds if int(n) > 0}
            out = [h for h in held if h.get("org_id") in want]
            for o, n in want.items():
                out = _merge(out, o, n)
            _store(p, out)
        return True
    except Exception:  # noqa: BLE001
        _log.critical("could not rewrite %s", HOLD_ALARM_NAME, exc_info=True)
        return False


def read_holds() -> "Optional[list[dict]]":
    """The named holds (``org_id``, ``owed``, ``since``): [] when there is no record, None when it cannot be read."""
    try:
        return [dict(h) for h in _load(hold_alarm_path())]
    except _Unreadable:
        return None
    except Exception:  # noqa: BLE001
        return None
