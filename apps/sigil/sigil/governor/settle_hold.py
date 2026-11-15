"""Customer launch settles HELD for the owner — a durable alarm `vigil doctor` reports as a hard issue.

A launch settle that cannot tell how much of a reservation to return to each credit bucket moves nothing and is
refused ``launch_gate.PLAN_DEBIT_PRUNED``, whoever asked for it: a customer cancel, the settle drain, ``ops-sweep
reservations`` or the release of a superseded reservation. ``LaunchGate`` then names the launch here, in
``$SIGIL_HOME/alarms/launch-settle-held.json`` (the alarm directory `vigil doctor` reads), and `vigil doctor` reports
the named launches (slugs only) as a HARD issue until each one settles:

* a later settle of that launch that completes, or finds it already settled, drops its name
  (:func:`release_held`);
* ``ops-sweep reservations --apply`` drops every name the spine or the seam marker shows settled
  (``LaunchGate.release_settled_holds``), e.g. once the owner has settled it;
* the file is removed when it names none.

The record is written atomically (0600, under a per-file lock shared by every process that settles: the cockpit, the
settle drain and the sweeps). A record that cannot be read is never overwritten (`vigil doctor` reports it as a hard
issue on its own), so no held launch it names can be dropped by a later write. Every function here is total: a
failure is logged CRITICAL and reported through the return value, never raised into a settle.

SOVEREIGN PLANE ONLY (FATAL-2): framework-free, ``assert_no_offense()`` at import; `vigil doctor` reads the JSON
file without importing this module.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Iterator, Optional

from ..reuse import assert_no_offense

assert_no_offense()

_log = logging.getLogger(__name__)

#: The alarm file `vigil doctor` reads (``integration/vigil_integration/doctor.py`` names the same file).
HELD_ALARM_NAME = "launch-settle-held.json"
_MAX_RECORD = 4 * 1024 * 1024


class _Unreadable(Exception):
    """The alarm record exists but cannot be read or parsed."""


def held_alarm_path() -> Path:
    """``$SIGIL_HOME/alarms/launch-settle-held.json`` (resolved at call time; doctor reads the same path)."""
    home = Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))
    return home / "alarms" / HELD_ALARM_NAME


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
    """The held entries of the record at ``p`` ([] when there is none); ``_Unreadable`` when it cannot be used."""
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
    if not isinstance(held, list) or not all(isinstance(h, dict) for h in held):
        raise _Unreadable("the alarm record is malformed")
    return held


def _store(p: Path, held: "list[dict]") -> None:
    if not held:
        p.unlink(missing_ok=True)
        return
    tmp = p.parent / (p.name + ".tmp")
    tmp.write_text(json.dumps({"v": 1, "held": held, "at": time.time()}, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def record_held(org_id: str, slug: str, nonce: str, reason: str) -> bool:
    """Name launch ``(org_id, slug, nonce)`` as held (``reason``: the settle's refusal). Idempotent: a launch already
    named keeps its first entry (and so the time it has been held since). Returns True when the record names it;
    never raises."""
    try:
        p = held_alarm_path()
        with _locked(p):
            held = _load(p)
            if not any(h.get("slug") == slug and h.get("nonce") == nonce for h in held):
                held.append({"org_id": str(org_id), "slug": str(slug), "nonce": str(nonce),
                             "reason": str(reason)[:64], "since": time.time()})
                _store(p, held)
        return True
    except Exception:  # noqa: BLE001 — an alarm write never breaks a settle; doctor reports an unreadable record
        _log.critical("could not record the held settle of launch %s (%s) in %s", slug, reason, HELD_ALARM_NAME,
                      exc_info=True)
        return False


def release_held(slug: str, nonce: str) -> bool:
    """Drop launch ``(slug, nonce)`` from the record (the file goes when it names none). A no-op without a record.
    Returns True when the record no longer names it; never raises (an unreadable record is left as it is)."""
    try:
        p = held_alarm_path()
        if not p.exists() and not p.is_symlink():
            return True
        with _locked(p):
            held = _load(p)
            kept = [h for h in held if not (h.get("slug") == slug and h.get("nonce") == nonce)]
            if len(kept) != len(held):
                _store(p, kept)
        return True
    except Exception:  # noqa: BLE001
        _log.critical("could not drop launch %s from %s", slug, HELD_ALARM_NAME, exc_info=True)
        return False


def read_held() -> "Optional[list[dict]]":
    """The held entries (``org_id``, ``slug``, ``nonce``, ``reason``, ``since``): [] when there is no record, None
    when it cannot be read. Never raises."""
    try:
        return [dict(h) for h in _load(held_alarm_path())]
    except _Unreadable:
        return None
    except Exception:  # noqa: BLE001
        return None
