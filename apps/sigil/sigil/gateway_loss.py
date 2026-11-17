"""PRICING G1 — the LOSS ALARM: when the day's UNCONFIRMED provider spend runs past 2% of the day's CONFIRMED
provider spend, the gateway refuses new reservations and raises an owner alert (a ``vigil doctor`` hard issue and a
unit alert); it clears when the day reconciles.

Unconfirmed spend (``vigil_core.model_metering`` / ``sigil.model_gateway``) is spend VIGIL must assume but cannot
prove it was billed for a customer run — a crash between a call and its meter record (an orphan), the unreported rest
of a cut-off stream — and it is NEVER billed to the customer: it is VIGIL's own cost. A little is normal; a lot, day
over day, means something is wrong (a leaking account, a crash loop, a misconfigured pool) and VIGIL is bleeding
money it cannot recover. The 2% rule turns that from a slow invisible loss into a hard stop with an owner alert.

The rule (both amounts are nano-USD, from the gateway meter's own per-day split of confirmed vs unconfirmed spend):

    the day's unconfirmed spend  >  2% of the day's confirmed spend        (STRICT: at exactly 2% it does not trip)

so ``100 * unconfirmed > 2 * confirmed`` in integers. When the day has confirmed spend of zero and any unconfirmed
spend, the ratio is unbounded and it trips (any loss with nothing confirmed beside it is over 2%).

While tripped, :meth:`LossLedger.tripped` is True, the gateway refuses a new reservation with a retryable overloaded
error (so a run is held, not failed on the customer), and a durable alarm file
(``$SIGIL_HOME/alarms/gateway-loss.json``) names the day and the amounts. It clears automatically when the ratio
falls back to 2% or below (the day's confirmed spend catches up, or a new UTC day starts from zero), and the owner
may acknowledge the day (``sigil gateway-loss ack``) once they have reconciled it, which resumes reservations for
that day and records who/when in an append-only log.

SOVEREIGN plane (FATAL-2): framework-free, ``assert_no_offense()`` at import; ``vigil doctor`` and ``vigil alerts``
read the inert JSON file without importing this module.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Iterator, Optional

from .reuse import assert_no_offense

assert_no_offense()

__all__ = ["LOSS_ALARM_NAME", "LossLedger", "alarm_path", "read_alarm", "LOSS_THRESHOLD_NUM", "LOSS_THRESHOLD_DEN"]

_log = logging.getLogger(__name__)

#: the alarm file ``vigil doctor`` and ``vigil alerts`` read (the same name is used by both without importing here)
LOSS_ALARM_NAME = "gateway-loss.json"
#: the 2% rule as an exact fraction (unconfirmed / confirmed > NUM / DEN); kept as integers so the test is exact
LOSS_THRESHOLD_NUM = 2
LOSS_THRESHOLD_DEN = 100
_MAX_RECORD = 1 * 1024 * 1024


def _utc_day(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def alarm_path(sigil_home: "Optional[os.PathLike | str]" = None) -> Path:
    """``<SIGIL_HOME>/alarms/gateway-loss.json`` (resolved at call time, as ``settle_hold`` resolves its own alarm)."""
    home = Path(sigil_home) if sigil_home is not None else Path(
        os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))
    return home / "alarms" / LOSS_ALARM_NAME


def read_alarm(sigil_home: "Optional[os.PathLike | str]" = None) -> "Optional[dict]":
    """The alarm record (a dict) when the loss alarm is raised, None when there is none, and ``{"unreadable": True}``
    when the file exists but cannot be read (doctor treats that as a hard issue too). Never raises."""
    p = alarm_path(sigil_home)
    try:
        if p.is_symlink():
            return {"unreadable": True}
        if not p.exists():
            return None
        if p.stat().st_size > _MAX_RECORD:
            return {"unreadable": True}
        rec = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"unreadable": True}
    if not isinstance(rec, dict) or rec.get("tripped") is not True:
        return {"unreadable": True}
    return rec


class LossLedger:
    """The day's confirmed and unconfirmed provider spend, the 2% rule over them, and the durable owner alarm.

    One per gateway process; the gateway's meter calls :meth:`add` as it records spend. Thread-safe. The in-memory
    totals are for the current UTC day only (a new day starts from zero); the gateway seeds the day at start from the
    meter files (:meth:`seed`), so a restart still knows the day's totals."""

    def __init__(self, alarm_file: "os.PathLike | str", *, clock=time.time) -> None:
        self._alarm_file = Path(alarm_file)
        self._clock = clock
        self._lock = threading.Lock()
        self._day = ""
        self._confirmed = 0
        self._unconfirmed = 0
        self._acked_day = ""

    @staticmethod
    def _breaches(confirmed: int, unconfirmed: int) -> bool:
        return LOSS_THRESHOLD_DEN * unconfirmed > LOSS_THRESHOLD_NUM * confirmed

    def set_day(self, day: str, confirmed: int, unconfirmed: int, now: Optional[float] = None) -> None:
        """Set the current day's confirmed and unconfirmed provider-spend totals (nano-USD) — the gateway meter is
        the source of truth and pushes its authoritative per-day split here, so this REPLACES, never accumulates.
        Re-evaluates the 2% rule and writes or clears the alarm file. A set for a day other than the one the meter is
        on rolls the ledger to it (a new UTC day starts from the values given)."""
        now = self._clock() if now is None else now
        with self._lock:
            self._day = str(day)
            self._confirmed = max(0, int(confirmed))
            self._unconfirmed = max(0, int(unconfirmed))
            self._sync_locked(now)

    def seed(self, confirmed: int, unconfirmed: int, now: Optional[float] = None) -> None:
        """Seed today's totals at gateway start (from the start-up scan of the meter files)."""
        now = self._clock() if now is None else now
        self.set_day(_utc_day(now), confirmed, unconfirmed, now)

    def _acked(self, day: str) -> bool:
        """True iff ``day`` has been acknowledged — in memory, or by the DURABLE ack marker, so an acknowledgement
        made by a separate ``sigil gateway-loss ack`` process is honoured by the running gateway."""
        if self._acked_day == day:
            return True
        return self._read_ack_marker() == day

    def tripped(self, now: Optional[float] = None) -> bool:
        """Whether new reservations must be refused right now: the live ratio breaches 2% and the day has neither
        rolled over nor been acknowledged by the owner. The durable ack marker is read only when the ratio actually
        breaches (the rare, money-losing case), so a healthy gateway does no extra I/O here."""
        now = self._clock() if now is None else now
        with self._lock:
            if self._day != _utc_day(now) or not self._breaches(self._confirmed, self._unconfirmed):
                return False                # a new day starts clean; within 2% nothing is refused
            return not self._acked(self._day)

    def state(self, now: Optional[float] = None) -> dict:
        now = self._clock() if now is None else now
        with self._lock:
            fresh = self._day == _utc_day(now)
            breaches = fresh and self._breaches(self._confirmed, self._unconfirmed)
            acked = bool(breaches and self._acked(self._day))
            return {"day": self._day, "confirmed_nano": self._confirmed, "unconfirmed_nano": self._unconfirmed,
                    "tripped": bool(breaches and not acked), "acked": acked}

    def acknowledge(self, by: str, now: Optional[float] = None) -> dict:
        """The owner acknowledges today's loss alarm once reconciled: reservations resume for the day (a DURABLE ack
        marker a running gateway honours) and the alarm file clears. Records who and when in the append-only log
        beside the alarm. Returns the recorded entry. Usable from a separate process (`sigil gateway-loss ack`)."""
        now = self._clock() if now is None else now
        who = str(by).strip() or "unknown"
        with self._lock:
            day = _utc_day(now)
            if self._day != day:            # acknowledging from a separate process: adopt today's bare day
                self._day, self._confirmed, self._unconfirmed = day, 0, 0
            self._acked_day = day
            entry = {"at": _dt.datetime.fromtimestamp(now, _dt.timezone.utc).isoformat(timespec="seconds"),
                     "by": who[:200], "day": day, "confirmed_nano": self._confirmed,
                     "unconfirmed_nano": self._unconfirmed}
            self._write_ack_marker(entry)
            self._append_ack(entry)
            self._sync_locked(now)
        _log.warning("gateway loss alarm: %s acknowledged the loss alarm for %s (confirmed %d, unconfirmed %d nano)",
                     who, day, entry["confirmed_nano"], entry["unconfirmed_nano"])
        return entry

    # -- the durable alarm file --------------------------------------------------------------------------
    def _ack_marker(self) -> Path:
        return self._alarm_file.parent / (self._alarm_file.stem + ".ack")

    def _read_ack_marker(self) -> str:
        """The UTC day the durable ack marker names, or ``""`` when there is none / it cannot be read."""
        p = self._ack_marker()
        try:
            if p.is_symlink() or not p.exists():
                return ""
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ""
        return str(rec.get("day", "")) if isinstance(rec, dict) else ""

    def _write_ack_marker(self, entry: dict) -> None:
        with self._locked_file():
            p = self._ack_marker()
            tmp = p.parent / (p.name + ".tmp")
            tmp.write_text(json.dumps(entry, sort_keys=True), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, p)

    def _sync_locked(self, now: float) -> None:
        """Write or clear the alarm file to match the live state. Never raises (an alarm write must not break a
        settle); a failure is logged. The ack marker is read only when the ratio breaches."""
        try:
            if self._breaches(self._confirmed, self._unconfirmed) and not self._acked(self._day):
                self._write({"v": 1, "tripped": True, "day": self._day, "confirmed_nano": self._confirmed,
                             "unconfirmed_nano": self._unconfirmed, "threshold_pct": 2,
                             "at": _dt.datetime.fromtimestamp(now, _dt.timezone.utc).isoformat(timespec="seconds")})
            else:
                self._remove()
        except Exception:  # noqa: BLE001 — an alarm write never breaks the caller
            _log.critical("gateway loss alarm: could not update %s", self._alarm_file, exc_info=True)

    @contextlib.contextmanager
    def _locked_file(self) -> Iterator[None]:
        import fcntl
        self._alarm_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = self._alarm_file.parent / (self._alarm_file.name + ".lock")
        fd = os.open(str(lock), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _write(self, record: dict) -> None:
        with self._locked_file():
            tmp = self._alarm_file.parent / (self._alarm_file.name + ".tmp")
            tmp.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._alarm_file)

    def _remove(self) -> None:
        if self._alarm_file.exists() or self._alarm_file.is_symlink():
            with self._locked_file():
                self._alarm_file.unlink(missing_ok=True)

    def _append_ack(self, entry: dict) -> None:
        log = self._alarm_file.parent / (self._alarm_file.stem + ".ack.jsonl")
        log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(log), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
