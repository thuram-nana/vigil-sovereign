"""E3bc — a recorded settle the settle drain cannot finish is never silent, marker or not.

With ``VIGIL_SETTLE_SPINE_RECORD`` on, a recorded settle the drain's finish pass cannot finish (a lock, a ledger, the
seam or the spool not writable — its seam marker never written included, which ``vigil doctor``'s marker probe cannot
see) holds the customer's refund and any relaunch on that host. Every pass records, beside the completion spool, the
leases it left unfinished and since when (``vigil_integration.live.settle_progress``), and whether the pass itself
kept failing; past ``UNFINISHED_SETTLE_GRACE_S`` the drain reports ``settle_stuck`` and the CLI prints an ALARM and
exits non-zero (the unit stays FAILED). A record it cannot write while something is held alarms at once. A lease
leaves the record when its settle lands. ``vigil doctor`` reads the same record
(``integration/tests/test_doctor_unfinished_settle.py``). A settled lease whose money landed but that cannot be retired
from the seam (its tombstone fails) is reported ``tombstone_failed`` every pass and recorded and alarmed the same way;
the drain re-drives it at most once every ``settle_checkpoint.RETIRE_RETRY_S`` (the alarm grace), never skipping its
first re-drive nor a settle with money still to land.

Mutation-verify targets (each neuter turns a NAMED test red):
  * the alarm count / its grace / first_seen not carried     -> test_a_settle_the_drain_cannot_finish_alarms_...,
                                                                 test_the_cli_fails_the_unit_with_an_alarm_...
  * the CLI alarm dropped                                     -> test_the_cli_fails_the_unit_with_an_alarm_...
  * an unwritable record not alarmed                          -> test_an_unwritable_progress_record_alarms_at_once
  * a failing finish pass not counted (its since reset)       -> test_a_finish_pass_that_keeps_failing_alarms_...
  * a finished lease not dropped / an empty record kept       -> test_a_settle_the_drain_cannot_finish_alarms_...
  * a lease left on the seam reported already_settled / not counted unfinished / not re-checked on the seam
                                                              -> test_a_settled_lease_the_drain_cannot_retire_...
  * re-driven every pass / never re-driven again / the retry cadence off the alarm grace
                                                              -> test_a_settled_lease_the_drain_cannot_retire_...,
                                                                 test_a_lease_retired_by_its_due_re_drive_never_alarms
  * the retire record trusted when unreadable, from the future or expired / over a settle with money to land
                                                              -> test_the_retire_record_never_skips_a_first_...

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_settle_drain_unfinished_alarm.py
"""
from __future__ import annotations

import json
import os
import time
import types
from pathlib import Path

import pytest

from sigil import settle_checkpoint
from sigil.governor.wallet import WalletRegistry
from sigil.settle_checkpoint import RETIRE_NAME, RETIRE_RETRY_S
from sigil.spine.store import SpineError, SpineStore
from sigil.ui.launch_gate import LaunchGate
from test_drain_quarantine_alarm import _write_gov_delegation
from test_settle_finish_pass_incremental import _decided_no_marker, _drain
from test_settle_one_pass_evidence import (  # noqa: F401  (_iso: the autouse isolation fixture)
    _NONE, NOW, B, _avail, _base, _counting, _iso, _kill, _published, _reserve, _seat, _settle, _spool, _store,
)
from vigil_integration.live import settle_progress
from vigil_integration.live.credit_lease_broker import unfinished_settlements

GRACE = settle_progress.UNFINISHED_SETTLE_GRACE_S


@pytest.fixture
def record_on(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")


def test_a_settle_the_drain_cannot_finish_alarms_past_its_grace_marker_or_not(record_on, monkeypatch, capsys):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    restore = _kill(monkeypatch, B, "record_lease_settlement", exc=PermissionError(13, "settlements dir not writable"))
    assert _settle(s, rA, 0, basis="cancel").get("retry") is True          # decision recorded, NO marker
    spool, clock = _spool(), {"t": NOW + 60}
    w = _drain(s, spool, clock, scope=rA["slug"])
    assert w.drain() == {**_NONE, "settle_unfinished": 1}
    assert settle_progress.read_state(spool)["leases"] == [
        {"slug": rA["slug"], "nonce": rA["nonce"], "first_seen": NOW + 60}]
    clock["t"] = NOW + 60 + GRACE - 1
    assert w.drain() == {**_NONE, "settle_unfinished": 1}                  # inside the grace: no alarm yet
    clock["t"] = NOW + 60 + GRACE
    assert w.drain() == {**_NONE, "settle_unfinished": 1, "settle_stuck": 1}
    assert f"a recorded settle of {rA['slug']} has not finished for more than 600 s" in capsys.readouterr().err
    assert unfinished_settlements(_base(), now=clock["t"] + 1e6, grace=0) == []   # the marker probe cannot see it
    held, err = settle_progress.overdue(settle_progress.read_state(spool), now=clock["t"])   # vigil doctor reads this
    assert held == [(rA["slug"], rA["nonce"])] and err is None
    assert _avail(s) == 700
    restore()
    clock["t"] += 60
    assert w.drain() == {**_NONE, "settle_completed": 1}                  # it lands, and the record is cleared
    assert not settle_progress.state_path(spool).exists() and _avail(s) == 1_000
    assert w.drain() == _NONE and not settle_progress.state_path(spool).exists()


def test_the_cli_fails_the_unit_with_an_alarm_while_a_settle_stays_unfinished(record_on, monkeypatch, capsys, tmp_path):
    import sigil.cli as cli
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert _settle(s, rA, 0, basis="cancel").get("retry") is True          # decision + marker, money not landed
    spool = Path(_spool())
    settle_progress.update_state(spool, now=time.time() - GRACE - 5, unfinished=[(rA["slug"], rA["nonce"])])
    monkeypatch.setattr(cli, "SpineStore", lambda: s)
    a = types.SimpleNamespace(spool=str(spool), base_dir=_base(), delegation=_write_gov_delegation(tmp_path),
                              scope="*", settle_cmd="drain", interval=2.0)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_settle_drain(a)
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "ALARM: 1 recorded settle(s) have not been finished" in err and "is not finished yet: deferred" in err
    restore()
    cli.cmd_settle_drain(a)                                                # finished: a clean exit, record cleared
    assert _avail(s) == 1_000 and not settle_progress.state_path(spool).exists()


def test_an_unwritable_progress_record_alarms_at_once(record_on, monkeypatch, capsys):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert _settle(s, rA, 0, basis="cancel").get("retry") is True
    spool = _spool()
    os.mkdir(settle_progress.state_path(spool))                           # the record cannot be replaced
    out = _drain(s, spool, {"t": NOW + 60}, scope=rA["slug"]).drain()
    assert out == {**_NONE, "settle_unfinished": 1, "settle_stuck": 1}, out
    assert "could not record the unfinished settles" in capsys.readouterr().err


def test_a_finish_pass_that_keeps_failing_alarms_past_its_grace(record_on, monkeypatch, capsys):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    _decided_no_marker(monkeypatch, s, rA)                                 # only the spine shows it
    real = SpineStore.iter_records

    def unreadable(self, *a, **k):
        raise SpineError("a sealed segment referenced by the manifest is missing")

    monkeypatch.setattr(SpineStore, "iter_records", unreadable)
    spool, clock = _spool(), {"t": NOW + 60}
    w = _drain(s, spool, clock, scope=rA["slug"])
    assert w.drain() == {**_NONE, "settle_finish_error": "SpineError"}    # never "nothing to finish"
    assert "interrupted settles not checked: SpineError" in capsys.readouterr().err
    clock["t"] += GRACE
    assert w.drain() == {**_NONE, "settle_finish_error": "SpineError", "settle_stuck": 1}
    assert "has failed for more than 600 s (SpineError)" in capsys.readouterr().err
    assert settle_progress.overdue(settle_progress.read_state(spool), now=clock["t"]) == ([], "SpineError")
    monkeypatch.setattr(SpineStore, "iter_records", real)
    clock["t"] += 60
    assert w.drain() == {**_NONE, "settle_completed": 1} and _avail(s) == 1_000
    assert not settle_progress.state_path(spool).exists()


# =====================================================================================================================
# a settled lease the drain cannot retire from the seam: reported, alarmed, re-driven once per grace
# =====================================================================================================================
def _unretirable(monkeypatch, s, r):
    """``r`` settled in full (its money landed) while its bundle cannot be removed from the seam; returns a restorer."""
    real = B.tombstone_credit_lease
    monkeypatch.setattr(B, "tombstone_credit_lease", lambda *a, **k: False)
    assert _settle(s, r, 100, basis="completion:completed")["ok"]
    assert _published(r) and _avail(s) == 900
    return lambda: monkeypatch.setattr(B, "tombstone_credit_lease", real)


def _redrives(monkeypatch):
    """Every ``settle_launch`` call from here on, by its ``finish_only``."""
    calls, real = [], LaunchGate.settle_launch

    def spy(self, **kw):
        calls.append(kw.get("finish_only"))
        return real(self, **kw)

    monkeypatch.setattr(LaunchGate, "settle_launch", spy)
    return calls


def test_the_retire_retry_is_the_alarm_grace():
    assert RETIRE_RETRY_S == GRACE


def test_a_settled_lease_the_drain_cannot_retire_is_reported_alarmed_and_re_driven_once_per_grace(
        record_on, monkeypatch, capsys):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    fixed = _unretirable(monkeypatch, s, rA)
    calls = _redrives(monkeypatch)
    spool, t0 = _spool(), NOW + 60
    clock = {"t": t0}
    w = _drain(s, spool, clock, scope=rA["slug"])
    assert w.drain() == {**_NONE, "settle_unfinished": 1}                  # never "already settled"
    assert calls == [True]                                                 # its first re-drive is never skipped
    assert f"a recorded settle of {rA['slug']} is not finished yet: tombstone_failed" in capsys.readouterr().err
    assert settle_progress.read_state(spool)["leases"] == [{"slug": rA["slug"], "nonce": rA["nonce"], "first_seen": t0}]
    seen, n, restore = _counting(monkeypatch, s)
    for dt in range(60, int(GRACE), 60):                                   # inside the grace: reported, not re-driven
        clock["t"] = t0 + dt
        assert w.drain() == {**_NONE, "settle_unfinished": 1}
    restore()
    assert calls == [True] and seen["visits"] == 0, (calls, seen, n)       # nothing appended: nothing read
    clock["t"] = t0 + GRACE                                                # re-driven once, and still not retired
    assert w.drain() == {**_NONE, "settle_unfinished": 1, "settle_stuck": 1}
    assert calls == [True, True]
    assert f"a recorded settle of {rA['slug']} has not finished for more than 600 s" in capsys.readouterr().err
    held, err = settle_progress.overdue(settle_progress.read_state(spool), now=clock["t"])   # vigil doctor reads this
    assert held == [(rA["slug"], rA["nonce"])] and err is None
    fixed()                                                                # the cause fixed
    clock["t"] = t0 + GRACE + 60
    assert w.drain() == {**_NONE, "settle_unfinished": 1, "settle_stuck": 1} and calls == [True, True]
    clock["t"] = t0 + 2 * GRACE                                            # the next due re-drive retires it
    assert w.drain() == _NONE and calls == [True, True, True]
    assert not _published(rA) and _avail(s) == 900                         # nothing moved twice
    assert not settle_progress.state_path(spool).exists() and not (Path(spool) / RETIRE_NAME).exists()


def test_a_lease_retired_by_its_due_re_drive_never_alarms(record_on, monkeypatch, capsys):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    fixed = _unretirable(monkeypatch, s, rA)
    calls = _redrives(monkeypatch)
    spool, t0 = _spool(), NOW + 60
    clock = {"t": t0}
    w = _drain(s, spool, clock, scope=rA["slug"])
    assert w.drain() == {**_NONE, "settle_unfinished": 1}
    fixed()
    clock["t"] = t0 + GRACE - 1
    assert w.drain() == {**_NONE, "settle_unfinished": 1} and calls == [True]
    clock["t"] = t0 + GRACE
    assert w.drain() == _NONE and calls == [True, True] and not _published(rA)
    assert "has not finished for more than" not in capsys.readouterr().err


@pytest.mark.parametrize("how", ["garbage", "from_the_future", "expired", "money_to_land"])
def test_the_retire_record_never_skips_a_first_re_drive_nor_a_settle_with_money_to_land(record_on, monkeypatch, how):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    t0 = NOW + 60
    if how == "money_to_land":                                             # decision + marker, the refund not landed
        restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
        assert _settle(s, rA, 0, basis="cancel").get("retry") is True
        restore()
    else:
        _unretirable(monkeypatch, s, rA)
    spool = _spool()
    at = {"from_the_future": t0 + 1, "expired": t0 - RETIRE_RETRY_S}.get(how, t0)
    settle_checkpoint.write_retire_attempts(Path(spool) / RETIRE_NAME, {(rA["slug"], rA["nonce"]): at})
    if how == "garbage":
        (Path(spool) / RETIRE_NAME).write_text("{", encoding="utf-8")
    calls = _redrives(monkeypatch)
    out = _drain(s, spool, {"t": t0}, scope=rA["slug"]).drain()
    assert calls == [True], (how, calls)                                   # driven, whatever the record says
    if how == "money_to_land":
        assert out == {**_NONE, "settle_completed": 1} and _avail(s) == 1_000 and not _published(rA)
    else:
        assert out == {**_NONE, "settle_unfinished": 1} and _avail(s) == 900
        assert json.loads((Path(spool) / RETIRE_NAME).read_text(encoding="utf-8"))["leases"] == [
            [rA["slug"], rA["nonce"], t0]]
