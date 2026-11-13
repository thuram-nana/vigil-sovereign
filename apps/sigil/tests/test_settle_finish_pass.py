"""E3bc — the settle drain finishes every RECORDED settle of a lease still on the seam, with no operator.

With ``VIGIL_SETTLE_SPINE_RECORD`` on, each settle-drain pass (``ops_sweeps.finish_interrupted_settles``) finishes,
through ``settle_launch(finish_only=True)``, every settle of a lease in its scope that was interrupted after its
decision was recorded — whatever decided it: an expired paused launch (E8), a cancel, a completion, any other settle —
moving ONLY the recorded decision, exactly once, and retires the lease; a relaunch on that host then publishes, and
``vigil doctor``'s predicate (``credit_lease_broker.unfinished_settlements``) no longer lists it. A completion's
settle finished this way writes that completion's notification (NTF-3) once. With the flag off the pass does not run
and the drain's output is unchanged. The pass reads the spine once for all the leases it lists.

Mutation-verify targets (each neuter turns a NAMED test red):
  * the drain's finish pass removed / gated on the E8 flag  -> test_record_on_an_expired_pause_settle_interrupted_...,
                                                              test_record_on_any_interrupted_recorded_settle_...
  * finish_only=False in the finish pass                    -> test_the_finish_pass_never_makes_a_fresh_settle
  * the finish pass skips a marker-present lease            -> test_the_finish_pass_retires_a_settled_lease_...
  * the finish pass ignores its scope                       -> test_a_scoped_drain_finishes_only_its_own_slug
  * NTF-3 not written on a completion-basis finish          -> test_record_on_any_interrupted_recorded_settle_...
  * the finish pass runs with the flag off                  -> test_record_off_the_drain_has_no_finish_pass
  * the finish pass reads only the seam (no spine pass)     -> test_record_on_a_settle_interrupted_before_its_marker_...
  * the doctor predicate ignores the marker / the grace     -> test_record_on_an_expired_pause_settle_interrupted_...,
                                                              test_the_doctor_predicate_waits_out_its_grace
  * the finish pass rescans the spine per listed lease      -> test_the_drain_pass_visits_each_spine_record_...

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_settle_finish_pass.py
"""
from __future__ import annotations

import tempfile
import time

import pytest

from sigil import ops_sweeps
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.postpaid import PostpaidArrearsLedger
from sigil.governor.wallet import WalletRegistry
from sigil.ui.launch_gate import LaunchGate
from test_settle_one_pass_evidence import (  # noqa: F401  (_iso: the autouse isolation fixture)
    _NONE, HOST, NOW, ORG, B, _avail, _base, _counting, _decisions, _iso, _kill, _outcomes, _plan,
    _published, _relaunch, _reserve, _seat, _settle, _store, _watcher,
)
from vigil_integration.live.credit_lease_broker import is_lease_settled, settlement_path, unfinished_settlements

GRACE = 86400.0                                        # the default VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS


@pytest.fixture
def record_on(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")


# =====================================================================================================================
# the drain finishes every recorded settle of a lease on the seam
# =====================================================================================================================
def test_record_on_an_expired_pause_settle_interrupted_after_its_marker_is_finished_by_the_next_drain_pass(
        record_on, monkeypatch, capsys):
    from test_paused_expiry_settle import _Launch
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_PAUSED_EXPIRY_SETTLE", "1")
    L = _Launch(_store())
    L.pause()                                           # paused until its window closed: nothing ran
    late = L.not_after + GRACE + 60
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert L.drain(late)["expired_unsettled"] == 1      # the E8 settle: decision + marker, then the money failed
    restore()
    assert L.avail() == 70 and L.settled() and L.published()
    assert L.gate.interrupted_settlement(L.lease)["pending_wallet"] == 30
    assert unfinished_settlements(_base(), now=late, grace=0) == [(L.slug, L.nonce)]   # vigil doctor lists it
    g = LaunchGate(L.store)
    rB = g.reserve_launch(requester="u", org_id=L.org, host=HOST, units=10, now=time.time(), duration_hours=1)
    assert rB["ok"], rB
    held = g.publish_lease(signed_lease=rB["lease"], expect_org_id=L.org)
    assert held["ok"] is False and held.get("retry") is True, held           # never replaces an unfinished settle
    out = L.drain(late + 3600)                          # the next pass finishes it, from its record
    assert out == {**_NONE, "settle_completed": 1, "expired_settled": 0, "expired_unsettled": 0}, out
    assert L.avail() == 70 - 10 + 30 and not L.published() and len(_decisions(L.store)) == 1
    assert L.gate.interrupted_settlement(L.lease) is None
    assert unfinished_settlements(_base(), now=late + 3600, grace=0) == []    # vigil doctor clears
    assert g.publish_lease(signed_lease=rB["lease"], expect_org_id=L.org)["ok"]   # the relaunch publishes
    assert unfinished_settlements(_base(), now=late + 3600, grace=0) == []    # a live launch is never listed
    for k in range(2):                                  # exactly once: later passes move nothing
        assert L.drain(late + 7200 + k) == {**_NONE, "expired_settled": 0, "expired_unsettled": 0}
    assert L.avail() == 70 - 10 + 30 and len(_decisions(L.store)) == 1
    assert "not finished yet" not in capsys.readouterr().err


@pytest.mark.parametrize("bucket", ["wallet", "plan", "postpaid"])
@pytest.mark.parametrize("basis", ["cancel", "completion:failed", "settle"])
def test_record_on_any_interrupted_recorded_settle_of_a_seam_lease_is_finished_by_the_drain(record_on, basis, bucket,
                                                                                           monkeypatch):
    if bucket == "postpaid":
        _seat(s := _store(), credits=0, postpaid=(5000, 30))
        restore = None
        killed = (PostpaidArrearsLedger, "settle")
    elif bucket == "plan":
        _seat(s := _store(), credits=0, plan=1_000)
        killed = (PlanCreditLedger, "grant")
    else:
        _seat(s := _store(), credits=1_000)
        killed = (WalletRegistry, "grant")

    def held() -> int:                                  # the credits this tenant has drawn and not got back
        if bucket == "postpaid":
            return PostpaidArrearsLedger(s).accrued(ORG)
        return 1_000 - (_plan(s) if bucket == "plan" else _avail(s))

    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    restore = _kill(monkeypatch, *killed, exc=OSError("disk full"))
    out = _settle(s, rA, 0, basis=basis)
    assert out["ok"] is False and out.get("retry") is True, out             # interrupted after decision + marker
    restore()
    assert held() == 300 and is_lease_settled(_base(), rA["slug"], rA["nonce"]) and _published(rA)
    rB, pub = _relaunch(s, 100, "B" * 16)
    assert pub["ok"] is False and pub.get("retry") is True, pub
    out = _watcher(s, rA["slug"]).drain()               # no completion waiting: only the finish pass acts
    assert out == {**_NONE, "settle_completed": 1}, out
    assert held() == 100 and len(_decisions(s)) == 1 and not _published(rA)   # A's 300 back once; B's 100 held
    assert _outcomes(s) == (["failed"] if basis == "completion:failed" else [])   # NTF-3 for a completion's settle
    assert LaunchGate(s).publish_lease(signed_lease=rB["lease"], expect_org_id=ORG)["ok"]
    assert _watcher(s, rA["slug"]).drain() == _NONE and held() == 100 and len(_outcomes(s)) <= 1


def test_record_on_a_settle_interrupted_before_its_marker_is_finished_by_the_drain(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    restore = _kill(monkeypatch, B, "record_lease_settlement", exc=OSError("seam unwritable"))
    out = _settle(s, rA, 0, basis="sweep:refund")
    assert out["ok"] is False and out.get("retry") is True, out             # the decision is recorded, no marker
    restore()
    assert len(_decisions(s)) == 1 and not is_lease_settled(_base(), rA["slug"], rA["nonce"]) and _avail(s) == 700
    assert unfinished_settlements(_base(), now=time.time(), grace=0) == []  # the seam alone cannot show it ...
    rB, pub = _relaunch(s, 100, "B" * 16)
    assert pub["ok"] is False and pub.get("retry") is True, pub             # ... but the relaunch waits for it
    assert _watcher(s, rA["slug"]).drain() == {**_NONE, "settle_completed": 1}   # the spine pass finds and ends it
    assert _avail(s) == 1_000 - 100 and is_lease_settled(_base(), rA["slug"], rA["nonce"]) and not _published(rA)
    assert LaunchGate(s).publish_lease(signed_lease=rB["lease"], expect_org_id=ORG)["ok"]
    assert len(_decisions(s)) == 1 and _avail(s) == 1_000 - 100


def test_a_finish_that_cannot_land_yet_is_reported_and_retried_next_pass(record_on, monkeypatch, capsys):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert _settle(s, rA, 0, basis="cancel").get("retry") is True
    out = _watcher(s, rA["slug"]).drain()               # the wallet still cannot be written
    assert out == {**_NONE, "settle_unfinished": 1}, out
    assert "a recorded settle of " + rA["slug"] + " is not finished yet: deferred" in capsys.readouterr().err
    restore()
    assert _avail(s) == 700
    assert _watcher(s, rA["slug"]).drain() == {**_NONE, "settle_completed": 1} and _avail(s) == 1_000


def test_the_finish_pass_retires_a_settled_lease_whose_money_landed(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    restore = _kill(monkeypatch, B, "tombstone_credit_lease")   # dies after the money, before the tombstone
    with pytest.raises(SystemExit):
        _settle(s, rA, 0, basis="completion:failed")
    restore()
    assert _avail(s) == 1_000 and _published(rA)
    assert unfinished_settlements(_base(), now=time.time(), grace=0) == [(rA["slug"], rA["nonce"])]
    tip = s.next_seq - 1
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90) == [
        {"slug": rA["slug"], "org_id": ORG, "nonce": rA["nonce"], "status": "already_settled"}]
    assert not _published(rA) and _avail(s) == 1_000 and list(s.iter_records(since_seq=tip)) == []
    assert unfinished_settlements(_base(), now=time.time(), grace=0) == []
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 99) == []


def test_the_finish_pass_never_makes_a_fresh_settle(record_on):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90) == []
    real = LaunchGate.interrupted_settlements
    try:                                                # even a pass that believed it pending only FINISHES
        LaunchGate.interrupted_settlements = lambda self, leases: {(ORG, rA["slug"], rA["nonce"]): {"pending_wallet": 1}}
        assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90) == []
    finally:
        LaunchGate.interrupted_settlements = real
    assert _avail(s) == 700 and _decisions(s) == [] and _published(rA)
    assert not is_lease_settled(_base(), rA["slug"], rA["nonce"])


def test_a_scoped_drain_finishes_only_its_own_slug(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000, hosts=(HOST, "other.cm"))
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    rX = _reserve(s, units=200, publish=True, hours=8, nonce="X" * 16, host="other.cm")
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert _settle(s, rA, 0, basis="cancel").get("retry") and _settle(s, rX, 0, basis="cancel").get("retry")
    restore()
    assert _watcher(s, rA["slug"]).drain() == {**_NONE, "settle_completed": 1} and _avail(s) == 500 + 300
    assert _published(rX) and LaunchGate(s).interrupted_settlement(rX["lease"])["pending_wallet"] == 200
    assert _watcher(s, rX["slug"]).drain() == {**_NONE, "settle_completed": 1} and _avail(s) == 1_000


def test_record_off_the_drain_has_no_finish_pass(monkeypatch):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        _settle(s, rA, 0, basis="cancel")               # no decision record with the flag off: nothing to finish from
    restore()
    assert ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 90) == []   # the pass itself is gated
    assert _published(rA)
    calls = []
    real = ops_sweeps.finish_interrupted_settles
    monkeypatch.setattr(ops_sweeps, "finish_interrupted_settles", lambda *a, **k: calls.append(1) or [])
    assert _watcher(s, rA["slug"]).drain() == _NONE and calls == []          # byte-identical, never called
    assert _published(rA) and _avail(s) == 700
    monkeypatch.setattr(ops_sweeps, "finish_interrupted_settles", real)
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")                     # (the flag on: the marker-present lease
    assert _watcher(s, rA["slug"]).drain() == _NONE and not _published(rA)   # is retired; nothing recorded to move)
    assert _avail(s) == 700


def test_the_doctor_predicate_waits_out_its_grace(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert _settle(s, rA, 0, basis="cancel").get("retry") is True
    t = settlement_path(_base(), rA["slug"]).stat().st_mtime
    assert unfinished_settlements(_base(), now=t + 599, grace=600) == []     # a settle may still be under way
    assert unfinished_settlements(_base(), now=t + 600, grace=600) == [(rA["slug"], rA["nonce"])]


@pytest.mark.parametrize("k", [3, 12])
def test_the_drain_pass_visits_each_spine_record_a_bounded_number_of_times(record_on, k, monkeypatch):
    s = _store()
    hosts = [f"h{i}.example" for i in range(k)]
    _seat(s, credits=100_000, hosts=hosts)
    for i, h in enumerate(hosts):                       # k launches on the seam, none with a settle to finish
        _reserve(s, units=10, publish=True, host=h, nonce=f"m{i:06d}x")
    seen, n, restore = _counting(monkeypatch, s)
    rows = ops_sweeps.finish_interrupted_settles(LaunchGate(s), now=NOW + 60)
    restore()
    assert rows == [] and seen["visits"] <= 3 * n, (k, seen, n)               # one read of the spine for all
