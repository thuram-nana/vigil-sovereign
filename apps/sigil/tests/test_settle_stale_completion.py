"""E3bc — a completion whose own launch is already settled is archived as a no-op, never quarantined.

A completion that waited for a retry (its settle stopped after its decision) can see its launch settled by the drain's
finish pass in the same pass, and a relaunch then replace that launch on the seam. On the next pass the completion no
longer names the published lease. When its own ``(slug, nonce)`` is already SETTLED — its seam settlement marker lists
it, or the spine carries its owner-signed settlement evidence — nothing is left for it to settle: it is archived to
``processed/`` as a safe no-op (a stderr line names it), never quarantined as a money ALARM. Every other nonce mismatch
is still quarantined.

Mutation-verify targets (each neuter turns a NAMED test red):
  * a stale completion of a settled launch quarantined        -> test_a_completion_of_a_launch_the_finish_pass_...
  * every nonce mismatch archived                             -> test_a_completion_for_another_unsettled_launch_...
  * the settled check by marker dropped                       -> test_a_stale_completion_settled_only_by_its_marker_...
  * the settled check on the spine dropped                    -> test_a_stale_completion_settled_only_on_the_spine_...

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_settle_stale_completion.py
"""
from __future__ import annotations

import os

import pytest

from sigil.governor.wallet import WalletRegistry
from sigil.ui.launch_gate import LaunchGate
from test_settle_fold_main import _Gov
from test_settle_one_pass_evidence import (  # noqa: F401  (_iso: the autouse isolation fixture)
    _NONE, HOST, NOW, ORG, _avail, _base, _decisions, _iso, _outcomes, _published, _reserve, _seat, _store,
)
from vigil_integration.live.credit_lease_broker import is_lease_settled, settlement_path


@pytest.fixture
def record_on(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")


@pytest.mark.parametrize("one_launch", ["", "1"])
def test_a_completion_of_a_launch_the_finish_pass_settled_is_archived_after_a_relaunch(record_on, monkeypatch,
                                                                                      one_launch):
    monkeypatch.setenv("VIGIL_ONE_LAUNCH_PER_HOST", one_launch)
    s = _store()
    _seat(s, credits=200)
    r = _reserve(s, publish=True)
    gov = _Gov(s, r)
    gov.emit("failed")
    real, calls = WalletRegistry.grant, []

    def flaky(self, *a, **k):                                             # one transient failure after the decision
        calls.append(1)
        if len(calls) == 1:
            raise OSError("spine append lock busy")
        return real(self, *a, **k)

    monkeypatch.setattr(WalletRegistry, "grant", flaky)
    out = gov.watcher().drain()
    assert out == {**_NONE, "deferred": 1, "settle_completed": 1}, out    # deferred, then finished by the pass
    assert _outcomes(s) == ["failed"] and not _published(r)
    g = LaunchGate(s)
    rB = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=30, now=NOW + 90, duration_hours=1)
    assert rB["ok"] and g.publish_lease(signed_lease=rB["lease"], expect_org_id=ORG)["ok"]
    out = gov.watcher().drain()
    assert out == {**_NONE, "noop": 1}, out                               # archived: no quarantine, no money alarm
    assert list(gov.watcher().rejected.iterdir()) == [] and _avail(s) == 200 - 30 and _outcomes(s) == ["failed"]


def test_a_completion_for_another_unsettled_launch_is_still_quarantined(record_on):
    s = _store()
    _seat(s, credits=200)
    rA = _reserve(s, publish=True, nonce="A" * 16)
    gov = _Gov(s, rA)
    gov.emit("completed")
    g = LaunchGate(s)
    rB = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=30, now=NOW + 90, duration_hours=1,
                          nonce="B" * 16)
    assert rB["ok"] and g.publish_lease(signed_lease=rB["lease"], expect_org_id=ORG)["ok"]   # A is flat, unsettled
    out = gov.watcher().drain()
    assert out == {**_NONE, "rejected": 1}, out                           # A is NOT settled: still a money alarm
    (reason,) = [p for p in gov.watcher().rejected.iterdir() if p.name.endswith(".reason")]
    assert "stale/mismatched" in reason.read_text(encoding="utf-8")


def test_a_stale_completion_settled_only_on_the_spine_is_archived(record_on):
    s = _store()
    _seat(s, credits=200)
    rA = _reserve(s, publish=True, nonce="A" * 16)
    gov = _Gov(s, rA)
    gov.emit("failed")
    assert gov.watcher().drain() == {**_NONE, "settled": 1}
    os.unlink(settlement_path(_base(), rA["slug"]))                       # the seam marker lost (a restore)
    g = LaunchGate(s)
    rB = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=30, now=NOW + 90, duration_hours=1,
                          nonce="B" * 16)
    assert rB["ok"] and g.publish_lease(signed_lease=rB["lease"], expect_org_id=ORG)["ok"]
    gov.emit("canceled")                                                  # a second completion for A
    assert gov.watcher().drain() == {**_NONE, "noop": 1}
    assert _avail(s) == 200 - 30


def test_a_stale_completion_settled_only_by_its_marker_is_archived(monkeypatch):
    monkeypatch.delenv("VIGIL_SETTLE_SPINE_RECORD", raising=False)       # flag off: a 0-refund settle leaves no record
    s = _store()
    _seat(s, credits=200)
    rA = _reserve(s, publish=True, nonce="A" * 16)
    gov = _Gov(s, rA)
    gov.emit("completed")
    assert gov.watcher().drain() == {**_NONE, "settled": 1}
    assert is_lease_settled(_base(), rA["slug"], rA["nonce"]) and _decisions(s) == []
    g = LaunchGate(s)
    rB = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=30, now=NOW + 90, duration_hours=1,
                          nonce="B" * 16)
    assert rB["ok"] and g.publish_lease(signed_lease=rB["lease"], expect_org_id=ORG)["ok"]
    gov.emit("failed")
    assert gov.watcher().drain() == {**_NONE, "noop": 1}
    assert _avail(s) == 200 - 30 - 30
