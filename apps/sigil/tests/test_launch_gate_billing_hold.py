"""W5 — the billing HOLD at the launch gate: an org that owes credits after a reversal cannot start or extend a run.

The hold is derived from the owner-signed reversal ledger (``governor.billing_reversal``, owed > 0), read under the
cross-process settle lock the reversal writes under. It refuses ``reserve_launch`` (metered AND flat) and
``extend_reservation`` (the gateway's terminal "credits exhausted" stop); the next top-up repays the arrears and lifts
it. With ``VIGIL_BILLING_REVERSALS`` off the gate never reads the ledger (byte-identical — the W2 tests prove it).

Mutation-verify targets:
  * reserve skips the hold check            -> test_the_hold_refuses_a_new_metered_reserve
  * the flat reserve skips the hold         -> test_the_hold_refuses_a_flat_reserve
  * extend skips the hold check             -> test_the_hold_refuses_an_allowance_extension
  * the extension hold is not terminal      -> test_the_extension_hold_is_the_terminal_credits_stop_for_w3
  * the hold does not lift on repay         -> test_a_top_up_repays_the_arrears_and_the_hold_lifts
"""
from __future__ import annotations

import itertools
import os
import tempfile

import pytest

from sigil import config
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.billing_reversal import BILLING_HOLD, BillingReversalLedger, REASON_DISPUTE
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import model_metering as mm

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", "VIGIL_BILLING_REVERSALS", mm.MARGIN_ENV, mm.CANCEL_ENV, *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, "0.5")
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def _seat(store, *, credits=1_000):
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    w = WalletRegistry(store)
    if credits:
        w.grant(ORG, credits, "topup", entry_id="cs_seat", issued_at=1.0)
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    return owner, w, LaunchGate(store)


def _hold(store, w, *, owed=900, cap=1000):
    """Put ORG on a billing hold owing ``owed`` credits: a ``cap``-credit top-up (cs_disputed) is mostly spent (the
    wallet drained to its unspent part ``cap - owed``), then disputed in full — so only the unspent part leaves the
    wallet and ``owed`` is booked as arrears. Robust to a reserve already holding part of the balance."""
    w.grant(ORG, cap, "topup", entry_id="cs_disputed", issued_at=1.0)
    keep = cap - owed
    extra = w.available(ORG) - keep
    if extra > 0:
        w.debit(ORG, extra, engagement_id="", entry_id=f"drain_{next(_iss)}", issued_at=1.5)
    L = BillingReversalLedger(store, wallet=w)
    L.reconcile(ORG, "cs_disputed", cap=cap, reason=REASON_DISPUTE, now=2.0, disputed=cap)
    assert L.owed(ORG) == owed and w.available(ORG) == 0


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def test_the_hold_refuses_a_new_metered_reserve(monkeypatch):
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    s = _store()
    owner, w, g = _seat(s)
    _hold(s, w)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW, depth="quick")
    assert not r["ok"] and "hold" in r["error"].lower() and "owed" in r["error"].lower()


def test_the_hold_refuses_a_flat_reserve():
    s = _store()                                   # no VIGIL_METERED_BILLING: a flat launch
    owner, w, g = _seat(s)
    _hold(s, w)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=10, now=NOW)
    assert not r["ok"] and "hold" in r["error"].lower()


def test_a_reserve_is_admitted_once_the_hold_is_lifted():
    s = _store()
    owner, w, g = _seat(s)
    _hold(s, w)
    w.grant(ORG, 1_000, "topup", entry_id="cs_topup2", issued_at=3.0)     # a new top-up
    BillingReversalLedger(s, wallet=w).repay(ORG, "cs_topup2", now=3.1)   # repays the 900 arrears (100 left)
    assert not BillingReversalLedger(s, wallet=w).on_hold(ORG) and w.available(ORG) == 100
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=10, now=NOW)
    assert r["ok"], r


def test_the_hold_refuses_an_allowance_extension(monkeypatch):
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    s = _store()
    owner, w, g = _seat(s)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW, depth="quick")
    assert r["ok"] and g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    _hold(s, w)                                                           # a reversal lands mid-run
    out = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=100, now=NOW)
    assert not out["ok"] and out.get("billing_hold") is True


def test_the_extension_hold_is_the_terminal_credits_stop_for_w3(monkeypatch):
    # the gateway treats `insufficient` as the non-retryable CREDITS_EXHAUSTED stop; W3 reads `reason == "billing_hold"`
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    s = _store()
    owner, w, g = _seat(s)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW, depth="quick")
    assert r["ok"] and g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    _hold(s, w)
    out = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=100, now=NOW)
    assert out["insufficient"] is True and out["reason"] == BILLING_HOLD and not out.get("retry")


def test_a_top_up_repays_the_arrears_and_the_hold_lifts(monkeypatch):
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    s = _store()
    owner, w, g = _seat(s)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW, depth="quick")
    assert r["ok"] and g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    _hold(s, w)
    assert not g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=50, now=NOW)["ok"]
    w.grant(ORG, 1_000, "topup", entry_id="cs_topup_new", issued_at=NOW)      # a top-up arrives
    BillingReversalLedger(s, wallet=w).repay(ORG, "cs_topup_new", now=NOW)    # repays the 900 arrears
    assert not BillingReversalLedger(s, wallet=w).on_hold(ORG)
    out = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=50, now=NOW)
    assert out["ok"], out


def test_with_reversals_off_the_gate_never_reads_a_hold(monkeypatch):
    monkeypatch.delenv("VIGIL_BILLING_REVERSALS", raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    s = _store()
    owner, w, g = _seat(s)
    _hold(s, w)                                    # the ledger says owed 900, but the flag is off -> ignored
    w.grant(ORG, 500, "topup", entry_id="cs_more", issued_at=NOW)   # balance to actually start a run
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW, depth="quick")
    assert r["ok"], r                              # admitted despite owed credits in the ledger (flag off)
