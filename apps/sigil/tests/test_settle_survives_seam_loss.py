"""E3b — settle idempotency must survive the loss of the seam settlement marker.

The seam settlement marker (``<VIGIL_BASE_DIR>/credit-lease-settlements/``) lives in the cross-plane seam, which
is not on the spine and is not captured by the sovereign backup. Before this fix it was the ONLY record that a
COMPLETED run (refund 0, so no refund grant) had been settled: lose it — a restore without the seam, or a seam
restored out of step with the spine — and the customer's ``launch_cancel`` (they keep the signed lease
``reserve_launch`` returned) fully refunded the charged, completed run. Every fresh settle now also appends an
owner-signed ``governor.launch_settled`` record to the spine, and a lease is settled if EITHER exists.

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_settle_survives_seam_loss.py
"""
from __future__ import annotations

import itertools
import os
import shutil
import tempfile

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.launch_settlement import (
    LAUNCH_SETTLED_SIGNAL, first_launch_settlement, record_launch_settled,
)
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import PostpaidArrearsLedger, PostpaidRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import generate_keypair
from vigil_integration.live.credit_lease_broker import (
    is_lease_settled, read_credit_lease, settlements_root,
)

_iss = itertools.count(1)
NOW = 2000.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _base():
    return os.environ["VIGIL_BASE_DIR"]


def _seat(store, org="org_a", host="apme.cm", *, credits=100, postpaid=None):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=NOW)["ok"]
    if postpaid is not None:
        PostpaidRegistry(store).set_account(org, postpaid[0], postpaid[1], issued_at=float(next(_iss)))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _avail(store, org="org_a"):
    return WalletRegistry(store).available(org)


def _lose_seam_markers():
    shutil.rmtree(settlements_root(_base()), ignore_errors=True)


def _reserve(store, units=30, nonce=None):
    r = LaunchGate(store).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=units, now=NOW,
                                         nonce=nonce)
    assert r["ok"], r
    return r


def test_completed_run_is_not_refunded_by_launch_cancel_after_the_seam_marker_is_lost():
    from sigil.ui.provision import build_provisioner
    s = _store()
    _seat(s)
    r = _reserve(s)
    assert _avail(s) == 70
    done = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=30, now=NOW)   # COMPLETED
    assert done["action"] == "launch_settled" and done["refunded"] == 0 and _avail(s) == 70
    _lose_seam_markers()
    assert not is_lease_settled(_base(), r["slug"], r["nonce"])
    out = build_provisioner(s).launch_cancel("u", "org_a", r["lease"], now=NOW)
    assert out["refunded"] == 0
    assert _avail(s) == 70                                   # still charged: no free run
    assert is_lease_settled(_base(), r["slug"], r["nonce"])  # the seam revocation was re-asserted
    # ...and the already-settled re-settle appended NO second settlement record (a customer re-issuing cancel
    # cannot grow the spine one signed record per call)
    assert len([x for x in s.iter_records() if (x.payload or {}).get("signal") == LAUNCH_SETTLED_SIGNAL]) == 1


def test_postpaid_completed_draw_is_not_reversed_after_the_seam_marker_is_lost():
    s = _store()
    _seat(s, credits=0, postpaid=(500, 30))
    r = _reserve(s, units=100, nonce="pp1")
    arrears = PostpaidArrearsLedger(s)
    assert arrears.accrued("org_a") == 100
    assert LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=100, now=NOW)["ok"]
    assert arrears.accrued("org_a") == 100
    _lose_seam_markers()
    st = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW + 1)   # cancel
    assert st["action"] == "launch_already_settled", st
    assert PostpaidArrearsLedger(s).accrued("org_a") == 100   # the consumed draw was NOT reversed


def test_every_fresh_settle_records_exactly_one_owner_signed_spine_settlement():
    s = _store()
    _seat(s)
    r = _reserve(s)
    gate = LaunchGate(s)
    assert gate.settle_launch(signed_lease=r["lease"], consumed_units=30, now=NOW)["action"] == "launch_settled"
    assert gate.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW)["action"] == \
        "launch_already_settled"
    recs = [x for x in s.iter_records() if (x.payload or {}).get("signal") == LAUNCH_SETTLED_SIGNAL]
    assert len(recs) == 1 and recs[0].payload["nonce"] == r["nonce"] and recs[0].payload["consumed"] == 30
    assert first_launch_settlement(s, gate.owner_key.public_key_b64, org_id="org_a", slug=r["slug"],
                                   nonce=r["nonce"]) == recs[0].seq


def test_a_settlement_record_not_signed_by_the_owner_does_not_block_a_legitimate_cancel():
    s = _store()
    _seat(s)
    r = _reserve(s)
    rogue = generate_keypair()
    record_launch_settled(s, rogue, org_id="org_a", slug=r["slug"], nonce=r["nonce"], consumed=30, issued_at=NOW)
    st = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW)        # pre-start cancel
    assert st["action"] == "launch_settled" and st["refunded"] == 30
    assert _avail(s) == 100


def test_a_settle_that_loses_the_spine_race_moves_no_money(monkeypatch):
    # Another process's settle records its decision between this call's check and its own record: the FIRST
    # spine record decides, so this (later) full-refund settle must move nothing.
    import sigil.governor.launch_settlement as ls
    s = _store()
    _seat(s)
    r = _reserve(s)
    gate = LaunchGate(s)
    real = ls.record_launch_settled

    def _competitor_first(store, owner_key, **kw):
        real(store, owner_key, **{**kw, "consumed": 30})      # the completed settle in another process
        return real(store, owner_key, **kw)

    monkeypatch.setattr(ls, "record_launch_settled", _competitor_first)
    st = gate.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW)
    assert st["action"] == "launch_already_settled" and st["refunded"] == 0, st
    assert _avail(s) == 70


def test_a_seam_revocation_failure_records_nothing_so_a_retry_still_settles(monkeypatch):
    import vigil_integration.live.credit_lease_broker as clb
    s = _store()
    _seat(s)
    r = _reserve(s)
    real = clb.record_lease_settlement
    calls = {"n": 0}

    def _flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("seam not writable")
        return real(*a, **kw)

    monkeypatch.setattr(clb, "record_lease_settlement", _flaky)
    bad = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW)
    assert bad["ok"] is False and _avail(s) == 70
    assert not [x for x in s.iter_records() if (x.payload or {}).get("signal") == LAUNCH_SETTLED_SIGNAL]
    ok = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW)
    assert ok["action"] == "launch_settled" and _avail(s) == 100


def test_a_settled_lease_cannot_be_republished_after_the_seam_marker_is_lost():
    s = _store()
    _seat(s)
    r = _reserve(s)
    gate = LaunchGate(s)
    assert gate.publish_lease(signed_lease=r["lease"], expect_org_id="org_a")["ok"]
    assert gate.settle_launch(signed_lease=r["lease"], consumed_units=30, now=NOW)["ok"]
    assert read_credit_lease(_base(), r["slug"]) is None
    _lose_seam_markers()
    again = gate.publish_lease(signed_lease=r["lease"], expect_org_id="org_a")
    assert again["ok"] is False and "settled" in again["error"]
    assert read_credit_lease(_base(), r["slug"]) is None     # not resurrected as a runnable bearer capability


def test_the_spine_settlement_lookup_is_bound_to_org_slug_and_nonce():
    s = _store()
    kp = ensure_owner_keypair()
    record_launch_settled(s, kp, org_id="org_b", slug="cust_x", nonce="n1", consumed=5, issued_at=NOW)
    seq = record_launch_settled(s, kp, org_id="org_a", slug="cust_x", nonce="n1", consumed=5, issued_at=NOW)
    pub = kp.public_key_b64
    assert first_launch_settlement(s, pub, org_id="org_a", slug="cust_x", nonce="n1") == seq
    assert first_launch_settlement(s, pub, org_id="org_a", slug="cust_x", nonce="n2") is None
    assert first_launch_settlement(s, pub, org_id="org_a", slug="cust_y", nonce="n1") is None
