"""Audit E1 — the customer-checkout guards hold over the REAL edge -> cockpit hop, not just on one instance.

(a) The checkout-creation rate limit was instance-local, and the cockpit builds a fresh Provisioner per request, so
    over HTTP it limited nothing (12 real-hop POSTs were all created). It is now the filesystem-backed
    LoginRateLimiter (its guard-and-count ``admit``), durable across requests AND processes, and fail-closed when
    its state cannot be read or written.
(b) The second-plan guard read only DRAINED subscriptions, so several plan checkouts could be created (and paid)
    before the first plan's webhook drained. An owner-signed, expiring, cross-process-exclusive PENDING
    plan-checkout record now refuses a second plan checkout for the org until the plan drains (then the drained
    subscription refuses it) or the record expires — and it cannot expire while its link can still bill: a plan
    checkout asks the processor for a bounded payment session that the record's TTL outlives, plus a margin. Nor
    does it lapse on time alone while the link may have been PAID: an expired record stays while the billing spool
    holds an undrained webhook for its tx_ref (a quarantine waits for an operator — no time bound), and a spool
    that cannot prove that keeps refusing. Deleting the record does not reopen the window (the created plan
    checkout is on the spine audit), and the checkout audit names the tx_ref. Top-ups are unaffected (their
    processor payload is unchanged).
(c) (the edge's blank-hop-key refusal lives in test_custui.py; the limiter primitive in test_login_ratelimit.py.)
"""
from __future__ import annotations

import concurrent.futures
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _opener, _post, _stack
from test_customer_checkout import _iso, _on, _provisioner, _real_provider  # noqa: F401  (_iso is autouse)

_TOPUP = "vigil_topup_1k"
_CHECKOUT = "/api/customer/billing/checkout"


def _signup(ep, email="guard@acme.com"):
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    c, _r = _post(op, ep, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "G"})
    assert c == 200
    return op


def _hop_stack(tmp_path, monkeypatch, posted):
    from sigil.ui import provision
    _on(monkeypatch)
    monkeypatch.setattr(provision.Provisioner, "_checkout_provider", lambda self: _real_provider(posted))
    return _stack(tmp_path, monkeypatch)


# --- (a) the durable checkout rate limit -------------------------------------------------------------------------

def test_the_checkout_rate_limit_holds_over_the_real_hop(tmp_path, monkeypatch):
    """12 sequential real-hop POSTs (each one a FRESH cockpit Provisioner): exactly _CHECKOUT_MAX are created."""
    from sigil.ui.provision import Provisioner
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep)
        res = [_post(op, ep, _CHECKOUT, {"price_id": _TOPUP}) for _ in range(Provisioner._CHECKOUT_MAX + 2)]
        codes = [c for c, _r in res]
        assert codes[:Provisioner._CHECKOUT_MAX] == [200] * Provisioner._CHECKOUT_MAX, res
        assert codes[Provisioner._CHECKOUT_MAX:] == [403, 403], res
        assert "too many checkout attempts" in json.dumps(res[-1][1])
        assert len(posted) == Provisioner._CHECKOUT_MAX            # the refused attempts never reached the processor
    finally:
        sov.shutdown(); edge.shutdown()


def test_concurrent_real_hop_checkouts_cannot_overrun_the_limit(tmp_path, monkeypatch):
    from sigil.ui.provision import Provisioner
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep, "race@acme.com")
        n = Provisioner._CHECKOUT_MAX + 6
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            codes = list(ex.map(lambda _i: _post(op, ep, _CHECKOUT, {"price_id": _TOPUP})[0], range(n)))
        assert codes.count(200) == Provisioner._CHECKOUT_MAX and codes.count(403) == 6, codes
        assert len(posted) == Provisioner._CHECKOUT_MAX
    finally:
        sov.shutdown(); edge.shutdown()


def test_overlapping_checkout_attempts_are_guarded_and_counted_atomically(monkeypatch):
    """The real-hop tests above reach the limiter one request at a time (each hop pays a slow body binding). Here the
    attempts really overlap — a start barrier, and the limiter's read-to-write step widened (test instrumentation) —
    as concurrent requests in several cockpit threads or processes would: exactly _CHECKOUT_MAX are admitted. A
    check-then-record limiter (``check`` + ``record_failure``) would let every one of them through."""
    import threading
    import time

    from sigil.ui.provision import Provisioner
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    lim = p.checkout_limiter
    real = lim._next_record

    def slow(rec, t):
        time.sleep(0.02)
        return real(rec, t)
    lim._next_record = slow
    n = Provisioner._CHECKOUT_MAX + 6
    start = threading.Barrier(n)

    def attempt(_i):
        start.wait(timeout=30)
        return p._checkout_rate_ok(admin, org, 5000.0)
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        admitted = list(ex.map(attempt, range(n)))
    assert admitted.count(True) == Provisioner._CHECKOUT_MAX, admitted


@pytest.mark.parametrize("fault", ["unwritable", "corrupt"])
def test_limiter_state_that_cannot_be_read_or_written_refuses_over_the_hop(tmp_path, monkeypatch, fault):
    import hashlib

    from sigil import config
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep, f"{fault}@acme.com")
        d = Path(config.CHECKOUT_RATELIMIT_DIR)
        if fault == "unwritable":
            d.write_text("not a directory", encoding="utf-8")       # the marker dir cannot be created / written
        else:
            assert _post(op, ep, _CHECKOUT, {"price_id": _TOPUP})[0] == 200
            for m in d.iterdir():
                if len(m.name) == len(hashlib.sha256(b"").hexdigest()):
                    m.write_text("{not json", encoding="utf-8")        # a corrupt / hostile marker
        before = len(posted)
        c, r = _post(op, ep, _CHECKOUT, {"price_id": _TOPUP})
        assert c == 403 and "too many checkout attempts" in json.dumps(r), (c, r)
        assert len(posted) == before                                   # nothing reached the processor
    finally:
        sov.shutdown(); edge.shutdown()


def test_an_unwired_checkout_limiter_refuses(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    p.checkout_limiter = None
    p._checkout_provider = lambda: pytest.fail("never reached without a limiter")
    with pytest.raises(ProvisionDenied, match="too many checkout attempts"):
        p.billing_checkout(admin, org, _TOPUP)


def test_the_limit_is_per_requester_as_well_as_per_org(monkeypatch):
    """One billing admin of TWO orgs cannot double their budget by alternating orgs: the requester key trips too."""
    from sigil.ui.provision import Provisioner, ProvisionDenied
    _on(monkeypatch)
    p, admin, _t, org, other, _w = _provisioner()
    p.orgs.grant_membership(other, admin, "org_admin", issued_at=5.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    for _ in range(Provisioner._CHECKOUT_MAX):
        p.billing_checkout(admin, org, _TOPUP, now=5000.0)
    with pytest.raises(ProvisionDenied, match="too many checkout attempts"):
        p.billing_checkout(admin, other, _TOPUP, now=5001.0)          # a fresh org, the same exhausted requester
    assert len(posted) == Provisioner._CHECKOUT_MAX


def test_the_factory_wires_the_durable_checkout_limiter(tmp_path, monkeypatch):
    from sigil import config
    from sigil.spine.store import SpineStore
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner, build_provisioner
    monkeypatch.setattr(config, "CHECKOUT_RATELIMIT_DIR", tmp_path / "chk")
    p = build_provisioner(SpineStore(str(tmp_path / "s.jsonl")))
    lim = p.checkout_limiter
    assert isinstance(lim, LoginRateLimiter) and lim.dir == tmp_path / "chk"
    assert (lim.max_fails, lim.window_s) == (Provisioner._CHECKOUT_MAX, Provisioner._CHECKOUT_WINDOW_S)
    assert lim.base_lock_s >= Provisioner._CHECKOUT_WINDOW_S


def test_the_factory_wires_the_owner_signed_pending_records(tmp_path, monkeypatch):
    from sigil import config
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    from sigil.ui.pending_checkout import PendingPlanCheckouts
    from sigil.ui.provision import build_provisioner
    monkeypatch.setattr(config, "PENDING_PLAN_CHECKOUT_DIR", tmp_path / "pending")
    kp = ensure_owner_keypair()
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SPOOL", str(tmp_path / "proxy-spool"))
    led = build_provisioner(SpineStore(str(tmp_path / "s.jsonl"))).pending_checkouts
    assert isinstance(led, PendingPlanCheckouts) and led.dir == tmp_path / "pending"
    assert led.owner_key.public_key_b64 == led.trusted_pubkey == kp.public_key_b64
    assert led.billing_spools is not None and tmp_path / "proxy-spool" in led.billing_spools   # reads the spool
    from sigil.ui.pending_checkout import stripe_billing_spool_dirs
    # processed/ is read only in the Stripe spool locations (never the Flutterwave spool's drained ledger)
    assert led.stripe_spools == stripe_billing_spool_dirs() and tmp_path / "proxy-spool" not in led.stripe_spools


def test_the_billing_spool_is_looked_for_where_the_proxy_and_the_drain_put_it(tmp_path, monkeypatch):
    """Both processors' spools: the provisioner's checkout serves Flutterwave or Stripe (VIGIL_BILLING_PROVIDER)."""
    from sigil.ui.pending_checkout import billing_spool_dirs, stripe_billing_spool_dirs
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    for k in ("VIGIL_BILLING_WEBHOOK_SPOOL", "VIGIL_BILLING_SPOOL", "VIGIL_STRIPE_WEBHOOK_SPOOL",
              "VIGIL_STRIPE_BILLING_SPOOL"):
        monkeypatch.delenv(k, raising=False)
    home = tmp_path / "home"
    assert billing_spool_dirs() == [home / "billing-spool", home / "stripe-billing-spool"]   # the runbook defaults
    assert stripe_billing_spool_dirs() == [home / "stripe-billing-spool"]
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SPOOL", str(tmp_path / "w"))
    monkeypatch.setenv("VIGIL_BILLING_SPOOL", str(tmp_path / "d"))
    monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SPOOL", str(tmp_path / "sw"))
    monkeypatch.setenv("VIGIL_STRIPE_BILLING_SPOOL", str(tmp_path / "sd"))
    assert billing_spool_dirs() == [tmp_path / "w", tmp_path / "d", home / "billing-spool",
                                    tmp_path / "sw", tmp_path / "sd", home / "stripe-billing-spool"]
    assert stripe_billing_spool_dirs() == [tmp_path / "sw", tmp_path / "sd", home / "stripe-billing-spool"]


# --- (b) the pending plan-checkout record ---------------------------------------------------------------------

_PLAN = "vigil_pro_monthly"


def _plans_on(monkeypatch):
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")


def _audits(p):
    seen: list = []
    real = p.store.append

    def cap(**kw):
        pl = kw.get("payload")
        if isinstance(pl, dict) and pl.get("signal") == "provision.audit":
            seen.append(pl)
        return real(**kw)
    p.store.append = cap
    return seen


def test_a_second_plan_checkout_is_refused_over_the_real_hop_while_the_first_is_undrained(tmp_path, monkeypatch):
    _plans_on(monkeypatch)
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep, "plan@acme.com")
        res = [_post(op, ep, _CHECKOUT, {"price_id": _PLAN}) for _ in range(3)]
        assert [c for c, _r in res] == [200, 403, 403], res
        assert "already in progress" in json.dumps(res[1][1])
        assert [x.get("payment_plan") for x in posted] == [_PLAN]        # ONE processor subscription, not three
        assert _post(op, ep, _CHECKOUT, {"price_id": _TOPUP})[0] == 200     # top-ups are unaffected
    finally:
        sov.shutdown(); edge.shutdown()


def test_concurrent_real_hop_plan_checkouts_create_exactly_one(tmp_path, monkeypatch):
    _plans_on(monkeypatch)
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep, "planrace@acme.com")
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            codes = list(ex.map(lambda _i: _post(op, ep, _CHECKOUT, {"price_id": _PLAN})[0], range(6)))
        assert sorted(codes) == [200, 403, 403, 403, 403, 403], codes
        assert len(posted) == 1
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_pending_record_expires_and_the_drained_plan_takes_over(monkeypatch):
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    ensure_owner_keypair()                                    # the deployment owner identity _org_has_live_plan reads
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S - 1)
    # the first plan's webhook drains: the DRAINED subscription now refuses a second plan, also past the TTL
    SubscriptionRegistry(p.store).subscribe(org, "pro", 2000, period_start=5000.0, period_end=100_000.0,
                                            issued_at=5001.0)
    with pytest.raises(ProvisionDenied, match="already has a plan"):    # (checked first: the accurate reason
        p.billing_checkout(admin, org, _PLAN, now=5060.0)                # while the record is still live too)
    with pytest.raises(ProvisionDenied, match="already has a plan"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert len(posted) == 1


def test_an_abandoned_plan_checkout_unblocks_after_the_ttl(monkeypatch):
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S - 1)
    p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S)     # the abandoned checkout lapsed
    assert len(posted) == 2
    assert DEFAULT_TTL_S >= 3 * 915                           # well above the ~15 min NET-2b parking window


# --- (b2) a PAID plan whose webhook the drain has not minted never lapses on time alone -----------------------

_SECRET = "verif-hash-test"          # a dummy webhook verif-hash, never a real one


def _envelope(body: dict) -> bytes:
    import base64
    return json.dumps({"schema": "vigil.webhook.billing.v1",
                       "body_b64": base64.b64encode(json.dumps(body).encode()).decode()}).encode()


def _spool_webhook(root: Path, tx_ref: str, txid: int, stage: str = "incoming") -> Path:
    """What the proxy spools for a paid charge (a Flutterwave ``charge.completed`` body names its tx_ref)."""
    import hashlib
    env = _envelope({"event": "charge.completed", "data": {"id": txid, "tx_ref": tx_ref, "status": "successful"}})
    d = root / stage
    d.mkdir(parents=True, exist_ok=True)
    f = d / (hashlib.sha256(env).hexdigest()[:32] + ".json")
    f.write_bytes(env)
    return f


def _plan_charge(txid: int, tx_ref: str, created: float) -> dict:
    from sigil.governor import catalog
    from sigil.governor.billing import _to_major
    amount_minor, currency = catalog.expected_amounts()[_PLAN]
    return {"id": txid, "status": "successful", "payment_plan": _PLAN, "amount": _to_major(amount_minor, currency),
            "currency": currency, "created_at": created, "tx_ref": tx_ref}


def _drain_rig(p, verifier, clock):
    """The REAL billing drain (BillingSigner + BillingSpoolWatcher) on the provisioner's own spine and spool."""
    from sigil.governor import catalog
    from sigil.governor.billing import BillingSigner, FlutterwaveBillingProvider
    from sigil.governor.metering import PlanCreditLedger
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.inbound.billing_spool import BillingSpoolWatcher
    signer = BillingSigner(FlutterwaveBillingProvider(_SECRET, verifier), wallet=WalletRegistry(p.store),
                           subscriptions=SubscriptionRegistry(p.store), plan=PlanCreditLedger(p.store),
                           catalog=catalog.entitlements(), expected=catalog.expected_amounts())
    root = p.pending_checkouts.billing_spools[0]
    return BillingSpoolWatcher(signer, spool_dir=str(root), verif_hash=_SECRET, now_fn=lambda: clock[0]), root


@pytest.mark.parametrize("net2b", [False, True])
def test_a_paid_plan_the_drain_has_not_minted_keeps_refusing_past_the_ttl(monkeypatch, net2b):
    """The customer pays plan checkout #1; the drain's /verify hits ONE transient failure, so the webhook is
    quarantined (NET-2b off: at once; on: once its bounded retries are spent) and waits for an operator — no time
    bound. Past the record's window a second plan checkout must still be refused (and not offered), until the plan
    drains, after which the drained subscription refuses it."""
    from sigil.governor.flutterwave_egress import FlutterwaveEgressError
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    if net2b:
        monkeypatch.setenv("VIGIL_NET_RECOVERY_ENABLED", "1")
    else:
        monkeypatch.delenv("VIGIL_NET_RECOVERY_ENABLED", raising=False)
    ensure_owner_keypair()
    p, admin, _t, org, other, _w = _provisioner()
    p.orgs.grant_membership(other, admin, "org_admin", issued_at=5.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    t0 = 10_000.0
    first = p.billing_checkout(admin, org, _PLAN, now=t0)["tx_ref"]
    charges = {"7001": _plan_charge(7001, first, t0 + 60)}             # the customer PAID at t0+60
    down = [True]

    def verifier(txid):
        if down[0]:
            exc = FlutterwaveEgressError("Flutterwave GET returned HTTP 503")
            exc.transient = True
            raise exc
        return charges.get(str(txid))
    clock = [t0 + 61]
    watcher, root = _drain_rig(p, verifier, clock)
    _spool_webhook(root, first, 7001)                                 # the proxy spooled it and answered 202
    while not watcher.drain()["rejected"]:
        assert net2b and (root / "retry").is_dir()
        clock[0] += 400.0                                             # past the 300 s cap: every parked one is due
    assert list((root / "rejected").glob("*.json"))
    later = t0 + DEFAULT_TTL_S + 60                                   # the record's window has ended
    offers = p.customer_billing_offers(admin, org, now=later)
    assert offers["has_active_plan"] is False and offers["plan_checkout_pending"] is True   # no plan re-offered
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=later)
    assert seen[-1]["outcome"] == "refused_pending_unconfirmed" and first in seen[-1]["reason"]
    assert "rejected/" in seen[-1]["reason"]
    assert p.customer_billing_offers(admin, org, now=later)["plan_checkout_pending"] is True  # the record was kept
    p.billing_checkout(admin, other, _PLAN, now=later)                # another org is not blocked
    p.billing_checkout(admin, org, _TOPUP, now=later)                 # nor are this org's top-ups
    assert [x.get("payment_plan") for x in posted] == [_PLAN, _PLAN, None]   # ONE plan for org, one for other
    # the operator re-drives the quarantined webhook once the processor is healthy: the plan DRAINS
    down[0] = False
    for f in (root / "rejected").glob("*.json"):
        f.replace(root / "incoming" / f.name)
    clock[0] = later + 60
    assert watcher.drain()["minted"] == 1
    with pytest.raises(ProvisionDenied, match="already has a plan"):
        p.billing_checkout(admin, org, _PLAN, now=later + 120)
    assert [x.get("payment_plan") for x in posted] == [_PLAN, _PLAN, None]


@pytest.mark.parametrize("stage", ["incoming", "working", "retry", "rejected"])
def test_an_undrained_webhook_in_any_spool_stage_holds_an_expired_window(monkeypatch, stage):
    """incoming/ (a late delivery, or a stopped drain), working/ (claimed mid-drain), retry/ (NET-2b parking),
    rejected/ (quarantine): wherever the paid webhook waits, the expired record does not lapse."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    _spool_webhook(p.pending_checkouts.billing_spools[0], first, 7001, stage)
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert f"{stage}/" in seen[-1]["reason"] and len(posted) == 1


def test_a_deleted_record_does_not_let_a_paid_but_undrained_plan_lapse(monkeypatch):
    """With the record file gone, the spine audit's lapsed plan checkout is checked against the spool instead —
    and the refused attempt leaves no claim behind."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    _spool_webhook(p.pending_checkouts.billing_spools[0], first, 7001, "rejected")
    _record_path(p).unlink()
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert seen[-1]["outcome"] == "refused_pending_unconfirmed" and first in seen[-1]["reason"]
    assert not any(Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64)) and len(posted) == 1


@pytest.mark.parametrize("whose", ["another_org", "own_topup"])
def test_only_an_earlier_plan_checkout_of_this_org_holds_the_window(monkeypatch, whose):
    """The spool check is exact: another org's undrained plan, or this org's undrained TOP-UP, is not an earlier
    plan checkout of this org — the abandoned plan checkout lapses as usual."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    _plans_on(monkeypatch)
    p, admin, _t, org, other, _w = _provisioner()
    p.orgs.grant_membership(other, admin, "org_admin", issued_at=5.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    ref = (p.billing_checkout(admin, other, _PLAN, now=5000.0)["tx_ref"] if whose == "another_org"
           else p.billing_checkout(admin, org, _TOPUP, now=5000.0)["tx_ref"])
    _spool_webhook(p.pending_checkouts.billing_spools[0], ref, 7001, "rejected")
    p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert [x.get("payment_plan") for x in posted][-1] == _PLAN and len(posted) == 3


@pytest.mark.parametrize("fault", ["unwired", "not_found", "unattributable", "symlink", "oversize", "fifo",
                                   "unlistable"])
def test_a_spool_that_cannot_prove_the_earlier_plan_unpaid_keeps_refusing(monkeypatch, tmp_path, fault):
    """Fail-closed: the expired record lapses only on a spool that was READ and shows no webhook that could be its
    payment. Unwired, not found, an envelope that cannot be read or attributed (a symlink is never followed, an
    oversize file never trusted, a FIFO never blocks the read), or a stage that cannot be listed all keep refusing —
    and keep the plan un-offered."""
    import os

    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    root = p.pending_checkouts.billing_spools[0]
    if fault == "unwired":
        p.pending_checkouts.billing_spools = None
    elif fault == "not_found":
        p.pending_checkouts.billing_spools = [tmp_path / "nowhere"]
    elif fault == "unattributable":
        (root / "rejected").mkdir()
        (root / "rejected" / "x.json").write_text("{torn", encoding="utf-8")
    elif fault == "symlink":
        real = _spool_webhook(tmp_path, "vigil:org_other:n", 7002)        # attributable — but only via the link
        (root / "rejected").mkdir()
        (root / "rejected" / "x.json").symlink_to(real)
    elif fault == "oversize":                                         # past the 256 KiB envelope cap (padding a
        (root / "rejected").mkdir()                                   # valid envelope: its head alone would parse)
        big = _envelope({"data": {"tx_ref": "vigil:org_other:n"}}) + b" " * (256 * 1024)
        (root / "rejected" / "x.json").write_bytes(big)
    elif fault == "fifo":
        (root / "rejected").mkdir()
        os.mkfifo(root / "rejected" / "x.json")                       # no writer: a blocking open would hang
    else:
        (root / "retry").write_text("not a directory", encoding="utf-8")
    later = 5000.0 + DEFAULT_TTL_S + 1
    assert p.customer_billing_offers(admin, org, now=later)["plan_checkout_pending"] is True
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="has not been confirmed"):
        p.billing_checkout(admin, org, _PLAN, now=later)
    assert seen[-1]["outcome"] == "refused_pending_unconfirmed" and len(posted) == 1
    assert os.path.exists(_record_path(p))                            # the expired record was kept


def test_a_webhook_the_drain_moves_mid_scan_is_still_seen(tmp_path, monkeypatch):
    """The drain re-admits retry/ -> incoming/ while the guard reads: a one-pass scan (incoming/ first) would miss
    the moving file. The scan re-reads until two passes agree, so it is caught; a spool that never settles refuses."""
    from sigil.reuse import generate_keypair
    from sigil.ui import pending_checkout as pc
    k = generate_keypair()
    root = tmp_path / "spool"
    led = pc.PendingPlanCheckouts(tmp_path / "pc", owner_key=k, trusted_pubkey=k.public_key_b64,
                                  billing_spools=[root])
    parked = _spool_webhook(root, "vigil:org_a:n1", 7001, "retry")
    (root / "incoming").mkdir()
    real = pc._envelope_tx_ref
    moves = {"n": 0}

    def drain_moves_it(path):
        if path.parent.name == "retry" and moves["n"] == 0:
            moves["n"] += 1
            parked.replace(root / "incoming" / parked.name)               # re-admitted just after incoming/ was read
        return real(path)
    monkeypatch.setattr(pc, "_envelope_tx_ref", drain_moves_it)
    assert "incoming/" in led.undrained(["vigil:org_a:n1"])

    def always_moving(path):
        raise FileNotFoundError(path)
    monkeypatch.setattr(pc, "_envelope_tx_ref", always_moving)
    assert led.undrained(["vigil:org_a:n1"]) == "the billing spool kept changing while it was read"
    monkeypatch.setattr(pc, "_envelope_tx_ref", real)
    (root / "incoming" / parked.name).unlink()
    assert led.undrained(["vigil:org_a:n1"]) == ""                     # a settled spool without it: proven absent


def test_a_plan_that_drains_while_the_claim_is_taken_still_refuses(monkeypatch):
    """The live-plan check runs before the claim; the first plan can drain in between (e.g. over a record that had
    just expired). It is re-checked under the claim, so the second subscription is refused and the claim freed."""
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    ensure_owner_keypair()
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    real_claim = p.pending_checkouts.claim
    later = 5000.0 + DEFAULT_TTL_S + 1

    def claim_while_it_drains(*a, **k):
        SubscriptionRegistry(p.store).subscribe(org, "pro", 2000, period_start=5060.0, period_end=1e7,
                                                issued_at=later)       # the drain minted it in the gap
        return real_claim(*a, **k)
    p.pending_checkouts.claim = claim_while_it_drains
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="already has a plan"):
        p.billing_checkout(admin, org, _PLAN, now=later)
    assert len(posted) == 1 and seen[-1]["outcome"] == "refused_existing_plan"
    assert not any(Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64))   # the claim was freed


def test_an_in_flight_plan_checkout_refuses_a_second_before_its_link_exists(monkeypatch):
    """The record is claimed BEFORE the outbound call, so a second request arriving while the first is still talking
    to the processor (no link, no "created" audit row yet) is refused by the record itself."""
    from sigil.governor.billing import checkout_tx_ref
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.pending_checkouts.claim(org, _PLAN, checkout_tx_ref(org, "inflight"), now=5000.0)   # request 1, mid-call
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _PLAN, now=5001.0)
    assert posted == [] and seen[-1]["outcome"] == "refused_pending_plan"
    assert seen[-1]["reason"].endswith(checkout_tx_ref(org, "inflight"))


def test_the_record_outlives_the_payable_link_plus_the_drain_lag():
    """The record's window outlasts the processor session the plan checkout asks for, plus a margin for the webhook
    of a last-second payment to arrive (at least the 60 s drain timer + the full NET-2b parking window, computed from
    its live defaults). The window is NOT what keeps a paid-but-undrained plan from lapsing — the spool check is
    (test_a_paid_plan_the_drain_has_not_minted_keeps_refusing_past_the_ttl)."""
    from vigil_integration.live import net_recovery

    from sigil.ui.pending_checkout import DEFAULT_TTL_S, DRAIN_LAG_S, PLAN_LINK_SESSION_MIN
    parking, d = 0.0, net_recovery.DEFAULT_BASE_S
    for _ in range(net_recovery.DEFAULT_MAX_ATTEMPTS):
        parking += min(d, net_recovery.DEFAULT_CAP_S)
        d *= 2
    assert DRAIN_LAG_S >= parking + 60.0
    assert DEFAULT_TTL_S >= PLAN_LINK_SESSION_MIN * 60.0 + DRAIN_LAG_S
    assert 1 <= PLAN_LINK_SESSION_MIN <= 1440                  # the processor's session ceiling


def test_a_plan_checkout_bounds_its_payment_session_and_a_topup_payload_is_unchanged(monkeypatch):
    from sigil.ui.pending_checkout import PLAN_LINK_SESSION_MIN
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _TOPUP, now=5000.0)
    p.billing_checkout(admin, org, _PLAN, now=5001.0)
    assert sorted(posted[0]) == ["amount", "currency", "customer", "meta", "tx_ref"]   # the top-up: as on main
    assert posted[1]["configurations"] == {"session_duration": PLAN_LINK_SESSION_MIN}
    assert posted[1]["payment_plan"] == _PLAN


def test_checkout_tx_ref_is_the_tx_ref_create_checkout_sets_and_validates_like_it():
    from sigil.governor.billing import checkout_tx_ref
    from sigil.governor import catalog
    sess = _real_provider([]).create_checkout(" org_a ", _TOPUP, expected=catalog.expected_amounts(), nonce="n1")
    assert checkout_tx_ref(" org_a ", "n1") == sess.tx_ref == "vigil:org_a:n1"
    for org, nonce in (("../x", "n1"), ("org_a", "a:b"), ("org_a", "")):
        with pytest.raises(ValueError):
            checkout_tx_ref(org, nonce)


@pytest.mark.parametrize("bad", [0, 1441, True, "30", 30.0])
def test_create_checkout_refuses_an_out_of_range_session(bad):
    from sigil.governor import catalog
    with pytest.raises(ValueError, match="session_minutes"):
        _real_provider([]).create_checkout("org_x", _TOPUP, expected=catalog.expected_amounts(), session_minutes=bad)


def test_topups_never_claim_and_another_org_is_independent(monkeypatch):
    _plans_on(monkeypatch)
    p, admin, _t, org, other, _w = _provisioner()
    p.orgs.grant_membership(other, admin, "org_admin", issued_at=5.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _TOPUP, now=5000.0)
    assert not any(Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64))   # a top-up writes no pending record
    p.billing_checkout(admin, org, _PLAN, now=5001.0)
    p.billing_checkout(admin, other, _PLAN, now=5002.0)                  # a different org is not blocked
    p.billing_checkout(admin, org, _TOPUP, now=5003.0)                   # and top-ups stay available
    assert [x.get("payment_plan") for x in posted] == [None, _PLAN, _PLAN, None]


def test_the_checkout_audit_records_the_tx_ref(monkeypatch):
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    seen = _audits(p)
    r1 = p.billing_checkout(admin, org, _PLAN, now=5000.0)
    r2 = p.billing_checkout(admin, org, _TOPUP, now=5001.0)
    created = [a for a in seen if a["outcome"] == "created"]
    assert [a["tx_ref"] for a in created] == [r1["tx_ref"], r2["tx_ref"]]
    rec = json.loads(next(Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64)).read_text(encoding="utf-8"))
    assert rec["tx_ref"] == r1["tx_ref"] == posted[0]["tx_ref"]           # the pending record names THE checkout
    assert created[0]["expires_at"] == rec["expires_at"]                 # the plan row carries its pending window
    assert "expires_at" not in created[1]                                # a top-up row does not


def test_a_deleted_pending_record_does_not_reopen_the_second_plan_window(monkeypatch):
    """The record is a SIGIL_HOME file; deleting it must fail CLOSED: the created plan checkout is on the
    tamper-evident spine audit with its window, which refuses until the window ends (then a new plan is allowed)."""
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    first = p.billing_checkout(admin, org, _PLAN, now=5000.0)["tx_ref"]
    _record_path(p).unlink()                                  # someone with SIGIL_HOME write access deletes it
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _PLAN, now=5001.0)
    assert len(posted) == 1
    assert seen[-1]["outcome"] == "refused_pending_spine" and first in seen[-1]["reason"]
    assert not any(Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64))   # the refused attempt left no claim
    p.billing_checkout(admin, org, _TOPUP, now=5002.0)                   # top-ups are unaffected
    p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S)     # the first window ended
    assert [x.get("payment_plan") for x in posted] == [_PLAN, None, _PLAN]


def test_a_spine_read_fault_refuses_the_plan_and_frees_the_claim(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)

    def broken(org_id, t):
        raise OSError("segment unreadable")                   # e.g. a manifest-referenced segment is missing
    p._spine_plan_checkouts = broken
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)
    assert posted == [] and seen[-1]["outcome"] == "refused_pending_spine" and "OSError" in seen[-1]["reason"]
    del p._spine_plan_checkouts
    p.billing_checkout(admin, org, _PLAN, now=5001.0)                    # no claim was left behind: retry works
    assert len(posted) == 1


@pytest.mark.parametrize("row", [{"outcome": "refused"}, {"outcome": "rate_limited"}, {"action": "launch_reserve"},
                                 {"org_id": "org_other"}])
def test_only_a_created_plan_checkout_of_this_org_holds_the_window(monkeypatch, row):
    """The spine backstop counts a row only when a payable link exists for THIS org: a CREATED billing_checkout."""
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.store.append(kind="event", source="provision", actor="WARDEN", payload={
        "signal": "provision.audit", "action": "billing_checkout", "requester": admin, "org_id": org,
        "target": _PLAN, "outcome": "created", "reason": "", "tx_ref": f"vigil:{org}:x", "expires_at": 9e9, **row})
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    assert len(posted) == 1


def test_the_offers_read_reports_a_plan_checkout_in_progress(monkeypatch):
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    _plans_on(monkeypatch)
    p, admin, _t, org, other, _w = _provisioner()
    p.orgs.grant_membership(other, admin, "org_admin", issued_at=5.0)
    p._checkout_provider = lambda: _real_provider([])
    assert p.customer_billing_offers(admin, org, now=4999.0)["plan_checkout_pending"] is False
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    assert p.customer_billing_offers(admin, org, now=5001.0)["plan_checkout_pending"] is True
    assert p.customer_billing_offers(admin, other, now=5001.0)["plan_checkout_pending"] is False
    assert p.customer_billing_offers(admin, org, now=5000.0 + DEFAULT_TTL_S)["plan_checkout_pending"] is False
    _record_path(p).write_text("{corrupt", encoding="utf-8")
    assert p.customer_billing_offers(admin, org, now=5001.0)["plan_checkout_pending"] is True   # fail-closed
    p.pending_checkouts = None
    assert p.customer_billing_offers(admin, other, now=5001.0)["plan_checkout_pending"] is True  # unwired: fail-closed
    monkeypatch.delenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED")
    assert p.customer_billing_offers(admin, org, now=5001.0)["plan_checkout_pending"] is False  # no plans offered


def _record_path(p):
    return next(Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64))


@pytest.mark.parametrize("tamper", ["backdate", "corrupt", "foreign_org", "unsigned"])
def test_a_tampered_or_corrupt_pending_record_refuses_with_an_operator_reason(monkeypatch, tamper):
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, other, _w = _provisioner()
    p.orgs.grant_membership(other, admin, "org_admin", issued_at=5.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    path = _record_path(p)
    rec = json.loads(path.read_text(encoding="utf-8"))
    if tamper == "backdate":                                  # make the live record look long expired
        rec["created_at"], rec["expires_at"] = 1.0, 2.0
        path.write_text(json.dumps(rec), encoding="utf-8")
    elif tamper == "corrupt":
        path.write_text("{truncated", encoding="utf-8")
    elif tamper == "unsigned":
        rec.pop("sig")
        rec["expires_at"] = 3.0
        path.write_text(json.dumps(rec), encoding="utf-8")
    else:                                                     # org's (valid, signed) record copied over `other`'s
        p.billing_checkout(admin, other, _PLAN, now=5000.0)
        target = next(q for q in Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64) if q != path)
        rec["expires_at"] = 3.0                               # ... and expire it, hoping to unblock
        target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        path = target
        org = other
    before = len(posted)
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="contact support"):
        p.billing_checkout(admin, org, _PLAN, now=9999.0)
    assert len(posted) == before
    a = seen[-1]
    assert a["outcome"] == "refused_pending_invalid" and path.name[:16] in a["reason"] and "remove it" in a["reason"]
    assert a["tx_ref"].startswith(f"vigil:{org}:")
    p.billing_checkout(admin, org, _TOPUP, now=9999.0)        # top-ups are unaffected by a bad plan record


def test_a_stale_unverifiable_record_is_reaped_after_the_ttl(monkeypatch):
    import os

    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    path = _record_path(p)
    path.write_text("{corrupt", encoding="utf-8")
    os.utime(path, (5000.0, 5000.0))                          # the (untrusted) file itself is old
    seen = _audits(p)
    p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert len(posted) == 2 and "reaped stale pending record" in seen[-1]["reason"]


def test_a_record_from_the_future_stays_live_and_says_why(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    p._checkout_provider = lambda: _real_provider([])
    p.billing_checkout(admin, org, _PLAN, now=10_000.0)
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)          # the clock moved backwards
    assert seen[-1]["outcome"] == "refused_pending_plan" and "clock moved backwards" in seen[-1]["reason"]


def test_a_processor_refusal_releases_the_claim(monkeypatch):
    from sigil.governor.billing import FlutterwaveBillingProvider
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()

    def down(payload):
        raise TimeoutError("processor down")
    p._checkout_provider = lambda: FlutterwaveBillingProvider("h", lambda *a, **k: None, checkout_creator=down)
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5001.0)                    # no link was issued: retry at once
    assert len(posted) == 1


@pytest.mark.parametrize("why", ["unwired", "no_owner_key", "unwritable"])
def test_plan_checkout_fails_closed_without_a_working_ledger(monkeypatch, tmp_path, why):
    from sigil.ui.pending_checkout import PendingPlanCheckouts
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    if why == "unwired":
        p.pending_checkouts = None
    elif why == "no_owner_key":
        p.pending_checkouts = PendingPlanCheckouts(tmp_path / "pc", owner_key=None, trusted_pubkey=None)
    else:
        (tmp_path / "pc").write_text("not a directory", encoding="utf-8")
        p.pending_checkouts.dir = tmp_path / "pc"
    with pytest.raises(ProvisionDenied, match="contact support"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)
    assert posted == []
    p.billing_checkout(admin, org, _TOPUP, now=5000.0)                   # top-ups never need the ledger
    assert len(posted) == 1


def test_release_drops_only_its_own_record(tmp_path):
    from sigil.reuse import generate_keypair
    from sigil.ui.pending_checkout import PendingPlanCheckouts
    k = generate_keypair()
    led = PendingPlanCheckouts(tmp_path / "pc", owner_key=k, trusted_pubkey=k.public_key_b64)
    led.claim("org_a", _PLAN, "vigil:org_a:n1", now=100.0)
    assert led.release("org_a", "vigil:org_a:other") is False
    assert led.release("org_a", "vigil:org_a:n1") is True
    assert led.release("org_a", "vigil:org_a:n1") is False


_CLAIM_WORKER = r"""
import os, sys, time
from sigil.reuse import KeyPair
from sigil.ui import pending_checkout as pc
pub, priv = sys.stdin.read().split()                 # the throwaway test key, never on argv
kp = KeyPair(public_key_b64=pub, private_key_b64=priv)
led = pc.PendingPlanCheckouts(sys.argv[1], owner_key=kp, trusted_pubkey=kp.public_key_b64,
                              billing_spools=[sys.argv[1] + ".spool"])   # an empty webhook spool: nothing undrained
real_read = led._read

def slow_read(*a):
    out = real_read(*a)
    time.sleep(0.03 * int(sys.argv[2][1:]))          # STAGGER the read-decide-write windows (test instrumentation)
    return out
led._read = slow_read
open(sys.argv[4] + ".ready." + sys.argv[2], "w").close()
while not os.path.exists(sys.argv[4] + ".go"):         # a start barrier: every process reads the SAME state
    time.sleep(0.005)
try:
    led.claim("org_race", "vigil_pro_monthly", "vigil:org_race:" + sys.argv[2], now=float(sys.argv[3]))
    sys.stdout.write("1")
except pc.PendingCheckoutRefused:
    sys.stdout.write("0")
"""


def _race(d, k, now: float) -> str:
    import time
    bar = f"{d}.barrier"
    Path(f"{d}.spool").mkdir(exist_ok=True)
    procs = [subprocess.Popen([sys.executable, "-c", _CLAIM_WORKER, str(d), f"n{i}", str(now), bar],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) for i in range(8)]
    for p in procs:
        assert p.stdin is not None
        p.stdin.write(f"{k.public_key_b64} {k.private_key_b64}")
        p.stdin.close()
    deadline = time.monotonic() + 60
    while sum(Path(f"{bar}.ready.n{i}").exists() for i in range(8)) < 8:
        assert time.monotonic() < deadline and all(p.poll() is None for p in procs), "a worker never got ready"
        time.sleep(0.01)
    Path(f"{bar}.go").touch()
    out = "".join(p.stdout.read() for p in procs if p.stdout is not None)
    assert all(p.wait(timeout=120) == 0 for p in procs), out
    return out


def test_racing_claims_from_separate_processes_admit_exactly_one(tmp_path):
    from sigil.reuse import generate_keypair
    k = generate_keypair()                                    # a throwaway test key, never a real owner key
    assert sorted(_race(tmp_path / "pc", k, 1000.0)) == ["0"] * 7 + ["1"]


def test_racing_claims_over_an_expired_record_admit_exactly_one(tmp_path):
    """The expired-record path is read -> unlink -> write: without the claim lock, a slower process could unlink the
    record a faster one has just written and publish its own — two pending plan checkouts, two links."""
    from sigil.reuse import generate_keypair
    from sigil.ui.pending_checkout import DEFAULT_TTL_S, PendingPlanCheckouts
    k = generate_keypair()
    led = PendingPlanCheckouts(tmp_path / "pc", owner_key=k, trusted_pubkey=k.public_key_b64)
    led.claim("org_race", _PLAN, "vigil:org_race:old", now=1000.0)
    assert sorted(_race(tmp_path / "pc", k, 1000.0 + DEFAULT_TTL_S + 1)) == ["0"] * 7 + ["1"]


def test_a_claim_fails_closed_when_the_lock_cannot_be_taken(tmp_path, monkeypatch):
    from sigil.reuse import generate_keypair
    from sigil.ui import pending_checkout as pc

    class _NoLock:
        LOCK_EX = 2

        @staticmethod
        def flock(fd, op):
            raise OSError("flock not supported here")
    k = generate_keypair()
    led = pc.PendingPlanCheckouts(tmp_path / "pc", owner_key=k, trusted_pubkey=k.public_key_b64)
    led.dir.mkdir()                                           # a usable directory: ONLY the lock is missing
    monkeypatch.setattr(pc, "fcntl", _NoLock)
    with pytest.raises(pc.PendingCheckoutRefused) as ei:
        led.claim("org_a", _PLAN, "vigil:org_a:n", now=100.0)
    assert ei.value.code == "refused_pending_io" and not led._marker("org_a").exists()


def test_a_claim_never_overwrites_a_record_it_did_not_read(tmp_path, monkeypatch):
    """Publishing is an exclusive create (os.link), so a record that appears between the read and the write (a
    writer that does not honour the lock) is never clobbered: the claim fails closed instead."""
    from sigil.reuse import generate_keypair
    from sigil.ui.pending_checkout import PendingCheckoutRefused, PendingPlanCheckouts
    k = generate_keypair()
    led = PendingPlanCheckouts(tmp_path / "pc", owner_key=k, trusted_pubkey=k.public_key_b64)
    led.claim("org_a", _PLAN, "vigil:org_a:first", now=100.0)
    before = led._marker("org_a").read_bytes()
    monkeypatch.setattr(led, "_read", lambda marker, org_id: (None, ""))   # it "saw" no record
    with pytest.raises(PendingCheckoutRefused) as ei:
        led.claim("org_a", _PLAN, "vigil:org_a:second", now=101.0)
    assert ei.value.code == "refused_pending_io"
    assert led._marker("org_a").read_bytes() == before


def test_a_symlinked_record_is_never_followed(tmp_path):
    """A marker that is a symlink (even to a genuine record) is not trusted: opened O_NOFOLLOW, it refuses."""
    from sigil.reuse import generate_keypair
    from sigil.ui.pending_checkout import PendingCheckoutRefused, PendingPlanCheckouts
    k = generate_keypair()
    led = PendingPlanCheckouts(tmp_path / "pc", owner_key=k, trusted_pubkey=k.public_key_b64)
    led.claim("org_a", _PLAN, "vigil:org_a:n", now=100.0)
    real = tmp_path / "elsewhere.json"
    led._marker("org_a").rename(real)
    led._marker("org_a").symlink_to(real)
    with pytest.raises(PendingCheckoutRefused) as ei:
        led.claim("org_a", _PLAN, "vigil:org_a:m", now=1e9)       # the genuine record behind it has expired
    assert ei.value.code == "refused_pending_invalid" and "unreadable" in ei.value.detail


@pytest.mark.parametrize("window", [("x", 200.0), (200.0, None), (200.0, 200.0), (300.0, 200.0)])
def test_a_signed_record_with_a_malformed_window_is_never_trusted(tmp_path, window):
    import json as _json

    from sigil.governor.authn import signed_payload
    from sigil.reuse import generate_keypair
    from sigil.ui.pending_checkout import SIGNAL, PendingCheckoutRefused, PendingPlanCheckouts
    k = generate_keypair()
    led = PendingPlanCheckouts(tmp_path / "pc", owner_key=k, trusted_pubkey=k.public_key_b64)
    core = {"signal": SIGNAL, "org_id": "org_a", "price_id": _PLAN, "tx_ref": "vigil:org_a:n",
            "created_at": window[0], "expires_at": window[1]}
    led.dir.mkdir(parents=True)
    led._marker("org_a").write_text(_json.dumps(signed_payload(core, k)), encoding="utf-8")
    with pytest.raises(PendingCheckoutRefused, match="unavailable") as ei:
        led.claim("org_a", _PLAN, "vigil:org_a:m", now=250.0)
    assert ei.value.code == "refused_pending_invalid" and "malformed validity window" in ei.value.detail
