"""W2b-3 — a metered launch names its DEPTH in the owner-signed lease and holds an allowance chunk from the wallet.

The prepaid wallet (pricing design §0.4; HANDOFF §11.5 c + h): with metered billing on, a launch selects an assessment
depth — VIGIL · Quick, Deep or Max — never an amount. Its first reservation is ``min(available, chunk)``
(``VIGIL_ALLOWANCE_CHUNK_CREDITS``, a holding granularity, not a price), never less than one useful model request,
and the run extends it as it goes (W2b-1/2); what it does not use returns to the wallet. Because those units are only a
chunk, they say nothing about the depth: the lease names it — in a document version an older reader refuses — under
the owner signature, and the run grant's effort and the engine's roster come from it.

Pins:
  * the first allowance is the chunk, or the whole balance below it, sized under the gate's lock from the live balance
    (two launches that race never hold more than the org has — I1 / I2), and never less than one useful request;
  * a balance (plan credits count) or credit-line headroom that cannot cover even one useful model request — the
    gateway's least prepaid reservation: 1,001 input tokens at the dearest input rate + 1,024 output tokens — refuses
    the launch with nothing debited and no amount quoted (I1, I5);
  * the depth is inside the owner signature, the grant's effort follows it, and a lease that names none keeps the
    effort its units derive;
  * a lease that names its depth is never published flat (it would be charged its whole chunk), and a completed run
    whose meter is gone is quarantined, never charged its whole chunk by the flat rule (I8);
  * a metered launch through the Provisioner selects the product's depth (Quick when none) and the chunk, never the
    product's units; a flat launch passes exactly what it passed before (I7);
  * a postpaid launch draws at most the credit line's headroom.

Mutation-verify targets (each neuter reds a NAMED test here):
  * reserve the whole chunk whatever the balance      -> test_the_first_allowance_is_the_chunk_or_the_whole_balance
  * size the allowance before the lock                -> test_the_allowance_is_sized_from_the_balance_under_the_lock
  * drop the one-useful-request start check           -> test_a_balance_below_one_useful_request_is_refused
  * price the least request without the input margin   -> test_a_balance_below_one_useful_request_is_refused
  * a first allowance below one useful request         -> test_the_first_allowance_is_the_chunk_or_the_whole_balance
  * start-check or size from the wallet only            -> test_plan_credits_fund_the_first_allowance
  * leave the depth or its version out of the lease   -> test_the_lease_names_the_depth_under_the_owner_signature
  * the grant's effort from the units band            -> test_the_grant_effort_follows_the_named_depth
  * publish a depth lease flat                        -> test_a_depth_lease_is_never_published_flat
  * settle a meterless depth lease by the flat rule     -> test_a_completed_depth_lease_without_its_meter_is_quarantined
  * a metered launch passes no depth / no chunk       -> test_a_metered_launch_selects_a_depth_and_the_chunk
  * a metered product reserves its own units          -> test_a_metered_product_selects_its_depth_not_its_units
  * a postpaid launch draws the chunk past the line   -> test_a_postpaid_launch_draws_at_most_the_lines_headroom
  * the postpaid one-useful-request threshold          -> test_a_postpaid_launch_draws_at_most_the_lines_headroom
"""
from __future__ import annotations

import itertools
import json
import os
import tempfile
import threading

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.metering import PlanCreditLedger, refill_active_subscription
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import PostpaidArrearsLedger, PostpaidRegistry
from sigil.governor.subscription import SubscriptionRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, Provisioner
from sigil.ui.target_authorization import add_customer_target
from vigil_core import AuthorizerKey, SignedCreditLaunchLease, TrustRoot, verify_credit_launch_lease
from vigil_core import model_metering as mm
from vigil_core.credit_lease import LEASE_DEPTH_VERSION
from vigil_core.model_grant import decode_token, meter_id
from vigil_core.rate_card import DEFAULT_RATE_CARD, RATE_CARD_ENV
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live.credit_lease_broker import read_credit_lease
from vigil_integration.live.model_grant_broker import read_model_grant

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
TEST_MARGIN = "0.5"                              # a test fixture (markup 2), not a pricing decision


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES",
              "VIGIL_MODEL_GATEWAY_ENABLED", "VIGIL_RUN_MODEL", mm.ALLOWANCE_CHUNK_ENV, RATE_CARD_ENV,
              "VIGIL_TIERED_PRODUCTS", "VIGIL_QUICK_MAX_UNITS", "VIGIL_CUSTOMER_STEPUP_REQUIRED",
              *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)


def _metered(monkeypatch):
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, TEST_MARGIN)
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _org(store, *, credits, hosts=(HOST,), postpaid=None, plan=0):
    """An org with ``credits`` in its wallet (and ``plan`` credits in a live subscription tranche) and a current
    ownership proof + owner-signed authority per host."""
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    if plan:
        subs = SubscriptionRegistry(store)
        subs.subscribe(ORG, "pro", plan, period_start=0.0, period_end=1e12, issued_at=float(next(_iss)))
        refill_active_subscription(subs, PlanCreditLedger(store), ORG, issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    for h in hosts:
        ch = reg.issue_challenge(ORG, h, issued_at=float(next(_iss)))
        reg.verify_and_record(ORG, h, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
        assert add_customer_target(h, org_id=ORG, store=store, now=NOW)["ok"]
    if postpaid is not None:
        PostpaidRegistry(store).set_account(ORG, postpaid, 30, issued_at=float(next(_iss)))
    return LaunchGate(store)


def _launch(g, *, depth="quick", chunk=100, host=HOST):
    return g.reserve_launch(requester="u", org_id=ORG, host=host, units=chunk, now=NOW, depth=depth)


def _avail(store):
    return WalletRegistry(store).available(ORG)


def _owner_root():
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=ensure_owner_keypair().public_key_b64)])


def _published_grant(r):
    bundle = read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"], expect_nonce=r["nonce"])
    grant, reason = decode_token(bundle.token, ensure_owner_keypair().public_key_b64)
    assert grant is not None, reason
    return grant


# ---- the first allowance: the chunk, at most the live balance ------------------------------------------------

@pytest.mark.parametrize("credits,chunk,held", [
    (1_000, 100, 100), (40, 100, 40), (250, 250, 250), (8, 100, 8),
    (1_000, 1, 8),        # a chunk below one useful request is raised to it: a run never starts unable to make one
])
def test_the_first_allowance_is_the_chunk_or_the_whole_balance(credits, chunk, held):
    s = _store()
    g = _org(s, credits=credits)
    r = _launch(g, chunk=chunk)
    assert r["ok"], r
    assert r["units_reserved"] == held == r["lease"]["document"]["units_reserved"]
    assert _avail(s) == credits - held                    # held from the wallet; never below zero (I2)


def test_a_balance_below_one_useful_request_is_refused():
    # The gateway's least prepaid reservation for any request: 1,001 input tokens (one token of content + the framing
    # margin both input bounds add) at the dearest input rate (1,563 per million: a reservation never counts on a
    # cached prefix) + 1,024 output tokens at 6,250 per million = 7.965 credits. A wallet of 7 can never have a model
    # request admitted, so the launch is refused before it starts — nothing debited, no lease (I1).
    assert gw.min_request_mc(DEFAULT_RATE_CARD) == 7_965
    s = _store()
    g = _org(s, credits=7)
    r = _launch(g)
    assert r["ok"] is False and "insufficient credits to start" in r["error"] and "lease" not in r
    assert not any(ch.isdigit() for ch in r["error"])     # no amount is quoted (pricing design §0.9)
    assert _avail(s) == 7
    assert not any(str((x.payload or {}).get("entry_id", "")).startswith("reserve-") for x in s.iter_records())


def test_plan_credits_fund_the_first_allowance():
    # A plan-only org (no wallet credits) starts on its plan tranche: the start check and the sizing count the plan
    # credits, drawn plan-first like every reservation.
    s = _store()
    g = _org(s, credits=0, plan=50)
    r = _launch(g)
    assert r["ok"], r
    assert r["units_reserved"] == 50
    assert PlanCreditLedger(s).available(ORG, NOW) == 0 and _avail(s) == 0
    s2 = _store()
    g2 = _org(s2, credits=0, plan=7)                      # below one useful request: refused, the plan untouched
    r2 = _launch(g2)
    assert r2["ok"] is False and "insufficient credits to start" in r2["error"]
    assert PlanCreditLedger(s2).available(ORG, NOW) == 7


class _RaceAtLock:
    """Stands in for the gate's spine lock: just before the reserve takes it, another launch of the org reserves
    ``race`` — after this launch's unlocked pre-check, before its locked re-check."""

    def __init__(self, lock, race):
        self._lk, self._race = lock, race

    def __enter__(self):
        if self._race is not None:
            race, self._race = self._race, None
            race()
        return self._lk.__enter__()

    def __exit__(self, *exc):
        return self._lk.__exit__(*exc)


def test_the_allowance_is_sized_from_the_balance_under_the_lock(monkeypatch):
    # The pre-check saw 1,000; another launch then took 900 before this one locked. The allowance must come from what
    # is left (100) — sized from the stale pre-check (500) it would over-debit the wallet (I2).
    s = _store()
    g = _org(s, credits=1_000)
    other = lambda: g.wallet.debit(ORG, 900, engagement_id="other", entry_id="reserve-wallet:other:n9",  # noqa: E731
                                   issued_at=NOW)
    monkeypatch.setattr(g, "_lock", _RaceAtLock(g._lock, other))
    r = _launch(g, chunk=500)
    assert r["ok"], r
    assert r["units_reserved"] == 100 and _avail(s) == 0


def test_racing_launches_never_hold_more_than_the_wallet():
    hosts = ("a1.apme.cm", "a2.apme.cm", "a3.apme.cm", "a4.apme.cm")
    s = _store()
    _org(s, credits=250, hosts=hosts)
    results: list = []

    def go(h):
        results.append(_launch(LaunchGate(s), host=h))

    threads = [threading.Thread(target=go, args=(h,)) for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r["units_reserved"] for r in results if r["ok"]) == [50, 100, 100]
    assert [r for r in results if not r["ok"]][0]["error"].startswith("insufficient credits to start")
    assert _avail(s) == 0


# ---- the depth, named under the owner signature ------------------------------------------------------------

@pytest.mark.parametrize("depth", ["quick", "deep", "max"])
def test_the_lease_names_the_depth_under_the_owner_signature(depth):
    s = _store()
    g = _org(s, credits=1_000)
    r = _launch(g, depth=depth)
    assert r["ok"], r
    signed = SignedCreditLaunchLease.model_validate(r["lease"])
    assert signed.document.run_tier == depth and signed.document.version == LEASE_DEPTH_VERSION
    assert verify_credit_launch_lease(signed, _owner_root())[0]
    raw = json.loads(signed.model_dump_json())
    del raw["document"]["run_tier"]                       # a versioned lease without its depth does not even parse
    with pytest.raises(ValueError, match="names its assessment depth"):
        SignedCreditLaunchLease.model_validate(raw)
    del raw["document"]["version"]                        # stripping both breaks the owner signature
    assert verify_credit_launch_lease(SignedCreditLaunchLease.model_validate(raw), _owner_root())[0] is False


def test_an_unknown_depth_or_an_unreadable_rate_card_refuses_before_any_debit(monkeypatch):
    s = _store()
    g = _org(s, credits=1_000)
    assert _launch(g, depth="ultra")["ok"] is False
    monkeypatch.setenv(RATE_CARD_ENV, "{not json")
    r = _launch(g)
    assert r["ok"] is False and "usage rates" in r["error"]
    assert _avail(s) == 1_000


def test_a_flat_launch_is_unchanged():
    # depth=None — every flat launch: exactly `units` is reserved and the lease names no depth and no version (I7)
    s = _store()
    g = _org(s, credits=1_000)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=10, now=NOW)
    assert r["ok"] and r["units_reserved"] == 10
    assert not {"run_tier", "version"} & set(r["lease"]["document"])
    assert _avail(s) == 990


def test_a_flat_launch_still_needs_its_whole_reservation():
    s = _store()
    g = _org(s, credits=6)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=10, now=NOW)
    assert r == {"ok": False, "error": "insufficient credits: need 10, have 6"}


# ---- the grant's effort, and the billing mode at publish -----------------------------------------------------

@pytest.mark.parametrize("depth,effort", [("quick", "high"), ("deep", "xhigh"), ("max", "max")])
def test_the_grant_effort_follows_the_named_depth(monkeypatch, depth, effort):
    # 100 credits would band as "deep": the named depth decides (Quick = high, Deep = xhigh, Max = max — design §2.2)
    _metered(monkeypatch)
    s = _store()
    g = _org(s, credits=1_000)
    r = _launch(g, depth=depth)
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    assert _published_grant(r).effort == effort


def test_a_lease_that_names_no_depth_keeps_its_derived_effort(monkeypatch):
    _metered(monkeypatch)
    s = _store()
    g = _org(s, credits=1_000)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=900, now=NOW)   # no depth: 900 bands "deep"
    assert "run_tier" not in r["lease"]["document"]
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    assert _published_grant(r).effort == "xhigh"


def test_a_depth_lease_is_never_published_flat(monkeypatch):
    # Reserved metered (a chunk the run would extend), then the owner turns metered billing off before it starts:
    # published flat, a completed run would be charged its whole chunk. Refused — nothing on the seam, no grant —
    # and the launch, which never started, is cancelled with a full refund.
    _metered(monkeypatch)
    s = _store()
    g = _org(s, credits=1_000)
    r = _launch(g, depth="deep")
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    out = g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)
    assert out["ok"] is False and "billing changed" in out["error"]
    base = os.environ["VIGIL_BASE_DIR"]
    assert read_credit_lease(base, r["slug"]) is None and read_model_grant(base, r["slug"]) is None
    assert g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW)["ok"]
    assert _avail(s) == 1_000


def test_a_completed_depth_lease_without_its_meter_is_quarantined(monkeypatch):
    # Published metered, run, completed — but its metered marker and meter are gone (a lost or restored meter
    # directory). The settle cannot read what the run used: it is quarantined for a human, never charged the whole
    # chunk by the flat rule (I8).
    _metered(monkeypatch)
    s = _store()
    g = _org(s, credits=1_000)
    r = _launch(g, depth="deep")
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    mid = meter_id(r["slug"], r["nonce"])
    gone = [f for f in config.MODEL_METER_DIR.iterdir() if f.name.startswith(mid)]
    assert gone                                            # the metered marker the publish wrote
    for f in gone:
        f.unlink()
    owner = ensure_owner_keypair()
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=r["slug"], not_after=9_000_000_000)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = CompletionSpoolWatcher(s, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                                 scope=r["slug"], base_dir=os.environ["VIGIL_BASE_DIR"], now_fn=lambda: NOW).drain()
    assert out["settled"] == 0 and out["rejected"] == 1
    assert _avail(s) == 900                                # still held: nothing charged on a guess, nothing refunded


# ---- postpaid: at most the credit line's headroom ------------------------------------------------------------

@pytest.mark.parametrize("drawn,chunk,held", [
    (960, 100, 40),       # the chunk, at most the line's live headroom
    (992, 100, 8),        # headroom 8: exactly one useful request
    (993, 100, None),     # headroom 7: below one useful request — refused, nothing drawn
    (0, 1, 8),            # a chunk below one useful request is raised to it (a postpaid launch cannot be extended)
])
def test_a_postpaid_launch_draws_at_most_the_lines_headroom(drawn, chunk, held):
    s = _store()
    g = _org(s, credits=0, postpaid=1_000)
    arrears = PostpaidArrearsLedger(s)
    if drawn:
        arrears.accrue(ORG, drawn, engagement_id="earlier", entry_id="reserve:earlier:n0", issued_at=float(next(_iss)))
    r = _launch(g, chunk=chunk)
    if held is None:
        assert r["ok"] is False and "no room left" in r["error"] and arrears.accrued(ORG) == drawn
        return
    assert r["ok"], r
    assert r["units_reserved"] == held and arrears.accrued(ORG) == drawn + held
    doc = r["lease"]["document"]
    assert doc["run_tier"] == "quick" and doc["version"] == LEASE_DEPTH_VERSION   # a postpaid lease names its depth


# ---- the Provisioner: a metered launch selects a depth and the chunk -----------------------------------------

def _prov(monkeypatch):
    """A real Provisioner with a member admin; admit_customer is forced True so the reservation INPUTS are what is
    exercised (the admit gate is pinned by its own tests)."""
    s = _store()
    owner = generate_keypair()
    op = owner.public_key_b64
    custs = CustomerRegistry(s, owner_key=owner, trusted_pubkey=op)
    orgs = OrgRegistry(s, owner_key=owner, trusted_pubkey=op)
    clock = itertools.count(1)
    p = Provisioner(
        s, customers=custs, orgs=orgs, wallet=WalletRegistry(s, owner_key=owner, trusted_pubkey=op),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: float(next(clock)))
    admin, org = "cust_admin000000000000001", "org_p1"
    custs.create("admin@acme.com", issued_at=1.0, password="password-xyz", username=admin)
    orgs.create_org(org, "Acme", owner=admin, issued_at=2.0)
    orgs.grant_membership(org, admin, "org_admin", issued_at=3.0)
    monkeypatch.setattr(p.orgs, "admit_customer", lambda **kw: True)
    return p, admin, org


def _capture(monkeypatch):
    """Capture exactly what launch_reserve hands LaunchGate.reserve_launch (the real chain is pinned above)."""
    seen: dict = {}

    def _cap(self, *, requester, org_id, host, units, now, **kw):
        seen.clear()
        seen.update(units=units, **kw)
        return {"ok": True, "slug": "cust_x", "host": host, "units_reserved": units, "nonce": "n1",
                "not_before": 0.0, "not_after": 0.0, "lease": {}, "trust_root": {}}
    monkeypatch.setattr("sigil.ui.launch_gate.LaunchGate.reserve_launch", _cap)
    return seen


def test_a_metered_launch_selects_a_depth_and_the_chunk(monkeypatch):
    _metered(monkeypatch)
    p, admin, org = _prov(monkeypatch)
    seen = _capture(monkeypatch)
    p.launch_reserve(admin, org, "acme.example")
    assert seen == {"units": mm.DEFAULT_ALLOWANCE_CHUNK_CREDITS, "depth": "quick"}
    monkeypatch.setenv(mm.ALLOWANCE_CHUNK_ENV, "250")
    p.launch_reserve(admin, org, "acme.example")
    assert seen == {"units": 250, "depth": "quick"}


@pytest.mark.parametrize("pid,depth", [("vigil_launch_quick", "quick"), ("vigil_launch_deep", "deep")])
def test_a_metered_product_selects_its_depth_not_its_units(monkeypatch, pid, depth):
    _metered(monkeypatch)
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    p, admin, org = _prov(monkeypatch)
    seen = _capture(monkeypatch)
    out = p.launch_reserve(admin, org, "acme.example", product_id=pid)
    assert seen == {"units": mm.DEFAULT_ALLOWANCE_CHUNK_CREDITS, "depth": depth} and out["product_id"] == pid


def test_a_flat_launch_through_the_provisioner_is_unchanged(monkeypatch):
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    p, admin, org = _prov(monkeypatch)
    seen = _capture(monkeypatch)
    p.launch_reserve(admin, org, "acme.example")
    assert seen == {"units": config.LAUNCH_UNITS}         # no depth: byte-identical to the flat call (I7)
    p.launch_reserve(admin, org, "acme.example", product_id="vigil_launch_deep")
    assert seen == {"units": 20}                          # a flat product still reserves its catalog units


@pytest.mark.parametrize("bad", ["0", "1000001", "x"])
def test_an_invalid_chunk_setting_refuses_a_metered_launch(monkeypatch, bad):
    _metered(monkeypatch)
    monkeypatch.setenv(mm.ALLOWANCE_CHUNK_ENV, bad)
    p, admin, org = _prov(monkeypatch)
    seen = _capture(monkeypatch)
    audits: list = []
    real = p.store.append

    def cap(**kw):
        pl = kw.get("payload")
        if isinstance(pl, dict) and pl.get("signal") == "provision.audit":
            audits.append(pl)
        return real(**kw)
    p.store.append = cap
    with pytest.raises(ProvisionDenied, match="billing setting is invalid"):
        p.launch_reserve(admin, org, "acme.example")
    assert seen == {}
    assert [(a.get("action"), a.get("outcome")) for a in audits] == [("launch_reserve", "denied")]


def test_the_gateway_reads_the_same_chunk_setting(monkeypatch):
    ensure_owner_keypair()
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv(mm.ALLOWANCE_CHUNK_ENV, "250")
    assert gw.config_from_env().allowance_chunk_credits == 250
    monkeypatch.setenv(mm.ALLOWANCE_CHUNK_ENV, "0")
    with pytest.raises(ValueError):
        gw.config_from_env()


# ---- red-pen verifier follow-ups -----------------------------------------------------------------------------

@pytest.mark.parametrize("split", [False, True])
def test_a_mixed_plan_and_wallet_first_allowance_records_its_split(monkeypatch, split):
    # 60 plan credits + a funded wallet, chunk 100: the hold is drawn plan-first (60) then wallet (40); with
    # VIGIL_LEASE_PLAN_SPLIT on, the lease records that split next to its depth.
    if split:
        monkeypatch.setenv("VIGIL_LEASE_PLAN_SPLIT", "1")
    else:
        monkeypatch.delenv("VIGIL_LEASE_PLAN_SPLIT", raising=False)
    s = _store()
    g = _org(s, credits=1_000, plan=60)
    r = _launch(g)
    assert r["ok"], r
    doc = r["lease"]["document"]
    assert r["units_reserved"] == 100 and doc["run_tier"] == "quick"
    assert PlanCreditLedger(s).available(ORG, NOW) == 0 and _avail(s) == 960
    assert doc.get("plan_reserved") == (60 if split else None)


def test_a_postpaid_metered_launch_publishes_the_effort_of_its_depth(monkeypatch):
    _metered(monkeypatch)
    s = _store()
    g = _org(s, credits=0, postpaid=1_000)
    r = _launch(g, depth="deep")
    assert r["ok"], r
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    assert _published_grant(r).effort == "xhigh"


def test_the_chunk_bound_is_the_gates_own_reservation_bound():
    # one rule: a chunk the shared reader accepts is never refused by the gate's own units range check
    from sigil.ui import launch_gate
    assert launch_gate._MAX_UNITS == mm.MAX_ALLOWANCE_CHUNK_CREDITS
