"""Slice G — the offense-launch authorization gate (billing != testing, enforced at the launch path).

LaunchGate.reserve_launch composes FOUR fail-closed conjuncts before it reserves credits + mints a lease:
  1. admit_customer(run_engagement) — a billing-only org_admin / viewer / non-member is refused;
  2. a current ownership proof for (org, host) — credits alone never authorize a test;
  3. a CURRENT owner-signed EngagementAuthority for exactly this host (scope + window), verifying under the
     owner key;
  4. CreditMeter.available >= units.
On any refusal NOTHING is debited and NO lease is minted; on success the lease verifies under the owner key
and the reserved credits are held.

Vault-backed harness (one owner key throughout); runs with the integration PYTHONPATH (the authority broker
+ add_customer_target live across the seam).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _setup(store, org, host, *, role="operator", credits=100, proof=True, authority=True, now=1000.0):
    """Seat a member + wallet credits (+ optionally an ownership proof + a minted EngagementAuthority)."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.target_authorization import add_customer_target
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", role, issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    if proof or authority:
        reg = AssetOwnershipRegistry(store)
        ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
        reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=1e12)
        if authority:
            r = add_customer_target(host, org_id=org, store=store, now=now)
            assert r["ok"], r
        if not proof:
            reg.revoke_proof(org, host)        # authority stays on the seam, but the proof is gone (isolate #2)


def _gate(store):
    from sigil.ui.launch_gate import LaunchGate
    return LaunchGate(store)


def _avail(store, org):
    from sigil.governor.wallet import WalletRegistry
    return WalletRegistry(store).available(org)


# --- happy path: all four conjuncts hold -> reserve + mint ------------------------------------------

def test_reserve_launch_happy_path_mints_a_verifiable_lease_and_holds_credits():
    from vigil_core import SignedCreditLaunchLease, TrustRoot, verify_credit_launch_lease
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)
    assert _avail(s, "org_a") == 100
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"] and r["units_reserved"] == 30 and r["slug"].startswith("cust_"), r
    # the lease verifies under the owner key
    signed = SignedCreditLaunchLease.model_validate(r["lease"])
    tr = TrustRoot.model_validate(r["trust_root"])
    ok, reason = verify_credit_launch_lease(signed, tr)
    assert ok, reason
    assert signed.document.scope_host == "apme.cm" and signed.document.org_id == "org_a"
    assert _avail(s, "org_a") == 70            # 30 credits reserved (held)


# --- conjunct 1: membership is not testing authority (billing != testing) ---------------------------

def test_billing_admin_cannot_launch():
    s = _store()
    _setup(s, "org_a", "apme.cm", role="org_admin", credits=100)   # billing admin, NO run_engagement
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"] is False and "membership is not testing authority" in r["error"]
    assert _avail(s, "org_a") == 100           # NOTHING debited on refusal


def test_nonmember_cannot_launch():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)
    r = _gate(s).reserve_launch(requester="stranger", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"] is False
    assert _avail(s, "org_a") == 100


# --- conjunct 2: a current ownership proof is required ----------------------------------------------

def test_no_ownership_proof_refused_even_with_authority_and_credits():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100, proof=False)   # authority minted, then proof revoked
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"] is False and "ownership proof" in r["error"]
    assert _avail(s, "org_a") == 100


# --- conjunct 3: a current owner-signed EngagementAuthority is required ------------------------------

def test_no_target_authority_refused():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100, authority=False)   # proof present, authority NOT minted
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"] is False and "engagement authority" in r["error"]
    assert _avail(s, "org_a") == 100


def test_cross_tenant_authority_not_accepted():
    """org_b cannot launch apme.cm on org_a's authority — the slug is per-(org,host), and org_b has no proof."""
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)                   # org_a fully set up
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    OrgRegistry(s).create_org("org_b", "org_b", owner="v", issued_at=float(next(_iss)))
    OrgRegistry(s).grant_membership("org_b", "v", "operator", issued_at=float(next(_iss)))
    WalletRegistry(s).grant("org_b", 100, "trial", entry_id="trial:org_b", issued_at=float(next(_iss)))
    r = _gate(s).reserve_launch(requester="v", org_id="org_b", host="apme.cm", units=10, now=2000.0)
    assert r["ok"] is False and "ownership proof" in r["error"]   # org_b never proved apme.cm
    assert _avail(s, "org_b") == 100


# --- conjunct 4: sufficient credits ------------------------------------------------------------------

def test_insufficient_credits_refused():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=5)
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"] is False and "insufficient credits" in r["error"]
    assert _avail(s, "org_a") == 5


# --- input validation --------------------------------------------------------------------------------

@pytest.mark.parametrize("units", [0, -1, 10_000_000])
def test_bad_units_refused(units):
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=units, now=2000.0)
    assert r["ok"] is False and _avail(s, "org_a") == 100


# --- settle / release: refund bound to the SIGNED lease (net spend == consumption) ------------------

def _reserve(store, *, units=30):
    _setup(store, "org_a", "apme.cm", credits=100)
    r = _gate(store).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=units, now=2000.0)
    assert r["ok"], r
    return r


def test_settle_refunds_the_unused_reservation():
    s = _store()
    r = _reserve(s)                                        # 100 - 30 reserved = 70
    out = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=10, now=3000.0)
    assert out["ok"] and out["refunded"] == 20 and out["net_spend"] == 10
    assert _avail(s, "org_a") == 90                        # net spend 10


def test_settle_cancel_is_a_full_refund():
    s = _store()
    r = _reserve(s)
    out = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=3000.0)
    assert out["refunded"] == 30 and _avail(s, "org_a") == 100   # cancel before work -> nothing spent


def test_settle_all_consumed_no_refund():
    s = _store()
    r = _reserve(s)
    out = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=30, now=3000.0)
    assert out["refunded"] == 0 and _avail(s, "org_a") == 70


def test_settle_clamps_consumed_to_reserved():
    """The offense side can NEVER claw back more than the signed reservation — consumed is clamped to the cap."""
    s = _store()
    r = _reserve(s)
    out = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=999, now=3000.0)
    assert out["refunded"] == 0 and _avail(s, "org_a") == 70     # clamped: no negative refund, no over-claw


def test_settle_is_idempotent():
    s = _store()
    r = _reserve(s)
    g = _gate(s)
    g.settle_launch(signed_lease=r["lease"], consumed_units=10, now=3000.0)
    g.settle_launch(signed_lease=r["lease"], consumed_units=10, now=4000.0)   # retry
    assert _avail(s, "org_a") == 90                        # refunded exactly once, not twice


def test_settle_invariant_refuses_an_overclaiming_plan_debit_record(monkeypatch):
    """K4-1 money-doctrine invariant (load-bearing clause): if the owner-signed reserve debit record over-claims
    the plan bucket relative to the signed lease (from_plan > reserved), the naive bucket split would grant an
    inflated plan_refund while silently skipping the resulting NEGATIVE wallet_refund — a net OVER-refund. The
    invariant must FIRE and refuse (fail-closed, NOTHING refunded), so net spend never falls below consumption."""
    s = _store()
    r = _reserve(s)                                            # reserves 30 of 100 -> available 70
    g = _gate(s)
    reserved = int(r["units_reserved"])
    # a drifted/forged debit record claiming MORE was debited from the (expiring) plan tranche than the lease reserves
    monkeypatch.setattr(g.meter.plan, "debited_entry", lambda oid, eid: (reserved + 50, 9e12))
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=3000.0)
    assert out["ok"] is False and "invariant" in out["error"]  # refused, not an over-refund
    assert _avail(s, "org_a") == 70                            # NOTHING moved — net spend can't drop below consumption


def test_settle_tombstones_and_marks_the_lease_unrunnable():
    """K4-1 / K5: settling a lease must make it non-runnable BEFORE anything can arm off it — tombstone the
    published seam bundle (read_credit_lease -> None) AND durably mark (slug,nonce) settled, and refuse to
    re-publish a settled lease (no resurrecting a spent bearer capability)."""
    import os
    from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease
    s = _store(); r = _reserve(s); g = _gate(s)
    base = os.environ["VIGIL_BASE_DIR"]
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id="org_a")["ok"]
    assert read_credit_lease(base, r["slug"]) is not None             # published -> a runnable bearer capability
    assert g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=3000.0, expect_org_id="org_a")["ok"]
    assert read_credit_lease(base, r["slug"]) is None                 # tombstoned on settle
    assert is_lease_settled(base, r["slug"], r["nonce"]) is True       # ...and durably marked settled
    pub2 = g.publish_lease(signed_lease=r["lease"], expect_org_id="org_a")
    assert pub2["ok"] is False and "settled" in pub2["error"].lower()  # cannot resurrect a settled lease


def test_settle_does_not_clobber_a_concurrent_newer_re_lease():
    """K4-1 red-pen fold: settling an OLD lease must NOT tombstone a concurrently-published NEWER re-lease's
    bundle (same slug, new nonce). The old lease's own (slug,nonce) marker still revokes it; the newer lease
    stays an un-settled, runnable bearer capability on the seam (nonce-matched tombstone)."""
    import os
    from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)
    g = _gate(s)
    base = os.environ["VIGIL_BASE_DIR"]
    r1 = g.reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    r2 = g.reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2100.0)
    assert r1["ok"] and r2["ok"] and r1["slug"] == r2["slug"] and r1["nonce"] != r2["nonce"]
    slug = r1["slug"]
    assert g.publish_lease(signed_lease=r1["lease"], expect_org_id="org_a")["ok"]
    assert g.publish_lease(signed_lease=r2["lease"], expect_org_id="org_a")["ok"]   # overwrites with the NEWER bundle
    # settle the OLD lease r1 — marks r1's nonce settled, must NOT remove r2's published bundle
    assert g.settle_launch(signed_lease=r1["lease"], consumed_units=0, now=3000.0, expect_org_id="org_a")["ok"]
    assert is_lease_settled(base, slug, r1["nonce"]) is True
    assert is_lease_settled(base, slug, r2["nonce"]) is False          # the newer re-lease is NOT settled
    bundle = read_credit_lease(base, slug)
    assert bundle is not None and bundle.signed_lease.document.nonce == r2["nonce"]  # r2's bundle survives


# --- red-pen fold: the refund is bound to the OWNER-SIGNED lease, never a wire amount ---------------

def test_settle_rejects_a_forged_lease_no_free_credits():
    """HIGH fold: settle verifies the lease under the owner key; a forged/attacker-signed lease asserting a
    huge units_reserved mints NOTHING (the earlier wire-trusted-units free-credit bug)."""
    from vigil_core import (AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair,
                            sign_credit_launch_lease)
    from datetime import datetime, timedelta, timezone
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)
    attacker = generate_keypair()
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    forged = sign_credit_launch_lease(
        CreditLaunchLease(engagement_slug="cust_x", org_id="org_a", scope_host="apme.cm",
                          units_reserved=1_000_000, not_before=t0, not_after=t0 + timedelta(hours=8),
                          nonce="n", issued_at=1.0),
        {"owner": attacker.private_key_b64})                      # signed by the WRONG key
    out = _gate(s).settle_launch(signed_lease=forged.model_dump(mode="json"), consumed_units=0, now=3000.0)
    assert out["ok"] is False and _avail(s, "org_a") == 100       # no refund minted


def test_settle_rejects_a_bare_wire_amount():
    """There is NO wire units_reserved parameter any more — a caller cannot assert a refund amount."""
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)
    out = _gate(s).settle_launch(signed_lease={"not": "a lease"}, consumed_units=0, now=3000.0)
    assert out["ok"] is False and _avail(s, "org_a") == 100


def test_forged_seam_authority_refused_owner_must_sign():
    """HIGH fold: _authority_ok verifies against a PINNED owner root, not the seam bundle's own trust_root.
    An attacker who writes a bundle co-listing the owner PUBLIC key + their own, signed by their own key,
    is refused (the owner key must have SIGNED, not merely be listed)."""
    import os
    from datetime import datetime, timedelta, timezone
    from vigil_core import (AuthorizerKey, EngagementAuthority, TargetEnvironment, TrustRoot,
                            generate_keypair, sign_engagement_authority)
    from vigil_integration.live.authorization_broker import write_authorization
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui.target_authorization import _customer_slug
    s = _store()
    # org_a: operator + proof + credits, but NO legitimately-minted authority (so only the forgery is present)
    _setup(s, "org_a", "apme.cm", credits=100, authority=False)
    owner = ensure_owner_keypair()
    attacker = generate_keypair()
    # a window that COVERS now=2000.0 (a POSIX ts), so ONLY the owner-pin can refuse — not the window check
    nb = datetime.fromtimestamp(0, tz=timezone.utc)
    na = datetime.fromtimestamp(1e9, tz=timezone.utc)
    slug = _customer_slug("org_a", "apme.cm")
    doc = EngagementAuthority(engagement_slug=slug, environment=TargetEnvironment("live"), scope=["apme.cm"],
                              not_before=nb, not_after=na, issued_by="attacker")
    forged = sign_engagement_authority(doc, {"attacker": attacker.private_key_b64})
    # trust_root co-lists the owner's PUBLIC key (public info) beside the attacker key; threshold 1
    forged_root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64),
        AuthorizerKey(key_id="attacker", name="attacker", public_key_b64=attacker.public_key_b64)])
    write_authorization(os.environ["VIGIL_BASE_DIR"], slug, forged, forged_root)
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"] is False and "engagement authority" in r["error"]   # owner never signed -> refused
    assert _avail(s, "org_a") == 100


def _owner_authority_on_seam(org, host, *, scope, not_before, not_after):
    """Write a GENUINELY owner-signed EngagementAuthority for (org, host)'s slug straight onto the seam, so a
    test can vary ONLY the scope / window the gate must still check after the owner-pin passes."""
    import os
    from datetime import datetime, timezone
    from vigil_core import (AuthorizerKey, EngagementAuthority, TargetEnvironment, TrustRoot,
                            sign_engagement_authority)
    from vigil_integration.live.authorization_broker import write_authorization
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui.target_authorization import _customer_slug
    owner = ensure_owner_keypair()
    slug = _customer_slug(org, host)
    doc = EngagementAuthority(engagement_slug=slug, environment=TargetEnvironment("live"), scope=scope,
                              not_before=datetime.fromtimestamp(not_before, tz=timezone.utc),
                              not_after=datetime.fromtimestamp(not_after, tz=timezone.utc), issued_by="owner")
    signed = sign_engagement_authority(doc, {"owner": owner.private_key_b64})
    root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])
    write_authorization(os.environ["VIGIL_BASE_DIR"], slug, signed, root)


@pytest.mark.parametrize("not_before,not_after,admitted", [
    (0.0, 1e9, True),          # positive control: owner-signed, exact scope, window covers now -> admitted
    (0.0, 1500.0, False),      # EXPIRED before now=2000 (a stale bundle left on the seam)
    (2500.0, 1e9, False),      # NOT YET valid at now=2000
], ids=["covering-window-admitted", "expired-refused", "not-yet-valid-refused"])
def test_owner_signed_authority_must_be_current(not_before, not_after, admitted):
    """The target authority must be CURRENT, not merely owner-signed: a genuinely owner-signed authority whose
    window has closed (or not opened) never authorizes a launch, and nothing is debited. The covering-window
    case is the control that proves the helper's bundle passes the owner-pin, so the refusals are the window's."""
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100, authority=False)
    _owner_authority_on_seam("org_a", "apme.cm", scope=["apme.cm"], not_before=not_before, not_after=not_after)
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    if admitted:
        assert r["ok"], r
        assert _avail(s, "org_a") == 90
    else:
        assert r["ok"] is False and "engagement authority" in r["error"], r
        assert _avail(s, "org_a") == 100


def test_owner_signed_authority_with_a_wider_scope_refused():
    """The target authority must scope EXACTLY this host: an owner-signed bundle under the slug whose scope
    also covers another host is refused — the gate never launches on an authority broader than [host]."""
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100, authority=False)
    _owner_authority_on_seam("org_a", "apme.cm", scope=["apme.cm", "other.example"], not_before=0.0, not_after=1e9)
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"] is False and "engagement authority" in r["error"], r
    assert _avail(s, "org_a") == 100


def test_nonce_reuse_does_not_mint_a_free_lease():
    """MED fold: re-reserving a (slug, nonce) whose debits already applied yields no delta -> refused, so a
    settled-then-reused nonce cannot mint a second lease on a swallowed debit."""
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)
    g = _gate(s)
    r1 = g.reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0, nonce="fixed")
    assert r1["ok"] and _avail(s, "org_a") == 70
    g.settle_launch(signed_lease=r1["lease"], consumed_units=0, now=2500.0)    # refund -> back to 100
    r2 = g.reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=3000.0, nonce="fixed")
    assert r2["ok"] is False and _avail(s, "org_a") == 100     # reused nonce -> no debit, no free lease


# --- red-pen fold: the refund restores the SAME buckets reserve debited (no plan->wallet laundering) -----
def _plan(store, org, allotment, period_end):
    """Seat an active subscription + a plan tranche so the meter's plan_live > 0 (reserve debits plan-first)."""
    from sigil.governor.metering import PlanCreditLedger, refill_active_subscription
    from sigil.governor.subscription import SubscriptionRegistry
    subs = SubscriptionRegistry(store)
    plan = PlanCreditLedger(store)
    subs.subscribe(org, "pro", allotment, period_start=0.0, period_end=period_end, issued_at=float(next(_iss)))
    refill_active_subscription(subs, plan, org, issued_at=float(next(_iss)))


def _pos(store, org, now):
    from sigil.governor.metering import CreditMeter, PlanCreditLedger
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.governor.wallet import WalletRegistry
    return CreditMeter(WalletRegistry(store), PlanCreditLedger(store), SubscriptionRegistry(store)).position(org, now)


def test_cancel_restores_plan_credits_not_the_wallet_no_laundering():
    # reserve debits PLAN-credits-first (non-rollover); a cancel (settle consumed=0) must RESTORE the plan
    # tranche, never launder expiring plan credits into the permanent wallet (the red-pen money finding).
    PE = 1e12
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=5)                  # tiny PERMANENT wallet
    _plan(s, "org_a", 100, PE)                                # 100 non-rollover PLAN credits
    assert _pos(s, "org_a", 2000.0).plan_live == 100 and _avail(s, "org_a") == 5
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"], r
    assert _pos(s, "org_a", 2000.0).plan_live == 90 and _avail(s, "org_a") == 5   # debited PLAN, not wallet
    out = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=2100.0)
    assert out["ok"] and out["refunded_plan"] == 10 and out["refunded_wallet"] == 0, out
    assert _pos(s, "org_a", 2000.0).plan_live == 100          # the PLAN tranche is restored
    assert _avail(s, "org_a") == 5                            # wallet NOT inflated — laundering closed
    # and the restored plan credits STILL expire at period_end (non-rollover preserved); nothing went permanent
    assert _pos(s, "org_a", PE + 1).plan_live == 0 and _avail(s, "org_a") == 5


def test_mixed_reservation_refunds_plan_and_wallet_to_their_own_buckets():
    # plan_live 5 + wallet 20, reserve 10 -> from_plan=5 (expiring), from_wallet=5 (permanent). cancel restores
    # each bucket to its own total (5 back to the plan tranche, 5 back to the wallet) — split re-derived from
    # the owner-signed debit records, never a wire amount.
    PE = 1e12
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=20)
    _plan(s, "org_a", 5, PE)
    assert _pos(s, "org_a", 2000.0).plan_live == 5 and _avail(s, "org_a") == 20
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"], r
    assert _pos(s, "org_a", 2000.0).plan_live == 0 and _avail(s, "org_a") == 15   # plan 5 + wallet 5 debited
    out = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=2100.0)
    assert out["refunded_plan"] == 5 and out["refunded_wallet"] == 5, out
    assert _pos(s, "org_a", 2000.0).plan_live == 5 and _avail(s, "org_a") == 20   # each bucket restored


# --- Slice K3: publish the owner-signed lease to the cross-plane seam (producer half) ----------------
def test_publish_lease_writes_the_owner_signed_lease_to_the_seam():
    from sigil.ui.target_authorization import _base_dir
    from vigil_core import verify_credit_launch_lease
    from vigil_integration.live.credit_lease_broker import read_credit_lease
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"], r
    out = _gate(s).publish_lease(signed_lease=r["lease"], expect_org_id="org_a")
    assert out["ok"] and out["slug"] == r["slug"] and out["scope_host"] == "apme.cm", out
    # the lease is now on the seam and verifies owner-pinned (what the offense plane will re-check keyless)
    bundle = read_credit_lease(_base_dir(), r["slug"])
    assert bundle is not None
    ok, reason = verify_credit_launch_lease(bundle.signed_lease, bundle.trust_root)
    assert ok, reason
    assert bundle.signed_lease.document.org_id == "org_a" and bundle.signed_lease.document.scope_host == "apme.cm"


def test_publish_lease_refuses_foreign_org_and_forged_lease_nothing_written():
    from sigil.ui.target_authorization import _base_dir
    from vigil_integration.live.credit_lease_broker import read_credit_lease
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"], r
    # TENANT BINDING: a different session org cannot publish org_a's lease -> refused, nothing on the seam
    out = _gate(s).publish_lease(signed_lease=r["lease"], expect_org_id="org_evil")
    assert out["ok"] is False and "different org" in out["error"], out
    assert read_credit_lease(_base_dir(), r["slug"]) is None
    # a forged/garbage lease -> refused (never reaches the seam)
    assert _gate(s).publish_lease(signed_lease={"not": "a lease"}, expect_org_id="org_a")["ok"] is False
