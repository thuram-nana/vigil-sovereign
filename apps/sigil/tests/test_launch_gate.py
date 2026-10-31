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
