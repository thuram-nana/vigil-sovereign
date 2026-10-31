"""Slice G0 — the CUSTOMER target-authority mint gate (billing != testing, the tested end-to-end invariant).

add_customer_target owner-signs a LIVE, non-destructive EngagementAuthority for a customer's own asset ONLY
when a current, infrastructure-bound ownership proof exists for (org_id, host). Load-bearing invariants:
  * THE LINCHPIN: no current ownership proof -> NO authority (fail-closed), however paid/privileged the org;
  * a proof for org A authorizes NOTHING for org B (per-(org_id, host) tenant isolation);
  * an EXPIRED proof does not authorize (time-aware gate);
  * the minted authority is owner-signed + verifiable, scope == EXACTLY the proven host, environment=live,
    allow_destructive=False (hardcoded — a customer path never authorizes a write), issued_by baked with
    the tenant;
  * the customer slug is tenant-namespaced and can never collide with an operator host-derived slug.

Runs with the integration PYTHONPATH (the authority broker lives in vigil_integration).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared authority seam
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())     # isolate the owner vault/spine
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _prove(store, org, host, *, now, ttl=1e9):
    """Seed a current ownership proof for (org, host) via the real challenge+verdict path (vault owner key)."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=ttl)


# --- the linchpin: proof required -------------------------------------------------------------------

def test_no_proof_refuses_the_mint():
    """A customer org with NO ownership proof gets no authority — billing/membership is not test authority."""
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import target_authorization as ta
    ensure_owner_keypair()
    s = _store()
    r = ta.add_customer_target("apme.cm", org_id="acme", store=s, now=1000.0)
    assert r["ok"] is False and "ownership proof" in r["error"]


def test_proof_then_mint_owner_signed_and_verifiable():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import target_authorization as ta
    from vigil_core import verify_engagement_authority
    from vigil_integration.live.authorization_broker import read_authorization
    import os

    kp = ensure_owner_keypair()
    s = _store()
    _prove(s, "acme", "apme.cm", now=1000.0)
    r = ta.add_customer_target("apme.cm", org_id="acme", store=s, now=2000.0, note="my prod site")
    assert r["ok"] and r["org_id"] == "acme" and r["scope"] == ["apme.cm"] and r["environment"] == "live"
    assert r["allow_destructive"] is False and r["slug"].startswith("cust_")

    got = read_authorization(os.environ["VIGIL_BASE_DIR"], r["slug"])
    assert got is not None
    ok, reason = verify_engagement_authority(got.signed_authority, got.trust_root)
    assert ok, reason
    doc = got.signed_authority.document
    assert {a.public_key_b64 for a in got.trust_root.authorizers} == {kp.public_key_b64}
    assert doc.scope == ["apme.cm"] and doc.environment.value == "live"
    assert doc.allow_destructive is False and doc.live_destructive_acknowledged is False
    assert doc.issued_by == "customer:acme"                       # tenant baked into the owner-signed bytes


# --- tenant isolation -------------------------------------------------------------------------------

def test_proof_for_one_org_does_not_authorize_another():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import target_authorization as ta
    ensure_owner_keypair()
    s = _store()
    _prove(s, "acme", "apme.cm", now=1000.0)                      # only acme proved apme.cm
    assert ta.add_customer_target("apme.cm", org_id="acme", store=s, now=2000.0)["ok"] is True
    other = ta.add_customer_target("apme.cm", org_id="evilcorp", store=s, now=2000.0)
    assert other["ok"] is False and "ownership proof" in other["error"]


def test_customer_slug_cannot_collide_with_operator_slug():
    """cust_<hash> (underscore) can never equal an operator host-derived slug (apme.cm -> apme-cm)."""
    from sigil.ui import target_authorization as ta
    cust = ta._customer_slug("acme", "apme.cm")
    op = ta._slug_for("apme.cm", None)
    assert cust.startswith("cust_") and "_" in cust
    assert cust != op and op == "apme-cm"
    # distinct per org and per host
    assert ta._customer_slug("acme", "apme.cm") != ta._customer_slug("other", "apme.cm")
    assert ta._customer_slug("acme", "apme.cm") != ta._customer_slug("acme", "other.cm")


# --- expiry + windows -------------------------------------------------------------------------------

def test_expired_proof_refuses_the_mint():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import target_authorization as ta
    ensure_owner_keypair()
    s = _store()
    _prove(s, "acme", "apme.cm", now=1000.0, ttl=50.0)            # expires at 1050
    r = ta.add_customer_target("apme.cm", org_id="acme", store=s, now=5000.0)   # well past expiry
    assert r["ok"] is False and "ownership proof" in r["error"]


def test_duration_capped():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import target_authorization as ta
    ensure_owner_keypair()
    s = _store()
    _prove(s, "acme", "apme.cm", now=1000.0)
    assert ta.add_customer_target("apme.cm", org_id="acme", store=s, now=2000.0,
                                  duration_hours=10_000_000)["ok"] is False
    assert ta.add_customer_target("apme.cm", org_id="acme", store=s, now=2000.0,
                                  duration_hours=0)["ok"] is False


# --- fail-closed host/org floor ---------------------------------------------------------------------

def test_store_required():
    from sigil.ui import target_authorization as ta
    assert ta.add_customer_target("apme.cm", org_id="acme", store=None, now=1.0)["ok"] is False


def test_bad_org_refused():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import target_authorization as ta
    ensure_owner_keypair()
    s = _store()
    assert ta.add_customer_target("apme.cm", org_id="../escape", store=s, now=1.0)["ok"] is False


@pytest.mark.parametrize("bad", ["whitehouse.gov", "https://apme.cm", "apme.cm:8080"])
def test_bad_host_refused(bad):
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import target_authorization as ta
    ensure_owner_keypair()
    s = _store()
    assert ta.add_customer_target(bad, org_id="acme", store=s, now=1.0)["ok"] is False
