"""Consumer PR-C — the sovereign CloudConnectRegistry (owner-signed READ-ONLY cloud-grant records).

Invariants pinned here:
  * the deterministic verdict (``cloud_grant_proves``) is PURE + fail-closed: it holds ONLY when VIGIL assumed the
    role with THIS challenge's external_id AND the role landed in the CLAIMED account; a wrong external_id, a
    wrong account, an unwired provider, an empty secret or a malformed observation all refuse;
  * issue_challenge + verify_and_connect is the DANGEROUS direction (owner-signed, fresh); disconnect is the SAFE
    direction (honored unsigned);
  * a grant is NEVER recorded without the verdict firing (prove over the real account's data — the SELF-RED-PEN
    "connect an asset you don't own" is refused);
  * a record signed by a NON-owner is inert (refused);
  * CROSS-TENANT isolation (the SELF-RED-PEN "cross-tenant asset read"): one org can never read another's grants;
  * a captured active grant cannot resurrect a disconnected account (anti-replay high-water); a fresh owner connect
    re-activates; an owner-signed ``expires_at`` bounds every grant;
  * CONNECT != OFFENSE (the SELF-RED-PEN "connect->offense escalation"): a cloud grant is NEVER an
    EngagementAuthority and is read-only — proven in test_connect_provision.py end-to-end.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor import cloud_connect as cc
from sigil.governor.cloud_connect import CloudConnectRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)
ACCT = "123456789012"
ROLE = "arn:aws:iam::123456789012:role/VigilReadOnly"


def _t() -> float:
    return float(next(_c))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, key=OWNER, pub=OP):
    return CloudConnectRegistry(store, owner_key=key, trusted_pubkey=pub)


def _observed(external_id: str = "EXT", account: str = ACCT) -> dict:
    return {"assumed_with_external_id": external_id, "account": account}


# ---- the pure verdict ---------------------------------------------------------------------------------------
def test_verdict_holds_only_for_matching_external_id_and_account():
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, _observed("EXT", ACCT)) is True


def test_verdict_refuses_a_wrong_external_id():
    # the SELF-RED-PEN confused-deputy guard: VIGIL assumed the role with a DIFFERENT external id than this challenge
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, _observed("OTHER", ACCT)) is False


def test_verdict_refuses_a_wrong_account():
    # the SELF-RED-PEN "connect an asset you don't own": the role landed in an account the claimant does not own
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, _observed("EXT", "999999999999")) is False


def test_verdict_refuses_unwired_providers_and_bad_input():
    assert cc.cloud_grant_proves("gcp", "EXT", "proj", {"assumed_with_external_id": "EXT", "account": "proj"}) is False
    assert cc.cloud_grant_proves("azure", "EXT", "sub", {"assumed_with_external_id": "EXT", "account": "sub"}) is False
    assert cc.cloud_grant_proves("aws", "", ACCT, _observed("", ACCT)) is False          # empty secret
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, "not-a-dict") is False              # malformed observation
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, {"account": ACCT}) is False         # missing external id
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, {"assumed_with_external_id": "EXT"}) is False  # missing account
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, {"assumed_with_external_id": 1, "account": 2}) is False  # non-str


def test_verdict_is_total_never_raises():
    for bad in (None, 1, [], object(), {"assumed_with_external_id": None, "account": None}):
        assert cc.cloud_grant_proves("aws", "EXT", ACCT, bad) is False


# ---- challenge + verify + record ----------------------------------------------------------------------------
def test_challenge_then_verify_records_a_read_only_grant():
    s = _store()
    r = _reg(s)
    ch = r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    assert ch.external_id == "EXT1" and ch.provider == "aws" and ch.account_id == ACCT
    g = r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT),
                             now=100.0, ttl_seconds=1000.0)
    assert g.role_ref == ROLE and g.access == "read-only" and g.expires_at == 1100.0
    cur = r.grant("acme", "aws", ACCT)
    assert cur is not None and cur.role_ref == ROLE and cur.state == "active"
    assert r.has_current_grant("acme", "aws", ACCT, now=500.0) is True


def test_verify_requires_the_owner_signing_key():
    s = _store()
    _reg(s).issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="owner signing key"):
        CloudConnectRegistry(s, owner_key=None, trusted_pubkey=OP).verify_and_connect(
            "acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT), now=1.0)


def test_verify_refuses_without_an_outstanding_challenge():
    s = _store()
    with pytest.raises(ValueError, match="no outstanding"):
        _reg(s).verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT), now=1.0)


def test_verify_refuses_a_failing_verdict_and_records_nothing():
    # the SELF-RED-PEN "connect an asset you don't own": a wrong account => NO grant is recorded
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="not proven"):
        r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", "999999999999"), now=1.0)
    assert r.grant("acme", "aws", ACCT) is None                  # nothing recorded


def test_verify_refuses_a_superseded_external_id():
    # re-issuing a challenge supersedes the old external id (LWW); an observation against the OLD one refuses
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=1.0, external_id="OLD")
    r.issue_challenge("acme", "aws", ACCT, issued_at=2.0, external_id="NEW")
    with pytest.raises(ValueError, match="not proven"):
        r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("OLD", ACCT), now=3.0)
    g = r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("NEW", ACCT), now=3.0)
    assert g.role_ref == ROLE


def test_verify_refuses_an_unwired_provider_before_touching_the_spine():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "gcp", "proj-123", issued_at=_t(), external_id="EXT1")   # a challenge may exist
    with pytest.raises(ValueError, match="not wired yet"):
        r.verify_and_connect("acme", "gcp", "proj-123", role_ref="vigil@proj.iam", observed=_observed("EXT1", "proj-123"),
                             now=1.0)


def test_a_record_signed_by_a_non_owner_is_inert():
    s = _store()
    # an attacker-signed challenge never verifies under the owner trust root, so there is nothing to verify against
    CloudConnectRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP).issue_challenge(
        "acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    assert _reg(s).challenge("acme", "aws", ACCT) is None
    # and a forged active GRANT record is refused by the fold (we drive it through a second registry's signer)
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT2")
    CloudConnectRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP).verify_and_connect(
        "acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT2", ACCT), now=1.0)
    assert r.grant("acme", "aws", ACCT) is None                  # forged grant -> inert


def test_bad_provider_account_and_role_are_refused():
    s = _store()
    r = _reg(s)
    with pytest.raises(ValueError, match="provider must be"):
        r.issue_challenge("acme", "digitalocean", ACCT, issued_at=_t())
    with pytest.raises(ValueError, match="account_id must be"):
        r.issue_challenge("acme", "aws", "bad/acct", issued_at=_t())
    with pytest.raises(ValueError, match="account_id must be"):
        r.issue_challenge("acme", "aws", "has space", issued_at=_t())
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="role reference"):
        r.verify_and_connect("acme", "aws", ACCT, role_ref="", observed=_observed("EXT1", ACCT), now=1.0)


# ---- disconnect / anti-replay / expiry ----------------------------------------------------------------------
def test_disconnect_is_the_safe_direction_honored_even_unsigned():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT), now=10.0)
    # a keyless registry (no owner key) can still disconnect (the safe direction never fails open)
    CloudConnectRegistry(s, owner_key=None, trusted_pubkey=OP).disconnect("acme", "aws", ACCT)
    assert r.grant("acme", "aws", ACCT) is None


def test_a_captured_active_grant_cannot_resurrect_a_disconnected_account():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=5.0, external_id="EXT1")
    r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT), now=10.0)
    r.disconnect("acme", "aws", ACCT)
    # replay the SAME verify at the SAME now (=> same issued_at=verified_at) -> not fresh past the high-water -> ignored
    r.issue_challenge("acme", "aws", ACCT, issued_at=20.0, external_id="EXT1")
    r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT), now=10.0)
    assert r.grant("acme", "aws", ACCT) is None
    # a FRESH verify (higher now => higher issued_at) re-activates (intended)
    r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT), now=30.0)
    assert r.grant("acme", "aws", ACCT) is not None


def test_has_current_grant_respects_the_owner_signed_expiry():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT),
                         now=100.0, ttl_seconds=1000.0)
    assert r.has_current_grant("acme", "aws", ACCT, now=500.0) is True
    assert r.has_current_grant("acme", "aws", ACCT, now=1099.0) is True
    assert r.has_current_grant("acme", "aws", ACCT, now=1100.0) is False     # exactly at expiry -> expired
    assert r.has_current_grant("acme", "aws", ACCT, now=5000.0) is False


# ---- cross-tenant isolation (the SELF-RED-PEN "cross-tenant asset read") -------------------------------------
def test_cross_tenant_isolation():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT), now=10.0)
    assert r.grant("evil", "aws", ACCT) is None                  # another org cannot read acme's grant
    assert r.has_current_grant("evil", "aws", ACCT, now=11.0) is False
    assert r.grants_of_org("evil") == []
    assert [(g.provider, g.account_id) for g in r.grants_of_org("acme")] == [("aws", ACCT)]
    assert r.cloud_overview("evil", now=11.0) == []


def test_grants_of_org_is_ordered_and_only_active_and_drops_expired_when_timed():
    s = _store()
    r = _reg(s)
    for acct, ext in (("333333333333", "e3"), ("111111111111", "e1"), ("222222222222", "e2")):
        r.issue_challenge("acme", "aws", acct, issued_at=_t(), external_id=ext)
        r.verify_and_connect("acme", "aws", acct, role_ref=f"arn:{acct}", observed=_observed(ext, acct),
                             now=10.0, ttl_seconds=1000.0)
    r.disconnect("acme", "aws", "333333333333")
    assert [g.account_id for g in r.grants_of_org("acme")] == ["111111111111", "222222222222"]
    # time-aware: everything expired at now=5000 -> none
    assert r.grants_of_org("acme", now=5000.0) == []
    # time-aware: all live at now=500
    assert [g.account_id for g in r.grants_of_org("acme", now=500.0)] == ["111111111111", "222222222222"]


def test_cloud_overview_marks_connected_vs_expired_and_hides_the_secret():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="SECRET")
    r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("SECRET", ACCT),
                         now=100.0, ttl_seconds=1000.0)
    live = r.cloud_overview("acme", now=500.0)
    assert live == [{"provider": "aws", "account_id": ACCT, "role_ref": ROLE, "verified_at": 100.0,
                     "expires_at": 1100.0, "access": "read-only", "status": "connected"}]
    assert r.cloud_overview("acme", now=2000.0)[0]["status"] == "expired"
    # the external-id secret never appears in any projection (only its hash is stored)
    import json
    assert "SECRET" not in json.dumps(live)


def test_owner_key_succession_each_grant_verified_under_the_pubkey_at_its_seq():
    # a grant signed under OWNER verifies while OWNER is trusted; trust a DIFFERENT key and it is inert (fail-closed).
    s = _store()
    _reg(s).issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    _reg(s).verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=_observed("EXT1", ACCT), now=10.0)
    other = generate_keypair()
    assert CloudConnectRegistry(s, owner_key=None, trusted_pubkey=other.public_key_b64).grant("acme", "aws", ACCT) is None
    assert _reg(s).grant("acme", "aws", ACCT) is not None
