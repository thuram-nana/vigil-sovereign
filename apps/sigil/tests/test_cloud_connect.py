"""Consumer PR-C — the sovereign CloudConnectRegistry (owner-signed READ-ONLY cloud-grant records).

Invariants pinned here:
  * the deterministic verdict (``cloud_grant_refusal`` / ``cloud_grant_proves``) is PURE, TOTAL and fail-closed: it
    holds ONLY when VIGIL assumed the role with THIS challenge's external_id, the role landed in the CLAIMED account,
    AND the same-shape NEGATIVE CONTROL (the same role, a fresh random external id) was explicitly DENIED — a role
    that admits any external id is the confused-deputy hole (any tenant could name it) and is refused;
  * issue_challenge + verify_and_connect is the DANGEROUS direction (owner-signed, fresh); disconnect is the SAFE
    direction (honored unsigned); an UNVERIFIABLE provider (gcp/azure) is refused at the first step (no dead end);
  * a grant is NEVER recorded without the verdict firing ("connect an asset you don't own" is refused);
  * a record signed by a NON-owner is inert; CROSS-TENANT isolation holds on every read;
  * a captured active grant cannot resurrect a disconnected account; an owner-signed ``expires_at`` bounds every
    grant; the grant carries the external id it was PROVEN under, so ``assume_target`` (the one read a later gated
    posture run consumes) stays correct after a new challenge supersedes the old one — and refuses everything else;
  * a write the fold would IGNORE (a stamp at/below the key's high-water) is refused up front, never reported done;
  * RESUME: the external id is stable while its connection is outstanding (``open_challenge`` hands it back and writes
    nothing; another org never gets it); ``disconnect`` retires BOTH grant and challenge (a reconnect starts clean);
    the overview lists a started-but-unfinished connection as ``pending`` without its id;
  * the hard-prune TRIPWIRE refuses a prune that would strand an active grant's only record (real sealed segments);
  * CONNECT != OFFENSE: a cloud grant is NEVER an EngagementAuthority (proven end-to-end in test_connect_provision.py).
"""
from __future__ import annotations

import itertools
import json
import tempfile

import pytest

from sigil.governor import cloud_connect as cc
from sigil.governor.authn import signed_payload
from sigil.governor.cloud_connect import CloudConnectRegistry
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)
ACCT = "123456789012"
ROLE = "arn:aws:iam::123456789012:role/VigilReadOnly"
CTL = "CONTROL-ID"


def _t() -> float:
    return float(next(_c))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, key=OWNER, pub=OP):
    return CloudConnectRegistry(store, owner_key=key, trusted_pubkey=pub)


def _observed(external_id: str = "EXT", account: str = ACCT, *, control: str = CTL, denied=True) -> dict:
    """What the trusted fetcher reports: the real assume, the account it landed in, and the negative control."""
    return {"assumed_with_external_id": external_id, "account": account, "control_external_id": control,
            "control_denied": denied}


def _verify(r, ext="EXT1", *, account=ACCT, now=10.0, ttl=None, role=ROLE, **obs):
    kw = {} if ttl is None else {"ttl_seconds": ttl}
    return r.verify_and_connect("acme", "aws", account, role_ref=role, observed=_observed(ext, account, **obs),
                                control_external_id=CTL, now=now, **kw)


# ---- the pure verdict ---------------------------------------------------------------------------------------
def test_verdict_holds_only_for_matching_external_id_account_and_a_denied_control():
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, _observed("EXT", ACCT), control_external_id=CTL) is True
    assert cc.cloud_grant_refusal("aws", "EXT", ACCT, _observed("EXT", ACCT), control_external_id=CTL) is None


def test_verdict_refuses_a_wrong_external_id():
    # the observation must belong to THIS challenge (a replayed observation from a prior challenge is refused)
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, _observed("OTHER", ACCT), control_external_id=CTL) is False


def test_verdict_refuses_a_wrong_account():
    # "connect an asset you don't own": the role landed in an account the claimant does not own
    why = cc.cloud_grant_refusal("aws", "EXT", ACCT, _observed("EXT", "999999999999"), control_external_id=CTL)
    assert why is not None and "not proven" in why


def test_verdict_refuses_a_role_that_admits_any_external_id_the_confused_deputy():
    # the same role ALSO accepted a random external id => its trust policy does not enforce ours => any VIGIL tenant
    # could name it. Refused, with the fix named — whatever else the observation says.
    why = cc.cloud_grant_refusal("aws", "EXT", ACCT, _observed("EXT", ACCT, denied=False), control_external_id=CTL)
    assert why is not None and "sts:ExternalId" in why
    for not_exactly_true in (None, 1, "true", "yes", [True]):
        assert cc.cloud_grant_proves("aws", "EXT", ACCT, _observed("EXT", ACCT, denied=not_exactly_true),
                                     control_external_id=CTL) is False, not_exactly_true


def test_verdict_refuses_a_control_that_is_not_the_one_issued_or_is_the_real_id():
    # the control must be the provisioner's own fresh id for THIS check, and must differ from the real one (else it
    # proves nothing)
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, _observed("EXT", ACCT, control="SOMETHING-ELSE"),
                                 control_external_id=CTL) is False
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, _observed("EXT", ACCT, control="EXT"),
                                 control_external_id="EXT") is False
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, _observed("EXT", ACCT), control_external_id="") is False


def test_verdict_refuses_unverifiable_providers_and_bad_input():
    good = _observed("EXT", ACCT)
    assert cc.cloud_grant_proves("gcp", "EXT", ACCT, good, control_external_id=CTL) is False
    assert cc.cloud_grant_proves("azure", "EXT", ACCT, good, control_external_id=CTL) is False
    assert cc.cloud_grant_proves("aws", "", ACCT, _observed("", ACCT), control_external_id=CTL) is False
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, "not-a-dict", control_external_id=CTL) is False
    for missing in ("assumed_with_external_id", "account", "control_external_id", "control_denied"):
        obs = dict(good)
        del obs[missing]
        assert cc.cloud_grant_proves("aws", "EXT", ACCT, obs, control_external_id=CTL) is False, missing
    assert cc.cloud_grant_proves("aws", "EXT", ACCT, {**good, "assumed_with_external_id": 1, "account": 2},
                                 control_external_id=CTL) is False


def test_verdict_is_total_never_raises():
    for bad in (None, 1, [], object(), {"assumed_with_external_id": None, "account": None}):
        assert cc.cloud_grant_proves("aws", "EXT", ACCT, bad, control_external_id=CTL) is False
    assert cc.cloud_grant_proves(None, None, None, None, control_external_id=None) is False


# ---- challenge + verify + record ----------------------------------------------------------------------------
def test_challenge_then_verify_records_a_read_only_grant_carrying_its_external_id():
    s = _store()
    r = _reg(s)
    ch = r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    assert ch.external_id == "EXT1" and ch.provider == "aws" and ch.account_id == ACCT
    g = _verify(r, now=100.0, ttl=1000.0)
    assert g.role_ref == ROLE and g.access == "read-only" and g.expires_at == 1100.0 and g.external_id == "EXT1"
    cur = r.grant("acme", "aws", ACCT)
    assert cur is not None and cur.role_ref == ROLE and cur.state == "active" and cur.external_id == "EXT1"
    assert "EXT1" not in repr(cur)                               # never rendered in a repr / log line
    assert cur.external_id_sha256 and cur.external_id_sha256 != "EXT1"
    assert r.has_current_grant("acme", "aws", ACCT, now=500.0) is True


def test_the_confused_deputy_role_is_refused_and_records_nothing():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="sts:ExternalId"):
        _verify(r, denied=False)
    assert r.grant("acme", "aws", ACCT) is None


def test_verify_requires_the_owner_signing_key():
    s = _store()
    _reg(s).issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="owner signing key"):
        _verify(CloudConnectRegistry(s, owner_key=None, trusted_pubkey=OP), now=1.0)


def test_verify_refuses_without_an_outstanding_challenge():
    s = _store()
    with pytest.raises(ValueError, match="no outstanding"):
        _verify(_reg(s), now=1.0)


def test_verify_refuses_a_failing_verdict_and_records_nothing():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    obs = _observed("EXT1", "999999999999")
    with pytest.raises(ValueError, match="not proven"):
        r.verify_and_connect("acme", "aws", ACCT, role_ref=ROLE, observed=obs, control_external_id=CTL, now=1.0)
    assert r.grant("acme", "aws", ACCT) is None                  # nothing recorded


def test_verify_refuses_a_superseded_external_id():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=1.0, external_id="OLD")
    r.issue_challenge("acme", "aws", ACCT, issued_at=2.0, external_id="NEW")
    with pytest.raises(ValueError, match="not completed"):
        _verify(r, "OLD", now=3.0)
    assert _verify(r, "NEW", now=3.0).role_ref == ROLE


def test_an_unverifiable_provider_is_refused_at_the_first_step_and_writes_nothing():
    s = _store()
    r = _reg(s)
    before = s.next_seq
    for prov, acct in (("gcp", "proj-123"), ("azure", "sub-1")):
        with pytest.raises(ValueError, match="only AWS"):
            r.issue_challenge("acme", prov, acct, issued_at=_t(), external_id="EXT1")
        with pytest.raises(ValueError, match="only AWS"):
            r.verify_and_connect("acme", prov, acct, role_ref="vigil@proj.iam", observed=_observed("EXT1", acct),
                                 control_external_id=CTL, now=1.0)
    assert s.next_seq == before                                  # no dead-end challenge, no record of any kind


def test_a_record_signed_by_a_non_owner_is_inert():
    s = _store()
    CloudConnectRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP).issue_challenge(
        "acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    assert _reg(s).challenge("acme", "aws", ACCT) is None
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT2")
    _verify(CloudConnectRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP), "EXT2", now=1.0)
    assert r.grant("acme", "aws", ACCT) is None                  # forged grant -> inert


def test_bad_provider_account_and_role_are_refused():
    s = _store()
    r = _reg(s)
    with pytest.raises(ValueError, match="provider must be"):
        r.issue_challenge("acme", "digitalocean", ACCT, issued_at=_t())
    for bad in ("bad/acct", "has space"):
        with pytest.raises(ValueError, match="account_id must be"):
            r.issue_challenge("acme", "aws", bad, issued_at=_t())
    with pytest.raises(ValueError, match="exactly 12 digits"):
        r.issue_challenge("acme", "aws", "12345", issued_at=_t())
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="role reference"):
        _verify(r, role="")
    with pytest.raises(ValueError, match="full ARN"):
        _verify(r, role="VigilReadOnly")
    with pytest.raises(ValueError, match="different AWS account"):
        _verify(r, role="arn:aws:iam::999999999999:role/VigilReadOnly")
    assert r.grant("acme", "aws", ACCT) is None


# ---- disconnect / anti-replay / expiry ----------------------------------------------------------------------
def test_disconnect_is_the_safe_direction_honored_even_unsigned():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    _verify(r)
    CloudConnectRegistry(s, owner_key=None, trusted_pubkey=OP).disconnect("acme", "aws", ACCT)
    assert r.grant("acme", "aws", ACCT) is None
    assert r.challenge("acme", "aws", ACCT) is None              # the challenge is retired too, even unsigned


def test_a_captured_active_grant_cannot_resurrect_a_disconnected_account():
    # the REAL replay: someone holding a copy of the owner-signed ACTIVE grant record re-appends it verbatim after the
    # customer disconnected. Its issued_at sits at the key's high-water, so the fold ignores it.
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=5.0, external_id="EXT1")
    _verify(r, now=10.0)
    captured = [rec.payload for rec in s.iter_records() if rec.payload.get("signal") == cc.GRANT_SIGNAL][-1]
    r.disconnect("acme", "aws", ACCT)
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(captured))
    assert r.grant("acme", "aws", ACCT) is None and r.assume_target("acme", "aws", ACCT, now=11.0) is None
    r.issue_challenge("acme", "aws", ACCT, issued_at=20.0, external_id="EXT2")
    _verify(r, "EXT2", now=30.0)                                 # a FRESH connect re-activates (intended)
    assert r.grant("acme", "aws", ACCT).external_id == "EXT2"


def test_a_write_the_fold_would_ignore_is_refused_not_reported_as_done():
    # a stamp at/below the key's high-water (e.g. the clock stepped back after a disconnect) would be silently IGNORED
    # by the fold — so the registry refuses it up front, and no caller is ever told "issued" / "connected" for nothing
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=5.0, external_id="EXT1")
    _verify(r, now=10.0)
    r.disconnect("acme", "aws", ACCT)
    before = s.next_seq
    with pytest.raises(ValueError, match="newer connection request"):
        r.issue_challenge("acme", "aws", ACCT, issued_at=5.0, external_id="EXT2")   # not above the challenge high-water
    assert s.next_seq == before and r.challenge("acme", "aws", ACCT) is None
    r.issue_challenge("acme", "aws", ACCT, issued_at=6.0, external_id="EXT2")
    before = s.next_seq
    with pytest.raises(ValueError, match="could not be recorded"):
        _verify(r, "EXT2", now=10.0)                                                  # not above the grant high-water
    assert s.next_seq == before and r.grant("acme", "aws", ACCT) is None
    assert _verify(r, "EXT2", now=11.0).external_id == "EXT2"                       # a fresh stamp is honored


# ---- resume: the external id is stable while its connection is outstanding --------------------------------------
def test_open_challenge_resumes_the_outstanding_id_and_writes_nothing():
    s = _store()
    r = _reg(s)
    ch, resumed = r.open_challenge("acme", "aws", ACCT, issued_at=_t())
    assert resumed is False and len(ch.external_id) >= 32
    before = s.next_seq
    again, resumed = r.open_challenge("acme", "aws", ACCT, issued_at=_t())
    assert resumed is True and again.external_id == ch.external_id and s.next_seq == before   # same id, no record
    other, _ = r.open_challenge("evil", "aws", ACCT, issued_at=_t())
    assert other.external_id != ch.external_id                   # another org NEVER gets this org's id
    _verify(r, ch.external_id, now=_t())
    # connected: still the same id, so re-verifying an expiring grant needs no trust-policy edit
    assert r.open_challenge("acme", "aws", ACCT, issued_at=_t()) == (ch, True)
    r.disconnect("acme", "aws", ACCT)
    fresh, resumed = r.open_challenge("acme", "aws", ACCT, issued_at=_t())
    assert resumed is False and fresh.external_id != ch.external_id          # a reconnect starts clean
    with pytest.raises(ValueError, match="only AWS"):
        r.open_challenge("acme", "gcp", "proj-1", issued_at=_t())


def test_has_current_grant_respects_the_owner_signed_expiry():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    _verify(r, now=100.0, ttl=1000.0)
    assert r.has_current_grant("acme", "aws", ACCT, now=500.0) is True
    assert r.has_current_grant("acme", "aws", ACCT, now=1099.0) is True
    assert r.has_current_grant("acme", "aws", ACCT, now=1100.0) is False     # exactly at expiry -> expired
    assert r.has_current_grant("acme", "aws", ACCT, now=5000.0) is False


# ---- the consumer read a later gated posture run uses ---------------------------------------------------------
def test_assume_target_is_default_deny_and_survives_a_superseding_challenge():
    s = _store()
    r = _reg(s)
    assert r.assume_target("acme", "aws", ACCT, now=1.0) is None                 # nothing connected
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="PROVEN")
    _verify(r, "PROVEN", now=100.0, ttl=1000.0)
    t = r.assume_target("acme", "aws", ACCT, now=500.0)
    assert (t.role_ref, t.external_id, t.expires_at) == (ROLE, "PROVEN", 1100.0) and "PROVEN" not in repr(t)
    # a NEW challenge (the customer clicked Connect again) must not break the connected grant: the run still gets the
    # id the role was PROVEN to require, never the unproven new one
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="UNPROVEN")
    assert r.assume_target("acme", "aws", ACCT, now=500.0).external_id == "PROVEN"
    assert r.assume_target("evil", "aws", ACCT, now=500.0) is None               # another org: nothing
    assert r.assume_target("acme", "aws", ACCT, now=1100.0) is None              # expired: nothing
    r.disconnect("acme", "aws", ACCT)
    assert r.assume_target("acme", "aws", ACCT, now=500.0) is None               # disconnected: nothing


def test_the_trust_policy_trusts_only_the_principal_and_only_under_the_external_id():
    doc = json.loads(cc.aws_trust_policy("arn:aws:iam::111122223333:role/vigil-connector", "EXT-1"))
    (st,) = doc["Statement"]
    assert st == {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:role/vigil-connector"},
                  "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:ExternalId": "EXT-1"}}}
    assert cc.aws_trust_policy("p", "e") == cc.aws_trust_policy("p", "e")       # deterministic text


# ---- cross-tenant isolation ----------------------------------------------------------------------------------
def test_cross_tenant_isolation():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    _verify(r)
    assert r.grant("evil", "aws", ACCT) is None
    assert r.has_current_grant("evil", "aws", ACCT, now=11.0) is False
    assert r.grants_of_org("evil") == []
    assert [(g.provider, g.account_id) for g in r.grants_of_org("acme")] == [("aws", ACCT)]
    assert r.cloud_overview("evil", now=11.0) == []


def test_grants_of_org_is_ordered_and_only_active_and_drops_expired_when_timed():
    s = _store()
    r = _reg(s)
    for acct, ext in (("333333333333", "e3"), ("111111111111", "e1"), ("222222222222", "e2")):
        r.issue_challenge("acme", "aws", acct, issued_at=_t(), external_id=ext)
        _verify(r, ext, account=acct, role=f"arn:aws:iam::{acct}:role/R", ttl=1000.0)
    r.disconnect("acme", "aws", "333333333333")
    assert [g.account_id for g in r.grants_of_org("acme")] == ["111111111111", "222222222222"]
    assert r.grants_of_org("acme", now=5000.0) == []
    assert [g.account_id for g in r.grants_of_org("acme", now=500.0)] == ["111111111111", "222222222222"]


def test_cloud_overview_marks_connected_vs_expired_and_hides_the_secret():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="SECRET")
    _verify(r, "SECRET", now=100.0, ttl=1000.0)
    live = r.cloud_overview("acme", now=500.0)
    assert live == [{"provider": "aws", "account_id": ACCT, "role_ref": ROLE, "verified_at": 100.0,
                     "expires_at": 1100.0, "access": "read-only", "status": "connected"}]
    assert r.cloud_overview("acme", now=2000.0)[0]["status"] == "expired"
    assert "SECRET" not in json.dumps(live)                      # the external id is never projected


def test_cloud_overview_lists_a_started_connection_as_pending_without_its_id():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="SECRET-PENDING")
    out = r.cloud_overview("acme", now=1.0)
    assert out == [{"provider": "aws", "account_id": ACCT, "access": "read-only", "status": "pending"}]
    assert "SECRET-PENDING" not in json.dumps(out)
    assert r.cloud_overview("evil", now=1.0) == []                                   # another tenant: nothing
    _verify(r, "SECRET-PENDING", now=100.0, ttl=1000.0)
    assert [c["status"] for c in r.cloud_overview("acme", now=500.0)] == ["connected"]   # finished, not pending
    r.disconnect("acme", "aws", ACCT)
    assert r.cloud_overview("acme", now=500.0) == []             # disconnected: neither connected nor pending


def test_owner_key_succession_each_grant_verified_under_the_pubkey_at_its_seq():
    s = _store()
    _reg(s).issue_challenge("acme", "aws", ACCT, issued_at=_t(), external_id="EXT1")
    _verify(_reg(s))
    other = generate_keypair()
    assert CloudConnectRegistry(s, owner_key=None, trusted_pubkey=other.public_key_b64).grant("acme", "aws", ACCT) is None
    assert _reg(s).grant("acme", "aws", ACCT) is not None


# ---- hard-prune durability (real sealed segments; mirrors the connected-repo / Red-Pen schedule tripwires) -----
@pytest.fixture
def owner_is_test_key(monkeypatch):
    """Point ``identity.owner_pubkey`` at this file's test owner for the prune tripwires — and, at teardown, re-bind the
    REAL function in every module that imported the fake BY NAME while the patch was live. ``check_prune_safe`` is the
    first importer of many governor modules (orgs, customers, wallet, monitoring_authority, …), each of which binds
    ``from .identity import owner_pubkey`` at import time; without this the fake key would outlive the test and every
    later owner-signature check in the same process (a membership, an ownership proof) would silently fail."""
    import sys

    from sigil.governor import identity
    real = identity.owner_pubkey

    def fake():
        return OP
    monkeypatch.setattr(identity, "owner_pubkey", fake)
    yield
    for mod in list(sys.modules.values()):
        if getattr(mod, "owner_pubkey", None) is fake:
            mod.owner_pubkey = real


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def _segmented(tmp_path, *, disconnect=False):
    """The challenge (seq 0) + grant (seq 1) [+ disconnect, seq 2] in the FIRST sealed segment, then a second sealed
    segment and a live tail — so a prune to K=5 archives the grant's deciding record."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=2.0, external_id="EXT1")   # seq 0
    _verify(r, now=3.0)                                                          # seq 1
    if disconnect:
        r.disconnect("acme", "aws", ACCT)                                       # seq 2 (tombstone)
    while s.next_seq < 5:
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})
    s.rotate()                                                                   # seal [0..4]
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})    # seq 5..9
    s.rotate()                                                                   # seal [5..9]
    return s


def test_the_prune_tripwire_refuses_stranding_an_active_grant(tmp_path, owner_is_test_key):
    s = _segmented(tmp_path)
    assert prune.stranded_active_cloud_grants(s, _archived_below(s, 5), 5) == [f"aws:{ACCT}@acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert f"aws:{ACCT}@acme" in str(e.value) and "cloud grant" in str(e.value)


def test_the_prune_tripwire_test_leaves_no_fake_owner_key_behind():
    # runs right after the tripwire test above (file order, one process — as CI runs it): the fixture's teardown must
    # have re-bound the REAL owner_pubkey in every module that imported the fake while it was live
    import sys
    leaked = sorted(name for name, mod in list(sys.modules.items())
                    if "owner_is_test_key" in getattr(getattr(mod, "owner_pubkey", None), "__qualname__", ""))
    assert leaked == []


def test_the_prune_tripwire_allows_a_grant_reconnected_live(tmp_path, owner_is_test_key):
    s = _segmented(tmp_path)
    r = _reg(s)
    r.issue_challenge("acme", "aws", ACCT, issued_at=90.0, external_id="EXT9")  # reconnected LIVE (seq >= 5)
    _verify(r, "EXT9", now=99.0)
    assert prune.stranded_active_cloud_grants(s, _archived_below(s, 5), 5) == []


def test_a_below_k_grant_blocks_the_prune_even_after_it_was_disconnected(tmp_path, owner_is_test_key):
    # grant + disconnect BOTH below K would reset the high-water, so a CAPTURED copy of the grant could be replayed above
    # K to RESURRECT a disconnected account — the tripwire is fail-closed and blocks it.
    s = _segmented(tmp_path, disconnect=True)
    assert prune.stranded_active_cloud_grants(s, _archived_below(s, 5), 5) == [f"aws:{ACCT}@acme"]


def test_a_forged_below_k_grant_never_blocks_a_prune(tmp_path, owner_is_test_key):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    forged = signed_payload({"signal": cc.GRANT_SIGNAL, "org_id": "acme", "provider": "aws", "account_id": ACCT,
                             "role_ref": ROLE, "external_id": "X", "verified_at": 3.0, "expires_at": 9e9,
                             "state": "active", "issued_at": 3.0}, ATTACKER)
    s.append(kind="event", source="governor", actor="WARDEN", payload=forged)
    while s.next_seq < 5:
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})
    s.rotate()
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})
    s.rotate()
    assert prune.stranded_active_cloud_grants(s, _archived_below(s, 5), 5) == []


# ---- backward-compat: token_sha256 JOINED the grant core AFTER grants were persisted (red-pen wyi72aiax) --------
# A grant written before token_sha256 existed carries NO such key and was owner-signed over the narrower 10-field
# core. The fold (and the prune high-water, which re-verifies the same core on ANY hard prune) must still accept it —
# else a genesis re-verify silently disconnects every pre-existing AWS account and the prune stops protecting it.
# Tampering with the field must still fail closed.
_BIG = 9e9


def _legacy_grant_payload(signer=OWNER, *, ext="EXT1", acct=ACCT, role=ROLE, v=3.0):
    """A grant EXACTLY as base code (pre-token_sha256) persisted it: the 10-field core, NO token_sha256 key."""
    return signed_payload({"signal": cc.GRANT_SIGNAL, "org_id": "acme", "provider": "aws", "account_id": acct,
                           "role_ref": role, "external_id": ext, "verified_at": v, "expires_at": v + _BIG,
                           "state": "active", "issued_at": v}, signer)


def _current_grant_payload(signer=OWNER, *, ext="EXT1", acct=ACCT, role=ROLE, v=3.0, token_sha256=""):
    """A grant as the current code signs it: the 11-field core WITH token_sha256 ('' for AWS, a sha for Cloudflare)."""
    return signed_payload({"signal": cc.GRANT_SIGNAL, "org_id": "acme", "provider": "aws", "account_id": acct,
                           "role_ref": role, "external_id": ext, "token_sha256": token_sha256, "verified_at": v,
                           "expires_at": v + _BIG, "state": "active", "issued_at": v}, signer)


def test_verify_cloud_active_accepts_a_legacy_grant_and_rejects_tampering():
    legacy = _legacy_grant_payload()
    assert cc._verify_cloud_active(legacy, cc._GRANT_CORE, OP) is True           # pre-token_sha256 grant still authentic
    assert cc._verify_cloud_active(_current_grant_payload(), cc._GRANT_CORE, OP) is True              # new AWS ("")
    assert cc._verify_cloud_active(_current_grant_payload(token_sha256="ab" * 32), cc._GRANT_CORE, OP) is True  # CF sha
    # ADD the field to a legacy grant -> validated under the 11-field core -> the owner signature no longer matches
    assert cc._verify_cloud_active({**legacy, "token_sha256": "deadbeef"}, cc._GRANT_CORE, OP) is False
    # STRIP the field from a current grant -> compat path tries the 10-field core -> signature no longer matches
    cur = _current_grant_payload(token_sha256="ab" * 32)
    assert cc._verify_cloud_active({k: v for k, v in cur.items() if k != "token_sha256"}, cc._GRANT_CORE, OP) is False
    # a NON-owner legacy grant is inert on either path (the compat path never weakens the signature requirement)
    assert cc._verify_cloud_active(_legacy_grant_payload(ATTACKER), cc._GRANT_CORE, OP) is False
    # the challenge core carries no token_sha256 -> the compat path is never taken for it
    assert cc._verify_cloud_active(legacy, cc._CHALLENGE_CORE, OP) is False


def test_a_legacy_grant_without_token_sha256_still_reads_active(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    s.append(kind="event", source="governor", actor="WARDEN", payload=_legacy_grant_payload(v=3.0))
    r = _reg(s)
    g = r.grant("acme", "aws", ACCT)
    assert g is not None and g.role_ref == ROLE and g.external_id == "EXT1" and g.token_sha256 == ""
    assert r.has_current_grant("acme", "aws", ACCT, now=100.0) is True
    tgt = r.assume_target("acme", "aws", ACCT, now=100.0)
    assert tgt is not None and tgt.role_ref == ROLE and tgt.external_id == "EXT1"


def test_a_token_sha256_added_to_a_legacy_record_post_sign_is_dropped_on_read(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**_legacy_grant_payload(), "token_sha256": "deadbeef"})     # field added after signing -> forged
    assert _reg(s).grant("acme", "aws", ACCT) is None


def _segmented_legacy(tmp_path):
    """Like _segmented, but the deciding grant (seq 0) is a LEGACY (pre-token_sha256) owner-signed record."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    s.append(kind="event", source="governor", actor="WARDEN", payload=_legacy_grant_payload(v=3.0))   # seq 0
    while s.next_seq < 5:
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})
    s.rotate()                                                                    # seal [0..4]
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})      # seq 5..9
    s.rotate()                                                                     # seal [5..9]
    return s


def test_the_prune_tripwire_still_protects_a_legacy_grant(tmp_path, owner_is_test_key):
    # the red-pen's exact failure mode: a pre-token_sha256 grant must still contribute the prune high-water, else a
    # hard prune to K silently deletes its only authoritative copy. With the compat path it is seen and the prune refused.
    s = _segmented_legacy(tmp_path)
    assert prune.stranded_active_cloud_grants(s, _archived_below(s, 5), 5) == [f"aws:{ACCT}@acme"]
    with pytest.raises(prune.PruneUnsafe):
        prune.check_prune_safe(s, 5)
