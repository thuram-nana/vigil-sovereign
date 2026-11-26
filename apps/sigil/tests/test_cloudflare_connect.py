"""Consumer PR-C — the sovereign CloudConnectRegistry for CLOUDFLARE grants (owner-signed, READ-ONLY, and — unlike
AWS/GCP/Azure — a provider whose proof rests on a bearer token VIGIL reads once and NEVER stores).

Invariants pinned here (the Cloudflare counterpart of test_cloud_connect.py):
  * the deterministic verdict holds ONLY when the trusted fetcher saw: the token's own name carried THIS challenge
    (name_matched True + external_id ct-match → replay refused), the token is scoped to the CLAIMED account, and it
    is READ-ONLY and SINGLE-ACCOUNT (the adapted negative control — a token that can write, or is account-global, is
    refused: VIGIL will not hold a powerful customer secret even briefly);
  * a grant is NEVER recorded without the verdict firing; the grant stores the token's PUBLIC id (role_ref) and a
    sha256 of the token — NEVER the token; cross-tenant isolation + disconnect behave exactly as AWS;
  * cloudflare is a first-class verifiable provider (challenge + verify + overview), AWS stays unchanged.
"""
from __future__ import annotations

import itertools
import json
import tempfile

import pytest

from sigil.governor import cloud_connect as cc
from sigil.governor.cloud_connect import CloudConnectRegistry
from sigil.reuse import generate_keypair, sha256_hex
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)
ACCT = "a1b2c3d4e5f6071829304a5b6c7d8e9f"           # 32 lowercase hex
OTHER_ACCT = "ffeeddccbbaa00998877665544332211"
TOKEN_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
SECRET_TOKEN = "cfTESTtoken0123456789ABCDEFghijkl-_wxyz"   # the bearer secret the registry must NEVER see or store
TOKEN_SHA = sha256_hex(SECRET_TOKEN.encode("utf-8"))
CTL = "CONTROL-ID"


def _t() -> float:
    return float(next(_c))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, key=OWNER, pub=OP):
    return CloudConnectRegistry(store, owner_key=key, trusted_pubkey=pub)


def _obs(external_id="EXT", account=ACCT, *, name_matched=True, read_only=True, single_account=True):
    return {"token_id": TOKEN_ID, "account": account, "name_matched": name_matched,
            "external_id": external_id, "read_only": read_only, "single_account": single_account}


def _verify(r, ext="EXT1", *, account=ACCT, now=10.0, ttl=None, role=TOKEN_ID, token_sha=TOKEN_SHA, **obs):
    kw = {} if ttl is None else {"ttl_seconds": ttl}
    return r.verify_and_connect("acme", "cloudflare", account, role_ref=role, observed=_obs(ext, account, **obs),
                                control_external_id=CTL, now=now, token_sha256=token_sha, **kw)


# ---- the pure verdict ----------------------------------------------------------------------------------------
def test_verdict_holds_for_a_named_read_only_single_account_token():
    assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, _obs("EXT", ACCT), control_external_id=CTL) is True
    assert cc.cloud_grant_refusal("cloudflare", "EXT", ACCT, _obs("EXT", ACCT), control_external_id=CTL) is None


def test_verdict_refuses_a_token_name_not_bound_to_this_challenge():
    assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, _obs("EXT", ACCT, name_matched=False),
                                 control_external_id=CTL) is False
    # a replayed observation from a prior challenge (its echoed external_id is OTHER) is refused
    assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, _obs("OTHER", ACCT), control_external_id=CTL) is False
    for not_true in (None, 1, "true", [True]):
        assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, _obs("EXT", ACCT, name_matched=not_true),
                                     control_external_id=CTL) is False


def test_verdict_refuses_a_wrong_account():
    why = cc.cloud_grant_refusal("cloudflare", "EXT", ACCT, _obs("EXT", OTHER_ACCT), control_external_id=CTL)
    assert why is not None and "not proven" in why


def test_verdict_refuses_a_token_that_can_write_the_over_privilege_guard():
    why = cc.cloud_grant_refusal("cloudflare", "EXT", ACCT, _obs("EXT", ACCT, read_only=False), control_external_id=CTL)
    assert why is not None and "read-only" in why
    for not_true in (None, 1, "true", [True]):
        assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, _obs("EXT", ACCT, read_only=not_true),
                                     control_external_id=CTL) is False


def test_verdict_refuses_an_account_global_token():
    why = cc.cloud_grant_refusal("cloudflare", "EXT", ACCT, _obs("EXT", ACCT, single_account=False),
                                 control_external_id=CTL)
    assert why is not None and "single account" in why
    for not_true in (None, 1, "true", [True]):
        assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, _obs("EXT", ACCT, single_account=not_true),
                                     control_external_id=CTL) is False


def test_verdict_is_total_and_fail_closed_on_bad_input():
    assert cc.cloud_grant_proves("cloudflare", "", ACCT, _obs("", ACCT), control_external_id=CTL) is False
    assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, "not-a-dict", control_external_id=CTL) is False
    assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, _obs("EXT", ACCT), control_external_id="") is False
    good = _obs("EXT", ACCT)
    for missing in ("account", "name_matched", "external_id", "read_only", "single_account"):
        obs = dict(good)
        del obs[missing]
        assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, obs, control_external_id=CTL) is False, missing
    for bad in (None, 1, [], object()):
        assert cc.cloud_grant_proves("cloudflare", "EXT", ACCT, bad, control_external_id=CTL) is False


# ---- challenge + verify + record -----------------------------------------------------------------------------
def test_challenge_then_verify_records_a_grant_with_the_token_id_and_sha_never_the_token():
    s = _store()
    r = _reg(s)
    ch = r.issue_challenge("acme", "cloudflare", ACCT, issued_at=_t(), external_id="EXT1")
    assert ch.provider == "cloudflare" and ch.account_id == ACCT
    g = _verify(r, now=100.0, ttl=1000.0)
    assert g.role_ref == TOKEN_ID and g.access == "read-only" and g.expires_at == 1100.0
    assert g.token_sha256 == TOKEN_SHA and g.external_id == "EXT1"
    cur = r.grant("acme", "cloudflare", ACCT)
    assert cur is not None and cur.role_ref == TOKEN_ID and cur.state == "active" and cur.token_sha256 == TOKEN_SHA
    assert r.has_current_grant("acme", "cloudflare", ACCT, now=500.0) is True
    # the SECRET token is nowhere in the spine (the registry never received it — only its id + sha)
    blob = json.dumps([rec.payload for rec in s.iter_records()])
    assert SECRET_TOKEN not in blob and SECRET_TOKEN not in repr(cur)


def test_an_over_privileged_or_global_token_is_refused_and_records_nothing():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "cloudflare", ACCT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="read-only"):
        _verify(r, read_only=False)
    with pytest.raises(ValueError, match="single account"):
        _verify(r, single_account=False)
    with pytest.raises(ValueError, match="does not match"):
        _verify(r, name_matched=False)
    assert r.grant("acme", "cloudflare", ACCT) is None


def test_verify_refuses_a_wrong_account_and_records_nothing():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "cloudflare", ACCT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="not proven"):
        r.verify_and_connect("acme", "cloudflare", ACCT, role_ref=TOKEN_ID, observed=_obs("EXT1", OTHER_ACCT),
                             control_external_id=CTL, now=1.0, token_sha256=TOKEN_SHA)
    assert r.grant("acme", "cloudflare", ACCT) is None


def test_account_and_token_id_formats_are_enforced():
    s = _store()
    r = _reg(s)
    with pytest.raises(ValueError, match="32 lowercase hex"):
        r.issue_challenge("acme", "cloudflare", "A1B2", issued_at=_t())
    with pytest.raises(ValueError, match="32 lowercase hex"):
        r.issue_challenge("acme", "cloudflare", "A1B2C3D4E5F6071829304A5B6C7D8E9F", issued_at=_t())  # uppercase
    r.issue_challenge("acme", "cloudflare", ACCT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="token id was not recognised"):
        _verify(r, role="not-a-token-id")
    assert r.grant("acme", "cloudflare", ACCT) is None


# ---- resume / disconnect / overview / cross-tenant -----------------------------------------------------------
def test_open_challenge_resumes_and_disconnect_retires_both():
    s = _store()
    r = _reg(s)
    ch, resumed = r.open_challenge("acme", "cloudflare", ACCT, issued_at=_t())
    assert resumed is False and len(ch.external_id) >= 32
    again, resumed = r.open_challenge("acme", "cloudflare", ACCT, issued_at=_t())
    assert resumed is True and again.external_id == ch.external_id
    _verify(r, ch.external_id, now=_t())
    r.disconnect("acme", "cloudflare", ACCT)
    assert r.grant("acme", "cloudflare", ACCT) is None and r.challenge("acme", "cloudflare", ACCT) is None


def test_cloud_overview_marks_cloudflare_connected_and_hides_the_secret():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "cloudflare", ACCT, issued_at=_t(), external_id="SECRET-EXT")
    _verify(r, "SECRET-EXT", now=100.0, ttl=1000.0)
    live = r.cloud_overview("acme", now=500.0)
    assert live == [{"provider": "cloudflare", "account_id": ACCT, "role_ref": TOKEN_ID, "verified_at": 100.0,
                     "expires_at": 1100.0, "access": "read-only", "status": "connected"}]
    blob = json.dumps(live)
    assert "SECRET-EXT" not in blob and SECRET_TOKEN not in blob and TOKEN_SHA not in blob   # neither id nor sha projected


def test_cross_tenant_isolation_and_aws_untouched():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "cloudflare", ACCT, issued_at=_t(), external_id="EXT1")
    _verify(r)
    assert r.grant("evil", "cloudflare", ACCT) is None
    assert [(g.provider, g.account_id) for g in r.grants_of_org("acme")] == [("cloudflare", ACCT)]
    # an AWS grant and a Cloudflare grant coexist for the same org, keyed independently
    aws_acct = "123456789012"
    r.issue_challenge("acme", "aws", aws_acct, issued_at=_t(), external_id="AWS-EXT")
    r.verify_and_connect("acme", "aws", aws_acct, role_ref=f"arn:aws:iam::{aws_acct}:role/R",
                         observed={"assumed_with_external_id": "AWS-EXT", "account": aws_acct,
                                   "control_external_id": CTL, "control_denied": True},
                         control_external_id=CTL, now=11.0)
    got = sorted((g.provider, g.account_id, g.token_sha256) for g in r.grants_of_org("acme"))
    assert got == [("aws", aws_acct, ""), ("cloudflare", ACCT, TOKEN_SHA)]   # AWS carries no token sha


def test_a_forged_cloudflare_grant_is_inert():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "cloudflare", ACCT, issued_at=_t(), external_id="EXT2")
    _verify(CloudConnectRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP), "EXT2", now=1.0)
    assert r.grant("acme", "cloudflare", ACCT) is None
