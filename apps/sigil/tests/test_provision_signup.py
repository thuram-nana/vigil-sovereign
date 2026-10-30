"""Slice E1 — the Provisioner (the owner-signed, policy-controlled signing service) + the principal's milestone.

MILESTONE (principal, 2026-10-30): prove an org admin can invite + manage legitimate users WITHOUT ever
gaining access to the owner signing key, another tenant's resources, or an unauthorized assessment target.

Load-bearing invariants:
  * self-serve signup mints NOTHING until a verify token proves mailbox control; THEN it owner-signs
    {customer, org, org_admin membership, trial} — role server-set (not client-chosen), org_id server-
    generated, trial a server constant granted ONLY post-verification (anti-Sybil);
  * a replayed/absent token is refused; a duplicate email is refused;
  * an org_admin manages THEIR org's team (grant/revoke) — the requester passes only username+org_id; the
    OWNER KEY lives only in the Provisioner's injected registries. A non-admin is denied; cross-org is
    denied; the grantable set excludes operator/owner (no offense-adjacent or global authority);
  * revocation is AUTHENTICATED (admit_customer-gated) — R1;
  * login is constant-time + rate-limited (lockout after repeated failure); recovery resets via a
    purpose-bound single-use token.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import PURPOSE_VERIFY, EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionRateLimited, Provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _prov():
    """A Provisioner wired with real registries/ledgers over one store + a TEST owner key. The requester in
    every management call holds NO key — only this Provisioner's injected registries do."""
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    wallet = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    tokens = EmailTokenLedger(tempfile.mkdtemp(), ttl_s=10_000.0)
    rl = LoginRateLimiter(tempfile.mkdtemp(), max_fails=3, window_s=10_000.0, base_lock_s=50.0)
    clock = itertools.count(1)
    p = Provisioner(s, customers=custs, orgs=orgs, wallet=wallet, email_tokens=tokens, rate_limiter=rl,
                    email_sender=NullEmailSender(), trial_credits=100, expose_dev_tokens=True,
                    now_fn=lambda: float(next(clock)))
    return p, s, custs, orgs, wallet


def test_signup_mints_capped_admin_and_trial_only_after_verification():
    p, s, custs, orgs, wallet = _prov()
    r = p.request_signup("alice@acme.com", ip="1.1.1.1", now=100.0)
    assert "dev_token" in r                                     # dev exposes the token (no real sender)
    assert custs.by_email("alice@acme.com") is None             # NOTHING minted at phase 1 (no trial farming)
    out = p.confirm_signup(r["dev_token"], password="customer-pw-1", org_name="Acme", now=100.0)
    u, oid = out["username"], out["org_id"]
    assert custs.by_email("alice@acme.com").username == u
    assert orgs.membership_role(u, oid) == "org_admin"          # SERVER-set role (confirm has no role param)
    assert oid.startswith("org_")                               # SERVER-generated collision-resistant org id
    assert wallet.available(oid) == 100                         # trial granted ONLY now, post-verification
    with pytest.raises(ProvisionDenied):                        # single-use: a replayed token is refused
        p.confirm_signup(r["dev_token"], password="x", org_name="Acme2", now=100.0)


def test_signup_requires_a_valid_token_and_refuses_duplicate_email():
    p, s, custs, orgs, wallet = _prov()
    with pytest.raises(ProvisionDenied):                        # no valid token ⇒ no mint (authenticated signup)
        p.confirm_signup("not-a-token", password="customer-pw-1", org_name="X", now=100.0)
    t1 = p.request_signup("bob@acme.com", ip="1.1.1.2", now=100.0)["dev_token"]
    p.confirm_signup(t1, password="customer-pw-1", org_name="B", now=100.0)
    t2 = p.request_signup("bob@acme.com", ip="1.1.1.3", now=100.0)["dev_token"]
    with pytest.raises(ProvisionDenied):                        # duplicate email refused
        p.confirm_signup(t2, password="customer-pw-2", org_name="B2", now=100.0)


def test_milestone_org_admin_manages_team_without_owner_key():
    p, s, custs, orgs, wallet = _prov()
    admin = p.confirm_signup(p.request_signup("admin@acme.com", ip="1.1.1.1", now=100.0)["dev_token"],
                             password="customer-pw-1", org_name="Acme", now=100.0)
    au, oid = admin["username"], admin["org_id"]
    mate = p.confirm_signup(p.request_signup("mate@acme.com", ip="1.1.1.2", now=100.0)["dev_token"],
                            password="customer-pw-2", org_name="MateOrg", now=100.0)
    mu, mate_org = mate["username"], mate["org_id"]

    # the admin adds the teammate to THEIR org as analyst — owner-signed by the Provisioner, requester keyless
    assert p.grant_member(au, oid, mu, "analyst", now=200.0)["role"] == "analyst"
    assert orgs.membership_role(mu, oid) == "analyst"
    # the teammate (analyst, not an admin) CANNOT manage members
    with pytest.raises(ProvisionDenied):
        p.grant_member(mu, oid, au, "viewer", now=201.0)
    # role cap: an admin can never grant operator/owner (no offense-adjacent or global authority)
    for bad in ("operator", "owner"):
        with pytest.raises(ProvisionDenied):
            p.grant_member(au, oid, mu, bad, now=202.0)
    # R1 — authenticated ordinary revocation by the admin
    p.revoke_member(au, oid, mu, now=203.0)
    assert orgs.membership_role(mu, oid) is None
    # cross-org: the admin of acme is NOT an admin of the teammate's org → denied (tenant isolation)
    with pytest.raises(ProvisionDenied):
        p.grant_member(au, mate_org, mu, "viewer", now=204.0)


def test_login_rate_limit_lockout_and_recovery():
    p, s, custs, orgs, wallet = _prov()
    p.confirm_signup(p.request_signup("carol@acme.com", ip="1.1.1.9", now=100.0)["dev_token"],
                     password="customer-pw-1", org_name="C", now=100.0)
    out = p.login("carol@acme.com", "customer-pw-1", ip="2.2.2.2", now=200.0)
    assert out["username"] and len(out["orgs"]) == 1
    for i in range(3):                                          # 3 wrong passwords → lockout
        with pytest.raises(ProvisionDenied):
            p.login("carol@acme.com", "wrong", ip="2.2.2.2", now=201.0 + i)
    with pytest.raises(ProvisionRateLimited):                   # locked even with the RIGHT password
        p.login("carol@acme.com", "customer-pw-1", ip="2.2.2.2", now=205.0)
    # recovery on a fresh ip resets the password via a purpose-bound single-use token
    rt = p.request_recover("carol@acme.com", ip="3.3.3.3", now=300.0)["dev_token"]
    p.confirm_recover(rt, new_password="customer-pw-NEW", now=300.0)
    assert p.login("carol@acme.com", "customer-pw-NEW", ip="4.4.4.4", now=400.0)["username"]


def test_recover_rejects_a_verify_purpose_token():
    p, s, custs, orgs, wallet = _prov()
    # a VERIFY token must not be usable on the recover path (purpose-bound); confirm_recover refuses it.
    vt = p.request_signup("dan@acme.com", ip="1.1.1.4", now=100.0)["dev_token"]
    with pytest.raises(ProvisionDenied):
        p.confirm_recover(vt, new_password="customer-pw-x", now=100.0)
    # and it is still usable for its real purpose afterwards (not burned)
    assert p.email_tokens.consume(vt, PURPOSE_VERIFY, now=100.0) == "dan@acme.com"
