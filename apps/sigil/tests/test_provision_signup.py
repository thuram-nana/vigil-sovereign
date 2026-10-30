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


def test_build_provisioner_production_wiring(tmp_path, monkeypatch):
    # the production factory wires the REAL owner-signed registries (persisted owner key — this process is
    # the only key holder), the ledgers rooted under SIGIL_HOME, and the OFF-by-default NullEmailSender; a
    # full signup owner-signs end-to-end through it (email off ⇒ the dev token is surfaced for the test).
    from sigil import config
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui.provision import build_provisioner
    # Isolate the filesystem ledgers the factory roots under `config` (the token + rate-limit/cap/member
    # dirs) into a per-test tmp dir, so repeated runs can never accumulate lockout markers under a shared
    # SIGIL_HOME (the test is deterministic and pollutes nothing — build_provisioner reads these at call time).
    for attr in ("EMAIL_TOKENS_DIR", "LOGIN_RATELIMIT_DIR", "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    ensure_owner_keypair()                           # persist an owner identity under the per-test SIGIL_HOME
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    p = build_provisioner(s, expose_dev_tokens=True)
    out = p.confirm_signup(p.request_signup("prod@acme.com", ip="9.9.9.9", now=100.0)["dev_token"],
                           password="customer-pw-1", org_name="Prod", now=100.0)
    assert CustomerRegistry(s).by_email("prod@acme.com").username == out["username"]  # owner-signed + verified
    assert out["org_id"].startswith("org_")
    # the factory wires BOTH anti-farming ceilings (a non-None signup cap + a non-None member limiter)
    assert p.signup_cap_limiter is not None and p.member_limiter is not None


# ---------------------------------------------------------------------------------------------------
# Second security review (2026-10-30) — the 8 findings, each with a concrete test. The HARD distinction
# is kept throughout: authentication / billing-authz / org membership / permission-to-TEST are separate.
# ---------------------------------------------------------------------------------------------------

def _cap_prov(*, signup_cap=None, member_cap=None):
    """A Provisioner like `_prov()` but with injectable low-ceiling cap/member limiters (anti-farming +
    member-management rate-limit tests). Each limiter is its own temp dir (disjoint from the login limiter)."""
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    wallet = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    tokens = EmailTokenLedger(tempfile.mkdtemp(), ttl_s=10_000.0)
    rl = LoginRateLimiter(tempfile.mkdtemp(), max_fails=100, window_s=10_000.0, base_lock_s=50.0)
    cap = (LoginRateLimiter(tempfile.mkdtemp(), max_fails=signup_cap, window_s=10_000.0, base_lock_s=10_000.0)
           if signup_cap is not None else None)
    mem = (LoginRateLimiter(tempfile.mkdtemp(), max_fails=member_cap, window_s=10_000.0, base_lock_s=10_000.0)
           if member_cap is not None else None)
    clock = itertools.count(1)
    p = Provisioner(s, customers=custs, orgs=orgs, wallet=wallet, email_tokens=tokens, rate_limiter=rl,
                    signup_cap_limiter=cap, member_limiter=mem, email_sender=NullEmailSender(),
                    trial_credits=100, expose_dev_tokens=True, now_fn=lambda: float(next(clock)))
    return p, s, custs, orgs, wallet


def test_signup_idempotent_recovery_on_crash_before_commit_marker():
    # FINDING A — durable, idempotent recovery. Simulate a crash AT the commit marker (the token-consume):
    # the owner-signed mutations are appended but the token is NOT consumed, so it stays valid. A retry with
    # the SAME token must COMPLETE the signup idempotently — one account, one org, and EXACTLY ONE trial
    # grant (never doubled) — then consume the token so a third attempt is refused.
    p, s, custs, orgs, wallet = _prov()
    tok = p.request_signup("ida@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
    real_consume = p.email_tokens.consume

    def boom(token, purpose, *, now=None):               # crash exactly at the commit marker
        raise RuntimeError("simulated crash at commit marker")
    p.email_tokens.consume = boom
    with pytest.raises(RuntimeError):
        p.confirm_signup(tok, password="customer-pw-1", org_name="Ida", now=100.0)
    acct = custs.by_email("ida@acme.com")
    assert acct is not None                              # the mutations committed BEFORE the (failed) marker

    p.email_tokens.consume = real_consume                # store recovered; the SAME token completes the signup
    out = p.confirm_signup(tok, password="customer-pw-1", org_name="Ida", now=100.0)
    assert out["username"] == acct.username              # SAME account (deterministic id) — never a second
    assert wallet.available(out["org_id"]) == 100        # trial granted EXACTLY once (entry_id idempotent)
    assert orgs.membership_role(out["username"], out["org_id"]) == "org_admin"
    with pytest.raises(ProvisionDenied):                 # token consumed on the successful retry → replay refused
        p.confirm_signup(tok, password="customer-pw-1", org_name="Ida", now=100.0)


def test_critical_audit_failure_fails_closed_but_login_telemetry_is_swallowed():
    # FINDING B — a SECURITY-CRITICAL mutation's audit is NOT swallowed: if the audit append fails the
    # operation FAILS CLOSED (and, because the token is not yet consumed, is safely retryable). A NON-critical
    # login-telemetry audit follows a separate availability policy and is swallowed (login still answers).
    p, s, custs, orgs, wallet = _prov()
    tok = p.request_signup("ben@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
    real_append = s.append

    def selective(**kw):                                 # fail ONLY the audit append; let mutations through
        payload = kw.get("payload")
        if isinstance(payload, dict) and payload.get("signal") == "provision.audit":
            raise RuntimeError("simulated audit-store failure")
        return real_append(**kw)
    s.append = selective
    with pytest.raises(RuntimeError):                    # critical signup audit → fail-closed
        p.confirm_signup(tok, password="customer-pw-1", org_name="Ben", now=100.0)
    s.append = real_append

    # the signup is recoverable (token never consumed): once the audit store is healthy the retry commits
    out = p.confirm_signup(tok, password="customer-pw-1", org_name="Ben", now=100.0)
    assert custs.by_email("ben@acme.com").username == out["username"]

    # a NON-critical login audit is swallowed: a bad login still raises the normal ProvisionDenied, not the
    # store's RuntimeError, even while the audit store is down.
    s.append = selective
    with pytest.raises(ProvisionDenied):
        p.login("ben@acme.com", "wrong-password", ip="2.2.2.2", now=300.0)
    s.append = real_append


def test_ordinary_membership_revocation_is_owner_signed():
    # FINDING C — R1: an ordinary revocation is an OWNER-SIGNED spine record (never an anonymous unsigned
    # append). Trace the ACTUAL record the provisioner emits and verify it under the owner pubkey.
    from sigil.governor.authn import verify_signed
    from sigil.governor.orgs import _MEMBERSHIP_CORE, MEMBERSHIP_SIGNAL
    p, s, custs, orgs, wallet = _prov()
    admin = p.confirm_signup(p.request_signup(" run@acme.com".strip(), ip="1.1.1.1", now=100.0)["dev_token"],
                             password="customer-pw-1", org_name="Run", now=100.0)
    au, oid = admin["username"], admin["org_id"]
    mu = p.confirm_signup(p.request_signup("mem@acme.com", ip="1.1.1.2", now=100.0)["dev_token"],
                          password="customer-pw-2", org_name="Mem", now=100.0)["username"]
    p.grant_member(au, oid, mu, "analyst", now=200.0)
    p.revoke_member(au, oid, mu, now=201.0)
    assert orgs.membership_role(mu, oid) is None
    revokes = [r.payload for r in s.iter_records()
               if isinstance(r.payload, dict) and r.payload.get("signal") == MEMBERSHIP_SIGNAL
               and r.payload.get("org_id") == oid and r.payload.get("username") == mu
               and r.payload.get("state") == "revoked"]
    assert revokes, "an ordinary revocation must emit a revoke record"
    assert verify_signed(revokes[-1], _MEMBERSHIP_CORE, OP)   # OWNER-signed — verifies under the owner pubkey


def test_requester_authority_is_from_the_membership_fold_not_a_claim():
    # FINDING D — authority comes from the requester's OWN owner-signed membership (resolved LIVE), never a
    # self-asserted claim. A requester with NO admin membership in the org is denied for grant AND revoke; the
    # HTTP edge binds `requester` from the authenticated session, so an attacker can never name another admin.
    p, s, custs, orgs, wallet = _prov()
    admin = p.confirm_signup(p.request_signup("ad@acme.com", ip="1.1.1.1", now=100.0)["dev_token"],
                             password="customer-pw-1", org_name="Ad", now=100.0)
    au, oid = admin["username"], admin["org_id"]
    vu = p.confirm_signup(p.request_signup("vic@acme.com", ip="1.1.1.2", now=100.0)["dev_token"],
                          password="customer-pw-2", org_name="Vic", now=100.0)["username"]
    with pytest.raises(ProvisionDenied):                 # a non-member of oid cannot grant into it
        p.grant_member(vu, oid, vu, "analyst", now=200.0)
    with pytest.raises(ProvisionDenied):                 # ...nor revoke the real admin
        p.revoke_member(vu, oid, au, now=201.0)
    assert orgs.membership_role(au, oid) == "org_admin"  # the admin is untouched


def test_grant_refuses_a_target_that_is_not_a_customer():
    # FINDING (account-state validation) — never seat a member that is not a real active customer identity.
    p, s, custs, orgs, wallet = _prov()
    admin = p.confirm_signup(p.request_signup("t@acme.com", ip="1.1.1.1", now=100.0)["dev_token"],
                             password="customer-pw-1", org_name="T", now=100.0)
    au, oid = admin["username"], admin["org_id"]
    with pytest.raises(ProvisionDenied):
        p.grant_member(au, oid, "cust_nonexistent_target_id", "analyst", now=200.0)


def test_last_admin_cannot_be_revoked_or_downgraded():
    # FINDING (last-admin protection) — an org must never be left with zero admins (orphaned/un-governable).
    p, s, custs, orgs, wallet = _prov()
    admin = p.confirm_signup(p.request_signup("solo@acme.com", ip="1.1.1.1", now=100.0)["dev_token"],
                             password="customer-pw-1", org_name="Solo", now=100.0)
    au, oid = admin["username"], admin["org_id"]
    with pytest.raises(ProvisionDenied):                 # the sole admin cannot revoke themselves
        p.revoke_member(au, oid, au, now=200.0)
    with pytest.raises(ProvisionDenied):                 # ...nor self-downgrade to a non-admin role
        p.grant_member(au, oid, au, "analyst", now=201.0)
    assert orgs.membership_role(au, oid) == "org_admin"
    mu = p.confirm_signup(p.request_signup("co@acme.com", ip="1.1.1.2", now=100.0)["dev_token"],
                          password="customer-pw-2", org_name="Co", now=100.0)["username"]
    p.grant_member(au, oid, mu, "org_admin", now=202.0)  # a SECOND admin now exists
    p.revoke_member(au, oid, au, now=203.0)              # so the first may step down
    assert orgs.membership_role(au, oid) is None
    assert orgs.membership_role(mu, oid) == "org_admin"


def test_signup_global_cap_refuses_beyond_the_window_limit():
    # FINDING (trial-credit farming) — a GLOBAL signup cap bounds trial minting per window, ON TOP of
    # per-email uniqueness + per-ip/email rate limits. With a cap of 2, the 3rd signup is refused.
    p, s, custs, orgs, wallet = _cap_prov(signup_cap=2)
    for name in ("a", "b"):
        tok = p.request_signup(f"{name}@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
        p.confirm_signup(tok, password="customer-pw", org_name=name, now=100.0)
    tok3 = p.request_signup("c@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
    with pytest.raises(ProvisionRateLimited):            # cap hit → fail-closed (the token stays valid to retry)
        p.confirm_signup(tok3, password="customer-pw", org_name="c", now=100.0)


def test_member_management_is_rate_limited_per_org():
    # FINDING (member:org rate limit "checked but not incremented") — the member limiter is now both GUARDED
    # and INCREMENTED. With a cap of 2, the first two member ops pass and the 3rd is refused.
    p, s, custs, orgs, wallet = _cap_prov(member_cap=2)
    au = p.confirm_signup(p.request_signup("adm@acme.com", ip="1.1.1.1", now=100.0)["dev_token"],
                          password="customer-pw-1", org_name="Adm", now=100.0)
    au, oid = au["username"], au["org_id"]
    m1 = p.confirm_signup(p.request_signup("m1@acme.com", ip="1.1.1.2", now=100.0)["dev_token"],
                          password="customer-pw-2", org_name="M1", now=100.0)["username"]
    p.grant_member(au, oid, m1, "analyst", now=200.0)    # op 1
    p.grant_member(au, oid, m1, "viewer", now=201.0)     # op 2 → trips the lock
    with pytest.raises(ProvisionRateLimited):
        p.grant_member(au, oid, m1, "analyst", now=202.0)  # op 3 → refused


def test_password_reset_signals_session_revocation():
    # FINDING (session invalidation on reset) — the signing service owns the owner-signed credential change
    # and SIGNALS that the edge must revoke sessions (the SessionLedger lives on the keyless edge). It also
    # drops sibling tokens so none survives the reset.
    p, s, custs, orgs, wallet = _prov()
    p.confirm_signup(p.request_signup("res@acme.com", ip="1.1.1.1", now=100.0)["dev_token"],
                     password="old-password", org_name="Res", now=100.0)
    rt = p.request_recover("res@acme.com", ip="3.3.3.3", now=300.0)["dev_token"]
    out = p.confirm_recover(rt, new_password="new-password", now=300.0)
    assert out["sessions_must_revoke"] is True           # the edge MUST revoke_all(username) on this signal
    assert p.login("res@acme.com", "new-password", ip="4.4.4.4", now=400.0)["username"]  # reset is owner-signed + live
