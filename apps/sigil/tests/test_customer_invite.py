"""The team EMAIL-INVITE flow, behind VIGIL_CUSTOMER_TEAM_INVITE (DEFAULT ON for launch).

Today the Team feature can add an EXISTING VIGIL account by email. An INVITE covers the other case: an org_admin
invites a person who has NO account yet, by email. The invite is a PENDING record plus a single-use, expiring token
sent in an email; it GRANTS NOTHING until it is accepted at sign-up / sign-in (an owner-signed, role-capped membership
grant, reusing the same ``grant_membership`` the member verbs use).

Covered here:
* create + the mock mailer is invoked (the token is in the email body, never in the audit; the audit names the opaque
  invite_id, never the invited address);
* the role cap (_CUSTOMER_GRANTABLE_ROLES) is enforced server-side; cross-tenant invites are refused; dedupe + the
  per-org pending cap + the per-org rate limit bound abuse; the email must be well-formed;
* accept grants the capped membership and nothing before it; the token is single-use; an expired token is refused
  (fail closed); the token must be redeemed by the matching mailbox; an already-member keeps their role;
* revoke drops a pending invite so it can no longer be accepted;
* the flag: DEFAULT ON serves the backend; an explicit off value (VIGIL_CUSTOMER_TEAM_INVITE=0) makes every route /
  action absent (404) and sign-up / sign-in ignore any presented token.
"""
from __future__ import annotations

import itertools
import json
import time

import pytest

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import HOP, _get, _opener, _post, _stack

from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import MEMBERSHIP_SIGNAL, OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import provision
from sigil.ui.email_channel import EmailSender, EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.member_invites_store import MemberInviteLedger
from sigil.ui.provision import (ProvisionDenied, ProvisionError, ProvisionRateLimited, ProvisionStepUpRequired,
                                Provisioner)

FLAG = "VIGIL_CUSTOMER_TEAM_INVITE"
OWNER = generate_keypair()
OP = OWNER.public_key_b64
_clock = itertools.count(1)


@pytest.fixture(autouse=True)
def _no_flags(monkeypatch):
    for var in (FLAG, "VIGIL_CUSTOMER_TEAM_UI", "VIGIL_CUSTOMER_STEPUP_REQUIRED", "VIGIL_CUSTOMER_SEATS",
                "VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", "VIGIL_TRIAL_PREVIEW_ENABLED"):
        monkeypatch.delenv(var, raising=False)


class _Recorder(EmailSender):
    """A mock mailer: records every send and reports delivery (so the invite's dev_token is NOT surfaced)."""
    def __init__(self):
        self.sent = []

    def send(self, to, subject, body):
        self.sent.append((to, subject, body))
        return True


def _prov(tmp_path, *, member_limiter=None, expose_dev_tokens=False, sender=None, ttl_s=1e4):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    if sender is None:
        # the dev_token is surfaced only when the send did NOT deliver (mirrors signup); a NullEmailSender (sends
        # nothing) stands in for a dev deployment so the accept tests can read the token back.
        sender = NullEmailSender() if expose_dev_tokens else _Recorder()
    p = Provisioner(
        s, customers=CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        orgs=OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(str(tmp_path / "tokens"), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(str(tmp_path / "rl"), max_fails=50, window_s=1e4, base_lock_s=50.0),
        member_limiter=member_limiter,
        member_invites=MemberInviteLedger(str(tmp_path / "invites"), ttl_s=ttl_s),
        email_sender=sender,
        expose_dev_tokens=expose_dev_tokens)
    return p, s


def _org(p, *, admin="cust_ad", org="org_a", email="admin@acme.io"):
    """An org with one admin (org_admin)."""
    p.customers.create(email, issued_at=float(next(_clock)), username=admin)
    p.orgs.create_org(org, "Acme", owner=admin, issued_at=float(next(_clock)))
    p.orgs.grant_membership(org, admin, "org_admin", issued_at=float(next(_clock)))


def _audits(s, action):
    return [r.payload for r in s.iter_records() if isinstance(r.payload, dict)
            and r.payload.get("signal") == "provision.audit" and r.payload.get("action") == action]


# --- create + the mock mailer --------------------------------------------------------------------------------------
def test_invite_creates_a_pending_invite_and_sends_the_email(tmp_path):
    rec = _Recorder()
    p, s = _prov(tmp_path, sender=rec)
    _org(p)
    before = p.orgs.member_count("org_a")
    got = p.customer_member_invite("cust_ad", "org_a", "  New.Person@ACME.io ", "analyst")
    assert got["org_id"] == "org_a" and got["role"] == "analyst" and got["status"] == "pending"
    assert got["email"] == "new.person@acme.io" and got["sent"] is True and "dev_token" not in got
    # the mailer was invoked once, to the invited address; the single-use token is in the BODY (and only there)
    assert len(rec.sent) == 1
    to, subject, body = rec.sent[0]
    assert to == "new.person@acme.io" and "VIGIL" in subject and provision._INVITE_SUBJECT == subject
    assert got["invite_id"] not in body            # the email carries the token, not the opaque invite_id
    # the audit names the OPAQUE invite_id, NEVER the invited address; and no token anywhere on the spine
    a = _audits(s, "member_invite")
    assert len(a) == 1 and a[0]["target"] == got["invite_id"] and a[0]["outcome"] == "role=analyst"
    spine = json.dumps([r.payload for r in s.iter_records()])
    assert "new.person" not in spine              # a third party's email is never logged to the spine
    for tok_line in body.splitlines():
        if tok_line.strip() and tok_line.strip() not in (subject,):
            assert tok_line.strip() not in spine  # nor is the token
    # an invite GRANTS NOTHING: the org's membership is unchanged until the invite is accepted
    assert p.orgs.member_count("org_a") == before
    assert [i["email"] for i in p.customer_member_invites_list("cust_ad", "org_a")["invites"]] == ["new.person@acme.io"]


def test_an_invite_grants_nothing_until_accepted(tmp_path):
    p, s = _prov(tmp_path)
    _org(p)
    p.customer_member_invite("cust_ad", "org_a", "new@acme.io", "org_admin")
    # a brand-new account for the invited mailbox is NOT a member of the org merely because an invite exists
    p.customers.create("new@acme.io", issued_at=float(next(_clock)), username="cust_new")
    assert p.orgs.membership_role("cust_new", "org_a") is None
    # no MEMBERSHIP signal was written for the invited account by the invite itself
    assert not any(isinstance(r.payload, dict) and r.payload.get("signal") == MEMBERSHIP_SIGNAL
                   and r.payload.get("username") == "cust_new" for r in s.iter_records())


# --- the role cap (non-negotiable) ---------------------------------------------------------------------------------
@pytest.mark.parametrize("role", ["operator", "founder", "owner", "", "Analyst", "viewer "])
def test_invite_role_cap_is_enforced_server_side(tmp_path, role):
    rec = _Recorder()
    p, s = _prov(tmp_path, sender=rec)
    _org(p)
    n = s.count()
    with pytest.raises(ProvisionDenied, match="role must be one of"):
        p.customer_member_invite("cust_ad", "org_a", "x@acme.io", role)
    assert s.count() == n and rec.sent == []       # nothing created, nothing sent
    assert p.customer_member_invites_list("cust_ad", "org_a")["count"] == 0


# --- cross-tenant + authority --------------------------------------------------------------------------------------
def test_invite_is_an_administrators_act_and_cross_tenant_is_refused(tmp_path):
    rec = _Recorder()
    p, s = _prov(tmp_path, sender=rec)
    _org(p)                                                                  # org_a, admin cust_ad
    _org(p, admin="cust_bb", org="org_b", email="b@beta.io")                 # org_b, admin cust_bb
    for who, org in (("cust_bb", "org_a"), ("cust_nobody", "org_a"), ("cust_ad", "org_b"), ("", "org_a")):
        with pytest.raises(ProvisionDenied, match="administrator of this org"):
            p.customer_member_invite(who, org, "x@acme.io", "viewer")
    assert rec.sent == []                                                    # no email ever left for a refused invite
    # the list is an administrator's read too -- a non-admin / other org's admin is refused
    for who, org in (("cust_bb", "org_a"), ("cust_ad", "org_b"), ("cust_nobody", "org_a")):
        with pytest.raises(ProvisionDenied, match="manage_members"):
            p.customer_member_invites_list(who, org)
    # the admin can invite into THEIR org only; the audit of a denied invite carries no target
    assert all(a["outcome"] == "denied" and a["target"] == "" for a in _audits(s, "member_invite"))


def test_invite_dedupes_a_pending_invite_and_caps_pending_per_org(tmp_path):
    p, s = _prov(tmp_path)
    p.customers.create("admin@acme.io", issued_at=float(next(_clock)), username="cust_ad")
    p.orgs.create_org("org_a", "Acme", owner="cust_ad", issued_at=float(next(_clock)))
    p.orgs.grant_membership("org_a", "cust_ad", "org_admin", issued_at=float(next(_clock)))
    assert p.customer_member_invite("cust_ad", "org_a", "p@acme.io", "viewer")["status"] == "pending"
    with pytest.raises(ProvisionDenied, match="already pending"):            # dedupe: one live invite per (org, email)
        p.customer_member_invite("cust_ad", "org_a", "  P@ACME.io ", "analyst")
    # the per-org pending cap (defence in depth; the ledger enforces it atomically)
    p.member_invites.max_pending_per_org = 2
    p.customer_member_invite("cust_ad", "org_a", "q@acme.io", "viewer")      # second, now at the cap
    with pytest.raises(ProvisionDenied, match="too many pending"):
        p.customer_member_invite("cust_ad", "org_a", "r@acme.io", "viewer")


def test_invite_is_rate_limited_per_org(tmp_path):
    lim = LoginRateLimiter(str(tmp_path / "member"), max_fails=2, window_s=60.0, base_lock_s=60.0, max_lock_s=600.0)
    p, s = _prov(tmp_path, member_limiter=lim)
    _org(p)
    p.customer_member_invite("cust_ad", "org_a", "a@acme.io", "viewer")
    p.customer_member_invite("cust_ad", "org_a", "b@acme.io", "viewer")
    with pytest.raises(ProvisionRateLimited):
        p.customer_member_invite("cust_ad", "org_a", "c@acme.io", "viewer")


@pytest.mark.parametrize("email", ["", "   ", "not-an-email", "a@b", "two words@acme.io"])
def test_invite_validates_the_email_format(tmp_path, email):
    rec = _Recorder()
    p, s = _prov(tmp_path, sender=rec)
    _org(p)
    with pytest.raises(ProvisionError) as e:
        p.customer_member_invite("cust_ad", "org_a", email, "viewer")
    assert str(e.value) == provision._INVITE_BAD_EMAIL and not isinstance(e.value, ProvisionDenied)
    assert rec.sent == []


def test_invite_needs_a_fresh_step_up_when_enforcement_is_on(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    p, s = _prov(tmp_path)
    _org(p)
    for stale in (None, 0.0, time.time() - 3600):
        with pytest.raises(ProvisionStepUpRequired):
            p.customer_member_invite("cust_ad", "org_a", "x@acme.io", "viewer", mfa_at=stale)
    assert p.customer_member_invite("cust_ad", "org_a", "x@acme.io", "viewer", mfa_at=time.time())["status"] == "pending"


# --- accept --------------------------------------------------------------------------------------------------------
def test_accept_grants_the_capped_membership_and_is_single_use(tmp_path):
    p, s = _prov(tmp_path, expose_dev_tokens=True)
    _org(p)
    got = p.customer_member_invite("cust_ad", "org_a", "newbie@acme.io", "analyst")
    token = got["dev_token"]
    # the invited person now has an account (sign-up / sign-in) with the SAME email
    p.customers.create("newbie@acme.io", issued_at=float(next(_clock)), username="cust_nb")
    assert p.orgs.membership_role("cust_nb", "org_a") is None                 # nothing yet
    res = p.customer_member_invite_accept("cust_nb", token=token)
    assert res == {"accepted": True, "org_id": "org_a", "username": "cust_nb", "role": "analyst", "seq": res["seq"]}
    assert p.orgs.membership_role("cust_nb", "org_a") == "analyst"            # the capped membership was granted
    a = _audits(s, "member_invite_accept")
    assert len(a) == 1 and a[0]["target"] == "cust_nb" and a[0]["outcome"] == "role=analyst"
    # single-use: a replay of the same token grants nothing more
    assert p.customer_member_invite_accept("cust_nb", token=token) == {"accepted": False, "reason": "invalid"}


def test_accept_of_an_expired_token_is_refused_fail_closed(tmp_path):
    p, s = _prov(tmp_path, expose_dev_tokens=True, ttl_s=100.0)
    _org(p)
    got = p.customer_member_invite("cust_ad", "org_a", "late@acme.io", "viewer", now=1000.0)
    p.customers.create("late@acme.io", issued_at=float(next(_clock)), username="cust_late")
    # past expires_at -> refused, nothing granted
    assert p.customer_member_invite_accept("cust_late", token=got["dev_token"], now=1000.0 + 101.0) == {
        "accepted": False, "reason": "invalid"}
    assert p.orgs.membership_role("cust_late", "org_a") is None


def test_accept_requires_the_matching_mailbox(tmp_path):
    p, s = _prov(tmp_path, expose_dev_tokens=True)
    _org(p)
    got = p.customer_member_invite("cust_ad", "org_a", "intended@acme.io", "viewer")
    # a DIFFERENT account cannot redeem an invite minted for someone else's mailbox
    p.customers.create("someone.else@acme.io", issued_at=float(next(_clock)), username="cust_else")
    assert p.customer_member_invite_accept("cust_else", token=got["dev_token"]) == {
        "accepted": False, "reason": "email_mismatch"}
    assert p.orgs.membership_role("cust_else", "org_a") is None
    assert _audits(s, "member_invite_accept")[0]["reason"] == "email_mismatch"
    # the token is NOT burned by a mismatched attempt -> the intended mailbox can still accept
    p.customers.create("intended@acme.io", issued_at=float(next(_clock)), username="cust_int")
    assert p.customer_member_invite_accept("cust_int", token=got["dev_token"])["accepted"] is True


def test_accept_of_an_already_member_keeps_their_role_and_consumes_the_token(tmp_path):
    p, s = _prov(tmp_path, expose_dev_tokens=True)
    _org(p)
    p.customers.create("mate@acme.io", issued_at=float(next(_clock)), username="cust_mate")
    p.orgs.grant_membership("org_a", "cust_mate", "org_admin", issued_at=float(next(_clock)))   # already an admin
    got = p.customer_member_invite("cust_ad", "org_a", "mate@acme.io", "viewer")
    res = p.customer_member_invite_accept("cust_mate", token=got["dev_token"])
    assert res == {"accepted": True, "org_id": "org_a", "username": "cust_mate", "role": "org_admin",
                   "already_member": True}
    assert p.orgs.membership_role("cust_mate", "org_a") == "org_admin"        # the invite never downgraded them
    # the token was consumed (single-use)
    assert p.customer_member_invite_accept("cust_mate", token=got["dev_token"]) == {"accepted": False, "reason": "invalid"}


def test_accept_with_a_bad_or_missing_token_never_raises(tmp_path):
    p, s = _prov(tmp_path)
    _org(p)
    p.customers.create("x@acme.io", issued_at=float(next(_clock)), username="cust_x")
    assert p.customer_member_invite_accept("cust_x", token="")["reason"] == "no_token"
    assert p.customer_member_invite_accept("cust_x", token="not-a-real-token")["reason"] == "invalid"
    assert p.customer_member_invite_accept("cust_missing", token="whatever")["reason"] == "no_account"


# --- revoke --------------------------------------------------------------------------------------------------------
def test_revoke_drops_a_pending_invite_so_it_cannot_be_accepted(tmp_path):
    p, s = _prov(tmp_path, expose_dev_tokens=True)
    _org(p)
    got = p.customer_member_invite("cust_ad", "org_a", "gone@acme.io", "viewer")
    assert p.customer_member_invites_list("cust_ad", "org_a")["count"] == 1
    out = p.customer_member_invite_revoke("cust_ad", "org_a", got["invite_id"])
    assert out == {"org_id": "org_a", "invite_id": got["invite_id"], "revoked": True}
    assert p.customer_member_invites_list("cust_ad", "org_a")["count"] == 0
    assert _audits(s, "member_invite_revoke")[0]["outcome"] == "revoked"
    # the token no longer redeems to anything (fail closed)
    p.customers.create("gone@acme.io", issued_at=float(next(_clock)), username="cust_gone")
    assert p.customer_member_invite_accept("cust_gone", token=got["dev_token"]) == {"accepted": False, "reason": "invalid"}
    assert p.orgs.membership_role("cust_gone", "org_a") is None
    # revoking an unknown invite is refused in plain words
    with pytest.raises(ProvisionDenied, match="no longer pending"):
        p.customer_member_invite_revoke("cust_ad", "org_a", "deadbeef")


# --- the flag: default ON, off only on an explicit off value -------------------------------------------------------
class _P:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def f(*a, **k):
            self.calls.append((name, a, k))
            return {"ok": True}
        return f


def test_the_cockpit_invite_actions_are_on_by_default_and_off_only_when_disabled(monkeypatch):
    from sigil.ui.server import Handler
    body = {"org_id": "org_a", "email": "m@acme.io", "role": "analyst", "invite_id": "iid", "token": "tok",
            "ip": "1.2.3.4", "mfa_at": 5.0, "requester": "cust_eve"}
    actions = ("member_invite", "member_invites_list", "member_invite_revoke", "member_invite_accept")
    # DEFAULT ON: the flag unset -> every action dispatches to its method, with the hop principal as requester
    monkeypatch.delenv(FLAG, raising=False)
    p = _P()
    for action in actions:
        Handler._provision_dispatch(None, p, action, "cust_ad", dict(body))
    assert [c[0] for c in p.calls] == ["customer_member_invite", "customer_member_invites_list",
                                       "customer_member_invite_revoke", "customer_member_invite_accept"]
    assert p.calls[0] == ("customer_member_invite", ("cust_ad", "org_a", "m@acme.io", "analyst"),
                          {"ip": "1.2.3.4", "mfa_at": 5.0})
    assert p.calls[3] == ("customer_member_invite_accept", ("cust_ad",), {"token": "tok", "ip": "1.2.3.4"})
    # explicitly OFF -> every action is unknown (404)
    monkeypatch.setenv(FLAG, "0")
    off = _P()
    for action in actions:
        assert Handler._provision_dispatch(None, off, action, "cust_ad", dict(body)) is None
    assert off.calls == []


def _edge_stub(session):
    from sigil.ui.custui import CustomerHandler
    h = object.__new__(CustomerHandler)
    sent = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                    or (200, {"ok": True}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


_SESSION = {"username": "cust_ad", "org_id": "org_a", "mfa_at": 123.0}


def test_the_edge_invite_routes_are_on_by_default_and_tenant_bound(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)                                   # DEFAULT ON
    # POST member/invite: only the email + role travel; org, requester and the step-up stamp are the session's
    h, sent = _edge_stub(dict(_SESSION))
    h._dispatch("member/invite", {"email": "m@acme.io", "role": "analyst", "org_id": "org_b", "requester": "cust_x"})
    assert sent["action"] == "member_invite" and sent["principal"] == "cust_ad"
    assert sent["body"] == {"org_id": "org_a", "email": "m@acme.io", "role": "analyst", "ip": "1.2.3.4", "mfa_at": 123.0}
    # POST member/invite/revoke
    h, sent = _edge_stub(dict(_SESSION))
    h._dispatch("member/invite/revoke", {"invite_id": "iid", "org_id": "org_b"})
    assert sent["action"] == "member_invite_revoke"
    assert sent["body"] == {"org_id": "org_a", "invite_id": "iid", "ip": "1.2.3.4", "mfa_at": 123.0}
    # no session (or no bound org) is refused before the hop fires
    for session in (None, {}, {"username": "cust_ad"}, {"username": "cust_ad", "org_id": ""}):
        h, sent = _edge_stub(session)
        h._dispatch("member/invite", {"email": "m@acme.io", "role": "viewer"})
        assert sent["code"] == 401 and "action" not in sent, session


def test_the_edge_invite_routes_are_absent_when_disabled(monkeypatch):
    monkeypatch.setenv(FLAG, "0")
    for action, bod in (("member/invite", {"email": "m@acme.io", "role": "viewer"}),
                        ("member/invite/revoke", {"invite_id": "iid"})):
        h, sent = _edge_stub(dict(_SESSION))
        h._dispatch(action, bod)
        assert sent == {"code": 404, "out": {"error": "unknown action"}}, action


# --- end to end, over the real edge -> cockpit hop -----------------------------------------------------------------
def _signup(ep, email, org_name="Acme", invite_token=None):
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    body = {"token": t, "password": "customer-pw-1", "org_name": org_name}
    if invite_token is not None:
        body["invite_token"] = invite_token
    c, r = _post(op, ep, "/api/customer/signup/confirm", body)
    assert c == 200, (c, r)
    return op, r


def test_over_the_hop_an_admin_invites_a_new_person_who_accepts_at_signup(tmp_path, monkeypatch):
    from sigil import config
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "CUSTOMER_MEMBER_INVITES_DIR", tmp_path / "invites")
    try:
        admin, a = _signup(ep, "boss@acme.io")
        org = a["org_id"]
        # the admin invites a person who has NO account yet; the dev token stands in for the email (no SMTP in dev)
        c, r = _post(admin, ep, "/api/customer/member/invite", {"email": "recruit@acme.io", "role": "analyst"})
        assert c == 200 and r["status"] == "pending" and r["role"] == "analyst", (c, r)
        token = r["dev_token"]
        # it shows in the pending list, and the org has gained no member yet (grants nothing until accepted)
        c, lst = _get(admin, ep, "/api/customer/member/invites")
        assert c == 200 and [i["email"] for i in lst["invites"]] == ["recruit@acme.io"]
        # the recruit signs up WITH the token -> they join the inviting org as analyst (and own their new workspace too)
        recruit, rr = _signup(ep, "recruit@acme.io", "Recruit", invite_token=token)
        assert rr["invite"]["accepted"] is True and rr["invite"]["org_id"] == org and rr["invite"]["role"] == "analyst"
        # the invite is now gone from the pending list; a replay of the token grants nothing
        assert _get(admin, ep, "/api/customer/member/invites")[1]["count"] == 0
        recruit2, rr2 = _signup(ep, "other@acme.io", "Other", invite_token=token)
        assert rr2["invite"]["accepted"] is False     # single-use: the token is spent
    finally:
        sov.shutdown()
        edge.shutdown()


def test_over_the_hop_default_on_serves_invites_without_the_flag_set(tmp_path, monkeypatch):
    # directive: DEFAULT ON. With VIGIL_CUSTOMER_TEAM_INVITE UNSET, the invite backend still serves.
    from sigil import config
    monkeypatch.delenv(FLAG, raising=False)
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "CUSTOMER_MEMBER_INVITES_DIR", tmp_path / "invites")
    try:
        admin, a = _signup(ep, "boss@acme.io")
        c, r = _post(admin, ep, "/api/customer/member/invite", {"email": "p@acme.io", "role": "viewer"})
        assert c == 200 and r["status"] == "pending", (c, r)        # served although the flag is unset
        assert _get(admin, ep, "/api/customer/member/invites")[1]["count"] == 1
    finally:
        sov.shutdown()
        edge.shutdown()


def test_over_the_hop_an_explicit_off_value_disables_the_invite_routes(tmp_path, monkeypatch):
    # directive: a working flag-OFF path. With VIGIL_CUSTOMER_TEAM_INVITE=0 the routes are absent and sign-in ignores
    # any presented token.
    monkeypatch.setenv(FLAG, "0")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        admin, a = _signup(ep, "boss@acme.io")
        assert _post(admin, ep, "/api/customer/member/invite", {"email": "p@acme.io", "role": "viewer"})[0] == 404
        assert _get(admin, ep, "/api/customer/member/invites")[0] == 404
        # a sign-up that presents a token is unaffected: it just ignores it (no "invite" key in the response)
        _recruit, rr = _signup(ep, "r@acme.io", "R", invite_token="some-token")
        assert "invite" not in rr
    finally:
        sov.shutdown()
        edge.shutdown()
