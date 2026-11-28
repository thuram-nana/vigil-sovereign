"""The customer app's Team screen, behind VIGIL_CUSTOMER_TEAM_UI (default OFF).

* The READ (edge GET api/customer/members -> provision members_list -> Provisioner.customer_members): the SESSION org's
  members only — username, role, since when that role was granted, and the email only when the customer registry
  holds an ACTIVE account with one — and only for someone who may manage the team (`manage_members`: an org_admin or
  the founder). A viewer, an analyst, an operator, a non-member or another org's admin is refused (403).
* ADD MEMBER (edge POST api/customer/member/add -> provision member_add -> Provisioner.add_member): a teammate is named
  by the email of their EXISTING VIGIL account (the username that member_grant takes is an opaque server-made id no
  person knows) with a customer-grantable role. There is no invitation flow, so an email with no account is refused in
  plain words and nothing is recorded about it. The admin check comes first (a non-admin learns nothing about whether
  an email has an account), then the step-up, then the per-org rate guard, then the lookup; a current member is never
  silently given another role; the critical audit precedes the owner-signed grant, inside the membership lock.
* Change role / Remove use the existing member/grant and member/revoke routes, unchanged.
* With the flag OFF: both edge routes are exactly an unknown route (404), both cockpit actions are absent, the page says
  data-team="0" (the flag is its only difference from the flag-on page) and the Team tab renders exactly the old
  "being wired" card and fetches nothing.
* The screen (app.js, executed under node with a minimal DOM; its functions are extracted verbatim): the list, the
  founder's row read-only, a role picker offering exactly the grantable roles, Add member, Change role, Remove with an
  in-page confirmation (never a browser dialog), the step-up answer, the honest 403 card and every refusal in words.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the read is not an administrator's act                    -> test_only_an_administrator_of_the_session_org_reads_its_team
  * the read lists every org's members                        -> test_only_an_administrator_of_the_session_org_reads_its_team
  * an inactive account's email is shown                      -> test_a_member_whose_account_is_not_active_is_listed_without_an_email
  * add_member skips or weakens the admin check               -> test_add_member_is_an_administrators_act_and_tells_no_one_else_...
  * add_member looks the email up before the admin check      -> test_add_member_is_an_administrators_act_and_tells_no_one_else_...
  * add_member accepts a role a customer cannot grant         -> test_add_member_offers_only_the_roles_a_customer_can_grant
  * add_member changes a current member's role                -> test_add_member_never_changes_a_current_members_role
  * add_member skips the step-up / the rate guard / the audit -> the step-up / rate-limit / adds-an-existing-account tests
  * add_member decides outside the membership lock            -> test_add_member_decides_inside_the_cross_process_membership_lock
  * the cockpit actions ignore the flag / take the body's requester -> test_the_cockpit_actions_exist_only_with_the_flag
  * the edge routes ignore the flag                           -> test_the_edge_routes_are_absent_with_the_flag_off
  * the edge takes the org from the body or query             -> test_the_edge_relays_for_the_session_org_only
  * the edge always writes data-team="1"                      -> test_the_edge_writes_the_team_flag_into_the_page
  * the app ignores the page flag                             -> test_with_the_flag_off_the_team_tab_is_the_old_card_and_fetches_nothing
  * the role picker offers Operator                           -> test_the_role_choices_are_exactly_the_roles_a_customer_can_grant
  * Remove sends without the in-page confirmation             -> test_remove_asks_in_the_page_first_and_only_yes_sends_member_revoke
  * the founder's row gets buttons                            -> test_the_founder_row_has_no_buttons
  * the step-up refusal is not answered with the authenticator message -> test_a_step_up_refusal_asks_for_a_fresh_authenticator_code
  * a role that cannot manage the team gets no honest card    -> test_a_role_that_cannot_manage_the_team_sees_an_honest_card
  * the last-admin refusal / a 5xx is not said plainly        -> test_every_refusal_is_said_plainly
  * a change can be sent twice while it is in flight          -> test_a_change_in_flight_cannot_be_sent_twice
  * the guide names a label the screen does not have          -> test_the_guide_team_step_uses_the_screens_real_labels
"""
from __future__ import annotations

import http.client
import itertools
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import HOP, _get, _opener, _post, _stack

from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import MEMBERSHIP_SIGNAL, OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import provision
from sigil.ui.custui import build_customer_server
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import (_CUSTOMER_GRANTABLE_ROLES, ProvisionDenied, ProvisionError, ProvisionRateLimited,
                                ProvisionStepUpRequired, Provisioner)

FLAG = "VIGIL_CUSTOMER_TEAM_UI"
APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS, GUIDE_JS, APP_JS = APP / "ui.js", APP / "guide.js", APP / "app.js"
OWNER = generate_keypair()
OP = OWNER.public_key_b64
_clock = itertools.count(1)


@pytest.fixture(autouse=True)
def _no_flags(monkeypatch):
    for var in (FLAG, "VIGIL_CUSTOMER_STEPUP_REQUIRED", "VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED",
                "VIGIL_TRIAL_PREVIEW_ENABLED"):
        monkeypatch.delenv(var, raising=False)


# --- the provisioner ------------------------------------------------------------------------------------------------
def _prov(tmp_path, *, member_limiter=None):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    p = Provisioner(
        s, customers=CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        orgs=OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(str(tmp_path / "tokens"), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(str(tmp_path / "rl"), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), member_limiter=member_limiter)
    return p, s


def _team(p):
    """Two workspaces. org_a: its founder, an admin, an operator, an analyst and a viewer; org_b: an admin and a viewer.
    Every member has an account (password-less: the email is what matters here)."""
    for name in ("fo", "ad", "op", "an", "vi", "bb", "bx"):
        p.customers.create(f"{name}@acme.io", issued_at=float(next(_clock)), username=f"cust_{name}")
    p.orgs.create_org("org_a", "Acme", owner="cust_fo", issued_at=float(next(_clock)))
    p.orgs.create_org("org_b", "Beta", owner="cust_bb", issued_at=float(next(_clock)))
    for u, r in (("cust_fo", "founder"), ("cust_ad", "org_admin"), ("cust_op", "operator"), ("cust_an", "analyst"),
                 ("cust_vi", "viewer")):
        p.orgs.grant_membership("org_a", u, r, issued_at=float(next(_clock)))
    for u, r in (("cust_bb", "org_admin"), ("cust_bx", "viewer")):
        p.orgs.grant_membership("org_b", u, r, issued_at=float(next(_clock)))


def _audits(s, action):
    return [r.payload for r in s.iter_records() if isinstance(r.payload, dict)
            and r.payload.get("signal") == "provision.audit" and r.payload.get("action") == action]


def test_only_an_administrator_of_the_session_org_reads_its_team(tmp_path):
    p, s = _prov(tmp_path)
    _team(p)
    got = p.customer_members("cust_ad", "org_a")
    assert got["org_id"] == "org_a" and got["count"] == 5
    # founder first, then admins, operators, analysts, viewers
    assert [(r["username"], r["role"]) for r in got["members"]] == [
        ("cust_fo", "founder"), ("cust_ad", "org_admin"), ("cust_op", "operator"), ("cust_an", "analyst"),
        ("cust_vi", "viewer")]
    since = {m.username: m.issued_at for m in p.orgs.memberships("org_a")}
    for r in got["members"]:
        assert set(r) == {"username", "role", "since", "email"}, r
        assert r["since"] == since[r["username"]] and r["email"] == r["username"][len("cust_"):] + "@acme.io"
    assert p.customer_members("cust_fo", "org_a") == got                  # the founder manages the team too
    for who in ("cust_op", "cust_an", "cust_vi", "cust_bb", "cust_bx", "cust_nobody", "", "owner"):
        with pytest.raises(ProvisionDenied, match="manage_members"):
            p.customer_members(who, "org_a")
    with pytest.raises(ProvisionDenied):
        p.customer_members("cust_ad", "org_b")                            # never another org's team
    assert [r["username"] for r in p.customer_members("cust_bb", "org_b")["members"]] == ["cust_bb", "cust_bx"]
    # a role change restarts "since"; a revoked admin loses the read on the very next request
    p.grant_member("cust_ad", "org_a", "cust_an", "viewer")
    row = next(r for r in p.customer_members("cust_ad", "org_a")["members"] if r["username"] == "cust_an")
    assert row["role"] == "viewer" and row["since"] > since["cust_an"]
    p.orgs.revoke_membership("org_a", "cust_ad")
    with pytest.raises(ProvisionDenied):
        p.customer_members("cust_ad", "org_a")


def test_a_member_whose_account_is_not_active_is_listed_without_an_email(tmp_path):
    p, s = _prov(tmp_path)
    _team(p)
    p.customers.revoke("cust_vi")
    rows = {r["username"]: r for r in p.customer_members("cust_ad", "org_a")["members"]}
    assert rows["cust_vi"] == {"username": "cust_vi", "role": "viewer", "since": rows["cust_vi"]["since"]}
    assert rows["cust_an"]["email"] == "an@acme.io"


def test_add_member_adds_an_existing_account_by_its_email(tmp_path):
    p, s = _prov(tmp_path)
    _team(p)
    p.customers.create("new.mate@acme.io", issued_at=float(next(_clock)), username="cust_nm")
    got = p.add_member("cust_ad", "org_a", "  New.Mate@ACME.io ", "analyst")
    assert got == {"org_id": "org_a", "username": "cust_nm", "role": "analyst", "seq": got["seq"]}
    assert p.orgs.membership_role("cust_nm", "org_a") == "analyst" and p.orgs.membership_role("cust_nm", "org_b") is None
    assert [(a["requester"], a["org_id"], a["target"], a["outcome"]) for a in _audits(s, "add_member")] == [
        ("cust_ad", "org_a", "cust_nm", "role=analyst")]
    rows = [r.payload for r in s.iter_records() if isinstance(r.payload, dict)]
    audit_at = next(i for i, r in enumerate(rows) if r.get("action") == "add_member")
    grant_at = next(i for i, r in enumerate(rows) if r.get("signal") == MEMBERSHIP_SIGNAL and r.get("username") == "cust_nm")
    assert audit_at < grant_at                                            # committed implies audited
    listed = {r["username"]: r for r in p.customer_members("cust_fo", "org_a")["members"]}
    assert listed["cust_nm"]["email"] == "new.mate@acme.io" and listed["cust_nm"]["role"] == "analyst"
    # a member of ANOTHER workspace is not a member here, so they can be added; their own membership is untouched
    assert p.add_member("cust_ad", "org_a", "bx@acme.io", "viewer")["username"] == "cust_bx"
    assert p.orgs.membership_role("cust_bx", "org_b") == "viewer" and p.orgs.membership_role("cust_bx", "org_a") == "viewer"


def test_add_member_refuses_an_email_with_no_account_and_records_nothing(tmp_path):
    p, s = _prov(tmp_path)
    _team(p)
    n = s.count()
    with pytest.raises(ProvisionDenied) as e:
        p.add_member("cust_ad", "org_a", "stranger@elsewhere.io", "viewer")
    assert str(e.value) == provision._ADD_NO_ACCOUNT
    assert s.count() == n                                                 # no grant, no audit row ...
    assert "stranger" not in json.dumps([r.payload for r in s.iter_records()])   # ... and no third party's email


# --- V12 seats: per-workspace member limit (VIGIL_CUSTOMER_SEATS, default OFF) --------------------------------------
def test_seats_off_by_default_imposes_no_member_limit(tmp_path, monkeypatch):
    # VIGIL_CUSTOMER_SEATS unset (the default) -> add_member/grant_member behave exactly as before, no cap,
    # even with a tiny VIGIL_CUSTOMER_DEFAULT_SEATS set (the flag, not the number, is what gates enforcement).
    monkeypatch.delenv("VIGIL_CUSTOMER_SEATS", raising=False)
    monkeypatch.setenv("VIGIL_CUSTOMER_DEFAULT_SEATS", "1")
    p, s = _prov(tmp_path)
    _team(p)                                                             # org_a already has 5 members
    for i in range(4):
        p.customers.create(f"extra{i}@acme.io", issued_at=float(next(_clock)), username=f"cust_x{i}")
        assert p.add_member("cust_ad", "org_a", f"extra{i}@acme.io", "viewer")["username"] == f"cust_x{i}"
    assert p.orgs.member_count("org_a") == 9


def test_seats_limit_refuses_a_new_member_at_capacity(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_SEATS", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_DEFAULT_SEATS", "6")
    p, s = _prov(tmp_path)
    _team(p)                                                             # 5 members, limit 6
    p.customers.create("sixth@acme.io", issued_at=float(next(_clock)), username="cust_six")
    p.customers.create("seventh@acme.io", issued_at=float(next(_clock)), username="cust_sev")
    assert p.add_member("cust_ad", "org_a", "sixth@acme.io", "viewer")["username"] == "cust_six"   # 6th fits
    assert p.orgs.member_count("org_a") == 6
    n = s.count()
    with pytest.raises(ProvisionDenied, match="member limit"):                                     # 7th refused
        p.add_member("cust_ad", "org_a", "seventh@acme.io", "viewer")
    assert s.count() == n                                               # fail-closed: nothing written, no audit
    assert p.orgs.membership_role("cust_sev", "org_a") is None


def test_seats_limit_never_blocks_a_role_change_only_new_members(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_SEATS", "on")
    monkeypatch.setenv("VIGIL_CUSTOMER_DEFAULT_SEATS", "5")              # org_a is exactly at the limit
    p, s = _prov(tmp_path)
    _team(p)
    assert p.orgs.member_count("org_a") == 5
    # a role change for an EXISTING member consumes no seat -> allowed even at capacity
    assert p.grant_member("cust_ad", "org_a", "cust_vi", "analyst")["role"] == "analyst"
    assert p.orgs.member_count("org_a") == 5
    # but adding a NEW member via grant_member is refused at capacity
    p.customers.create("nm@acme.io", issued_at=float(next(_clock)), username="cust_nm")
    with pytest.raises(ProvisionDenied, match="member limit"):
        p.grant_member("cust_ad", "org_a", "cust_nm", "viewer")
    assert p.orgs.membership_role("cust_nm", "org_a") is None


def test_seats_revoking_a_member_frees_a_seat(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_SEATS", "yes")
    monkeypatch.setenv("VIGIL_CUSTOMER_DEFAULT_SEATS", "5")
    p, s = _prov(tmp_path)
    _team(p)                                                            # full at 5
    p.customers.create("nm@acme.io", issued_at=float(next(_clock)), username="cust_nm")
    with pytest.raises(ProvisionDenied, match="member limit"):
        p.add_member("cust_ad", "org_a", "nm@acme.io", "viewer")
    p.revoke_member("cust_ad", "org_a", "cust_vi")                      # free one seat (viewer, not last admin)
    assert p.orgs.member_count("org_a") == 4
    assert p.add_member("cust_ad", "org_a", "nm@acme.io", "viewer")["username"] == "cust_nm"
    assert p.orgs.member_count("org_a") == 5


def test_team_read_reports_seat_usage_only_when_seats_on(tmp_path, monkeypatch):
    p, s = _prov(tmp_path)
    _team(p)                                                            # org_a has 5 members
    monkeypatch.delenv("VIGIL_CUSTOMER_SEATS", raising=False)           # flag off -> no seats key (byte-identical)
    assert "seats" not in p.customer_members("cust_ad", "org_a")
    monkeypatch.setenv("VIGIL_CUSTOMER_SEATS", "1")                     # flag on -> usage reported
    monkeypatch.setenv("VIGIL_CUSTOMER_DEFAULT_SEATS", "8")
    got = p.customer_members("cust_ad", "org_a")
    assert got["count"] == 5 and got["seats"] == {"used": 5, "limit": 8}


def test_the_team_screen_shows_seat_usage_when_seats_are_on():
    out = _node(_app() + r"""
VUI.getJSON = async p => { calls.push(["GET", p]);
  return { org_id: "org_a", members: members, count: members.length, seats: { used: 4, limit: 8 } }; };
show(); await tick();
out.seat = text(root.querySelector(".cust-team-seats"));
out.hasAdd = !!root.querySelector(".cust-team-add");
""")
    assert out["seat"] == "4 of 8 member seats used" and out["hasAdd"] is True


def test_the_team_seat_line_hints_when_full_and_is_absent_when_seats_off():
    full = _node(_app() + r"""
VUI.getJSON = async p => { calls.push(["GET", p]);
  return { org_id: "org_a", members: members, count: members.length, seats: { used: 8, limit: 8 } }; };
show(); await tick();
out.seat = text(root.querySelector(".cust-team-seats"));
""")
    assert "8 of 8 member seats used" in full["seat"] and "add a seat" in full["seat"]
    one = _node(_app() + r"""
VUI.getJSON = async p => { calls.push(["GET", p]);
  return { org_id: "org_a", members: members, count: members.length, seats: { used: 1, limit: 1 } }; };
show(); await tick();
out.seat = text(root.querySelector(".cust-team-seats"));
""")
    assert "1 of 1 member seat used" in one["seat"]          # singular "seat" when limit == 1
    off = _node(_app() + r"""
show(); await tick();
out.absent = root.querySelector(".cust-team-seats") === null;
""")
    assert off["absent"] is True


def test_add_member_never_changes_a_current_members_role(tmp_path):
    p, s = _prov(tmp_path)
    _team(p)
    for email in ("an@acme.io", "fo@acme.io", "ad@acme.io", " OP@acme.io"):   # incl. the founder and the requester
        n = s.count()
        with pytest.raises(ProvisionDenied) as e:
            p.add_member("cust_ad", "org_a", email, "org_admin")
        assert str(e.value) == provision._ADD_ALREADY_MEMBER and s.count() == n, email
    assert [(m.username, m.role) for m in p.orgs.memberships("org_a")] == [
        ("cust_ad", "org_admin"), ("cust_an", "analyst"), ("cust_fo", "founder"), ("cust_op", "operator"),
        ("cust_vi", "viewer")]


@pytest.mark.parametrize("role", ["operator", "founder", "owner", "", "Admin", "org_admin "])
def test_add_member_offers_only_the_roles_a_customer_can_grant(tmp_path, role):
    p, s = _prov(tmp_path)
    _team(p)
    n = s.count()
    with pytest.raises(ProvisionDenied, match="role must be one of"):
        p.add_member("cust_fo", "org_a", "bx@acme.io", role)
    assert s.count() == n and p.orgs.membership_role("cust_bx", "org_a") is None


def test_add_member_is_an_administrators_act_and_tells_no_one_else_whether_an_email_has_an_account(tmp_path):
    p, s = _prov(tmp_path)
    _team(p)
    for who, org in (("cust_op", "org_a"), ("cust_an", "org_a"), ("cust_vi", "org_a"), ("cust_bb", "org_a"),
                     ("cust_nobody", "org_a"), ("cust_ad", "org_b")):
        said = set()
        for email in ("bx@acme.io", "stranger@elsewhere.io"):             # an email with an account, and one without
            with pytest.raises(ProvisionDenied) as e:
                p.add_member(who, org, email, "viewer")
            said.add(str(e.value))
        assert said == {"requester is not an administrator of this org"}, (who, org, said)
    assert p.orgs.membership_role("cust_bx", "org_a") is None
    denied = _audits(s, "add_member")
    assert len(denied) == 12 and all(a["outcome"] == "denied" and a["target"] == "" for a in denied)


def test_add_member_needs_a_fresh_step_up_when_enforcement_is_on(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    p, s = _prov(tmp_path)
    _team(p)
    for stale in (None, 0.0, time.time() - 3600):
        with pytest.raises(ProvisionStepUpRequired):
            p.add_member("cust_ad", "org_a", "bx@acme.io", "viewer", mfa_at=stale)
    assert p.orgs.membership_role("cust_bx", "org_a") is None
    assert p.add_member("cust_ad", "org_a", "bx@acme.io", "viewer", mfa_at=time.time())["role"] == "viewer"


def test_add_member_is_rate_limited_per_org_and_a_refused_lookup_counts(tmp_path):
    lim = LoginRateLimiter(str(tmp_path / "member"), max_fails=3, window_s=60.0, base_lock_s=60.0, max_lock_s=600.0)
    p, s = _prov(tmp_path, member_limiter=lim)
    _team(p)
    for i in range(3):                                                    # probing for accounts is bounded per org
        with pytest.raises(ProvisionDenied, match="no VIGIL account"):
            p.add_member("cust_ad", "org_a", f"probe{i}@elsewhere.io", "viewer")
    with pytest.raises(ProvisionRateLimited):
        p.add_member("cust_ad", "org_a", "bx@acme.io", "viewer")
    assert p.orgs.membership_role("cust_bx", "org_a") is None
    assert p.add_member("cust_bb", "org_b", "an@acme.io", "viewer")["role"] == "viewer"   # another org's own budget


@pytest.mark.parametrize("email", ["", "   ", "not-an-email", "a@b", "x" * 300 + "@acme.io", "two words@acme.io"])
def test_add_member_refuses_a_malformed_email(tmp_path, email):
    p, s = _prov(tmp_path)
    _team(p)
    n = s.count()
    with pytest.raises(ProvisionError) as e:
        p.add_member("cust_ad", "org_a", email, "viewer")
    assert str(e.value) == provision._ADD_BAD_EMAIL and not isinstance(e.value, ProvisionDenied)
    assert s.count() == n


def test_add_member_decides_inside_the_cross_process_membership_lock(tmp_path, monkeypatch):
    # The same cross-process lock grant_member / revoke_member and the owner verbs hold around their checks, audit and
    # write: while another holder has it, Add member gives up after its bounded wait with nothing written.
    from vigil_integration.live.seam_lock import LockBusy
    p, s = _prov(tmp_path)
    _team(p)
    monkeypatch.setattr(provision, "_MEMBERS_LOCK_WAIT_S", 0.05)
    n = s.count()
    with provision._members_lock(s):
        with pytest.raises(LockBusy):
            p.add_member("cust_ad", "org_a", "bx@acme.io", "viewer")
    assert s.count() == n and p.orgs.membership_role("cust_bx", "org_a") is None
    assert p.add_member("cust_ad", "org_a", "bx@acme.io", "viewer")["role"] == "viewer"


def test_the_customer_facing_refusals_reach_the_page_whole():
    """The cockpit cuts a refusal at 200 characters; every Add member refusal fits, names no model, engine or price,
    and names only labels the app really shows."""
    texts = (provision._ADD_NO_ACCOUNT, provision._ADD_ALREADY_MEMBER, provision._ADD_BAD_EMAIL)
    assert all(len(t) <= 200 for t in texts)
    assert not _FORBIDDEN.search(" ".join(texts))
    src = APP_JS.read_text(encoding="utf-8")
    assert 'text: "Create an account"' in src and 'text: "Change role"' in src
    assert "Create an account" in provision._ADD_NO_ACCOUNT and "Change role" in provision._ADD_ALREADY_MEMBER


# --- the cockpit's provision dispatch ---------------------------------------------------------------------------------
class _P:
    def __init__(self):
        self.calls: list = []

    def __getattr__(self, name):
        def f(*a, **k):
            self.calls.append((name, a, k))
            return {"ok": True}
        return f


def test_the_cockpit_actions_exist_only_with_the_flag(monkeypatch):
    from sigil.ui.server import Handler
    body = {"org_id": "org_a", "email": "m@acme.io", "role": "analyst", "ip": "1.2.3.4", "mfa_at": 5.0,
            "requester": "cust_eve", "username": "cust_eve"}
    for action in ("members_list", "member_add"):
        p = _P()
        assert Handler._provision_dispatch(None, p, action, "cust_ad", dict(body)) is None   # -> 404
        assert p.calls == []
    monkeypatch.setenv(FLAG, "1")
    p = _P()
    Handler._provision_dispatch(None, p, "members_list", "cust_ad", dict(body))
    Handler._provision_dispatch(None, p, "member_add", "cust_ad", dict(body))
    # the requester is the hop principal — a body field naming someone else is never used
    assert p.calls == [("customer_members", ("cust_ad", "org_a"), {"ip": "1.2.3.4"}),
                       ("add_member", ("cust_ad", "org_a", "m@acme.io", "analyst"), {"ip": "1.2.3.4", "mfa_at": 5.0})]


# --- the edge -----------------------------------------------------------------------------------------------------------
def _edge_stub(session):
    """A customer-edge handler with its session and its hop to the provisioner stubbed: what does it relay?"""
    from sigil.ui.custui import CustomerHandler
    h = object.__new__(CustomerHandler)
    sent: dict = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                    or (200, {"ok": True}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


_SESSION = {"username": "cust_ad", "org_id": "org_a", "mfa_at": 123.0}


def test_the_edge_routes_are_absent_with_the_flag_off():
    h, sent = _edge_stub(dict(_SESSION))
    h.path = "/api/customer/members"
    h.do_GET()
    h2, unknown = _edge_stub(dict(_SESSION))
    h2.path = "/api/customer/nope"
    h2.do_GET()
    assert sent == unknown == {"code": 404, "out": {"error": "not found"}}
    h, sent = _edge_stub(dict(_SESSION))
    h._dispatch("member/add", {"email": "m@acme.io", "role": "viewer"})
    h2, unknown = _edge_stub(dict(_SESSION))
    h2._dispatch("no/such/route", {})
    assert sent == unknown == {"code": 404, "out": {"error": "unknown action"}}


def test_the_edge_relays_for_the_session_org_only(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    h, sent = _edge_stub(dict(_SESSION))
    h.path = "/api/customer/members?org_id=org_b&username=cust_bb"
    h.do_GET()
    assert sent == {"action": "members_list", "principal": "cust_ad", "body": {"org_id": "org_a", "ip": "1.2.3.4"},
                    "code": 200, "out": {"ok": True}}
    h, sent = _edge_stub(dict(_SESSION))
    h._dispatch("member/add", {"email": "m@acme.io", "role": "analyst", "org_id": "org_b", "requester": "cust_bb",
                               "mfa_at": 9e9, "member_username": "cust_x"})
    assert sent["action"] == "member_add" and sent["principal"] == "cust_ad"
    # only the email and the role travel; org, requester and the step-up stamp are the session's
    assert sent["body"] == {"org_id": "org_a", "email": "m@acme.io", "role": "analyst", "ip": "1.2.3.4", "mfa_at": 123.0}
    for session in (None, {}, {"username": "cust_ad"}, {"username": "cust_ad", "org_id": ""}):
        h, sent = _edge_stub(session)
        h._dispatch("member/add", {"email": "m@acme.io", "role": "viewer"})
        assert sent["code"] == 401 and "action" not in sent, session
        h, sent = _edge_stub(session)
        h.path = "/api/customer/members"
        h.do_GET()
        assert sent["code"] == 401 and "action" not in sent, session


# --- the edge and the cockpit, over the real hop ------------------------------------------------------------------------
def _signup(ep, email, org_name="Acme"):
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    c, r = _post(op, ep, "/api/customer/signup/confirm",
                 {"token": t, "password": "customer-pw-1", "org_name": org_name})
    assert c == 200, (c, r)
    return op, r["username"], r["org_id"]


def _account(sov, email, username):
    """An existing customer account with NO workspace of its own (owner-signed on the cockpit's spine), so its sign-in
    lands in the one workspace it is added to."""
    CustomerRegistry(sov.store()).create(email, issued_at=time.time(), password="customer-pw-2", username=username)


def _sign_in(ep, email):
    op = _opener()
    c, r = _post(op, ep, "/api/customer/login", {"email": email, "password": "customer-pw-2"})
    assert c == 200, (c, r)
    return op, r


def _team_of(op, ep):
    c, r = _get(op, ep, "/api/customer/members")
    assert c == 200, (c, r)
    return [(m["username"], m["role"], m.get("email")) for m in r["members"]]


def _hop(sport, action, principal, body):
    """A signed edge->cockpit hop straight to the provisioner route (what the edge sends, minus the edge)."""
    from vigil_core.hopauth import body_binding, stamp_hop_assertion
    path, ts, data = f"/api/provision/{action}", str(int(time.time())), json.dumps(body).encode()
    sig = stamp_hop_assertion(HOP, principal, f"{action}:{body_binding(HOP, data)}", "POST", path, ts)
    req = urllib.request.Request(f"http://127.0.0.1:{sport}{path}", data=data, method="POST",
                                 headers={"Content-Type": "application/json", "X-VIGIL-Provision-Principal": principal,
                                          "X-VIGIL-Provision-Ts": ts, "X-VIGIL-Provision-Sig": sig})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_over_the_hop_an_admin_adds_a_teammate_changes_their_role_and_removes_them(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        admin, a, org = _signup(ep, "admin@acme.io")
        mate, m, _mate_org = _signup(ep, "mate@acme.io", "Mate")          # a teammate who already uses VIGIL
        assert _team_of(admin, ep) == [(a, "org_admin", "admin@acme.io")]
        c, r = _post(admin, ep, "/api/customer/member/add", {"email": " Mate@ACME.io ", "role": "analyst"})
        assert c == 200 and (r["org_id"], r["username"], r["role"]) == (org, m, "analyst"), (c, r)
        assert _team_of(admin, ep) == [(a, "org_admin", "admin@acme.io"), (m, "analyst", "mate@acme.io")]
        c, r = _post(admin, ep, "/api/customer/member/grant", {"member_username": m, "role": "viewer"})
        assert c == 200 and r["role"] == "viewer", (c, r)
        assert _team_of(admin, ep)[1] == (m, "viewer", "mate@acme.io")
        assert _post(admin, ep, "/api/customer/member/revoke", {"member_username": m})[0] == 200
        assert _team_of(admin, ep) == [(a, "org_admin", "admin@acme.io")]
        assert _team_of(mate, ep) == [(m, "org_admin", "mate@acme.io")]    # their own workspace was never touched
    finally:
        sov.shutdown()
        edge.shutdown()


def test_over_the_hop_no_one_reads_or_adds_to_another_workspaces_team(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        opa, a, org_a = _signup(ep, "a@acme.io", "A")
        opb, b, org_b = _signup(ep, "b@beta.io", "B")
        c, r = _get(opa, ep, f"/api/customer/members?org_id={org_b}")    # naming the other org changes nothing
        assert c == 200 and r["org_id"] == org_a and [x["username"] for x in r["members"]] == [a], (c, r)
        c, r = _post(opa, ep, "/api/customer/member/add", {"email": "b@beta.io", "role": "viewer", "org_id": org_b})
        assert c == 200 and r["org_id"] == org_a, (c, r)                  # it lands in the SESSION's workspace
        assert [x[0] for x in _team_of(opa, ep)] == [a, b]
        assert _team_of(opb, ep) == [(b, "org_admin", "b@beta.io")]       # B's team is untouched
    finally:
        sov.shutdown()
        edge.shutdown()


def test_over_the_hop_viewers_analysts_and_operators_cannot_see_or_change_the_team(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        admin, a, org = _signup(ep, "admin@acme.io")
        _account(sov, "tess@acme.io", "cust_tess0001")
        _account(sov, "other@acme.io", "cust_other001")
        assert _post(admin, ep, "/api/customer/member/add", {"email": "tess@acme.io", "role": "viewer"})[0] == 200
        tess, r = _sign_in(ep, "tess@acme.io")
        assert r["active_org"] == org                                     # the one workspace they belong to
        for role in ("viewer", "analyst", "operator"):
            if role == "analyst":
                assert _post(admin, ep, "/api/customer/member/grant",
                             {"member_username": "cust_tess0001", "role": "analyst"})[0] == 200
            if role == "operator":                                        # an owner act
                OrgRegistry(sov.store()).grant_membership(org, "cust_tess0001", "operator", issued_at=time.time() + 1e6)
            c, body = _get(tess, ep, "/api/customer/members")
            assert c == 403 and "manage_members" in body["error"], (role, c, body)
            for email in ("other@acme.io", "nobody@acme.io"):             # no add, and no hint whether an email has
                c, body = _post(tess, ep, "/api/customer/member/add", {"email": email, "role": "viewer"})   # an account
                assert (c, body) == (403, {"error": "denied: requester is not an administrator of this org"}), (role, email)
        assert [x[0] for x in _team_of(admin, ep)] == [a, "cust_tess0001"]
    finally:
        sov.shutdown()
        edge.shutdown()


def test_over_the_hop_the_founder_cannot_be_changed_or_removed(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        fop, f, org = _signup(ep, "founder@acme.io")
        OrgRegistry(sov.store()).grant_membership(org, f, "founder", issued_at=time.time() + 1e6)   # an owner act
        _account(sov, "ada@acme.io", "cust_ada00001")
        assert _post(fop, ep, "/api/customer/member/add", {"email": "ada@acme.io", "role": "org_admin"})[0] == 200
        ada, _r = _sign_in(ep, "ada@acme.io")
        assert _team_of(ada, ep) == [(f, "founder", "founder@acme.io"), ("cust_ada00001", "org_admin", "ada@acme.io")]
        for op in (ada, fop):                                             # another admin, and the founder on themself
            for role in ("viewer", "analyst", "org_admin"):
                c, r = _post(op, ep, "/api/customer/member/grant", {"member_username": f, "role": role})
                assert c == 403 and "service owner" in r["error"], (c, r)
            c, r = _post(op, ep, "/api/customer/member/revoke", {"member_username": f})
            assert c == 403 and "service owner" in r["error"], (c, r)
            c, r = _post(op, ep, "/api/customer/member/add", {"email": "founder@acme.io", "role": "viewer"})
            assert (c, r) == (403, {"error": "denied: " + provision._ADD_ALREADY_MEMBER}), (c, r)
        assert _team_of(ada, ep)[0] == (f, "founder", "founder@acme.io")
    finally:
        sov.shutdown()
        edge.shutdown()


def test_over_the_hop_the_last_person_who_can_manage_the_team_stays(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        admin, a, org = _signup(ep, "solo@acme.io")
        for path, body in (("/api/customer/member/revoke", {"member_username": a}),
                           ("/api/customer/member/grant", {"member_username": a, "role": "viewer"})):
            c, r = _post(admin, ep, path, body)
            # the wording the page recognises for its plain last-admin message (test_every_refusal_is_said_plainly)
            assert (c, r) == (403, {"error": "denied: cannot remove the last administrator of the org"}), (path, c, r)
        assert _team_of(admin, ep) == [(a, "org_admin", "solo@acme.io")]
    finally:
        sov.shutdown()
        edge.shutdown()


def test_over_the_hop_an_email_with_no_account_is_refused_in_plain_words(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        admin, a, org = _signup(ep, "admin@acme.io")
        assert _post(admin, ep, "/api/customer/member/add", {"email": "nobody@acme.io", "role": "viewer"}) == (
            403, {"error": "denied: " + provision._ADD_NO_ACCOUNT})
        assert _post(admin, ep, "/api/customer/member/add", {"email": "not an email", "role": "viewer"}) == (
            400, {"error": "provision failed: " + provision._ADD_BAD_EMAIL})
        c, r = _post(admin, ep, "/api/customer/member/add", {"email": "admin@acme.io", "role": "operator"})
        assert c == 403 and "role must be one of" in r["error"], (c, r)
        assert _team_of(admin, ep) == [(a, "org_admin", "admin@acme.io")]
    finally:
        sov.shutdown()
        edge.shutdown()


def test_over_the_hop_add_member_asks_for_a_fresh_step_up_when_enforced(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        admin, a, org = _signup(ep, "admin@acme.io")
        _account(sov, "mate@acme.io", "cust_mate0001")
        c, r = _post(admin, ep, "/api/customer/member/add", {"email": "mate@acme.io", "role": "viewer"})
        assert c == 401 and r.get("step_up_required") is True, (c, r)
        assert _team_of(admin, ep) == [(a, "org_admin", "admin@acme.io")]  # nothing was added; the read needs none
    finally:
        sov.shutdown()
        edge.shutdown()


def test_with_the_flag_off_the_team_routes_are_absent_and_member_management_is_unchanged(tmp_path, monkeypatch):
    sov, edge, ep, sport = _stack(tmp_path, monkeypatch)
    try:
        admin, a, org = _signup(ep, "admin@acme.io")
        _mate, m, _ = _signup(ep, "mate@acme.io", "Mate")
        assert _get(admin, ep, "/api/customer/members") == _get(admin, ep, "/api/customer/nope") == (
            404, {"error": "not found"})
        assert _post(admin, ep, "/api/customer/member/add", {"email": "mate@acme.io", "role": "viewer"}) == _post(
            admin, ep, "/api/customer/no/such", {}) == (404, {"error": "unknown action"})
        # the cockpit's own gate: a validly signed hop for either action is an unknown action
        for action, body in (("members_list", {"org_id": org}),
                             ("member_add", {"org_id": org, "email": "mate@acme.io", "role": "viewer"})):
            assert _hop(sport, action, a, body) == (404, {"error": "unknown provision action"}), action
        assert OrgRegistry(sov.store()).membership_role(m, org) is None
        # the member routes that already existed are exactly as they were
        c, r = _post(admin, ep, "/api/customer/member/grant", {"member_username": m, "role": "analyst"})
        assert c == 200 and r == {"org_id": org, "username": m, "role": "analyst", "seq": r["seq"]}, (c, r)
        assert _post(admin, ep, "/api/customer/member/revoke", {"member_username": m})[0] == 200
        assert OrgRegistry(sov.store()).membership_role(m, org) is None
        monkeypatch.setenv(FLAG, "1")                                     # read on every request: on, the hop answers
        c, r = _hop(sport, "members_list", a, {"org_id": org})
        assert c == 200 and [x["username"] for x in r["members"]] == [a], (c, r)
    finally:
        sov.shutdown()
        edge.shutdown()


# --- the page flag ----------------------------------------------------------------------------------------------------
def _page_and_build(tmp_path):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "s"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
        r = c.getresponse()
        return r.read().decode(), r.getheader("X-Vigil-Build")
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_edge_writes_the_team_flag_into_the_page(tmp_path, monkeypatch):
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-team="0"' in off and "__VIGIL_TEAM__" not in off
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-team="1"' in on and build_on != build_off               # a new build the open pages are told about
    # the flag is the page's only difference: its value, and the build id it changes
    assert on.replace('data-team="1"', 'data-team="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv(FLAG, v)
        assert 'data-team="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v


# --- the screen (app.js under node) ---------------------------------------------------------------------------------
def _need_node() -> str:
    """The node binary, or a SKIP where node is absent — except in CI (GITHUB_ACTIONS) or where VIGIL_REQUIRE_NODE is
    set: there a missing node FAILS, so these executed-JS proofs can never go green unrun."""
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH: this job must "
                        "EXECUTE these JS tests")
        pytest.skip("node not installed")
    return node


# A minimal DOM: what ui.js's h() and the Team screen touch. A <select>'s value follows its options as in a browser
# (setting it selects the first option with that value; reading it gives the selected option's value), and a disabled
# button ignores clicks.
_DOM = r"""
class Node {}
class Text extends Node {
  constructor(t) { super(); this.nodeValue = String(t); this.parentNode = null; }
  get textContent() { return this.nodeValue; }
}
class ClassList {
  constructor(el) { this.el = el; }
  _get() { return (this.el.className || "").split(/\s+/).filter(Boolean); }
  add(c) { const s = this._get(); if (s.indexOf(c) < 0) s.push(c); this.el.className = s.join(" "); }
  remove(c) { this.el.className = this._get().filter(x => x !== c).join(" "); }
  contains(c) { return this._get().indexOf(c) >= 0; }
}
class El extends Node {
  constructor(tag) {
    super(); this.tagName = String(tag).toUpperCase(); this.attrs = {}; this.children = []; this.dataset = {};
    this.style = {}; this.className = ""; this.id = ""; this.parentNode = null; this.hidden = false;
    this.disabled = false; this.classList = new ClassList(this); this.listeners = {}; this._value = "";
  }
  _options() { return this._all([]).filter(e => e.tagName === "OPTION"); }
  get value() {
    if (this.tagName !== "SELECT") return this._value;
    const opts = this._options(), pick = opts.find(o => o.selected) || opts.find(o => !o.disabled);
    return pick ? pick.value : "";
  }
  set value(v) {
    if (this.tagName !== "SELECT") { this._value = String(v); return; }
    let hit = false;
    this._options().forEach(o => { o.selected = !hit && o.value === String(v); if (o.selected) hit = true; });
  }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
    if (k === "disabled") this.disabled = true;
    if (k === "value") this.value = String(v);
  }
  getAttribute(k) {
    if (k.indexOf("data-") === 0) { const d = k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      if (d in this.dataset) return String(this.dataset[d]); }
    return k in this.attrs ? this.attrs[k] : null;
  }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); this.children.push(c); c.parentNode = this; return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); c.parentNode = null; return c; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  get firstChild() { return this.children[0] || null; }
  set textContent(v) { this.children = []; if (String(v)) this.appendChild(new Text(v)); }
  get textContent() { return this.children.map(c => c.textContent).join(""); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter(x => x !== f); }
  dispatch(t, ev) { (this.listeners[t] || []).slice().forEach(f => f(ev || { preventDefault() {} })); }
  click() { if (!this.disabled) this.dispatch("click"); }
  focus() {}
  _all(out) { this.children.forEach(c => { if (c instanceof El) { out.push(c); c._all(out); } }); return out; }
  querySelectorAll(sel) { return this._all([]).filter(e => matches(e, sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
function matches(e, sel) {
  const m = sel.match(/^([a-z][a-z0-9]*)?(#[\w-]+)?((?:\.[\w-]+)*)(?:\[([\w-]+)="([^"]*)"\])?$/i);
  if (!m) throw new Error("selector not supported by the test DOM: " + sel);
  if (m[1] && e.tagName !== m[1].toUpperCase()) return false;
  if (m[2] && e.id !== m[2].slice(1)) return false;
  const cls = (m[3] || "").split(".").filter(Boolean);
  if (cls.some(c => !e.classList.contains(c))) return false;
  if (m[4] && e.getAttribute(m[4]) !== m[5]) return false;
  return true;
}
globalThis.Node = Node;
globalThis.window = globalThis;
const body = new El("body");
globalThis.document = {
  body, documentElement: body,
  createElement: t => new El(t), createTextNode: t => new Text(t),
  querySelector: s => body.querySelector(s), querySelectorAll: s => body.querySelectorAll(s),
  addEventListener: () => {}, removeEventListener: () => {},
};
function text(e) { return e ? e.textContent : null; }
function buttons(root) { return root.querySelectorAll("button").map(b => b.textContent); }
function button(root, label) { return root.querySelectorAll("button").filter(b => b.textContent === label)[0]; }
function ser(n) {
  if (!(n instanceof El)) return { t: n.textContent };
  return { tag: n.tagName, id: n.id, cls: n.className, attrs: n.attrs, data: n.dataset, hidden: n.hidden,
           kids: n.children.map(ser) };
}
const tick = () => new Promise(r => setTimeout(r, 0));
"""

# The app's world, stubbed: who is signed in, what the server answers, and every call made to it.
_WORLD = r"""
document.body.dataset.team = __FLAG__;
globalThis.location = { hash: "#/team" };
let who = { authenticated: true, username: "cust_me" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const navs = []; function nav(r) { navs.push(r); }
let refreshed = 0; async function refreshWho() { refreshed++; }
const calls = [];
let members = __MEMBERS__;
let listFail = null;            // {status, data, message}: the next list read fails like that
let postFail = null;            // {status, data, message}: the next change fails like that
function failure(f) {
  const e = new Error(f.message || (f.data && f.data.error) || "failed");
  e.status = f.status; e.data = f.data || null;
  return e;
}
const VUI = window.VUI;
VUI.getJSON = async p => {
  calls.push(["GET", p]);
  if (listFail) { const f = listFail; listFail = null; throw failure(f); }
  return { org_id: "org_a", members: members, count: members.length };
};
VUI.postJSON = async (p, b) => {
  calls.push(["POST", p, b]);
  if (postFail) { const f = postFail; postFail = null; throw failure(f); }
  return { ok: true };
};
const toasts = []; VUI.toast = m => { toasts.push(m); };
var GUIDE = null, GUIDE_ON = false;
function shell(inner, current) { return h("div.cust-shell", { dataset: { current: current } }, inner); }
function viewLogin() { return h("div.cust-login"); }
const root = new El("div"); document.body.appendChild(root);
function show() { VUI.mount(root, ROUTES["#/team"]()); return root; }
function rowOf(name) {
  return root.querySelectorAll(".cust-member").filter(r => text(r.querySelector(".cust-member-name")) === name)[0];
}
function msg() { const m = root.querySelector(".cust-team-msg"); return [m.textContent, m.className]; }
function addCard() { return root.querySelector(".cust-team-add"); }
"""

_MEMBERS = [
    {"username": "cust_fo", "role": "founder", "since": 1700000000.0, "email": "fo@acme.io"},
    {"username": "cust_me", "role": "org_admin", "since": 1700100000.0, "email": "me@acme.io"},
    {"username": "cust_op", "role": "operator", "since": 1700200000.0, "email": "op@acme.io"},
    {"username": "cust_an", "role": "analyst", "since": 1700300000.0},
]
_STEP_UP = {"status": 401, "data": {"error": "a fresh second-factor (step-up) is required for this operation",
                                    "step_up_required": True}}
_STEP_UP_SAID = ("For your security, changing your team needs a fresh second-factor check. Verify with your "
                 "authenticator, then try again. Nothing was changed.")
_BAD = "cust-team-msg bad"


def _fn(src: str, name: str) -> str:
    """One of app.js's multi-line top-level functions, verbatim."""
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


def _line(src: str, pattern: str) -> str:
    """One of app.js's own module-level lines, verbatim (so the harness runs what ships, not a copy of it)."""
    m = re.search(pattern, src, re.M)
    assert m, f"app.js no longer has a line matching {pattern!r}"
    return m.group(0)


def _team_block(src: str) -> str:
    i = src.index("  // ---- Team (VIGIL_CUSTOMER_TEAM_UI)")
    return src[i:src.index("  // ---- notification centre", i)]


def _app(flag: str = "1", members=None) -> str:
    """The harness: the stubs above plus app.js's own code for the Team tab, extracted verbatim."""
    src = APP_JS.read_text(encoding="utf-8")
    world = (_WORLD.replace("__FLAG__", json.dumps(flag))
             .replace("__MEMBERS__", json.dumps(_MEMBERS if members is None else members)))
    return "\n".join([world, _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                      _line(src, r'^  var API = "[^"]*";'), _fn(src, "fmtDate"),
                      _line(src, r"^  function here\(\) \{.*\}$"), _fn(src, "loadingHolder"), _fn(src, "viewSoon"),
                      _team_block(src), "const ROUTES = {\n" + _line(src, r'^    "#/team": function .*,$') + "\n};"])


def _node(script: str) -> dict:
    prog = _DOM + f"\nrequire({json.dumps(str(UI_JS))});\nrequire({json.dumps(str(GUIDE_JS))});\n" + script
    wrapped = ("const out = {};\n(async () => {\n" + prog + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
               " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", wrapped], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def test_with_the_flag_off_the_team_tab_is_the_old_card_and_fetches_nothing():
    for flag in ("0", "", "__VIGIL_TEAM__"):
        out = _node(_app(flag) + r"""
const a = ROUTES["#/team"](), b = viewSoon("Team");
out.same = JSON.stringify(ser(a)) === JSON.stringify(ser(b));
out.text = text(a); out.teamOn = TEAM_ON;
await tick();
out.calls = calls;
""")
        assert out["same"] is True and out["teamOn"] is False, flag              # exactly the card it always was
        assert "Team is being wired" in out["text"] and out["calls"] == [], flag  # and nothing is fetched
    src = APP_JS.read_text(encoding="utf-8")
    assert '"#/team": function () { return authed() ? (TEAM_ON ? viewTeam() : viewSoon("Team")) : viewLogin(); },' in src
    assert '  var TEAM_ON = pageFlag("team");' in src


def test_the_team_screen_lists_the_members_of_the_workspace():
    out = _node(_app() + r"""
show(); await tick();
out.calls = calls;
out.title = text(root.querySelector("h2"));
out.rows = root.querySelectorAll(".cust-member").map(r => ({
  name: text(r.querySelector(".cust-member-name")), chips: r.querySelectorAll(".chip").map(text),
  badge: text(r.querySelector(".cust-badge")), notes: r.querySelectorAll("p").map(text), buttons: buttons(r),
  options: r.querySelectorAll("option").map(o => [o.value, o.textContent, !!o.disabled]),
  picked: r.querySelector("select") ? r.querySelector("select").value : null,
}));
const add = addCard();
out.add = { title: text(add.querySelector("h3")), labels: add.querySelectorAll("label").map(text),
            options: add.querySelectorAll("option").map(o => [o.value, o.textContent]),
            picked: add.querySelector("select").value, buttons: buttons(add),
            email: add.querySelector("input").getAttribute("type") };
""")
    assert out["calls"] == [["GET", "api/customer/members"]] and out["title"] == "Team"
    fo, me, op, an = out["rows"]
    assert [r["name"] for r in out["rows"]] == ["fo@acme.io", "me@acme.io", "op@acme.io", "cust_an"]
    assert fo["badge"] == "Founder" and me["badge"] == "Admin" and op["badge"] == "Operator" and an["badge"] == "Analyst"
    assert me["chips"] == ["You"] and fo["chips"] == op["chips"] == an["chips"] == []
    assert f"Role since {_day(1700100000.0)}" in me["notes"] and f"Role since {_day(1700300000.0)}" in an["notes"]
    grantable = [["org_admin", "Admin", False], ["analyst", "Analyst", False], ["viewer", "Viewer", False]]
    assert me["options"] == grantable and me["picked"] == "org_admin" and me["buttons"] == ["Change role", "Remove"]
    assert an["options"] == grantable and an["picked"] == "analyst"
    # an Operator's role is shown truthfully but cannot be picked; only VIGIL makes someone an Operator again
    assert op["options"] == [["", "Operator", True]] + grantable and op["picked"] == ""
    assert any("only VIGIL can make them one again" in n for n in op["notes"])
    assert out["add"] == {"title": "Add member", "labels": ["Work email", "Role"],
                          "options": [["org_admin", "Admin"], ["analyst", "Analyst"], ["viewer", "Viewer"]],
                          "picked": "viewer", "buttons": ["Add member"], "email": "email"}


def test_the_founder_row_has_no_buttons():
    out = _node(_app() + r"""
show(); await tick();
const fo = rowOf("fo@acme.io");
out.buttons = buttons(fo); out.selects = fo.querySelectorAll("select").length;
out.confirm = fo.querySelectorAll(".cust-member-confirm").length; out.notes = fo.querySelectorAll("p").map(text);
""")
    assert out["buttons"] == [] and out["selects"] == 0 and out["confirm"] == 0
    assert "Only VIGIL changes or removes the founder." in out["notes"]


def test_the_role_choices_are_exactly_the_roles_a_customer_can_grant():
    out = _node(_app() + "out.roles = TEAM_ROLES; out.labels = ROLE_LABELS;")
    assert dict(out["roles"]) == {"org_admin": "Admin", "analyst": "Analyst", "viewer": "Viewer"}
    assert {k for k, _ in out["roles"]} == set(_CUSTOMER_GRANTABLE_ROLES)
    assert out["labels"]["founder"] == "Founder" and out["labels"]["operator"] == "Operator"


def test_role_labels_never_read_an_inherited_name():
    """A role string from the server is looked up as an OWN key only: an unexpected value is shown as itself."""
    out = _node(_app() + r"""
out.labels = ["founder", "org_admin", "operator", "constructor", "__proto__", "toString", "", null].map(roleLabel);
""")
    assert out["labels"] == ["Founder", "Admin", "Operator", "constructor", "__proto__", "toString", "—", "—"]


def test_add_member_sends_only_the_email_and_the_role_and_reads_the_list_again():
    out = _node(_app() + r"""
show(); await tick();
button(addCard(), "Add member").click(); await tick();
out.empty = msg(); out.before = calls.length;
addCard().querySelector("input").value = "  New.Mate@Acme.io ";
addCard().querySelector("select").value = "analyst";
button(addCard(), "Add member").click(); await tick(); await tick();
out.calls = calls.slice(1); out.toasts = toasts; out.after = msg();
""")
    assert out["empty"] == ["Enter your teammate's work email.", _BAD] and out["before"] == 1
    # sent and said as the list shows it (trimmed, lower case — the server compares it that way too)
    assert out["calls"] == [["POST", "api/customer/member/add", {"email": "new.mate@acme.io", "role": "analyst"}],
                            ["GET", "api/customer/members"]]
    assert out["toasts"] == ["new.mate@acme.io was added as Analyst."] and out["after"] == ["", "cust-team-msg"]


def test_change_role_sends_member_grant_with_the_chosen_role():
    out = _node(_app() + r"""
show(); await tick();
button(rowOf("cust_an"), "Change role").click(); await tick();
out.same = msg(); out.before = calls.length;
rowOf("cust_an").querySelector("select").value = "viewer";
button(rowOf("cust_an"), "Change role").click(); await tick(); await tick();
out.calls = calls.slice(1); out.toasts = toasts;
button(rowOf("op@acme.io"), "Change role").click(); await tick();      // nothing picked for the Operator yet
out.op = msg(); out.total = calls.length;
""")
    assert out["same"] == ["Choose a new role for cust_an first.", _BAD] and out["before"] == 1
    assert out["calls"] == [["POST", "api/customer/member/grant", {"member_username": "cust_an", "role": "viewer"}],
                            ["GET", "api/customer/members"]]
    assert out["toasts"] == ["cust_an is now Viewer."]
    assert out["op"] == ["Choose a new role for op@acme.io first.", _BAD] and out["total"] == 3


def test_remove_asks_in_the_page_first_and_only_yes_sends_member_revoke():
    out = _node(_app() + r"""
show(); await tick();
const box = name => rowOf(name).querySelector(".cust-member-confirm");
out.closed = box("cust_an").hidden;
button(rowOf("cust_an"), "Remove").click();
out.open = [box("cust_an").hidden, text(box("cust_an").querySelector("p")), buttons(box("cust_an"))];
out.afterAsk = calls.length;
button(box("cust_an"), "Cancel").click();
out.cancelled = [box("cust_an").hidden, box("cust_an").children.length, calls.length];
button(rowOf("cust_an"), "Remove").click();
button(box("cust_an"), "Yes, remove").click(); await tick(); await tick();
out.calls = calls.slice(1); out.toasts = toasts;
button(rowOf("me@acme.io"), "Remove").click();
out.self = text(box("me@acme.io").querySelector("p"));
""")
    assert out["closed"] is True
    assert out["open"] == [False, "Remove cust_an from this workspace? They lose access to it straight away.",
                           ["Yes, remove", "Cancel"]]
    assert out["afterAsk"] == 1 and out["cancelled"] == [True, 0, 1]       # asking and cancelling send nothing
    assert out["calls"] == [["POST", "api/customer/member/revoke", {"member_username": "cust_an"}],
                            ["GET", "api/customer/members"]]
    assert out["toasts"] == ["cust_an was removed from this workspace."]
    assert out["self"] == "Remove yourself from this workspace? You lose access to it straight away."


def test_a_step_up_refusal_asks_for_a_fresh_authenticator_code():
    out = _node(_app() + "const STEP = " + json.dumps(_STEP_UP) + r""";
show(); await tick();
postFail = STEP;
addCard().querySelector("input").value = "mate@acme.io";
button(addCard(), "Add member").click(); await tick();
out.add = msg(); out.addEnabled = !button(addCard(), "Add member").disabled;
postFail = STEP;
rowOf("cust_an").querySelector("select").value = "viewer";
button(rowOf("cust_an"), "Change role").click(); await tick();
out.change = msg();
postFail = STEP;
button(rowOf("cust_an"), "Remove").click();
button(rowOf("cust_an").querySelector(".cust-member-confirm"), "Yes, remove").click(); await tick();
out.remove = msg();
out.navs = navs; out.refreshed = refreshed; out.toasts = toasts;
out.posts = calls.filter(c => c[0] === "POST").length;
""")
    for k in ("add", "change", "remove"):
        assert out[k] == [_STEP_UP_SAID, _BAD], k
    assert out["addEnabled"] is True and out["posts"] == 3
    assert out["navs"] == [] and out["refreshed"] == 0 and out["toasts"] == []   # no sign-in bounce, nothing claimed


def test_a_role_that_cannot_manage_the_team_sees_an_honest_card():
    out = _node(_app() + r"""
listFail = { status: 403, data: { error: "denied: requester may not read this org (manage_members)" } };
show(); await tick();
out.card = text(root.querySelector("#cust-team")); out.buttons = buttons(root);
out.add = !!addCard(); out.calls = calls;
""")
    assert out["card"] == ("Only the workspace's founder and admins can see and change its team. Ask one of them to "
                           "add someone or to change a role.")
    assert out["buttons"] == [] and out["add"] is False and out["calls"] == [["GET", "api/customer/members"]]


def test_every_refusal_is_said_plainly():
    ui = UI_JS.read_text(encoding="utf-8")
    updating = re.search(r'const UPDATING_WRITE = "([^"]+)";', ui).group(1)        # the kit's own words
    cases = {
        "lastAdmin": {"status": 403, "data": {"error": "denied: cannot remove the last administrator of the org"}},
        "noAccount": {"status": 403, "data": {"error": "denied: " + provision._ADD_NO_ACCOUNT}},
        "already": {"status": 403, "data": {"error": "denied: " + provision._ADD_ALREADY_MEMBER}},
        "badEmail": {"status": 400, "data": {"error": "provision failed: " + provision._ADD_BAD_EMAIL}},
        "busy": {"status": 429, "data": {"error": "rate limited; retry after 41s"}},
        "updating": {"status": 503, "data": {"error": "updating"}, "message": updating},
        "lost": {"status": 502, "data": {"error": "provisioner unreachable"}},
        "offline": {},
    }
    out = _node(_app() + "const CASES = " + json.dumps(cases) + r""";
show(); await tick();
out.said = {}; out.reads = {};
for (const k of Object.keys(CASES)) {
  postFail = CASES[k];
  const n = calls.length;
  if (k === "lastAdmin") {
    button(rowOf("me@acme.io"), "Remove").click();
    button(rowOf("me@acme.io").querySelector(".cust-member-confirm"), "Yes, remove").click();
  } else {
    addCard().querySelector("input").value = "mate@acme.io";
    button(addCard(), "Add member").click();
  }
  await tick(); await tick();
  out.said[k] = msg();
  out.reads[k] = calls.slice(n + 1).filter(c => c[0] === "GET").length;
}
""")
    said = {k: v[0] for k, v in out["said"].items()}
    assert all(v[1] == _BAD for v in out["said"].values())
    assert said["lastAdmin"] == ("me@acme.io is the last person who can manage this workspace's team. Make another "
                                 "member an Admin first. Nothing was changed.")
    assert said["noAccount"] == ("There is no VIGIL account for that email. Ask your teammate to create one with "
                                 "Create an account on the sign-in screen, then add them again. Nothing was changed.")
    assert said["already"] == ("That person is already a member of this workspace. To give them another role, use "
                               "Change role on their row. Nothing was changed.")
    assert said["badEmail"] == "Enter the email address your teammate signs in to VIGIL with. Nothing was changed."
    assert said["busy"] == "Too many team changes in a short time. Wait a minute, then try again. Nothing was changed."
    assert said["updating"] == updating
    # no answer came back: the page cannot say nothing changed, so it reads the list again instead
    for k in ("lost", "offline"):
        assert said[k] == "VIGIL could not confirm the change. The list shows your team as it is now.", k
        assert out["reads"][k] == 1, k
    for k in ("lastAdmin", "noAccount", "already", "badEmail", "busy", "updating"):
        assert out["reads"][k] == 0, k


def test_a_session_that_ended_goes_to_sign_in():
    out = _node(_app() + r"""
listFail = { status: 401, data: { error: "login required" } };
show(); await tick();
out.load = [refreshed, navs.slice()];
show(); await tick();
postFail = { status: 401, data: { error: "login required" } };
addCard().querySelector("input").value = "mate@acme.io";
button(addCard(), "Add member").click(); await tick();
out.change = [refreshed, navs.slice(), msg()];
""")
    assert out["load"] == [1, ["#/login"]]
    assert out["change"] == [2, ["#/login", "#/login"], ["", "cust-team-msg"]]


def test_leaving_the_screen_before_the_list_arrives_changes_nothing():
    out = _node(_app() + r"""
let release;
VUI.getJSON = p => { calls.push(["GET", p]); return new Promise(r => { release = () => r({ members: members }); }); };
show();
location.hash = "#/billing";
release(); await tick();
out.rows = root.querySelectorAll(".cust-member").length; out.holder = text(root.querySelector("#cust-team"));
""")
    assert out["rows"] == 0 and out["holder"] == "Loading…"


def test_a_change_in_flight_cannot_be_sent_twice():
    out = _node(_app() + r"""
show(); await tick();
let release;
VUI.postJSON = (p, b) => { calls.push(["POST", p, b]); return new Promise(r => { release = () => r({ ok: true }); }); };
addCard().querySelector("input").value = "mate@acme.io";
const add = button(addCard(), "Add member");
add.click(); add.click(); add.click();
out.pending = calls.filter(c => c[0] === "POST").length;
release(); await tick(); await tick();
out.posts = calls.filter(c => c[0] === "POST").length;
""")
    assert out["pending"] == 1 and out["posts"] == 1


_FORBIDDEN = re.compile(r"\b(claude|anthropic|opus|sonnet|haiku|fable|strix|nyx|ultracode|gpt|openai|llm)\b"
                        r"|[$€£]\s?\d|\b\d[\d,.]*\s*credits?\b|\bmargin\b", re.IGNORECASE)


def test_the_team_screen_builds_every_element_with_h_and_asks_no_browser_dialog():
    src = APP_JS.read_text(encoding="utf-8")
    block = _team_block(src)
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "html:", "eval(", "new Function"):
        assert bad not in block, bad
    assert not re.search(r"(?<![\w.])(confirm|alert|prompt)\s*\(|window\.(confirm|alert|prompt)", src)
    # every call is relative to the mount (API = "api/customer"); these are the only member/invite ones (the invite
    # routes join once VIGIL_CUSTOMER_TEAM_INVITE wires the Team screen's e-mail invitations). /member/invite/revoke is
    # a three-segment path the two-segment regex does not capture, which is fine — it is the same invite plane.
    assert set(re.findall(r'"(/members?(?:/[a-z]+)?)"', block)) == {"/members", "/member/add", "/member/grant",
                                                                   "/member/revoke", "/member/invite", "/member/invites"}
    assert 'VUI.getJSON(API + "/members")' in block and "VUI.postJSON(API + path, body)" in block
    assert "org_id" not in block                                         # the page never names an org
    copy = " ".join(re.findall(r'"([^"]*)"', block))
    assert not _FORBIDDEN.search(copy), _FORBIDDEN.search(copy)


def test_the_guide_team_step_uses_the_screens_real_labels():
    out = _node(_app() + r"""
show(); await tick();
out.screen = root.querySelectorAll("button").map(text)
  .concat(root.querySelectorAll("label").map(text), root.querySelectorAll("h3").map(text));
button(rowOf("cust_an"), "Remove").click();
out.screen = out.screen.concat(buttons(rowOf("cust_an").querySelector(".cust-member-confirm")));
const t = window.VIGIL_GUIDE.findStep("workspace", "team").step;
out.clicks = t.clicks; out.why = t.why; out.route = t.route;
""")
    guide = "\n".join(out["clicks"])
    for label in ("Add member", "Change role", "Remove", "Yes, remove"):
        assert label in guide and label in out["screen"], label          # named in the guide, and really on screen
    assert "Under Add member" in guide and "work email" in guide and "Role" in out["screen"]
    assert "Create an account" in guide and 'text: "Create an account"' in APP_JS.read_text(encoding="utf-8")
    assert "founder's row has no buttons" in guide and "Remove next to" not in guide
    assert "the founder and admins can see and change the team" in out["why"] and out["route"] == "#/team"
