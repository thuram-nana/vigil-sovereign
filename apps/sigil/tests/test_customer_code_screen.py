"""C6 — the customer Code (Red-Pen) screen: Connect GitHub, the connected repositories and their Red-Pen policy, Red-Pen
System, Fix this / Retest on a finding, and Disconnect — the screen (app.js under node), the edge routes and the cockpit
actions behind them.

* The edge writes data-code="1" into the page only while VIGIL_REDPEN_ENABLED is on — the master Red-Pen flag that also
  serves the api/customer/code routes and the cockpit's redpen_* actions — and "0" otherwise: the same bytes for every
  off value, and the value counts in the build id. Off, every route and action is absent exactly as an unknown one, there
  is no Code tab, #/code is the home screen, the guide offers no "Go to Code", and nothing is fetched.
* The ORG is always the session's: the edge stamps it (a body or query org is ignored) and forwards only the repository
  and the choice. The GitHub post-install callback has no session (the cookie is SameSite=Strict) and carries no org at
  all: the provisioner takes it from the owner-signed state Connect GitHub minted.
* Only manage_code (the founder, an owner-granted operator) reads or changes code review; a billing admin, an analyst, a
  viewer and another workspace are refused, and the screen says so honestly.
* The callback records an installation ONLY once it is verified as the returning person's (the redirect's installation
  id is browser-controlled); with no verifier wired — the default — it records nothing and never asks GitHub.
* Review now / schedule / Fix this / Retest are guarded for real (manage_code, step-up, an ACTIVE connected repository of
  the session org) and answer an inert "coming" until their workers land; the screen offers only what is available.
* No payload or copy names a model, quotes a price or estimates; the install link is opened only when it is GitHub's own
  https install page.

app.js's own code is extracted verbatim and run on the customer UI kit (ui.js) with a minimal DOM; every page flag the
extracted code can reference is stubbed off, so the harness keeps working as other screens add theirs.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the edge always writes "1"                                  -> test_the_edge_writes_the_code_flag_into_the_page
  * a Code route / action / tab / "Go to" not gated by the flag  -> test_the_edge_routes_are_absent_with_the_flag_off,
                                                                    test_with_the_flag_off_the_app_is_unchanged
  * the cockpit serves redpen_* with the flag off                -> test_with_the_flag_off_nothing_answers_over_the_hop
  * the edge forwards a body org / an unlisted field, or acts with no session
                                                                 -> test_the_edge_relays_for_the_session_org_only
  * the callback skips its Host gate, or relays an oversized parameter
                                                                 -> test_the_github_callback_relays_the_state_only
  * the provisioner admits a role without manage_code            -> test_only_manage_code_reads_or_changes_code_review
  * a sensitive change skips the step-up                         -> test_a_sensitive_change_needs_a_fresh_second_factor
  * the overview leaks another tenant's repository               -> test_the_overview_shows_the_session_orgs_repositories_only
  * a forged / expired / other-kind state is honoured            -> test_connect_github_returns_githubs_page_with_a_signed_state
  * an unverified installation is recorded                       -> test_the_callback_records_nothing_until_the_installation_is_verified
  * an execution action runs on a repository that is not connected
                                                                 -> test_the_execution_actions_are_guarded_and_start_nothing
  * a non-GitHub install link is opened                          -> test_connect_github_opens_only_githubs_install_page
  * Disconnect sends without asking                              -> test_disconnect_asks_first_and_keep_it_connected_sends_nothing
  * an unavailable action is offered / a locked finding gets Fix this / another repository's findings are shown
                                                                 -> test_unavailable_actions_are_not_offered,
                                                                    test_a_manager_sees_connect_the_repositories_and_their_policy
  * the step-up answer treated as a sign-out / a refusal not said plainly
                                                                 -> test_every_refusal_is_said_plainly
  * a change bypasses the account-security step-up               -> test_a_sensitive_change_goes_through_the_step_up_when_present
  * GitHub's return prints the raw value                         -> test_back_from_github_says_what_happened_in_fixed_words
"""
from __future__ import annotations

import base64
import http.client
import itertools
import json
import re
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _post, _stack
from test_customer_onboarding import _FORBIDDEN as _COPY_FORBIDDEN
from test_customer_onboarding import _node as _guide_node
from test_customer_team import _edge_stub, _fn, _hop, _line, _node, _page_and_build, _signup

from sigil.governor import github_app
from sigil.governor.authn import signed_payload
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair, owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.redpen_spend import RedPenSpendLedger
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionError, Provisioner, ProvisionStepUpRequired
from sigil.ui.target_authorization import _customer_slug

FLAG = "VIGIL_REDPEN_ENABLED"
SLUG = "VIGIL_GITHUB_APP_SLUG"
APP_JS = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app" / "app.js"
API_REPO, WEB_REPO = "github.com/acme/api", "github.com/acme/web"
_clock = itertools.count(1)
_STEP_UP = {"status": 401, "data": {"error": "a fresh second-factor (step-up) is required for this operation",
                                    "step_up_required": True}}
_STEP_UP_SAID = ("For your security, this change needs a fresh second-factor check. Verify with your authenticator, then "
                 "try again. Nothing was changed.")


@pytest.fixture(autouse=True)
def _no_flags(monkeypatch):
    for var in (FLAG, SLUG, "VIGIL_CUSTOMER_STEPUP_REQUIRED", "VIGIL_GITHUB_APP_ID", "VIGIL_GITHUB_APP_PRIVATE_KEY",
                "VIGIL_GITHUB_APP_PRIVATE_KEY_SSM", "VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", "VIGIL_TRIAL_PREVIEW_ENABLED"):
        monkeypatch.delenv(var, raising=False)


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _code_block(src: str) -> str:
    """The Code screen's own section of app.js, verbatim (the harness runs what ships, not a copy of it)."""
    i = src.index("  // ---- Code (Red-Pen, VIGIL_REDPEN_ENABLED)")
    return src[i:src.index("  // ---- notification centre", i)]


# --- the edge flag ------------------------------------------------------------------------------------------------------
def test_the_edge_writes_the_code_flag_into_the_page(tmp_path, monkeypatch):
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-code="0"' in off and "__VIGIL_CODE__" not in off
    for v in ("0", "", "no", "maybe"):                         # every off value serves the very same page
        monkeypatch.setenv(FLAG, v)
        assert _page_and_build(tmp_path / f"c{v or 'empty'}") == (off, build_off), v
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-code="1"' in on and build_on != build_off    # a new build the open pages are told about
    # the flag is the page's only difference: its value, and the build id it changes
    assert on.replace('data-code="1"', 'data-code="0"').replace(build_on, build_off) == off


# --- with the flag off, the app is exactly what it was -------------------------------------------------------------------
_VIEWS = ("viewDashboard", "viewLogin", "viewSignup", "viewRecover", "viewGoogleCode", "viewBilling", "viewBillingReturn",
          "viewInvoices", "viewAssets", "viewAssessments", "viewGuideScreen", "viewMonitoring", "viewTeam", "viewCode",
          "viewSecurityScreen")
# Every page flag the extracted code may reference, off. CODE_ON is then re-read from the page by app.js's own line.
_FLAGS_OFF = ("var GUIDE = null, GUIDE_ON = false, SECURITY_ON = false, TEAM_ON = false, MONITORING_ON = false, "
              "LAUNCH_ON = false, CODE_ON = false, SETTINGS_ON = false;")


def _wiring(flag: str, script: str) -> dict:
    """app.js's own top bar (shell + navLink), routeShown and route table, verbatim, over stub screens."""
    src = _src()
    i = src.index("  var ROUTES = {")
    world = "\n".join([
        f"document.body.dataset.code = {json.dumps(flag)};",
        'globalThis.location = { hash: "#/code" };',
        'let who = { authenticated: true, username: "ana" };',
        "const state = { get: () => ({ who }) };",
        "function authed() { return !!(who && who.authenticated); }",
        "const calls = []; const VUI = window.VUI;",
        "VUI.getJSON = async p => { calls.push(['GET', p]); return {}; };",
        "VUI.postJSON = async (p, b) => { calls.push(['POST', p, b]); return {}; };",
        "function nav(r) { location.hash = r; }",
        "function ntfWidget() { return null; }\nasync function doLogout() {}",
        'function viewSoon(t) { return "viewSoon:" + t; }',
        _FLAGS_OFF] + [f"function {v}() {{ return {json.dumps(v)}; }}" for v in _VIEWS])
    return _node("\n".join([world, _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                            _line(src, r'^  var CODE_ON = pageFlag\("code"\);$'), _fn(src, "navLink"),
                            _fn(src, "shell"), _line(src, r"^  function routeShown\(route\) \{.*\}$"),
                            src[i:src.index("\n  };", i) + 5], script]))


def test_with_the_flag_off_the_app_is_unchanged():
    script = r"""
out.links = shell(h("div"), "#/").querySelectorAll("button.cust-nav-link").map(b => text(b));
out.route = ROUTES["#/code"](); out.home = ROUTES["#/"]();
who = { authenticated: false }; out.signedOut = ROUTES["#/code"](); who = { authenticated: true, username: "ana" };
out.shown = [routeShown("#/code"), routeShown("#/billing"), routeShown("#/monitoring")];
await tick();
out.calls = calls;
"""
    for flag in ("0", "", "__VIGIL_CODE__"):
        off = _wiring(flag, script)
        assert off["links"] == ["Overview", "Billing", "Invoices", "Assets", "Assessments", "Team", "Sign out (ana)"], flag
        assert off["route"] == off["home"] == "viewDashboard" and off["signedOut"] == "viewLogin", flag
        assert off["shown"] == [False, True, False] and off["calls"] == [], flag      # no "Go to Code", no call
    on = _wiring("1", script)
    assert on["links"] == ["Overview", "Billing", "Invoices", "Assets", "Assessments", "Team", "Code", "Sign out (ana)"]
    assert on["route"] == "viewCode" and on["signedOut"] == "viewLogin" and on["shown"] == [True, True, False]
    src = _src()
    assert '.concat(CODE_ON ? [navLink("Code", "#/code")] : [])' in src and "shown: routeShown" in _fn(
        src, "viewGuideScreen")


# --- the edge -------------------------------------------------------------------------------------------------------------
_SESSION = {"username": "cust_fo", "org_id": "org_a", "mfa_at": 123.0}
# What the screen sends for each action, and the cockpit action it must reach.
_BODIES = {
    "code/connect": ({}, "redpen_connect"),
    "code/settings": ({"repo": API_REPO, "block_threshold": "medium_up", "monthly_limit_credits": 50}, "redpen_set_settings"),
    "code/disconnect": ({"repo": API_REPO}, "redpen_disconnect"),
    "code/review": ({"repo": API_REPO}, "redpen_review"),
    "code/schedule": ({"repo": API_REPO, "cadence": "weekly"}, "redpen_schedule"),
    "code/fix": ({"repo": API_REPO, "finding_ref": "f1"}, "redpen_fix_this"),
    "code/retest": ({"repo": API_REPO, "finding_ref": "f1"}, "redpen_retest"),
}
_SMUGGLED = {"org_id": "org_b", "requester": "cust_bb", "mfa_at": 9e9, "username": "cust_bb", "installation_id": 7,
             "units": 999, "price_id": "x", "state": "s"}


def test_the_edge_routes_are_absent_with_the_flag_off():
    for path in ("/api/customer/code", "/api/customer/code/connected?state=s&installation_id=1&setup_action=install"):
        h, sent = _edge_stub(dict(_SESSION))
        h.path = path
        h.do_GET()
        h2, unknown = _edge_stub(dict(_SESSION))
        h2.path = "/api/customer/nope"
        h2.do_GET()
        assert sent == unknown == {"code": 404, "out": {"error": "not found"}}, path
    for action, (body, _target) in _BODIES.items():
        h, sent = _edge_stub(dict(_SESSION))
        h._dispatch(action, dict(body))
        h2, unknown = _edge_stub(dict(_SESSION))
        h2._dispatch("no/such/route", {})
        assert sent == unknown == {"code": 404, "out": {"error": "unknown action"}}, action


def test_the_edge_relays_for_the_session_org_only(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    h, sent = _edge_stub(dict(_SESSION))
    h.path = "/api/customer/code?org_id=org_b&username=cust_bb"
    h.do_GET()
    assert sent == {"action": "redpen_code_overview", "principal": "cust_fo",
                    "body": {"org_id": "org_a", "ip": "1.2.3.4"}, "code": 200, "out": {"ok": True}}
    for action, (body, target) in _BODIES.items():
        h, sent = _edge_stub(dict(_SESSION))
        h._dispatch(action, {**body, **_SMUGGLED})
        assert sent["action"] == target and sent["principal"] == "cust_fo", action
        # only the repository and the choice travel; the org, the requester and the step-up stamp are the session's
        assert sent["body"] == {"org_id": "org_a", "ip": "1.2.3.4", "mfa_at": 123.0, **body}, action
    for session in (None, {}, {"username": "cust_fo"}, {"username": "cust_fo", "org_id": ""}):
        for action, (body, _target) in _BODIES.items():
            h, sent = _edge_stub(session)
            h._dispatch(action, dict(body))
            assert sent["code"] == 401 and "action" not in sent, (session, action)
        h, sent = _edge_stub(session)
        h.path = "/api/customer/code"
        h.do_GET()
        assert sent["code"] == 401 and "action" not in sent, session


def _callback(path: str, *, host: str = "127.0.0.1:8734",
              reply=(200, {"org_id": "org_a", "recorded": False, "verification_required": True, "connected": []})):
    """The edge's GitHub post-install callback, with its hop stubbed: what does it relay, and where does it send the
    browser? GitHub's redirect carries no customer session."""
    h, sent = _edge_stub(None)
    h._provision = lambda action, principal, body: sent.update(action=action, principal=principal, body=body) or reply
    h.headers = {"Host": host}
    h.server = SimpleNamespace(allowed_hosts=frozenset({"127.0.0.1:8734"}), app=SimpleNamespace(build="b0"))
    resp: dict = {"headers": {}}
    h.send_response = lambda code: resp.update(code=code)
    h.send_header = lambda k, v: resp["headers"].update({k: v})
    h.end_headers = lambda: resp.update(ended=True)
    h.path = path
    h.do_GET()
    return sent, resp


def test_the_github_callback_relays_the_state_only(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    q = "/api/customer/code/connected?installation_id=42&setup_action=install&state=S1&code=C1&org_id=org_b"
    sent, resp = _callback(q)
    # no org rides along (a query org is ignored) and the hop has no principal: the org comes from the signed state
    assert sent["action"] == "redpen_connect_record" and sent["principal"] == ""
    assert sent["body"] == {"state": "S1", "installation_id": "42", "setup_action": "install", "code": "C1",
                            "ip": "1.2.3.4"}
    assert resp["code"] == 302 and resp["ended"] is True and resp["headers"]["Location"] == "/#/code?connected=0"
    assert resp["headers"]["Referrer-Policy"] == "no-referrer" and resp["headers"]["Cache-Control"] == "no-store"
    for reply, outcome in (((200, {"recorded": True, "connected": [API_REPO]}), "1"),
                           ((200, {"recorded": False, "pending": True}), "pending"),
                           ((403, {"error": "denied: this GitHub connection link is invalid or has expired"}), "0"),
                           ((502, {"error": "provisioner unreachable"}), "0")):
        _, resp = _callback(q, reply=reply)
        assert resp["headers"]["Location"] == f"/#/code?connected={outcome}", reply
    # an oversized or repeated parameter is relayed EMPTY (the provisioner then refuses it), never cut to size
    sent, _ = _callback("/api/customer/code/connected?state=" + "A" * 5000 + "&installation_id=1&installation_id=2"
                        "&setup_action=install")
    assert sent["body"]["state"] == "" and sent["body"]["installation_id"] == ""
    # a foreign Host is refused before any hop, and nothing is redirected
    sent, resp = _callback(q, host="evil.example")
    assert sent == {"code": 403, "out": {"error": "denied (host)"}} and "code" not in resp


# --- the provisioner -------------------------------------------------------------------------------------------------------
def _prov(tmp_path, monkeypatch, *, verifier=None):
    """A provisioner with two workspaces. org_a: its founder, an owner-granted operator, a billing admin, an analyst and a
    viewer; org_b: its founder. Every registry uses the vault owner key the Code actions sign with. The founder-tester
    kill switch is ON here, so a founder is admitted as a founder (with it OFF a founder is admitted as org_admin and
    loses manage_code with the rest of its testing — same as run_engagement; an owner-granted operator keeps it either
    way)."""
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv("VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", "1")
    ensure_owner_keypair()
    kp = owner_keypair()
    pub = kp.public_key_b64
    tmp_path.mkdir(parents=True, exist_ok=True)
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    p = Provisioner(s, customers=CustomerRegistry(s, owner_key=kp, trusted_pubkey=pub),
                    orgs=OrgRegistry(s, owner_key=kp, trusted_pubkey=pub),
                    wallet=WalletRegistry(s, owner_key=kp, trusted_pubkey=pub),
                    email_tokens=EmailTokenLedger(str(tmp_path / "tokens"), ttl_s=1e4),
                    rate_limiter=LoginRateLimiter(str(tmp_path / "rl"), max_fails=50, window_s=1e4, base_lock_s=50.0),
                    email_sender=NullEmailSender(), installation_verifier=verifier)
    for name in ("fo", "op", "ad", "an", "vi", "bb"):
        p.customers.create(f"{name}@acme.io", issued_at=float(next(_clock)), username=f"cust_{name}")
    p.orgs.create_org("org_a", "Acme", owner="cust_fo", issued_at=float(next(_clock)))
    p.orgs.create_org("org_b", "Beta", owner="cust_bb", issued_at=float(next(_clock)))
    for org, u, r in (("org_a", "cust_fo", "founder"), ("org_a", "cust_op", "operator"), ("org_a", "cust_ad", "org_admin"),
                      ("org_a", "cust_an", "analyst"), ("org_a", "cust_vi", "viewer"), ("org_b", "cust_bb", "founder")):
        p.orgs.grant_membership(org, u, r, issued_at=float(next(_clock)))
    return p, s


def _connect(p, org, repo, *, threshold="critical_high", limit=0, iid=42):
    """Connect a repository directly (no GitHub egress), through the provisioner's own strictly-increasing issued_at so
    a test connect is never stale against a record the provisioner minted (set_settings / connect_record use the same
    source)."""
    return ConnectedRepoRegistry(p.store).connect(org, iid, repo, block_threshold=threshold,
                                                  monthly_limit_credits=limit, issued_at=p._next_issued())


def _audits(s, action):
    return [r.payload for r in s.iter_records() if isinstance(r.payload, dict)
            and r.payload.get("signal") == "provision.audit" and r.payload.get("action") == action]


def _records(s) -> int:
    return sum(1 for _ in s.iter_records())


# Each Code action as the screen sends it, for (requester, org), with the session's step-up stamp.
_ACTIONS = {
    "redpen_code_overview": lambda p, u, o, mfa=0.0: p.redpen_code_overview(u, o),
    "redpen_connect": lambda p, u, o, mfa=0.0: p.redpen_connect(u, o, mfa_at=mfa),
    "redpen_set_settings": lambda p, u, o, mfa=0.0: p.redpen_set_settings(u, o, API_REPO, block_threshold="none",
                                                                          mfa_at=mfa),
    "redpen_disconnect": lambda p, u, o, mfa=0.0: p.redpen_disconnect(u, o, API_REPO),
    "redpen_review": lambda p, u, o, mfa=0.0: p.redpen_review(u, o, API_REPO, mfa_at=mfa),
    "redpen_schedule": lambda p, u, o, mfa=0.0: p.redpen_schedule(u, o, API_REPO, cadence="weekly", mfa_at=mfa),
    "redpen_fix_this": lambda p, u, o, mfa=0.0: p.redpen_fix_this(u, o, API_REPO, "f1", mfa_at=mfa),
    "redpen_retest": lambda p, u, o, mfa=0.0: p.redpen_retest(u, o, API_REPO, "f1", mfa_at=mfa),
}


def test_only_manage_code_reads_or_changes_code_review(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    monkeypatch.setenv(SLUG, "vigil-red-pen")
    for name, call in _ACTIONS.items():
        # a billing admin, an analyst, a viewer, another workspace's founder and a stranger: refused (never "not
        # connected" — the repository IS connected), and audited
        for who in ("cust_ad", "cust_an", "cust_vi", "cust_bb", "cust_nobody"):
            _connect(p, "org_a", API_REPO)
            with pytest.raises(ProvisionDenied, match="may not manage code review"):
                call(p, who, "org_a")
        for who in ("cust_fo", "cust_op"):                       # the founder and an owner-granted operator
            _connect(p, "org_a", API_REPO)
            assert call(p, who, "org_a")["org_id"] == "org_a", (name, who)
        assert any(a["outcome"] == "denied" and a["requester"] == "cust_ad" for a in _audits(s, name)), name


def test_with_the_flag_off_every_code_action_refuses(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    _connect(p, "org_a", API_REPO)
    monkeypatch.delenv(FLAG)
    for name, call in _ACTIONS.items():
        with pytest.raises(ProvisionDenied, match="not enabled"):
            call(p, "cust_fo", "org_a")
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.redpen_connect_record(state="x", installation_id="1", setup_action="install")


def test_a_sensitive_change_needs_a_fresh_second_factor(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    monkeypatch.setenv(SLUG, "vigil-red-pen")
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    _connect(p, "org_a", API_REPO)
    sensitive = [n for n in _ACTIONS if n not in ("redpen_code_overview", "redpen_disconnect")]
    for name in sensitive:
        with pytest.raises(ProvisionStepUpRequired):
            _ACTIONS[name](p, "cust_fo", "org_a")
        with pytest.raises(ProvisionStepUpRequired):
            _ACTIONS[name](p, "cust_fo", "org_a", mfa=time.time() - 3600)    # a stale factor
        with pytest.raises(ProvisionDenied):                                  # authority first: never "step up"
            _ACTIONS[name](p, "cust_vi", "org_a")
        assert _ACTIONS[name](p, "cust_fo", "org_a", mfa=time.time())["org_id"] == "org_a", name
    # reading and disconnecting (the safe direction) never ask for one
    assert _ACTIONS["redpen_code_overview"](p, "cust_fo", "org_a")["org_id"] == "org_a"
    assert _ACTIONS["redpen_disconnect"](p, "cust_fo", "org_a")["disconnected"] is True


def test_the_overview_shows_the_session_orgs_repositories_only(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    _connect(p, "org_a", API_REPO, threshold="medium_up", limit=100)
    _connect(p, "org_a", WEB_REPO)
    _connect(p, "org_b", "github.com/beta/secret")
    _connect(p, "org_a", "github.com/acme/old")
    ConnectedRepoRegistry(s, owner_key=None).disconnect("org_a", "github.com/acme/old")
    now = time.time()
    RedPenSpendLedger(s).record_charge("org_a", API_REPO, 40, nonce="n1", now=now)
    RedPenSpendLedger(s).record_charge("org_b", "github.com/beta/secret", 7, nonce="n2", now=now)
    assert p.redpen_code_overview("cust_fo", "org_a", now=now) == {"org_id": "org_a", "repos": [
        {"repo": API_REPO, "slug": _customer_slug("org_a", API_REPO), "block_threshold": "medium_up",
         "monthly_limit_credits": 100, "used_this_month": 40},
        {"repo": WEB_REPO, "slug": _customer_slug("org_a", WEB_REPO), "block_threshold": "critical_high",
         "monthly_limit_credits": 0}],
        "available": {"connect": False, "review": False, "schedule": False, "fix": False, "retest": False}}
    monkeypatch.setenv(SLUG, "vigil-red-pen")
    assert p.redpen_code_overview("cust_op", "org_a")["available"]["connect"] is True
    assert [r["repo"] for r in p.redpen_code_overview("cust_bb", "org_b")["repos"]] == ["github.com/beta/secret"]


def test_settings_change_the_owner_signed_policy_of_a_connected_repository(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    _connect(p, "org_a", API_REPO)
    _connect(p, "org_b", API_REPO)                               # the same repository, connected by another workspace
    reg = ConnectedRepoRegistry(s, owner_key=None)
    got = p.redpen_set_settings("cust_fo", "org_a", API_REPO, block_threshold="none", monthly_limit_credits=25)
    assert got == {"org_id": "org_a", "repo": API_REPO, "block_threshold": "none", "monthly_limit_credits": 25}
    rec = reg.active("org_a", API_REPO)
    assert (rec.block_threshold.value, rec.monthly_limit_credits) == ("none", 25)    # owner-signed and honoured
    assert reg.active("org_b", API_REPO).block_threshold.value == "critical_high"     # the other tenant untouched
    p.redpen_set_settings("cust_op", "org_a", API_REPO, monthly_limit_credits="0")    # only the limit: threshold kept
    rec = reg.active("org_a", API_REPO)
    assert (rec.block_threshold.value, rec.monthly_limit_credits) == ("none", 0)
    for bad in ({"block_threshold": "low"}, {"monthly_limit_credits": -1}, {"monthly_limit_credits": True},
                {"monthly_limit_credits": 2.5}, {"monthly_limit_credits": "ten"}, {}):
        with pytest.raises(ProvisionError):
            p.redpen_set_settings("cust_fo", "org_a", API_REPO, **bad)
    with pytest.raises(ProvisionDenied, match="not connected"):
        p.redpen_set_settings("cust_fo", "org_a", "github.com/acme/none", block_threshold="none")
    with pytest.raises(ProvisionError, match="github.com/<owner>/<repo>"):
        p.redpen_set_settings("cust_fo", "org_a", "https://github.com/acme/api", block_threshold="none")


def test_disconnect_is_the_safe_direction_and_idempotent(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    _connect(p, "org_a", API_REPO)
    _connect(p, "org_b", API_REPO)
    reg = ConnectedRepoRegistry(s, owner_key=None)
    assert p.redpen_disconnect("cust_op", "org_a", API_REPO) == {"org_id": "org_a", "repo": API_REPO,
                                                                 "disconnected": True}
    assert reg.active("org_a", API_REPO) is None and reg.active("org_b", API_REPO) is not None
    assert p.redpen_disconnect("cust_op", "org_a", API_REPO)["disconnected"] is False        # idempotent
    assert [a["outcome"] for a in _audits(s, "redpen_disconnect")] == ["disconnected", "noop"]


def _state_of(url: str) -> str:
    return parse_qs(urlparse(url).query)["state"][0]


def _b64(payload: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def _claims(state: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(state + "=" * (-len(state) % 4)))


def test_connect_github_returns_githubs_page_with_a_signed_state(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    for slug in (None, "evil.example/x", "-bad", "a" * 40):         # no (or no valid) App registered: never a dead link
        if slug is not None:
            monkeypatch.setenv(SLUG, slug)
        with pytest.raises(ProvisionDenied, match="not set up"):
            p.redpen_connect("cust_fo", "org_a")
    monkeypatch.setenv(SLUG, "VIGIL-Red-Pen")
    url = p.redpen_connect("cust_fo", "org_a", now=1000.0)["install_url"]
    u = urlparse(url)
    assert (u.scheme, u.netloc, u.path) == ("https", "github.com", "/apps/vigil-red-pen/installations/new")
    state = _state_of(url)
    assert p._redpen_state_org(state, now=1000.0) == "org_a"
    assert p._redpen_state_org(state, now=1000.0 + 15 * 60 + 1) is None              # a stale link is refused
    claims = _claims(state)
    assert set(claims) == {"kind", "org_id", "exp", "nonce", "sig", "pubkey"}         # nothing secret inside
    tampered = dict(claims, org_id="org_b")                                           # aimed at another tenant
    core = {k: claims[k] for k in ("kind", "org_id", "exp", "nonce")}
    other_key = signed_payload({**core, "org_id": "org_b"}, generate_keypair())        # re-signed by someone else
    other_kind = signed_payload({**core, "kind": "redpen_other"}, owner_keypair())     # another purpose's signature
    for bad in (_b64(tampered), _b64(other_key), _b64(other_kind), "not-base64!", _b64({"org_id": "org_a"}), "",
                "A" * 3000):
        assert p._redpen_state_org(bad, now=1000.0) is None, bad[:40]
    # each workspace gets its own state
    assert p._redpen_state_org(_state_of(p.redpen_connect("cust_bb", "org_b", now=1000.0)["install_url"]),
                               now=1000.0) == "org_b"


def test_the_callback_records_nothing_until_the_installation_is_verified(tmp_path, monkeypatch):
    seen = []

    def verifier(*, installation_id, code):
        seen.append((installation_id, code))
        return code == "good"

    p, s = _prov(tmp_path, monkeypatch, verifier=verifier)
    monkeypatch.setenv(SLUG, "vigil-red-pen")
    state = _state_of(p.redpen_connect("cust_fo", "org_a")["install_url"])
    real_mint = github_app.mint_installation_token
    gh = []
    monkeypatch.setattr(github_app, "mint_installation_token", lambda iid: gh.append(("mint", iid)) or {"token": "t-1"})
    monkeypatch.setattr(github_app, "list_installation_repositories", lambda tok: gh.append(("list", tok)) or {
        "repositories": [{"full_name": "acme/api"}, {"full_name": "acme/web"}, {"full_name": "bad name"}, "junk"]})
    reg = ConnectedRepoRegistry(s, owner_key=None)
    # unverified: the browser-controlled installation id is not proven to be the returning person's — nothing recorded,
    # and GitHub is never even asked
    out = p.redpen_connect_record(state=state, installation_id="42", setup_action="install", code="bad")
    assert out == {"org_id": "org_a", "recorded": False, "verification_required": True, "connected": []}
    assert gh == [] and reg.repos_of_org("org_a") == [] and seen == [(42, "bad")]
    # verified: every repository the installation was granted is connected, owner-signed, for the STATE's org
    out = p.redpen_connect_record(state=state, installation_id="42", setup_action="install", code="good")
    assert out == {"org_id": "org_a", "recorded": True, "connected": [API_REPO, WEB_REPO]}
    assert gh == [("mint", 42), ("list", "t-1")]
    assert [(r.repo, r.installation_id) for r in reg.repos_of_org("org_a")] == [(API_REPO, 42), (WEB_REPO, 42)]
    assert reg.repos_of_org("org_b") == []
    # an update keeps a repository's policy
    p.redpen_set_settings("cust_fo", "org_a", API_REPO, block_threshold="none", monthly_limit_credits=9)
    p.redpen_connect_record(state=state, installation_id="42", setup_action="update", code="good")
    rec = reg.active("org_a", API_REPO)
    assert (rec.block_threshold.value, rec.monthly_limit_credits) == ("none", 9)
    # no verifier wired (the default): nothing is recorded, ever
    p.installation_verifier = None
    gh.clear()
    assert p.redpen_connect_record(state=state, installation_id="43", setup_action="install",
                                   code="good")["verification_required"] is True and gh == []
    p.installation_verifier = verifier
    # a bad link, an org owner's approval still pending, another setup action, a malformed installation id
    with pytest.raises(ProvisionDenied, match="invalid or has expired"):
        p.redpen_connect_record(state="garbage", installation_id="42", setup_action="install", code="good")
    assert p.redpen_connect_record(state=state, setup_action="request") == {"org_id": "org_a", "recorded": False,
                                                                            "pending": True, "connected": []}
    assert p.redpen_connect_record(state=state, installation_id="42", setup_action="delete",
                                   code="good")["recorded"] is False
    for bad in ("", "0", "-1", "1e3", "42 ", "9" * 13):
        with pytest.raises(ProvisionDenied, match="valid installation"):
            p.redpen_connect_record(state=state, installation_id=bad, setup_action="install", code="good")
    # GitHub refuses — or no App is registered here yet (the real exchange): nothing recorded, never a crash
    monkeypatch.setattr(github_app, "mint_installation_token", real_mint)
    out = p.redpen_connect_record(state=state, installation_id="44", setup_action="install", code="good")
    assert out == {"org_id": "org_a", "recorded": False, "connected": []}
    assert any(a["outcome"] == "github_refused" for a in _audits(s, "redpen_connect_record"))


def test_the_execution_actions_are_guarded_and_start_nothing(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    execution = ("redpen_review", "redpen_schedule", "redpen_fix_this", "redpen_retest")
    _connect(p, "org_b", API_REPO)                               # connected by ANOTHER workspace only
    for name in execution:
        with pytest.raises(ProvisionDenied, match="not connected"):
            _ACTIONS[name](p, "cust_fo", "org_a")
    _connect(p, "org_a", API_REPO)
    n = _records(s)
    outs = {name: _ACTIONS[name](p, "cust_fo", "org_a") for name in execution}
    repo = {"org_id": "org_a", "repo": API_REPO, "coming": True}
    assert outs == {"redpen_review": repo, "redpen_schedule": {**repo, "cadence": "weekly"},
                    "redpen_fix_this": {**repo, "finding_ref": "f1"}, "redpen_retest": {**repo, "finding_ref": "f1"}}
    assert _records(s) == n                     # nothing reserved, charged, enqueued or recorded until the worker lands
    with pytest.raises(ProvisionError, match="cadence"):
        p.redpen_schedule("cust_fo", "org_a", API_REPO, cadence="daily")
    for ref in ("", "a b", "x" * 201):
        with pytest.raises(ProvisionError, match="finding reference"):
            p.redpen_fix_this("cust_fo", "org_a", API_REPO, ref)


# --- the edge and the cockpit, over the real hop ---------------------------------------------------------------------------
def _manager(sov, ep, email):
    """A signed-up customer whom the owner made an operator of their workspace (operator carries manage_code)."""
    op, u, oid = _signup(ep, email)
    OrgRegistry(sov.store()).grant_membership(oid, u, "operator", issued_at=time.time() + 2e6)
    return op, u, oid


def _location(port: int, path: str) -> str:
    """GET the callback the way GitHub's redirect does (a foreign Referer, no cookie) and return where it sends the
    browser."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", path, headers={"Host": f"127.0.0.1:{port}", "Referer": "https://github.com/"})
    r = c.getresponse()
    r.read()
    assert r.status == 302, r.status
    return r.getheader("Location")


def test_the_code_routes_over_the_real_hop(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _sp = _stack(tmp_path, monkeypatch)
    try:
        op, _u, oid = _manager(sov, ep, "fo@acme.io")
        admin, _a, other = _signup(ep, "ad@beta.io", "Beta")       # a default sign-up: the billing admin of Beta
        reg = ConnectedRepoRegistry(sov.store())
        reg.connect(oid, 42, API_REPO, issued_at=time.time())
        reg.connect(other, 43, "github.com/beta/secret", issued_at=time.time())
        c, r = _get(op, ep, f"/api/customer/code?org_id={other}")
        assert c == 200 and r["org_id"] == oid and [x["repo"] for x in r["repos"]] == [API_REPO], (c, r)
        # a billing admin can neither read nor change code review
        assert _get(admin, ep, "/api/customer/code")[0] == 403
        assert _post(admin, ep, "/api/customer/code/disconnect", {"repo": "github.com/beta/secret"})[0] == 403
        assert reg.active(other, "github.com/beta/secret") is not None
        # settings: the session org's record changes; a body org is ignored
        c, r = _post(op, ep, "/api/customer/code/settings", {"repo": API_REPO, "block_threshold": "medium_up",
                                                             "monthly_limit_credits": 30, "org_id": other})
        assert c == 200 and r == {"org_id": oid, "repo": API_REPO, "block_threshold": "medium_up",
                                  "monthly_limit_credits": 30}, (c, r)
        # Connect GitHub: refused until the owner registers the App here, then GitHub's page with a signed state
        c, r = _post(op, ep, "/api/customer/code/connect", {})
        assert c == 403 and "not set up" in r["error"], (c, r)
        monkeypatch.setenv(SLUG, "vigil-red-pen")
        c, r = _post(op, ep, "/api/customer/code/connect", {})
        assert c == 200 and r["install_url"].startswith("https://github.com/apps/vigil-red-pen/installations/new?state=")
        state = _state_of(r["install_url"])
        # GitHub sends the browser back: no session, no org — and with no verifier wired, nothing is recorded
        assert _location(ep, f"/api/customer/code/connected?installation_id=77&setup_action=install&state={state}"
                         ) == "/#/code?connected=0"
        assert [x.repo for x in reg.repos_of_org(oid)] == [API_REPO]
        assert _location(ep, f"/api/customer/code/connected?setup_action=request&state={state}"
                         ) == "/#/code?connected=pending"
        assert _location(ep, "/api/customer/code/connected?installation_id=77&setup_action=install&state=forged"
                         ) == "/#/code?connected=0"
        # Red-Pen System and the finding actions: guarded for real, inert until their workers land
        c, r = _post(op, ep, "/api/customer/code/review", {"repo": API_REPO})
        assert c == 200 and r == {"org_id": oid, "repo": API_REPO, "coming": True}, (c, r)
        assert _post(op, ep, "/api/customer/code/review", {"repo": "github.com/beta/secret"})[0] == 403
        for path, extra in (("schedule", {"cadence": "monthly"}), ("fix", {"finding_ref": "f1"}),
                            ("retest", {"finding_ref": "f1"})):
            c, r = _post(op, ep, f"/api/customer/code/{path}", {"repo": API_REPO, **extra})
            assert c == 200 and r["coming"] is True, (path, c, r)
        c, r = _post(op, ep, "/api/customer/code/disconnect", {"repo": API_REPO})
        assert c == 200 and r["disconnected"] is True and reg.active(oid, API_REPO) is None
        assert reg.active(other, "github.com/beta/secret") is not None
    finally:
        sov.shutdown()
        edge.shutdown()


def test_with_the_flag_off_nothing_answers_over_the_hop(tmp_path, monkeypatch):
    sov, edge, ep, sp = _stack(tmp_path, monkeypatch)
    try:
        op, u, oid = _manager(sov, ep, "fo@acme.io")
        unknown_get, unknown_post = _get(op, ep, "/api/customer/nope"), _post(op, ep, "/api/customer/no/such", {})
        assert unknown_get == (404, {"error": "not found"}) and unknown_post == (404, {"error": "unknown action"})
        for path in ("/api/customer/code", "/api/customer/code/connected?state=s&installation_id=1&setup_action=install"):
            assert _get(op, ep, path) == unknown_get, path
        for action, (body, _target) in _BODIES.items():
            assert _post(op, ep, f"/api/customer/{action}", body) == unknown_post, action
        # and the cockpit has no redpen_* action either: a signed hop straight to it is an unknown action
        targets = sorted({t for _b, t in _BODIES.values()} | {"redpen_code_overview", "redpen_connect_record"})
        for action in targets:
            assert _hop(sp, action, u, {"org_id": oid}) == (404, {"error": "unknown provision action"}), action
        monkeypatch.setenv(FLAG, "1")                              # read on every request: on, the hop answers
        assert _hop(sp, "redpen_code_overview", u, {"org_id": oid})[0] == 200
    finally:
        sov.shutdown()
        edge.shutdown()


# --- nothing names a model, quotes a price or estimates; no secret leaves ----------------------------------------------------
_LEAK = re.compile(r"\b(claude|anthropic|opus|sonnet|haiku|fable|strix|nyx|ultracode|gpt|openai|llm|model\w*)\b"
                   r"|[$€£]\s?\d|\b(usd|eur|gbp|currency|amount\w*|price\w*|cost\w*|units?|estimat\w*|quot\w*|"
                   r"predict\w*|token\w*|secret\w*|private\w*|pem)\b", re.IGNORECASE)


def test_no_code_payload_names_a_model_quotes_a_price_or_carries_a_secret(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv(SLUG, "vigil-red-pen")
    p, s = _prov(tmp_path, monkeypatch, verifier=lambda **_k: True)
    _connect(p, "org_a", API_REPO, threshold="medium_up", limit=100)
    RedPenSpendLedger(s).record_charge("org_a", API_REPO, 40, nonce="n1", now=time.time())
    monkeypatch.setattr(github_app, "mint_installation_token", lambda iid: {"token": "ghs_SECRET-INSTALL-TOKEN"})
    monkeypatch.setattr(github_app, "list_installation_repositories",
                        lambda tok: {"repositories": [{"full_name": "acme/web", "private": True}]})
    connect = p.redpen_connect("cust_fo", "org_a")
    state = _state_of(connect["install_url"])
    payloads = [p.redpen_code_overview("cust_fo", "org_a"),
                {**connect, "install_url": connect["install_url"].replace(state, "STATE")},
                p.redpen_connect_record(state=state, installation_id="42", setup_action="install", code="c"),
                p.redpen_set_settings("cust_fo", "org_a", API_REPO, block_threshold="none", monthly_limit_credits=5),
                *(_ACTIONS[n](p, "cust_fo", "org_a") for n in ("redpen_review", "redpen_schedule", "redpen_fix_this",
                                                               "redpen_retest")),
                p.redpen_disconnect("cust_fo", "org_a", API_REPO)]
    blob = json.dumps(payloads)
    assert not _LEAK.search(blob), _LEAK.search(blob).group(0)
    assert "ghs_" not in blob and "SECRET" not in blob                 # the installation token never leaves the cockpit
    # the state carries the org and an expiry, owner-signed — no key material beyond the PUBLIC key that signed it
    assert owner_keypair().private_key_b64 not in json.dumps(_claims(state))


def test_the_code_screens_copy_follows_the_product_rules():
    block = _code_block(_src())
    blob = " ".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert not _COPY_FORBIDDEN.search(blob), _COPY_FORBIDDEN.search(blob).group(0)
    for sentence in re.split(r"(?<=[.!?])\s+", blob):            # an estimate is only ever mentioned to rule it out
        if re.search(r"estimat|quote|predict", sentence, re.IGNORECASE):
            assert re.search(r"\bnever\b|\bno\b|\bnot\b", sentence, re.IGNORECASE), sentence


# --- the screen (app.js under node) -----------------------------------------------------------------------------------------
_WORLD = r"""
document.body.dataset.code = __FLAG__;
globalThis.location = { hash: "#/code", pathname: "/", search: "", assigned: [], assign(u) { this.assigned.push(u); } };
let who = { authenticated: true, username: "cust_fo" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let renders = 0; function render() { renders++; }
let refreshed = 0; async function refreshWho() { refreshed++; }
function shell(inner, current) { return h("div.cust-shell", { dataset: { current: current } }, inner); }
function viewLogin() { return h("div.cust-login"); }
function viewDashboard() { return h("div.cust-home"); }
__FLAGS_OFF__
const VUI = window.VUI;
const calls = [], toasts = [], errs = [];
let server = {};            // "GET <path>" / "POST <path>" -> {data} | {status, data}
function answer(key) {
  const r = server[key];
  if (!r) { const e = new Error("404"); e.status = 404; e.data = { error: "not found" }; throw e; }
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data; throw e; }
  return r.data;
}
VUI.getJSON = async p => { calls.push(["GET", p]); return answer("GET " + p); };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); return answer("POST " + p); };
VUI.toast = m => toasts.push(String(m));
VUI.errorBanner = m => errs.push(String(m));
VUI.clearErrorBanner = () => {};
const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
const root = new El("div"); document.body.appendChild(root);
async function show() { VUI.mount(root, ROUTES["#/code"]()); await flush(); return root; }
function card(repo) { return root.querySelectorAll("div.card").filter(c => text(c.querySelector("span.host")) === repo)[0]; }
function posts() { return calls.filter(c => c[0] === "POST"); }
"""


def _screen_app(flag: str) -> str:
    """The stubbed world plus app.js's own Code screen, extracted verbatim."""
    src = _src()
    world = _WORLD.replace("__FLAG__", json.dumps(flag)).replace("__FLAGS_OFF__", _FLAGS_OFF)
    return "\n".join([world, _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                      _line(src, r'^  var API = "[^"]*";'), _fn(src, "kv"), _fn(src, "loadingHolder"),
                      _line(src, r"^  function here\(\) \{.*\}$"), _line(src, r"^  function err\(msg\) \{.*$"),
                      _line(src, r"^  function clearErr\(\) \{.*$"), _fn(src, "own"), _code_block(src),
                      "const ROUTES = {\n" + _line(src, r'^    "#/code": function .*,$') + "\n};"])


_ALL = {"connect": True, "review": True, "schedule": True, "fix": True, "retest": True}
_OVERVIEW = {"org_id": "org_a", "available": _ALL, "repos": [
    {"repo": API_REPO, "slug": "s-api", "block_threshold": "medium_up", "monthly_limit_credits": 100,
     "used_this_month": 100},
    {"repo": WEB_REPO, "slug": "s-web", "block_threshold": "critical_high", "monthly_limit_credits": 0}]}
_FINDINGS = {"org_id": "org_a", "count": 3, "findings": [
    {"engagement_slug": "s-api", "finding_ref": "f1", "title": "SQL injection in the login query", "severity": "high",
     "surface": "app/login.py", "summary": "Reproduced in an isolated copy."},
    {"engagement_slug": "s-api", "finding_ref": "f2", "title": "A locked finding", "severity": "medium", "locked": True},
    {"engagement_slug": "s-host", "finding_ref": "f3", "title": "A host's finding", "severity": "low"}]}


def _screen(server: "dict | None" = None, then: str = "", *, hash_: str = "#/code", before: str = "",
            flag: str = "1", overview: "dict | None" = None) -> dict:
    srv = {"GET api/customer/code": {"data": overview if overview is not None else _OVERVIEW},
           "GET api/customer/assessments/findings": {"data": _FINDINGS}}
    srv.update(server or {})
    return _node(_screen_app(flag) + f"\nserver = {json.dumps(srv)};\n{before}\nlocation.hash = {json.dumps(hash_)};\n"
                 "await show();\n" + then)


def test_with_the_flag_off_the_code_screen_fetches_nothing():
    for flag in ("0", "", "__VIGIL_CODE__"):
        out = _screen(then="out.calls = calls; out.home = !!root.querySelector('div.cust-home'); out.on = CODE_ON;",
                      flag=flag)
        assert out == {"calls": [], "home": True, "on": False}, flag


def test_a_manager_sees_connect_the_repositories_and_their_policy():
    out = _screen(then=r"""
out.calls = calls;
out.top = buttons(root.querySelector("div.card"));
out.hosts = root.querySelectorAll("span.host").map(text);
const api = card("github.com/acme/api"), web = card("github.com/acme/web");
out.thr = [api.querySelector("select").value, web.querySelector("select").value];
out.options = api.querySelector("select").querySelectorAll("option").map(text);
out.limit = [api.querySelector("input").value, web.querySelector("input").value];
out.apiText = text(api); out.webText = text(web);
out.apiButtons = buttons(api);
out.findings = api.querySelectorAll("div.cust-code-finding").map(f => [text(f.querySelector("strong")), buttons(f)]);
out.webFindings = text(web.querySelector("div.cust-code-findings"));
""")
    assert out["calls"] == [["GET", "api/customer/code"], ["GET", "api/customer/assessments/findings"]]
    assert out["top"] == ["Connect GitHub"] and out["hosts"] == [API_REPO, WEB_REPO]
    assert out["thr"] == ["medium_up", "critical_high"] and out["options"] == ["Nothing", "Critical and High",
                                                                               "Medium and up"]
    assert out["limit"] == ["100", "0"]
    assert "Used this month100 of 100 credits" in out["apiText"] and "reached its monthly limit" in out["apiText"]
    assert "Used this month" not in out["webText"]
    assert out["apiButtons"] == ["Save", "Review now", "Weekly", "Monthly", "No schedule", "Fix this", "Retest",
                                 "Disconnect"]
    # only THIS repository's findings, and a locked (preview) finding offers no Fix this / Retest
    assert out["findings"] == [["SQL injection in the login query", ["Fix this", "Retest"]], ["A locked finding", []]]
    assert "No findings for this repository" in out["webFindings"]


def test_unavailable_actions_are_not_offered():
    none = {"connect": False, "review": False, "schedule": False, "fix": False, "retest": False}
    out = _screen(overview={**_OVERVIEW, "available": none}, then=r"""
const api = card("github.com/acme/api");
out.apiButtons = buttons(api); out.apiText = text(api);
out.top = [text(root.querySelector("div.card")), buttons(root.querySelector("div.card"))];
""")
    assert out["apiButtons"] == ["Save", "Disconnect"]
    assert "now or on a schedule, is not available on this deployment yet" in out["apiText"]
    assert "Fix this and Retest are not available on this deployment yet" in out["apiText"]
    assert "Connecting GitHub is not available on this deployment yet" in out["top"][0] and out["top"][1] == []
    some = {**none, "review": True, "retest": True}
    out = _screen(overview={**_OVERVIEW, "available": some}, then=r"""
const api = card("github.com/acme/api"); out.apiButtons = buttons(api); out.apiText = text(api);
""")
    assert out["apiButtons"] == ["Save", "Review now", "Retest", "Disconnect"]
    assert "Fix this is not available on this deployment yet" in out["apiText"]
    out = _screen(overview={"org_id": "org_a", "repos": [], "available": none}, then="out.body = text(root);")
    assert "No repository is connected yet." in out["body"] and "Select Connect GitHub" not in out["body"]


def test_connect_github_opens_only_githubs_install_page():
    good = "https://github.com/apps/vigil-red-pen/installations/new?state=abc"
    for url, opened in ((good, True), ("http://github.com/apps/x/installations/new", False),
                        ("https://github.com.evil.io/apps/x", False), ("https://evil.io/apps/x", False),
                        ("https://user:pw@github.com/apps/x", False), ("https://github.com:8443/apps/x", False),
                        ("https://github.com/login?next=/apps/x", False), ("javascript:alert(1)", False), (None, False)):
        out = _screen({"POST api/customer/code/connect": {"data": {"install_url": url}}}, r"""
button(root, "Connect GitHub").click(); await flush();
out.assigned = location.assigned; out.errs = errs; out.posts = posts();
""")
        assert out["posts"] == [["POST", "api/customer/code/connect", {}]], url
        assert out["assigned"] == ([good] if opened else []), url
        assert bool(out["errs"]) is (not opened) and (opened or "was not opened" in out["errs"][0]), url
    out = _screen({"POST api/customer/code/connect": _STEP_UP}, r"""
button(root, "Connect GitHub").click(); await flush();
out.assigned = location.assigned; out.errs = errs; out.navs = navs; out.refreshed = refreshed;
""")
    assert out == {"assigned": [], "errs": [_STEP_UP_SAID], "navs": [], "refreshed": 0}


def test_saving_the_policy_sends_only_the_repository_and_the_choice():
    out = _screen({"POST api/customer/code/settings": {"data": {"ok": True}}}, r"""
const api = card("github.com/acme/api");
api.querySelector("select").value = "none"; api.querySelector("input").value = " 250 ";
button(api, "Save").click(); await flush();
out.posts = posts(); out.toasts = toasts; out.renders = renders;
""")
    assert out["posts"] == [["POST", "api/customer/code/settings",
                             {"repo": API_REPO, "block_threshold": "none", "monthly_limit_credits": 250}]]
    assert out["toasts"] == ["Red-Pen settings saved for github.com/acme/api."] and out["renders"] == 1
    for bad in ("", "-1", "2.5", "ten", "1e3", "9999999999"):
        out = _screen(then=f"""
const api = card("github.com/acme/api"); api.querySelector("input").value = {json.dumps(bad)};
button(api, "Save").click(); await flush(); out.posts = posts(); out.errs = errs;
""")
        assert out["posts"] == [] and "whole number of credits" in out["errs"][0], bad


def test_red_pen_system_and_the_finding_actions_call_their_routes():
    srv = {"POST api/customer/code/review": {"data": {"coming": True}},
           "POST api/customer/code/schedule": {"data": {"ok": True}},
           "POST api/customer/code/fix": {"data": {"coming": True}},
           "POST api/customer/code/retest": {"data": {"ok": True}}}
    out = _screen(srv, r"""
const api = card("github.com/acme/api");
for (const label of ["Review now", "Weekly", "Monthly", "No schedule"]) { button(api, label).click(); await flush(); }
const f1 = api.querySelectorAll("div.cust-code-finding")[0];
button(f1, "Fix this").click(); await flush(); button(f1, "Retest").click(); await flush();
out.posts = posts(); out.toasts = toasts;
""")
    repo = {"repo": API_REPO}
    assert out["posts"] == [["POST", "api/customer/code/review", repo],
                            ["POST", "api/customer/code/schedule", {**repo, "cadence": "weekly"}],
                            ["POST", "api/customer/code/schedule", {**repo, "cadence": "monthly"}],
                            ["POST", "api/customer/code/schedule", {**repo, "cadence": "off"}],
                            ["POST", "api/customer/code/fix", {**repo, "finding_ref": "f1"}],
                            ["POST", "api/customer/code/retest", {**repo, "finding_ref": "f1"}]]
    t = out["toasts"]
    assert t[0].startswith("Reviewing a whole repository is not available") and "Nothing was started" in t[0]
    assert t[1:4] == ["The review schedule for this repository is saved."] * 3
    assert t[4].startswith("Fix this is not available") and t[5].startswith("Retest started.")


def test_disconnect_asks_first_and_keep_it_connected_sends_nothing():
    out = _screen({"POST api/customer/code/disconnect": {"data": {"disconnected": True}}}, r"""
const api = card("github.com/acme/api");
button(api, "Disconnect").click(); await flush();
out.asked = text(api.querySelector("div.cust-mon-confirm")); out.afterAsk = posts().length;
button(api, "Keep it connected").click(); await flush();
out.back = buttons(api).slice(-1); out.afterKeep = posts().length;
button(api, "Disconnect").click(); await flush(); button(api, "Yes, disconnect").click(); await flush();
out.posts = posts(); out.toasts = toasts; out.renders = renders;
""")
    assert "Stop reviewing github.com/acme/api?" in out["asked"] and out["afterAsk"] == 0
    assert out["back"] == ["Disconnect"] and out["afterKeep"] == 0
    assert out["posts"] == [["POST", "api/customer/code/disconnect", {"repo": API_REPO}]]
    assert out["toasts"] == ["github.com/acme/api is disconnected. Red-Pen starts no new review of it."]
    assert out["renders"] == 1


def test_a_role_that_cannot_manage_code_sees_an_honest_card():
    out = _screen({"GET api/customer/code": {"status": 403, "data": {
        "error": "denied: requester may not manage code review for this org"}}},
        "out.body = text(root.querySelector('#code-body')); out.calls = calls;")
    assert out["body"].startswith("Only the founder of this workspace, or an Operator VIGIL has added")
    assert out["calls"] == [["GET", "api/customer/code"]]         # and no findings read for someone refused
    out = _screen({"GET api/customer/code": {"status": 401, "data": {"error": "login required"}}},
                  "out.navs = navs; out.refreshed = refreshed;")
    assert out == {"navs": ["#/login"], "refreshed": 1}


def test_every_refusal_is_said_plainly():
    lead = "The Red-Pen settings were not saved"
    for answer, said, renders in (
            (_STEP_UP, _STEP_UP_SAID, 0),
            ({"status": 403, "data": {"error": "denied: github.com/acme/api is not connected for this workspace: "
                                               "connect it first"}},
             f"{lead}: github.com/acme/api is not connected for this workspace: connect it first. Nothing was changed.",
             0),
            ({"status": 400, "data": {"error": "provision failed: block_threshold must be none, critical_high or "
                                               "medium_up"}},
             f"{lead}: block_threshold must be none, critical_high or medium_up. Nothing was changed.", 0),
            ({"status": 503, "data": {"error": "updating"}},
             f"{lead}: VIGIL is updating. Try again in a moment. Nothing was changed.", 0),
            ({"status": 502, "data": {"error": "provisioner unreachable"}},
             f"{lead}: VIGIL could not confirm it. This screen now shows your repositories as they are.", 1)):
        out = _screen({"POST api/customer/code/settings": answer}, r"""
button(card("github.com/acme/api"), "Save").click(); await flush();
out.errs = errs; out.navs = navs; out.renders = renders; out.refreshed = refreshed;
""")
        assert out == {"errs": [said], "navs": [], "renders": renders, "refreshed": 0}, answer
    out = _screen({"POST api/customer/code/settings": {"status": 401, "data": {"error": "login required"}}}, r"""
button(card("github.com/acme/api"), "Save").click(); await flush(); out.navs = navs; out.errs = errs;
""")
    assert out == {"navs": ["#/login"], "errs": []}                # a lost session goes to sign-in, unannounced


def test_a_sensitive_change_goes_through_the_step_up_when_present():
    srv = {"POST api/customer/code/settings": {"data": {"ok": True}}, "POST api/customer/code/review": {"data": {}}}
    out = _screen(srv, r"""
const wheres = [];
globalThis.withStepUp = function (action, where) { wheres.push(where && where.className); return action(); };
const api = card("github.com/acme/api");
button(api, "Save").click(); await flush(); button(api, "Review now").click(); await flush();
out.wheres = wheres; out.posts = posts().length;
""")
    assert out == {"wheres": ["cust-mon-actions", "cust-mon-actions"], "posts": 2}
    # the person closes the check: nothing more is said, sent or re-read
    out = _screen(srv, r"""
globalThis.withStepUp = function () { const e = new Error("closed"); e.stepUpCancelled = true; return Promise.reject(e); };
button(card("github.com/acme/api"), "Save").click(); await flush();
out.errs = errs; out.posts = posts().length; out.renders = renders;
""")
    assert out == {"errs": [], "posts": 0, "renders": 0}


def test_back_from_github_says_what_happened_in_fixed_words():
    for value, said in (("1", "GitHub is connected."), ("pending", "waiting for an owner of your GitHub organization"),
                        ("0", "GitHub was not connected, and nothing was recorded.")):
        out = _screen(hash_=f"#/code?connected={value}",
                      before='globalThis.history = { replaced: [], replaceState(a, b, u) { this.replaced.push(u); } };',
                      then="out.note = text(root.querySelector('div.cust-launch-note')); out.replaced = history.replaced;")
        assert said in out["note"] and out["replaced"] == ["/#/code"], value
    for value in ("2", "__proto__", "constructor", "<img src=x onerror=alert(1)>", ""):
        out = _screen(hash_=f"#/code?connected={value}",
                      then="out.note = root.querySelector('div.cust-launch-note'); out.text = text(root);")
        assert out["note"] is None, value                        # an unknown outcome shows no banner at all
        assert not value or value not in out["text"].replace("Code", ""), value


# --- the guide --------------------------------------------------------------------------------------------------------------
def test_the_tour_lights_the_code_tab_on_the_code_steps():
    out = _guide_node(r"""
const navbar = h("div.cust-topbar", {}, ["#/billing", "#/code", "#/guide"].map(r =>
  h("button.cust-nav-link", { type: "button", dataset: { route: r }, text: r })));
document.body.appendChild(navbar);
const lit = () => document.querySelectorAll(".cust-nav-spot").map(e => e.dataset.route);
const t = G.openTour({ h, doc: document, username: "ana", storage: memStore(false) });
const panel = () => t.el.querySelector(".cust-tour-panel");
out.lit = {};
for (let i = 0; i < G.TOUR.length; i++) {
  out.lit[text(panel().querySelector("h2"))] = lit();
  if (i < G.TOUR.length - 1) button(panel(), "Next").click();
}
""")
    for title in ("Connect your GitHub account", "Red-Pen reviews every pull request", "Fix a finding"):
        assert out["lit"][title] == ["#/code"], title
    assert out["lit"]["Buy credits"] == ["#/billing"] and out["lit"]["Welcome to VIGIL"] == []


def test_the_guide_names_the_code_screens_real_buttons():
    block = _code_block(_src())
    real = set(re.findall(r'codeButton\("([^"]+)"', block))
    real |= {label for _v, label in re.findall(r'\["(\w+)", "([^"]+)"\]', block)}     # thresholds and cadences
    expected = {"Connect GitHub", "Save", "Review now", "Weekly", "Monthly", "No schedule", "Fix this", "Retest",
                "Disconnect", "Yes, disconnect", "Keep it connected", "Nothing", "Critical and High", "Medium and up"}
    assert expected <= real, expected - real
    chapters = _guide_node("out.chapters = G.CHAPTERS;")["chapters"]
    steps = {st["id"]: " ".join(st["clicks"]) for ch in chapters if ch["id"] == "redpen" for st in ch["steps"]}
    named = {"connect": ("Code", "Connect GitHub"), "settings": ("Nothing", "Critical and High", "Medium and up", "Save"),
             "system": ("Review now", "Weekly", "Monthly", "No schedule"), "fix": ("Fix this", "Retest"),
             "disconnect": ("Disconnect", "Yes, disconnect")}
    for step, labels in named.items():
        for label in labels:
            assert label in steps[step], (step, label)
            assert label == "Code" or label in real, (step, label)
    assert '.concat(CODE_ON ? [navLink("Code", "#/code")] : [])' in _src()          # the tab the guide names
