"""Legal/governance S12 — the customer read-only Authorizations surface, behind VIGIL_CUSTOMER_AUTHORIZATIONS
(default OFF).

The Authorizations screen DISCLOSES to a workspace, read-only, the owner-signed EngagementAuthorities on record for its
OWN proven-owned hosts (scope, validity window, environment, GET-only / non-destructive flags) and lets it REQUEST
authorization of a host — which drops an UNSIGNED owner-review request only. It is a disclosure of the enforced gate
(scope/exclusions R1, expiry R2, out-of-scope/new-host refusal R3), never a second enforcement path and never a
widening one:

  * target_authorization.list_customer_authorities reads the owner-signed authorities for the (org_id, host) slugs the
    SOVEREIGN caller supplies — only slugs RE-DERIVED from (org_id, host), so one org never sees another's; it discloses
    PRESENT / BOUND / VERIFIED / ACTIVE(window) + scope/window/GET-only, and a forged/unbound/unverified bundle is
    disclosed present-but-inactive (the gate refuses it independently);
  * Provisioner.customer_authorizations_list reads the SESSION org's own proven-owned hosts (view_assessments,
    tenant-scoped, no global leg) and projects their authorities — it MINTS NOTHING and writes no spine row;
  * Provisioner.customer_authorization_request drops an UNSIGNED owner-review note to authorization_requests_store (an
    off-spine per-org queue) — gated by membership AND a current ownership proof for the host; it signs nothing and the
    owner still signs the real authority in the cockpit;
  * the cockpit dispatch is absent (unknown action -> 404) unless the flag is on, and acts for the hop principal, never
    a body field;
  * the edge GET api/customer/authorizations + POST api/customer/authorizations/request are absent (404) unless the
    flag is on, need a session (401), and read/act for the session's ORG only (a body naming another org is ignored);
  * app.js adds the #/settings/authorizations screen + the Settings-hub link only while data-authorizations="1"; off, it
    is byte-identical (no link, the route is the home screen, no read is made). The screen READS /authorizations and
    POSTs /authorizations/request and reaches the network no other way, and discloses the formal authorization terms
    with an owner/counsel placeholder (never invented legal text).
"""
from __future__ import annotations

import http.client
import itertools
import json
import re
import tempfile
import threading
from pathlib import Path

import pytest

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
# the executed-JS harness (a minimal DOM + node runner), shared verbatim with the Team/Settings screens' proofs
from test_customer_team import _fn, _line, _need_node, _node

from sigil import backup, config
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import authorization_requests_store as reqs
from sigil.ui import target_authorization as ta
from sigil.ui.custui import CustomerHandler, build_customer_server
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, Provisioner

FLAG = "VIGIL_CUSTOMER_AUTHORIZATIONS"
APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
INDEX_HTML = APP / "index.html"
_ISSUED = itertools.count(1)
T0 = 1000.0
T_READ = 2000.0


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())       # the shared authority seam
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())      # isolate the owner vault/spine
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "CUSTOMER_AUTHORIZATION_REQUESTS_DIR", tmp_path / "customer_authorization_requests")


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _prov(store, owner):
    return Provisioner(
        store, customers=CustomerRegistry(store, owner_key=owner), orgs=OrgRegistry(store, owner_key=owner),
        wallet=WalletRegistry(store, owner_key=owner), email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: T_READ)


def _org(p, org, members):
    p.orgs.create_org(org, org.upper(), owner="owner", issued_at=float(next(_ISSUED)))
    for user, role in members.items():
        p.orgs.grant_membership(org, user, role, issued_at=float(next(_ISSUED)))


def _prove(store, org, host, *, now=T0, ttl=1e12):
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_ISSUED)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=ttl)


# =====================================================================================================================
# target_authorization.list_customer_authorities — the tenant-safe read + the active/expired/scope disclosure
# =====================================================================================================================
def test_list_customer_authorities_discloses_active_expired_scope_and_is_tenant_safe():
    ensure_owner_keypair()
    s = _store()
    # acme proves two hosts and the owner signs an authority for each: one long window (active at T_READ), one tiny
    # window (expired at T_READ). The proofs stay current so both hosts remain the org's own.
    _prove(s, "acme", "acmeone.cm")
    _prove(s, "acme", "acmetwo.cm")
    assert ta.add_customer_target("acmeone.cm", org_id="acme", store=s, now=T0, duration_hours=720)["ok"]
    assert ta.add_customer_target("acmetwo.cm", org_id="acme", store=s, now=T0, duration_hours=0.1)["ok"]
    # a different org proves+authorizes its OWN host — it must never surface for acme
    _prove(s, "globex", "globexone.cm")
    assert ta.add_customer_target("globexone.cm", org_id="globex", store=s, now=T0, duration_hours=720)["ok"]

    rows = ta.list_customer_authorities("acme", ["acmeone.cm", "acmetwo.cm"], now=T_READ)
    by_host = {r["host"]: r for r in rows}
    a, b = by_host["acmeone.cm"], by_host["acmetwo.cm"]
    assert a["authorized"] and a["verified"] and a["scope_ok"] and a["trusted"] and a["active"] is True
    assert a["scope"] == ["acmeone.cm"] and a["environment"] == "live"
    assert a["allow_destructive"] is False and a["live_destructive_acknowledged"] is False   # GET-only disclosure
    assert a["issued_by"] == "customer:acme"
    # the second authority is expired (R2 disclosure): present + verified, but the window has passed -> not active
    assert b["authorized"] and b["verified"] and b["active"] is False
    # TENANT ISOLATION: acme's read, given acme's OWN hosts, never re-derives or reads globex's slug
    assert "globexone.cm" not in by_host
    assert ta._customer_slug("acme", "acmeone.cm") != ta._customer_slug("globex", "globexone.cm")
    # a host with no authority is disclosed as not-authorized (so the UI can offer "request authorization")
    none_rows = ta.list_customer_authorities("acme", ["unproven.cm"], now=T_READ)
    assert none_rows == [{"host": "unproven.cm", "slug": ta._customer_slug("acme", "unproven.cm"),
                          "authorized": False, "active": False}]


def test_a_forged_or_foreign_signed_authority_is_disclosed_present_but_inactive():
    """Acceptance #5/#6: the surface never trusts a bundle not owner-signed by THIS cockpit. A bundle written at the
    org's own slug but signed by a DIFFERENT key is disclosed present-but-inactive (bound False); the launch/gate
    refuses it independently. The UI cannot widen scope or make a forged authority active."""
    from vigil_core import (
        AuthorizerKey, EngagementAuthority, TargetEnvironment, TrustRoot, sign_engagement_authority,
    )
    from vigil_integration.live.authorization_broker import write_authorization

    from sigil.reuse import generate_keypair
    ensure_owner_keypair()                                     # THIS cockpit's owner key
    foreign = generate_keypair()                               # NOT this cockpit's key
    slug = ta._customer_slug("acme", "acmeone.cm")
    from datetime import datetime, timedelta, timezone
    t = datetime.fromtimestamp(T0, tz=timezone.utc)
    doc = EngagementAuthority(engagement_slug=slug, environment=TargetEnvironment("live"), scope=["acmeone.cm"],
                              not_before=t, not_after=t + timedelta(hours=720), issued_by="customer:acme")
    signed = sign_engagement_authority(doc, {"owner": foreign.private_key_b64})
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                           public_key_b64=foreign.public_key_b64)])
    write_authorization(ta._base_dir(), slug, signed, tr)
    row = ta.list_customer_authorities("acme", ["acmeone.cm"], now=T_READ)[0]
    assert row["authorized"] is True                           # a bundle is present ...
    assert row["verified"] is False and row["active"] is False  # ... but it is not THIS owner's: never trusted/active


def test_a_colisted_owner_key_forgery_is_disclosed_inactive():
    """The co-listed-key forgery (the pinned-owner-root guarantee): a bundle whose OWN trust_root lists the
    owner's PUBLIC key BESIDE an attacker key (threshold 1), signed by the ATTACKER ONLY, must be disclosed
    present-but-INACTIVE. The surface verifies against a PINNED owner root (not the bundle's own trust_root),
    exactly like the enforcement gate launch_gate._authority_ok, so a mere 'owner key is listed' membership
    can never make a never-owner-signed bundle read as Active."""
    from datetime import datetime, timedelta, timezone

    from vigil_core import (
        AuthorizerKey, EngagementAuthority, TargetEnvironment, TrustRoot, sign_engagement_authority,
    )
    from vigil_integration.live.authorization_broker import write_authorization

    from sigil.reuse import generate_keypair
    ensure_owner_keypair()
    owner_pub = ta._owner_keypair().public_key_b64             # THIS cockpit's owner PUBLIC key (co-listed below)
    attacker = generate_keypair()                             # NOT this cockpit's key
    slug = ta._customer_slug("acme", "acmeone.cm")
    t = datetime.fromtimestamp(T0, tz=timezone.utc)
    doc = EngagementAuthority(engagement_slug=slug, environment=TargetEnvironment("live"), scope=["acmeone.cm"],
                              not_before=t, not_after=t + timedelta(hours=720), issued_by="customer:acme")
    signed = sign_engagement_authority(doc, {"attacker": attacker.private_key_b64})   # signed by the ATTACKER only
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner_pub),          # owner co-listed (PUBLIC)
        AuthorizerKey(key_id="attacker", name="attacker", public_key_b64=attacker.public_key_b64)])
    write_authorization(ta._base_dir(), slug, signed, tr)
    row = ta.list_customer_authorities("acme", ["acmeone.cm"], now=T_READ)[0]
    assert row["authorized"] is True                          # a bundle is present ...
    # ... but it was never signed by THIS owner's key: the pinned-root verify fails -> never trusted/active.
    assert row["verified"] is False and row["trusted"] is False and row["active"] is False


# =====================================================================================================================
# the provisioner: flag-gated, tenant-scoped reads + the unsigned, off-spine request (no authority, no spine write)
# =====================================================================================================================
def test_provisioner_read_is_flag_gated_tenant_scoped_and_mints_nothing(monkeypatch):
    ensure_owner_keypair()
    s = _store()
    p = _prov(s, ensure_owner_keypair())
    _org(p, "acme", {"olive": "operator", "adam": "org_admin"})
    _org(p, "globex", {"mallory": "operator"})
    _prove(s, "acme", "acmeone.cm")
    assert ta.add_customer_target("acmeone.cm", org_id="acme", store=s, now=T0, duration_hours=720)["ok"]
    _prove(s, "globex", "globexone.cm")
    assert ta.add_customer_target("globexone.cm", org_id="globex", store=s, now=T0, duration_hours=720)["ok"]

    # flag OFF -> refused even if the dispatch is reached (defence in depth), nothing read
    monkeypatch.delenv(FLAG, raising=False)
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.customer_authorizations_list("olive", "acme")
    monkeypatch.setenv(FLAG, "1")
    n = s.count()
    out = p.customer_authorizations_list("olive", "acme", now=T_READ)
    assert out["org_id"] == "acme" and out["can_request"] is True
    hosts = {r["host"] for r in out["authorities"]}
    assert hosts == {"acmeone.cm"}                                 # acme sees ONLY its own host
    assert out["authorities"][0]["active"] is True
    assert s.count() == n                                          # a pure read: nothing appended to the spine
    # TENANT ISOLATION / honest refusal: a billing role, another org, a non-member are each refused (never shown data)
    for who, org in (("adam", "acme"), ("olive", "globex"), ("nobody", "acme")):
        with pytest.raises(ProvisionDenied, match="may not read"):
            p.customer_authorizations_list(who, org, now=T_READ)


def test_request_drops_an_unsigned_offspine_note_mints_no_authority_and_writes_no_spine(monkeypatch):
    ensure_owner_keypair()
    s = _store()
    p = _prov(s, ensure_owner_keypair())
    _org(p, "acme", {"olive": "operator"})
    _prove(s, "acme", "acmetwo.cm")                               # proven-owned, but NOT yet authorized
    monkeypatch.setenv(FLAG, "1")
    n = s.count()
    out = p.customer_authorization_request("olive", "acme", "acmetwo.cm", note="prod site", now=T_READ)
    assert out == {"ok": True, "requested": True, "host": "acmetwo.cm", "org_id": "acme"}
    # the request is an UNSIGNED, off-spine note: it is in the requests store, NOT on the signed spine ...
    assert reqs.pending_hosts("acme") == ["acmetwo.cm"]
    assert reqs.read_requests("acme")["acmetwo.cm"]["requested_by"] == "olive"
    assert s.count() == n                                          # no spine append at all
    # ... and it mints NO authority (the slug has no owner-signed authority on the seam)
    assert ta.authority_status(ta._customer_slug("acme", "acmetwo.cm"))["present"] is False
    # a request for a host the org does NOT proven-own is refused (ownership is separate from billing/membership)
    with pytest.raises(ProvisionDenied, match="ownership proof"):
        p.customer_authorization_request("olive", "acme", "notmine.cm", now=T_READ)
    # flag OFF -> refused (defence in depth), nothing recorded
    monkeypatch.delenv(FLAG, raising=False)
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.customer_authorization_request("olive", "acme", "acmetwo.cm", now=T_READ)
    # the surface's new helpers carry the sovereignty guard (assert_no_offense) and never write the signed spine
    src = Path(reqs.__file__).read_text(encoding="utf-8")
    assert "from ..reuse import assert_no_offense" in src and "assert_no_offense()" in src


# =====================================================================================================================
# the off-spine requests store round-trips (per-org, merge, lenient defaults)
# =====================================================================================================================
def test_requests_store_round_trips_per_org_and_merges(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CUSTOMER_AUTHORIZATION_REQUESTS_DIR", tmp_path / "authz_requests")
    assert reqs.read_requests("org_a") == {} and reqs.pending_hosts("org_a") == []    # missing -> empty, never raises
    reqs.record_request("org_a", host="a.cm", requested_by="olive", note="n1", now=5.0)
    reqs.record_request("org_a", host="b.cm", requested_by="olive", now=6.0)
    assert reqs.pending_hosts("org_a") == ["a.cm", "b.cm"]
    # a re-request UPDATES the same host in place (never grows without bound)
    reqs.record_request("org_a", host="a.cm", requested_by="pat", note="n2", now=7.0)
    stored = reqs.read_requests("org_a")
    assert stored["a.cm"] == {"requested_by": "pat", "note": "n2", "at": 7.0} and set(stored) == {"a.cm", "b.cm"}
    assert reqs.read_requests("org_b") == {}                      # another org's queue is separate
    # a bad input is refused in plain words, nothing written
    for bad in (("", {"host": "x.cm"}), ("org_a", {"host": ""})):
        with pytest.raises(ValueError):
            reqs.record_request(bad[0], host=bad[1]["host"], requested_by="olive", now=8.0)
    # backup CLASSIFIES the new dir (so the structural coverage gate stays green) — an operational queue, EXCLUDED
    assert backup.classify_top_level("customer_authorization_requests") == "excluded"
    assert backup._EXCLUSION_REASONS["customer_authorization_requests"]


# =====================================================================================================================
# the edge: flag-off 404 (its own, nothing relayed) + account/org from the session, never the body
# =====================================================================================================================
def _edge_stub(session):
    h = object.__new__(CustomerHandler)
    sent = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                    or (200, {"ok": True, "authorities": [], "requested": []}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


def test_edge_flag_off_answers_its_own_404_and_relays_nothing(monkeypatch):
    session = {"username": "cust_ana", "org_id": "org_a"}
    for value in (None, "0", "", "no", "off"):
        if value is None:
            monkeypatch.delenv(FLAG, raising=False)
        else:
            monkeypatch.setenv(FLAG, value)
        h, sent = _edge_stub(session)
        h._dispatch("authorizations/request", {"host": "x.cm"})
        assert sent == {"code": 404, "out": {"error": "unknown action"}}, value    # no "action": nothing relayed
        h, sent = _edge_stub(session)
        h.path = "/api/customer/authorizations"
        h.do_GET()
        assert sent == {"code": 404, "out": {"error": "not found"}}, value
    # flag ON: the edge relays each verb for the SESSION's ORG, never a body field
    monkeypatch.setenv(FLAG, "1")
    h, sent = _edge_stub(session)
    h.path = "/api/customer/authorizations?org_id=org_evil"
    h.do_GET()
    assert sent["action"] == "customer_authorizations_list" and sent["principal"] == "cust_ana"
    assert sent["body"] == {"org_id": "org_a", "ip": "1.2.3.4"}                     # session org, not the query
    h, sent = _edge_stub(session)
    h._dispatch("authorizations/request", {"host": "x.cm", "note": "n", "org_id": "org_evil", "username": "cust_eve"})
    assert sent["action"] == "customer_authorization_request" and sent["principal"] == "cust_ana"
    assert sent["body"] == {"org_id": "org_a", "host": "x.cm", "note": "n", "ip": "1.2.3.4"}   # only host/note travel
    # no session (or no org) -> refused before any hop
    for s in (None, {}, {"username": "u"}):
        h, sent = _edge_stub(s)
        h._dispatch("authorizations/request", {"host": "x.cm"})
        assert sent["code"] == 401 and "action" not in sent, s


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


def test_flag_off_route_404_over_the_real_edge_and_the_page_is_byte_identical(tmp_path, monkeypatch):
    sov, edge, ep, _sp = _stack(tmp_path, monkeypatch)
    try:
        # sign in so the 404 is the FLAG's (a signed-in session would otherwise reach the read)
        op = _opener()
        tok = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        assert _post(op, ep, "/api/customer/signup/confirm",
                     {"token": tok, "password": "customer-pw-1", "org_name": "Acme"})[0] == 200
        assert _get(op, ep, "/api/customer/authorizations") == (404, {"error": "not found"})
        assert _post(op, ep, "/api/customer/authorizations/request",
                     {"host": "x.cm"}) == (404, {"error": "unknown action"})
    finally:
        sov.shutdown()
        edge.shutdown()
    # the page: the flag is its only difference (its value + the build id it changes) — byte-identical otherwise
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-authorizations="0"' in off and "__VIGIL_AUTHORIZATIONS__" not in off
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-authorizations="1"' in on and build_on != build_off
    assert on.replace('data-authorizations="1"', 'data-authorizations="0"').replace(build_on, build_off) == off
    # the index template's placeholder is flag-driven (defaulting off), not hardcoded on
    assert 'data-authorizations="__VIGIL_AUTHORIZATIONS__"' in INDEX_HTML.read_text(encoding="utf-8")
    # app.js gates the screen and the route on the flag, so off they add nothing
    src = APP_JS.read_text(encoding="utf-8")
    assert '  var AUTHZ_ON = pageFlag("authorizations");' in src
    assert ('    "#/settings/authorizations": function () { return authed() ? (AUTHZ_ON ? viewAuthorizations() : '
            'viewDashboard()) : viewLogin(); },') in src
    assert 'settingsLink("Authorizations", "#/settings/authorizations")' in src


# =====================================================================================================================
# the executed page (node): the screen renders, discloses R1/R2/R3 + the pending-terms placeholder, and the request
# drops an unsigned ask — reaching the network through its two routes alone
# =====================================================================================================================
_DATA = {"org_id": "org_acme", "can_request": True, "requested": ["p.example"], "authorities": [
    {"host": "a.example", "slug": "cust_a1", "authorized": True, "bound": True, "verified": True, "trusted": True,
     "active": True, "scope": ["a.example"], "environment": "live", "not_before": "2024-01-01T00:00:00+00:00",
     "not_after": "2099-01-01T00:00:00+00:00", "allow_destructive": False, "issued_by": "customer:org_acme"},
    {"host": "c.example", "slug": "cust_c1", "authorized": True, "bound": True, "verified": True, "trusted": True,
     "active": False, "scope": ["c.example"], "environment": "live", "not_before": "2024-01-01T00:00:00+00:00",
     "not_after": "2024-02-01T00:00:00+00:00", "allow_destructive": False, "issued_by": "customer:org_acme"},
    {"host": "p.example", "slug": "cust_p1", "authorized": False, "active": False}]}

_WORLD_A = r"""
document.body.dataset.authorizations = __FLAG__;
globalThis.location = { hash: "#/settings/authorizations" };
let who = { authenticated: true, username: "cust_me" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const navs = []; function nav(r) { navs.push(r); }
let refreshed = 0; async function refreshWho() { refreshed++; }
const calls = [];
let data = __DATA__;
let getFail = null, postFail = null;
function failure(f) { const e = new Error(f.message || (f.data && f.data.error) || "failed");
  e.status = f.status; e.data = f.data || null; return e; }
const VUI = window.VUI;
VUI.getJSON = async p => { calls.push(["GET", p]); if (getFail) { const f = getFail; getFail = null; throw failure(f); }
  return JSON.parse(JSON.stringify(data)); };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); if (postFail) { const f = postFail; postFail = null; throw failure(f); }
  return { ok: true, requested: true }; };
const raw = [];
globalThis.fetch = async u => { raw.push(["fetch", String(u)]);
  return { ok: false, status: 599, headers: { get: () => null }, json: async () => ({}), text: async () => "" }; };
globalThis.XMLHttpRequest = function () { raw.push(["xhr"]); this.open = () => {}; this.send = () => {}; this.setRequestHeader = () => {}; };
const toasts = []; VUI.toast = m => { toasts.push(m); };
const banners = []; VUI.errorBanner = m => { banners.push(m); };
var GUIDE = null, GUIDE_ON = false;
function shell(inner, current) { return h("div.cust-shell", { dataset: { current: current } }, inner); }
function viewLogin() { return h("div.cust-login"); }
function viewDashboard() { return h("div.cust-dash"); }
const root = new El("div"); document.body.appendChild(root);
function show() { VUI.mount(root, ROUTES["#/settings/authorizations"]()); return root; }
"""


def _authz_block(src: str) -> str:
    i = src.index("  // ---- Authorizations (VIGIL_CUSTOMER_AUTHORIZATIONS)")
    return src[i:src.index("  // ---- misc", i)]


def _authz_app(flag: str = "1", data=None) -> str:
    src = APP_JS.read_text(encoding="utf-8")
    world = (_WORLD_A.replace("__FLAG__", json.dumps(flag))
             .replace("__DATA__", json.dumps(data if data is not None else _DATA)))
    return "\n".join([world,
                      _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                      _line(src, r'^  var API = "[^"]*";'),
                      _line(src, r"^  function here\(\) \{.*\}$"), _fn(src, "loadingHolder"),
                      _line(src, r"^  function err\(msg\) \{.*$"),
                      _line(src, r"^  var AUTHZ_ON = .*;$"),
                      _authz_block(src),
                      'const ROUTES = {\n' + _line(src, r'^    "#/settings/authorizations": function .*,$') + '\n};'])


def test_flag_on_screen_renders_discloses_r1_r2_r3_and_the_request_drops_an_unsigned_ask():
    _need_node()
    out = _node(_authz_app("1", _DATA) + r"""
show(); await tick(); await tick();
out.authzOn = AUTHZ_ON;
out.title = text(root.querySelector("h2"));
out.onRender = calls.slice();                                            // what the screen calls just to render
out.buttons = buttons(root);
out.textAll = root.textContent;
// click the first "Request authorization": it POSTs the request route (host only), then re-reads
const n = calls.length;
button(root, "Request authorization").click(); await tick(); await tick();
out.afterReq = calls.slice(n);
out.toasts = toasts.slice();
out.all = calls; out.raw = raw;
""")
    assert out["authzOn"] is True and out["title"] == "Authorizations"
    # rendering only READS /authorizations — it makes no write (the screen mints/widens nothing)
    assert out["onRender"] == [["GET", "api/customer/authorizations"]]
    # two hosts are not actively authorized (the expired one + the not-authorized one): each offers "Request authorization"
    assert out["buttons"].count("Request authorization") == 2
    # it DISCLOSES the enforced gate: scope/exclusions (R1), the validity window / expiry (R2), new-host refusal (R3)
    t = out["textAll"]
    assert "In scope:" in t and "Out of scope:" in t                     # R1
    assert "Valid " in t and "Status: Expired or not yet valid" in t     # R2 (one authority has lapsed)
    assert "new host" in t.lower() and "not in a signed scope" in t.lower()   # R3
    assert "Read-only / non-destructive (GET-only)" in t                 # GET-only / non-destructive disclosure
    # the formal authorization terms are an owner/counsel PLACEHOLDER — never invented legal text
    assert "«AUTHORIZATION TERMS — PENDING OWNER/COUNSEL»" in t
    # the request POSTs the request route carrying ONLY the host (the org is the server session), then re-reads
    assert out["afterReq"] == [["POST", "api/customer/authorizations/request", {"host": "c.example"}],
                               ["GET", "api/customer/authorizations"]]
    assert out["toasts"] == ["Authorization requested"]
    # EVERY request the screen ever made went to one of its two routes — nothing to the network any other way
    for call in out["all"]:
        assert call[1] in ("api/customer/authorizations", "api/customer/authorizations/request"), call
    assert out["raw"] == []
    # the source: the Authorizations block reaches the network ONLY through its own two routes
    src = APP_JS.read_text(encoding="utf-8")
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", _authz_block(src))
    assert re.findall(r"VUI\.(\w+JSON)\(API \+ \"([^\"]*)\"", code) == [
        ("getJSON", "/authorizations"), ("postJSON", "/authorizations/request")]
    assert not re.search(r"[\"'`]/?api/", code)
    for banned in ("fetch(", "XMLHttpRequest", "sendBeacon", "uploadChunked", ".sse(", "location.href",
                   "location.assign", "location.replace", "window.open"):
        assert banned not in code, banned


def test_flag_off_the_route_is_the_home_screen_and_reads_nothing():
    _need_node()
    out = _node(_authz_app("0", _DATA) + r"""
const a = ROUTES["#/settings/authorizations"](), b = viewDashboard();
out.same = JSON.stringify(ser(a)) === JSON.stringify(ser(b));
out.authzOn = AUTHZ_ON;
out.calls = calls; out.raw = raw;
""")
    assert out["authzOn"] is False
    assert out["same"] is True                                           # byte-identical to the home screen
    assert out["calls"] == [] and out["raw"] == []                       # no read, nothing to the network
