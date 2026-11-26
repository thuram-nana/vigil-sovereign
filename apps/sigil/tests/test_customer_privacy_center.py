"""Legal/governance S2 — the customer Privacy centre, behind VIGIL_CUSTOMER_PRIVACY_CENTER (default OFF).

The Privacy centre is a #/privacy screen that SURFACES, for the signed-in customer, the privacy information this
deployment has ALREADY published — it never shows a reworded or invented copy:

  * the strictly-necessary cookie inventory, the subprocessor list and the links to the full pages are read at request
    time from the ONE canonical source, the packaged ``public_site`` pages (``ui/privacy_center_store`` reads them), so
    there is no second copy to drift from the published wording;
  * ``Provisioner.privacy_center`` serves an ACTIVE customer only and returns those published, org-INDEPENDENT facts
    (the same for every workspace) — NEVER the signed append-only spine (no audit row), never money, never authority;
  * the edge route ``GET api/customer/privacy`` is absent (404) unless the flag is on — the EDGE's own unknown-route
    404, nothing relayed — needs a session (401), and takes the account from the SESSION (a body/query naming another
    account changes nothing);
  * app.js adds the Privacy tab + #/privacy screen only while data-privacy-center="1"; off, it is byte-identical (no
    tab, #/privacy is the home screen, no privacy read is made). The screen makes ONE read and no write, and adds no
    authority or money control; every class it renders is styled.

It also carries a correctness fix to a PUBLIC page: the trust page's subprocessor line no longer claims
"Flutterwave (primary)" as the active card processor — it names Stripe for card payments, agreeing with the privacy
page (the owner's decision: Stripe; Flutterwave paused).
"""
from __future__ import annotations

import http.client
import json
import re
import tempfile
import threading
from pathlib import Path

import pytest

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _stack
# the executed-JS harness (a minimal DOM + node runner), shared verbatim with the Team / Settings screens' proofs
from test_customer_team import _fn, _line, _need_node, _node

from sigil import config
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import privacy_center_store as store
from sigil.ui.custui import CustomerHandler, build_customer_server
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, Provisioner

FLAG = "VIGIL_CUSTOMER_PRIVACY_CENTER"
APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
APP_CSS = APP / "app.css"
INDEX_HTML = APP / "index.html"
PUBLIC = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "public_site"
OWNER = generate_keypair()
OP = OWNER.public_key_b64

# the six subprocessors the privacy page publishes, in order
_SUBPROCESSORS = ("Amazon Web Services (AWS)", "Cloudflare", "Stripe", "Google", "GitHub", "Anthropic")
# the three strictly-necessary cookies the cookies page publishes
_COOKIES = ("sigil_session", "vigil_customer_session", "OIDC binding cookie")


@pytest.fixture(autouse=True)
def _no_flag(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)


# --- the provisioner / spine (mirrors the settings/onboarding harness) ------------------------------------------------
def _prov(now_fn=lambda: 1234.0):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    p = Provisioner(
        s, customers=custs, orgs=OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=now_fn)
    return p, s, custs


def _page_and_build(tmp_path):
    """The customer page this edge serves, and its build id — the flag's effect written into the page."""
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


def _edge_stub(session):
    """The edge's OWN handler, I/O stubbed: the session it sees, and every hop to the cockpit RECORDED (an ``action`` in
    ``sent`` means the edge relayed) — so a test sees what the edge itself answers, never what the cockpit would."""
    h = object.__new__(CustomerHandler)
    sent = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                    or (200, {"ok": True, "cookies": [], "subprocessors": [], "links": {}}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


# --- the executed-JS harness for the screen (node) --------------------------------------------------------------------
def _privacy_block(src: str) -> str:
    i = src.index("  // ---- Privacy centre (VIGIL_CUSTOMER_PRIVACY_CENTER)")
    # the block ends at the NEXT section header (another legal screen, e.g. Seller identity, may now follow it
    # before "// ---- misc" once the sibling disclosure slices are integrated), never spilling into it.
    return src[i:src.index("\n  // ----", i + 1)]


_WORLD_P = r"""
document.body.dataset.privacyCenter = __FLAG__;
globalThis.location = { hash: "#/privacy" };
let who = { authenticated: true, username: "cust_me", org_id: "org_a" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const navs = []; function nav(r) { navs.push(r); }
let refreshed = 0; async function refreshWho() { refreshed++; }
const calls = [];
let data = __DATA__;
let getFail = null;
function failure(f) { const e = new Error(f.message || "failed"); e.status = f.status; e.data = f.data || null; return e; }
const VUI = window.VUI;
VUI.getJSON = async p => { calls.push(["GET", p]); if (getFail) { const f = getFail; getFail = null; throw failure(f); }
  return data; };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); return { ok: true }; };
// every other way a page could reach the network, recorded (the screen must use none of them)
const raw = [];
globalThis.fetch = async u => { raw.push(["fetch", String(u)]);
  return { ok: false, status: 599, headers: { get: () => null }, json: async () => ({}), text: async () => "" }; };
globalThis.XMLHttpRequest = function () { raw.push(["xhr"]); this.open = () => {}; this.send = () => {};
  this.setRequestHeader = () => {}; };
const toasts = []; VUI.toast = m => { toasts.push(m); };
var GUIDE = null, GUIDE_ON = false;
function shell(inner, current) { return h("div.cust-shell", { dataset: { current: current } }, inner); }
function viewDashboard() { return h("div.cust-dash"); }
function viewLogin() { return h("div.cust-login"); }
const root = new El("div"); document.body.appendChild(root);
function show() { VUI.mount(root, ROUTES["#/privacy"]()); return root; }
"""


def _privacy_app(flag: str = "1", data=None) -> str:
    """The harness: the stubs above plus app.js's own code for the Privacy screen, extracted verbatim — the shared
    ``area6View`` read helper, the helpers it calls, and the Privacy block."""
    src = APP_JS.read_text(encoding="utf-8")
    world = (_WORLD_P.replace("__FLAG__", json.dumps(flag))
             .replace("__DATA__", json.dumps(data if data is not None else {})))
    return "\n".join([world,
                      _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                      _line(src, r'^  var API = "[^"]*";'),
                      _line(src, r"^  function here\(\) \{.*\}$"), _fn(src, "loadingHolder"), _fn(src, "area6View"),
                      _privacy_block(src),
                      'const ROUTES = {\n' + _line(src, r'^    "#/privacy": function .*,$') + '\n};'])


# =====================================================================================================================
# 1. Flag OFF: route 404, page + nav byte-identical (its only difference is the flag value + the build id it changes)
# =====================================================================================================================
def test_1_flag_off_route_404_page_and_nav_byte_identical(tmp_path, monkeypatch):
    # the EDGE's own unknown-route 404 with the flag off — never the cockpit's "unknown provision action". With the flag
    # off the route is absent BEFORE any auth/cockpit read, so the 404 is session-independent (proven here anonymous;
    # test_1b proves the same for a signed-in session at the edge, stubbed, with nothing relayed).
    sov, edge, ep, _sp = _stack(tmp_path, monkeypatch)
    try:
        assert _get(_opener(), ep, "/api/customer/privacy") == (404, {"error": "not found"})
    finally:
        sov.shutdown()
        edge.shutdown()
    # the page: the flag is its only difference (its value + the build id it changes) — byte-identical otherwise
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-privacy-center="0"' in off and "__VIGIL_PRIVACY_CENTER__" not in off
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-privacy-center="1"' in on and build_on != build_off
    assert on.replace('data-privacy-center="1"', 'data-privacy-center="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv(FLAG, v)
        assert 'data-privacy-center="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v
    # the index template's placeholder is still a placeholder (flag-driven, defaulting off), not hardcoded on
    assert 'data-privacy-center="__VIGIL_PRIVACY_CENTER__"' in INDEX_HTML.read_text(encoding="utf-8")
    # app.js: the Privacy tab and route are flag-guarded, so off they add no screen to the nav or the router
    src = APP_JS.read_text(encoding="utf-8")
    assert '  var PRIVACY_CENTER_ON = pageFlag("privacyCenter");' in src
    assert '.concat(PRIVACY_CENTER_ON ? [navLink("Privacy", "#/privacy")] : [])' in src
    assert ('    "#/privacy": function () { return authed() ? (PRIVACY_CENTER_ON ? viewPrivacy() : viewDashboard())'
            ' : viewLogin(); },') in src


# =====================================================================================================================
# 1b. Flag OFF: the EDGE itself refuses the GET and relays nothing — independently of the cockpit's own gate
# =====================================================================================================================
def test_1b_flag_off_the_edge_answers_its_own_404_and_relays_nothing(monkeypatch):
    session = {"username": "cust_ana", "org_id": "org_a"}
    for value in (None, "0", "", "no", "off", "maybe"):
        if value is None:
            monkeypatch.delenv(FLAG, raising=False)
        else:
            monkeypatch.setenv(FLAG, value)
        h, sent = _edge_stub(session)
        h.path = "/api/customer/privacy"
        h.do_GET()
        assert sent == {"code": 404, "out": {"error": "not found"}}, value     # no "action": nothing relayed
    # positive control: the very same stubbed edge, flag on, relays the read for the SESSION's account + org
    monkeypatch.setenv(FLAG, "1")
    h, sent = _edge_stub(session)
    h.path = "/api/customer/privacy"
    h.do_GET()
    assert (sent["action"], sent["principal"], sent["code"]) == ("privacy_center", "cust_ana", 200)
    assert sent["body"] == {"org_id": "org_a", "ip": "1.2.3.4"}                 # only the session org travels
    # no session (or no bound org): the edge refuses before the hop
    for bad in (None, {}, {"username": "cust_ana"}):
        h, sent = _edge_stub(bad)
        h.path = "/api/customer/privacy"
        h.do_GET()
        assert sent["code"] == 401 and "action" not in sent, bad


# =====================================================================================================================
# 2. Flag ON: the screen renders the PUBLISHED cookie inventory + subprocessor list + links, from ONE read and no write
# =====================================================================================================================
def test_2_flag_on_screen_renders_cookie_and_subprocessor_summary():
    _need_node()
    facts = store.read_privacy_center()                 # the REAL published facts, as the server would return them
    out = _node(_privacy_app("1", {"ok": True, **facts}) + r"""
show(); await tick(); await tick();
out.on = PRIVACY_CENTER_ON;
out.title = text(root.querySelector("h2"));
out.onRender = calls.slice();
// a cookie body row is a <tr> with <td> cells (the header row has only <th>)
out.cookieRows = root.querySelectorAll("tr").filter(function (r) { return r.querySelectorAll("td").length > 0; })
  .map(function (r) { return [text(r.querySelector("th")), r.querySelectorAll("td").map(text)]; });
out.count = text(root.querySelector(".cust-privacy-count"));
out.muted = root.querySelectorAll("p.cust-muted").map(text);   // the lead, the cookie note, the subprocessor lead
out.subs = root.querySelectorAll("strong").map(text);          // the only <strong> on the screen are the provider names
out.links = root.querySelectorAll("a").map(function (a) { return a.getAttribute("href"); });
out.buttons = buttons(root);
out.raw = raw; out.all = calls;
""")
    assert out["on"] is True and out["title"] == "Privacy"
    # rendering only READS once — it makes no POST and reaches the network no other way: no authority/money mutation
    assert out["onRender"] == [["GET", "api/customer/privacy"]]
    assert out["raw"] == [] and [c for c in out["all"] if c[0] != "GET"] == []
    assert out["buttons"] == []                         # a pure display screen: links out, never a control of its own
    # (a) the cookie inventory: the three strictly-necessary cookies, each with its purpose and category
    assert [row[0] for row in out["cookieRows"]] == list(_COOKIES)
    assert all(row[1][-1] == "Strictly necessary" for row in out["cookieRows"])
    assert "3 strictly-necessary" in out["count"] and "0 optional" in out["count"]
    assert "nothing to consent to" in out["count"]
    # the canonical cookie note (the published "short version") is rendered, not a reworded summary
    assert any("strictly-necessary session cookies" in (m or "") for m in out["muted"]), out["muted"]
    # (b) the subprocessor list, in the published order
    assert out["subs"] == list(_SUBPROCESSORS)
    # (c) links to the full published pages (the cookie notice and the privacy policy)
    assert "/cookies" in out["links"] and "/privacy" in out["links"]


# =====================================================================================================================
# 3. The store reads the canonical PUBLISHED facts (one source of truth) — never a forked / invented copy
# =====================================================================================================================
def test_3_store_reads_the_canonical_published_facts_no_fork():
    facts = store.read_privacy_center()
    cookies_html = (PUBLIC / "cookies" / "index.html").read_text(encoding="utf-8")
    privacy_html = (PUBLIC / "privacy" / "index.html").read_text(encoding="utf-8")
    # the cookie inventory is exactly the published table: three cookies, every one strictly necessary, zero optional
    assert [c["name"] for c in facts["cookies"]] == list(_COOKIES)
    assert facts["cookie_summary"] == {"strictly_necessary": 3, "optional": 0,
                                       "note": facts["cookie_summary"]["note"]}
    assert facts["cookie_summary"]["strictly_necessary"] == 3 and facts["cookie_summary"]["optional"] == 0
    assert all(c["category"] == "Strictly necessary" for c in facts["cookies"])
    # the subprocessor list is exactly the published providers list, in order
    assert [s["name"] for s in facts["subprocessors"]] == list(_SUBPROCESSORS)
    # NO FORK: every fact the store surfaces is actually present in the canonical public page it came from
    for c in facts["cookies"]:
        assert c["name"] in cookies_html, c["name"]
    assert facts["cookie_summary"]["note"] and facts["cookie_summary"]["note"].split(".")[0] in \
        re.sub(r"\s+", " ", __import__("html").unescape(re.sub(r"<[^>]+>", "", cookies_html)))
    for s in facts["subprocessors"]:
        assert s["name"] in privacy_html, s["name"]
        assert s["detail"] and s["name"] in s["detail"]                 # the detail is the page's own line, name kept
    # the links are the canonical published paths, nothing invented
    assert facts["links"] == {"cookies": "/cookies", "privacy": "/privacy", "trust": "/trust"}


# =====================================================================================================================
# 4. The cockpit dispatch is absent without the flag; with it, the account is the hop principal (never a body field)
# =====================================================================================================================
def test_4_dispatch_absent_without_flag_and_account_is_the_hop_principal(monkeypatch):
    from sigil.ui.server import Handler

    class _P:
        def __init__(self):
            self.calls = []

        def __getattr__(self, name):
            def f(*a, **k):
                self.calls.append((name, a, k))
                return {"ok": True}
            return f

    monkeypatch.delenv(FLAG, raising=False)
    p = _P()
    assert Handler._provision_dispatch(None, p, "privacy_center", "cust_ana",
                                       {"org_id": "org_a", "ip": "1.2.3.4"}) is None   # -> 404
    assert p.calls == []
    monkeypatch.setenv(FLAG, "1")
    p = _P()
    Handler._provision_dispatch(None, p, "privacy_center", "cust_ana",
                                {"org_id": "org_a", "ip": "1.2.3.4", "username": "cust_eve", "org": "org_z"})
    # the requester is the hop principal; the org is the session org the edge passed; a body username is never read
    assert p.calls == [("privacy_center", ("cust_ana", "org_a"), {"ip": "1.2.3.4"})]


# =====================================================================================================================
# 5. The isolation invariant for a PUBLISHED-facts screen: a session is REQUIRED over the real hop (401, fail-closed),
#    and the facts are org-INDEPENDENT — two orgs get byte-identical answers and a client cannot change them by naming
#    an org (there is NO org-specific data to isolate; the account/org come from the SESSION, never a client claim)
# =====================================================================================================================
def test_5_a_session_is_required_over_the_hop_and_the_facts_are_org_independent(tmp_path, monkeypatch):
    # (a) over the REAL loopback hop: an anonymous caller (no session) is refused 401 — the route is present, fail-closed
    # on auth — never the facts. (No sign-up here: the 401 is the edge's own session gate, so this needs no customer.)
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _sp = _stack(tmp_path, monkeypatch)
    try:
        assert _get(_opener(), ep, "/api/customer/privacy")[0] == 401
        assert _get(_opener(), ep, "/api/customer/privacy?username=cust_x&org_id=org_x")[0] == 401   # a claim alone is nobody
    finally:
        sov.shutdown()
        edge.shutdown()
    # (b) org-INDEPENDENCE, proven at the provisioner (deterministic): two customers in two different orgs get the SAME
    # published facts, and the same customer gets the same facts whatever org the edge passes — the answer never depends
    # on the org, so two workspaces can never see each other's data (there is nothing org-specific to see)
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    custs.create("ben@other.io", issued_at=1.0, password="password-xyz", username="cust_ben")
    canonical = {"ok": True, **store.read_privacy_center()}
    assert p.privacy_center("cust_ana", "org_a") == canonical
    assert p.privacy_center("cust_ben", "org_b") == canonical           # a different workspace: the SAME published facts
    assert p.privacy_center("cust_ana", "org_zzz") == canonical         # the org argument never changes the answer
    assert p.privacy_center("cust_ana", "") == canonical                # nor does an absent org
    assert [x["name"] for x in canonical["subprocessors"]] == list(_SUBPROCESSORS)
    assert [c["name"] for c in canonical["cookies"]] == list(_COOKIES)


# =====================================================================================================================
# 6. A pure read: an ACTIVE customer only, and it NEVER touches the signed append-only spine (no audit row)
# =====================================================================================================================
def test_6_read_only_active_customer_only_never_the_spine():
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    n = s.count()
    for _ in range(10):
        got = p.privacy_center("cust_ana", "org_a")
        assert got["ok"] is True and [c["name"] for c in got["cookies"]] == list(_COOKIES)
    assert s.count() == n                                              # not one read appended to the spine
    audits = [r.payload for r in s.iter_records() if isinstance(r.payload, dict)
              and r.payload.get("signal") == "provision.audit"
              and str(r.payload.get("action", "")).startswith("privacy")]
    assert audits == []
    # an inactive / unknown account is refused (active-customer only)
    custs.revoke("cust_ana")
    for who in ("cust_ana", "", "owner"):
        with pytest.raises(ProvisionDenied):
            p.privacy_center(who, "org_a")
    # the store carries the FATAL-2 sovereignty guard (assert_no_offense), like every sovereign-side module
    src = Path(store.__file__).read_text(encoding="utf-8")
    assert "from ..reuse import assert_no_offense" in src and "assert_no_offense()" in src


# =====================================================================================================================
# 7. Every class the Privacy screen renders is styled (no dead class), and it names no app.js writer
# =====================================================================================================================
def test_7_every_class_the_privacy_screen_renders_is_styled():
    src = APP_JS.read_text(encoding="utf-8")
    block = _privacy_block(src)
    css = APP_CSS.read_text(encoding="utf-8") + (APP / "components.css").read_text(encoding="utf-8")
    classes = set(re.findall(r'h\("(?:[a-z0-9]+)?((?:\.[\w-]+)+)"', block))
    rendered = {c for group in classes for c in group.split(".") if c}
    unstyled = sorted(c for c in rendered if ("." + c) not in css)
    assert unstyled == [], f"the Privacy screen renders class(es) with no style: {unstyled}"
    # it reaches the network only through its own read, and names no app.js writer (buy credits, launch, monitoring …)
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", block)
    assert re.findall(r'VUI\.(\w+JSON)\(', code) == [] and 'area6View("#/privacy"' in code
    for banned in ("postJSON", "fetch(", "XMLHttpRequest", "sendBeacon", "withStepUp", "startCheckout", "doLaunch",
                   "location.href", "location.assign", "window.open"):
        assert banned not in code, banned


# =====================================================================================================================
# 8. The correctness fix: the trust page no longer claims Flutterwave as the active card processor; it agrees with
#    the privacy page (Stripe for card payments)
# =====================================================================================================================
def test_8_trust_page_names_stripe_not_flutterwave_as_card_processor():
    trust = (PUBLIC / "trust" / "index.html").read_text(encoding="utf-8")
    privacy = (PUBLIC / "privacy" / "index.html").read_text(encoding="utf-8")
    # the subprocessor row of the trust page: the active card processor is Stripe, and Flutterwave is no longer named
    row = re.search(r"Hosted billing \(when used\)</th><td>([^<]*)</td>", trust)
    assert row, "the trust page's hosted-billing subprocessor row moved — re-aim this test"
    line = row.group(1)
    assert "Flutterwave" not in line, line                 # the paused processor is no longer claimed as active
    assert "Stripe" in line and "card payments" in line, line
    # and it agrees with the privacy page, which names Stripe for card payments
    assert "Flutterwave" not in privacy
    assert re.search(r"<strong>Stripe</strong>\s*—\s*card payments", privacy)
    # the Flutterwave BILLING ADAPTER code may still exist (default-off, paused) — this fix is only the public claim,
    # so the trust page agrees with the privacy page; we do not touch the adapter.
