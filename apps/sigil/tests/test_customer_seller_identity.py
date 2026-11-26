"""Legal/governance S7 — the customer Seller identity screen, behind VIGIL_CUSTOMER_SELLER_IDENTITY (default OFF).

The hosted VIGIL service is provided by one company, and consumer / distance-selling law requires the customer be able
to see who. S7 adds a #/seller-identity screen that DISPLAYS that identity — SIGIL SARL's published legal name, legal
form, registered city/country, registration number, contact email, website and governing law — and nothing else:

  * the identity is a GLOBAL, owner-reviewed CODE constant (ui/seller_identity.py), the SAME trust root as the catalog:
    every value is PUBLISHED verbatim on the public Terms and/or Privacy pages, never reworded, never invented, never a
    per-tenant wire field. Owner decision — PUBLISHED DETAILS ONLY: no street address, no phone, no VAT number;
  * Provisioner.seller_identity_get serves an ACTIVE customer only and returns that same global block whoever asks — it
    reads no per-tenant data, writes nothing, and NEVER touches the signed append-only spine (no audit row);
  * the cockpit's provision dispatch is absent (unknown action -> 404) unless the flag is on, and acts for the hop
    principal, never a body field;
  * the edge route GET api/customer/seller-identity is absent (404) unless the flag is on — the EDGE's own unknown-route
    404, nothing relayed — needs a session (401), and relays only the session principal (no org, no body claim);
  * app.js adds the Seller identity tab + #/seller-identity screen only while data-seller-identity="1"; off, it is
    byte-identical (no tab, #/seller-identity is the home screen, no seller-identity call is made). The screen is a pure
    display: one read, then a card of the published values — no form, no Save, no POST, no money or authority control.

Each test here is one acceptance point for slice S7.
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
from test_custui import _get, _opener, _post, _stack
# the executed-JS harness (a minimal DOM + node runner), shared verbatim with the Team and Settings screens' proofs
from test_customer_team import _fn, _line, _need_node, _node

from sigil import config
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import seller_identity as si
from sigil.ui.custui import CustomerHandler, build_customer_server
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, Provisioner

FLAG = "VIGIL_CUSTOMER_SELLER_IDENTITY"
APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
INDEX_HTML = APP / "index.html"
PUBLIC_SITE = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "public_site"
TERMS = PUBLIC_SITE / "terms" / "index.html"
PRIVACY = PUBLIC_SITE / "privacy" / "index.html"
OWNER = generate_keypair()
OP = OWNER.public_key_b64

#: The published block, straight from the owner-reviewed source — the single source of truth the screen renders.
_PUBLISHED = si.published_seller_identity()
#: [key, label] the screen shows, in order — mirrors app.js's SELLER_FIELDS exactly (one source).
_FIELDS = [
    ("legal_name", "Legal name"),
    ("legal_name_expansion", "In full"),
    ("legal_form", "Legal form"),
    ("registered_city", "Registered in"),
    ("registered_country", "Country"),
    ("registration_number", "Registration number"),
    ("contact_email", "Contact email"),
    ("website", "Website"),
    ("governing_law", "Governing law"),
]


@pytest.fixture(autouse=True)
def _no_flag(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)


# --- the provisioner / spine (mirrors the settings-shell harness) ----------------------------------------------------
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


def _signed_up(tmp_path, monkeypatch, email):
    sov, edge, ep, sp = _stack(tmp_path, monkeypatch)
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "Acme"})
    assert conf[0] == 200, conf
    return sov, edge, ep, op, conf[1]["username"]


def _sign_in(ep, email):
    op = _opener()
    c, r = _post(op, ep, "/api/customer/login", {"email": email, "password": "customer-pw-1"})
    assert c == 200, (c, r)
    return op, r["username"]


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


def _edge_stub(session, reply=None):
    """The edge's OWN handler, I/O stubbed: the session it sees, and every hop to the cockpit RECORDED (an ``action`` in
    ``sent`` means the edge relayed) — so a test sees what the edge itself answers, never what the cockpit would."""
    h = object.__new__(CustomerHandler)
    sent = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                    or (200, reply if reply is not None else {"ok": True,
                                                                                              "seller": _PUBLISHED}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


# --- the executed-JS harness for the screen (node) -------------------------------------------------------------------
def _seller_block(src: str) -> str:
    i = src.index("  // ---- Seller identity (VIGIL_CUSTOMER_SELLER_IDENTITY)")
    return src[i:src.index("  // ---- misc", i)]


_WORLD = r"""
document.body.dataset.sellerIdentity = __FLAG__;
globalThis.location = { hash: "#/seller-identity" };
let who = { authenticated: true, username: "cust_me" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const navs = []; function nav(r) { navs.push(r); }
let refreshed = 0; async function refreshWho() { refreshed++; }
const calls = [];
let seller = __SELLER__;
let getFail = null, getReply = null;
function failure(f) { const e = new Error(f.message || (f.data && f.data.error) || "failed");
  e.status = f.status; e.data = f.data || null; return e; }
const VUI = window.VUI;
VUI.getJSON = async p => { calls.push(["GET", p]); if (getFail) { const f = getFail; getFail = null; throw failure(f); }
  if (getReply) { const r = getReply; getReply = null; return r; }
  return { ok: true, seller: seller }; };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); return { ok: true }; };
// every other way a page could reach the network, recorded — each answering inertly: the screen must use none of them
const raw = [];
globalThis.fetch = async u => { raw.push(["fetch", String(u)]);
  return { ok: false, status: 599, headers: { get: () => null }, json: async () => ({}), text: async () => "" }; };
globalThis.XMLHttpRequest = function () { raw.push(["xhr"]); this.open = () => {}; this.send = () => {};
  this.setRequestHeader = () => {}; };
try { Object.defineProperty(globalThis, "navigator", { configurable: true,
  value: { sendBeacon: u => { raw.push(["beacon", String(u)]); return true; } } }); } catch (e) { /* kept as is */ }
const toasts = []; VUI.toast = m => { toasts.push(m); };
var GUIDE = null, GUIDE_ON = false, MONITORING_ON = false, CODE_ON = false, CONNECT_ON = false, POSTURE_ON = false;
function shell(inner, current) { return h("div.cust-shell", { dataset: { current: current } }, inner); }
function viewLogin() { return h("div.cust-login"); }
function viewDashboard() { return h("div.cust-dash"); }
const root = new El("div"); document.body.appendChild(root);
function show() { VUI.mount(root, ROUTES["#/seller-identity"]()); return root; }
"""


def _seller_app(flag: str = "1", seller=None) -> str:
    """The harness: the stubs above plus app.js's own code for the Seller identity screen, extracted verbatim — the
    Seller identity block and the helpers it calls (h, pageFlag, API, kv, here, loadingHolder)."""
    src = APP_JS.read_text(encoding="utf-8")
    world = (_WORLD.replace("__FLAG__", json.dumps(flag))
             .replace("__SELLER__", json.dumps(seller if seller is not None else _PUBLISHED)))
    return "\n".join([world,
                      _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                      _line(src, r'^  var API = "[^"]*";'), _fn(src, "kv"),
                      _line(src, r"^  function here\(\) \{.*\}$"), _fn(src, "loadingHolder"),
                      _seller_block(src),
                      'const ROUTES = {\n' + _line(src, r'^    "#/seller-identity": function .*,$') + '\n};'])


# =====================================================================================================================
# 1. Flag OFF: route 404, index placeholder unexpanded, page + app.js byte-identical bar the flag
# =====================================================================================================================
def test_1_flag_off_route_404_page_and_nav_byte_identical(tmp_path, monkeypatch):
    sov, edge, ep, op, user = _signed_up(tmp_path, monkeypatch, "off@acme.io")
    try:
        # the EDGE's own unknown-route 404, signed in or not — never the cockpit's "unknown provision action"
        for who in (op, _opener()):
            assert _get(who, ep, "/api/customer/seller-identity") == (404, {"error": "not found"})
    finally:
        sov.shutdown()
        edge.shutdown()
    # the page: the flag is its only difference (its value + the build id it changes) — byte-identical otherwise
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-seller-identity="0"' in off and "__VIGIL_SELLER_IDENTITY__" not in off
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-seller-identity="1"' in on and build_on != build_off
    assert on.replace('data-seller-identity="1"', 'data-seller-identity="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv(FLAG, v)
        assert 'data-seller-identity="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v
    # the index template's placeholder is still a placeholder (flag-driven, defaulting off), not hardcoded on
    assert 'data-seller-identity="__VIGIL_SELLER_IDENTITY__"' in INDEX_HTML.read_text(encoding="utf-8")
    # app.js: the Seller identity tab and route are flag-guarded, so off they add no screen to the nav or the router
    src = APP_JS.read_text(encoding="utf-8")
    assert '  var SELLER_IDENTITY_ON = pageFlag("sellerIdentity");' in src
    assert '.concat(SELLER_IDENTITY_ON ? [navLink("Seller identity", "#/seller-identity")] : [])' in src
    assert ('    "#/seller-identity": function () { return authed() ? (SELLER_IDENTITY_ON ? viewSellerIdentity()'
            ' : viewDashboard()) : viewLogin(); },') in src


# =====================================================================================================================
# 1b. Flag OFF: the EDGE itself refuses the read and relays nothing — independently of the cockpit's own gate
# =====================================================================================================================
def test_1b_flag_off_the_edge_answers_its_own_404_and_relays_nothing(monkeypatch):
    session = {"username": "cust_ana", "org_id": "org_a"}
    for value in (None, "0", "", "no", "off", "maybe"):
        if value is None:
            monkeypatch.delenv(FLAG, raising=False)
        else:
            monkeypatch.setenv(FLAG, value)
        h, sent = _edge_stub(session)
        h.path = "/api/customer/seller-identity"
        h.do_GET()
        assert sent == {"code": 404, "out": {"error": "not found"}}, value     # no "action": nothing relayed
    # positive control: the very same stubbed edge, flag on, relays the read for the session's account
    monkeypatch.setenv(FLAG, "1")
    h, sent = _edge_stub(session)
    h.path = "/api/customer/seller-identity"
    h.do_GET()
    assert (sent["action"], sent["principal"], sent["code"]) == ("seller_identity_get", "cust_ana", 200)
    assert sent["body"] == {"ip": "1.2.3.4"}                                    # only the hop ip travels, no org/body


# =====================================================================================================================
# 2. Flag ON: the screen renders the published block, through its one read, and adds no control (no POST, no writer)
# =====================================================================================================================
def test_2_flag_on_screen_renders_published_values_and_adds_no_control():
    _need_node()
    out = _node(_seller_app("1", _PUBLISHED) + r"""
show(); await tick();
out.on = SELLER_IDENTITY_ON;
out.title = text(root.querySelector("h2"));
out.onRender = calls.slice();                                             // what the screen calls just to render
out.rows = root.querySelectorAll(".cust-kv").map(r => { const s = r.querySelectorAll("span");
  return [text(s[0]), text(s[1])]; });
out.buttons = buttons(root);
for (const b of root.querySelectorAll("button")) { b.click(); await tick(); await tick(); }
out.afterClicks = calls.slice(out.onRender.length);
out.navs = navs.slice();
out.raw = raw;
""")
    assert out["on"] is True and out["title"] == "Seller identity"
    # rendering only READS the published block once — no POST, so the screen adds no new authority/money mutation
    assert out["onRender"] == [["GET", "api/customer/seller-identity"]]
    # the card shows every published field, in order, with the EXACT published value — the screen renders, never invents
    assert out["rows"] == [[label, _PUBLISHED[key]] for key, label in _FIELDS]
    # a pure display: no button in the happy path, so nothing to click, nothing navigated, nothing else to the network
    assert out["buttons"] == [] and out["afterClicks"] == [] and out["navs"] == [] and out["raw"] == []
    # the source: the Seller block's code (its comments dropped) reaches the network only through its own read route,
    # and never writes
    block = _seller_block(APP_JS.read_text(encoding="utf-8"))
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", block)
    assert re.findall(r"VUI\.(\w+JSON)\(API \+ \"([^\"]*)\"", code) == [("getJSON", "/seller-identity")]
    assert len(re.findall(r"\bAPI\b", code)) == 1 and not re.search(r"[\"'`]/?api/", code)
    for banned in ("postJSON", "fetch(", "XMLHttpRequest", "sendBeacon", "uploadChunked", ".sse(", "withStepUp",
                   "location.href", "location.assign", "location.replace", "window.open"):
        assert banned not in code, banned


# =====================================================================================================================
# 3. Every published value is the canonical public-site text, verbatim — never a reworded or invented copy
# =====================================================================================================================
def test_3_the_published_values_are_exactly_the_canonical_public_site_text():
    terms = TERMS.read_text(encoding="utf-8")
    privacy = PRIVACY.read_text(encoding="utf-8")
    both = terms + "\n" + privacy
    terms_flat = re.sub(r"\s+", " ", terms)             # the published prose wraps across lines; compare flattened
    # the identity the module publishes is exactly the owner's published facts — a change here must change the public
    # pages too (and vice versa), so neither can drift into a reworded or invented seller identity
    assert _PUBLISHED["legal_name"] == "SIGIL SARL"
    assert _PUBLISHED["legal_name_expansion"] == "Sovereign Integrity Governance Infrastructure Labs"
    assert _PUBLISHED["registration_number"] == "RCCM RC.BUA.2026.B.0190"
    assert _PUBLISHED["contact_email"] == "info@sigilsovereign.com"
    assert _PUBLISHED["website"] == "sigilsovereign.com"
    assert (_PUBLISHED["registered_city"], _PUBLISHED["registered_country"]) == ("Buea", "Cameroon")
    # each atomic published fact appears VERBATIM on the canonical pages
    assert "SIGIL SARL" in terms and "SIGIL SARL" in privacy
    assert "Sovereign Integrity Governance Infrastructure Labs" in terms
    assert "SARL" in terms and "société à responsabilité limitée" in terms.lower()  # the legal form, as published
    assert "Buea" in both and "Cameroon" in both
    assert "RC.BUA.2026.B.0190" in terms and "RC.BUA.2026.B.0190" in privacy
    assert "info@sigilsovereign.com" in privacy and "info@sigilsovereign.com" in terms
    assert "sigilsovereign.com" in terms
    # the legal form and governing law the module shows are the published wording, not a paraphrase
    assert "société à responsabilité limitée" in _PUBLISHED["legal_form"].lower() and "SARL" in _PUBLISHED["legal_form"]
    assert "the laws of the Republic of Cameroon, including the applicable OHADA Uniform Acts" in terms_flat
    assert _PUBLISHED["governing_law"] == "the laws of the Republic of Cameroon, including the applicable OHADA Uniform Acts"
    # owner decision — PUBLISHED DETAILS ONLY: no street address, no phone, no VAT / tax number is published or shown
    for forbidden in ("vat", "tax", "phone", "tel", "street", "address"):
        assert not any(forbidden in k for k in _PUBLISHED), forbidden
    joined = " ".join(_PUBLISHED.values())
    assert "VAT" not in joined and "+" not in joined        # no VAT line, no phone number


# =====================================================================================================================
# 4. Account = the hop-bound session principal; a body/org claim is ignored; the block is GLOBAL (same for everyone)
# =====================================================================================================================
def test_4_account_is_the_hop_principal_block_is_global(monkeypatch):
    # (a) the cockpit dispatch: absent without the flag; with it, the account is the hop principal, never a body field
    from sigil.ui.server import Handler

    class _P:
        def __init__(self):
            self.calls = []

        def __getattr__(self, name):
            def f(*a, **k):
                self.calls.append((name, a, k))
                return {"ok": True, "seller": _PUBLISHED}
            return f

    monkeypatch.delenv(FLAG, raising=False)
    p = _P()
    assert Handler._provision_dispatch(None, p, "seller_identity_get", "cust_ana", {"ip": "1.2.3.4"}) is None  # -> 404
    assert p.calls == []
    monkeypatch.setenv(FLAG, "1")
    p = _P()
    Handler._provision_dispatch(None, p, "seller_identity_get", "cust_ana",
                                {"username": "cust_eve", "org_id": "org_z", "ip": "1.2.3.4"})
    assert p.calls == [("seller_identity_get", ("cust_ana",), {})]              # the body's account claim is ignored

    # (b) the edge: a query naming another account changes nothing; the principal is the session username, no org
    h, sent = _edge_stub({"username": "cust_ana", "org_id": "org_a"})
    h.path = "/api/customer/seller-identity?username=cust_eve&org_id=org_z"
    h.do_GET()
    assert sent["action"] == "seller_identity_get" and sent["principal"] == "cust_ana"
    assert sent["body"] == {"ip": "1.2.3.4"}                                    # only the hop ip, never an org claim
    for session in (None, {}, {"username": ""}):
        h, sent = _edge_stub(session)
        h.path = "/api/customer/seller-identity"
        h.do_GET()
        assert sent["code"] == 401 and "action" not in sent, session           # no session -> 401, nothing relayed

    # (c) the block is GLOBAL: two different active customers get the SAME published identity (no per-tenant data)
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    custs.create("ben@other.io", issued_at=1.0, password="password-xyz", username="cust_ben")
    a = p.seller_identity_get("cust_ana")
    b = p.seller_identity_get("cust_ben")
    assert a == b == {"ok": True, "seller": _PUBLISHED}


# =====================================================================================================================
# 5. Read-only: active-customer only, never a spine write, and the sovereignty guard is present
# =====================================================================================================================
def test_5_read_only_active_customer_only_and_off_the_spine():
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    n = s.count()
    # many reads — none appends to the spine, none is audited
    for _ in range(10):
        assert p.seller_identity_get("cust_ana") == {"ok": True, "seller": _PUBLISHED}
    assert s.count() == n
    audits = [r.payload for r in s.iter_records() if isinstance(r.payload, dict)
              and r.payload.get("signal") == "provision.audit"
              and "seller" in str(r.payload.get("action", ""))]
    assert audits == []
    # an inactive / unknown account is refused (active-customer only), like every other account-level read
    custs.revoke("cust_ana")
    for who in ("cust_ana", "", "owner", "nobody"):
        with pytest.raises(ProvisionDenied):
            p.seller_identity_get(who)
    # the module carries the FATAL-2 sovereignty guard (no offense-engine import may ride the edge plane)
    src = Path(si.__file__).read_text(encoding="utf-8")
    assert "from ..reuse import assert_no_offense" in src and "assert_no_offense()" in src
    # a fresh copy each call: a caller cannot mutate the global constant through the returned dict
    one = si.published_seller_identity()
    one["legal_name"] = "TAMPERED"
    assert si.published_seller_identity()["legal_name"] == "SIGIL SARL"


# =====================================================================================================================
# 6. Over the REAL loopback hop: the read round-trips with the flag on, needs a session, and is absent with it off
# =====================================================================================================================
def test_6_get_round_trips_over_the_real_hop(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, op, ana = _signed_up(tmp_path, monkeypatch, "ana@acme.io")
    try:
        anon = _opener()
        assert _get(anon, ep, "/api/customer/seller-identity")[0] == 401       # no session
        # the signed-in account reads the published block
        c, r = _get(op, ep, "/api/customer/seller-identity")
        assert (c, r) == (200, {"ok": True, "seller": _PUBLISHED}), (c, r)
        # a sign-in on another device sees the SAME global block
        op2, again = _sign_in(ep, "ana@acme.io")
        assert again == ana and _get(op2, ep, "/api/customer/seller-identity") == (200, {"ok": True, "seller": _PUBLISHED})
    finally:
        sov.shutdown()
        edge.shutdown()
    # with the flag OFF the route is genuinely ABSENT (404), not a masked 401 — the backend is gone as the tab is
    monkeypatch.delenv(FLAG, raising=False)
    sov, edge, ep, op, ana = _signed_up(tmp_path / "off", monkeypatch, "ana2@acme.io")
    try:
        assert _get(op, ep, "/api/customer/seller-identity")[0] == 404
    finally:
        sov.shutdown()
        edge.shutdown()
