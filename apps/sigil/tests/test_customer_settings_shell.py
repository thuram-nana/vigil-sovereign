"""Legal/governance S1 — the customer settings shell + the General preferences hub, behind VIGIL_CUSTOMER_SETTINGS
(default OFF).

The settings shell is a #/settings hub in the customer app that LINKS the screens that already exist (Account security,
Authorized administrators = the Team screen, Billing) and adds a General tab that captures the workspace's legal-entity
/ contact profile. That profile is a UI PREFERENCE — never money, never authority, never a signed spine record — kept
server-side, per account:

  * ui/preferences_store keeps one hashed-name 0600 file per account in a 0700 directory of its own
    ($SIGIL_HOME/customer_preferences — the backup CAPTURES it: the customer typed it and nothing regenerates it); only
    the CLOSED PREFERENCE_KEYS allowlist of string fields that are valid text is ever stored. A missing or symlinked
    file holds no profile (the documented DEFAULTS); a file that is there but cannot be read as a whole profile (an I/O
    error, anything but a regular file, oversized, not UTF-8, malformed; a short read is read on to the end) reads as
    the DEFAULTS in the lenient read and is ProfileUnreadable in the STRICT read the General tab and every save use; no
    open ever blocks (a FIFO at an account's path never holds the save lock);
  * a save merges ONLY the keys it names (one save at a time, so concurrent saves of different fields both land), and
    is refused with nothing written rather than ever losing a field: a record over the read bound (_MAX_BYTES, measured
    on the SERIALISED bytes — an accepted save always reads back as accepted), a lone surrogate or body bytes that are
    not text, or that the parser refuses (a clean 400 in the route's own words, never a codec's or the parser's
    message; every other route keeps its own answer), a stored file that cannot be read (a store fault: a 500,
    never a 400 that blames a field);
  * Provisioner.preferences_get / preferences_set serve an ACTIVE customer only, enforce the allowlist, and write to
    the per-account store — NEVER to the signed append-only spine (no audit row): a customer cannot grow the spine by
    saving the tab;
  * the cockpit's provision dispatch is absent (unknown action -> 404) unless the flag is on, and acts for the hop
    principal, never a body field;
  * the edge route GET/POST api/customer/preferences is absent (404) unless the flag is on — the EDGE's own unknown-route
    / unknown-action 404, with nothing relayed to the cockpit — needs a session (401), and reads/records for the
    session's account only — a body naming another account changes nothing for it;
  * app.js adds the Settings tab + #/settings hub only while data-settings="1"; off, it is byte-identical (no tab,
    #/settings is the home screen, no preferences call is made). The hub links Account security only where that
    screen is shown; a failed read shows an error with Save disabled (never an empty form); Save sends only the
    fields the customer changed; and every class it renders is styled;
  * the in-app guide covers the Settings screen (its step names the page switch, ``when: "settings"``) and lists it only
    while routeShown shows #/settings: with the flag off the Guide screen is byte-identical and the tour never visits it.

Each test here is one acceptance bullet for slice S1. Mutation-verify targets (each neuter reds a NAMED test here):
  * read_prefs ignores the file (always defaults)             -> test_9_get_post_get_round_trips_for_the_same_account
  * write_prefs accepts any key                               -> test_7_store_rejects_keys_outside_the_closed_allowlist
  * read_prefs follows a symlink / reads odd bytes            -> test_6_malformed_or_oversized_file_reads_as_default
  * a damaged file is merged onto as the empty defaults       -> test_6_malformed_or_oversized_file_reads_as_default
  * one read is taken for the whole file / a failed read kept -> test_6b_a_short_read_is_never_taken_for_the_whole_file
  * the open blocks on a FIFO / a special file is read        -> test_6c_a_special_file_at_an_accounts_path_never_blocks_and_is_never_read
  * an account name with no UTF-8 form raises the codec error -> test_6d_an_account_name_with_no_utf8_form_holds_no_profile
  * the provisioner skips the active-customer check           -> test_5_account_is_the_hop_principal_no_cross_account
  * the provisioner audits / writes the spine                 -> test_8_preferences_never_touch_the_signed_spine
  * the cockpit dispatch ignores the flag / takes the body    -> test_5_account_is_the_hop_principal_no_cross_account
  * the edge GET route ignores the flag                       -> test_1b_flag_off_the_edge_answers_its_own_404_and_relays_nothing
                                                                 (and test_1, by the 404's exact body)
  * the edge POST action ignores the flag                     -> test_1b_flag_off_the_edge_answers_its_own_404_and_relays_nothing
                                                                 (and test_1, by the 404's exact body)
  * the edge takes the account from the body                  -> test_5_account_is_the_hop_principal_no_cross_account
  * the edge always writes data-settings="1"                  -> test_1_flag_off_route_404_page_and_nav_byte_identical
  * the hub invents an authority/money control, spends credits
    or changes monitoring (a POST, a raw request, an app.js
    writer such as startCheckout / doLaunch / monTurnOn)      -> test_2_flag_on_hub_renders_and_links_existing_screens
  * the guide has no Settings step                            -> test_11_the_guide_covers_settings_only_while_it_is_shown
                                                                 (and test_customer_onboarding's screen census)
  * the guide lists a switch-named step whatever the switch   -> test_11_the_guide_covers_settings_only_while_it_is_shown
  * the guide names Account security with that screen off     -> test_11_the_guide_covers_settings_only_while_it_is_shown
  * routeShown ignores the settings flag                      -> test_11_the_guide_covers_settings_only_while_it_is_shown
  * the store caps code points, not the serialised bytes      -> test_12_an_accepted_save_always_reads_back_as_accepted
  * the store takes a lone surrogate / the read surfaces one  -> test_13_unencodable_text_is_refused_in_plain_words
  * the provisioner lets a codec error's message through      -> test_13_unencodable_text_is_refused_in_plain_words
                                                                 (end to end: test_13b)
  * the edge echoes the codec's or the parser's message for a
    body it cannot read, its plain refusal ignores the flag or
    the route, or calls every refusal "not valid text"        -> test_13b_over_the_real_hop_bad_input_is_a_clean_400_and_changes_nothing
  * a failed read renders an (empty) form / Save enabled      -> test_14_a_failed_read_shows_an_error_and_save_is_disabled
  * Save sends every field, not only the changed ones         -> test_14_a_failed_read_shows_an_error_and_save_is_disabled
                                                                 (an untouched value with spaces around it: test_14b)
  * a save reply without the profile mounts an empty form, or
    a read failing after the customer left changes the page   -> test_14b_after_a_save_the_tab_shows_what_is_stored_and_never_a_blank_profile
  * a save merges onto defaults when the file cannot be read  -> test_15_the_server_merges_only_the_keys_it_is_sent
  * the tab's read shows an unreadable file as an empty
    profile / a store fault is a 400 that blames a field      -> test_15c_a_stored_profile_that_cannot_be_read_is_an_error_on_the_tab_never_an_empty_form
  * saves are not serialized (no _SAVE_LOCK)                  -> test_15b_concurrent_saves_of_different_fields_both_land
  * the backup leaves the profile out / restores it umask     -> test_10_backup_captures_the_profile_and_toggle_off_is_byte_identical
                                                                 (and test_backup_recovery_functional)
  * the hub links Account security with that screen off      -> test_16_the_hub_links_account_security_only_where_it_is_shown
  * the hub ignores routeShown                                -> test_16_the_hub_links_account_security_only_where_it_is_shown
  * a class the Settings block renders has no style           -> test_17_every_class_the_settings_hub_renders_is_styled
"""
from __future__ import annotations

import errno
import http.client
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
# the executed-JS harness (a minimal DOM + node runner), shared verbatim with the Team screen's proofs
from test_customer_team import _fn, _line, _need_node, _node

from sigil import config
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import preferences_store as store
from sigil.ui.custui import CustomerHandler, build_customer_server
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionError, Provisioner

FLAG = "VIGIL_CUSTOMER_SETTINGS"
APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
APP_CSS = APP / "app.css"
INDEX_HTML = APP / "index.html"
OWNER = generate_keypair()
OP = OWNER.public_key_b64

_PROFILE = {
    "legal_entity_name": "Acme SARL",
    "registered_address": "1 Rue de la Paix, 75002 Paris, FR",
    "contractual_contact_email": "legal@acme.example",
    "emergency_contact_name": "Dana Ops",
    "emergency_contact_phone": "+33 1 23 45 67 89",
    "emergency_contact_email": "soc@acme.example",
}


@pytest.fixture(autouse=True)
def _no_flag(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)


@pytest.fixture
def home(tmp_path, monkeypatch):
    d = tmp_path / "customer_preferences"
    monkeypatch.setattr(config, "CUSTOMER_PREFERENCES_DIR", d)
    return d


# --- the provisioner / spine (mirrors the onboarding harness) --------------------------------------------------------
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


def _post_raw(opener, port, path, data: bytes):
    """A POST of these exact body bytes (the shared _post re-encodes its body as JSON), answered as (status, body)."""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method="POST",
                                 headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"})
    try:
        with opener.open(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


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
                                                    or (200, {"ok": True, "preferences": store.DEFAULTS}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


# --- the executed-JS harness for the hub (node) ----------------------------------------------------------------------
def _settings_block(src: str) -> str:
    i = src.index("  // ---- Settings (VIGIL_CUSTOMER_SETTINGS)")
    return src[i:src.index("  // ---- shell", i)]


_WORLD_S = r"""
document.body.dataset.settings = __FLAG__;
document.body.dataset.security = __SECURITY__;
if (__SECURITY_JS__) { window.VIGIL_SECURITY = {}; }        // security.js loaded (the page loads it before app.js)
globalThis.location = { hash: "#/settings" };
let who = { authenticated: true, username: "cust_me" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const navs = []; function nav(r) { navs.push(r); }
let refreshed = 0; async function refreshWho() { refreshed++; }
const calls = [];
let prefs = __PREFS__;
let getFail = null, postFail = null, getReply = null, postReply = null;
function failure(f) { const e = new Error(f.message || (f.data && f.data.error) || "failed");
  e.status = f.status; e.data = f.data || null; return e; }
const VUI = window.VUI;
VUI.getJSON = async p => { calls.push(["GET", p]); if (getFail) { const f = getFail; getFail = null; throw failure(f); }
  if (getReply) { const r = getReply; getReply = null; return r; }
  return { ok: true, preferences: prefs }; };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); if (postFail) { const f = postFail; postFail = null; throw failure(f); }
  prefs = Object.assign({}, prefs, (b && b.preferences) || {});
  if (postReply) { const r = postReply; postReply = null; return r; }
  return { ok: true, preferences: prefs }; };
// every other way a page could reach the network, recorded — each answering inertly, so a call is seen in `raw`, not
// lost to a crash: the hub must use none of them
const raw = [];
globalThis.fetch = async u => { raw.push(["fetch", String(u)]);
  return { ok: false, status: 599, headers: { get: () => null }, json: async () => ({}), text: async () => "" }; };
globalThis.XMLHttpRequest = function () { raw.push(["xhr"]); this.open = () => {}; this.send = () => {};
  this.setRequestHeader = () => {}; };
try { Object.defineProperty(globalThis, "navigator", { configurable: true,
  value: { sendBeacon: u => { raw.push(["beacon", String(u)]); return true; } } }); } catch (e) { /* kept as is */ }
VUI.uploadChunked = async u => { raw.push(["upload", String(u)]); return {}; };
VUI.sse = u => { raw.push(["sse", String(u)]); return { close() {} }; };
// every call to one of app.js's own writers (buy credits, launch, monitoring on/off ...), recorded by its stand-in
// (_writer_stubs): the hub must call none of them
const writes = [];
const toasts = []; VUI.toast = m => { toasts.push(m); };
const banners = []; VUI.errorBanner = m => { banners.push(m); };
var GUIDE = null, GUIDE_ON = false, MONITORING_ON = false, CODE_ON = false, CONNECT_ON = false, POSTURE_ON = false;
function shell(inner, current) { return h("div.cust-shell", { dataset: { current: current } }, inner); }
function viewLogin() { return h("div.cust-login"); }
function viewDashboard() { return h("div.cust-dash"); }
const root = new El("div"); document.body.appendChild(root);
function show() { VUI.mount(root, ROUTES["#/settings"]()); return root; }
"""


def _settings_app(flag: str = "1", prefs=None, *, security: str = "1", security_js: bool = True) -> str:
    """The harness: the stubs above plus app.js's own code for the hub, extracted verbatim — the Settings block, the
    helpers it calls, routeShown and the Account-security switch (``security``: its page flag; ``security_js``: whether
    security.js is on the page) — and a recording stand-in for each of app.js's writers (``_writer_stubs``)."""
    src = APP_JS.read_text(encoding="utf-8")
    world = (_WORLD_S.replace("__FLAG__", json.dumps(flag)).replace("__SECURITY__", json.dumps(security))
             .replace("__SECURITY_JS__", json.dumps(security_js))
             .replace("__PREFS__", json.dumps(prefs if prefs is not None else {})))
    harness = "\n".join([world,
                         _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                         _line(src, r'^  var API = "[^"]*";'), _fn(src, "field"),
                         _line(src, r"^  function val\(id\) \{.*\}$"), _line(src, r"^  function here\(\) \{.*\}$"),
                         _fn(src, "loadingHolder"), _line(src, r"^  function err\(msg\) \{.*$"),
                         _line(src, r"^  var SECURITY = window\.VIGIL_SECURITY;$"),
                         _line(src, r"^  var SECURITY_ON = .*;$"),
                         _line(src, r"^  function routeShown\(route\) \{.*\}$"),
                         _settings_block(src),
                         'const ROUTES = {\n' + _line(src, r'^    "#/settings": function .*,$') + '\n};'])
    return harness + "\n" + _writer_stubs(src, harness)


def _writer_stubs(src: str, harness: str) -> str:
    """A stand-in for each of app.js's own writers (``_app_writers``) the harness does not define itself: a call to one
    is RECORDED in ``writes`` — so a hub that buys credits or turns monitoring on reds on what it called, rather than
    only crashing on a name the harness lacks."""
    names = sorted(n for n in _app_writers(src, _settings_block(src))
                   if not re.search(r"\bfunction " + re.escape(n) + r"\(", harness))
    return "\n".join(f'function {n}() {{ writes.push("{n}"); return Promise.resolve({{}}); }}' for n in names)


def _top_level_functions(src: str) -> dict:
    """app.js's top-level (two-space) function declarations: name -> its source (a one-liner, or up to its closing
    ``  }`` line)."""
    out, lines, i = {}, src.split("\n"), 0
    while i < len(lines):
        m = re.match(r"^  (?:async )?function (\w+)\(", lines[i])
        if not m:
            i += 1
            continue
        if lines[i].rstrip().endswith("}") and lines[i].count("{") == lines[i].count("}"):
            out[m.group(1)] = lines[i]
            i += 1
            continue
        j = i + 1
        while j < len(lines) and lines[j] != "  }":
            j += 1
        out[m.group(1)] = "\n".join(lines[i:j + 1])
        i = j + 1
    return out


# A write, as app.js makes one: the kit's POST, the step-up wrapper every money / authority change rides, an upload,
# or a raw request.
_WRITE = re.compile(r"postJSON\(|withStepUp\(|uploadChunked\(|sendBeacon|XMLHttpRequest|\bfetch\(")


def _app_writers(src: str, block: str) -> set:
    """The names of app.js's own functions OUTSIDE the Settings block that make a write themselves (buy credits,
    launch or retest, turn monitoring on or off, change the team, sign in or out ...) — computed from app.js, so a
    writer added later is covered too."""
    rest = src.replace(block, "")
    return {name for name, body in _top_level_functions(rest).items() if _WRITE.search(body)}


# =====================================================================================================================
# 1. Flag OFF: route 404, index placeholders unexpanded, nav byte-identical
# =====================================================================================================================
def test_1_flag_off_route_404_page_and_nav_byte_identical(tmp_path, monkeypatch, home):
    # the edge route is exactly an unknown route (404) with the flag off, and nothing is served or recorded
    sov, edge, ep, op, user = _signed_up(tmp_path, monkeypatch, "off@acme.io")
    try:
        # the EDGE's own answers (its unknown-route / unknown-action 404), signed in or not — never the cockpit's
        # "unknown provision action", which is what a request the edge had relayed would get back
        for who in (op, _opener()):
            assert _get(who, ep, "/api/customer/preferences") == (404, {"error": "not found"})
            assert _post(who, ep, "/api/customer/preferences",
                         {"preferences": _PROFILE}) == (404, {"error": "unknown action"})
        assert not home.exists()
    finally:
        sov.shutdown()
        edge.shutdown()
    # the page: the flag is its only difference (its value + the build id it changes) — byte-identical otherwise
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-settings="0"' in off and "__VIGIL_SETTINGS__" not in off
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-settings="1"' in on and build_on != build_off
    assert on.replace('data-settings="1"', 'data-settings="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv(FLAG, v)
        assert 'data-settings="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v
    # the index template's placeholder is still a placeholder (flag-driven, defaulting off), not hardcoded on
    assert 'data-settings="__VIGIL_SETTINGS__"' in INDEX_HTML.read_text(encoding="utf-8")
    # app.js: the Settings tab and route are flag-guarded, so off they add no screen to the nav or the router
    src = APP_JS.read_text(encoding="utf-8")
    assert '  var SETTINGS_ON = pageFlag("settings");' in src
    assert '.concat(SETTINGS_ON ? [navLink("Settings", "#/settings")] : [])' in src
    assert ('    "#/settings": function () { return authed() ? (SETTINGS_ON ? viewSettings() : viewDashboard())'
            ' : viewLogin(); },') in src


# =====================================================================================================================
# 1b. Flag OFF: the EDGE itself refuses both verbs and relays nothing — independently of the cockpit's own gate
# =====================================================================================================================
def test_1b_flag_off_the_edge_answers_its_own_404_and_relays_nothing(monkeypatch):
    """The edge's two flag gates stand on their own, not only behind the cockpit's: with the flag off the POST action is
    the edge's OWN unknown-action 404 and the GET its own unknown-route 404, and NOTHING is relayed to the cockpit —
    even for a signed-in account. (End to end, a relayed request would 404 too, at the cockpit's gate, so a bare 404
    status cannot tell the two gates apart; here the stubbed hop records any relay the edge attempts.)"""
    session = {"username": "cust_ana", "org_id": "org_a"}
    for value in (None, "0", "", "no", "off", "maybe"):
        if value is None:
            monkeypatch.delenv(FLAG, raising=False)
        else:
            monkeypatch.setenv(FLAG, value)
        h, sent = _edge_stub(session)
        h._dispatch("preferences", {"preferences": _PROFILE, "username": "cust_eve"})
        assert sent == {"code": 404, "out": {"error": "unknown action"}}, value     # no "action": nothing relayed
        h, sent = _edge_stub(session)
        h.path = "/api/customer/preferences"
        h.do_GET()
        assert sent == {"code": 404, "out": {"error": "not found"}}, value
    # positive control: the very same stubbed edge, flag on, relays each verb for the session's account
    monkeypatch.setenv(FLAG, "1")
    h, sent = _edge_stub(session)
    h._dispatch("preferences", {"preferences": _PROFILE})
    assert (sent["action"], sent["principal"], sent["code"]) == ("preferences_set", "cust_ana", 200)
    h, sent = _edge_stub(session)
    h.path = "/api/customer/preferences"
    h.do_GET()
    assert (sent["action"], sent["principal"], sent["code"]) == ("preferences_get", "cust_ana", 200)


# =====================================================================================================================
# 2. Flag ON: the #/settings hub renders and links the existing screens; adds no authority/money control
# =====================================================================================================================
def test_2_flag_on_hub_renders_and_links_existing_screens(tmp_path):
    """The hub renders, links the screens that already exist, and the ONLY thing it ever sends is the General tab's own
    preferences — it spends no credits, changes no monitoring, no role, no plan. Proven both ways: executed (every
    button the hub shows is clicked, before and after a save, and every request is recorded, the kit's and any other
    way to the network, as is every call to one of app.js's own writers) and in the source (the Settings block names
    no app.js function that writes, and no path but its own)."""
    _need_node()
    out = _node(_settings_app("1", _PROFILE) + r"""
show(); await tick();
out.settingsOn = SETTINGS_ON;
out.title = text(root.querySelector("h2"));
out.onRender = calls.slice();                                            // what the hub calls just to render
out.links = root.querySelectorAll(".cust-settings-link").map(b => b.getAttribute("data-route"));
out.fields = PREF_FIELDS.map(f => { const el = root.querySelector("#pref-" + f[0]); return el ? el.value : null; });
// every button the hub shows, clicked as it is: a link only navigates; Save with nothing changed sends nothing
out.buttons = buttons(root);
for (const b of root.querySelectorAll("button")) { b.click(); await tick(); await tick(); }
out.afterClicks = calls.slice(out.onRender.length);
out.navs = navs.slice();
// a changed field, saved: one POST of the preferences route, carrying only that field
const n = calls.length;
root.querySelector("#pref-legal_entity_name").value = "Beta SARL";
button(root, "Save").click(); await tick(); await tick();
out.afterSave = calls.slice(n);
out.toasts = toasts.slice();
// and the hub as the save re-rendered it: every button clicked again
const m = calls.length;
for (const b of root.querySelectorAll("button")) { b.click(); await tick(); await tick(); }
out.afterReclicks = calls.slice(m);
out.all = calls; out.raw = raw; out.writes = writes;
""")
    assert out["settingsOn"] is True and out["title"] == "Settings"
    # rendering only READS the preferences — it makes no POST, so the hub adds no new authority/money mutation
    assert out["onRender"] == [["GET", "api/customer/preferences"]]
    # it LINKS the screens that already exist (no new control forked here), and its links only navigate there
    assert out["links"] == ["#/security", "#/team", "#/billing"]
    assert out["buttons"] == ["Save", "Account security & sign-in", "Authorized administrators", "Billing"]
    assert out["afterClicks"] == [] and out["navs"] == ["#/security", "#/team", "#/billing"]
    # the General tab shows every field, pre-filled from what the server stored
    assert out["fields"] == [_PROFILE[k] for k in store.PREFERENCE_KEYS]
    # Save posts to the preferences route only — the field that changed, nothing else (a UI preference, not a money,
    # monitoring or authority verb); the server's merge is reflected back
    assert out["afterSave"] == [["POST", "api/customer/preferences", {"preferences": {"legal_entity_name": "Beta SARL"}}]]
    assert out["toasts"] == ["No changes to save", "Saved"] and out["afterReclicks"] == []
    # EVERY request the hub ever made: the preferences route, and a POST carries only allowlisted string fields;
    # nothing went to the network any other way
    for call in out["all"]:
        assert call[1] == "api/customer/preferences" and call[0] in ("GET", "POST"), call
        if call[0] == "POST":
            assert set(call[2]) == {"preferences"}, call
            assert set(call[2]["preferences"]) <= set(store.PREFERENCE_KEYS), call
            assert all(isinstance(v, str) for v in call[2]["preferences"].values()), call
    assert out["raw"] == []
    # ... and it called none of app.js's own writers (each one's stand-in records a call): no credits bought, no
    # launch, monitoring neither turned on nor off, no team change
    assert out["writes"] == []
    # the source: the Settings block's code (its comments dropped) reaches the network only through its own
    # preferences route ...
    src = APP_JS.read_text(encoding="utf-8")
    block = _settings_block(src)
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", block)
    assert re.findall(r"VUI\.(\w+JSON)\(API \+ \"([^\"]*)\"", code) == [("getJSON", "/preferences"),
                                                                      ("postJSON", "/preferences")]
    assert len(re.findall(r"\bAPI\b", code)) == 2 and not re.search(r"[\"'`]/?api/", code)
    for banned in ("fetch(", "XMLHttpRequest", "sendBeacon", "uploadChunked", ".sse(", "location.href",
                   "location.assign", "location.replace", "window.open"):
        assert banned not in code, banned
    # ... and names none of app.js's functions that write: buying credits (startCheckout), launching or retesting
    # (doLaunch, launchAction, retestFinding), monitoring (monTurnOn, monTurnOff), the team (viewTeam), Red-Pen
    # (codePost), the step-up wrapper (withStepUp), signing in or out ...
    writers = _app_writers(src, block)
    assert {"startCheckout", "doLaunch", "launchAction", "retestFinding", "monTurnOn", "monTurnOff", "codePost",
            "withStepUp"} <= writers, sorted(writers)
    assert sorted(w for w in writers if re.search(r"\b" + w + r"\b", code)) == []


# =====================================================================================================================
# 3. A missing file reads as the documented defaults (safe direction), never a 500
# =====================================================================================================================
def test_3_missing_file_reads_as_documented_defaults(home):
    assert config.CUSTOMER_PREFERENCES_DIR == home
    assert store.DEFAULTS == {k: "" for k in store.PREFERENCE_KEYS}
    # reading never raises and never creates anything; the documented defaults are an empty profile
    assert store.read_prefs("cust_ana") == store.DEFAULTS and not home.exists()
    assert store.read_prefs("") == store.DEFAULTS
    # the provisioner answers an active customer the same documented defaults, not a 500
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    assert p.preferences_get("cust_ana") == {"ok": True, "preferences": store.DEFAULTS}


# =====================================================================================================================
# 4. The write is atomic (spine.atomicio), temp 0600, dir 0700, filename = sha256(username), no username/email in path
# =====================================================================================================================
def test_4_write_is_atomic_0600_file_0700_dir_hashed_name(home, monkeypatch):
    import sigil.spine.atomicio as aio
    seen = []
    real = aio.atomic_write_text
    monkeypatch.setattr(aio, "atomic_write_text", lambda path, data, **k: (seen.append(Path(path)), real(path, data, **k))[1])

    merged = store.write_prefs("cust_ana", {"legal_entity_name": "Acme SARL"}, now=5.0)
    assert merged["legal_entity_name"] == "Acme SARL"
    f = next(home.iterdir())
    assert seen == [f]                                                   # the write went through spine.atomicio
    # the filename is a domain-separated sha256 of the username — no username, no email, no .tmp left behind
    assert re.fullmatch(r"[0-9a-f]{64}\.json", f.name)
    assert "cust_ana" not in f.name and "ana@acme.io" not in f.name and "@" not in f.name
    assert [p.suffix for p in home.iterdir()] == [".json"]              # no torn temp file lingers
    assert f.name == store._name("cust_ana") and store._name("cust_ana") != store._name("cust_ben")
    # 0600 file in a 0700 directory
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert json.loads(f.read_text())["at"] == 5.0


# =====================================================================================================================
# 5. Account = the hop-bound session principal; a username/org request field is ignored (no cross-account write)
# =====================================================================================================================
def test_5_account_is_the_hop_principal_no_cross_account(home, tmp_path, monkeypatch):
    # (a) the cockpit dispatch: absent without the flag; with it, the account is the hop principal, never a body field
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
    for a in ("preferences_get", "preferences_set"):
        p = _P()
        assert Handler._provision_dispatch(None, p, a, "cust_ana", {"preferences": _PROFILE}) is None   # -> 404
        assert p.calls == []
    monkeypatch.setenv(FLAG, "1")
    p = _P()
    Handler._provision_dispatch(None, p, "preferences_get", "cust_ana", {"username": "cust_eve", "ip": "1.2.3.4"})
    Handler._provision_dispatch(None, p, "preferences_set", "cust_ana",
                                {"preferences": {"legal_entity_name": "A"}, "username": "cust_eve", "org_id": "org_z"})
    assert p.calls == [("preferences_get", ("cust_ana",), {}),
                       ("preferences_set", ("cust_ana", {"legal_entity_name": "A"}), {})]

    # (b) the edge: a query/body naming another account changes nothing; the principal is the session username
    h, sent = _edge_stub({"username": "cust_ana", "org_id": "org_a"})
    h.path = "/api/customer/preferences?username=cust_eve"
    h.do_GET()
    assert sent["action"] == "preferences_get" and sent["principal"] == "cust_ana" and sent["body"] == {"ip": "1.2.3.4"}
    h, sent = _edge_stub({"username": "cust_ana"})
    h._dispatch("preferences", {"preferences": {"legal_entity_name": "A"}, "username": "cust_eve", "org_id": "org_z"})
    assert sent["action"] == "preferences_set" and sent["principal"] == "cust_ana"
    assert sent["body"] == {"preferences": {"legal_entity_name": "A"}, "ip": "1.2.3.4"}   # only the prefs travel
    for session in (None, {}, {"username": ""}):
        h, sent = _edge_stub(session)
        h._dispatch("preferences", {"preferences": _PROFILE})
        assert sent["code"] == 401 and "action" not in sent, session

    # (c) over the real hop: A's POST naming B writes A's store, never B's
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, opa, ana = _signed_up(tmp_path, monkeypatch, "ana@acme.io")
    try:
        other = _post(_opener(), ep, "/api/customer/signup/request", {"email": "ben@other.io"})[1]["dev_token"]
        opb = _opener()
        ben = _post(opb, ep, "/api/customer/signup/confirm",
                    {"token": other, "password": "customer-pw-1", "org_name": "Other"})[1]["username"]
        c, r = _post(opa, ep, "/api/customer/preferences",
                     {"preferences": {"legal_entity_name": "Acme SARL"}, "username": ben, "org_id": "org_x"})
        assert c == 200 and r["preferences"]["legal_entity_name"] == "Acme SARL", (c, r)
        assert store.read_prefs(ana)["legal_entity_name"] == "Acme SARL"
        assert store.read_prefs(ben) == store.DEFAULTS                  # the named account was never written
    finally:
        sov.shutdown()
        edge.shutdown()


# =====================================================================================================================
# 6. A malformed or oversized (> _MAX_BYTES) file reads as the default in the lenient read, not an error — and the
#    STRICT read (the General tab, every save) refuses it: a save never merges onto a profile it could not read
# =====================================================================================================================
def test_6_malformed_or_oversized_file_reads_as_default(home, tmp_path):
    store.write_prefs("cust_ana", _PROFILE, now=1.0)
    f = next(home.iterdir())
    whole = f.read_bytes()
    big = json.dumps({"prefs": {"legal_entity_name": "x" * (store._MAX_BYTES + 10)}})
    for raw in (b"", b"not json", b"[]", b"null", b'{"prefs": "nope"}', b'{"state": "done"}', b"\xff\xfe",
                big.encode(), b'{"prefs": {"legal_entity_name": "ok"}}' + b" " * (store._MAX_BYTES + 10),
                whole[:len(whole) // 2]):                       # a truncated record: half of the real one
        f.write_bytes(raw)
        assert store.read_prefs("cust_ana") == store.DEFAULTS, raw[:24]
        with pytest.raises(store.ProfileUnreadable):
            store.read_prefs("cust_ana", strict=True)
        # a partial save would merge onto the empty defaults and blank the fields it does not name: refused, the
        # damaged file left exactly as it was (it used to be overwritten with the one field the save named)
        with pytest.raises(store.ProfileUnreadable):
            store.write_prefs("cust_ana", {"emergency_contact_phone": "+33 2"}, now=2.0)
        assert f.read_bytes() == raw, raw[:24]
    f.write_bytes(whole)
    assert store.read_prefs("cust_ana", strict=True) == _PROFILE
    # a non-allowlisted key sitting in a well-formed file is ignored, not surfaced (defence in depth on the read too)
    f.write_text(json.dumps({"prefs": {"legal_entity_name": "Acme SARL", "api_key": "sk-leak", "balance": 999}}))
    assert store.read_prefs("cust_ana") == {**store.DEFAULTS, "legal_entity_name": "Acme SARL"}
    # a symlink planted where the account's file goes is never followed, and a record replaces the link, never writes
    # through it
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(json.dumps({"prefs": {"legal_entity_name": "LEAK"}}))
    f.unlink()
    f.symlink_to(elsewhere)
    assert store.read_prefs("cust_ana") == store.DEFAULTS == store.read_prefs("cust_ana", strict=True)
    store.write_prefs("cust_ana", {"legal_entity_name": "Acme SARL"}, now=2.0)
    assert not f.is_symlink() and store.read_prefs("cust_ana")["legal_entity_name"] == "Acme SARL"
    assert json.loads(elsewhere.read_text())["prefs"]["legal_entity_name"] == "LEAK"   # the link target was untouched
    shutil.rmtree(home)                                                 # the directory gone: defaults, no error
    assert store.read_prefs("cust_ana") == store.DEFAULTS == store.read_prefs("cust_ana", strict=True)


def test_6b_a_short_read_is_never_taken_for_the_whole_file(home, monkeypatch):
    """A file system may answer a read with fewer bytes than asked (a FUSE- or NFS-backed home): the store reads to the
    end of the file, so a stored profile read a few bytes at a time is the whole profile, and a partial save keeps
    every field it does not name. (One read used to be taken for the whole file: the cut record read as the defaults,
    and the save blanked the other five fields.)"""
    store.write_prefs("cust_ana", _PROFILE, now=1.0)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 7)))
    assert store.read_prefs("cust_ana", strict=True) == _PROFILE == store.read_prefs("cust_ana")
    assert store.write_prefs("cust_ana", {"emergency_contact_phone": "+33 2"}, now=2.0) == {
        **_PROFILE, "emergency_contact_phone": "+33 2"}
    monkeypatch.setattr(os, "read", real_read)
    assert store.read_prefs("cust_ana") == {**_PROFILE, "emergency_contact_phone": "+33 2"}
    # a read that fails before the end of the file is a file that could not be read — even when the bytes read so far
    # parse as a whole record: refused, never taken for the profile
    f = home / store._name("cust_ana")
    before = f.read_bytes()
    reads: list = []

    def _fails_at_the_end(fd, n):
        reads.append(n)
        if len(reads) > 1:
            raise OSError(errno.EIO, "Input/output error")
        return real_read(fd, n)

    monkeypatch.setattr(os, "read", _fails_at_the_end)
    with pytest.raises(store.ProfileUnreadable):
        store.read_prefs("cust_ana", strict=True)
    reads.clear()
    with pytest.raises(store.ProfileUnreadable):
        store.write_prefs("cust_ana", {"legal_entity_name": "X"}, now=3.0)
    monkeypatch.setattr(os, "read", real_read)
    assert f.read_bytes() == before


def test_6c_a_special_file_at_an_accounts_path_never_blocks_and_is_never_read(home):
    """Only a regular file is a stored profile. A FIFO planted at an account's path is refused at once — its open never
    waits for a writer, so it never holds the store's process-wide save lock (every other account's save goes on) —
    and it is never read: bytes waiting in it stay there. A directory there is refused too."""
    home.mkdir(parents=True, exist_ok=True)
    fifo = home / store._name("cust_ana")
    os.mkfifo(fifo)
    results: dict = {}

    def _run(name, fn):
        try:
            results[name] = fn()
        except Exception as e:  # noqa: BLE001 — surfaced by the assertions below
            results[name] = e

    calls = {"save": lambda: store.write_prefs("cust_ana", {"legal_entity_name": "X"}, now=1.0),
             "strict": lambda: store.read_prefs("cust_ana", strict=True),
             "lenient": lambda: store.read_prefs("cust_ana")}
    try:
        for name, fn in calls.items():                  # no writer holds the FIFO: a blocking open would wait forever
            t = threading.Thread(target=_run, args=(name, fn), daemon=True)
            t.start()
            t.join(timeout=10)
            assert not t.is_alive(), f"{name} blocked on the FIFO"
    finally:
        try:                                            # a reader stuck in open() is released by a writer's open
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        except OSError:
            pass
    assert isinstance(results["save"], store.ProfileUnreadable) and isinstance(results["strict"], store.ProfileUnreadable)
    assert results["lenient"] == store.DEFAULTS and not store._SAVE_LOCK.locked()
    assert store.write_prefs("cust_ben", {"legal_entity_name": "Ben SA"}, now=1.0)["legal_entity_name"] == "Ben SA"
    # bytes waiting in the FIFO (a writer holds it open) are never read: the store refuses before any read
    record = json.dumps({"prefs": {**_PROFILE}, "at": 1.0}).encode()
    held = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    try:
        os.write(held, record)
        with pytest.raises(store.ProfileUnreadable):
            store.write_prefs("cust_ana", {"legal_entity_name": "X"}, now=2.0)
        with pytest.raises(store.ProfileUnreadable):
            store.read_prefs("cust_ana", strict=True)
        assert os.read(held, len(record) + 1) == record                # still there, whole
    finally:
        os.close(held)
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)                       # refused, never replaced
    fifo.unlink()
    fifo.mkdir()                                                       # a directory where the file goes
    with pytest.raises(store.ProfileUnreadable):
        store.write_prefs("cust_ana", {"legal_entity_name": "X"}, now=3.0)
    assert store.read_prefs("cust_ana") == store.DEFAULTS


def test_6d_an_account_name_with_no_utf8_form_holds_no_profile(home):
    """An account name with no UTF-8 form (a lone surrogate) can hold no stored profile: every read answers the
    documented defaults — the lenient read never raises — and a save is refused in plain words, with nothing written."""
    bad = "cust_\ud800"
    assert store.read_prefs(bad) == store.DEFAULTS == store.read_prefs(bad, strict=True)
    with pytest.raises(ValueError) as ei:
        store.write_prefs(bad, {"legal_entity_name": "X"}, now=1.0)
    assert type(ei.value) is ValueError and "valid text" in str(ei.value)   # never the codec's own error
    assert not home.exists() or not any(home.iterdir())


# =====================================================================================================================
# 7. The store rejects any key outside the closed allowlist (no arbitrary field; never a secret/authority/money key)
# =====================================================================================================================
def test_7_store_rejects_keys_outside_the_closed_allowlist(home):
    # the allowlist carries only plain profile/contact fields — nothing that names a secret, authority or money value
    assert store.PREFERENCE_KEYS == ("legal_entity_name", "registered_address", "contractual_contact_email",
                                     "emergency_contact_name", "emergency_contact_phone", "emergency_contact_email")
    forbidden = ("secret", "api_key", "apikey", "token", "password", "key", "owner", "authority", "role", "perm",
                 "grant", "balance", "credit", "wallet", "money", "price", "cost")
    assert not any(bad in k for k in store.PREFERENCE_KEYS for bad in forbidden)
    # any key outside the allowlist is refused and nothing is written
    for bad in ({"api_key": "sk-x"}, {"owner_authority": "yes"}, {"balance": "1"}, {"role": "owner"},
                {"__proto__": "x"}, {"legal_entity_name": "ok", "secret": "leak"}):
        with pytest.raises(ValueError):
            store.write_prefs("cust_ana", bad, now=1.0)
    # an allowlisted key with a non-string value, or an over-long value, is refused too
    with pytest.raises(ValueError):
        store.write_prefs("cust_ana", {"legal_entity_name": 123}, now=1.0)
    with pytest.raises(ValueError):
        store.write_prefs("cust_ana", {"registered_address": "x" * (store._MAX_VALUE_LEN + 1)}, now=1.0)
    with pytest.raises(ValueError):
        store.write_prefs("", {"legal_entity_name": "ok"}, now=1.0)    # never a record without an account
    assert not home.exists() or not any(home.iterdir())               # not one refusal wrote a file
    # a valid allowlisted subset writes and round-trips
    assert store.write_prefs("cust_ana", {"legal_entity_name": "Acme SARL"}, now=1.0)["legal_entity_name"] == "Acme SARL"
    assert store.read_prefs("cust_ana") == {**store.DEFAULTS, "legal_entity_name": "Acme SARL"}


# =====================================================================================================================
# 8. Preferences are NEVER written to the signed append-only spine (UI preference; assert_no_offense present)
# =====================================================================================================================
def test_8_preferences_never_touch_the_signed_spine(home):
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    n = s.count()
    # many reads and writes — none appends to the spine, none is audited
    for i in range(10):
        p.preferences_set("cust_ana", {"legal_entity_name": f"Acme {i}"})
        p.preferences_get("cust_ana")
    assert s.count() == n
    audits = [r.payload for r in s.iter_records() if isinstance(r.payload, dict)
              and r.payload.get("signal") == "provision.audit"
              and str(r.payload.get("action", "")).startswith("preferences")]
    assert audits == []
    # the account still reads back its latest answer from the OFF-spine store
    assert p.preferences_get("cust_ana")["preferences"]["legal_entity_name"] == "Acme 9"
    # an inactive account is refused (active-customer only), and the store carries the sovereignty guard
    custs.revoke("cust_ana")
    for who in ("cust_ana", "", "owner"):
        with pytest.raises(ProvisionDenied):
            p.preferences_get(who)
        with pytest.raises(ProvisionDenied):
            p.preferences_set(who, {"legal_entity_name": "x"})
    src = Path(store.__file__).read_text(encoding="utf-8")
    assert "from ..reuse import assert_no_offense" in src and "assert_no_offense()" in src
    # a bad preference through the provisioner is a clean refusal, never a 500 and never a spine write
    with pytest.raises(ProvisionError):
        p2, s2, custs2 = _prov()
        custs2.create("b@acme.io", issued_at=1.0, password="password-xyz", username="cust_b")
        n2 = s2.count()
        try:
            p2.preferences_set("cust_b", {"api_key": "leak"})
        finally:
            assert s2.count() == n2


# =====================================================================================================================
# 9. GET -> POST -> GET round-trips the stored preference for the same account
# =====================================================================================================================
def test_9_get_post_get_round_trips_for_the_same_account(tmp_path, monkeypatch, home):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, op, ana = _signed_up(tmp_path, monkeypatch, "ana@acme.io")
    try:
        anon = _opener()
        assert _get(anon, ep, "/api/customer/preferences")[0] == 401            # no session
        assert _post(anon, ep, "/api/customer/preferences", {"preferences": _PROFILE})[0] == 401
        # a first read: the documented defaults (an empty profile)
        assert _get(op, ep, "/api/customer/preferences") == (200, {"ok": True, "preferences": store.DEFAULTS})
        # a cross-origin write is refused
        assert _post(op, ep, "/api/customer/preferences", {"preferences": _PROFILE},
                     origin="https://evil.example")[0] == 403
        # POST the profile, then GET it back — the same account round-trips the stored preference
        c, r = _post(op, ep, "/api/customer/preferences", {"preferences": _PROFILE})
        assert (c, r) == (200, {"ok": True, "preferences": _PROFILE}), (c, r)
        assert _get(op, ep, "/api/customer/preferences") == (200, {"ok": True, "preferences": _PROFILE})
        # a sign-in on another device (a new session) sees the SAME stored answer
        op2, again = _sign_in(ep, "ana@acme.io")
        assert again == ana and _get(op2, ep, "/api/customer/preferences") == (200, {"ok": True, "preferences": _PROFILE})
        # a partial save updates only the named field (merge), leaving the rest
        c, r = _post(op2, ep, "/api/customer/preferences", {"preferences": {"legal_entity_name": "Acme II SARL"}})
        assert c == 200 and r["preferences"] == {**_PROFILE, "legal_entity_name": "Acme II SARL"}, (c, r)
        # a key outside the allowlist is refused in plain words, not a 500, and changes nothing
        c, r = _post(op2, ep, "/api/customer/preferences", {"preferences": {"api_key": "leak"}})
        assert c == 400, (c, r)
        assert store.read_prefs(ana) == {**_PROFILE, "legal_entity_name": "Acme II SARL"}
    finally:
        sov.shutdown()
        edge.shutdown()


# =====================================================================================================================
# 10. The backup CAPTURES the customer-entered profile (a restore brings it back, owner-only); toggling the flag OFF
#     again is byte-identical
# =====================================================================================================================
def test_10_backup_captures_the_profile_and_toggle_off_is_byte_identical(tmp_path, monkeypatch):
    from sigil import backup
    from sigil.backup import create_backup
    from test_backup_recovery_functional import PW, _make_full_source, _restore
    # the customer typed the profile and nothing regenerates it, so it is NOT under customer/ (the operational markers
    # the backup excludes): it is its own top-level directory, CAPTURED, restored owner-only
    assert config.CUSTOMER_PREFERENCES_DIR == config.SIGIL_HOME / "customer_preferences"
    assert backup.classify_top_level("customer_preferences") == "captured"
    assert "customer_preferences" in backup._STATE_DIRS and "customer_preferences" in backup._PRIVATE_STATE_DIRS
    # and the customer/ exclusion no longer files it under markers that "regenerate": what it lists is ephemeral only,
    # and it says where the profile went
    reason = backup._EXCLUSION_REASONS["customer"]
    excluded = reason[reason.index("(") + 1:reason.index(")")]
    assert "onboarding tour" in excluded and "preferences" not in excluded and "profile" not in excluded
    assert "`customer_preferences`, captured" in reason
    # a REAL backup of a home whose profile the REAL store wrote, restored into a fresh home: the store reads the
    # profile back from the restored home, 0600 in a 0700 directory (contact data, as the store keeps it)
    src, vault, owner, _w = _make_full_source(tmp_path)
    monkeypatch.setattr(config, "CUSTOMER_PREFERENCES_DIR", src / "customer_preferences")
    store.write_prefs("cust_ana", _PROFILE, now=1.0)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=vault, owner_key=owner)
    new, _rv, out = _restore(tmp_path, dest)
    assert out["verified"] is True
    monkeypatch.setattr(config, "CUSTOMER_PREFERENCES_DIR", new / "customer_preferences")
    assert store.read_prefs("cust_ana") == _PROFILE
    restored = new / "customer_preferences"
    files = list(restored.iterdir())
    assert stat.S_IMODE(restored.stat().st_mode) == 0o700
    assert files and {stat.S_IMODE(p.stat().st_mode) for p in files} == {0o600}
    assert not (new / "customer").exists()                # nothing of the excluded customer/ tree came with it
    # toggling the flag OFF again is byte-identical: the page returns to data-settings="0" and nothing residual remains
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "on")
    monkeypatch.delenv(FLAG, raising=False)
    off, build_off = _page_and_build(tmp_path / "off")
    base, build_base = _page_and_build(tmp_path / "base")               # a never-on build, for reference
    assert off == base and 'data-settings="0"' in off                  # off == the baseline build, byte for byte
    assert on.replace('data-settings="1"', 'data-settings="0"').replace(build_on, build_off) == off
    # and with the flag off the edge route is gone again (no residual route), and no migration is needed to serve it:
    # the store is plain per-account state (a backup carries it as it is), never a code migration
    home = tmp_path / "toggle" / "customer_preferences"
    monkeypatch.setattr(config, "CUSTOMER_PREFERENCES_DIR", home)
    sov, edge, ep, op, user = _signed_up(tmp_path, monkeypatch, "toggle@acme.io")
    try:
        assert _get(op, ep, "/api/customer/preferences")[0] == 404
        assert not home.exists()
    finally:
        sov.shutdown()
        edge.shutdown()


# =====================================================================================================================
# 11. The in-app guide covers Settings — only while it is shown: with the flag off the guide is byte-identical
# =====================================================================================================================
_GUIDE_WORLD = r"""
document.body.dataset.settings = __FLAG__;
document.body.dataset.security = __SECURITY__;
const VUI = window.VUI, G = window.VIGIL_GUIDE, navs = [];
var MONITORING_ON = false, CODE_ON = false, CONNECT_ON = false, POSTURE_ON = false;   // routeShown's other screens: off
// The Guide screen as app.js mounts it (viewGuideScreen passes shown: routeShown, flag: pageFlag): every chapter tab in
// turn, serialized.
function guideTabs(shown) {
  const g = G.viewGuide({ h, username: "ana", storage: null, nav: r => navs.push(r), shown, flag: pageFlag });
  document.body.appendChild(g);
  const seen = {};
  for (const title of G.CHAPTERS.map(c => c.title).concat(["Questions"])) {
    g.querySelectorAll("button.cust-guide-tab").filter(b => b.textContent === title)[0].click();
    seen[title] = ser(g);
  }
  return seen;
}
"""


def _guide_app(flag: str, security: str = "0") -> str:
    """guide.js (loaded by the harness) plus app.js's own SETTINGS_ON and routeShown lines, verbatim; ``security`` is
    the Account-security page switch (the Settings step's ``alt`` clicks name that screen only where it is on)."""
    src = APP_JS.read_text(encoding="utf-8")
    return "\n".join([_GUIDE_WORLD.replace("__FLAG__", json.dumps(flag)).replace("__SECURITY__", json.dumps(security)),
                      _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                      _line(src, r'^  var SETTINGS_ON = pageFlag\("settings"\);$'),
                      _line(src, r"^  function routeShown\(route\) \{.*\}$")])


def test_11_the_guide_covers_settings_only_while_it_is_shown():
    """The guide covers the Settings screen as it covers every screen the app routes to (the census:
    test_customer_onboarding.py::test_the_guide_covers_every_screen_of_the_app), in the screen's own words — and, like
    the screen, only while the flag is on: the step names its page switch (``when: "settings"``, the very name
    SETTINGS_ON reads), routeShown hides #/settings while the flag is off, and the Guide screen lists a switch-named step
    only where app.js's ``flag`` (pageFlag) says the switch is on and routeShown shows its screen. So with the flag off every chapter of the Guide screen is byte-identical to
    the guide without the step; the tour never visits it; with the flag on the step is listed and leads to #/settings."""
    _need_node()
    src = APP_JS.read_text(encoding="utf-8")
    data = _node("out.chapters = window.VIGIL_GUIDE.CHAPTERS; out.tour = window.VIGIL_GUIDE.TOUR;")
    steps = {(ch["id"], st["id"]): st for ch in data["chapters"] for st in ch["steps"]}
    st = steps[("workspace", "organization")]
    assert (st["where"], st["route"], st["when"]) == ("Settings", "#/settings", "settings")
    assert '  var SETTINGS_ON = pageFlag("settings");' in src      # the switch the step names is the one app.js reads
    # every control the step names is one the hub really shows (its own literal in the Settings block) — and the
    # Account-security link, which the hub shows only where that screen is on, is named only in the step's `alt`
    # clicks, which the guide uses only where that screen's page switch is on
    told, block = " ".join(st["clicks"] + st["alt"]["clicks"]), _settings_block(src)
    for label in ("Settings", "General", "Save", "Your organization", "Account security & sign-in",
                  "Authorized administrators", "Billing"):
        assert label in told and f'"{label}"' in block, label
    assert st["alt"]["when"] == "security" and st["alt"]["clicks"][:-1] == st["clicks"][:-1]
    assert "Account security" not in " ".join(st["clicks"]) and "Account security & sign-in" in st["alt"]["clicks"][-1]
    assert '(hash !== "#/security" || SECURITY_ON)' in block      # the hub's own condition for that link
    assert 'navLink("Settings", "#/settings")' in src and "roles are changed on Team" in st["why"]
    # a switch-named step is never on the tour, so the tour is the same whatever the flag
    scoped = {key for key, s in steps.items() if s.get("when")}
    assert ("workspace", "organization") in scoped
    assert [t for t in data["tour"] if (t.get("chapter"), t.get("step")) in scoped] == []
    # flag off: the Guide screen, every chapter tab, is byte-identical to the guide without the step
    for flag in ("0", "", "__VIGIL_SETTINGS__"):
        out = _node(_guide_app(flag) + r"""
out.shown = [routeShown("#/settings"), routeShown("#/billing")];
out.off = guideTabs(routeShown);
const ws = G.CHAPTERS.filter(c => c.id === "workspace")[0];
ws.steps = ws.steps.filter(s => s.id !== "organization");          // the guide without the Settings step
out.base = guideTabs(routeShown);
out.navs = navs;
""")
        assert out["shown"] == [False, True], flag
        assert out["off"] == out["base"] and out["navs"] == [], flag
    # flag on: the step is listed on its chapter, and its "Go to Settings" opens the hub
    on = _node(_guide_app("1") + r"""
out.shown = [routeShown("#/settings"), routeShown("#/billing")];
const g = G.viewGuide({ h, username: "ana", storage: null, nav: r => navs.push(r), shown: routeShown, flag: pageFlag,
                        chapter: "workspace" });
document.body.appendChild(g);
out.titles = g.querySelectorAll("span.cust-guide-step-title").map(e => text(e));
out.go = buttons(g).filter(t => t.indexOf("Go to ") === 0);
button(g, "Go to Settings").click();
out.navs = navs;
""")
    assert on["shown"] == [True, True]
    assert on["titles"] == ["The Overview", "Bring in your team", "Notifications", "Record your organization's details"]
    assert on["go"] == ["Go to Overview", "Go to Team", "Go to Settings"] and on["navs"] == ["#/settings"]
    # the step names Account security & sign-in only where that screen's switch is on, as the hub links it
    told = {}
    for security in ("0", "1"):
        told[security] = _node(_guide_app("1", security) + r"""
const g = G.viewGuide({ h, username: "ana", storage: null, nav: r => navs.push(r), shown: routeShown, flag: pageFlag,
                        chapter: "workspace" });
document.body.appendChild(g);
const card = g.querySelectorAll("div.cust-guide-step").filter(c =>
  text(c.querySelector("span.cust-guide-step-title")) === "Record your organization's details")[0];
out.clicks = card.querySelector("ol.cust-tour-clicks").querySelectorAll("li").map(e => text(e));
""")["clicks"]
    assert told["0"] == st["clicks"] and told["1"] == st["alt"]["clicks"]
    assert "Account security" not in " ".join(told["0"]) and "Account security & sign-in" in told["1"][-1]
    # the Guide screen lists a switch-named step only where BOTH agree: the app's flag(when) says its switch is on,
    # and shown(route) says this deployment shows its screen — either one saying no leaves it out
    both = _node(_guide_app("1") + r"""
const listed = env => {
  const g = G.viewGuide(Object.assign({ h, username: "ana", storage: null, nav: r => navs.push(r), chapter: "workspace" },
                                      env));
  return g.querySelectorAll("span.cust-guide-step-title").map(e => text(e)).indexOf("Record your organization's details") >= 0;
};
out.both = listed({ flag: () => true, shown: () => true });
out.flagOnly = listed({ flag: () => true, shown: r => r !== "#/settings" });
out.shownOnly = listed({ flag: () => false, shown: () => true });
out.neither = listed({});
""")
    assert both == {"both": True, "flagOnly": False, "shownOnly": False, "neither": False}


# =====================================================================================================================
# 12. An accepted save always reads back as accepted: the read bound is enforced on the SERIALISED record, not on code
#     points (a non-ASCII character is 6 bytes escaped, an emoji 12) — over it the save is refused, nothing written
# =====================================================================================================================
def _record_bytes(prefs: dict, now: float = 1.0) -> int:
    """The size of the record write_prefs stores for this profile — what the read bound is measured on."""
    return len(json.dumps({"prefs": {**store.DEFAULTS, **prefs}, "at": float(now)}, sort_keys=True).encode("utf-8"))


def test_12_an_accepted_save_always_reads_back_as_accepted(home):
    store.write_prefs("cust_ana", _PROFILE, now=1.0)
    f = home / store._name("cust_ana")
    before = f.read_bytes()
    # within the per-value cap but over the serialised bound: refused, nothing written. (It used to be ACCEPTED, and the
    # next read took the oversized file for the empty defaults: the save wiped the whole profile.)
    wide = {"legal_entity_name": "é" * store._MAX_VALUE_LEN, "registered_address": "é" * store._MAX_VALUE_LEN}
    emoji = {"emergency_contact_name": "\U0001F600" * 700}
    for over in (wide, emoji):
        assert all(len(v) <= store._MAX_VALUE_LEN for v in over.values())
        assert _record_bytes({**_PROFILE, **over}) > store._MAX_BYTES
        with pytest.raises(ValueError, match="too long to store"):
            store.write_prefs("cust_ana", over, now=2.0)
        assert f.read_bytes() == before and store.read_prefs("cust_ana") == _PROFILE     # the profile kept, whole
    with pytest.raises(ValueError, match="too long to store"):
        store.write_prefs("cust_ben", emoji, now=1.0)
    assert not (home / store._name("cust_ben")).exists()                              # a first save: no file at all
    # the bound is exact: a record of exactly _MAX_BYTES is kept and reads back as accepted; one byte more is refused
    base = {"legal_entity_name": "é" * store._MAX_VALUE_LEN, "registered_address": "é" * 300}
    pad = store._MAX_BYTES - _record_bytes({**base, "emergency_contact_name": ""})
    assert 0 < pad <= store._MAX_VALUE_LEN
    exact = {**base, "emergency_contact_name": "x" * pad}
    assert _record_bytes(exact) == store._MAX_BYTES
    assert store.write_prefs("cust_cy", exact, now=1.0) == {**store.DEFAULTS, **exact}
    assert store.read_prefs("cust_cy") == {**store.DEFAULTS, **exact}
    assert (home / store._name("cust_cy")).stat().st_size == store._MAX_BYTES
    with pytest.raises(ValueError, match="too long to store"):
        store.write_prefs("cust_dee", {**base, "emergency_contact_name": "x" * (pad + 1)}, now=1.0)
    assert not (home / store._name("cust_dee")).exists()
    # the bound narrows no ASCII profile the per-value cap allows: every field at the cap is kept
    full = {k: "x" * store._MAX_VALUE_LEN for k in store.PREFERENCE_KEYS}
    assert store.write_prefs("cust_eve", full, now=1.7e9) == full and store.read_prefs("cust_eve") == full
    # and across characters that serialise wider than they look, EVERY save the store accepts reads back as accepted
    for i, ch in enumerate(("é", "中", "\U0001F600", "\x01", '"', "\\", " ")):
        for n in (1, 100, 500, store._MAX_VALUE_LEN):
            user, prefs = f"cust_shape_{i}_{n}", {"legal_entity_name": ch * n, "registered_address": ch * n}
            try:
                merged = store.write_prefs(user, prefs, now=1.0)
            except ValueError:
                assert not (home / store._name(user)).exists(), (ch, n)
                continue
            assert store.read_prefs(user) == merged == {**store.DEFAULTS, **prefs}, (ch, n)


# =====================================================================================================================
# 13. Text that cannot be encoded (a lone UTF-16 surrogate) is refused in plain words, nothing written: never stored,
#     never a codec error's own message
# =====================================================================================================================
_UNENCODABLE = ("\ud800", "Acme \udfff SARL", "\udc00\ud800", "Acme \ud83d")   # lone high, lone low, reversed, cut pair


def _plain(msg: str) -> bool:
    """A refusal in plain words: it has a UTF-8 form and quotes no codec error ("'utf-8' codec can't encode ...")."""
    msg.encode("utf-8")
    return not any(w in msg for w in ("codec", "surrogates not allowed", "can't encode", "can't decode"))


def test_13_unencodable_text_is_refused_in_plain_words(home, monkeypatch):
    store.write_prefs("cust_ana", _PROFILE, now=1.0)
    f = home / store._name("cust_ana")
    before = f.read_bytes()
    for k in store.PREFERENCE_KEYS:
        for bad in _UNENCODABLE:
            with pytest.raises(ValueError, match="not valid text") as ei:
                store.write_prefs("cust_ana", {k: bad}, now=2.0)
            assert _plain(str(ei.value)), str(ei.value)
    with pytest.raises(ValueError, match="not valid text"):
        store.write_prefs("cust_ben", {"legal_entity_name": "\ud800"}, now=1.0)
    assert f.read_bytes() == before and not (home / store._name("cust_ben")).exists()
    # a key that is not valid text is an unknown key, its echo escaped
    with pytest.raises(ValueError, match="unknown preference key") as ei:
        store.write_prefs("cust_ana", {"\udc80": "x"}, now=2.0)
    assert _plain(str(ei.value))
    # a well-formed surrogate PAIR is ordinary text (an emoji): kept, and it reads back
    kept = store.write_prefs("cust_ana", {"emergency_contact_name": "Dana \U0001F600"}, now=3.0)
    assert kept["emergency_contact_name"] == "Dana \U0001F600" == store.read_prefs("cust_ana")["emergency_contact_name"]
    # a stored value that is not valid text (only a raw file write makes one) is never surfaced: it reads as ""
    f.write_text(json.dumps({"prefs": {**_PROFILE, "legal_entity_name": "Acme \ud800"}}))
    assert store.read_prefs("cust_ana") == {**_PROFILE, "legal_entity_name": ""}
    # the provisioner refuses in plain words, never with the codec's message — even should one come up from the store
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    with pytest.raises(ProvisionError) as ei:
        p.preferences_set("cust_ana", {"legal_entity_name": "\ud800"})
    assert _plain(str(ei.value)) and "not valid text" in str(ei.value)

    def _codec(*_a, **_k):
        "\ud800".encode("utf-8")                               # raises the codec's own UnicodeEncodeError

    monkeypatch.setattr(store, "write_prefs", _codec)
    with pytest.raises(ProvisionError) as ei:
        p.preferences_set("cust_ana", {"legal_entity_name": "Acme SARL"})
    assert str(ei.value) == "the preferences could not be saved: a value is not valid text"


_NOT_TEXT = (b'{"preferences": {"registered_address": "\xff"}}',              # bytes that are not UTF-8 at all:
             b'{"preferences": {"registered_address": "1 Rue \xc0\x80"}}')    # a stray byte, an overlong NUL
# text the JSON parser refuses, and the route's own plain answer for each
_NOT_JSON = ((b'{"preferences": {"legal_entity_name": "Acme', "bad request: the body could not be read as JSON"),
             (b'{"preferences": {"legal_entity_name": "a\x01b"}}',              # a raw control character
              "bad request: the body could not be read as JSON"),
             (b'{"preferences": {"legal_entity_name": ' + b"9" * 5000 + b"}}",  # more digits than the parser converts
              "bad request: the body could not be read as JSON"),
             (b"[]", "bad request: body must be an object"))
_PLAIN_REFUSALS = ("bad request: the body is not valid text", "bad request: the body could not be read as JSON")


def test_13b_over_the_real_hop_bad_input_is_a_clean_400_and_changes_nothing(tmp_path, monkeypatch, home):
    """End to end over the loopback hop: a lone surrogate (the JSON escape, or a surrogate's raw bytes), one as a key,
    body bytes that are not text at all, and a profile over the read bound are each a 400 in plain words — never a
    codec's own message (the edge's, after a write, or its body reader's) — and the stored profile is unchanged: it still
    reads back, whole. With the flag off the route is absent, and the edge answers such a body exactly as it answers it
    on any other unknown path."""
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, op, ana = _signed_up(tmp_path, monkeypatch, "ana@acme.io")
    try:
        assert _post(op, ep, "/api/customer/preferences", {"preferences": _PROFILE}) == (
            200, {"ok": True, "preferences": _PROFILE})
        wide = {"legal_entity_name": "é" * store._MAX_VALUE_LEN, "registered_address": "é" * store._MAX_VALUE_LEN}
        for raw in (json.dumps({"preferences": {"legal_entity_name": "\ud800"}}).encode("ascii"),
                    b'{"preferences": {"registered_address": "1 Rue \xed\xa0\x80"}}',
                    json.dumps({"preferences": {"\udc80": "x"}}).encode("ascii"),
                    *_NOT_TEXT,
                    json.dumps({"preferences": wide}).encode("ascii")):
            c, r = _post_raw(op, ep, "/api/customer/preferences", raw)
            assert c == 400 and isinstance(r, dict) and _plain(r.get("error", "")), (raw[:48], c, r)
            assert _get(op, ep, "/api/customer/preferences") == (200, {"ok": True, "preferences": _PROFILE}), raw[:48]
        assert store.read_prefs(ana) == _PROFILE
        for raw in _NOT_TEXT:
            assert _post_raw(op, ep, "/api/customer/preferences", raw) == (
                400, {"error": "bad request: the body is not valid text"}), raw
        # a body that is text but that the parser refuses gets plain words of the route's own too — never the parser's
        # message (a raw control character, an integer longer than the parser converts), and never "not valid text"
        for raw, said in _NOT_JSON:
            assert _post_raw(op, ep, "/api/customer/preferences", raw) == (400, {"error": said}), raw[:48]
        assert store.read_prefs(ana) == _PROFILE
        # every other customer route keeps its own answer for the same bytes, the flag on or off
        other = {raw: _post_raw(op, ep, "/api/customer/not-a-route", raw)
                 for raw in (*_NOT_TEXT, *(r for r, _said in _NOT_JSON))}
        for raw, got in other.items():
            assert got[0] == 400 and got[1]["error"] not in _PLAIN_REFUSALS, (raw[:48], got)
        # flag off: no such route, and the plain refusal is not there either — the edge's answer is the one any other
        # unknown customer path gets for the same bytes, as it always was
        monkeypatch.delenv(FLAG)
        for raw in other:
            off = _post_raw(op, ep, "/api/customer/preferences", raw)
            assert off == _post_raw(op, ep, "/api/customer/not-a-route", raw) == other[raw], (raw[:48], off)
        monkeypatch.setenv(FLAG, "1")
        assert store.read_prefs(ana) == _PROFILE
        # should a codec error ever come up from the store itself (the store refuses a lone surrogate first, so only a
        # store that raised one would reach this), the reply over the hop is still the provisioner's plain refusal
        def _codec(*_a, **_k):
            "\ud800".encode("utf-8")                           # raises the codec's own UnicodeEncodeError

        monkeypatch.setattr(store, "write_prefs", _codec)
        assert _post(op, ep, "/api/customer/preferences", {"preferences": {"legal_entity_name": "Acme SARL"}}) == (
            400, {"error": "provision failed: the preferences could not be saved: a value is not valid text"})
    finally:
        sov.shutdown()
        edge.shutdown()


# =====================================================================================================================
# 14. A failed read (anything but a sign-in problem) shows an error with Save disabled — never an empty form whose Save
#     would blank the stored fields; and Save sends ONLY the fields the customer changed
# =====================================================================================================================
_FAILED_READ = r"""
getFail = __FAIL__;
show(); await tick(); await tick();
out.error = text(root.querySelector(".cust-settings-error"));
out.role = root.querySelector(".cust-settings-error").getAttribute("role");
out.inputs = root.querySelectorAll("input").length;
const save = button(root, "Save");
out.saveDisabled = !!save.disabled;
save.click(); await tick(); await tick();                      // a disabled Save ignores the click ...
await save.listeners.click[0](); await tick();                 // ... and even run directly, it sends nothing
out.posts = calls.filter(c => c[0] === "POST");
out.banners = banners.slice();
// Try again reads once more and, answered this time, shows the stored details with Save enabled
button(root, "Try again").click(); await tick(); await tick();
out.gets = calls.filter(c => c[0] === "GET").length;
out.fields = PREF_FIELDS.map(f => { const el = root.querySelector("#pref-" + f[0]); return el ? el.value : null; });
out.saveEnabled = !button(root, "Save").disabled;
out.navs = navs; out.refreshed = refreshed;
"""


def test_14_a_failed_read_shows_an_error_and_save_is_disabled():
    _need_node()
    for fail in ({"status": 500, "data": {"error": "provision failed"}}, {"status": 502},
                 {"status": 503, "data": {"error": "updating"}},
                 {"status": 403, "data": {"error": "denied: requester is not an active customer"}},
                 {"message": "network down"}):
        out = _node(_settings_app("1", _PROFILE) + _FAILED_READ.replace("__FAIL__", json.dumps(fail)))
        assert out["error"].startswith("Could not load your organization's details") and out["role"] == "alert", fail
        assert out["inputs"] == 0 and out["saveDisabled"] is True and out["posts"] == [], fail   # no form, nothing sent
        assert out["banners"] == [("Your organization's details could not be loaded, so nothing was saved. "
                                   "Select Try again.")], fail
        assert out["gets"] == 2 and out["fields"] == [_PROFILE[k] for k in store.PREFERENCE_KEYS], fail
        assert out["saveEnabled"] is True and out["navs"] == [] and out["refreshed"] == 0, fail
    # a reply without the profile is a failed read like any other: no form
    out = _node(_settings_app("1", _PROFILE) + r"""
getReply = { ok: true };
show(); await tick(); await tick();
out.error = text(root.querySelector(".cust-settings-error")); out.inputs = root.querySelectorAll("input").length;
out.saveDisabled = !!button(root, "Save").disabled;
""")
    assert out["error"].startswith("Could not load") and out["inputs"] == 0 and out["saveDisabled"] is True
    # a sign-in problem goes to sign-in, as on every screen
    out = _node(_settings_app("1", _PROFILE) + r"""
getFail = { status: 401 };
show(); await tick(); await tick();
out.navs = navs; out.refreshed = refreshed; out.error = text(root.querySelector(".cust-settings-error"));
""")
    assert out["navs"] == ["#/login"] and out["refreshed"] == 1 and out["error"] is None
    # Save sends ONLY what the customer changed: an untouched stored field is never sent, so it can never be blanked; a
    # field emptied on purpose is sent empty; with nothing changed nothing is sent
    out = _node(_settings_app("1", _PROFILE) + r"""
show(); await tick();
button(root, "Save").click(); await tick(); await tick();
out.unchanged = calls.filter(c => c[0] === "POST");
root.querySelector("#pref-registered_address").value = "2 Avenue Foch, 75116 Paris, FR";
root.querySelector("#pref-emergency_contact_phone").value = "  ";
root.querySelector("#pref-legal_entity_name").value = "  Acme SARL  ";       // the same once trimmed: unchanged
button(root, "Save").click(); await tick(); await tick();
out.posts = calls.filter(c => c[0] === "POST");
out.toasts = toasts;
out.fields = PREF_FIELDS.map(f => root.querySelector("#pref-" + f[0]).value);
""")
    changed = {"registered_address": "2 Avenue Foch, 75116 Paris, FR", "emergency_contact_phone": ""}
    assert out["unchanged"] == [] and out["toasts"] == ["No changes to save", "Saved"]
    assert out["posts"] == [["POST", "api/customer/preferences", {"preferences": changed}]]
    assert out["fields"] == [{**_PROFILE, **changed}[k] for k in store.PREFERENCE_KEYS]


def test_14b_after_a_save_the_tab_shows_what_is_stored_and_never_a_blank_profile():
    """After a save the tab shows the profile the server stored: its merged answer — or, should the reply not carry
    the profile, the stored profile read again; never an empty form standing in for a stored profile. A field the
    customer did not touch is never sent, even when the stored value has spaces around it. And a read that fails after
    the customer has left the screen changes nothing on the page and sends no one to sign in."""
    _need_node()
    out = _node(_settings_app("1", _PROFILE) + r"""
show(); await tick();
root.querySelector("#pref-registered_address").value = "2 Avenue Foch, 75116 Paris, FR";
postReply = { ok: true };                                      // a reply without the profile
button(root, "Save").click(); for (let i = 0; i < 6; i++) await tick();
out.gets = calls.filter(c => c[0] === "GET").length;
out.inputs = root.querySelectorAll("input").length;
out.fields = PREF_FIELDS.map(f => { const el = root.querySelector("#pref-" + f[0]); return el ? el.value : null; });
""")
    stored = {**_PROFILE, "registered_address": "2 Avenue Foch, 75116 Paris, FR"}
    assert out["gets"] == 2 and out["inputs"] == len(store.PREFERENCE_KEYS)
    assert out["fields"] == [stored[k] for k in store.PREFERENCE_KEYS]
    # an untouched field whose stored value has spaces around it is not a change: only the edited field is sent
    spaced = {**_PROFILE, "legal_entity_name": "  Acme SARL  "}
    out = _node(_settings_app("1", spaced) + r"""
show(); await tick();
root.querySelector("#pref-emergency_contact_phone").value = "+33 6 00 00 00 00";
button(root, "Save").click(); await tick(); await tick();
out.posts = calls.filter(c => c[0] === "POST");
""")
    assert out["posts"] == [["POST", "api/customer/preferences",
                             {"preferences": {"emergency_contact_phone": "+33 6 00 00 00 00"}}]]
    # the customer left before the read failed: the page is left as it is, and no one is sent to sign in
    for fail in ({"status": 500}, {"status": 401}):
        out = _node(_settings_app("1", _PROFILE) + r"""
getFail = __FAIL__;
show();
const holder = root.querySelector("#cust-settings-general");
location.hash = "#/billing";                                    // left the screen before the read answered
for (let i = 0; i < 6; i++) await tick();
out.error = holder.querySelectorAll(".cust-settings-error").length;
out.buttons = holder.querySelectorAll("button").length;
out.navs = navs; out.refreshed = refreshed;
""".replace("__FAIL__", json.dumps(fail)))
        assert out == {"error": 0, "buttons": 0, "navs": [], "refreshed": 0}, (fail, out)


# =====================================================================================================================
# 15. The server merges ONLY the keys it is sent — and never takes a stored file it cannot read for an empty profile
# =====================================================================================================================
def test_15_the_server_merges_only_the_keys_it_is_sent(home, monkeypatch):
    store.write_prefs("cust_ana", _PROFILE, now=1.0)
    f = home / store._name("cust_ana")
    # each partial save changes the key it names and keeps every other stored field; naming nothing changes nothing
    for k in store.PREFERENCE_KEYS:
        assert store.write_prefs("cust_ana", {k: "changed"}, now=2.0) == {**_PROFILE, k: "changed"}
        assert store.write_prefs("cust_ana", {k: _PROFILE[k]}, now=2.0) == _PROFILE
    assert store.write_prefs("cust_ana", {}, now=2.0) == _PROFILE
    before = f.read_bytes()
    # the stored file is there but cannot be read right now: the save is REFUSED and nothing is written — a merge onto
    # the empty defaults would have blanked the five fields this save does not name
    real_open = os.open

    def _unreadable(path, flags, *a, **k):
        if str(path) == str(f):
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", _unreadable)
    with pytest.raises(store.ProfileUnreadable):
        store.write_prefs("cust_ana", {"legal_entity_name": "Beta SARL"}, now=3.0)
    assert store.read_prefs("cust_ana") == store.DEFAULTS          # the lenient read keeps its contract: no raise
    with pytest.raises(store.ProfileUnreadable):
        store.read_prefs("cust_ana", strict=True)                   # the strict read (the General tab) reports it
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    # a store fault, not the input: never a ProvisionError (a 400 that would blame a field) — the cockpit's clean 500
    with pytest.raises(store.ProfileUnreadable):
        p.preferences_set("cust_ana", {"legal_entity_name": "Beta SARL"})
    with pytest.raises(store.ProfileUnreadable):
        p.preferences_get("cust_ana")                               # never the empty profile, shown as the customer's
    monkeypatch.setattr(os, "open", real_open)
    assert f.read_bytes() == before and store.read_prefs("cust_ana") == _PROFILE   # whole: every field it had
    # no file yet holds no stored profile: a first save proceeds (a symlink where it goes: test_6)
    assert store.write_prefs("cust_new", {"legal_entity_name": "New SA"}, now=4.0) == {
        **store.DEFAULTS, "legal_entity_name": "New SA"}


def test_15c_a_stored_profile_that_cannot_be_read_is_an_error_on_the_tab_never_an_empty_form(tmp_path, monkeypatch,
                                                                                              home):
    """Over the real edge, hop and cockpit: while the account's stored file is there but cannot be read, the General
    tab's read is a 500 (a store fault) — so the app shows its error with Save disabled (test_14), never an empty form
    standing in for a stored profile — and a save is a 500 too, with nothing written. The app then says the settings
    could not be saved, never that a field is too long: that copy is for a 400, a refusal of what was typed. Once the
    file can be read again, the profile is there, whole."""
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, op, ana = _signed_up(tmp_path, monkeypatch, "ana@acme.io")
    try:
        assert _post(op, ep, "/api/customer/preferences", {"preferences": _PROFILE})[0] == 200
        f = home / store._name(ana)
        before = f.read_bytes()
        real_open = os.open

        def _unreadable(path, flags, *a, **k):
            if str(path) == str(f):
                raise PermissionError(errno.EACCES, "Permission denied", str(path))
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr(os, "open", _unreadable)
        assert _get(op, ep, "/api/customer/preferences") == (500, {"error": "provision failed"})
        assert _post(op, ep, "/api/customer/preferences", {"preferences": {"legal_entity_name": "Beta SARL"}}) == (
            500, {"error": "provision failed"})
        monkeypatch.setattr(os, "open", real_open)
        assert f.read_bytes() == before
        assert _get(op, ep, "/api/customer/preferences") == (200, {"ok": True, "preferences": _PROFILE})
    finally:
        sov.shutdown()
        edge.shutdown()
    _need_node()
    copy = {}
    for code in (500, 400):
        out = _node(_settings_app("1", _PROFILE) + r"""
show(); await tick();
root.querySelector("#pref-legal_entity_name").value = "Beta SARL";
postFail = __FAIL__;
button(root, "Save").click(); await tick(); await tick();
out.banners = banners.slice(); out.saveEnabled = !button(root, "Save").disabled;
""".replace("__FAIL__", json.dumps({"status": code, "data": {"error": "x"}})))
        assert len(out["banners"]) == 1 and out["saveEnabled"] is True, (code, out)
        copy[code] = out["banners"][0]
    assert copy[500] == "Your settings could not be saved. Please try again." and "shorten" not in copy[500]
    assert "shorten" in copy[400] and "nothing was changed" in copy[400]


def test_15b_concurrent_saves_of_different_fields_both_land(home, monkeypatch):
    """Saves run one at a time (the cockpit serves requests on threads): two saves racing — each reading the stored
    profile before the other wrote — would have the later write put back, over the field the earlier one changed, the
    value it had read. The race is forced here, not hoped for: each save's read waits (up to a second) for the other
    save's read. Unserialized, both reads meet and both saves merge onto the same old profile; serialized, the second
    save cannot read until the first has written, so the wait gives up and the second save merges onto the first."""
    store.write_prefs("cust_ana", _PROFILE, now=1.0)
    real_load = store._load
    both_read = threading.Barrier(2)

    def _read_then_wait_for_the_other(username, *, strict):
        got = real_load(username, strict=strict)
        try:
            both_read.wait(timeout=1.0)
        except threading.BrokenBarrierError:
            pass                                       # the other save could not read meanwhile: serialized
        return got

    monkeypatch.setattr(store, "_load", _read_then_wait_for_the_other)
    errors = []

    def _save(key, value):
        try:
            store.write_prefs("cust_ana", {key: value}, now=2.0)
        except Exception as e:  # noqa: BLE001 — surfaced by the assertion below
            errors.append(e)

    saves = [threading.Thread(target=_save, args=("legal_entity_name", "Beta SARL")),
             threading.Thread(target=_save, args=("registered_address", "2 Avenue Foch, 75116 Paris, FR"))]
    for t in saves:
        t.start()
    for t in saves:
        t.join(timeout=30)
    monkeypatch.setattr(store, "_load", real_load)
    assert errors == [] and not any(t.is_alive() for t in saves)
    assert store.read_prefs("cust_ana") == {**_PROFILE, "legal_entity_name": "Beta SARL",
                                            "registered_address": "2 Avenue Foch, 75116 Paris, FR"}


# =====================================================================================================================
# 16. The hub links Account security only where that screen is shown — and asks routeShown for every link
# =====================================================================================================================
_LINKS = r"""
show(); await tick();
out.links = root.querySelectorAll(".cust-settings-link").map(b => b.getAttribute("data-route"));
out.labels = buttons(root);
out.securityShown = routeShown("#/security");
"""


def test_16_the_hub_links_account_security_only_where_it_is_shown():
    _need_node()
    on = _node(_settings_app("1", _PROFILE) + _LINKS)
    assert on["links"] == ["#/security", "#/team", "#/billing"]
    # Account security off (its page flag off or unexpanded, or security.js not on the page): #/security is the home
    # screen, so the hub offers no link to it. routeShown itself, which the guide reads, is unchanged: the guide stays
    # exactly as it was
    for security, js in (("0", True), ("", True), ("__VIGIL_SECURITY__", True), ("1", False)):
        off = _node(_settings_app("1", _PROFILE, security=security, security_js=js) + _LINKS)
        assert off["links"] == ["#/team", "#/billing"], (security, js)
        assert "Account security & sign-in" not in off["labels"] and off["securityShown"] is True, (security, js)
    # every link asks routeShown: a screen routeShown hides gets no link (here routeShown shows everything but billing,
    # so the hub's other links — Account security, Team and the legal/governance-S3 Data rights link — all remain)
    hidden = _node(_settings_app("1", _PROFILE) + 'routeShown = r => r !== "#/billing";\n' + _LINKS)
    assert hidden["links"] == ["#/security", "#/team", "#/data-rights"]


# =====================================================================================================================
# 17. Every class the Settings hub renders has a style in app.css
# =====================================================================================================================
def _css_rules(css: str) -> list:
    """app.css as (selector list, declarations) pairs, comments dropped (the rules inside an @media block count too)."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    return [(m.group(1).strip(), m.group(2).strip()) for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css)]


def test_17_every_class_the_settings_hub_renders_is_styled():
    block = _settings_block(APP_JS.read_text(encoding="utf-8"))
    rules = [(sel, body) for sel, body in _css_rules(APP_CSS.read_text(encoding="utf-8")) if body]
    rendered = {c for tag in re.findall(r'\bh\("([^"]+)"', block) for c in re.findall(r"\.([\w-]+)", tag)}
    ours = sorted(c for c in rendered if c.startswith("cust-"))
    assert {"cust-field", "cust-settings-links", "cust-settings-link", "cust-settings-general-form",
            "cust-settings-error", "cust-pref-save", "cust-pref-retry"} <= set(ours), ours

    def styled(token: str) -> bool:
        """Whether some rule styles the element that carries ``token`` ITSELF: ``token`` is in the subject (the last
        compound) of one of the rule's selectors — a rule that names it only as an ancestor (``.cust-field label``)
        styles another element, so a container whose own rule is gone is caught."""
        for sel, _body in rules:
            for one in sel.split(","):
                compounds = re.split(r"\s*[>+~]\s*|\s+", one.strip())
                if compounds and re.search(re.escape(token) + r"(?![\w-])", compounds[-1]):
                    return True
        return False

    assert [c for c in ours if not styled("." + c)] == []
    assert styled("#cust-settings-general")
    # the tab's email and phone fields look like its text fields (the shared kit styles text/url/password inputs only)
    for t in ("email", "tel"):
        assert any(f".cust-field input[type={t}]" in sel and "background" in body and "border" in body
                   for sel, body in rules), t
