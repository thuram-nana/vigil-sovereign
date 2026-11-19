"""Legal/governance S1 — the customer settings shell + the General preferences hub, behind VIGIL_CUSTOMER_SETTINGS
(default OFF).

The settings shell is a #/settings hub in the customer app that LINKS the screens that already exist (Account security,
Authorized administrators = the Team screen, Billing) and adds a General tab that captures the workspace's legal-entity
/ contact profile. That profile is a UI PREFERENCE — never money, never authority, never a signed spine record — kept
server-side, per account:

  * ui/preferences_store keeps one hashed-name 0600 file per account in a 0700 directory under customer/; only the
    CLOSED PREFERENCE_KEYS allowlist of string fields is ever stored, and anything missing, unreadable, malformed,
    oversized or symlinked reads as the documented DEFAULTS (an empty profile), never an error;
  * Provisioner.preferences_get / preferences_set serve an ACTIVE customer only, enforce the allowlist, and write to
    the per-account store — NEVER to the signed append-only spine (no audit row): a customer cannot grow the spine by
    saving the tab;
  * the cockpit's provision dispatch is absent (unknown action -> 404) unless the flag is on, and acts for the hop
    principal, never a body field;
  * the edge route GET/POST api/customer/preferences is absent (404) unless the flag is on, needs a session (401), and
    reads/records for the session's account only — a body naming another account changes nothing for it;
  * app.js adds the Settings tab + #/settings hub only while data-settings="1"; off, it is byte-identical (no tab,
    #/settings is the home screen, no preferences call is made).

Each test here is one acceptance bullet for slice S1. Mutation-verify targets (each neuter reds a NAMED test here):
  * read_prefs ignores the file (always defaults)             -> test_9_get_post_get_round_trips_for_the_same_account
  * write_prefs accepts any key                               -> test_7_store_rejects_keys_outside_the_closed_allowlist
  * read_prefs follows a symlink / reads odd bytes            -> test_6_malformed_or_oversized_file_reads_as_default
  * the provisioner skips the active-customer check           -> test_5_account_is_the_hop_principal_no_cross_account
  * the provisioner audits / writes the spine                 -> test_8_preferences_never_touch_the_signed_spine
  * the cockpit dispatch ignores the flag / takes the body    -> test_5_account_is_the_hop_principal_no_cross_account
  * the edge route ignores the flag                           -> test_1_flag_off_route_404_page_and_nav_byte_identical
  * the edge takes the account from the body                  -> test_5_account_is_the_hop_principal_no_cross_account
  * the edge always writes data-settings="1"                  -> test_1_flag_off_route_404_page_and_nav_byte_identical
  * the hub invents an authority/money control                -> test_2_flag_on_hub_renders_and_links_existing_screens
"""
from __future__ import annotations

import http.client
import json
import re
import shutil
import stat
import tempfile
import threading
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
from sigil.ui.custui import build_customer_server
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionError, Provisioner

FLAG = "VIGIL_CUSTOMER_SETTINGS"
APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
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
    d = tmp_path / "customer" / "preferences"
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


# --- the executed-JS harness for the hub (node) ----------------------------------------------------------------------
def _settings_block(src: str) -> str:
    i = src.index("  // ---- Settings (VIGIL_CUSTOMER_SETTINGS)")
    return src[i:src.index("  // ---- shell", i)]


_WORLD_S = r"""
document.body.dataset.settings = __FLAG__;
globalThis.location = { hash: "#/settings" };
let who = { authenticated: true, username: "cust_me" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const navs = []; function nav(r) { navs.push(r); }
let refreshed = 0; async function refreshWho() { refreshed++; }
const calls = [];
let prefs = __PREFS__;
let getFail = null, postFail = null;
function failure(f) { const e = new Error(f.message || (f.data && f.data.error) || "failed");
  e.status = f.status; e.data = f.data || null; return e; }
const VUI = window.VUI;
VUI.getJSON = async p => { calls.push(["GET", p]); if (getFail) { const f = getFail; getFail = null; throw failure(f); }
  return { ok: true, preferences: prefs }; };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); if (postFail) { const f = postFail; postFail = null; throw failure(f); }
  prefs = Object.assign({}, prefs, (b && b.preferences) || {}); return { ok: true, preferences: prefs }; };
const toasts = []; VUI.toast = m => { toasts.push(m); };
VUI.errorBanner = () => {};
var GUIDE = null, GUIDE_ON = false;
function shell(inner, current) { return h("div.cust-shell", { dataset: { current: current } }, inner); }
function viewLogin() { return h("div.cust-login"); }
function viewDashboard() { return h("div.cust-dash"); }
const root = new El("div"); document.body.appendChild(root);
function show() { VUI.mount(root, ROUTES["#/settings"]()); return root; }
"""


def _settings_app(flag: str = "1", prefs=None) -> str:
    src = APP_JS.read_text(encoding="utf-8")
    world = (_WORLD_S.replace("__FLAG__", json.dumps(flag))
             .replace("__PREFS__", json.dumps(prefs if prefs is not None else {})))
    return "\n".join([world,
                      _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                      _line(src, r'^  var API = "[^"]*";'), _fn(src, "field"),
                      _line(src, r"^  function val\(id\) \{.*\}$"), _line(src, r"^  function here\(\) \{.*\}$"),
                      _fn(src, "loadingHolder"), _line(src, r"^  function err\(msg\) \{.*$"),
                      _settings_block(src),
                      'const ROUTES = {\n' + _line(src, r'^    "#/settings": function .*,$') + '\n};'])


# =====================================================================================================================
# 1. Flag OFF: route 404, index placeholders unexpanded, nav byte-identical
# =====================================================================================================================
def test_1_flag_off_route_404_page_and_nav_byte_identical(tmp_path, monkeypatch, home):
    # the edge route is exactly an unknown route (404) with the flag off, and nothing is served or recorded
    sov, edge, ep, op, user = _signed_up(tmp_path, monkeypatch, "off@acme.io")
    try:
        assert _get(op, ep, "/api/customer/preferences")[0] == 404
        assert _post(op, ep, "/api/customer/preferences", {"preferences": _PROFILE})[0] == 404
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
# 2. Flag ON: the #/settings hub renders and links the existing screens; adds no authority/money control
# =====================================================================================================================
def test_2_flag_on_hub_renders_and_links_existing_screens(tmp_path):
    _need_node()
    out = _node(_settings_app("1", _PROFILE) + r"""
show(); await tick();
out.settingsOn = SETTINGS_ON;
out.title = text(root.querySelector("h2"));
out.onRender = calls.slice();                                            // what the hub calls just to render
out.links = root.querySelectorAll(".cust-settings-link").map(b => b.getAttribute("data-route"));
out.fields = PREF_FIELDS.map(f => { const el = root.querySelector("#pref-" + f[0]); return el ? el.value : null; });
// saving the General tab posts the preference (never an authority/money route); the server's merge is reflected back
root.querySelector("#pref-legal_entity_name").value = "Beta SARL";
button(root, "Save").click(); await tick(); await tick();
out.afterSave = calls[calls.length - 1];
out.toasts = toasts;
""")
    assert out["settingsOn"] is True and out["title"] == "Settings"
    # rendering only READS the preferences — it makes no POST, so the hub adds no new authority/money mutation
    assert out["onRender"] == [["GET", "api/customer/preferences"]]
    # it LINKS the screens that already exist (no new control forked here)
    assert out["links"] == ["#/security", "#/team", "#/billing"]
    # the General tab shows every field, pre-filled from what the server stored
    assert out["fields"] == [_PROFILE[k] for k in store.PREFERENCE_KEYS]
    # Save posts the whole tab to the preferences route only — a UI preference, not a money/authority verb
    assert out["afterSave"][0] == "POST" and out["afterSave"][1] == "api/customer/preferences"
    assert out["afterSave"][2]["preferences"]["legal_entity_name"] == "Beta SARL" and out["toasts"] == ["Saved"]
    # and the hub posts to no other route (no member/billing/authority mutation lives in the Settings block)
    block = _settings_block(APP_JS.read_text(encoding="utf-8"))
    assert "postJSON" in block
    assert block.count('postJSON(API + "/preferences"') == 1 and "/member/" not in block and "/billing/" not in block


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
    from sigil.ui.custui import CustomerHandler

    def _edge_stub(session):
        h = object.__new__(CustomerHandler)
        sent = {}
        h._session = lambda: session
        h._ip = lambda: "1.2.3.4"
        h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                        or (200, {"ok": True, "preferences": store.DEFAULTS}))
        h._json = lambda obj, code=200: sent.update(code=code, out=obj)
        h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
        return h, sent

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
# 6. A malformed or oversized (> _MAX_BYTES) file reads as the default, not an error
# =====================================================================================================================
def test_6_malformed_or_oversized_file_reads_as_default(home, tmp_path):
    store.write_prefs("cust_ana", {"legal_entity_name": "Acme SARL"}, now=1.0)
    f = next(home.iterdir())
    big = json.dumps({"prefs": {"legal_entity_name": "x" * (store._MAX_BYTES + 10)}})
    for raw in (b"", b"not json", b"[]", b"null", b'{"prefs": "nope"}', b'{"state": "done"}', b"\xff\xfe",
                big.encode(), b'{"prefs": {"legal_entity_name": "ok"}}' + b" " * (store._MAX_BYTES + 10)):
        f.write_bytes(raw)
        assert store.read_prefs("cust_ana") == store.DEFAULTS, raw[:24]
    # a non-allowlisted key sitting in a well-formed file is ignored, not surfaced (defence in depth on the read too)
    f.write_text(json.dumps({"prefs": {"legal_entity_name": "Acme SARL", "api_key": "sk-leak", "balance": 999}}))
    assert store.read_prefs("cust_ana") == {**store.DEFAULTS, "legal_entity_name": "Acme SARL"}
    # a symlink planted where the account's file goes is never followed, and a record replaces the link, never writes
    # through it
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(json.dumps({"prefs": {"legal_entity_name": "LEAK"}}))
    f.unlink()
    f.symlink_to(elsewhere)
    assert store.read_prefs("cust_ana") == store.DEFAULTS
    store.write_prefs("cust_ana", {"legal_entity_name": "Acme SARL"}, now=2.0)
    assert not f.is_symlink() and store.read_prefs("cust_ana")["legal_entity_name"] == "Acme SARL"
    assert json.loads(elsewhere.read_text())["prefs"]["legal_entity_name"] == "LEAK"   # the link target was untouched
    shutil.rmtree(home)                                                 # the directory gone: defaults, no error
    assert store.read_prefs("cust_ana") == store.DEFAULTS


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
# 10. Backup excludes the customer/ store (a restore shows defaults); toggling the flag OFF again is byte-identical
# =====================================================================================================================
def test_10_backup_excludes_customer_store_and_toggle_off_is_byte_identical(tmp_path, monkeypatch):
    from sigil import backup
    # the whole customer/ subtree is excluded from a (sovereign) backup, so a restore shows the documented defaults
    assert config.CUSTOMER_PREFERENCES_DIR.parent.name == "customer"
    assert backup.classify_top_level("customer") == "excluded"
    assert "preferences" in backup._EXCLUSION_REASONS["customer"]
    # toggling the flag OFF again is byte-identical: the page returns to data-settings="0" and nothing residual remains
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "on")
    monkeypatch.delenv(FLAG, raising=False)
    off, build_off = _page_and_build(tmp_path / "off")
    base, build_base = _page_and_build(tmp_path / "base")               # a never-on build, for reference
    assert off == base and 'data-settings="0"' in off                  # off == the baseline build, byte for byte
    assert on.replace('data-settings="1"', 'data-settings="0"').replace(build_on, build_off) == off
    # and with the flag off the edge route is gone again (no residual route), and no migration is needed to serve it:
    # the store is customer-plane state (a restore shows defaults), never a code migration
    home = tmp_path / "customer" / "preferences"
    monkeypatch.setattr(config, "CUSTOMER_PREFERENCES_DIR", home)
    sov, edge, ep, op, user = _signed_up(tmp_path, monkeypatch, "toggle@acme.io")
    try:
        assert _get(op, ep, "/api/customer/preferences")[0] == 404
        assert not home.exists()
    finally:
        sov.shutdown()
        edge.shutdown()
