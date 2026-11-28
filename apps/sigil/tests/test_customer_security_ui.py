"""C3 — account security in the customer app (customer_app/security.js, wired by app.js), behind
VIGIL_CUSTOMER_SECURITY_UI (default OFF).

* The edge writes data-security="1" into the page only while the flag is on, and data-passkey="1" only while the flag
  AND customer passkeys (VIGIL_CUSTOMER_PASSKEY_ENABLED) are on; both count in the build id.
* Account security (#/security, opened from the account's name in the top bar) reads GET api/customer/security: the
  SESSION account's factors — an authenticator app set up or not, its passkeys (id, when added), the name an
  authenticator shows — never a secret, a sealed blob or a public key. The cockpit's `security_status` action reads for
  the hop principal only. With the flag off the edge route and the cockpit action are absent (404) like unknown ones.
* The app's OWN security.js, run under node against the REAL edge -> cockpit hop (node's fetch with a cookie jar):
  Set up shows the key and the setup link once; a code from the repo's TOTP helper, typed in and confirmed, turns
  two-step verification on (and steps the session up); Add a passkey (a node software authenticator, P-256) registers
  exactly what the provisioner verifies, and "Sign in with a passkey" with it mints a customer session; a sensitive
  action the server refuses for a fresh second factor is verified inline and sent ONE more time — never a third.
* Unit (node, the server stubbed): the WebAuthn payloads carry exactly the edge's fields in the server's encodings; a
  browser without WebAuthn, or without getPublicKey(), is told so before anything is created; the step-up helper
  retries exactly once, never loops, re-runs nothing on a wrong code or a cancel, and Buy goes through it; the setup key
  never reaches storage, a cookie or a URL and is gone once confirmed; the QR code equals a reference encoder's symbol.
* Off, the app is unchanged: the sign-in screen and the top bar render exactly as the functions they replaced, Buy
  behaves exactly like the function it replaced (both run side by side through every server answer), withStepUp(action)
  is action(), and #/security is the home screen.

The app's functions run under node with a minimal DOM, extracted verbatim from app.js; security.js and the UI kit are
loaded as they ship.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the edge ignores the flag / serves passkeys without it     -> test_the_edge_writes_the_security_flags_into_the_page
  * the status read leaks a secret, ignores the active check   -> test_the_status_read_names_the_accounts_factors_and_never_a_secret
  * the cockpit ignores the flag / reads a body account        -> test_the_cockpit_status_action_exists_only_with_the_flag
  * the edge reads a body account / ignores the flag           -> test_the_edge_reads_the_status_for_the_session_account_only,
                                                                  test_the_edge_status_route_is_absent_with_the_flag_off
  * Confirm does not verify / the key is kept after it         -> test_the_screen_sets_up_an_authenticator_through_the_edge,
                                                                  test_the_setup_key_is_shown_once_and_never_stored
  * a payload field or encoding drifts                         -> test_a_passkey_is_added_and_signs_in_through_the_edge,
                                                                  test_the_registration_payload_is_exactly_what_the_edge_relays
  * the getPublicKey pre-check is dropped                      -> test_browsers_without_passkeys_are_told_so_before_anything_is_created
  * step-up retries twice / loops / re-runs on a wrong code    -> test_step_up_retries_the_action_exactly_once,
                                                                  test_step_up_never_loops_on_a_second_refusal,
                                                                  test_a_wrong_code_is_said_in_the_box_and_nothing_is_re_run
  * Buy is not wired through the helper                        -> test_buy_goes_through_the_step_up_helper
  * the app ignores the page flags                             -> test_with_the_flag_off_the_app_is_unchanged,
                                                                  test_with_the_flag_off_buy_behaves_exactly_as_before
  * a QR table or step drifts                                  -> test_the_qr_code_matches_a_reference_encoder
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack_passkey, _stack_vault
from test_customer_passkey import ORIGIN as PK_ORIGIN
from test_customer_passkey import RP as PK_RP
from test_customer_passkey import SoftAuthenticator
from test_secrets_sealed import make_fake_tpm

from sigil import config
from sigil.governor import totp as _totp
from sigil.governor.customer_credentials import CustomerCredentialRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.custui import CUSTOMER_COOKIE, build_customer_server
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionError, Provisioner
from sigil.ui.signcount import SignCountLedger
from sigil.ui.totp_replay import TotpReplayLedger

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS, SECURITY_JS, APP_JS, GUIDE_JS = APP / "ui.js", APP / "security.js", APP / "app.js", APP / "guide.js"
OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _need_node() -> str:
    """The node binary (callers use it as argv[0]), or a SKIP where node is absent — except in CI
    (GITHUB_ACTIONS) or where VIGIL_REQUIRE_NODE is set (every CI job that runs this file sets it): there a
    missing node FAILS, so these executed-JS proofs can never go green unrun."""
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH: this job must "
                        "EXECUTE these JS tests")
        pytest.skip("node not installed")
    return node


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(src: str, name: str) -> str:
    """One of app.js's functions, verbatim (from the start of its line, so an `async` stays with it)."""
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


def _line(src: str, pattern: str) -> str:
    m = re.search(pattern, src, re.M)
    assert m, f"app.js no longer has a line matching {pattern!r}"
    return m.group(0)


def _security_lines(src: str) -> str:
    """app.js's own two lines that decide whether the security screens are on (verbatim)."""
    return (_line(src, r"^  var SECURITY = window\.VIGIL_SECURITY;$") + "\n"
            + _line(src, r"^  var SECURITY_ON = .*;$"))


# --- the edge flags ------------------------------------------------------------------------------------------------
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


def test_the_edge_writes_the_security_flags_into_the_page(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_SECURITY_UI", raising=False)
    monkeypatch.delenv("VIGIL_CUSTOMER_PASSKEY_ENABLED", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-security="0"' in off and 'data-passkey="0"' in off
    assert "__VIGIL_SECURITY__" not in off and "__VIGIL_PASSKEY__" not in off
    assert re.search(r'<script src="security\.js\?v=[0-9a-f]+"></script>', off)
    assert off.index('<script src="guide.js') < off.index('<script src="security.js') < off.index('<script src="app.js')
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ENABLED", "1")          # passkeys alone show nothing new
    alone, build_alone = _page_and_build(tmp_path / "b")
    assert 'data-security="0"' in alone and 'data-passkey="0"' in alone
    monkeypatch.setenv("VIGIL_CUSTOMER_SECURITY_UI", "1")
    both, build_both = _page_and_build(tmp_path / "c")
    assert 'data-security="1"' in both and 'data-passkey="1"' in both and build_both != build_alone
    monkeypatch.delenv("VIGIL_CUSTOMER_PASSKEY_ENABLED")
    sec, build_sec = _page_and_build(tmp_path / "d")
    assert 'data-security="1"' in sec and 'data-passkey="0"' in sec
    assert len({build_off, build_both, build_sec}) == 3                 # each switch is a new build
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv("VIGIL_CUSTOMER_SECURITY_UI", v)
        assert 'data-security="0"' in _page_and_build(tmp_path / f"e{v or 'empty'}")[0], v


# --- the status read: the provisioner ------------------------------------------------------------------------------
def _provisioner(tmp_path, monkeypatch):
    from sigil.platform import vault as vaultmod
    v = vaultmod.Vault(tmp_path / "vault", make_fake_tpm())
    v.provision()
    monkeypatch.setattr(vaultmod, "_owner_vault", v)
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_RP_ID", PK_RP)
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ORIGINS", PK_ORIGIN)
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    creds = CustomerCredentialRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    clock = itertools.count(1)
    p = Provisioner(
        s, customers=custs, orgs=OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(str(tmp_path / "tokens"), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(str(tmp_path / "rl"), max_fails=50, window_s=1e4, base_lock_s=50.0),
        customer_credentials=creds, mfa_replay=TotpReplayLedger(str(tmp_path / "replay")),
        signcount=SignCountLedger(str(tmp_path / "signcount")),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: float(next(clock)))
    return p, custs, creds


def _enroll_passkey(p, user, auth, cid, challenge):
    reg = auth.register(challenge)
    return p.enroll_passkey(user, credential_id=cid, public_key_spki_b64=reg["public_key_spki_b64"],
                            cose_alg=reg["cose_alg"], uv=False, client_data_json=reg["client_data_json"],
                            expected_challenge=challenge)


def test_the_status_read_names_the_accounts_factors_and_never_a_secret(tmp_path, monkeypatch):
    p, custs, creds = _provisioner(tmp_path, monkeypatch)
    ana, ben = "cust_sec0000000000000000001", "cust_sec0000000000000000002"
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username=ana)
    custs.create("ben@acme.io", issued_at=1.0, password="password-xyz", username=ben)
    assert p.security_status(ana) == {"ok": True, "totp": False, "passkeys": [], "account_name": "ana@acme.io"}
    secret = p.enroll_totp(ana)["secret"]
    one, two = SoftAuthenticator(), SoftAuthenticator()
    _enroll_passkey(p, ana, one, "cred-zzz", "ch-1")              # added first, sorts last by id
    _enroll_passkey(p, ana, two, "cred-aaa", "ch-2")
    st = p.security_status(ana)
    assert st["totp"] is True and st["account_name"] == "ana@acme.io"
    assert [k["id"] for k in st["passkeys"]] == ["cred-zzz", "cred-aaa"]          # in the order they were added
    assert st["passkeys"][0]["added_at"] < st["passkeys"][1]["added_at"]
    assert set(st) == {"ok", "totp", "passkeys", "account_name"}
    assert all(set(k) == {"id", "added_at"} for k in st["passkeys"])
    blob = json.dumps(st)
    sealed = creds.totp_for(ana).sealed_secret
    for leak in (secret, sealed, one.spki_b64(), two.spki_b64()):              # never a secret or a key
        assert leak not in blob
    # another account's factors are its own
    assert p.security_status(ben) == {"ok": True, "totp": False, "passkeys": [], "account_name": "ben@acme.io"}
    creds.revoke(ana, "cred-zzz")                                                # a revoked passkey is gone
    assert [k["id"] for k in p.security_status(ana)["passkeys"]] == ["cred-aaa"]
    for who in ("", "cust_nobody0000000000000001", "owner"):                   # not an active customer
        with pytest.raises(ProvisionDenied):
            p.security_status(who)
    custs.revoke(ben)
    with pytest.raises(ProvisionDenied):
        p.security_status(ben)
    p.customer_credentials = None                                                # nothing wired: fail closed
    with pytest.raises(ProvisionError):
        p.security_status(ana)


# --- the cockpit's provision dispatch --------------------------------------------------------------------------------
class _P:
    def __init__(self):
        self.calls: list = []

    def __getattr__(self, name):
        def f(*a, **k):
            self.calls.append((name, a, k))
            return {"ok": True}
        return f


def test_the_cockpit_status_action_exists_only_with_the_flag(monkeypatch):
    from sigil.ui.server import Handler
    monkeypatch.delenv("VIGIL_CUSTOMER_SECURITY_UI", raising=False)
    p = _P()
    assert Handler._provision_dispatch(None, p, "security_status", "cust_ana", {"username": "cust_eve"}) is None
    assert p.calls == []                                                          # -> 404, nothing read
    monkeypatch.setenv("VIGIL_CUSTOMER_SECURITY_UI", "1")
    p = _P()
    Handler._provision_dispatch(None, p, "security_status", "cust_ana",
                                {"username": "cust_eve", "requester": "cust_eve", "ip": "1.2.3.4"})
    assert p.calls == [("security_status", ("cust_ana",), {})]                  # the hop principal, never the body


# --- the edge ---------------------------------------------------------------------------------------------------------------
def _edge_stub(session):
    """A customer-edge handler with its session and its hop to the provisioner stubbed: what does it relay?"""
    from sigil.ui.custui import CustomerHandler
    h = object.__new__(CustomerHandler)
    sent: dict = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                    or (200, {"ok": True, "totp": False}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


def test_the_edge_reads_the_status_for_the_session_account_only(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_SECURITY_UI", "1")
    h, sent = _edge_stub({"username": "cust_ana", "org_id": "org_a"})
    h.path = "/api/customer/security?username=cust_eve&requester=cust_eve"
    h.do_GET()
    assert sent == {"action": "security_status", "principal": "cust_ana", "body": {"ip": "1.2.3.4"},
                    "code": 200, "out": {"ok": True, "totp": False}}
    for session in (None, {}, {"username": ""}):                                  # no signed-in account: 401, no hop
        h, sent = _edge_stub(session)
        h.path = "/api/customer/security"
        h.do_GET()
        assert sent["code"] == 401 and "action" not in sent, session


def test_the_edge_status_route_is_absent_with_the_flag_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_SECURITY_UI", raising=False)
    h, sent = _edge_stub({"username": "cust_ana"})
    h.path = "/api/customer/security"
    h.do_GET()
    h2, unknown = _edge_stub({"username": "cust_ana"})
    h2.path = "/api/customer/nope"
    h2.do_GET()
    assert sent == unknown == {"code": 404, "out": {"error": "not found"}}


def _signed_up(ep, email):
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    c, r = _post(op, ep, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "Acme"})
    assert c == 200, (c, r)
    return op, r["username"]


def _cookie(opener) -> str:
    jar = opener.handlers[[type(x).__name__ for x in opener.handlers].index("HTTPCookieProcessor")].cookiejar
    return next(f"{ck.name}={ck.value}" for ck in jar if ck.name == CUSTOMER_COOKIE)


def test_the_status_read_over_the_edge_follows_the_account(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_SECURITY_UI", "1")
    sov, edge, ep, _ = _stack_vault(tmp_path, monkeypatch)
    try:
        op, ana = _signed_up(ep, "ana@acme.io")
        assert _get(_opener(), ep, "/api/customer/security")[0] == 401                # no session
        assert _get(op, ep, "/api/customer/security?username=cust_eve") == (
            200, {"ok": True, "totp": False, "passkeys": [], "account_name": "ana@acme.io"})
        enr = _post(op, ep, "/api/customer/mfa/totp/enroll", {})[1]
        assert _post(op, ep, "/api/customer/mfa/verify", {"code": _totp.code_now(enr["secret"], at=time.time())})[0] == 200
        c, st = _get(op, ep, "/api/customer/security")
        assert c == 200 and st["totp"] is True and enr["secret"] not in json.dumps(st)
        op2, _ben = _signed_up(ep, "ben@other.io")                                    # another account: its own answer
        assert _get(op2, ep, "/api/customer/security")[1]["totp"] is False
    finally:
        sov.shutdown()
        edge.shutdown()


def test_with_the_flag_off_the_status_route_is_absent_over_the_edge(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_SECURITY_UI", raising=False)
    sov, edge, ep, _ = _stack_vault(tmp_path, monkeypatch)
    try:
        op, _ana = _signed_up(ep, "off@acme.io")
        assert _get(op, ep, "/api/customer/security")[0] == 404
    finally:
        sov.shutdown()
        edge.shutdown()


# --- node: a minimal DOM, the kit, security.js ------------------------------------------------------------------------
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
  constructor(tag, ns) {
    super(); this.tagName = String(tag).toUpperCase(); this.ns = ns || null; this.attrs = {}; this.children = [];
    this.dataset = {}; this.style = {}; this.className = ""; this.id = ""; this.parentNode = null; this.hidden = false;
    this.disabled = false; this.value = ""; this.classList = new ClassList(this); this.listeners = {};
  }
  setAttribute(k, v) { if (k === "class") this.className = String(v); else if (k === "id") this.id = String(v);
                       else this.attrs[k] = String(v); }
  getAttribute(k) {
    if (k === "class") return this.className || null;
    if (k === "id") return this.id || null;
    if (k.indexOf("data-") === 0) { const d = k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      if (d in this.dataset) return String(this.dataset[d]); }
    return k in this.attrs ? this.attrs[k] : null;
  }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); this.children.push(c); c.parentNode = this; return c; }
  insertBefore(c, ref) {
    if (c.parentNode) c.parentNode.removeChild(c);
    const i = ref ? this.children.indexOf(ref) : -1;
    if (i < 0) this.children.push(c); else this.children.splice(i, 0, c);
    c.parentNode = this; return c;
  }
  removeChild(c) { this.children = this.children.filter(x => x !== c); c.parentNode = null; return c; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  get firstChild() { return this.children[0] || null; }
  set textContent(v) { this.children.forEach(c => { c.parentNode = null; }); this.children = [];
                       if (String(v)) this.appendChild(new Text(v)); }
  get textContent() { return this.children.map(c => c.textContent).join(""); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter(x => x !== f); }
  dispatch(t, ev) { (this.listeners[t] || []).slice().forEach(f => f(ev || { preventDefault() {} })); }
  click() { if (!this.disabled) this.dispatch("click"); }       // a disabled button takes no click, as in a browser
  focus() {}
  _all(out) { this.children.forEach(c => { if (c instanceof El) { out.push(c); c._all(out); } }); return out; }
  querySelectorAll(sel) { return this._all([]).filter(e => matchesSel(e, sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
function matchesSel(e, sel) {                  // "a b c": e matches c, with ancestors matching b then a
  const parts = sel.trim().split(/\s+/);
  if (!matches(e, parts[parts.length - 1])) return false;
  let i = parts.length - 2, p = e.parentNode;
  while (i >= 0 && p) { if (p instanceof El && matches(p, parts[i])) i--; p = p.parentNode; }
  return i < 0;
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
  createElement: t => new El(t), createElementNS: (ns, t) => new El(t, ns), createTextNode: t => new Text(t),
  getElementById: id => body._all([]).filter(e => e.id === id)[0] || null,
  querySelector: s => body.querySelector(s), querySelectorAll: s => body.querySelectorAll(s),
  addEventListener() {}, removeEventListener() {},
};
const out = {};
const tick = () => new Promise(r => setTimeout(r, 0));
async function settle() { for (let i = 0; i < 30; i++) await tick(); }
async function waitFor(pred, what) {
  const t0 = Date.now();
  while (!pred()) {
    if (Date.now() - t0 > 20000) throw new Error("timed out waiting for " + (what || "a condition"));
    await new Promise(r => setTimeout(r, 10));
  }
}
function text(e) { return e ? e.textContent : null; }
function buttons(root) { return root.querySelectorAll("button").map(b => b.textContent); }
function button(root, label) { return root.querySelectorAll("button").filter(b => b.textContent === label)[0]; }
function fail(status, data) { const e = new Error((data && data.error) || String(status)); e.status = status;
                              e.data = data || null; return e; }
// --- a software WebAuthn authenticator (P-256) for this "browser" at CFG.waOrigin, RP CFG.rp -----------------------
const nodeCrypto = require("crypto");
const sha256 = b => nodeCrypto.createHash("sha256").update(b).digest();
const b64u = b => Buffer.from(b).toString("base64url");
const ab = b => { const x = Buffer.from(b); return x.buffer.slice(x.byteOffset, x.byteOffset + x.byteLength); };
const AUTH = { creds: {}, created: [], got: [], uv: true };
function installWebAuthn(opts) {
  opts = opts || {};
  window.PublicKeyCredential = opts.noWebAuthn ? undefined : function PublicKeyCredential() {};
  window.AuthenticatorAttestationResponse = opts.noGetPublicKey ? function R() {} : (function () {
    function R() {} R.prototype.getPublicKey = function () { return null; }; return R; })();
  const credentials = opts.noWebAuthn ? undefined : {
    create: async (o) => {
      const pk = o.publicKey; AUTH.created.push(pk);
      if (opts.createError) { const e = new Error("refused"); e.name = opts.createError; throw e; }
      if (pk.rp && pk.rp.id && pk.rp.id !== CFG.rp) { const e = new Error("rp"); e.name = "SecurityError"; throw e; }
      for (const x of (pk.excludeCredentials || [])) {
        if (AUTH.creds[b64u(x.id)]) { const e = new Error("exists"); e.name = "InvalidStateError"; throw e; }
      }
      const kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
      const rawId = nodeCrypto.randomBytes(16);
      const cdj = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: b64u(Buffer.from(pk.challenge)),
                                              origin: CFG.waOrigin }));
      const ad = Buffer.concat([sha256(CFG.rp), Buffer.from([0x41 | (AUTH.uv ? 0x04 : 0)]), Buffer.alloc(4)]);
      AUTH.creds[b64u(rawId)] = { key: kp.privateKey, count: 0, user: Buffer.from(pk.user.id) };
      const spki = kp.publicKey.export({ type: "spki", format: "der" });
      AUTH.lastSpki = spki.toString("base64");
      const resp = { clientDataJSON: ab(cdj), attestationObject: ab(Buffer.alloc(0)),
                     getAuthenticatorData: () => ab(ad), getPublicKeyAlgorithm: () => -7,
                     getPublicKey: () => (opts.nullPublicKey ? null : ab(spki)) };
      if (opts.oldResponse) { delete resp.getPublicKey; delete resp.getPublicKeyAlgorithm; }
      return { id: b64u(rawId), rawId: ab(rawId), type: "public-key", response: resp };
    },
    get: async (o) => {
      const pk = o.publicKey; AUTH.got.push(pk);
      if (opts.getError) { const e = new Error("refused"); e.name = opts.getError; throw e; }
      const ids = Object.keys(AUTH.creds);
      if (!ids.length) { const e = new Error("none"); e.name = "NotAllowedError"; throw e; }
      const id = ids[ids.length - 1], c = AUTH.creds[id];
      c.count += 1;
      const cnt = Buffer.alloc(4); cnt.writeUInt32BE(c.count);
      const ad = Buffer.concat([sha256(CFG.rp), Buffer.from([0x05]), cnt]);
      const cdj = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: b64u(Buffer.from(pk.challenge)),
                                              origin: CFG.waOrigin }));
      const sig = nodeCrypto.sign("sha256", Buffer.concat([ad, sha256(cdj)]), c.key);
      return { id, rawId: ab(Buffer.from(id, "base64url")), type: "public-key",
               response: { authenticatorData: ab(ad), clientDataJSON: ab(cdj), signature: ab(sig), userHandle: ab(c.user) } };
    },
  };
  Object.defineProperty(globalThis, "navigator", { value: { credentials }, configurable: true, writable: true });
}
"""


def _load(extra_js: str = "") -> str:
    return (_DOM + f"\nrequire({json.dumps(str(UI_JS))});\nrequire({json.dumps(str(SECURITY_JS))});\n"
            "const VUI = window.VUI; const h = VUI.h; const S = window.VIGIL_SECURITY;\n"
            "VUI.toast = m => { (out.toasts = out.toasts || []).push(String(m)); };\n" + extra_js)


def _run(script: str, cfg: "dict | None" = None, *, timeout: int = 90) -> dict:
    """Run `script` (async; it fills `out`) after the DOM, the kit and security.js; CFG is the last argv."""
    prog = ("const CFG = JSON.parse(process.argv[process.argv.length - 1]);\n" + _load() + "\n(async () => {\n"
            + script + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
            " e => { console.error(e && e.stack || e); process.exit(3); });")
    base = {"rp": PK_RP, "waOrigin": PK_ORIGIN}
    r = subprocess.run([_need_node(), "-e", prog, json.dumps({**base, **(cfg or {})})], capture_output=True,
                       text=True, timeout=timeout)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# A stubbed server: each path answers its list in order (the last one repeats); {"__fail": status, "data": {...}}
# throws like the kit does. Every call is recorded.
_STUB = r"""
const calls = [];
const STUB_ROUTES = CFG.routes || {};
function answer(method, path, body) {
  calls.push([method, path, body === undefined ? null : body]);
  const q = STUB_ROUTES[path];
  if (!q || !q.length) throw fail(404, { error: "not found" });
  const a = q.length > 1 ? q.shift() : q[0];
  if (a && a.__fail) throw fail(a.__fail, a.data);
  if (a && a.__hang) return new Promise(() => {});            // an answer that never comes (a slow network)
  return JSON.parse(JSON.stringify(a));
}
VUI.postJSON = async (p, b) => answer("POST", p, b);
VUI.getJSON = async (p) => answer("GET", p);
"""

# --- node over the REAL edge: fetch with a cookie jar, TOTP codes from the repo's helper ---------------------------------
_LIVE = r"""
const realFetch = globalThis.fetch;
const jar = { v: CFG.cookie || "" };
const posts = [];
globalThis.fetch = async (url, opts) => {
  opts = Object.assign({}, opts || {});
  const headers = Object.assign({}, opts.headers || {});
  if (jar.v) headers["Cookie"] = jar.v;
  if ((opts.method || "GET") !== "GET") headers["Origin"] = CFG.base;
  delete opts.credentials;
  opts.headers = headers;
  if (opts.method === "POST") posts.push([String(url), Object.keys(JSON.parse(opts.body || "{}")).sort()]);
  const r = await realFetch(CFG.base + "/" + String(url), opts);
  const sc = r.headers.get("set-cookie");
  if (sc) { const m = sc.match(/vigil_customer_session=([^;]*)/); if (m) jar.v = m[1] ? "vigil_customer_session=" + m[1] : ""; }
  return r;
};
const { execFileSync } = require("child_process");
const TOTP_PY = "import sys, time\nfrom sigil.governor import totp\n"
  + "print(totp.code_for_step(sys.argv[1], totp.current_step(time.time()) + int(sys.argv[2])))";
function totpCode(secret, offset) {
  return execFileSync(CFG.py, ["-c", TOTP_PY, secret, String(offset || 0)],
                      { env: Object.assign({}, process.env, { PYTHONPATH: CFG.pythonpath }) }).toString().trim();
}
"""


def _live_cfg(ep: int, cookie: str, **extra) -> dict:
    return {"base": f"http://127.0.0.1:{ep}", "cookie": cookie, "py": sys.executable,
            "pythonpath": os.pathsep.join(p for p in sys.path if p), **extra}


def test_the_screen_sets_up_an_authenticator_through_the_edge(tmp_path, monkeypatch):
    """Set up -> the key and the setup link, once -> a code from the repo's TOTP helper, typed and confirmed through the
    real edge: two-step verification is on, the screen no longer holds the key, and the session is stepped up."""
    monkeypatch.setenv("VIGIL_CUSTOMER_SECURITY_UI", "1")
    sov, edge, ep, _ = _stack_vault(tmp_path, monkeypatch)
    try:
        op, ana = _signed_up(ep, "ana@acme.io")
        cookie = _cookie(op)
        out = _run(_LIVE + r"""
const env = { h, VUI, api: "api/customer", who: { authenticated: true, username: CFG.user }, passkeys: true,
              nav: r => (out.navs = out.navs || []).push(r), here: () => "#/security", onAuthLost: () => { out.lost = 1; } };
const root = S.viewSecurity(env); document.body.appendChild(root);
await waitFor(() => button(root, "Set up"), "the screen");
out.before = text(root.querySelector(".cust-badge"));
button(root, "Set up").click();
await waitFor(() => root.querySelector("code.cust-totp-key"), "the key");
const key = text(root.querySelector("code.cust-totp-key")).replace(/\s+/g, "");
out.key = key;
out.link = root.querySelector("a.cust-sec-applink").getAttribute("href");
out.qr = !!root.querySelector("svg.cust-qr");
root.querySelector("#sec-totp-code").value = totpCode(key, 0);
button(root, "Confirm").click();
await waitFor(() => text(root.querySelector(".cust-badge")) === "On", "two-step verification on");
out.after = text(root.querySelector(".cust-badge"));
out.keyGone = document.body.textContent.indexOf(key) < 0 && !root.querySelector("code.cust-totp-key");
out.buttons = buttons(root);
out.posts = posts;
""", _live_cfg(ep, cookie, user=ana))
        assert out["before"] == "Not set up" and out["after"] == "On" and out["keyGone"] is True
        assert out["qr"] is True and out["link"].startswith("otpauth://totp/") and f"secret={out['key']}" in out["link"]
        assert "Set up again" in out["buttons"] and "lost" not in out
        assert out["posts"] == [["api/customer/mfa/totp/enroll", []], ["api/customer/mfa/verify", ["code"]]]
        # the code the screen sent was checked by the provisioner (the key is the account's now) ...
        assert _get(op, ep, "/api/customer/security")[1]["totp"] is True
        # ... and the edge stepped THIS session up (a fresh second factor on the live session)
        rec = edge.sessions.resolve(cookie.split("=", 1)[1])
        assert rec and rec.get("mfa_method") == "totp" and time.time() - float(rec["mfa_at"]) < 60
    finally:
        sov.shutdown()
        edge.shutdown()


def test_a_passkey_is_added_and_signs_in_through_the_edge(tmp_path, monkeypatch):
    """Add a passkey (a node software authenticator) through the screen and the real edge — the provisioner verifies
    the registration it was sent — then "Sign in with a passkey" with it, in a browser with no session, signs in."""
    monkeypatch.setenv("VIGIL_CUSTOMER_SECURITY_UI", "1")
    sov, edge, ep, _ = _stack_passkey(tmp_path, monkeypatch)
    try:
        op, ana = _signed_up(ep, "pk@acme.io")
        out = _run(_LIVE + r"""
installWebAuthn();
const env = { h, VUI, api: "api/customer", who: { authenticated: true, username: CFG.user }, passkeys: true,
              nav: () => {}, here: () => "#/security", onAuthLost: () => { out.lost = 1; } };
const root = S.viewSecurity(env); document.body.appendChild(root);
await waitFor(() => button(root, "Add a passkey"), "the screen");
out.before = root.querySelectorAll("ul.cust-sec-list li").length;
button(root, "Add a passkey").click();
await waitFor(() => root.querySelector("ul.cust-sec-list"), "the passkey in the list");
out.list = root.querySelectorAll("ul.cust-sec-list li").map(text);
const created = AUTH.created[0];
out.createOptions = { rp: created.rp, user: { id: Buffer.from(created.user.id).toString(), name: created.user.name },
  algs: created.pubKeyCredParams.map(p => p.alg), sel: created.authenticatorSelection,
  challengeIsBytes: created.challenge instanceof Uint8Array, exclude: created.excludeCredentials.length };
// a second Add on this device: the browser is told which passkeys exist, so the device says it has one
button(root, "Add a passkey").click();
await waitFor(() => /already has a passkey/.test(document.body.textContent), "the duplicate refusal");
// sign out here (a browser with no session) and sign in with the passkey
jar.v = "";
const r = await S.passkeySignIn({ VUI, api: "api/customer" });
out.login = r; out.cookie = jar.v; out.posts = posts; out.toasts = out.toasts || [];
out.got = AUTH.got.map(g => ({ challengeIsBytes: g.challenge instanceof Uint8Array, allow: g.allowCredentials || null }));
""", _live_cfg(ep, _cookie(op), user=ana))
        assert "lost" not in out and out["before"] == 0 and out["list"][0].startswith("Passkey 1 · added ")
        assert out["toasts"] == ["Passkey added."] and len(out["list"]) == 1
        opts = out["createOptions"]
        assert opts["rp"] == {"name": "VIGIL"}                    # no rp.id: the passkey belongs to this page's host
        assert opts["user"] == {"id": ana, "name": "pk@acme.io"} and opts["algs"] == [-7, -257, -8]
        assert opts["sel"]["residentKey"] == "required" and opts["challengeIsBytes"] and opts["exclude"] == 0
        enroll = ["api/customer/passkey/enroll/challenge", []]
        verify = ["api/customer/passkey/enroll/verify",
                  sorted(["challenge", "client_data_json", "cose_alg", "credential_id", "public_key_spki_b64", "uv"])]
        login = ["api/customer/passkey/login/verify",
                 sorted(["authenticator_data", "challenge", "client_data_json", "credential_id", "signature"])]
        # exactly one registration was sent (the duplicate never reached the edge), then the sign-in
        assert out["posts"] == [enroll, verify, enroll, ["api/customer/passkey/login/challenge", []], login]
        assert out["got"] == [{"challengeIsBytes": True, "allow": None}]
        assert out["login"]["username"] == ana and out["login"]["active_org"]
        c, who = _get(_opener(), ep, "/api/customer/whoami", cookie=out["cookie"])
        assert c == 200 and who == {"authenticated": True, "username": ana, "org_id": out["login"]["active_org"]}
        st = _get(op, ep, "/api/customer/security")[1]
        assert len(st["passkeys"]) == 1 and st["totp"] is False
        rec = edge.sessions.resolve(out["cookie"].split("=", 1)[1])
        assert rec.get("mfa_method") == "passkey"                # a passkey sign-in is itself a fresh second factor
    finally:
        sov.shutdown()
        edge.shutdown()


_STEPUP_LIVE = r"""
const where = h("div.cust-offer"); document.body.appendChild(where);
let runs = 0;
const verifies = () => posts.filter(p => p[0] === "api/customer/mfa/verify").length;
const action = () => { runs++; return VUI.postJSON("api/customer/member/grant", { member_username: CFG.mate, role: "analyst" }); };
const done = S.stepUp({ h, VUI, api: "api/customer", where, nav: () => {} }, action)
  .then(r => { out.result = r; }, e => { out.error = { status: e.status, data: e.data }; });
await waitFor(() => where.querySelector(".cust-stepup"), "the step-up box");
out.box = { title: text(where.querySelector(".cust-stepup strong")), buttons: buttons(where) };
where.querySelector(".cust-stepup input").value = totpCode(CFG.secret, 0);
button(where, "Verify").click();
await done;
out.runs = runs; out.verifies = verifies(); out.boxes = where.querySelectorAll(".cust-stepup").length;
"""


def _stepup_stack(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_SECURITY_UI", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    sov, edge, ep, _ = _stack_vault(tmp_path, monkeypatch)
    admin, _a = _signed_up(ep, "admin@acme.io")
    _mate_op, mate = _signed_up(ep, "mate@other.io")
    secret = _post(admin, ep, "/api/customer/mfa/totp/enroll", {})[1]["secret"]   # enrolled, not yet verified
    return sov, edge, ep, admin, mate, secret


def test_the_step_up_prompt_over_the_edge_sends_the_action_once_more(tmp_path, monkeypatch):
    sov, edge, ep, admin, mate, secret = _stepup_stack(tmp_path, monkeypatch)
    try:
        out = _run(_LIVE + _STEPUP_LIVE, _live_cfg(ep, _cookie(admin), mate=mate, secret=secret))
        assert out["box"] == {"title": "Verify with your authenticator", "buttons": ["Verify", "Cancel"]}
        assert out["runs"] == 2 and out["verifies"] == 1 and out["boxes"] == 0
        assert out["result"]["role"] == "analyst" and "error" not in out
    finally:
        sov.shutdown()
        edge.shutdown()


def test_the_step_up_prompt_over_the_edge_never_loops(tmp_path, monkeypatch):
    """A server that still refuses after a verified code (here: a step-up window no factor can meet) gets the action
    exactly twice: the second refusal goes back to the caller — no second box, no third request."""
    sov, edge, ep, admin, mate, secret = _stepup_stack(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "CUSTOMER_STEPUP_WINDOW_SECONDS", -1)
    try:
        out = _run(_LIVE + _STEPUP_LIVE, _live_cfg(ep, _cookie(admin), mate=mate, secret=secret))
        assert out["runs"] == 2 and out["verifies"] == 1 and out["boxes"] == 0 and "result" not in out
        assert out["error"]["status"] == 401 and out["error"]["data"]["step_up_required"] is True
    finally:
        sov.shutdown()
        edge.shutdown()


# --- unit: the WebAuthn payloads ------------------------------------------------------------------------------------------
def test_the_registration_payload_is_exactly_what_the_edge_relays():
    """Every field passkey/enroll/verify relays, in the encoding the provisioner decodes: credential_id base64url (no
    padding), public_key_spki_b64 STANDARD base64 with padding, client_data_json base64url, cose_alg the number, uv the
    authenticator's flag. Checked against the edge's own relay list and with python's own decoders."""
    out = _run(r"""
installWebAuthn();
const cred = await navigator.credentials.create({ publicKey: { challenge: new TextEncoder().encode("ch-xyz"),
  rp: { name: "VIGIL" }, user: { id: new TextEncoder().encode("cust_a"), name: "a", displayName: "a" } } });
out.body = S.registrationPayload(cred, "ch-xyz");
out.raw = { id: Buffer.from(cred.rawId).toString("hex"), spki: AUTH.lastSpki,
            cdj: Buffer.from(cred.response.clientDataJSON).toString() };
AUTH.uv = false;
const c2 = await navigator.credentials.create({ publicKey: { challenge: new Uint8Array([1]), rp: { name: "V" },
  user: { id: new Uint8Array([1]), name: "a", displayName: "a" } } });
out.uv2 = S.registrationPayload(c2, "x").uv;
""")
    from sigil.ui import custui
    from sigil.ui import webauthn as wa
    body = out["body"]
    src = custui.CustomerHandler._passkey.__code__.co_consts      # the edge's relay of passkey/enroll/verify
    relayed = {"credential_id", "public_key_spki_b64", "cose_alg", "uv", "client_data_json", "challenge"}
    assert relayed <= {c for c in src if isinstance(c, str)}
    assert set(body) == relayed
    assert re.fullmatch(r"[A-Za-z0-9_-]+", body["credential_id"]) and bytes.fromhex(out["raw"]["id"]) == wa.b64url_decode(body["credential_id"])
    assert body["public_key_spki_b64"] == out["raw"]["spki"]
    assert base64.b64decode(body["public_key_spki_b64"], validate=True)              # the provisioner's strict decode
    assert body["client_data_json"] == wa.b64url_nopad(out["raw"]["cdj"].encode())     # exactly base64url, no padding
    cd = json.loads(out["raw"]["cdj"])
    assert cd["challenge"] == wa.challenge_b64url("ch-xyz") and cd["type"] == "webauthn.create"   # UTF-8 of the string
    assert body["cose_alg"] == -7 and body["uv"] is True and out["uv2"] is False and body["challenge"] == "ch-xyz"


def test_the_sign_in_payload_is_exactly_what_the_edge_relays():
    out = _run(r"""
installWebAuthn();
await navigator.credentials.create({ publicKey: { challenge: new Uint8Array([1]), rp: { name: "V" },
  user: { id: new TextEncoder().encode("cust_a"), name: "a", displayName: "a" } } });
const cred = await navigator.credentials.get({ publicKey: { challenge: new TextEncoder().encode("login-ch") } });
out.body = S.assertionPayload(cred, "login-ch");
out.raw = { ad: Buffer.from(cred.response.authenticatorData).toString("hex"),
            sig: Buffer.from(cred.response.signature).toString("hex") };
""")
    from sigil.ui import webauthn as wa
    body = out["body"]
    assert set(body) == {"credential_id", "authenticator_data", "client_data_json", "signature", "challenge"}
    for k in ("credential_id", "authenticator_data", "client_data_json", "signature"):
        assert re.fullmatch(r"[A-Za-z0-9_-]+", body[k]), k                            # base64url, no padding
    assert body["authenticator_data"] == wa.b64url_nopad(bytes.fromhex(out["raw"]["ad"]))
    assert body["signature"] == wa.b64url_nopad(bytes.fromhex(out["raw"]["sig"]))
    cd = json.loads(wa.b64url_decode(body["client_data_json"]))
    assert cd == {"type": "webauthn.get", "challenge": wa.challenge_b64url("login-ch"), "origin": PK_ORIGIN}
    assert body["challenge"] == "login-ch"


def test_browsers_without_passkeys_are_told_so_before_anything_is_created():
    out = _run(_STUB + r"""
const env = (passkeys) => ({ h, VUI, api: "api/customer", who: { username: "cust_a" }, passkeys, nav: () => {},
                             here: () => "#/security" });
async function screen(opts, passkeys) {
  installWebAuthn(opts); AUTH.created.length = 0; calls.length = 0;
  document.body.children = [];
  const root = S.viewSecurity(env(passkeys)); document.body.appendChild(root);
  await settle();
  const add = button(root, "Add a passkey");
  if (add) { add.click(); await settle(); }
  return { support: S.webauthnSupport(), add: !!add, text: root.textContent, created: AUTH.created.length,
           posted: calls.filter(c => c[0] === "POST").map(c => c[1]) };
}
out.none = await screen({ noWebAuthn: true }, true);
out.nokey = await screen({ noGetPublicKey: true }, true);
out.off = await screen({}, false);
out.nullKey = await screen({ nullPublicKey: true }, true);
out.oldResponse = await screen({ oldResponse: true }, true);
out.cancelled = await screen({ createError: "NotAllowedError" }, true);
out.ok = await screen({}, true);
installWebAuthn({ noWebAuthn: true });
calls.length = 0;
try { await S.passkeySignIn({ VUI, api: "api/customer" }); } catch (e) { out.signIn = [e.code, S.signInMessage(e)]; }
out.signInCalls = calls.length;
""", {"routes": {"api/customer/security": [{"ok": True, "totp": False, "passkeys": [], "account_name": "a@b.io"}],
                 "api/customer/passkey/enroll/challenge": [{"challenge": "ch-1"}],
                 "api/customer/passkey/enroll/verify": [{"ok": True}],
                 "api/customer/passkey/login/challenge": [{"challenge": "ch-2"}]}})
    # no WebAuthn at all, or no getPublicKey(): said plainly, no button, nothing created and nothing sent
    for case, words in (("none", "This browser cannot create passkeys"), ("nokey", "cannot add passkeys to VIGIL")):
        o = out[case]
        assert o["add"] is False and o["created"] == 0 and o["posted"] == [] and words in o["text"], case
    assert out["none"]["support"] == "none" and out["nokey"]["support"] == "no-key" and out["ok"]["support"] == "ok"
    # passkeys not served here: no button either
    assert out["off"]["add"] is False and "Passkeys are not available here yet." in out["off"]["text"]
    # a browser that created one but did not hand over its key: nothing is registered
    for case in ("nullKey", "oldResponse"):
        o = out[case]
        assert o["created"] == 1 and o["posted"] == ["api/customer/passkey/enroll/challenge"], case
        assert "cannot hand a new passkey to VIGIL" in o["text"], case
    assert "No passkey was added." in out["cancelled"]["text"]
    assert out["ok"]["posted"] == ["api/customer/passkey/enroll/challenge", "api/customer/passkey/enroll/verify"]
    assert out["signIn"][0] == "unsupported" and "cannot use passkeys" in out["signIn"][1] and out["signInCalls"] == 0


# --- unit: the step-up helper ----------------------------------------------------------------------------------------------
_STEP = _STUB + r"""
const where = h("div.cust-offer"); document.body.appendChild(where);
let runs = 0;
const ACTION = CFG.action || [];
function action() {
  runs++;
  const a = ACTION.length > 1 ? ACTION.shift() : ACTION[0];
  if (a && a.__fail) return Promise.reject(fail(a.__fail, a.data));
  return Promise.resolve(a);
}
const navs = [];
let result = null, error = null;
const p = S.stepUp({ h, VUI, api: "api/customer", where, nav: r => navs.push(r) }, action)
  .then(r => { result = r; }, e => { error = { status: e.status || null, data: e.data || null, cancelled: !!e.stepUpCancelled }; });
async function code(c, label) {
  where.querySelector(".cust-stepup input").value = c; button(where, label || "Verify").click(); await settle();
}
function report() {
  out.runs = runs; out.result = result; out.error = error; out.navs = navs;
  out.boxes = where.querySelectorAll(".cust-stepup").length;
  out.msg = text(where.querySelector(".cust-stepup-msg"));
  out.verifies = calls.filter(c => c[1] === "api/customer/mfa/verify").map(c => c[2]);
}
"""
_REFUSE = {"__fail": 401, "data": {"error": "a fresh second-factor (step-up) is required", "step_up_required": True}}


def test_step_up_retries_the_action_exactly_once():
    out = _run(_STEP + r"""
await settle();
out.title = text(where.querySelector(".cust-stepup strong"));
out.focusable = !!where.querySelector(".cust-stepup input#stepup-code-1");
await code("123 456"); await p; report();
""", {"action": [_REFUSE, {"checkout_url": "https://checkout.stripe.com/x"}],
      "routes": {"api/customer/mfa/verify": [{"ok": True, "method": "totp"}]}})
    assert out["title"] == "Verify with your authenticator" and out["focusable"] is True
    assert out["runs"] == 2 and out["verifies"] == [{"code": "123456"}] and out["boxes"] == 0
    assert out["result"] == {"checkout_url": "https://checkout.stripe.com/x"} and out["error"] is None


def test_step_up_never_loops_on_a_second_refusal():
    out = _run(_STEP + "await settle(); await code('123456'); await p; await settle(); report();",
               {"action": [_REFUSE], "routes": {"api/customer/mfa/verify": [{"ok": True}]}})
    assert out["runs"] == 2 and len(out["verifies"]) == 1 and out["boxes"] == 0      # no second box, no third run
    assert out["error"] == {"status": 401, "data": _REFUSE["data"], "cancelled": False}


def test_step_up_passes_other_errors_and_answers_through_without_asking():
    for first, want in (({"__fail": 500, "data": {"error": "boom"}}, {"status": 500, "data": {"error": "boom"}}),
                        ({"__fail": 401, "data": {"error": "login required"}}, {"status": 401, "data": {"error": "login required"}}),
                        ({"__fail": 403, "data": {"error": "denied", "step_up_required": True}},
                         {"status": 403, "data": {"error": "denied", "step_up_required": True}})):
        out = _run(_STEP + "await settle(); report();", {"action": [first]})
        assert out["runs"] == 1 and out["boxes"] == 0 and out["verifies"] == [], first
        assert out["error"] == {**want, "cancelled": False}, first
    out = _run(_STEP + "await settle(); report();", {"action": [{"ok": True}]})
    assert out["runs"] == 1 and out["result"] == {"ok": True} and out["boxes"] == 0


def test_a_wrong_code_is_said_in_the_box_and_nothing_is_re_run():
    out = _run(_STEP + r"""
await settle();
await code("12345"); out.short = text(where.querySelector(".cust-stepup-msg")); out.afterShort = calls.length;
await code("111111"); out.wrong = text(where.querySelector(".cust-stepup-msg")); out.runsAfterWrong = runs;
await code("222222"); out.replayed = text(where.querySelector(".cust-stepup-msg"));
await code("333333"); await p; report();
""", {"action": [_REFUSE, {"ok": True}],
      "routes": {"api/customer/mfa/verify": [{"__fail": 403, "data": {"error": "denied: invalid or expired TOTP code"}},
                                             {"__fail": 403, "data": {"error": "denied: this TOTP code was already used"}},
                                             {"ok": True}]}})
    assert out["short"] == "Enter the 6 digits your authenticator app shows." and out["afterShort"] == 0
    assert out["wrong"] == "That code did not work. Enter the new code your app shows." and out["runsAfterWrong"] == 1
    assert out["replayed"].startswith("That code was already used.")
    assert out["runs"] == 2 and out["result"] == {"ok": True} and len(out["verifies"]) == 3


def test_cancel_and_an_ended_session_reject_without_re_running():
    out = _run(_STEP + "await settle(); button(where, 'Cancel').click(); await p; report();", {"action": [_REFUSE]})
    assert out["runs"] == 1 and out["boxes"] == 0 and out["error"]["cancelled"] is True and out["verifies"] == []
    out = _run(_STEP + "await settle(); await code('123456'); await p; report();",
               {"action": [_REFUSE], "routes": {"api/customer/mfa/verify": [{"__fail": 401, "data": {"error": "login required"}}]}})
    assert out["runs"] == 1 and out["boxes"] == 0 and out["error"]["status"] == 401 and out["error"]["cancelled"] is False


def test_an_account_without_an_authenticator_is_sent_to_account_security():
    out = _run(_STEP + r"""
await settle(); await code("123456");
out.offer = buttons(where);
button(where, "Open Account security").click(); await p; report();
""", {"action": [_REFUSE],
      "routes": {"api/customer/mfa/verify": [{"__fail": 403, "data": {"error": "denied: no TOTP factor is enrolled"}}]}})
    assert "Open Account security" in out["offer"]
    assert out["navs"] == ["#/security"] and out["error"]["cancelled"] is True and out["runs"] == 1


# --- app.js: Buy goes through the helper; flag off, everything is as before ------------------------------------------------
# startCheckout as it was before this slice (427e4909), verbatim: the flag-off build must behave exactly like it.
_BASE_START_CHECKOUT = r"""  async function startCheckout(o, btn) {
    btn.disabled = true;
    try {
      var r = await VUI.postJSON(API + "/billing/checkout", { price_id: o.price_id });
      if (!r || !isCheckoutUrl(r.checkout_url)) {
        err("The payment link we received was not a secure https link, so we did not open it. Nothing was charged.");
        btn.disabled = false; return;
      }
      location.assign(r.checkout_url);            // leave for the processor's hosted page
    } catch (e) {
      btn.disabled = false;
      if (e && e.status === 401 && e.data && e.data.step_up_required) {
        return err("For your security, this purchase needs a fresh second-factor check. Verify with your "
          + "authenticator, then try again. Nothing was charged.");
      }
      if (e && e.status === 401) { await refreshWho(); nav("#/login"); return; }
      err("Checkout could not start" + ((e && e.data && e.data.error) ? ": " + e.data.error : ".")
        + " Nothing was charged.");
    }
  }
"""


def _checkout_harness() -> str:
    src = _src()
    new = "\n".join([_fn(src, "pageFlag"), _security_lines(src), _fn(src, "withStepUp"), _fn(src, "startCheckout")])
    common = _fn(src, "isCheckoutUrl")

    def factory(name, body):
        return (f"function {name}(env) {{ const {{ VUI, API, err, refreshWho, nav, location }} = env;\n{common}\n"
                f"{body}\nreturn startCheckout; }}\n")
    return factory("makeBase", _BASE_START_CHECKOUT) + factory("makeNew", new) + r"""
async function buy(make, flag, answers, verifyAnswers) {
  document.body.dataset.security = flag;
  const trace = [], q = answers.slice(), vq = (verifyAnswers || []).slice();
  const V = Object.assign({}, window.VUI, {
    postJSON: async (p, b) => {
      trace.push(["post", p, b]);
      const a = p.indexOf("mfa/verify") >= 0 ? vq.shift() : q.shift();
      if (a && a.__fail) throw fail(a.__fail, a.data);
      return a;
    } });
  const env = { VUI: V, API: "api/customer", err: m => trace.push(["err", m]),
                refreshWho: async () => { trace.push(["refreshWho"]); }, nav: r => trace.push(["nav", r]),
                location: { assign: u => trace.push(["assign", u]) } };
  const row = h("div.cust-offer"), btn = h("button.btn", { type: "button", text: "Buy" });
  row.appendChild(btn); document.body.appendChild(row);
  const run = make(env)({ price_id: "pack_500" }, btn);
  await settle();
  const box = row.querySelector(".cust-stepup");
  if (box && CFG.code) { box.querySelector("input").value = CFG.code; button(box, "Verify").click(); }
  if (box && CFG.cancel) button(box, "Cancel").click();
  await run;
  trace.push(["disabled", btn.disabled], ["boxes", row.querySelectorAll(".cust-stepup").length]);
  row.remove();
  return trace;
}
"""


_ANSWERS = {
    "https": [{"checkout_url": "https://checkout.stripe.com/c/pay/x"}],
    "http": [{"checkout_url": "http://checkout.example/x"}],
    "empty": [None],
    "stepup": [_REFUSE],
    "login": [{"__fail": 401, "data": {"error": "login required"}}],
    "denied": [{"__fail": 403, "data": {"error": "denied: manage_billing"}}],
    "boom": [{"__fail": 500, "data": None}],
    "updating": [{"__fail": 503, "data": {"error": "updating"}}],
}


def test_with_the_flag_off_buy_behaves_exactly_as_before():
    """The byte-identical proof: the flag-off Buy and the function it replaced, run side by side through every server
    answer, leave the same trace (requests, messages, navigation, the button) — and so does the flag-ON Buy whenever
    the server does not ask for a fresh second factor."""
    out = _run(_checkout_harness() + r"""
out.cases = {};
for (const [name, answers] of Object.entries(CFG.answers)) {
  out.cases[name] = { base: await buy(makeBase, "0", answers), off: await buy(makeNew, "0", answers),
                      offPlaceholder: await buy(makeNew, "__VIGIL_SECURITY__", answers),
                      on: name === "stepup" ? null : await buy(makeNew, "1", answers) };
}
""", {"answers": _ANSWERS})
    for name, c in out["cases"].items():
        assert c["off"] == c["base"] and c["offPlaceholder"] == c["base"], name
        if c["on"] is not None:
            assert c["on"] == c["base"], name
    assert ["assign", "https://checkout.stripe.com/c/pay/x"] in out["cases"]["https"]["base"]
    assert any(e[0] == "err" and "fresh second-factor check" in e[1] for e in out["cases"]["stepup"]["off"])


def test_buy_goes_through_the_step_up_helper():
    js = _src()
    assert "withStepUp(function () { return VUI.postJSON(API + \"/billing/checkout\", { price_id: o.price_id }); }" \
        in _fn(js, "startCheckout")
    out = _run(_checkout_harness() + r"""
out.ok = await buy(makeNew, "1", [CFG.refuse, { checkout_url: "https://checkout.stripe.com/c/pay/x" }], [{ ok: true }]);
""", {"refuse": _REFUSE, "code": "654321"})
    post = ["post", "api/customer/billing/checkout", {"price_id": "pack_500"}]
    assert out["ok"] == [post, ["post", "api/customer/mfa/verify", {"code": "654321"}], post,
                         ["assign", "https://checkout.stripe.com/c/pay/x"], ["disabled", True], ["boxes", 0]]
    out = _run(_checkout_harness() + "out.again = await buy(makeNew, '1', [CFG.refuse, CFG.refuse], [{ ok: true }]);",
               {"refuse": _REFUSE, "code": "654321"})
    assert out["again"][:3] == [post, ["post", "api/customer/mfa/verify", {"code": "654321"}], post]
    assert out["again"][3][0] == "err" and "fresh second-factor check" in out["again"][3][1]       # shown, no loop
    assert out["again"][-2:] == [["disabled", False], ["boxes", 0]]
    out = _run(_checkout_harness() + "out.cancel = await buy(makeNew, '1', [CFG.refuse]);",
               {"refuse": _REFUSE, "cancel": True})
    assert out["cancel"] == [post, ["disabled", False], ["boxes", 0]]       # closed: nothing sent again, no error


_BASE_VIEW_LOGIN = r"""  function viewLogin() {
    var form = h("div.card.cust-auth", {}, [
      h("h2", { text: "Sign in" }),
      googleBlock(),
      field("login-email", "Email", "email"),
      field("login-password", "Password", "password"),
      h("div.row", {}, [
        h("button.btn.btn-primary", { type: "button", text: "Sign in", onClick: doLogin }),
        h("button.cust-nav-link", { type: "button", text: "Create an account", onClick: function () { nav("#/signup"); } }),
      ]),
      h("div.row", {}, [
        h("button.cust-nav-link", { type: "button", text: "Forgot your password?", onClick: function () { nav("#/recover"); } }),
      ]),
    ]);
    return shell(form, "#/login");
  }
"""
_BASE_RIGHT = r"""    var right = authed()
      ? h("button.cust-nav-link", { type: "button", text: "Sign out (" + (w.username || "") + ")", onClick: doLogout })
      : h("button.cust-nav-link", { type: "button", text: "Sign in", onClick: function () { nav("#/login"); } });
"""


def _app_harness() -> str:
    """The sign-in screen, the top bar and the routes, from app.js verbatim, plus their pre-slice versions (the top
    bar's right side swapped back in) for a side-by-side comparison."""
    src = _src()
    shell = _fn(src, "shell")
    i = shell.index("    var right = authed()")
    j = shell.index("    return h(\"div.cust-shell\"")
    base_shell = shell[:i] + _BASE_RIGHT + shell[j:]
    a = src.index("  var ROUTES = {")
    routes = src[a:src.index("\n  };", a) + 5]
    stubs = r"""
let who = { authenticated: true, username: "ana" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const trace = [];
function nav(r) { trace.push(["nav", r]); }
function doLogout() {} function doLogin() {} function ntfWidget() { return null; } function googleBlock() { return null; } function ssoBlock() { return null; }
function clearErr() {} function err(m) { trace.push(["err", m]); }
function refreshWho() { trace.push(["refreshWho"]); return Promise.resolve(); }
const API = "api/customer";
const GUIDE = null; const GUIDE_ON = false; const MONITORING_ON = false; const TEAM_ON = false; const LAUNCH_ON = false; const CODE_ON = false; const CONNECT_ON = false;
const ATTACK_PATH_ON = false; const BLIND_VULN_ON = false;   // PR-L (Area 11): off here (shell reads ATTACK_PATH_ON)
const SETTINGS_ON = false; const PRIVACY_CENTER_ON = false;
const SELLER_IDENTITY_ON = false;    // legal/governance S7: off here (shell reads SELLER_IDENTITY_ON for its tab)
const LIVE_ON = false;    // Live Control: off here (shell reads LIVE_ON for its tab)
globalThis.location = { hash: "#/" };
function viewDashboard() { return "dashboard"; } function viewSecurityScreen() { return "security"; }
function viewGuideScreen() { return "guide"; } function viewSignup() {} function viewRecover() {} function viewGoogleCode() {}
function viewBilling() {} function viewBillingReturn() {} function viewInvoices() {} function viewAssets() {}
function viewAssessments() {} function viewSoon() {}
function ser(e) {
  if (!e || !e.tagName) return e && e.nodeValue !== undefined ? "#" + e.nodeValue : String(e);
  const at = Object.keys(e.attrs).sort().map(k => k + "=" + e.attrs[k]).join(",");
  return "<" + e.tagName + (e.id ? "#" + e.id : "") + (e.className ? "." + e.className : "") + "[" + at + "]"
    + JSON.stringify(e.dataset) + (e.listeners.click ? "(click)" : "") + ">" + e.children.map(ser).join("") + "</>";
}
"""
    base = ("function baseViews() {\n" + _BASE_VIEW_LOGIN + base_shell.replace("function shell(", "function bshell(")
            + "\nreturn { viewLogin, shell: bshell }; }\n").replace("return shell(form", "return bshell(form")
    # the page's data-* flags are in place BEFORE app.js's own flag lines run (as the edge writes them into the page)
    return ("Object.assign(document.body.dataset, CFG.flags || {});\n" + stubs + _fn(src, "pageFlag") + "\n"
            + _security_lines(src) + "\n" + _fn(src, "field") + "\n"
            + _fn(src, "navLink") + "\n" + shell + "\n" + _fn(src, "accountLinks") + "\n" + _fn(src, "passkeyBlock")
            + "\n" + _fn(src, "inviteToast")   # passkey sign-in surfaces an accepted invite exactly as doLogin does
            + "\n" + _fn(src, "doPasskeyLogin") + "\n" + _fn(src, "withStepUp") + "\n" + _fn(src, "viewLogin") + "\n"
            + routes + "\n" + base)


@pytest.mark.parametrize("flags", [{}, {"security": "0"}, {"security": "0", "passkey": "1"},
                                   {"security": "__VIGIL_SECURITY__", "passkey": "__VIGIL_PASSKEY__"}])
def test_with_the_flag_off_the_app_is_unchanged(flags):
    """The sign-in screen and the top bar render node for node like the functions they replaced (the top bar's tabs
    aside: other screens add theirs), #/security is the home screen, and withStepUp(action) is action() itself."""
    out = _run(_app_harness() + r"""
installWebAuthn();
const b = baseViews();
const strip = el => { el.querySelectorAll("nav").forEach(n => { n.children = []; }); return el; };
who = { authenticated: false };
out.login = [ser(viewLogin()), ser(b.viewLogin())];
who = { authenticated: true, username: "ana" };
out.top = [ser(strip(shell(h("p", { text: "x" }), "#/"))), ser(strip(b.shell(h("p", { text: "x" }), "#/")))];
let ran = 0;
out.same = withStepUp(() => { ran++; return "the action's own promise"; });
out.ran = ran; out.route = ROUTES["#/security"]();
who = { authenticated: false };
out.anonRoute = ser(ROUTES["#/security"]()) === ser(viewLogin());
""", {"flags": flags})
    assert out["login"][0] == out["login"][1]                         # the sign-in screen, exactly as before
    assert out["top"][0] == out["top"][1]                             # the top bar, exactly as before
    assert out["route"] == "dashboard" and out["anonRoute"] is True
    assert out["same"] == "the action's own promise" and out["ran"] == 1
    assert "Sign out (ana)" in out["top"][0] and "#/security" not in out["top"][0]
    assert "passkey" not in out["login"][0].lower()


def test_with_the_flag_on_the_name_opens_account_security_and_sign_in_offers_a_passkey():
    out = _run(_app_harness() + r"""
installWebAuthn();
location.hash = "#/security";
const bar = shell(h("p", { text: "x" }), "#/security").querySelector(".cust-topbar");
const right = bar.children.slice(-2);
out.right = right.map(b => [b.textContent, b.getAttribute("title"), b.getAttribute("aria-label"),
                            b.getAttribute("aria-current")]);
right[0].click();
out.route = ROUTES["#/security"]();
who = { authenticated: false };
const card = () => viewLogin().querySelector(".cust-auth");
out.login = buttons(card());
document.body.dataset.passkey = "0";
out.loginNoPasskey = buttons(card());
document.body.dataset.passkey = "1"; installWebAuthn({ noWebAuthn: true });
const v = card(); out.loginNoWebAuthn = [buttons(v), text(v.querySelector(".cust-passkey-none"))];
out.trace = trace;
""", {"flags": {"security": "1", "passkey": "1"}})
    assert out["right"] == [["ana", "Account security", "Account security (ana)", "page"],
                            ["Sign out", None, None, None]]
    assert out["trace"] == [["nav", "#/security"]] and out["route"] == "security"
    assert out["login"] == ["Sign in", "Create an account", "Sign in with a passkey", "Forgot your password?"]
    assert "Sign in with a passkey" not in out["loginNoPasskey"]
    assert "Sign in with a passkey" not in out["loginNoWebAuthn"][0]
    assert out["loginNoWebAuthn"][1] == "Passkey sign-in needs a browser that supports passkeys."


def test_passkey_sign_in_follows_the_password_sign_in_flow():
    """A passkey sign-in ends exactly like a password sign-in (doLogin): refresh the session, go home, say so."""
    src = _src()
    login_tail = re.search(
        r'if \(r && r\.username\) \{ await refreshWho\(\); nav\("#/"\); VUI\.toast\("Signed in"\); inviteToast\(r\); \}',
        _fn(src, "doLogin"))
    assert login_tail and login_tail.group(0) in _fn(src, "doPasskeyLogin")
    out = _run(_app_harness() + _STUB + r"""
installWebAuthn();
await navigator.credentials.create({ publicKey: { challenge: new Uint8Array([1]), rp: { name: "V" },
  user: { id: new TextEncoder().encode("ana"), name: "a", displayName: "a" } } });
await doPasskeyLogin(); await settle();
out.ok = trace.splice(0);
installWebAuthn({ getError: "NotAllowedError" });
await doPasskeyLogin(); await settle();
out.cancelled = trace.splice(0);
out.calls = calls.map(c => c[1]);
""", {"flags": {"security": "1", "passkey": "1"},
      "routes": {"api/customer/passkey/login/challenge": [{"challenge": "c1"}],
                 "api/customer/passkey/login/verify": [{"username": "cust_ana", "orgs": ["org_a"], "active_org": "org_a"}]}})
    assert out["ok"] == [["refreshWho"], ["nav", "#/"]] and out["toasts"] == ["Signed in"]
    assert out["cancelled"] == [["err", "Passkey sign-in did not complete. Try again, or sign in with your email and password."]]
    assert out["calls"] == ["api/customer/passkey/login/challenge", "api/customer/passkey/login/verify",
                            "api/customer/passkey/login/challenge"]


# --- the setup key: shown once, never kept ---------------------------------------------------------------------------------
def test_the_setup_key_is_shown_once_and_never_stored():
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    uri = f"otpauth://totp/VIGIL%3Aana%40acme.io?secret={secret}&issuer=VIGIL&algorithm=SHA1&digits=6&period=30"
    out = _run(_STUB + r"""
const writes = [];
const spy = name => ({ getItem: () => null, removeItem: () => {}, clear: () => {},
                       setItem: (k, v) => writes.push([name, String(k) + "=" + String(v)]) });
Object.defineProperty(globalThis, "localStorage", { value: spy("localStorage"), configurable: true });
Object.defineProperty(globalThis, "sessionStorage", { value: spy("sessionStorage"), configurable: true });
globalThis.indexedDB = { open: (...a) => { writes.push(["indexedDB", JSON.stringify(a)]); throw new Error("no"); } };
let cookie = "";
Object.defineProperty(document, "cookie", { get: () => cookie, set: v => { writes.push(["cookie", v]); cookie = v; } });
globalThis.history = { pushState: (...a) => writes.push(["history", JSON.stringify(a)]),
                       replaceState: (...a) => writes.push(["history", JSON.stringify(a)]) };
let hash = "#/security";
globalThis.location = { get hash() { return hash; }, set hash(v) { writes.push(["hash", v]); hash = v; },
                        assign: u => writes.push(["assign", u]) };
installWebAuthn();
const env = { h, VUI, api: "api/customer", who: { username: "cust_ana" }, passkeys: true, nav: () => {},
              here: () => "#/security" };
let root = S.viewSecurity(env); document.body.appendChild(root);
await settle();
button(root, "Set up").click(); await settle();
out.shown = document.body.textContent.split(CFG.secret.replace(/(.{4})(?=.)/g, "$1 ")).length - 1;
out.inPanel = !!root.querySelector(".cust-sec-setup code.cust-totp-key");
out.linked = root.querySelector("a.cust-sec-applink").getAttribute("href") === CFG.uri;
root.querySelector("#sec-totp-code").value = "123456";
button(root, "Confirm").click(); await settle();
const all = el => el.textContent + el.querySelectorAll("a").map(a => a.getAttribute("href")).join(" ");
out.afterConfirm = all(root).indexOf(CFG.secret) < 0 && all(root).replace(/\s+/g, "").indexOf(CFG.secret) < 0;
out.badge = text(root.querySelector(".cust-badge"));
root.remove();
root = S.viewSecurity(env); document.body.appendChild(root); await settle();
out.reopened = all(root).replace(/\s+/g, "").indexOf(CFG.secret) < 0;
out.writes = writes;
out.keyKept = JSON.stringify(writes).indexOf(CFG.secret) >= 0;
""", {"secret": secret, "uri": uri,
      "routes": {"api/customer/security": [{"ok": True, "totp": False, "passkeys": [], "account_name": "ana@acme.io"},
                                           {"ok": True, "totp": True, "passkeys": [], "account_name": "ana@acme.io"}],
                 "api/customer/mfa/totp/enroll": [{"ok": True, "method": "totp", "provisioning_uri": uri,
                                                   "secret": secret}],
                 "api/customer/mfa/verify": [{"ok": True, "method": "totp"}]}})
    assert out["shown"] == 1 and out["inPanel"] is True and out["linked"] is True     # once, in the setup panel only
    assert out["afterConfirm"] is True and out["badge"] == "On" and out["reopened"] is True
    assert out["writes"] == [] and out["keyKept"] is False          # no storage, cookie, IndexedDB, history or URL


def test_the_key_leaves_the_screen_as_soon_as_the_code_is_confirmed():
    """The setup panel (and the key in it) goes the moment the code is confirmed, not when the screen's re-read of the
    account answers — here that answer never comes."""
    secret = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU"
    out = _run(_STUB + r"""
const root = S.viewSecurity({ h, VUI, api: "api/customer", who: { username: "cust_a" }, passkeys: false,
                              nav: () => {}, here: () => "#/security" });
document.body.appendChild(root); await settle();
button(root, "Set up").click(); await settle();
out.before = root.textContent.replace(/\s+/g, "").indexOf(CFG.secret) >= 0;
root.querySelector("#sec-totp-code").value = "123456";
button(root, "Confirm").click(); await settle();
out.after = root.textContent.replace(/\s+/g, "").indexOf(CFG.secret) >= 0 || !!root.querySelector("a.cust-sec-applink");
out.toasts = out.toasts || [];
""", {"secret": secret,
      "routes": {"api/customer/security": [{"ok": True, "totp": False, "passkeys": [], "account_name": "a@b.io"},
                                           {"__hang": True}],
                 "api/customer/mfa/totp/enroll": [{"ok": True, "provisioning_uri": f"otpauth://totp/x?secret={secret}",
                                                   "secret": secret}],
                 "api/customer/mfa/verify": [{"ok": True}]}})
    assert out["before"] is True and out["after"] is False and out["toasts"] == ["Two-step verification is on."]


def test_setting_it_up_again_asks_first():
    out = _run(_STUB + r"""
installWebAuthn();
const root = S.viewSecurity({ h, VUI, api: "api/customer", who: { username: "cust_ana" }, passkeys: true,
                              nav: () => {}, here: () => "#/security" });
document.body.appendChild(root); await settle();
button(root, "Set up again").click(); await settle();
out.warn = [text(root.querySelector(".cust-sec-warn p")), buttons(root.querySelector(".cust-sec-warn"))];
out.callsAfterWarn = calls.filter(c => c[0] === "POST").length;
button(root, "Cancel").click(); await settle();
out.back = buttons(root).indexOf("Set up again") >= 0;
button(root, "Set up again").click(); await settle(); button(root, "Continue").click(); await settle();
out.posts = calls.filter(c => c[0] === "POST").map(c => c[1]);
out.panel = !!root.querySelector(".cust-sec-setup");
""", {"routes": {"api/customer/security": [{"ok": True, "totp": True, "passkeys": [], "account_name": "a@b.io"}],
                 "api/customer/mfa/totp/enroll": [{"ok": True, "provisioning_uri": "otpauth://totp/x?secret=AAAA",
                                                   "secret": "AAAA"}]}})
    assert out["warn"][0].startswith("Setting it up again replaces your current authenticator")
    assert out["warn"][1] == ["Continue", "Cancel"] and out["callsAfterWarn"] == 0 and out["back"] is True
    assert out["posts"] == ["api/customer/mfa/totp/enroll"] and out["panel"] is True


# --- CSP, copy, the guide -----------------------------------------------------------------------------------------------
_BANNED = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "html:",
           'setAttribute("on', "setAttribute('on", ".onclick", "onclick=", 'setAttribute("style"', "style:", "cssText",
           "localStorage", "sessionStorage", "indexedDB", "document.cookie")
_MINE = ("withStepUp", "viewSecurityScreen", "passkeyBlock", "doPasskeyLogin", "accountLinks", "startCheckout")


def test_no_inline_handlers_html_strings_inline_styles_or_storage():
    sec = SECURITY_JS.read_text(encoding="utf-8")
    src = _src()
    for name, code in [("security.js", sec)] + [(n, _fn(src, n)) for n in _MINE]:
        for banned in _BANNED:
            assert banned not in code, (name, banned)
    page = (APP / "index.html").read_text(encoding="utf-8")
    assert all("src=" in tag for tag in re.findall(r"<script[^>]*>", page))       # no inline script
    assert not re.search(r"\son[a-z]+\s*=", page) and not re.search(r"\sstyle\s*=", page)
    css = (APP / "app.css").read_text(encoding="utf-8")
    assert ".cust-stepup" in css and ".cust-qr" in css and ".cust-sec-setup .cust-code-input" in css


_FORBIDDEN = re.compile(r"\b(claude|anthropic|opus|sonnet|haiku|fable|strix|nyx|ultracode|gpt|openai|llm)\b"
                        r"|[$€£]\s?\d|\b\d[\d,.]*\s*credits?\b|\bmargin\b", re.IGNORECASE)


def test_the_copy_follows_the_product_rules():
    src = _src()
    code = SECURITY_JS.read_text(encoding="utf-8") + "\n".join(_fn(src, n) for n in _MINE)
    strings = re.findall(r'"((?:[^"\\]|\\.)*)"', code)
    blob = "\n".join(strings)
    assert not _FORBIDDEN.search(blob), _FORBIDDEN.search(blob).group(0)
    assert not re.search(r"estimat|quote|predict", blob, re.IGNORECASE)


def test_the_guide_names_the_real_labels():
    """The guide's "Sign in" and "Protect your account" steps name exactly what the screens show: each label below is
    in the step's copy AND on the rendered screen (a button, a heading or the box's title)."""
    guide = _run("require(" + json.dumps(str(GUIDE_JS)) + "); const G = window.VIGIL_GUIDE;"
                 "out.signin = G.findStep('start', 'signin').step; out.security = G.findStep('start', 'security').step;")
    shown = _run(_STUB + r"""
installWebAuthn();
const env = { h, VUI, api: "api/customer", who: { username: "cust_ana" }, passkeys: true, nav: () => {},
              here: () => "#/security" };
const root = S.viewSecurity(env); document.body.appendChild(root); await settle();
const seen = new Set(root.querySelectorAll("button").map(text).concat(root.querySelectorAll("h3").map(text)));
button(root, "Set up").click(); await settle();
root.querySelectorAll("button").map(text).forEach(t => seen.add(t));
out.setupText = root.textContent;
const where = h("div"); document.body.appendChild(where);
S.stepUp({ h, VUI, api: "api/customer", where }, () => Promise.reject(fail(401, { step_up_required: true })))
  .catch(() => {});
await settle();
where.querySelectorAll("button").map(text).forEach(t => seen.add(t));
seen.add(text(where.querySelector(".cust-stepup strong")));
out.seen = Array.from(seen);
""", {"routes": {"api/customer/security": [{"ok": True, "totp": False, "passkeys": [], "account_name": "a@b.io"}],
                 "api/customer/mfa/totp/enroll": [{"ok": True, "provisioning_uri": "otpauth://totp/x?secret=AAAA",
                                                   "secret": "AAAA"}]}})
    sec = guide["security"]
    copy = " ".join(sec["clicks"])
    assert sec["route"] == "#/security" and sec["where"] == "Account security"
    for label in ("Two-step verification", "Set up", "Confirm", "Passkeys", "Add a passkey",
                  "Verify with your authenticator", "Verify"):
        assert label.lower() in copy.lower(), label
        assert label in shown["seen"], label
    assert "QR code" in copy and "Scan this QR code" in shown["setupText"]
    assert "the key shown under it" in copy and "Enter this key" in shown["setupText"]
    src = _src()
    assert 'h("h2", { text: "Account security" })' in _fn(src, "viewSecurityScreen")
    assert 'setAttribute("title", "Account security")' in _fn(src, "accountLinks")
    assert any("Sign in with a passkey" in c for c in guide["signin"]["clicks"])
    assert '"Sign in with a passkey"' in _fn(src, "passkeyBlock")


# --- the QR code --------------------------------------------------------------------------------------------------------------
# Reference symbols from libqrencode 4.1.1 (`qrencode -l M -8 -m 0 -t ASCII`): byte mode, level M. Small ones as hex
# rows (one per module row, most significant bit = leftmost module), large ones as the sha256 of their 0/1 module string.
# Each is compared with security.js's symbol for the same text and MASK (the reference picked the mask; any of the
# eight is a valid symbol — the format bits carry it).
_OTPAUTH = ("otpauth://totp/VIGIL%3Aana.lopez%40acme-industries.example?secret=" + "A" * 32
            + "&issuer=VIGIL&algorithm=SHA1&digits=6&period=30")
_QR_GOLDEN = [
    ("HELLO", 1, 3, ["1fd27f", "105e41", "17455d", "17555d", "17425d", "104341", "1fd57f", "001300", "16eb4b",
                     "0dafcc", "114a03", "16227a", "0bf125", "001e45", "1fd320", "10543e", "1741fb", "17565e",
                     "175964", "1044b1", "1fd4a0"]),
    (_OTPAUTH, 8, 1, ["1fdc49ef6417f", "10424f5ee6f41", "17599cf2f7b5d", "1748fcb2e6a5d", "1748e8fd5505d",
                      "105de9c600c41", "1fd555555557f", "000b7b4731700", "14685eff15725", "0ca79658b8a81",
                      "01707d498aba7", "0f19448d3218a", "0ccc5dd5757dd", "1e9b60192baaf", "186ae55c9cdb1",
                      "09117809150bb", "14fc5e55f5650", "031492ab9a289", "186ea6709221d", "082d723f0483b",
                      "06f15b1555e51", "16018223aa8ac", "07f5c5ffbf9f5", "11133cc7bfb1a", "1d5736d57555b",
                      "0d15cac6aab11", "13f5b5fd913f5", "0227d02d9112a", "17772f33b762c", "1201db4e88aa1",
                      "02e6b2b78fff9", "19903f8db91ea", "0adafa1d7d6bb", "0f3180aaa8021", "166b139601add",
                      "120ecb3308fc8", "0af1c7bd513e8", "1c97ee27aa9e4", "08d6755fbf365", "0e3e444d112fa",
                      "1c6122fd1d3fb", "0017ae4589111", "1fdb175708955", "104c58454311b", "17434d7d555ff",
                      "17487c11a8a36", "1757b9902dd56", "104ea08131aa8", "1fd80371b18f1"]),
    ("VIGIL:ünïcödé@例え.jp", 3, 1, ["1fd9ef7f", "104a2341", "175c815d", "174e305d", "174f345d", "105ad341",
                                    "1fd5557f", "00098200", "1468b525", "14131834", "096fd1c5", "058673cb",
                                    "1571c0ad", "0535caec", "01e0254d", "11098172", "1062b362", "0b271754",
                                    "1d4bdd49", "0339700d", "1eeecffd", "0017c912", "1fdd2351", "10498b17",
                                    "1743bbf2", "174692ce", "175c9ecf", "1049f518", "1fde0e09"]),
    ("x" * 290, 13, 0, "9fc177a7b8875ccd8674f266cd53acd2774a083e2c15b53b7612a35e752e8a25"),
    ("x" * 1000, 26, 2, "a84b7fbe72da0dff9a2fc431dab4ff650284c43ee17e4bb5387185cdb35d4027"),
    ("x" * 2331, 40, 0, "2176ffc7cfebf33b29a7e341174a69d5717f925a2fedfc7c3aa0e143ec0b2f33"),
]


# The versions above whose mask libqrencode chose by the same penalty as the standard's rules (on the small ones its
# variant of the rules picks another — any mask is valid, the format bits carry it).
_QR_AUTO_AGREES = {13, 26, 40}


def _rows_from_hex(rows: list, size: int) -> list:
    return [[c == "1" for c in format(int(r, 16), f"0{size}b")] for r in rows]


def _format_info(m: list) -> "tuple[int, int]":
    """(error-correction bits, mask) from a symbol's first copy of the format information."""
    bits = [m[i][8] for i in range(6)] + [m[7][8], m[8][8], m[8][7]] + [m[8][14 - i] for i in range(9, 15)]
    v = (sum(1 << i for i, b in enumerate(bits) if b) ^ 0x5412) >> 10
    return v >> 3, v & 7


def test_the_qr_code_matches_a_reference_encoder():
    out = _run(r"""
const bitsOf = m => m.map(r => r.map(b => (b ? "1" : "0")).join("")).join("");
function fmtInfo(m) {                     // (error-correction bits, mask) from the first copy of the format bits
  const bits = [0, 1, 2, 3, 4, 5].map(i => m[i][8]).concat([m[7][8], m[8][8], m[8][7]],
                                                          [9, 10, 11, 12, 13, 14].map(i => m[8][14 - i]));
  const v = (bits.reduce((a, b, i) => a | ((b ? 1 : 0) << i), 0) ^ 0x5412) >> 10;
  return [v >> 3, v & 7];
}
out.got = CFG.cases.map(([t, mask]) => {
  const forced = S.qrMatrix(t, mask), auto = S.qrMatrix(t), af = fmtInfo(auto);
  return { rows: forced.map(r => r.map(b => (b ? "1" : "0")).join("")),
           autoFmt: af, autoIsThatMask: bitsOf(S.qrMatrix(t, af[1])) === bitsOf(auto) };
});
out.tooLong = S.qrMatrix("x".repeat(2332));
""", {"cases": [[t, mask] for t, _v, mask, _g in _QR_GOLDEN]})
    assert out["tooLong"] is None                                     # past version 40: no code (the key still shows)
    for (text, ver, mask, golden), got in zip(_QR_GOLDEN, out["got"]):
        size = ver * 4 + 17
        rows = got["rows"]
        assert len(rows) == size and all(len(r) == size for r in rows), (text[:12], ver)
        if isinstance(golden, list):
            assert rows == [format(int(r, 16), f"0{size}b") for r in golden], (text[:12], ver)
        else:
            assert hashlib.sha256("".join(rows).encode()).hexdigest() == golden, (text[:12], ver)
        assert _format_info(_rows_from_hex([format(int(r, 2), "x") for r in rows], size)) == (0, mask)   # level M
        # the mask security.js picks on its own is level M and exactly one of the eight valid symbols ...
        assert got["autoFmt"][0] == 0 and got["autoIsThatMask"] is True, (text[:12], ver)
        # ... and, on the symbols where the reference's penalty variant agrees with the standard's, the same mask
        if ver in _QR_AUTO_AGREES:
            assert got["autoFmt"][1] == mask, (text[:12], ver)


def test_the_qr_code_is_drawn_as_dark_on_white_svg_nodes():
    out = _run(_STUB + r"""
const root = S.viewSecurity({ h, VUI, api: "api/customer", who: { username: "cust_a" }, passkeys: false,
                              nav: () => {}, here: () => "#/security" });
document.body.appendChild(root); await settle();
button(root, "Set up").click(); await settle();
const svg = root.querySelector("svg.cust-qr");
out.svg = { ns: svg.ns, viewBox: svg.getAttribute("viewBox"), role: svg.getAttribute("role"),
            label: svg.getAttribute("aria-label"), kids: svg.children.map(c => [c.tagName, c.getAttribute("fill")]) };
out.size = S.qrMatrix(CFG.uri).length;
""", {"uri": _OTPAUTH,
      "routes": {"api/customer/security": [{"ok": True, "totp": False, "passkeys": [], "account_name": "a@b.io"}],
                 "api/customer/mfa/totp/enroll": [{"ok": True, "provisioning_uri": _OTPAUTH, "secret": "A" * 32}]}})
    full = out["size"] + 8
    assert out["svg"] == {"ns": "http://www.w3.org/2000/svg", "viewBox": f"0 0 {full} {full}", "role": "img",
                          "label": "QR code to add VIGIL to your authenticator app",
                          "kids": [["RECT", "#ffffff"], ["PATH", "#000000"]]}
