"""The customer app's "Continue with Google" button (customer_app/app.js) and the edge flag behind it.

* The edge writes data-google-signin="1" into the page at startup only while customer Google sign-in is on
  (VIGIL_CUSTOMER_OIDC_ENABLED); otherwise "0". The value counts in the build id, so turning Google on or off is a
  new build the open pages are told about.
* The sign-in and the sign-up screens both carry the button; it renders only with the flag, carries Google's mark,
  and a tap is a top-level navigation to the RELATIVE api/customer/oidc/login (the edge answers with the redirect).
* A Google sign-in that did not complete lands on #oidc=err: one generic message, then the sign-in screen.
* The sign-up copy says what the email carries (a token), never a "verification link" the email does not have.

The app's own functions run under node, extracted verbatim from app.js.
"""
from __future__ import annotations

import http.client
import json
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from sigil.ui.custui import build_customer_server

APP_JS = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app" / "app.js"
_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(src: str, name: str) -> str:
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1                    # from the start of its line ("  function" / "  async function")
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


def _google_section(src: str) -> str:
    """The "Continue with Google" block through the installed-app hand-off it branches to (app.js, verbatim)."""
    a = src.index("  // ---- Continue with Google")
    b = src.index("\n  }\n", src.index("  async function doHandoff(", a))
    return src[a:b + 4]


# --- the edge flag ------------------------------------------------------------------------------------------------
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


def test_the_edge_writes_the_google_flag_into_the_page_and_the_build(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_OIDC_ENABLED", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-google-signin="0"' in off and "__VIGIL_GOOGLE_SIGNIN__" not in off
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_ENABLED", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-google-signin="1"' in on and "__VIGIL_GOOGLE_SIGNIN__" not in on
    assert build_on != build_off                       # a page with the button is a different build
    for v in ("0", "no", "maybe"):
        monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_ENABLED", v)
        assert 'data-google-signin="0"' in _page_and_build(tmp_path / f"c{v}")[0], v


# --- the screens (static) ----------------------------------------------------------------------------------------
def test_both_auth_screens_carry_the_button_and_the_signup_copy_names_what_the_email_carries():
    js = _src()
    assert "googleBlock()" in _fn(js, "viewLogin") and "googleBlock()" in _fn(js, "viewSignup")
    signup = _fn(js, "viewSignup") + _fn(js, "doSignupRequest")
    assert "verification link" not in js                 # the email carries no link
    assert "token" in signup


# --- the button (executed) ---------------------------------------------------------------------------------------
_HARNESS = r"""
const vm = require("vm");
const [SECTION, PAGEFLAG, GERR, CFG] = process.argv.slice(-4);
const cfg = JSON.parse(CFG);
const out = { assigned: [], errors: [], replaced: [] };
function El(tag, ns) { return { tagName: tag, ns: ns || null, attrs: {}, children: [], listeners: {}, textContent: "",
  setAttribute(k, v) { this.attrs[k] = String(v); }, appendChild(c) { this.children.push(c); return c; },
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); } }; }
const document = { body: { dataset: cfg.dataset }, createElementNS: (ns, t) => El(t, ns), createElement: (t) => El(t) };
function h(spec, props, kids) {
  const e = El(spec); props = props || {};
  if (props.text) e.textContent = props.text;
  for (const k in props) if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2).toLowerCase(), props[k]);
  (Array.isArray(kids) ? kids : (kids ? [kids] : [])).forEach(c => c && e.appendChild(c));
  return e;
}
const ctx = { document, h, API: "api/customer", out, navigator: { standalone: false },
  window: { matchMedia: () => ({ matches: false }) },
  location: { hash: cfg.hash || "", pathname: "/", search: "", assign: (u) => out.assigned.push(u) },
  history: { replaceState: (_s, _t, u) => { out.replaced.push(u); ctx.location.hash = u.slice(u.indexOf("#")); } },
  clearErr: () => {}, err: (m) => out.errors.push(m) };
vm.createContext(ctx);
vm.runInContext(PAGEFLAG + "\n" + SECTION + "\n" + GERR +
  "\nthis.googleBlock = googleBlock; this.googleError = googleError;", ctx);
const blk = ctx.googleBlock();
if (blk) {
  const btn = blk.children[0], mark = btn.children[0];
  out.button = btn.children[1].textContent;
  out.btnTag = btn.tagName;
  out.mark = { ns: mark.ns, paths: mark.children.length, fills: mark.children.map(p => p.attrs.fill) };
  out.divider = blk.children[1].children[0].textContent;
  btn.listeners.click.forEach(f => f());
} else { out.button = null; }
out.handled = ctx.googleError();
out.hashAfter = ctx.location.hash;
console.log(JSON.stringify(out));
"""


def _run(dataset, hash_=""):
    js = _src()
    r = subprocess.run(["node", "-e", _HARNESS, _google_section(js), _fn(js, "pageFlag"), _fn(js, "googleError"),
                        json.dumps({"dataset": dataset, "hash": hash_})],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@_node
def test_the_button_shows_only_with_the_flag_and_starts_the_relative_login():
    on = _run({"googleSignin": "1"})
    assert on["button"] == "Continue with Google" and on["btnTag"].startswith("button")
    assert on["mark"] == {"ns": "http://www.w3.org/2000/svg", "paths": 4,
                          "fills": ["#EA4335", "#4285F4", "#FBBC05", "#34A853"]}
    assert on["divider"] == "or use your email"
    assert on["assigned"] == ["api/customer/oidc/login"]            # relative: resolves against the mount
    for ds in ({"googleSignin": "0"}, {"googleSignin": "__VIGIL_GOOGLE_SIGNIN__"}, {}):
        assert _run(ds)["button"] is None, ds


@_node
def test_a_google_sign_in_that_did_not_complete_says_so_once_and_shows_sign_in():
    out = _run({"googleSignin": "1"}, hash_="#oidc=err")
    assert out["handled"] is True and out["replaced"] == ["/#/login"] and out["hashAfter"] == "#/login"
    assert out["errors"] == ["Google sign-in did not complete. Try again, or sign in with your email and password."]
    for h in ("", "#/", "#/login", "#oidc=errx", "#/oidc=err"):
        quiet = _run({"googleSignin": "1"}, hash_=h)
        assert quiet["handled"] is False and quiet["errors"] == [] and quiet["replaced"] == [], h


def test_the_failure_landing_runs_before_routing():
    render = _fn(_src(), "render")
    assert render.index("googleError();") < render.index("var hash = location.hash")
