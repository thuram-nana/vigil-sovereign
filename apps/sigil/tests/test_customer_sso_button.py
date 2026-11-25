"""The customer app's "Sign in with your company" button (customer_app/app.js) and the edge flag behind it.

Enterprise SSO (SAML / per-org OIDC) is the live front door; this is its discovery affordance on the login
screen. The backend route already exists (GET /api/customer/sso/login?org=<id>, sso_edge.py); the button lets a
person reach it without being handed a per-org URL. There is no email→org discovery, so the person names their
workspace in a revealed field, and Continue (or Enter) is a top-level navigation to the org-scoped login route.

* The edge writes data-sso="1" into the page at startup only while enterprise SSO is on (VIGIL_CUSTOMER_SSO);
  otherwise "0". The value counts in the build id, so turning it on or off is a new build the open pages learn of.
* The button renders only with the flag; it reveals a workspace-id field; Continue/Enter navigate to the RELATIVE,
  same-origin api/customer/sso/login?org=<url-encoded workspace> (the edge redirects to the IdP). An empty or
  malformed workspace is refused with no navigation; the value is URL-encoded, so a workspace that looks like an
  off-site URL ("//evil", "https://evil") cannot become an open redirect or inject a second query param. Cancel
  returns to the single button.

The app's own functions run under node, extracted verbatim from app.js (same discipline as the Google button).
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from sigil.ui.custui import build_customer_server


def _need_node() -> str:
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH: this job must "
                        "EXECUTE these JS tests")
        pytest.skip("node not installed")
    return node


APP_JS = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app" / "app.js"


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(src: str, name: str) -> str:
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


def _sso_section(src: str) -> str:
    """The enterprise-SSO block — ssoOn() + ssoBlock() together (app.js, verbatim). A section (like the
    Google test's) rather than a single function, because ssoBlock calls the one-line ssoOn helper."""
    a = src.index("  // ---- Sign in with your company")
    b = src.index("\n  }\n", src.index("  function ssoBlock(", a))
    return src[a:b + 4]


# --- the edge flag -----------------------------------------------------------------------------------------------
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


def test_the_edge_writes_the_sso_flag_into_the_page_and_the_build(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_SSO", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-sso="0"' in off and "__VIGIL_SSO__" not in off
    monkeypatch.setenv("VIGIL_CUSTOMER_SSO", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-sso="1"' in on and "__VIGIL_SSO__" not in on
    assert build_on != build_off                       # a page with the button is a different build
    for v in ("0", "no", "maybe", ""):
        monkeypatch.setenv("VIGIL_CUSTOMER_SSO", v)
        assert 'data-sso="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v


# --- the screen (static) -----------------------------------------------------------------------------------------
def test_the_login_screen_carries_the_sso_block():
    assert "ssoBlock()" in _fn(_src(), "viewLogin")


# --- the button (executed under node) ----------------------------------------------------------------------------
# The harness mirrors the real kit (customer_app/ui.js): h() parses "tag#id.class.class" and records the class
# list; VUI.mount() flattens nested child arrays (field() returns [label, input]) and registers ids. A `cfg.action`
# drives one interaction — Continue click, Enter keydown, Cancel click, or a malformed (lone-surrogate) value.
_HARNESS = r"""
const vm = require("vm");
const [PAGEFLAG, FIELD, VAL, SSOBLOCK, CFG] = process.argv.slice(-5);
const cfg = JSON.parse(CFG);
const out = { assigned: [], errors: [] };
const byId = {};
function flat(x) {
  let o = [];
  (Array.isArray(x) ? x : (x == null ? [] : [x])).forEach(function (c) {
    if (Array.isArray(c)) o = o.concat(flat(c)); else if (c != null) o.push(c);
  });
  return o;
}
function El(tag) {
  return { tagName: tag, id: "", className: "", attrs: {}, children: [], listeners: {}, textContent: "", value: "",
    setAttribute(k, v) { this.attrs[k] = String(v); },
    appendChild(c) { this.children.push(c); return c; },
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
    dispatch(t, ev) { (this.listeners[t] || []).forEach(f => f(ev || {})); },
    click() { this.dispatch("click"); }, focus() {} };
}
function register(e) { if (e && e.id) byId[e.id] = e; if (e && e.children) e.children.forEach(register); }
function h(spec, props, kids) {
  const m = /^([A-Za-z0-9]+)?(?:#([^.#]+))?((?:\.[^.#]+)*)$/.exec(spec) || [];
  const e = El(m[1] || "div");
  if (m[2]) { e.id = m[2]; byId[e.id] = e; }
  e.className = (m[3] || "").split(".").filter(Boolean).join(" ");
  props = props || {};
  if (props.text != null) e.textContent = String(props.text);
  if (props.type) e.attrs.type = String(props.type);
  for (const k in props) if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2).toLowerCase(), props[k]);
  flat(kids).forEach(c => e.appendChild(c));
  return e;
}
const VUI = {
  mount(el, kids) { el.children = flat(kids); el.children.forEach(register); },
  $(sel) { return byId[sel.replace(/^#/, "")] || null; },
  errorBanner(m) { out.errors.push(m); },
};
const document = { body: { dataset: cfg.dataset } };
const ctx = { document, h, VUI, API: "api/customer", encodeURIComponent,
  clearErr() {}, err(m) { out.errors.push(m); },
  location: { assign(u) { out.assigned.push(u); } } };
vm.createContext(ctx);
vm.runInContext([PAGEFLAG, FIELD, VAL, SSOBLOCK, "this.ssoBlock = ssoBlock;"].join("\n"), ctx);

function allNodes(n, acc) { acc.push(n); (n.children || []).forEach(c => allNodes(c, acc)); return acc; }
function btnByText(root, text) { return allNodes(root, []).find(n => n.tagName === "button" && n.textContent === text) || null; }

const holder = ctx.ssoBlock();
if (!holder) { out.holder = null; }
else {
  out.holder = "present";
  out.initButton = holder.children[0] && holder.children[0].textContent;
  out.initClasses = holder.children[0] && holder.children[0].className;
  holder.children[0].click();                                   // reveal the workspace field
  const input = byId["sso-workspace"];
  out.hasInput = !!input;
  out.inputType = input && input.attrs.type;
  if (input) input.value = cfg.workspace == null ? "" : cfg.workspace;
  const cont = btnByText(holder, "Continue");
  out.continueClasses = cont && cont.className;
  out.cancelPresent = !!btnByText(holder, "Cancel");
  const action = cfg.action || "continue";
  if (action === "continue") { if (cont) cont.click(); }
  else if (action === "enter") { if (input) input.dispatch("keydown", { key: "Enter" }); }
  else if (action === "otherkey") { if (input) input.dispatch("keydown", { key: "a" }); }
  else if (action === "malformed") { if (input) { input.value = "\uD800"; } if (cont) cont.click(); }
  else if (action === "cancel") {
    const cancel = btnByText(holder, "Cancel"); if (cancel) cancel.click();
    out.collapsedText = holder.children[0] && holder.children[0].textContent;
    out.collapsedCount = holder.children.length;
  }
}
console.log(JSON.stringify(out));
"""


def _run(dataset, workspace=None, action="continue"):
    js = _src()
    r = subprocess.run(
        [_need_node(), "-e", _HARNESS,
         _fn(js, "pageFlag"), _fn(js, "field"), _fn(js, "val"), _sso_section(js),
         json.dumps({"dataset": dataset, "workspace": workspace, "action": action})],
        capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_the_button_shows_only_with_the_flag():
    on = _run({"sso": "1"}, workspace="acme")
    assert on["holder"] == "present"
    assert on["initButton"] == "Sign in with your company"
    assert "cust-sso" in on["initClasses"].split()          # the class app.css styles the button by
    for ds in ({"sso": "0"}, {"sso": "__VIGIL_SSO__"}, {}):
        assert _run(ds, workspace="acme")["holder"] is None, ds


def test_continue_navigates_to_the_org_scoped_sso_login():
    out = _run({"sso": "1"}, workspace="acme")
    assert out["hasInput"] and out["inputType"] == "text" and out["cancelPresent"]
    assert "btn-primary" in out["continueClasses"].split()   # the primary-action styling the Continue button needs
    assert out["assigned"] == ["api/customer/sso/login?org=acme"]     # relative + same-origin
    assert out["errors"] == []


def test_enter_in_the_field_submits_like_continue():
    out = _run({"sso": "1"}, workspace="acme", action="enter")
    assert out["assigned"] == ["api/customer/sso/login?org=acme"]
    empty = _run({"sso": "1"}, workspace="", action="enter")    # the empty-guard runs on the Enter path too
    assert empty["assigned"] == [] and empty["errors"] == ["Enter your company or workspace ID."]
    other = _run({"sso": "1"}, workspace="acme", action="otherkey")   # a non-Enter key does nothing
    assert other["assigned"] == []


def test_cancel_collapses_back_to_the_button():
    out = _run({"sso": "1"}, workspace="acme", action="cancel")
    assert out["assigned"] == []                                 # no navigation
    assert out["collapsedCount"] == 1 and out["collapsedText"] == "Sign in with your company"


def test_empty_workspace_is_refused_with_no_navigation():
    for ws in (None, "", "   "):
        out = _run({"sso": "1"}, workspace=ws)
        assert out["assigned"] == [], ws                         # no navigation on an empty workspace
        assert out["errors"] == ["Enter your company or workspace ID."], ws


def test_a_malformed_workspace_id_is_refused_without_navigation():
    # a lone UTF-16 surrogate makes encodeURIComponent throw; the guard must swallow it (no nav) and say so.
    out = _run({"sso": "1"}, action="malformed")
    assert out["assigned"] == []
    assert out["errors"] == ["Enter a valid company or workspace ID."]


def test_workspace_id_is_url_encoded_so_it_cannot_inject():
    # query/path metacharacters are percent-encoded into the single org value — no second param, no path segment.
    out = _run({"sso": "1"}, workspace="a&b=c/../x #z")
    assert out["assigned"] == ["api/customer/sso/login?org=a%26b%3Dc%2F..%2Fx%20%23z"]


def test_an_off_site_looking_workspace_cannot_become_an_open_redirect():
    # a workspace that looks like an off-site URL stays inside the same-origin RELATIVE path, fully encoded:
    # no "//" (protocol-relative) and no ":" (scheme) survive into the navigated URL.
    for ws in ("//evil.example/x", "https://evil.example", "\\/\\/evil"):
        url = _run({"sso": "1"}, workspace=ws)["assigned"][0]
        assert url.startswith("api/customer/sso/login?org="), ws
        assert "//" not in url and ":" not in url, (ws, url)
