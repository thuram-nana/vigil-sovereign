"""AS-21a — the RETEST GUARD on the customer app's Monitoring settings screen (#/monitoring/settings), under node.

AS-21a stacks on AS-2k's settings screen. Where AS-2k lets a manager SHORTEN a host's armed window or turn it off,
AS-21a adds a guarded RE-ARM: renew the host's monitoring authority to VIGIL's full standard window from now, in the
host's CURRENT mode, reusing the SAME monitoring/authorize write (no window_s). It mints no new authority and opens no
new edge route. Because re-arm LENGTHENS the armed window (the privilege-raising counterpart to Shorten window), it is
GUARDED: asked in place first, like Turn off, and nothing is sent until it is confirmed.

* Re-arm lives in its OWN row (div.cust-mon-rearm), so AS-2k's window controls (div.cust-mon-actions: Shorten window,
  Turn off) are byte-identical and unchanged.
* The guard asks first: nothing is sent while asking; "Keep as is" restores the controls and sends nothing; only "Yes,
  re-arm" sends monitoring/authorize {host, mode} in the host's CURRENT mode with NO window_s (renew to full) — never
  an org field and never a window_s.
* A 401 {step_up_required} is honest and changes nothing; a lost session goes back to sign-in.
* A non-manager sees no Re-arm control (read-only, as for Shorten/Turn off).
* The re-arm path reaches the network ONLY through monitoring/authorize (source scan) and names no body org_id.

The screen is already gated by VIGIL_CUSTOMER_MONITORING_ENABLED and routed by AS-2k; AS-21a adds no route, so the
route/hub gating is pinned by test_customer_monitoring_settings_ui.py and is not re-asserted here.

app.js's own functions are extracted verbatim and run on the customer UI kit (ui.js) with a minimal DOM.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from test_customer_onboarding import _need_node

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS, APP_JS = APP / "ui.js", APP / "app.js"


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(src: str, name: str) -> str:
    """One of app.js's own top-level functions, verbatim (a one-liner, or everything through its "  }" close)."""
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    line = src[i:src.index("\n", i)]
    if line.count("{") and line.count("{") == line.count("}"):
        return line + "\n"
    return src[i:src.index("\n  }\n", i) + 4]


def _var(src: str, name: str) -> str:
    """One of app.js's own module-level `var` statements, verbatim (ends at a line whose code ends with ";")."""
    i = src.index(f"\n  var {name} = ") + 1
    lines = []
    for ln in src[i:].split("\n"):
        lines.append(ln)
        if re.search(r";\s*(//.*)?$", ln):
            break
    return "\n".join(lines) + "\n"


# A minimal DOM: elements, text, classes, ids, data-*, attributes, events, input values, and tag/.class/#id/[attr].
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
    this.disabled = false; this.value = ""; this.classList = new ClassList(this); this.listeners = {};
  }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); this.children.push(c); c.parentNode = this; return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); c.parentNode = null; return c; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  get firstChild() { return this.children[0] || null; }
  set textContent(v) { this.children = []; if (String(v)) this.appendChild(new Text(v)); }
  get textContent() { return this.children.map(c => c.textContent).join(""); }
  set htmlFor(v) { this.attrs["for"] = String(v); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter(x => x !== f); }
  click() { (this.listeners.click || []).slice().forEach(f => f({ preventDefault() {} })); }
  _all(out) { this.children.forEach(c => { if (c instanceof El) { out.push(c); c._all(out); } }); return out; }
  querySelectorAll(sel) { return this._all([]).filter(e => matches(e, sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
function matches(e, sel) {
  const m = sel.match(/^([a-z][a-z0-9]*)?(?:#([\w-]+))?((?:\.[\w-]+)*)(?:\[([\w-]+)="([^"]*)"\])?$/i);
  if (!m) throw new Error("selector not supported by the test DOM: " + sel);
  if (m[1] && e.tagName !== m[1].toUpperCase()) return false;
  if (m[2] && e.id !== m[2]) return false;
  if ((m[3] || "").split(".").filter(Boolean).some(c => !e.classList.contains(c))) return false;
  if (m[4] && e.getAttribute(m[4]) !== m[5]) return false;
  return true;
}
globalThis.Node = Node;
globalThis.window = globalThis;
const body = new El("body");
globalThis.document = {
  body, documentElement: body, hidden: false,
  createElement: t => new El(t), createTextNode: t => new Text(t),
  querySelector: s => body.querySelector(s), querySelectorAll: s => body.querySelectorAll(s),
  addEventListener: () => {}, removeEventListener: () => {},
};
function text(e) { return e ? e.textContent : null; }
function buttons(root) { return root.querySelectorAll("button").map(b => b.textContent); }
function button(root, label) { return root.querySelectorAll("button").filter(b => b.textContent === label)[0]; }
"""

# The app's world, stubbed: who is signed in, where the page is, what the server answers, and every call made.
_WORLD = r"""
document.body.dataset.monitoring = %(flag)s;
let who = { authenticated: true, username: "ana" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/monitoring/settings" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let renders = 0; function render() { renders++; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
var GUIDE = null, GUIDE_ON = false;
const VUI = window.VUI;
const calls = [], toasts = [], errs = [];
let server = {};            // "GET <path>" / "POST <path>" -> {data} | {status, data} | {wait: <promise>}
async function answer(key) {
  const r = server[key];
  if (!r) { const e = new Error("404"); e.status = 404; e.data = { error: "not found" }; throw e; }
  if (r.wait) return await r.wait;
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data; throw e; }
  return r.data;
}
VUI.getJSON = async p => { calls.push(["GET", p]); return answer("GET " + p); };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); return answer("POST " + p); };
VUI.toast = m => toasts.push(String(m));
VUI.errorBanner = m => errs.push(String(m));
VUI.clearErrorBanner = () => {};
const tick = () => new Promise(r => setTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
const out = {};
"""

_APP_FUNCS = ("pageFlag", "loadingHolder", "kv", "fmtDate", "err", "clearErr", "here", "own", "monSettingsButton",
              "monFailed", "viewMonitoringSettings", "monSettingsRows", "monSettingsBody", "monSettingsCard",
              "monSettingsActions", "monShortenWindow", "monSettingsConfirmOff", "monSettingsTurnOff",
              "monSettingsConfirmReArm", "monReArm", "routeShown")
_APP_VARS = ("API", "MONITORING_ON", "AEGIS_ONBOARDING_ON", "MON_MODE", "MON_DAY_S")


def _harness(flag: str = "1") -> str:
    src = _src()
    return "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", "const h = window.VUI.h;",
                      _WORLD % {"flag": json.dumps(flag)}]
                     + [_fn(src, n) for n in _APP_FUNCS] + [_var(src, n) for n in _APP_VARS])


def _node(script: str, *, flag: str = "1") -> dict:
    prog = (_harness(flag) + "\n(async () => {\n" + script + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
            " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# What the server sends: a manager of a workspace monitoring a.example (Observe) and b.example (Respond).
_PE = 1_800_000_000.0
_MANAGER = {"org_id": "org_x", "can_manage": True, "grants": [
    {"host": "b.example", "mode": "block", "not_before": _PE - 86400, "not_after": _PE, "active": True},
    {"host": "a.example", "mode": "observe", "not_before": _PE - 3600, "not_after": _PE, "active": True}]}


_SCREEN = r"""
const view = viewMonitoringSettings(); document.body.appendChild(view);
const card = host => document.querySelectorAll("div.cust-mon-settings-card").filter(c => c.dataset.host === host)[0];
const acts = host => buttons(card(host).querySelector("div.cust-mon-actions"));
const rearm = host => card(host).querySelector("div.cust-mon-rearm");
"""


def _screen(listing: dict, then: str = "", *, extra: "dict | None" = None) -> dict:
    srv = {"GET api/customer/monitoring": {"data": listing}}
    srv.update(extra or {})
    return _node(f"server = {json.dumps(srv)};" + _SCREEN + "await flush();\n" + then)


# --- re-arm sits in its own row and leaves AS-2k's window controls untouched ----------------------------------------
def test_rearm_is_its_own_control_and_leaves_the_window_controls_untouched():
    out = _screen(_MANAGER, r"""
out.a = acts("a.example"); out.b = acts("b.example");         // AS-2k's window row, unchanged
out.rearmA = buttons(rearm("a.example")); out.rearmB = buttons(rearm("b.example"));
out.calls = calls;
""")
    assert out["a"] == ["Shorten window", "Turn off"] and out["b"] == ["Shorten window", "Turn off"]
    assert out["rearmA"] == ["Re-arm"] and out["rearmB"] == ["Re-arm"]   # one guarded Re-arm per armed host
    # the screen reads ONLY the monitoring list — re-arm opens no new route and fires nothing on render
    assert out["calls"] == [["GET", "api/customer/monitoring"]]


# --- the guard: asked first, confirmed, renews to the full window (no window_s), in the current mode ----------------
def test_rearm_asks_first_then_renews_in_the_current_mode_with_no_window_s():
    out = _screen(_MANAGER, r"""
const before = calls.length;
button(rearm("a.example"), "Re-arm").click(); await flush();
out.asked = buttons(card("a.example").querySelector("div.cust-mon-confirm"));
out.question = text(card("a.example").querySelector("div.cust-mon-confirm"));
out.sentWhileAsking = calls.length - before;
button(card("a.example"), "Yes, re-arm").click(); await flush();
out.post = calls[calls.length - 1]; out.toasts = toasts; out.renders = renders;
""", extra={"POST api/customer/monitoring/authorize": {"data": {"ok": True}}})
    assert out["asked"] == ["Yes, re-arm", "Keep as is"]
    assert "Re-arm a.example?" in out["question"] and "full standard window" in out["question"]
    assert out["sentWhileAsking"] == 0                                   # nothing is sent while the guard asks
    # a.example is in Observe: re-arm re-sends that CURRENT mode with NO window_s (renew to full) and no org field
    assert out["post"] == ["POST", "api/customer/monitoring/authorize", {"host": "a.example", "mode": "observe"}]
    assert "window_s" not in out["post"][2] and "org_id" not in out["post"][2]
    assert out["toasts"] == ["Monitoring for a.example was re-armed."] and out["renders"] == 1


def test_rearm_carries_the_hosts_current_mode():
    out = _screen(_MANAGER, r"""
button(rearm("b.example"), "Re-arm").click(); await flush();           // b.example is in Respond (block)
button(card("b.example"), "Yes, re-arm").click(); await flush();
out.post = calls[calls.length - 1];
""", extra={"POST api/customer/monitoring/authorize": {"data": {"ok": True}}})
    assert out["post"] == ["POST", "api/customer/monitoring/authorize", {"host": "b.example", "mode": "block"}]


def test_keep_as_is_restores_the_controls_and_sends_nothing():
    out = _screen(_MANAGER, r"""
const before = calls.length;
button(rearm("a.example"), "Re-arm").click(); await flush();
button(card("a.example"), "Keep as is").click(); await flush();
out.restoredActs = acts("a.example"); out.restoredRearm = buttons(rearm("a.example"));
out.sent = calls.length - before; out.renders = renders;
""", extra={"POST api/customer/monitoring/authorize": {"data": {"ok": True}}})
    assert out["restoredActs"] == ["Shorten window", "Turn off"] and out["restoredRearm"] == ["Re-arm"]
    assert out["sent"] == 0 and out["renders"] == 0                      # the guard let nothing through


# --- honest refusals: step-up changes nothing; a lost session goes to sign-in ---------------------------------------
def test_a_fresh_second_factor_is_asked_for_honestly_and_changes_nothing():
    step_up = {"status": 401, "data": {"error": "a fresh second factor is required", "step_up_required": True}}
    out = _screen(_MANAGER, r"""
button(rearm("b.example"), "Re-arm").click(); await flush();
const b = button(card("b.example"), "Yes, re-arm"); b.click(); await flush();
out.errs = errs; out.navs = navs; out.who = whoRefreshes; out.renders = renders; out.disabled = b.disabled;
""", extra={"POST api/customer/monitoring/authorize": step_up})
    assert len(out["errs"]) == 1 and "fresh second-factor check" in out["errs"][0]
    assert "Nothing was changed" in out["errs"][0]
    assert out["navs"] == [] and out["who"] == 0 and out["renders"] == 0 and out["disabled"] is False

    denied = {"status": 403, "data": {"error": "denied: requester may not manage monitoring for this org"}}
    out = _screen(_MANAGER, r"""
button(rearm("a.example"), "Re-arm").click(); await flush();
button(card("a.example"), "Yes, re-arm").click(); await flush(); out.errs = errs;
""", extra={"POST api/customer/monitoring/authorize": denied})
    assert out["errs"] == ["Monitoring was not changed: denied: requester may not manage monitoring for this org"]

    out = _screen(_MANAGER, r"""
button(rearm("a.example"), "Re-arm").click(); await flush();
button(card("a.example"), "Yes, re-arm").click(); await flush(); out.navs = navs; out.who = whoRefreshes;
""", extra={"POST api/customer/monitoring/authorize": {"status": 401, "data": {"error": "login required"}}})
    assert out["navs"] == ["#/login"] and out["who"] == 1


# --- a non-manager sees it read-only: no Re-arm at all --------------------------------------------------------------
def test_a_role_that_cannot_manage_sees_no_rearm():
    viewer = {"org_id": "org_x", "can_manage": False,
              "grants": [{"host": "a.example", "mode": "block", "not_before": 1.0, "not_after": _PE, "active": True}]}
    out = _screen(viewer, r"""
out.buttons = buttons(document.querySelector("#mon-settings-body"));
out.rearmRows = document.querySelectorAll("div.cust-mon-rearm").length;
out.hosts = document.querySelectorAll("span.host").map(e => text(e));
""")
    assert out["buttons"] == [] and out["rearmRows"] == 0 and out["hosts"] == ["a.example"]   # read-only, still listed


# --- the re-arm path forks no route and names no org ---------------------------------------------------------------
def test_the_rearm_path_only_touches_the_existing_authorize_route_with_no_window_s():
    """The re-arm functions reach the network only through the EXISTING monitoring/authorize action, never name a body
    org_id (the edge scopes org from the session), and carry NO window_s (renew to the full server window, never a
    client-chosen one)."""
    src = _src()
    block = "\n".join(_fn(src, n) for n in ("monSettingsConfirmReArm", "monReArm"))
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", block)
    paths = re.findall(r"API \+ \"([^\"]*)\"", code)
    assert sorted(set(paths)) == ["/monitoring/authorize"]
    assert "org_id" not in code and "window_s" not in code              # session-scoped; renews to the full window
    for banned in ("fetch(", "XMLHttpRequest", "sendBeacon", "location.href", "window.open", "innerHTML"):
        assert banned not in code, banned
