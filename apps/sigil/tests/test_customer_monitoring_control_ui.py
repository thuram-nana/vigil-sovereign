"""AS-27b — the DEFENSE CONTROL screen on the customer app (#/monitoring/control), under node.

AS-27b is the UI-chain increment after AS-4b (chain ...->3d->4b->27b) and the SAFE-direction mirror of the
Protection preview. It adds a READ-ONLY screen that shows, per host the manager can act on, whether AEGIS is
enforcing live blocking (Respond) RIGHT NOW and whether an authorized STAND-DOWN (the safe-direction return to
observe) would have any effect. The grade comes entirely from the SERVER (the AS-27b core evaluator, over the
same gated monitoring reads); the page RENDERS fixed copy from the server's semantic fields and invents nothing.

* It renders NO button (pure display), so no screen's button census grows a control.
* An enforcing host shows a stand-down applies; a not-enforcing host shows the honest "nothing to stand down"
  blocker. The operate-vs-view copy is decided by the SERVER (can_manage_defense), never the client.
* A read-only role (can_manage=false) sees a plain honest note, never the hosts. An honest empty state and an
  honest error (the read failed) render a plain note, never a crash and never the raw server error. The screen
  reads ONLY api/customer/monitoring/control.
* With monitoring off (MONITORING_ON false), #/monitoring/control is the home screen, exactly as any unknown
  route — no render, no read.

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
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    line = src[i:src.index("\n", i)]
    if line.count("{") and line.count("{") == line.count("}"):
        return line + "\n"
    return src[i:src.index("\n  }\n", i) + 4]


def _var(src: str, name: str) -> str:
    i = src.index(f"\n  var {name} = ") + 1
    lines = []
    for ln in src[i:].split("\n"):
        lines.append(ln)
        if re.search(r";\s*(//.*)?$", ln):
            break
    return "\n".join(lines) + "\n"


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
    this.disabled = false; this.classList = new ClassList(this); this.listeners = {};
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
"""

_WORLD = r"""
document.body.dataset.monitoring = %(flag)s;
let who = { authenticated: true, username: "ana" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/monitoring/control" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let renders = 0; function render() { renders++; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
var GUIDE = null, GUIDE_ON = false;
var SECURITY_ON = false, TEAM_ON = false, LAUNCH_ON = false, CODE_ON = false, CONNECT_ON = false, SETTINGS_ON = false, PRIVACY_CENTER_ON = false, SELLER_IDENTITY_ON = false, LIVE_ON = false, POSTURE_ON = false, AI_GOVERNANCE_ON = false;
const VUI = window.VUI;
const calls = [], toasts = [], errs = [];
let server = {};
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

_APP_FUNCS = ("pageFlag", "loadingHolder", "kv", "here", "own", "monControlOperatorNote",
              "monControlCard", "monControlBody", "viewDefenseControl", "routeShown")
_APP_VARS = ("API", "MONITORING_ON", "MON_STANDDOWN")


def _harness(flag: str = "1") -> str:
    src = _src()
    return "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", "const h = window.VUI.h;",
                      _WORLD % {"flag": json.dumps(flag)}]
                     + [_fn(src, n) for n in _APP_FUNCS] + [_var(src, n) for n in _APP_VARS])


def _node(script: str, *, flag: str = "1") -> dict:
    prog = (_harness(flag) + "\n(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
            " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _c(host, *, enforcing, mode="block", armed=True, proof=True, respond=True, available=None, blockers=()):
    avail = enforcing if available is None else available
    return {"host": host, "mode": mode, "armed": armed, "proof_current": proof, "respond_entitled": respond,
            "enforcing": enforcing, "override_active": False, "standdown_available": avail,
            "standdown_blockers": list(blockers)}


_SCREEN = r"""
const view = viewDefenseControl(); document.body.appendChild(view);
const ccard = host => document.querySelectorAll("div.cust-mon-control-card").filter(c => c.dataset.host === host)[0];
const ctext = host => text(ccard(host));
const cbadge = host => text(ccard(host).querySelector("span.cust-badge"));
"""


def _screen(payload: dict, then: str = "", *, flag: str = "1") -> dict:
    srv = {"GET api/customer/monitoring/control": {"data": payload}}
    return _node(f"server = {json.dumps(srv)};" + _SCREEN + "await flush();\n" + then, flag=flag)


# --- the control states (grounded in the server's grade) -----------------------------------------------------
def test_an_enforcing_host_shows_a_standdown_applies_and_renders_no_button():
    payload = {"org_id": "org_x", "can_manage": True, "can_manage_defense": True,
               "controls": [_c("a.example", enforcing=True)]}
    out = _screen(payload, r"""
out.badge = cbadge("a.example"); out.text = ctext("a.example"); out.buttons = buttons(ccard("a.example"));
out.op = text(document.querySelector("p.cust-mon-control-op")); out.calls = calls;
""")
    assert out["badge"] == "Enforcing · Respond"
    assert "blocking attacks on this host before they reach your app" in out["text"]
    assert "stand-down would pause enforcement back to observe" in out["text"]
    assert "Nothing is stood down from this screen" in out["text"]
    assert out["buttons"] == []                                                 # pure display — no button
    assert "You may operate the live defense" in out["op"]                      # can_manage_defense => operate copy
    assert out["calls"] == [["GET", "api/customer/monitoring/control"]]         # it reads ONLY the control view


def test_a_not_enforcing_host_shows_the_honest_nothing_to_stand_down_blocker():
    payload = {"org_id": "org_x", "can_manage": True, "can_manage_defense": True, "controls": [
        _c("obs.example", enforcing=False, mode="observe", available=False, blockers=["not_enforcing"]),
        _c("off.example", enforcing=False, mode="observe", armed=False, available=False, blockers=["not_enforcing"])]}
    out = _screen(payload, r"""
out.obs = [cbadge("obs.example"), ctext("obs.example")];
out.off = ctext("off.example");
out.anyButton = document.querySelectorAll("button").length;
""")
    assert out["obs"][0] == "Observing" and "observing this host: inspecting and reporting" in out["obs"][1]
    assert "nothing to stand down" in out["obs"][1]
    assert "AEGIS is not monitoring this host yet" in out["off"]
    assert out["anyButton"] == 0                                                # the whole screen is read-only


def test_a_view_only_manager_is_told_operating_the_defense_needs_the_capability():
    payload = {"org_id": "org_x", "can_manage": True, "can_manage_defense": False,
               "controls": [_c("a.example", enforcing=True)]}
    out = _screen(payload, r"""
out.op = text(document.querySelector("p.cust-mon-control-op")); out.buttons = document.querySelectorAll("button").length;
""")
    assert "needs the defense-manager capability" in out["op"] and "the founder holds" in out["op"]
    assert out["buttons"] == 0                                                  # still read-only — no operate button


def test_a_read_only_role_sees_an_honest_note_never_the_hosts():
    out = _screen({"org_id": "org_x", "can_manage": False, "can_manage_defense": False, "controls": []}, r"""
out.text = text(document.querySelector("#mon-control-body"));
out.cards = document.querySelectorAll("div.cust-mon-control-card").length;
""")
    assert "Only the founder or an admin" in out["text"] and out["cards"] == 0


def test_an_empty_control_view_is_an_honest_note_not_a_crash():
    out = _screen({"org_id": "org_x", "can_manage": True, "can_manage_defense": True, "controls": []}, r"""
out.text = text(document.querySelector("#mon-control-body"));
out.cards = document.querySelectorAll("div.cust-mon-control-card").length;
""")
    assert "No host of this workspace has a current proof of control yet" in out["text"] and out["cards"] == 0


def test_a_failed_read_shows_fixed_copy_never_the_raw_server_error():
    out = _node("server = " + json.dumps({
        "GET api/customer/monitoring/control": {"status": 500, "data": {"error": "stack trace: KABOOM at line 7"}}})
        + ";" + _SCREEN + "await flush();\n"
        "out.text = text(document.querySelector('#mon-control-body')); out.errs = errs;")
    assert "Could not load defense control just now" in out["text"]
    assert "KABOOM" not in out["text"] and "stack" not in out["text"]           # the raw server error is never echoed


# --- feature-off: the route is the home screen, no render, no read -------------------------------------------
def test_with_monitoring_off_the_control_route_is_the_home_screen_and_reads_nothing():
    src = _src()
    # routeShown hides the route when monitoring is off; the ROUTES entry falls back to the dashboard (not the view).
    assert '"#/monitoring/control": function () { return authed() ? (MONITORING_ON ? viewDefenseControl()' in src
    out = _node("out.shown = routeShown('#/monitoring/control'); out.calls = calls;", flag="0")
    assert out["shown"] is False and out["calls"] == []                         # off => not shown, nothing read


# --- the control path invents nothing and writes nothing -----------------------------------------------------
def test_the_control_path_is_pure_display_no_write_no_raw_network():
    src = _src()
    block = "\n".join(_fn(src, n) for n in ("viewDefenseControl", "monControlBody", "monControlOperatorNote",
                                            "monControlCard"))
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", block)
    assert "postJSON" not in code                                              # a control view never writes
    for banned in ("fetch(", "XMLHttpRequest", "sendBeacon", "location.href", "window.open", "innerHTML"):
        assert banned not in code, banned
