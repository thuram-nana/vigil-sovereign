"""AS-6d — the AEGIS ONBOARDING screen on the customer app (#/monitoring/onboarding), under node.

AS-6d is the final UI-chain increment (chain ...->4b->27b->6d): a guided flow that COMPOSES the already-built
monitoring surfaces (it re-implements none of them). It walks a tenant from a connected (proven) host to a
monitored (observe) one as an ordered checklist, then surfaces the AS-4b preview + AS-27b defense-control
read-only views as explore-next links. The grade comes entirely from the SERVER (the AS-6d core evaluator);
the page RENDERS fixed copy from the server's semantic step keys + status and invents nothing.

* The current step shows exactly one plain NAV link to the screen that performs it (prove_host -> Assets,
  plan -> Billing, turn_on_observe -> Monitoring); a done or later step shows no button. Clicking navigates.
* A complete journey shows the "monitored" banner and the two explore-next links (preview + control); the
  step cards carry no button (all done).
* A read-only role (can_manage=false) sees a plain honest note, never the steps. An honest error (the read
  failed) renders fixed copy, never a crash and never the raw server error. It reads ONLY
  api/customer/monitoring/onboarding and WRITES nothing (pure nav).
* With the onboarding flag off (AEGIS_ONBOARDING_ON false), #/monitoring/onboarding is the home screen,
  exactly as any unknown route — no render, no read.

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
document.body.dataset.monitoring = %(mon)s;
document.body.dataset.aegisOnboarding = %(onb)s;
let who = { authenticated: true, username: "ana" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/monitoring/onboarding" };
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

_APP_FUNCS = ("pageFlag", "loadingHolder", "kv", "here", "own", "monOnboardButton", "monOnboardingStepCard",
              "monOnboardingBody", "viewMonitoringOnboarding", "routeShown")
_APP_VARS = ("API", "MONITORING_ON", "AEGIS_ONBOARDING_ON", "MON_ONBOARD_STEP", "MON_ONBOARD_STATUS")


def _harness(*, mon: str = "1", onb: str = "1") -> str:
    src = _src()
    return "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", "const h = window.VUI.h;",
                      _WORLD % {"mon": json.dumps(mon), "onb": json.dumps(onb)}]
                     + [_fn(src, n) for n in _APP_FUNCS] + [_var(src, n) for n in _APP_VARS])


def _node(script: str, *, mon: str = "1", onb: str = "1") -> dict:
    prog = (_harness(mon=mon, onb=onb) + "\n(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
            " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _step(key, status, done):
    return {"key": key, "status": status, "done": done}


def _journey(*, steps, complete, next_step, explore, proven=1, active=0, enforcing=0, has_plan=True, respond=True):
    return {"proven_host_count": proven, "active_host_count": active, "enforcing_host_count": enforcing,
            "has_plan": has_plan, "respond_entitled": respond, "steps": steps, "complete": complete,
            "next_step": next_step, "explore_available": explore}


_SCREEN = r"""
const view = viewMonitoringOnboarding(); document.body.appendChild(view);
const scard = step => document.querySelectorAll("div.cust-mon-onboard-card").filter(c => c.dataset.step === step)[0];
"""


def _screen(payload: dict, then: str = "", *, mon: str = "1", onb: str = "1") -> dict:
    srv = {"GET api/customer/monitoring/onboarding": {"data": payload}}
    return _node(f"server = {json.dumps(srv)};" + _SCREEN + "await flush();\n" + then, mon=mon, onb=onb)


# --- the journey states (grounded in the server's grade) -----------------------------------------------------
def test_an_empty_workspace_shows_prove_host_current_with_one_nav_link():
    payload = {"org_id": "o", "can_manage": True, "journey": _journey(
        steps=[_step("prove_host", "current", False), _step("plan", "todo", False),
               _step("turn_on_observe", "todo", False)],
        complete=False, next_step="prove_host", explore=False, proven=0)}
    out = _screen(payload, r"""
out.prove = [text(scard("prove_host")), buttons(scard("prove_host"))];
out.plan = buttons(scard("plan")); out.turn = buttons(scard("turn_on_observe"));
out.calls = calls;
// clicking the current step's link navigates to Assets (pure nav — no write)
scard("prove_host").querySelector("button").click(); out.navs = navs;
""")
    assert "Connect a host" in out["prove"][0] and "Prove you control a host in Assets" in out["prove"][0]
    assert out["prove"][1] == ["Go to Assets"]                                  # exactly one nav link on the current step
    assert out["plan"] == [] and out["turn"] == []                             # later steps carry no button
    assert out["calls"] == [["GET", "api/customer/monitoring/onboarding"]]     # it reads ONLY the onboarding read
    assert out["navs"] == ["#/assets"]                                          # the link navigates, nothing written


def test_the_plan_step_links_to_billing_and_turn_on_links_to_monitoring():
    plan_payload = {"org_id": "o", "can_manage": True, "journey": _journey(
        steps=[_step("prove_host", "done", True), _step("plan", "current", False),
               _step("turn_on_observe", "todo", False)],
        complete=False, next_step="plan", explore=False, has_plan=False)}
    out = _screen(plan_payload, 'out.plan = buttons(scard("plan"));')
    assert out["plan"] == ["Go to Billing"]
    turn_payload = {"org_id": "o", "can_manage": True, "journey": _journey(
        steps=[_step("prove_host", "done", True), _step("plan", "done", True),
               _step("turn_on_observe", "current", False)],
        complete=False, next_step="turn_on_observe", explore=False)}
    out = _screen(turn_payload, 'out.turn = buttons(scard("turn_on_observe"));')
    assert out["turn"] == ["Go to Monitoring"]


def test_a_complete_journey_shows_the_banner_and_the_two_explore_links_and_no_step_button():
    payload = {"org_id": "o", "can_manage": True, "journey": _journey(
        steps=[_step("prove_host", "done", True), _step("plan", "done", True),
               _step("turn_on_observe", "done", True)],
        complete=True, next_step=None, explore=True, active=1)}
    out = _screen(payload, r"""
out.banner = text(document.querySelector("div.cust-mon-onboard-complete"));
out.explore = buttons(document.querySelector("div.cust-mon-onboard-explore"));
out.stepButtons = document.querySelectorAll("div.cust-mon-onboard-card").map(c => buttons(c).length);
// the explore links navigate to the AS-4b preview and the AS-27b control (pure nav)
document.querySelector("div.cust-mon-onboard-explore-links").querySelectorAll("button").forEach(b => b.click());
out.navs = navs;
""")
    assert "Your workspace is monitored" in out["banner"]
    assert out["explore"] == ["See what enforcing would add", "Review defense control"]
    assert out["stepButtons"] == [0, 0, 0]                                      # every step done => no step button
    assert out["navs"] == ["#/monitoring/preview", "#/monitoring/control"]


def test_a_read_only_role_sees_an_honest_note_never_the_steps():
    out = _screen({"org_id": "o", "can_manage": False, "journey": None}, r"""
out.text = text(document.querySelector("#mon-onboarding-body"));
out.cards = document.querySelectorAll("div.cust-mon-onboard-card").length;
""")
    assert "Only the founder or an admin" in out["text"] and out["cards"] == 0


def test_a_failed_read_shows_fixed_copy_never_the_raw_server_error():
    out = _node("server = " + json.dumps({
        "GET api/customer/monitoring/onboarding": {"status": 500, "data": {"error": "stack trace: KABOOM at line 7"}}})
        + ";" + _SCREEN + "await flush();\n"
        "out.text = text(document.querySelector('#mon-onboarding-body'));")
    assert "Could not load onboarding just now" in out["text"]
    assert "KABOOM" not in out["text"] and "stack" not in out["text"]           # the raw server error is never echoed


# --- feature-off: the route is the home screen, no render, no read -------------------------------------------
def test_with_the_onboarding_flag_off_the_route_is_the_home_screen_and_reads_nothing():
    src = _src()
    # routeShown hides the route when the flag is off; the ROUTES entry falls back to the dashboard (not the view).
    assert ('"#/monitoring/onboarding": function () { return authed() ? (AEGIS_ONBOARDING_ON ? '
            'viewMonitoringOnboarding()') in src
    # monitoring on, onboarding off => AEGIS_ONBOARDING_ON false
    out = _node("out.shown = routeShown('#/monitoring/onboarding'); out.flag = AEGIS_ONBOARDING_ON; out.calls = calls;",
                mon="1", onb="0")
    assert out["flag"] is False and out["shown"] is False and out["calls"] == []


def test_the_onboarding_flag_requires_the_monitoring_flag_too():
    # the strict second gate: with monitoring off, AEGIS_ONBOARDING_ON is false even if its own flag is on
    out = _node("out.flag = AEGIS_ONBOARDING_ON; out.shown = routeShown('#/monitoring/onboarding');",
                mon="0", onb="1")
    assert out["flag"] is False and out["shown"] is False


# --- the onboarding path invents nothing and writes nothing --------------------------------------------------
def test_the_onboarding_path_is_pure_nav_no_write_no_raw_network():
    src = _src()
    block = "\n".join(_fn(src, n) for n in ("viewMonitoringOnboarding", "monOnboardingBody",
                                            "monOnboardingStepCard", "monOnboardButton"))
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", block)
    assert "postJSON" not in code                                              # an onboarding view never writes
    for banned in ("fetch(", "XMLHttpRequest", "sendBeacon", "location.href", "window.open", "innerHTML"):
        assert banned not in code, banned
