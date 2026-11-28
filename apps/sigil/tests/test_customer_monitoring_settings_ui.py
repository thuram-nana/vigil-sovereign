"""AS-2k — the customer app's Monitoring SETTINGS screen (#/monitoring/settings), executed under node.

AS-2k is a THIN settings surface over the SAME reads/writes the Monitoring screen (AS-2f/AS-2g) already uses:
GET api/customer/monitoring for the SESSION workspace's per-(org, host) authorities, and the EXISTING
monitoring/authorize + monitoring/revoke writes. It mints no new authority and opens no new edge route. Where
#/monitoring turns monitoring on and picks Observe/Respond, this screen CONFIGURES an already-armed authority: it
shows each monitored host's armed telemetry window and lets a manager SHORTEN that window (re-arm, same mode, a
shorter window the sovereign caps) or turn the host off.

* It is gated by the SAME VIGIL_CUSTOMER_MONITORING_ENABLED as #/monitoring: off, #/monitoring/settings is the home
  screen exactly as any unknown route, and the Settings hub shows no link to it (routeShown -> MONITORING_ON).
* A manager (the server decides can_manage) sees each armed host, its mode, armed-until / armed-since, a "Shorten
  window" control and "Turn off"; anyone else sees it read-only. Honest empties ("No host is monitored yet.").
* Shorten sends monitoring/authorize {host, mode, window_s} in the host's CURRENT mode — never an org field; a
  non-positive / blank window changes nothing. Turn off asks first, then sends monitoring/revoke {host}.
* A 401 {step_up_required} is honest and changes nothing; a lost session goes back to sign-in.
* The screen reaches the network ONLY through /monitoring, /monitoring/authorize and /monitoring/revoke (source
  scan) — it forks no new route and names no body org_id.

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
              "monSettingsActions", "monShortenWindow", "monSettingsConfirmOff", "monSettingsTurnOff", "routeShown")
_APP_VARS = ("API", "MONITORING_ON", "MON_MODE", "MON_DAY_S")


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


# What the server sends: a manager of a workspace monitoring a.example (Observe) and b.example (Respond), with one
# host whose grant has ended (c.example — not active), which the settings screen does not list.
_PE = 1_800_000_000.0
_MANAGER = {"org_id": "org_x", "can_manage": True, "grants": [
    {"host": "b.example", "mode": "block", "not_before": _PE - 86400, "not_after": _PE, "active": True},
    {"host": "a.example", "mode": "observe", "not_before": _PE - 3600, "not_after": _PE, "active": True},
    {"host": "c.example", "mode": "observe", "not_before": 1.0, "not_after": 2.0, "active": False}]}


_SCREEN = r"""
const view = viewMonitoringSettings(); document.body.appendChild(view);
const card = host => document.querySelectorAll("div.cust-mon-settings-card").filter(c => c.dataset.host === host)[0];
const acts = host => buttons(card(host).querySelector("div.cust-mon-actions"));
"""


def _screen(listing: dict, then: str = "", *, extra: "dict | None" = None) -> dict:
    srv = {"GET api/customer/monitoring": {"data": listing}}
    srv.update(extra or {})
    return _node(f"server = {json.dumps(srv)};" + _SCREEN + "await flush();\n" + then)


# --- the screen -----------------------------------------------------------------------------------------------------
def test_a_manager_sees_each_armed_host_and_its_window():
    out = _screen(_MANAGER, r"""
out.hosts = document.querySelectorAll("span.host").map(e => text(e));
out.badges = document.querySelectorAll("span.cust-badge").map(e => text(e));
out.kvs = document.querySelectorAll("div.cust-kv").map(e => text(e));
out.a = acts("a.example"); out.b = acts("b.example");
out.hasWindowInput = card("a.example").querySelectorAll("input.cust-mon-window").length;
out.gone = card("c.example") == null;                 // a grant that has ended is not listed
out.calls = calls;
""")
    assert out["hosts"] == ["a.example", "b.example"]                    # only ARMED hosts, sorted, once each
    assert out["badges"] == ["Monitoring · Observe", "Monitoring · Respond"]
    assert out["a"] == ["Shorten window", "Turn off"] and out["b"] == ["Shorten window", "Turn off"]
    assert out["hasWindowInput"] == 1 and out["gone"] is True
    assert "Armed until" in " ".join(out["kvs"]) and "Armed since" in " ".join(out["kvs"])
    # the screen reads ONLY the monitoring list — it opens no new route and never fires the events poll here
    assert out["calls"] == [["GET", "api/customer/monitoring"]]


def test_shortening_a_window_sends_authorize_in_the_current_mode_with_window_s():
    out = _screen(_MANAGER, r"""
const inp = card("b.example").querySelector("input.cust-mon-window"); inp.value = "3";
button(card("b.example"), "Shorten window").click(); await flush();
out.post = calls[calls.length - 1]; out.toasts = toasts; out.renders = renders;
""", extra={"POST api/customer/monitoring/authorize": {"data": {"ok": True}}})
    # the host's CURRENT mode (block) is re-sent with the shorter window in SECONDS (3 days); no org field is carried
    assert out["post"] == ["POST", "api/customer/monitoring/authorize",
                           {"host": "b.example", "mode": "block", "window_s": 3 * 86400}]
    assert "org_id" not in out["post"][2]
    assert out["toasts"] == ["The armed window for b.example was shortened."] and out["renders"] == 1


def test_a_blank_or_non_positive_window_changes_nothing():
    out = _screen(_MANAGER, r"""
const before = calls.length;
button(card("a.example"), "Shorten window").click(); await flush();     // blank input
out.blank = [errs.slice(), calls.length - before];
card("a.example").querySelector("input.cust-mon-window").value = "0";
button(card("a.example"), "Shorten window").click(); await flush();     // zero
card("a.example").querySelector("input.cust-mon-window").value = "-5";
button(card("a.example"), "Shorten window").click(); await flush();     // negative
card("a.example").querySelector("input.cust-mon-window").value = "lots";
button(card("a.example"), "Shorten window").click(); await flush();     // not a number
out.sent = calls.length - before; out.errs = errs.length;
""", extra={"POST api/customer/monitoring/authorize": {"data": {"ok": True}}})
    assert out["blank"][1] == 0 and "positive number of days" in out["blank"][0][0]
    assert out["sent"] == 0 and out["errs"] == 4                         # nothing sent; each try said why


def test_turn_off_asks_first_then_revokes_and_keep_sends_nothing():
    out = _screen(_MANAGER, r"""
const before = calls.length;
button(card("a.example"), "Turn off").click(); await flush();
out.asked = acts("a.example"); out.question = text(card("a.example").querySelector("div.cust-mon-confirm"));
out.sentWhileAsking = calls.length - before;
button(card("a.example"), "Keep monitoring").click(); await flush();
out.restored = acts("a.example"); out.sentAfterKeep = calls.length - before;
button(card("a.example"), "Turn off").click(); await flush();
button(card("a.example"), "Yes, turn off").click(); await flush();
out.post = calls[calls.length - 1]; out.toasts = toasts; out.renders = renders;
""", extra={"POST api/customer/monitoring/revoke": {"data": {"revoked": True}}})
    assert out["asked"] == ["Yes, turn off", "Keep monitoring"] and "Stop monitoring a.example?" in out["question"]
    assert out["sentWhileAsking"] == 0 and out["sentAfterKeep"] == 0
    assert out["restored"] == ["Shorten window", "Turn off"]            # Keep monitoring puts the controls back
    assert out["post"] == ["POST", "api/customer/monitoring/revoke", {"host": "a.example"}]
    assert out["toasts"] == ["Monitoring is off for a.example."] and out["renders"] == 1


def test_a_fresh_second_factor_is_asked_for_honestly():
    step_up = {"status": 401, "data": {"error": "a fresh second factor is required", "step_up_required": True}}
    out = _screen(_MANAGER, r"""
const inp = card("b.example").querySelector("input.cust-mon-window"); inp.value = "2";
const b = button(card("b.example"), "Shorten window"); b.click(); await flush();
out.errs = errs; out.navs = navs; out.who = whoRefreshes; out.renders = renders; out.disabled = b.disabled;
""", extra={"POST api/customer/monitoring/authorize": step_up})
    assert len(out["errs"]) == 1 and "fresh second-factor check" in out["errs"][0] and "Nothing was changed" in out["errs"][0]
    assert out["navs"] == [] and out["who"] == 0 and out["renders"] == 0 and out["disabled"] is False
    # any other refusal is the server's own words; a lost session goes back to sign-in
    denied = {"status": 403, "data": {"error": "denied: no free protected-host slot on the monitoring plan"}}
    out = _screen(_MANAGER, r"""
card("b.example").querySelector("input.cust-mon-window").value = "2";
button(card("b.example"), "Shorten window").click(); await flush(); out.errs = errs;
""", extra={"POST api/customer/monitoring/authorize": denied})
    assert out["errs"] == ["Monitoring was not changed: denied: no free protected-host slot on the monitoring plan"]
    out = _screen(_MANAGER, r"""
button(card("a.example"), "Turn off").click(); await flush(); button(card("a.example"), "Yes, turn off").click();
await flush(); out.navs = navs; out.who = whoRefreshes;
""", extra={"POST api/customer/monitoring/revoke": {"status": 401, "data": {"error": "login required"}}})
    assert out["navs"] == ["#/login"] and out["who"] == 1


def test_a_role_that_cannot_manage_sees_it_read_only():
    viewer = {"org_id": "org_x", "can_manage": False,
              "grants": [{"host": "a.example", "mode": "block", "not_before": 1.0, "not_after": _PE, "active": True}]}
    out = _screen(viewer, r"""
out.body = text(document.querySelector("#mon-settings-body"));
out.buttons = buttons(document.querySelector("#mon-settings-body"));
out.inputs = document.querySelectorAll("input.cust-mon-window").length;
out.hosts = document.querySelectorAll("span.host").map(e => text(e));
""")
    assert "Only the founder or an admin of this workspace can change monitoring settings" in out["body"]
    assert out["buttons"] == [] and out["inputs"] == 0 and out["hosts"] == ["a.example"]   # read-only, still listed
    out = _screen({"org_id": "org_x", "can_manage": False, "grants": []},
                  'out.body = text(document.querySelector("#mon-settings-body"));')
    assert "No host of this workspace is monitored." in out["body"]


def test_with_nothing_armed_a_manager_is_told_where_to_turn_it_on():
    out = _screen({"org_id": "org_x", "can_manage": True, "grants": []},
                  'out.body = text(document.querySelector("#mon-settings-body")); out.inputs = document.querySelectorAll("input").length;')
    assert "No host is monitored yet. Turn monitoring on for a host on the Monitoring screen first." in out["body"]
    assert out["inputs"] == 0


def test_the_screen_loads_honestly():
    out = _node(r"""
let release; server = { "GET api/customer/monitoring": { wait: new Promise(r => { release = r; }) } };
const view = viewMonitoringSettings(); document.body.appendChild(view);
out.loading = text(view.querySelector("#mon-settings-body")); out.title = text(view.querySelector("h2"));
location.hash = "#/billing";                       // left before the answer came back: nothing is mounted
release({ org_id: "o", can_manage: true, grants: [] }); await flush();
out.afterLeaving = text(view.querySelector("#mon-settings-body"));
location.hash = "#/monitoring/settings";
server = { "GET api/customer/monitoring": { status: 500, data: { error: "provision failed" } } };
const v2 = viewMonitoringSettings(); document.body.appendChild(v2); await flush();
out.failed = text(v2.querySelector("#mon-settings-body"));
server = { "GET api/customer/monitoring": { status: 401, data: { error: "login required" } } };
const v3 = viewMonitoringSettings(); document.body.appendChild(v3); await flush();
out.navs = navs; out.who = whoRefreshes;
""")
    assert out["title"] == "Monitoring settings" and out["loading"] == "Loading…" and out["afterLeaving"] == "Loading…"
    assert out["failed"] == "Could not load Monitoring settings: provision failed"
    assert out["navs"] == ["#/login"] and out["who"] == 1


# --- the route + the Settings-hub link are gated by the AEGIS monitoring flag --------------------------------------
def test_the_route_and_hub_link_are_behind_the_monitoring_flag():
    src = _src()
    # the ROUTES entry: on -> the settings view; off -> the home screen (byte-identical to an unknown route)
    assert ('"#/monitoring/settings": function () { return authed() ? (MONITORING_ON ? viewMonitoringSettings() '
            ': viewDashboard()) : viewLogin(); }') in src
    # routeShown hides it with the SAME flag, so the guide/hub never link a hidden screen
    assert re.search(r'function routeShown\(route\) \{[^\n]* && \(route !== "#/monitoring/settings" \|\| '
                     r'MONITORING_ON\)[^\n]*; \}', src)
    # the Settings hub links it through settingsLink (which checks routeShown) — on only when monitoring is on
    assert 'settingsLink("Monitoring", "#/monitoring/settings")' in src


def test_the_screen_only_touches_the_existing_monitoring_routes():
    """The settings view forks NO new route and mints no new authority: it reaches the network only through the three
    monitoring paths AS-2f/AS-2g already serve, and never names a body org_id (the edge scopes org from the session)."""
    src = _src()
    block = "\n".join(_fn(src, n) for n in ("viewMonitoringSettings", "monSettingsRows", "monSettingsBody",
                                            "monSettingsCard", "monSettingsActions", "monShortenWindow",
                                            "monSettingsConfirmOff", "monSettingsTurnOff"))
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", block)
    paths = re.findall(r"API \+ \"([^\"]*)\"", code)
    assert sorted(set(paths)) == ["/monitoring", "/monitoring/authorize", "/monitoring/revoke"]
    assert "org_id" not in code                                          # org is the session's, never a body field
    for banned in ("fetch(", "XMLHttpRequest", "sendBeacon", "location.href", "window.open", "innerHTML"):
        assert banned not in code, banned
