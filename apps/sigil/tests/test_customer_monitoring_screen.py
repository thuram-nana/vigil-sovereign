"""C4 — the customer app's Monitoring (AEGIS) screen and the AEGIS plans on Billing, executed under node.

* The edge writes data-monitoring="1" into the page only while VIGIL_CUSTOMER_MONITORING_ENABLED is on — the switch
  that also serves the monitoring routes, so the screen and its API are never out of step — and "0" otherwise: the
  same bytes for every off value, and the value counts in the build id.
* With it off the app is unchanged: no Monitoring tab, #/monitoring is the home screen exactly as an unknown route, no
  monitoring call, no timer, and the guide offers no "Go to Monitoring".
* With it on, the screen shows only what the server sent: a manager (the founder or an admin, as the server decides)
  sees the AEGIS plan, the hosts with a current proof and their state, "Turn on Observe" (and "Turn on Respond" only
  when the plan includes it, only on a verified host and only while the plan has a free host), "Switch to …" and
  "Turn off", which asks in place before anything is sent; anyone else sees the monitored hosts and an honest card.
  A 401 {step_up_required} gets an honest message and changes nothing. Events are listed newest first with no
  internal field, and refresh every 30 s only while the screen is shown, signed in and visible.
* Billing renders an AEGIS plan offer as a monitoring plan ("AEGIS Observe, 1 host — monthly: …", never credits), and
  a plan is hidden only by a plan of its OWN kind: a credit plan never hides an AEGIS plan, nor the reverse.

app.js's own functions are extracted verbatim and run on the customer UI kit (ui.js) with a minimal DOM.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the app ignores the page flag / the tab or the route is not gated  -> test_with_the_flag_off_the_app_is_unchanged
  * the edge always writes "1"                       -> test_the_edge_writes_the_monitoring_flag_into_the_page
  * Respond offered without a respond plan           -> test_a_manager_sees_the_plan_the_hosts_and_what_each_can_do
  * the free-host check dropped                      -> test_a_manager_sees_the_plan_the_hosts_and_what_each_can_do
  * actions shown to a role that cannot manage       -> test_a_role_that_cannot_manage_sees_monitoring_read_only
  * turn off sent without the confirm                -> test_turn_off_asks_first_and_keep_monitoring_sends_nothing
  * the step-up answer treated as a sign-out         -> test_a_fresh_second_factor_is_asked_for_honestly
  * an internal event field rendered / not newest first -> test_events_are_newest_first_with_nothing_internal
  * the poll keeps running off screen / hidden / signed out, or a stale answer lands
                                                     -> test_the_events_refresh_only_while_the_screen_is_in_view
  * offerLine prints an AEGIS plan as credits        -> test_billing_renders_an_aegis_plan_as_a_monitoring_plan
  * one plan kind hides the other                    -> test_one_plan_kind_never_hides_the_other
  * "Go to Monitoring" on a deployment without it    -> test_the_guide_never_sends_anyone_to_a_hidden_screen
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from test_customer_onboarding import _need_node, _page_and_build

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS, APP_JS, GUIDE_JS = APP / "ui.js", APP / "app.js", APP / "guide.js"


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(src: str, name: str) -> str:
    """One of app.js's own top-level functions, verbatim: a one-line function (its braces close on its own line), or
    everything through its closing "  }" line."""
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    line = src[i:src.index("\n", i)]
    if line.count("{") and line.count("{") == line.count("}"):
        return line + "\n"
    return src[i:src.index("\n  }\n", i) + 4]


def _var(src: str, name: str) -> str:
    """One of app.js's own module-level `var` statements, verbatim (it may span lines; it ends at a line whose code
    ends with ";", before any trailing comment)."""
    i = src.index(f"\n  var {name} = ") + 1
    lines = []
    for ln in src[i:].split("\n"):
        lines.append(ln)
        if re.search(r";\s*(//.*)?$", ln):
            break
    return "\n".join(lines) + "\n"


# A minimal DOM: elements, text, classes, ids, data-*, attributes, events, and tag/.class/#id/[attr] selectors.
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
const docListeners = {};
globalThis.document = {
  body, documentElement: body, hidden: false,
  createElement: t => new El(t), createTextNode: t => new Text(t),
  querySelector: s => body.querySelector(s), querySelectorAll: s => body.querySelectorAll(s),
  addEventListener: (t, f) => { (docListeners[t] = docListeners[t] || []).push(f); },
  removeEventListener: (t, f) => { docListeners[t] = (docListeners[t] || []).filter(x => x !== f); },
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
globalThis.location = { hash: "#/monitoring" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let renders = 0; function render() { renders++; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
var GUIDE_ON = false;
var SECURITY_ON = false, TEAM_ON = false, LAUNCH_ON = false, CODE_ON = false, CONNECT_ON = false, SETTINGS_ON = false;   // every other page flag: off
var ATTACK_PATH_ON = false, BLIND_VULN_ON = false;   // PR-L (Area 11) flags: off here (shell reads ATTACK_PATH_ON)
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
const timers = { set: [], cleared: [] }; let timerId = 0;
globalThis.setInterval = (fn, ms) => { timerId++; timers.set.push({ id: timerId, fn, ms }); return timerId; };
globalThis.clearInterval = id => { timers.cleared.push(id); };
const tick = () => new Promise(r => setTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
const out = {};
"""

_APP_FUNCS = ("pageFlag", "loadingHolder", "kv", "fmtDate", "err", "clearErr", "here", "isMonitoringOffer",
              "aegisPlanName", "offerLine", "offerShown", "own", "fmtWhen", "viewMonitoring", "monitoringBody",
              "monHostRows", "monActive", "monPlanCard", "monPlanHelp", "monHostCard", "monActions", "monButton",
              "monConfirmOff", "monTurnOn", "monTurnOff", "monFailed", "monEventsList", "monVisible", "startMonPoll",
              "stopMonPoll", "syncMonPoll", "onMonVisibility", "pollMonEvents", "routeShown")
_APP_VARS = ("API", "TOPUP", "MONITORING_ON", "MON_POLL_MS", "mon", "MON_MODE", "MON_ACTION")


def _harness(flag: str = "1") -> str:
    """The stubbed world plus app.js's own monitoring and billing code, extracted verbatim."""
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


# What the server sends: a manager of a workspace on AEGIS Respond for 5 hosts, monitoring a.example in Observe.
_PE = 1_800_000_000.0
_MANAGER = {"org_id": "org_x", "can_manage": True,
            "grants": [{"host": "a.example", "mode": "observe", "not_before": 1.0, "not_after": _PE, "active": True}],
            "hosts": [{"host": "b.example", "expires_at": _PE + 86400}, {"host": "a.example", "expires_at": _PE}],
            "plan": {"host_slots": 5, "respond": True, "period_end": _PE}}
_EVENTS = {"org_id": "org_x", "events": []}

_SCREEN = r"""
const view = viewMonitoring(); document.body.appendChild(view);
const card = host => document.querySelectorAll("div.card").filter(c => text(c.querySelector("span.host")) === host)[0];
const badge = host => text(card(host).querySelector("span.cust-badge"));
const acts = host => buttons(card(host).querySelector("div.cust-mon-actions"));
"""


def _screen(listing: dict, then: str = "", *, events: "dict | None" = None, extra: "dict | None" = None) -> dict:
    srv = {"GET api/customer/monitoring": {"data": listing},
           "GET api/customer/monitoring/events": {"data": events if events is not None else _EVENTS}}
    srv.update(extra or {})
    return _node(f"server = {json.dumps(srv)};" + _SCREEN + "await flush();\n" + then)


# --- the edge flag ---------------------------------------------------------------------------------------------------
def test_the_edge_writes_the_monitoring_flag_into_the_page(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-monitoring="0"' in off and "__VIGIL_MONITORING__" not in off
    for v in ("0", "", "no", "maybe"):                       # every off value serves the very same page
        monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", v)
        assert _page_and_build(tmp_path / f"c{v or 'empty'}") == (off, build_off), v
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-monitoring="1"' in on and build_on != build_off
    assert on.replace('data-monitoring="1"', 'data-monitoring="0"').replace(build_on, build_off) == off


# --- with the flag off, the app is exactly what it was -------------------------------------------------------------------
_VIEWS = ("viewDashboard", "viewLogin", "viewSignup", "viewRecover", "viewGoogleCode", "viewBilling",
          "viewBillingReturn", "viewInvoices", "viewAssets", "viewAssessments", "viewGuideScreen", "viewMonitoring")


def _wiring(flag: str, script: str) -> dict:
    """app.js's own top bar (shell + navLink) and route table, verbatim, over stub screens that return their name."""
    src = _src()
    i = src.index("  var ROUTES = {")
    table = src[i:src.index("\n  };", i) + 5]
    stubs = ("var SECURITY_ON = false;\nfunction ntfWidget() { return null; }\nasync function doLogout() {}\n"
             "function viewSoon(t) { return \"viewSoon:\" + t; }\n"
             + "\n".join(f"function {v}() {{ return {json.dumps(v)}; }}" for v in _VIEWS))
    return _node(stubs + "\n" + _fn(src, "navLink") + _fn(src, "shell") + table + "\n" + script, flag=flag)


def test_with_the_flag_off_the_app_is_unchanged():
    script = r"""
const links = () => shell(h("div"), "#/").querySelectorAll("button.cust-nav-link").map(b => text(b));
out.links = links();
location.hash = "#/monitoring";
out.route = ROUTES["#/monitoring"]();
out.unknown = ROUTES["#/"]();
who = { authenticated: false }; out.routeSignedOut = ROUTES["#/monitoring"](); who = { authenticated: true, username: "ana" };
out.shown = routeShown("#/monitoring"); out.shownBilling = routeShown("#/billing");
syncMonPoll(); await pollMonEvents(); onMonVisibility();
out.timers = timers.set.length; out.calls = calls;
LISTENER
out.listeners = (docListeners.visibilitychange || []).length;
"""
    src = _src()
    listener = re.search(r"^  if \(MONITORING_ON\) \{ document\.addEventListener\(\"visibilitychange\", "
                         r"onMonVisibility\); \}$", src, re.M)
    assert listener, "app.js no longer registers the events refresh on the page's visibility (behind the flag)"
    script = script.replace("LISTENER", listener.group(0))
    for flag in ("0", "", "__VIGIL_MONITORING__"):
        off = _wiring(flag, script)
        assert off["links"] == ["Overview", "Billing", "Invoices", "Assets", "Assessments", "Team", "Sign out (ana)"], flag
        assert off["route"] == off["unknown"] == "viewDashboard" and off["routeSignedOut"] == "viewLogin", flag
        assert off["shown"] is False and off["shownBilling"] is True, flag
        assert off["timers"] == 0 and off["calls"] == [] and off["listeners"] == 0, flag   # no poll, call or listener
    on = _wiring("1", script)
    assert on["links"] == ["Overview", "Billing", "Invoices", "Assets", "Assessments", "Team", "Monitoring",
                           "Sign out (ana)"]
    assert on["route"] == "viewMonitoring" and on["routeSignedOut"] == "viewLogin" and on["shown"] is True
    assert on["listeners"] == 1
    assert '.concat(MONITORING_ON ? [navLink("Monitoring", "#/monitoring")] : [])' in src
    render = _fn(src, "render")
    assert render.index("syncNtf();") < render.index("syncMonPoll();") < render.index("maybeOpenTour();")


# --- the screen ----------------------------------------------------------------------------------------------------------------
def test_a_manager_sees_the_plan_the_hosts_and_what_each_can_do():
    out = _screen(_MANAGER, r"""
out.plan = document.querySelectorAll("div.cust-kv").map(e => text(e));
out.hosts = document.querySelectorAll("span.host").map(e => text(e));
out.a = [badge("a.example"), acts("a.example")]; out.b = [badge("b.example"), acts("b.example")];
out.calls = calls;
""")
    assert out["hosts"] == ["a.example", "b.example"]                     # every host, sorted, shown once
    assert "PlanAEGIS Respond, 5 hosts" in out["plan"] and "Hosts monitored1 of 5" in out["plan"]
    assert out["a"] == ["Monitoring · Observe", ["Switch to Respond", "Turn off"]]
    assert out["b"] == ["Not monitored", ["Turn on Observe", "Turn on Respond"]]
    assert out["calls"] == [["GET", "api/customer/monitoring"], ["GET", "api/customer/monitoring/events"]]
    # an Observe-only plan never offers Respond (on a new host or as a switch)
    observe = json.loads(json.dumps(_MANAGER))
    observe["plan"] = {"host_slots": 5, "respond": False, "period_end": _PE}
    out = _screen(observe, 'out.a = acts("a.example"); out.b = acts("b.example");')
    assert out == {"a": ["Turn off"], "b": ["Turn on Observe"]}
    # a full plan offers no Turn on, says why, and still lets a monitored host switch or stop
    full = json.loads(json.dumps(_MANAGER))
    full["plan"]["host_slots"] = 1
    out = _screen(full, 'out.a = acts("a.example"); out.b = acts("b.example"); '
                        'out.why = text(card("b.example").querySelector("div.cust-mon-actions"));')
    assert out["a"] == ["Switch to Respond", "Turn off"] and out["b"] == []
    assert "Every host your plan covers is monitored" in out["why"]
    # a host whose proof is not current (monitored before, its proof since expired) cannot be turned on
    lapsed = {"org_id": "org_x", "can_manage": True, "hosts": [], "plan": _MANAGER["plan"],
              "grants": [{"host": "c.example", "mode": "block", "not_before": 1.0, "not_after": 2.0, "active": False}]}
    out = _screen(lapsed, 'out.c = [badge("c.example"), acts("c.example"), text(card("c.example"))];')
    assert out["c"][0] == "Not monitored" and out["c"][1] == []
    assert "has ended" in out["c"][2] and "verify it again in Assets" in out["c"][2]


def test_without_a_plan_or_a_host_the_screen_says_what_is_missing():
    no_plan = dict(_MANAGER, plan=None)
    out = _screen(no_plan, r"""
out.a = acts("a.example"); out.b = acts("b.example"); out.body = text(document.querySelector("#mon-body"));
out.help = text(document.querySelector("#mon-plan-help")); out.go = buttons(document.querySelector("#mon-plan-help"));
""")
    assert out["b"] == [] and out["a"] == ["Turn off"]          # nothing to turn on; what runs can still be stopped
    assert "This workspace has no active AEGIS plan, so monitoring cannot be turned on yet." in out["body"]
    # Billing does not offer one (checkout off, or no AEGIS plan for sale): no button to a screen that cannot help
    assert "not sold in the app yet" in out["help"] and "contact VIGIL" in out["help"] and out["go"] == []
    # once Billing really offers an AEGIS plan, the screen sends the manager there (and only then)
    aegis = {"price_id": "vigil_aegis_observe_1h_monthly", "kind": "subscription_active", "monitor_hosts": 1,
             "monitor_respond": False, "period_days": 30.0}
    out = _screen(no_plan, r"""
out.go = buttons(document.querySelector("#mon-plan-help"));
button(document.querySelector("#mon-plan-help"), "Go to Billing").click(); out.navs = navs;
""", extra={"GET api/customer/billing/offers": {"data": {"offers": [aegis]}}})
    assert out["go"] == ["Go to Billing"] and out["navs"] == ["#/billing"]
    out = _screen({"org_id": "org_x", "can_manage": True, "grants": [], "hosts": [], "plan": _MANAGER["plan"]},
                  'out.body = text(document.querySelector("#mon-body"));')
    assert "No host of this workspace has a current proof of control" in out["body"]


def test_a_role_that_cannot_manage_sees_monitoring_read_only():
    viewer = {"org_id": "org_x", "can_manage": False,
              "grants": [{"host": "a.example", "mode": "block", "not_before": 1.0, "not_after": _PE, "active": True}]}
    out = _screen(viewer, r"""
out.body = text(document.querySelector("#mon-body"));
out.buttons = buttons(document.querySelector("#mon-body")); out.badge = badge("a.example");
""")
    assert "Only the founder or an admin of this workspace can turn monitoring on or off" in out["body"]
    assert out["buttons"] == [] and out["badge"] == "Monitoring · Respond"
    assert "AEGIS plan" not in out["body"] and "Proof expires" not in out["body"]
    out = _screen({"org_id": "org_x", "can_manage": False, "grants": []}, 'out.body = text(document.querySelector("#mon-body"));')
    assert "No host of this workspace is monitored" in out["body"]


def test_turning_monitoring_on_sends_only_the_listed_host_and_a_mode():
    out = _screen(_MANAGER, r"""
button(card("b.example"), "Turn on Respond").click(); await flush();
out.post = calls[calls.length - 1]; out.toasts = toasts; out.renders = renders;
button(card("a.example"), "Switch to Respond").click(); await flush();
out.switch = calls[calls.length - 1];
""", extra={"POST api/customer/monitoring/authorize": {"data": {"ok": True}}})
    assert out["post"] == ["POST", "api/customer/monitoring/authorize", {"host": "b.example", "mode": "block"}]
    assert out["switch"] == ["POST", "api/customer/monitoring/authorize", {"host": "a.example", "mode": "block"}]
    assert out["toasts"][0] == "Monitoring is on for b.example (Respond)." and out["renders"] == 1


def test_turn_off_asks_first_and_keep_monitoring_sends_nothing():
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
    assert out["restored"] == ["Switch to Respond", "Turn off"]
    assert out["post"] == ["POST", "api/customer/monitoring/revoke", {"host": "a.example"}]
    assert out["toasts"] == ["Monitoring is off for a.example."] and out["renders"] == 1


def test_a_fresh_second_factor_is_asked_for_honestly():
    step_up = {"status": 401, "data": {"error": "a fresh second factor is required", "step_up_required": True}}
    out = _screen(_MANAGER, r"""
const b = button(card("b.example"), "Turn on Observe"); b.click(); await flush();
out.errs = errs; out.navs = navs; out.who = whoRefreshes; out.renders = renders; out.disabled = b.disabled;
""", extra={"POST api/customer/monitoring/authorize": step_up})
    assert len(out["errs"]) == 1 and "fresh second-factor check" in out["errs"][0]
    assert "Nothing was changed" in out["errs"][0]
    assert out["navs"] == [] and out["who"] == 0 and out["renders"] == 0 and out["disabled"] is False
    # any other refusal is the server's own words; a lost session goes back to sign-in
    denied = {"status": 403, "data": {"error": "denied: no free protected-host slot on the monitoring plan"}}
    out = _screen(_MANAGER, 'button(card("b.example"), "Turn on Observe").click(); await flush(); out.errs = errs;',
                  extra={"POST api/customer/monitoring/authorize": denied})
    assert out["errs"] == ["Monitoring was not changed: denied: no free protected-host slot on the monitoring plan"]
    out = _screen(_MANAGER, r"""
button(card("a.example"), "Turn off").click(); await flush(); button(card("a.example"), "Yes, turn off").click();
await flush(); out.navs = navs; out.who = whoRefreshes;
""", extra={"POST api/customer/monitoring/revoke": {"status": 401, "data": {"error": "login required"}}})
    assert out["navs"] == ["#/login"] and out["who"] == 1


_MARKERS = {"seq": 9100001, "report_id": "RID-9100002", "certificate_sha256": "CERT-9100003",
            "org_id": "ORG-9100004", "source_class": "SRC-9100005", "provenance_tier": "TIER-9100006",
            "confidence": 0.9100007}


def test_events_are_newest_first_with_nothing_internal():
    evs = [dict(_MARKERS, host="a.example", ts=1_700_000_000.0, decision="lead", attack_class="path_traversal",
                action="observe"),
           dict(_MARKERS, host="b.example", ts=1_700_000_600.0, decision="confirmed", attack_class="sqli",
                action="block"),
           dict(_MARKERS, host="a.example", ts=1_700_000_300.0, decision="confirmed", attack_class="xss",
                action="constructor")]
    out = _screen(_MANAGER, r"""
const t = document.querySelector("#mon-events");
out.head = t.querySelectorAll("th").map(e => text(e));
out.rows = t.querySelector("tbody").children.map(r => r.children.map(c => text(c)));
out.all = text(t);
""", events={"org_id": "org_x", "events": evs})
    assert out["head"] == ["When", "Host", "Attack", "Result", "AEGIS action"]
    assert out["rows"] == [["2023-11-14 22:23 UTC", "b.example", "sqli", "Confirmed", "Blocked"],
                           ["2023-11-14 22:18 UTC", "a.example", "xss", "Confirmed", "—"],
                           ["2023-11-14 22:13 UTC", "a.example", "path traversal", "Not confirmed", "Observed"]]
    for v in _MARKERS.values():
        assert str(v) not in out["all"], v
    out = _screen(_MANAGER, 'out.empty = text(document.querySelector("#mon-events"));')
    assert out["empty"].startswith("No events yet.")


def test_the_events_refresh_only_while_the_screen_is_in_view():
    out = _screen(_MANAGER, r"""
syncMonPoll();
out.started = timers.set.map(t => t.ms);
const polls = () => calls.filter(c => c[1] === "api/customer/monitoring/events").length;
const p0 = polls(); timers.set[0].fn(); await flush(); out.ticked = polls() - p0;
// hidden: it stops; visible again: it restarts and refreshes at once
document.hidden = true; onMonVisibility(); out.hiddenTimer = mon.timer; const p1 = polls();
timers.set[0].fn(); await flush(); out.whileHidden = polls() - p1;
document.hidden = false; onMonVisibility(); await flush(); out.back = [mon.timer !== null, polls() - p1];
// another screen: it stops
location.hash = "#/billing"; syncMonPoll(); out.away = mon.timer;
// a stale answer: the screen is left while a refresh is in flight, so its answer is dropped
location.hash = "#/monitoring"; syncMonPoll();
let release; server["GET api/customer/monitoring/events"] = { wait: new Promise(r => { release = r; }) };
const shownBefore = text(document.querySelector("#mon-events"));
const inflight = pollMonEvents();
location.hash = "#/billing"; syncMonPoll();
release({ events: [{ host: "late.example", ts: 1, decision: "confirmed", attack_class: "sqli", action: "block" }] });
await inflight; await flush();
out.staleDropped = text(document.querySelector("#mon-events")) === shownBefore;
// another account signs in on this browser while ana's refresh is in flight: ana's answer never reaches ben's screen
location.hash = "#/monitoring"; syncMonPoll();
server["GET api/customer/monitoring/events"] = { wait: new Promise(r => { release = r; }) };
const anaPoll = pollMonEvents();
who = { authenticated: false }; syncMonPoll();          // ana signs out
who = { authenticated: true, username: "ben" }; syncMonPoll();
release({ events: [{ host: "ana-only.example", ts: 2, decision: "confirmed", attack_class: "sqli", action: "block" }] });
await anaPoll; await flush();
out.crossAccount = text(document.querySelector("#mon-events")).indexOf("ana-only.example") >= 0;
// signed out: it stops; a 401 on a refresh stops it and asks who is signed in
location.hash = "#/monitoring"; syncMonPoll(); who = { authenticated: false }; syncMonPoll(); out.signedOut = mon.timer;
who = { authenticated: true, username: "ana" }; syncMonPoll();
server["GET api/customer/monitoring/events"] = { status: 401, data: { error: "login required" } };
await pollMonEvents(); out.after401 = [mon.timer, whoRefreshes];
""")
    assert out["started"] == [30000] and out["ticked"] == 1
    assert out["hiddenTimer"] is None and out["whileHidden"] == 0
    assert out["back"] == [True, 1]
    assert out["away"] is None and out["staleDropped"] is True and out["crossAccount"] is False
    assert out["signedOut"] is None and out["after401"] == [None, 1]


def test_the_screen_loads_honestly():
    out = _node(r"""
let release; server = { "GET api/customer/monitoring": { wait: new Promise(r => { release = r; }) } };
const view = viewMonitoring(); document.body.appendChild(view);
out.loading = text(view.querySelector("#mon-body")); out.title = text(view.querySelector("h2"));
location.hash = "#/billing";                      // left before the answer came back: nothing is mounted
release({ org_id: "o", can_manage: false, grants: [] }); await flush();
out.afterLeaving = text(view.querySelector("#mon-body"));
location.hash = "#/monitoring";
server = { "GET api/customer/monitoring": { status: 500, data: { error: "provision failed" } } };
const v2 = viewMonitoring(); document.body.appendChild(v2); await flush();
out.failed = text(v2.querySelector("#mon-body"));
server = { "GET api/customer/monitoring": { status: 401, data: { error: "login required" } } };
const v3 = viewMonitoring(); document.body.appendChild(v3); await flush();
out.navs = navs; out.who = whoRefreshes;
""")
    assert out["title"] == "Monitoring" and out["loading"] == "Loading…" and out["afterLeaving"] == "Loading…"
    assert out["failed"] == "Could not load Monitoring: provision failed"
    assert out["navs"] == ["#/login"] and out["who"] == 1


# --- Billing ------------------------------------------------------------------------------------------------------------
def test_billing_renders_an_aegis_plan_as_a_monitoring_plan(monkeypatch):
    from sigil.governor import catalog
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    plans = catalog.plans()                                    # the owner catalog's own public entries
    assert {p["price_id"] for p in plans} >= set(catalog.monitoring_price_ids())
    out = _node(f"const plans = {json.dumps(plans)};" + r"""
out.lines = plans.map(p => [p.price_id, isMonitoringOffer(p), offerLine(p)]);
""")
    lines = {pid: (mon, line) for pid, mon, line in out["lines"]}
    assert lines["vigil_aegis_observe_1h_monthly"] == (
        True, "AEGIS Observe, 1 host — monthly: watches traffic and reports attacks")
    assert lines["vigil_aegis_respond_5h_monthly"] == (
        True, "AEGIS Respond, 5 hosts — monthly: watches traffic, reports attacks and can block them")
    for pid in catalog.monitoring_price_ids():
        assert lines[pid][0] is True and "credit" not in lines[pid][1].lower(), pid
    assert lines["vigil_pro_monthly"] == (False, "Plan: 12000 credits every 30 days")     # credit plans unchanged
    assert lines["vigil_topup_1k"] == (False, "1000 credits")


_BUY = r"""
const run = async (payload) => {
  server = { "GET api/customer/billing/offers": { data: payload } };
  location.hash = "#/billing";
  const holder = buySection(); document.body.appendChild(holder); await flush();
  const names = holder.querySelectorAll("strong").map(e => text(e));
  holder.remove();
  return names;
};
"""
_TOP = {"price_id": "t1", "kind": "topup_purchased", "name": "Top-up", "credits": 1000, "amount_minor": 1000,
        "currency": "USD"}
_CREDIT = {"price_id": "c1", "kind": "subscription_active", "name": "Pro (monthly)", "allotment": 6000,
           "period_days": 30.0, "amount_minor": 9900, "currency": "USD"}
_AEGIS = {"price_id": "m1", "kind": "subscription_active", "name": "AEGIS Observe, 1 host (monthly)", "allotment": 0,
          "period_days": 30.0, "monitor_hosts": 1, "monitor_respond": False, "amount_minor": 4900, "currency": "USD"}


def _buy(payloads: dict) -> dict:
    src = _src()
    code = "\n".join(_fn(src, n) for n in ("buySection", "startCheckout", "money", "isCheckoutUrl"))
    return _node(code + _BUY + "".join(f"out[{json.dumps(k)}] = await run({json.dumps(v)});\n"
                                        for k, v in payloads.items()))


def test_one_plan_kind_never_hides_the_other():
    offers = [_TOP, _CREDIT, _AEGIS]
    out = _buy({"none": {"offers": offers},
                "credit_live": {"offers": offers, "has_active_plan": True},
                "credit_pending": {"offers": offers, "plan_checkout_pending": True},
                "aegis_live": {"offers": offers, "has_monitoring_plan": True},
                "aegis_pending": {"offers": offers, "monitoring_checkout_pending": True},
                "both": {"offers": offers, "has_active_plan": True, "has_monitoring_plan": True}})
    names = ["Top-up", "Pro (monthly)", "AEGIS Observe, 1 host (monthly)"]
    assert out["none"] == names
    assert out["credit_live"] == out["credit_pending"] == ["Top-up", "AEGIS Observe, 1 host (monthly)"]
    assert out["aegis_live"] == out["aegis_pending"] == ["Top-up", "Pro (monthly)"]
    assert out["both"] == ["Top-up"]


def test_without_aegis_offers_the_buy_list_is_what_it_was():
    """With the monitoring flag off the server offers no AEGIS plan, so for every payload it can then send the list is
    exactly the one the previous filter showed: top-ups always, credit plans unless a credit plan is live or being
    checked out."""
    cases = {}
    for live in (False, True):
        for pending in (False, True):
            cases[f"{live}-{pending}"] = {"offers": [_TOP, _CREDIT], "has_active_plan": live,
                                          "plan_checkout_pending": pending}
    out = _buy(cases)
    for k, names in out.items():
        live, pending = (s == "True" for s in k.split("-"))
        assert names == (["Top-up"] if (live or pending) else ["Top-up", "Pro (monthly)"]), k


# --- the guide -----------------------------------------------------------------------------------------------------------
def _aegis_chapter() -> dict:
    prog = (_DOM + f"\nrequire({json.dumps(str(UI_JS))});\nrequire({json.dumps(str(GUIDE_JS))});\n"
            "process.stdout.write(JSON.stringify(window.VIGIL_GUIDE.CHAPTERS.filter(c => c.id === 'aegis')[0]));")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_the_guide_names_the_screens_real_buttons():
    """The AEGIS chapter walks through the Monitoring screen with the labels the screen really shows: every action
    button of the screen is named in the chapter (except the confirm's way back), and the tab is the one in the top bar."""
    src = _src()
    labels = set(re.findall(r'monButton\("([^"]+)"', src))
    assert labels == {"Turn on Observe", "Turn on Respond", "Switch to Observe", "Switch to Respond", "Turn off",
                      "Yes, turn off", "Keep monitoring", "Go to Billing"}
    ch = _aegis_chapter()
    steps = {s["id"]: s for s in ch["steps"]}
    told = "\n".join(c for s in ch["steps"] for c in s["clicks"])
    for label in labels - {"Keep monitoring", "Go to Billing"}:
        assert label in told, label
    assert 'navLink("Monitoring", "#/monitoring")' in src and "Select Monitoring in the top bar" in told
    assert [steps[k]["route"] for k in ("plans", "monitor", "events", "manage")] == \
        ["#/billing", "#/monitoring", "#/monitoring", "#/monitoring"]
    assert any("Turn on Respond appears only when your plan includes Respond" in c for c in steps["monitor"]["clicks"])
    assert any("newest first" in c for c in steps["events"]["clicks"])


def test_the_guide_never_sends_anyone_to_a_hidden_screen():
    def go_buttons(shown: str) -> dict:
        prog = (_DOM + f"\nrequire({json.dumps(str(UI_JS))});\nrequire({json.dumps(str(GUIDE_JS))});\n" + r"""
const G = window.VIGIL_GUIDE; const h = window.VUI.h; const out = {}; const navs = [];
const g = G.viewGuide({ h, username: "ana", storage: null, nav: r => navs.push(r), chapter: "aegis", shown: SHOWN });
document.body.appendChild(g);
out.go = g.querySelectorAll("button").map(b => b.textContent).filter(t => t.indexOf("Go to ") === 0);
const m = g.querySelectorAll("button").filter(b => b.textContent === "Go to Monitoring")[0];
if (m) { m.click(); }
out.navs = navs;
process.stdout.write(JSON.stringify(out));
""").replace("SHOWN", shown)
        r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)

    hidden = go_buttons('r => r !== "#/monitoring"')
    assert hidden == {"go": ["Go to Billing"], "navs": []}                 # only the plans step's Billing
    shown = go_buttons("() => true")
    assert shown["go"] == ["Go to Billing"] + ["Go to Monitoring"] * 3 and shown["navs"] == ["#/monitoring"]
    legacy = go_buttons("undefined")                                       # a caller that says nothing: every route
    assert legacy["go"] == shown["go"]
    # app.js tells the guide which screens it hides
    src = _src()
    assert "shown: routeShown" in _fn(src, "viewGuideScreen")
    assert re.search(r'function routeShown\(route\) \{ return \(route !== "#/monitoring" \|\| MONITORING_ON\) '
                     r'&& \(route !== "#/code" \|\| CODE_ON\) && \(route !== "#/connect" \|\| CONNECT_ON\) '
                     r'&& \(route !== "#/fix-first" \|\| POSTURE_ON\)'
                     r'( && [^;]*)?; \}', src)   # (PR-G appends Plans/Reports after PR-B's Fix first)
    assert re.search(r'function routeShown\(route\) \{[^\n]* && \(route !== "#/settings" \|\| SETTINGS_ON\); \}',
                     src)   # (lgS1 appends Settings last)
