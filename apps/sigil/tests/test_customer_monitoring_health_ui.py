"""AS-3d — HOST HEALTH + ACKNOWLEDGE on the customer app's Monitoring screen (#/monitoring), under node.

AS-3d is the UI-chain increment after AS-29 (chain 4a->2f->2g->2k->21a->29->3d). It adds, to the Monitoring screen,
a HOST HEALTH section and a per-viewer ACKNOWLEDGE, both built ENTIRELY over the two reads the screen already makes
(GET api/customer/monitoring for the armed grants + verified hosts, GET api/customer/monitoring/events for the
gateway-reported attacks). It adds NO route, NO write, NO flag and NO new authority.

* HEALTH is honest and grounded: an armed (active) host shows "Watching · <mode>"; a manager's armed host whose
  ownership PROOF is no longer current (not in the server's verified `hosts`) shows "Proof of control lapsed" with the
  honest note that its monitoring cannot be renewed until it is verified again. The events stream is ATTACK reports, not
  a telemetry heartbeat, so "no events" renders "No attacks reported yet" (good), never "telemetry down".
* The LAST REPORT line is a plain fact: when AEGIS last reported on the host and whether that report was confirmed.
* ACKNOWLEDGE is a PER-VIEWER mark-as-seen in THIS browser's storage (namespaced by signed-in user, capped). It makes
  NO server call, updates the card in place, and the next poll shows it seen. A new report_id (a fresh attack) is
  unacknowledged again. With storage off the feature still works (nothing is remembered).
* The health/acknowledge path reaches the network through NO route at all (source scan): acknowledge is purely local.

app.js's own functions are extracted verbatim and run on the customer UI kit (ui.js) with a minimal DOM + a localStorage
stub. The screen's flag-gating, reads and existing controls are pinned by test_customer_monitoring_screen.py and are not
re-asserted here.
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

# The app's world, stubbed. STORAGE is a per-viewer localStorage (the acknowledge set lives here); pass storage="off"
# to boot WITHOUT it, proving the feature degrades gracefully (nothing remembered, but the card still updates).
_WORLD = r"""
document.body.dataset.monitoring = "1";
let who = { authenticated: true, username: "ana" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/monitoring" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let renders = 0; function render() { renders++; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
var GUIDE_ON = false;
var SECURITY_ON = false, TEAM_ON = false, LAUNCH_ON = false, CODE_ON = false, CONNECT_ON = false, SETTINGS_ON = false, PRIVACY_CENTER_ON = false, SELLER_IDENTITY_ON = false, LIVE_ON = false;
var ATTACK_PATH_ON = false, BLIND_VULN_ON = false;
const _ls = {};
if (%(storage)s) {
  globalThis.localStorage = { getItem: k => (k in _ls ? _ls[k] : null),
    setItem: (k, v) => { _ls[k] = String(v); }, removeItem: k => { delete _ls[k]; } };
}
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
const timers = { set: [], cleared: [] }; let timerId = 0;
globalThis.setInterval = (fn, ms) => { timerId++; timers.set.push({ id: timerId, fn, ms }); return timerId; };
globalThis.clearInterval = id => { timers.cleared.push(id); };
const tick = () => new Promise(r => setTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
const out = {};
"""

_APP_FUNCS = ("pageFlag", "loadingHolder", "kv", "fmtDate", "fmtWhen", "err", "clearErr", "here", "own",
              "aegisPlanName", "viewMonitoring", "monitoringBody", "monHostRows", "monActive", "monPlanCard", "monPlanHelp",
              "monHostCard", "monActions", "monButton", "monConfirmOff", "monTurnOn", "monTurnOff", "monFailed",
              "monEventsList", "monAckStore", "monAckKey", "monAckSet", "monAckSeen", "monAckMark", "monLatestByHost",
              "monHealthButton", "monHealthBody", "monHealthCard", "monAcknowledge", "monVisible", "startMonPoll",
              "stopMonPoll", "syncMonPoll", "onMonVisibility", "pollMonEvents", "routeShown")
_APP_VARS = ("API", "MONITORING_ON", "MON_POLL_MS", "mon", "MON_MODE", "MON_ACTION", "MON_ACK_CAP")


def _harness(*, storage: bool = True) -> str:
    src = _src()
    return "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", "const h = window.VUI.h;",
                      _WORLD % {"storage": json.dumps(storage)}]
                     + [_fn(src, n) for n in _APP_FUNCS] + [_var(src, n) for n in _APP_VARS])


def _node(script: str, *, storage: bool = True) -> dict:
    prog = (_harness(storage=storage) + "\n(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
            " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


_PE = 1_800_000_000.0
# a manager monitoring a.example (Observe) and b.example (Respond); both proofs current.
_MANAGER = {"org_id": "org_x", "can_manage": True,
            "grants": [{"host": "a.example", "mode": "observe", "not_before": 1.0, "not_after": _PE, "active": True},
                       {"host": "b.example", "mode": "block", "not_before": 1.0, "not_after": _PE, "active": True}],
            "hosts": [{"host": "a.example", "expires_at": _PE}, {"host": "b.example", "expires_at": _PE}],
            "plan": {"host_slots": 5, "respond": True, "period_end": _PE}}


def _ev(host: str, ts: float, decision: str, rid: str, action: str = "block") -> dict:
    return {"host": host, "ts": ts, "decision": decision, "attack_class": "sqli", "action": action, "report_id": rid}


_SCREEN = r"""
const view = viewMonitoring(); document.body.appendChild(view);
const hcard = host => document.querySelectorAll("div.cust-mon-health-card").filter(c => c.dataset.host === host)[0];
const hbadge = host => text(hcard(host).querySelector("span.cust-badge"));
const hbuttons = host => buttons(hcard(host));
const htext = host => text(hcard(host));
"""


def _screen(listing: dict, then: str = "", *, events=None, storage: bool = True) -> dict:
    srv = {"GET api/customer/monitoring": {"data": listing},
           "GET api/customer/monitoring/events": {"data": {"org_id": "org_x", "events": events or []}}}
    return _node(f"server = {json.dumps(srv)};" + _SCREEN + "await flush();\n" + then, storage=storage)


# --- health: one card per armed host, honest badge, honest last-report ---------------------------------------------
def test_each_armed_host_gets_a_health_card_watching_with_no_attacks_when_the_stream_is_empty():
    out = _screen(_MANAGER, r"""
out.hosts = document.querySelectorAll("div.cust-mon-health-card").map(c => c.dataset.host);
out.a = [hbadge("a.example"), hbuttons("a.example"), htext("a.example")];
out.b = hbadge("b.example");
out.calls = calls;
""")
    assert out["hosts"] == ["a.example", "b.example"]                       # one card per ARMED host, sorted
    assert out["a"][0] == "Watching · Observe" and out["a"][1] == []        # live authority, no attacks => no button
    assert "No attacks reported yet" in out["a"][2]
    assert out["b"] == "Watching · Respond"
    # health reads NOTHING new: still exactly the two reads the Monitoring screen already makes
    assert out["calls"] == [["GET", "api/customer/monitoring"], ["GET", "api/customer/monitoring/events"]]


def test_a_managers_armed_host_with_a_lapsed_proof_shows_an_honest_health_warning():
    lapsed = {"org_id": "org_x", "can_manage": True, "plan": _MANAGER["plan"],
              "hosts": [{"host": "b.example", "expires_at": _PE}],                 # a.example's proof is NOT current
              "grants": [{"host": "a.example", "mode": "observe", "not_before": 1.0, "not_after": _PE, "active": True}]}
    out = _screen(lapsed, r"""
out.badge = hbadge("a.example"); out.text = htext("a.example"); out.buttons = hbuttons("a.example");
""")
    assert out["badge"] == "Proof of control lapsed"
    assert "verify it again in Assets" in out["text"] and "cannot be renewed" in out["text"]
    assert out["buttons"] == []                                              # the lapse is a read-only honest signal
    # a NON-manager is never told the verified hosts, so no proof claim is made — the host just shows Watching
    viewer = {"org_id": "org_x", "can_manage": False,
              "grants": [{"host": "a.example", "mode": "observe", "not_before": 1.0, "not_after": _PE, "active": True}]}
    out = _screen(viewer, 'out.badge = hbadge("a.example"); out.hasProof = htext("a.example").indexOf("Proof") >= 0;')
    assert out["badge"] == "Watching · Observe" and out["hasProof"] is False


def test_the_last_report_line_is_a_plain_fact_and_an_unconfirmed_signal_offers_no_acknowledge():
    evs = [_ev("a.example", 1_700_000_000.0, "lead", "RID-lead", action="observe")]
    out = _screen(_MANAGER, r"""
out.a = [htext("a.example"), hbuttons("a.example")];
""", events=evs)
    assert "unconfirmed signal" in out["a"][0] and "2023-11-14" in out["a"][0]   # fmtWhen stamped it, honestly labelled
    assert out["a"][1] == []                                                 # only a CONFIRMED attack can be acknowledged


# --- acknowledge: a per-viewer mark-as-seen, no server call -------------------------------------------------------
def test_a_confirmed_attack_offers_acknowledge_and_marking_it_is_local_and_sticks():
    evs = [_ev("a.example", 1_700_000_900.0, "confirmed", "RID-1")]
    out = _screen(_MANAGER, r"""
out.before = [hbuttons("a.example"), htext("a.example").indexOf("not acknowledged") >= 0];
const n = calls.length;
button(hcard("a.example"), "Acknowledge").click(); await flush();
out.afterClick = [hbuttons("a.example"), htext("a.example")];
out.sent = calls.length - n; out.toasts = toasts;
// a fresh poll re-renders the section from storage: the host is now acknowledged, with no button
mon.gen; await pollMonEvents(); await flush();
out.afterPoll = [hbuttons("a.example"), htext("a.example")];
""", events=evs)
    assert out["before"] == [["Acknowledge"], True]
    assert out["afterClick"][0] == [] and "Acknowledged on this device" in out["afterClick"][1]
    assert out["sent"] == 0 and out["toasts"] == ["Acknowledged on this device."]   # NO server call
    # the next poll re-renders the card from the persisted ack: no button, and it reads as acknowledged
    assert out["afterPoll"][0] == [] and "acknowledged on this device" in out["afterPoll"][1]


def test_a_new_report_id_is_unacknowledged_again_and_acks_are_per_user():
    out = _screen(_MANAGER, r"""
button(hcard("a.example"), "Acknowledge").click(); await flush();     // ack RID-1
// a NEW confirmed attack (different report_id) arrives on the next poll — it is unacknowledged again
server["GET api/customer/monitoring/events"] = { data: { org_id: "org_x", events: [
  { host: "a.example", ts: 1700002000, decision: "confirmed", attack_class: "sqli", action: "block", report_id: "RID-2" }] } };
await pollMonEvents(); await flush();
out.newAttack = hbuttons("a.example");
// a DIFFERENT signed-in user has their own ack set (namespaced), so they still see RID-2 as unacknowledged
who = { authenticated: true, username: "ben" };
await pollMonEvents(); await flush();
out.otherUser = hbuttons("a.example");
""", events=[_ev("a.example", 1_700_000_900.0, "confirmed", "RID-1")])
    assert out["newAttack"] == ["Acknowledge"]            # a fresh attack must be acknowledged on its own
    assert out["otherUser"] == ["Acknowledge"]            # ana's ack never speaks for ben


def test_with_storage_off_the_card_still_updates_even_though_nothing_is_remembered():
    evs = [_ev("a.example", 1_700_000_900.0, "confirmed", "RID-1")]
    out = _screen(_MANAGER, r"""
out.before = hbuttons("a.example");
button(hcard("a.example"), "Acknowledge").click(); await flush();
out.afterClick = [hbuttons("a.example"), htext("a.example")];
out.sent = calls.filter(c => c[0] === "POST").length;
""", events=evs, storage=False)
    assert out["before"] == ["Acknowledge"]
    assert out["afterClick"][0] == [] and "Acknowledged on this device" in out["afterClick"][1]
    assert out["sent"] == 0                               # still no server call with storage unavailable


# --- the health/acknowledge path opens no route and does no network --------------------------------------------------
def test_the_health_and_acknowledge_path_touches_no_route_and_no_raw_network():
    src = _src()
    block = "\n".join(_fn(src, n) for n in ("monHealthBody", "monHealthCard", "monAcknowledge", "monHealthButton",
                                            "monAckStore", "monAckKey", "monAckSet", "monAckSeen", "monAckMark",
                                            "monLatestByHost"))
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", block)
    assert "postJSON" not in code and "getJSON" not in code                 # acknowledge is purely local — no server call
    assert 'API + "' not in code                                           # it forks NO edge route at all
    for banned in ("fetch(", "XMLHttpRequest", "sendBeacon", "location.href", "window.open", "innerHTML", "org_id"):
        assert banned not in code, banned
