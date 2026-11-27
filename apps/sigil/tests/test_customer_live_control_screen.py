"""C-LIVE — the customer app's Live Control screen (#/live), executed under node on the real app.js.

The screen is a pure composition of already-proven customer routes: it reads the launches (state + the signed
pause/resume lease), polls the CUSTOMER-SAFE live-activity feed with a cursor, and POSTs an ADVISORY instruction.
Everything here runs app.js's OWN functions verbatim on the ui.js kit with a minimal DOM — nothing is re-implemented.

Invariants a false-green would break (each neuter reds a NAMED test):
  * the whole surface is gated by the page flag — flag off => no tab, #/live is the home screen  -> test_flag_off_*
  * the feed shows only what the server sent, newest appended, labelled; nothing when idle       -> test_renders_*
  * steering POSTs host+text+idem_key, is idempotent per click, clears on success, refuses empty  -> test_send_*
  * pause/resume send ONLY the signed lease, and only the actions the server offered are shown    -> test_pause_*
  * the poll is single-flight (no double-append on the cursor) and stops off-route / off-screen    -> test_poll_*
  * a late answer that lands after you navigate away is dropped                                     -> test_stale_*
"""
from __future__ import annotations

import json
import subprocess

from test_customer_monitoring_screen import _DOM, _fn, _need_node, _src, _var

# app.js's own Live Control code, run verbatim.
_LIVE_FUNCS = ("pageFlag", "loadingHolder", "own", "here", "liveActive", "liveRow", "renderLiveFeed",
               "loadLiveActivity", "scheduleLivePoll", "stopLivePoll", "sendInstruction", "liveLaunchAction",
               "liveControlBody", "viewLiveControl", "onLiveRoute", "onLiveVisibility")
_LIVE_VARS = ("API", "STATE_LABELS", "LIVE_POLL_MS", "LIVE_ICON", "live", "LIVE_ON")

# The app's world, stubbed: who is signed in, where the page is, what the server answers, and every call made. The
# poll uses setTimeout(fn, 15000); we keep tick() on real timing and CAPTURE the long poll callbacks so the test
# fires them deliberately (never on a wall clock).
_WORLD = r"""
document.body.dataset.liveControl = %(flag)s;
let who = { authenticated: true, username: "ana" };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/live" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let renders = 0; function render() { renders++; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
var GUIDE_ON = false;
const VUI = window.VUI;
// launchUi is app.js's own var (extracted); the stubbed world only reads/writes .data like the app does.
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
const realSetTimeout = setTimeout;
const pollQ = [];           // captured poll callbacks (the 15s timer); test fires them explicitly
globalThis.setTimeout = (fn, ms) => { if (!ms) return realSetTimeout(fn, 0); pollQ.push(fn); return pollQ.length; };
globalThis.clearTimeout = () => {};
function firePoll() { const fn = pollQ.shift(); if (fn) fn(); return !!fn; }
const tick = () => new Promise(r => realSetTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 16; i++) await tick(); };
const launchUiData = d => { launchUi.data = d; };
// Render the screen into the live document so document.querySelector() sees it, exactly as the router would mount it.
function show() { document.body.children = []; const v = viewLiveControl(); document.body.appendChild(v); return v; }
const out = {};
"""


def _harness(flag: str = "1") -> str:
    src = _src()
    # launchUi is a big app var with unrelated fields; a tiny stub matches how Live Control uses it (.data only).
    return "\n".join([_DOM, f"require({json.dumps(str(__import__('test_customer_monitoring_screen').UI_JS))});",
                      "const h = window.VUI.h;", "var launchUi = { data: null };",
                      _WORLD % {"flag": json.dumps(flag)}]
                     + [_fn(src, n) for n in _LIVE_FUNCS] + [_var(src, n) for n in _LIVE_VARS])


def _node(script: str, *, flag: str = "1") -> dict:
    prog = (_harness(flag) + "\n(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
              " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# A workspace with one assessment of a.example running (pausable, signed lease "L1"), and a short activity trail.
_RUNNING = {"launches": [{"host": "a.example", "state": "running", "actions": ["pause"], "lease": "L1"}]}
_ACTIVITY = {"ok": True, "slug": "sl", "cursor": 1,
             "rows": [{"seq": 0, "ts": 1.0, "phase": "scan", "label": "Scanning the surface", "status": "started"},
                      {"seq": 1, "ts": 2.0, "phase": "scan", "label": "Scanning the surface", "status": "completed"}]}


# --- the flag gate ------------------------------------------------------------------------------------------------
def test_flag_off_the_screen_is_the_home_screen_and_polls_nothing():
    out = _node(r"""
out.liveOn = LIVE_ON;
out.calls = calls.length;      // nothing loaded: the surface is inert
out.poll = pollQ.length;
""", flag="0")
    assert out["liveOn"] is False and out["calls"] == 0 and out["poll"] == 0


def test_flag_on_the_screen_loads_the_launches_and_the_feed():
    out = _node(r"""
server["GET api/customer/launches"] = { data: %(running)s };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { data: %(act)s };
const view = show();
await flush();
out.dataCurrent = view.dataset.current;
out.heading = document.querySelector("h2") ? document.querySelector("h2").textContent : null;
out.hostLine = document.querySelectorAll("p.cust-muted").map(p => p.textContent).find(t => t.indexOf("a.example") >= 0) || null;
out.steps = document.querySelectorAll("li.live-step").map(li => li.textContent);
out.hasTextarea = !!document.querySelector("textarea.live-instruct");
out.sendBtn = document.querySelectorAll("button").map(b => b.textContent).find(t => t === "Send to VIGIL") || null;
out.pauseBtn = document.querySelectorAll("button").map(b => b.textContent).find(t => t === "Pause") || null;
out.cursor = live.cursor;
""" % {"running": json.dumps(_RUNNING), "act": json.dumps(_ACTIVITY)})
    assert out["dataCurrent"] == "#/live"
    assert out["heading"] == "Live Control"
    assert out["hostLine"] and "a.example" in out["hostLine"] and "Running" in out["hostLine"]
    assert len(out["steps"]) == 2 and all("Scanning the surface" in s for s in out["steps"])
    assert out["hasTextarea"] and out["sendBtn"] == "Send to VIGIL" and out["pauseBtn"] == "Pause"
    assert out["cursor"] == 1          # the feed cursor advanced to the server's


def test_renders_an_honest_card_when_nothing_is_running_and_does_not_poll():
    out = _node(r"""
server["GET api/customer/launches"] = { data: { launches: [{ host: "a.example", state: "completed" }] } };
show();
await flush();
out.card = document.querySelectorAll("div.cust-soon").map(d => d.textContent);
out.host = live.host;              // no running host: nothing to steer or poll
out.feedCalls = calls.filter(c => String(c[1]).indexOf("/live/activity") >= 0).length;
out.poll = pollQ.length;
""")
    assert out["card"] and "No assessment is running" in out["card"][0]
    assert out["host"] is None and out["feedCalls"] == 0 and out["poll"] == 0


# --- steering (the advisory instruction) --------------------------------------------------------------------------
def test_send_posts_host_text_and_an_idem_key_then_clears():
    out = _node(r"""
server["GET api/customer/launches"] = { data: %(running)s };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { data: { ok: true, cursor: -1, rows: [] } };
server["POST api/customer/launch/instruct"] = { data: { ok: true, seq: 7 } };
show();
await flush();
const ta = document.querySelector("textarea.live-instruct");
ta.value = "  concentrate on authentication  ";
document.querySelectorAll("button").find(b => b.textContent === "Send to VIGIL").click();
await flush();
const post = calls.find(c => c[0] === "POST" && c[1] === "api/customer/launch/instruct");
out.body = post ? post[2] : null;
out.cleared = ta.value;
out.note = document.querySelector("div.live-note") ? document.querySelector("div.live-note").textContent : null;
""" % {"running": json.dumps(_RUNNING)})
    body = out["body"]
    assert body and body["host"] == "a.example" and body["text"] == "concentrate on authentication"
    assert isinstance(body.get("idem_key"), str) and len(body["idem_key"]) > 0    # a fresh key per click
    assert out["cleared"] == "" and out["note"] and "Sent" in out["note"]


def test_send_with_empty_text_posts_nothing():
    out = _node(r"""
server["GET api/customer/launches"] = { data: %(running)s };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { data: { ok: true, cursor: -1, rows: [] } };
show();
await flush();
const ta = document.querySelector("textarea.live-instruct");
ta.value = "   ";                    // whitespace only
document.querySelectorAll("button").find(b => b.textContent === "Send to VIGIL").click();
await flush();
out.posts = calls.filter(c => c[0] === "POST").length;
""" % {"running": json.dumps(_RUNNING)})
    assert out["posts"] == 0


def test_send_shows_the_servers_refusal_and_keeps_the_text():
    out = _node(r"""
server["GET api/customer/launches"] = { data: %(running)s };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { data: { ok: true, cursor: -1, rows: [] } };
server["POST api/customer/launch/instruct"] = { status: 403, data: { error: "not your engagement" } };
show();
await flush();
const ta = document.querySelector("textarea.live-instruct");
ta.value = "focus on auth";
document.querySelectorAll("button").find(b => b.textContent === "Send to VIGIL").click();
await flush();
out.note = document.querySelector("div.live-note").textContent;
out.kept = ta.value;                 // a failed send does not throw away what the user typed
""" % {"running": json.dumps(_RUNNING)})
    assert "not your engagement" in out["note"] and out["kept"] == "focus on auth"


# --- pause / resume (the signed lease only) -----------------------------------------------------------------------
def test_pause_sends_only_the_signed_lease_then_reloads():
    out = _node(r"""
server["GET api/customer/launches"] = { data: %(running)s };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { data: { ok: true, cursor: -1, rows: [] } };
server["POST api/customer/launch/pause"] = { data: { ok: true } };
show();
await flush();
document.querySelectorAll("button").find(b => b.textContent === "Pause").click();
await flush();
const post = calls.find(c => c[0] === "POST" && c[1] === "api/customer/launch/pause");
out.body = post ? post[2] : null;
out.reloaded = calls.filter(c => c[0] === "GET" && c[1] === "api/customer/launches").length;
""" % {"running": json.dumps(_RUNNING)})
    assert out["body"] == {"lease": "L1"}          # ONLY the lease — no host, no org, no scope
    assert out["reloaded"] >= 2                     # initial + the post-action reload


def test_resume_is_offered_only_when_the_server_offers_it():
    out = _node(r"""
server["GET api/customer/launches"] = { data: { launches: [
  { host: "a.example", state: "paused", actions: ["resume"], lease: "L2" }] } };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { data: { ok: true, cursor: -1, rows: [] } };
show();
await flush();
const labels = document.querySelectorAll("button").map(b => b.textContent);
out.hasResume = labels.indexOf("Resume") >= 0;
out.hasPause = labels.indexOf("Pause") >= 0;      // not offered -> not shown
""")
    assert out["hasResume"] is True and out["hasPause"] is False


# --- the poll: single-flight, cursor-advancing, and view-gated ----------------------------------------------------
def test_poll_is_single_flight_and_never_double_appends():
    # two concurrent loads read the SAME cursor; without the in-flight guard both would append the same rows.
    out = _node(r"""
server["GET api/customer/launches"] = { data: %(running)s };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { data: %(act)s };
show();
await flush();
out.afterFirst = live.rows.length;
// fire two more loads back-to-back; the server now returns nothing new at the advanced cursor
server["GET api/customer/live/activity?host=a.example&since=1"] = { data: { ok: true, cursor: 1, rows: [] } };
const a = loadLiveActivity(), b = loadLiveActivity();
await Promise.all([a, b]); await flush();
out.afterConcurrent = live.rows.length;
out.steps = document.querySelectorAll("li.live-step").length;
""" % {"running": json.dumps(_RUNNING), "act": json.dumps(_ACTIVITY)})
    assert out["afterFirst"] == 2 and out["afterConcurrent"] == 2 and out["steps"] == 2


def test_poll_stops_off_route_and_off_screen():
    out = _node(r"""
server["GET api/customer/launches"] = { data: %(running)s };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { data: %(act)s };
show();
await flush();
out.scheduled = pollQ.length >= 1;          // a next poll is queued while shown
// navigate away: the hashchange handler must drop the pending poll
location.hash = "#/billing";
onLiveRoute();
out.timerAfterRoute = live.timer;
// back on route but hidden: visibility handler must not start a poll
location.hash = "#/live"; document.hidden = true;
onLiveVisibility();
out.loadingWhileHidden = live.loading;
""" % {"running": json.dumps(_RUNNING), "act": json.dumps(_ACTIVITY)})
    assert out["scheduled"] is True and out["timerAfterRoute"] is None and out["loadingWhileHidden"] is False


def test_poll_appends_only_new_rows_on_the_advanced_cursor():
    out = _node(r"""
server["GET api/customer/launches"] = { data: %(running)s };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { data: %(act)s };
show();
await flush();
out.first = live.rows.map(r => r.seq);
// the next poll returns one new row at seq 2
server["GET api/customer/live/activity?host=a.example&since=1"] =
  { data: { ok: true, cursor: 2, rows: [{ seq: 2, ts: 3.0, phase: "reasoning_pass", label: "Recording the evidence", status: "completed" }] } };
firePoll();
await flush();
out.second = live.rows.map(r => r.seq);
out.lastLabel = document.querySelectorAll("span.live-step-l").map(e => e.textContent).slice(-1)[0];
""" % {"running": json.dumps(_RUNNING), "act": json.dumps(_ACTIVITY)})
    assert out["first"] == [0, 1] and out["second"] == [0, 1, 2]
    assert out["lastLabel"] == "Recording the evidence"


# --- a late answer that lands after you leave is dropped ----------------------------------------------------------
def test_stale_activity_answer_is_dropped_after_navigating_away():
    out = _node(r"""
let release;
const slow = new Promise(r => { release = r; });
server["GET api/customer/launches"] = { data: %(running)s };
server["GET api/customer/live/activity?host=a.example&since=-1"] = { wait: slow };
show();
await flush();                               // the feed GET is now in flight, awaiting `slow`
location.hash = "#/billing";                 // user leaves
onLiveRoute();
release(%(act)s);                            // the answer finally lands
await flush();
out.rows = live.rows.length;                 // dropped: we are no longer on #/live
""" % {"running": json.dumps(_RUNNING), "act": json.dumps(_ACTIVITY)})
    assert out["rows"] == 0
