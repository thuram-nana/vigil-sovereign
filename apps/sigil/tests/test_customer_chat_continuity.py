"""The CONTINUITY layer of the customer command box (#/command), executed under node on the real app.js.

This runs app.js's OWN continuity functions verbatim on the ui.js kit with a minimal DOM — nothing is re-implemented
here. It pins the three client-side pieces and the client half of the transcript store, each a money/authority-safe
addition that must NEVER relax the launch/verify doctrine the command box already enforces:

  * CLIENT QUEUE — several lines Sent back-to-back drain in order, ONE round-trip at a time, nothing dropped, Send
    stays enabled, queued lines show as pending; a queued launch is NEVER auto-confirmed (it still stops at the
    explicit Confirm click).                                                                     -> test_queue_*
  * REMEMBERED HOST — a host-less follow-up resolves against the remembered current host and the host is passed
    EXPLICITLY to the edge; a named host switches context; a confirm is STILL required.          -> test_host_*
  * LIVE STATUS POLL — while a run is live the activity card updates in place (reusing LIVE_POLL_MS + the
    launch_activity `since` cursor) and STOPS when the run ends / off-route.                      -> test_poll_*
  * TRANSCRIPT (client half) — on mount, with the store flag ON, the prior conversation is replayed; flag OFF, the
    box reads nothing on arrival (byte-identical to today).                                       -> test_transcript_*

The box NEVER puts org / requester / username / mfa_at in a body — the edge supplies those from the session.
"""
from __future__ import annotations

import http.client
import json
import subprocess
import threading

from sigil.ui.custui import build_customer_server

from test_customer_command_ui import _CMD_FUNCS, _CMD_VARS, UI_JS
from test_customer_monitoring_screen import _DOM, _fn, _need_node, _src, _var
from test_customer_onboarding import _page_and_build

# The box's world, stubbed. Like the #/live feed, the poll uses setTimeout(fn, LIVE_POLL_MS); we keep tick() on real
# timing but CAPTURE the long-poll callbacks so a test fires them explicitly (no 15s wait).
_WORLD = r"""
document.body.dataset.command = %(flag)s;
document.body.dataset.chatMemory = %(memflag)s;
let who = { authenticated: true, username: "ana" };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/command" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
const VUI = window.VUI;
const calls = [];
let server = {};
function deliver(r) {
  if (!r) { const e = new Error("404"); e.status = 404; e.data = { error: "not found" }; throw e; }
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data; throw e; }
  return r.data;
}
VUI.getJSON = async p => { calls.push(["GET", p]); return deliver(server["GET " + p]); };
VUI.postJSON = async (p, b) => {
  calls.push(["POST", p, b]);
  let r = server["POST " + p];
  if (typeof r === "function") r = r(b);
  else if (Array.isArray(r)) r = r.shift();
  if (r && typeof r.then === "function") r = await r;      // an async descriptor (to measure round-trip ordering)
  return deliver(r);
};
const realSetTimeout = setTimeout;
const pollQ = [];                       // captured poll callbacks (the 15s timer); test fires them explicitly
globalThis.setTimeout = (fn, ms) => { if (!ms) return realSetTimeout(fn, 0); pollQ.push(fn); return pollQ.length; };
globalThis.clearTimeout = () => {};
function firePoll() { const fn = pollQ.shift(); if (fn) fn(); return !!fn; }
const tick = () => new Promise(r => realSetTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 16; i++) await tick(); };
function show() { document.body.children = []; const v = viewCommandBox(); document.body.appendChild(v); return v; }
function btn(label) { return document.querySelectorAll("button").find(b => b.textContent === label); }
function type(line) { const i = document.querySelector("input.cmd-input"); i.value = line; return i; }
function send(line) { type(line); btn("Send").click(); }     // Send WITHOUT draining (back-to-back queueing)
async function submit(line) { send(line); await flush(); }
function postBodies(path) { return calls.filter(c => c[0] === "POST" && c[1] === "api/customer/" + path).map(c => c[2]); }
function youTurns() { return document.querySelectorAll("div.cmd-you").filter(d => !d.classList.contains("cmd-history")); }
const out = {};
"""


def _harness(flag: str = "1", memflag: str = "0") -> str:
    src = _src()
    return "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", "const h = window.VUI.h;",
                      _WORLD % {"flag": json.dumps(flag), "memflag": json.dumps(memflag)}]
                     + [_fn(src, n) for n in _CMD_FUNCS] + [_var(src, n) for n in _CMD_VARS])


def _node(script: str, *, flag: str = "1", memflag: str = "0") -> dict:
    prog = (_harness(flag, memflag) + "\n(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
              " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


_AWAIT = {"intent": "launch", "host": "apme.cm", "state": "awaiting_confirm", "status": "verified",
          "blocked": "confirm the assessment before it reserves credits", "need": "confirm",
          "choices": [{"product_id": "p_quick", "depth": "quick"}, {"product_id": "p_deep", "depth": "deep"}]}
_STARTED = {"intent": "launch", "host": "apme.cm", "state": "running",
            "reserved": {"slug": "sl", "product_id": "p_quick"}, "started": {"ok": True}}


# --- piece 1: the client message queue ----------------------------------------------------------------------------
def test_queue_drains_in_order_and_drops_nothing():
    out = _node(r"""
let n = 0;
server["POST api/customer/assistant/command"] = b => ({ data: { intent: "advice",
  advice: { kind: "assistant_advice", is_advice: true, answer: "A" + (++n), grounded_in: [], finding_count: 0,
            document_count: 0, truncated: false } } });
show();
send("one"); send("two"); send("three");                 // three lines Sent back-to-back, nothing awaited between
out.pendingBeforeDrain = youTurns().filter(d => d.classList.contains("cmd-pending")).length;
out.youBeforeDrain = youTurns().length;                  // all three shown at once
out.sendDisabledMidflight = btn("Send").disabled === true;
await flush();
out.order = postBodies("assistant/command").map(b => b.line);   // drained IN ORDER, none dropped
out.answers = document.querySelectorAll("div.cmd-answer").map(a => a.textContent);
out.sendDisabledAfter = btn("Send").disabled === true;
""")
    assert out["youBeforeDrain"] == 3 and out["pendingBeforeDrain"] >= 2   # queued lines show as pending
    assert out["sendDisabledMidflight"] is False and out["sendDisabledAfter"] is False   # Send NEVER disabled
    assert out["order"] == ["one", "two", "three"]                        # FIFO, in order, nothing dropped
    assert out["answers"] == ["A1", "A2", "A3"]


def test_queue_processes_one_round_trip_at_a_time():
    # mutation-sensitive: the second classify must not fire until the first round-trip has returned (the drain is
    # strictly sequential — a parallel fan-out would race the flow machine's one-step-at-a-time backend).
    out = _node(r"""
let inflight = 0, maxInflight = 0;
server["POST api/customer/assistant/command"] = async b => { inflight++; maxInflight = Math.max(maxInflight, inflight);
  await tick(); inflight--; return { data: { intent: "advice",
  advice: { kind: "assistant_advice", is_advice: true, answer: "x", grounded_in: [], finding_count: 0,
            document_count: 0, truncated: false } } }; };
show();
send("one"); send("two"); send("three");
await flush();
out.maxInflight = maxInflight;
out.count = postBodies("assistant/command").length;
""")
    assert out["maxInflight"] == 1 and out["count"] == 3


def test_queue_never_auto_confirms_a_queued_launch():
    # A queued launch must still STOP at awaiting_confirm: the first flow step carries confirm strictly false, the
    # Confirm button is surfaced, and a following queued line never slips a confirm=true behind it.
    out = _node(r"""
server["POST api/customer/assistant/command"] = b => b.line.indexOf("launch") === 0
  ? { data: { intent: "launch", host: "apme.cm", depth: "" } }
  : { data: { intent: "status", host: "apme.cm" } };
server["POST api/customer/flow"] = b => b.intent === "launch"
  ? (b.confirm === true ? { data: %(started)s } : { data: %(await)s })
  : { data: { intent: "status", host: "apme.cm", state: "running", launch: { slug: "sl" }, activity: { rows: [] } } };
show();
send("launch apme.cm"); send("status");                  // a launch then a status, queued back-to-back
await flush();
const launchSteps = postBodies("flow").filter(b => b.intent === "launch");
out.launchConfirms = launchSteps.map(b => b.confirm);    // every launch step before the click: confirm === false
out.anyAutoConfirm = postBodies("flow").some(b => b.confirm === true);
out.confirmButton = !!btn("Confirm and launch");
out.started = document.body.textContent.indexOf("Assessment started") >= 0;
""" % {"started": json.dumps(_STARTED), "await": json.dumps(_AWAIT)})
    assert out["launchConfirms"] == [False]              # exactly one launch step, confirm false — never reserved
    assert out["anyAutoConfirm"] is False and out["confirmButton"] is True and out["started"] is False


# --- piece 2: the remembered current host -------------------------------------------------------------------------
def test_host_remembered_resolves_a_hostless_followup_and_shows_working_on():
    out = _node(r"""
server["POST api/customer/assistant/command"] = b => b.line.indexOf("launch") === 0
  ? { data: { intent: "launch", host: "apme.cm", depth: "" } }
  : { data: { intent: "pause" } };                       // the follow-up names NO host
server["POST api/customer/flow"] = b => b.intent === "launch"
  ? { data: %(await)s }
  : { data: { intent: "pause", host: b.host, state: "running", control: { ok: true } } };
show();
await submit("launch apme.cm");                          // names apme.cm -> remembered
out.working = document.querySelector("div.cmd-hostbar") ? document.querySelector("div.cmd-hostbar").textContent : "";
await submit("pause");                                   // host-less -> resolves to apme.cm
const pauseStep = postBodies("flow").find(b => b.intent === "pause");
out.pauseHost = pauseStep ? pauseStep.host : null;       // the UI filled the remembered host EXPLICITLY
""" % {"await": json.dumps(_AWAIT)})
    assert out["working"] == "Working on: apme.cm"
    assert out["pauseHost"] == "apme.cm"                 # the server stayed host-explicit; the UI supplied it


def test_host_a_confirm_is_still_required_after_a_remembered_host():
    # DoD: the remembered host resolves a host-less "launch", but the launch STILL stops at awaiting_confirm — the
    # remembered host must never short-circuit the explicit spend confirm.
    out = _node(r"""
server["POST api/customer/assistant/command"] = b => b.line === "launch"
  ? { data: { intent: "launch" } }                       // host-less launch
  : { data: { intent: "launch", host: "apme.cm", depth: "" } };
server["POST api/customer/flow"] = b => b.confirm === true ? { data: %(started)s } : { data: %(await)s };
show();
await submit("launch apme.cm");                          // remember apme.cm (awaiting_confirm)
await submit("launch");                                  // host-less launch resolves to apme.cm
const steps = postBodies("flow");
out.hosts = steps.map(b => b.host);
out.confirms = steps.map(b => b.confirm);
out.confirmButton = !!btn("Confirm and launch");
out.started = document.body.textContent.indexOf("Assessment started") >= 0;
""" % {"started": json.dumps(_STARTED), "await": json.dumps(_AWAIT)})
    assert out["hosts"] == ["apme.cm", "apme.cm"]        # both resolved to the remembered host
    assert out["confirms"] == [False, False]             # NEITHER auto-confirmed
    assert out["confirmButton"] is True and out["started"] is False


def test_host_a_named_host_switches_context():
    out = _node(r"""
server["POST api/customer/assistant/command"] = b => b.line.indexOf("launch") === 0
  ? { data: { intent: "launch", host: "apme.cm", depth: "" } }
  : { data: { intent: "status", host: "beta.cm" } };     // a different named host
server["POST api/customer/flow"] = b => b.intent === "launch"
  ? { data: %(await)s }
  : { data: { intent: "status", host: b.host, state: "ready", launch: null, activity: null } };
show();
await submit("launch apme.cm");
await submit("status beta.cm");                          // names beta.cm -> switches context
out.working = document.querySelector("div.cmd-hostbar").textContent;
const statusStep = postBodies("flow").find(b => b.intent === "status");
out.statusHost = statusStep.host;
""" % {"await": json.dumps(_AWAIT)})
    assert out["working"] == "Working on: beta.cm" and out["statusHost"] == "beta.cm"


# --- piece 3: the live status poll --------------------------------------------------------------------------------
def test_poll_updates_the_activity_card_live_then_stops_when_the_run_ends():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "status", host: "apme.cm" } };
server["POST api/customer/flow"] = [
  { data: { intent: "status", host: "apme.cm", state: "running", launch: { slug: "sl", state: "running" },
            activity: { rows: [{ seq: 0, label: "Scanning the surface" }], cursor: 0 } } },
  { data: { intent: "status", host: "apme.cm", state: "running", launch: { slug: "sl", state: "running" },
            activity: { rows: [{ seq: 1, label: "Probing the login" }], cursor: 1 } } },
  { data: { intent: "status", host: "apme.cm", state: "done", launch: null,
            activity: { rows: [{ seq: 2, label: "Writing the report" }], cursor: 2 } } }
];
show();
await submit("status");
out.afterSubmit = document.querySelectorAll("li.cmd-step").map(li => li.textContent);
out.scheduled1 = pollQ.length;                           // a poll is scheduled while the run is live
firePoll(); await flush();
out.afterPoll1 = document.querySelectorAll("li.cmd-step").map(li => li.textContent);
out.scheduled2 = pollQ.length;                           // still running -> rescheduled
firePoll(); await flush();                               // this answer says the run is DONE
out.afterPoll2 = document.querySelectorAll("li.cmd-step").map(li => li.textContent);
out.scheduledAfterEnd = pollQ.length;                    // run ended -> poll STOPS (nothing rescheduled)
out.pollPosts = postBodies("flow").filter(b => b.intent === "status").map(b => b.since);
""")
    assert out["afterSubmit"] == ["Scanning the surface"] and out["scheduled1"] == 1
    assert out["afterPoll1"] == ["Scanning the surface", "Probing the login"] and out["scheduled2"] == 1
    assert out["afterPoll2"] == ["Scanning the surface", "Probing the login", "Writing the report"]
    assert out["scheduledAfterEnd"] == 0                  # the poll stopped itself when the run ended
    assert out["pollPosts"] == ["", "0", "1"]            # the cursor advanced 0 -> 1 across the polls


def test_poll_stops_when_the_box_is_left_and_drops_the_in_flight_answer():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "status", host: "apme.cm" } };
server["POST api/customer/flow"] = { data: { intent: "status", host: "apme.cm", state: "running",
  launch: { slug: "sl", state: "running" }, activity: { rows: [{ seq: 0, label: "Scanning" }], cursor: 0 } } };
show();
await submit("status");
out.scheduled = pollQ.length;
location.hash = "#/billing"; onCmdRoute();               // leaving the box ENDS the loop
firePoll(); await flush();                               // the captured callback runs but must do nothing
out.rescheduled = pollQ.length;
out.pollHost = cmdPoll.host;
""")
    assert out["scheduled"] == 1 and out["rescheduled"] == 0 and out["pollHost"] == ""


def test_poll_does_not_start_when_no_run_is_live():
    # a status card for a host with NO active launch (or a feed unavailable on this deployment) never schedules a poll.
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "status", host: "apme.cm" } };
server["POST api/customer/flow"] = { data: { intent: "status", host: "apme.cm", state: "ready",
  launch: null, activity: null } };
show();
await submit("status");
out.scheduled = pollQ.length;
""")
    assert out["scheduled"] == 0


# --- piece 4a (client half): the persistent transcript ------------------------------------------------------------
def test_transcript_off_reads_nothing_on_arrival():
    out = _node(r"""
out.memOn = CHAT_MEMORY_ON;
show();
await flush();
out.reads = calls.filter(c => c[0] === "GET").length;    // flag OFF: nothing is read on arrival (byte-identical)
out.history = document.querySelectorAll("div.cmd-history").length;
""", memflag="0")
    assert out["memOn"] is False and out["reads"] == 0 and out["history"] == 0


def test_transcript_replays_prior_turns_oldest_first_on_mount():
    out = _node(r"""
out.memOn = CHAT_MEMORY_ON;
server["GET api/customer/chat/history"] = { data: { turns: [
  { role: "user", text: "verify apme.cm", ts: 1 },
  { role: "assistant", text: "Ownership verified.", ts: 2 },
  { role: "user", text: "what should I fix first?", ts: 3 },
  { role: "assistant", text: "Fix the admin login first.", ts: 4 } ] } };
show();
await flush();
out.reads = calls.filter(c => c[0] === "GET" && c[1] === "api/customer/chat/history").length;
out.turns = document.querySelectorAll("div.cmd-history").map(d => d.textContent);
out.note = document.querySelector("p.cmd-history-note") ? document.querySelector("p.cmd-history-note").textContent : "";
""", memflag="1")
    assert out["memOn"] is True and out["reads"] == 1
    assert out["note"] == "Earlier in this conversation"
    assert out["turns"] == ["Youverify apme.cm", "VIGILOwnership verified.",
                            "Youwhat should I fix first?", "VIGILFix the admin login first."]


def test_transcript_a_401_on_load_bounces_to_sign_in():
    out = _node(r"""
server["GET api/customer/chat/history"] = { status: 401, data: { error: "login required" } };
show();
await flush();
out.navs = navs;
out.whoRefreshed = whoRefreshes;
""", memflag="1")
    assert out["navs"] == ["#/login"] and out["whoRefreshed"] == 1


# --- the box still never leaks a session field in a body ----------------------------------------------------------
def test_no_session_fields_leak_across_the_continuity_paths():
    out = _node(r"""
server["POST api/customer/assistant/command"] = b => b.line.indexOf("launch") === 0
  ? { data: { intent: "launch", host: "apme.cm", depth: "" } }
  : { data: { intent: "status", host: "apme.cm" } };
server["POST api/customer/flow"] = b => b.intent === "launch"
  ? { data: %(await)s }
  : { data: { intent: "status", host: "apme.cm", state: "running", launch: { slug: "sl", state: "running" },
              activity: { rows: [{ seq: 0, label: "Scanning" }], cursor: 0 } } };
show();
send("launch apme.cm"); send("status");
await flush();
firePoll(); await flush();                                // the background poll posts too — it must also be clean
const bodies = calls.filter(c => c[0] === "POST").map(c => c[2]);
const banned = ["org_id", "requester", "username", "mfa_at", "ip", "session_key"];
out.leaks = bodies.map(b => banned.filter(k => Object.prototype.hasOwnProperty.call(b, k))).filter(x => x.length);
""" % {"await": json.dumps(_AWAIT)})
    assert out["leaks"] == []


# --- the edge: the chat-memory flag + the transcript route gating -------------------------------------------------
def test_edge_writes_the_chat_memory_flag_into_the_page(tmp_path, monkeypatch):
    # STRICT default-OFF: unset => "0"; only an explicit affirmative token forces "1". It counts in the build id.
    monkeypatch.delenv("VIGIL_CUSTOMER_CHAT_MEMORY", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-chat-memory="0"' in off and "__VIGIL_CHAT_MEMORY__" not in off
    monkeypatch.setenv("VIGIL_CUSTOMER_CHAT_MEMORY", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-chat-memory="1"' in on
    assert build_on != build_off                                      # the flag counts in the build id


def _get(srv, path: str) -> int:
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
    c.request("GET", path, headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
    return c.getresponse().status


def test_edge_chat_history_route_is_404_when_off_and_live_when_on(tmp_path, monkeypatch):
    # flag OFF => the route is the unknown-route 404 (byte-identical). ON => it is served (no session => 401, i.e. it
    # reached the handler — NOT a 404). This proves the route gating without a running provisioner.
    monkeypatch.delenv("VIGIL_CUSTOMER_CHAT_MEMORY", raising=False)
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "s1"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert _get(srv, "/api/customer/chat/history") == 404
    finally:
        srv.shutdown()
        srv.server_close()
    monkeypatch.setenv("VIGIL_CUSTOMER_CHAT_MEMORY", "1")
    srv2 = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                 sessions_dir=str(tmp_path / "s2"))
    threading.Thread(target=srv2.serve_forever, daemon=True).start()
    try:
        assert _get(srv2, "/api/customer/chat/history") == 401        # served the handler (no session), never a 404
    finally:
        srv2.shutdown()
        srv2.server_close()
