"""B2/B3 — the customer app's chat COMMAND box (#/command), executed under node on the real app.js.

One box drives a whole engagement. A typed line is classified DETERMINISTICALLY by the edge
(api/customer/assistant/command); an ``advice`` intent is answered read-only, every other intent advances the
per-(org, session) flow (api/customer/flow). The box runs app.js's OWN functions verbatim on the ui.js kit with a
minimal DOM — nothing is re-implemented here.

Money / safety doctrine the box enforces in the UI (each neuter reds a NAMED test):
  * the whole surface is gated by the page flag — flag off => no screen, #/command is the home screen  -> test_flag_off_*
  * a question is answered as read-only ADVICE; it fires no flow step and launches nothing                 -> test_advice_*
  * a launch STOPS at awaiting_confirm; only an EXPLICIT spend-confirm CLICK reserves, with confirm=true     -> test_launch_*
  * nothing is ever auto-confirmed: the first flow step for a launch carries confirm strictly false          -> test_never_auto_*
  * verify requires the EXPLICIT "I am authorized" checkbox, read live; unticked sends nothing                -> test_verify_*
  * the box NEVER puts org / requester / mfa_at in a body (the edge takes those from the session)             -> test_no_session_*
  * status surfaces the existing activity feed; a control with no running launch is blocked honestly          -> test_status_*, test_control_*
  * an edge error is shown honestly, and a 401 bounces to sign in                                             -> test_error_*
  * the edge writes data-command="1" (default on) / "0" (forced off) into the page                            -> test_edge_writes_*
"""
from __future__ import annotations

import http.client
import json
import os
import re
import subprocess
import threading
from pathlib import Path

import pytest

from test_customer_monitoring_screen import _DOM, _fn, _need_node, _src, _var
from test_customer_onboarding import _page_and_build  # noqa: F401  (reused: the edge-rendered page + build id)

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS = APP / "ui.js"

# app.js's own command-box code, run verbatim.
_CMD_FUNCS = ("pageFlag", "own", "cmdIdem", "cmdAdd", "cmdNote", "cmdSay", "cmdPlanLabel", "cmdError", "cmdKV",
              "cmdAdvice", "cmdVerifyCard", "cmdConfirmCard", "cmdActivityCard", "cmdDomainCard", "cmdRender",
              "cmdFlow", "cmdCommand", "cmdSubmit", "viewCommandBox")
_CMD_VARS = ("API", "COMMAND_ON", "cmdbox")

# The app's world, stubbed: who is signed in, where the page is, what the edge answers, and every call made. A POST
# answer may be a FUNCTION of the body (so one path can answer differently per flow step — confirm=false vs true, or
# method-less challenge vs authorized verify), an ARRAY (a queue), or a plain {data}/{status}/{wait} descriptor.
_WORLD = r"""
document.body.dataset.command = %(flag)s;
let who = { authenticated: true, username: "ana" };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/command" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
const VUI = window.VUI;
const calls = [], toasts = [];
let server = {};            // "GET <path>" / "POST <path>" -> {data}|{status,data}|{wait}|fn(body)|[descriptors]
function deliver(r, key) {
  if (!r) { const e = new Error("404"); e.status = 404; e.data = { error: "not found" }; throw e; }
  if (r.wait) return r.wait;
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data; throw e; }
  return r.data;
}
VUI.getJSON = async p => { calls.push(["GET", p]); return deliver(server["GET " + p], "GET " + p); };
VUI.postJSON = async (p, b) => {
  calls.push(["POST", p, b]);
  let r = server["POST " + p];
  if (typeof r === "function") r = r(b);
  else if (Array.isArray(r)) r = r.shift();
  return deliver(r, "POST " + p);
};
VUI.toast = m => toasts.push(String(m));
const tick = () => new Promise(r => setTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 16; i++) await tick(); };
function show() { document.body.children = []; const v = viewCommandBox(); document.body.appendChild(v); return v; }
function btn(label) { return document.querySelectorAll("button").find(b => b.textContent === label); }
function type(line) { const i = document.querySelector("input.cmd-input"); i.value = line; return i; }
async function submit(line) { type(line); btn("Send").click(); await flush(); }
// every body a POST carried (classify + each flow step), so a test can assert what the box did and did NOT send.
function postBodies(path) { return calls.filter(c => c[0] === "POST" && c[1] === "api/customer/" + path).map(c => c[2]); }
const out = {};
"""


def _harness(flag: str = "1") -> str:
    src = _src()
    return "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", "const h = window.VUI.h;",
                      _WORLD % {"flag": json.dumps(flag)}]
                     + [_fn(src, n) for n in _CMD_FUNCS] + [_var(src, n) for n in _CMD_VARS])


def _node(script: str, *, flag: str = "1") -> dict:
    prog = (_harness(flag) + "\n(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
              " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# representative server replies -------------------------------------------------------------------------------------
_ADVICE = {"intent": "advice", "advice": {"kind": "assistant_advice", "is_advice": True,
                                          "answer": "Fix the admin login first.", "grounded_in": ["f1"],
                                          "finding_count": 2, "document_count": 1, "truncated": False}}
_CHALLENGE = {"intent": "verify", "host": "apme.cm", "state": "verifying",
              "challenge": {"host": "apme.cm", "dns_name": "_vigil-challenge.apme.cm", "dns_value": "vigil=TOK",
                            "well_known_url": "https://apme.cm/.well-known/vigil-site-verification.txt",
                            "well_known_body": "vigil=TOK", "meta_tag": "<meta name=\"vigil-site-verification\" content=\"TOK\">",
                            "marker": "vigil=TOK"}}
_VERIFIED = {"intent": "verify", "host": "apme.cm", "state": "ready", "verified": {"host": "apme.cm", "ok": True}}
_AWAIT = {"intent": "launch", "host": "apme.cm", "state": "awaiting_confirm", "status": "verified",
          "blocked": "confirm the assessment before it reserves credits", "need": "confirm",
          "choices": [{"product_id": "p_quick", "depth": "quick"}, {"product_id": "p_deep", "depth": "deep"}]}
_STARTED = {"intent": "launch", "host": "apme.cm", "state": "running",
            "reserved": {"slug": "sl", "units_reserved": "u", "product_id": "p_quick"}, "started": {"ok": True}}


# --- the flag gate ------------------------------------------------------------------------------------------------
def test_flag_off_the_box_is_inert_and_polls_nothing():
    out = _node(r"""
out.commandOn = COMMAND_ON;      // the route table shows the home screen; the box surface is never built
out.calls = calls.length;
""", flag="0")
    assert out["commandOn"] is False and out["calls"] == 0


def test_flag_on_the_box_renders_its_own_screen_with_a_send_control():
    out = _node(r"""
const view = show();
out.current = view.dataset.current;
out.heading = document.querySelector("h2") ? document.querySelector("h2").textContent : null;
out.hasInput = !!document.querySelector("input.cmd-input");
out.send = btn("Send") ? btn("Send").textContent : null;
out.calls = calls.length;                       // nothing is read on arrival; the box only POSTs on submit
""")
    assert out["current"] == "#/command" and out["heading"] == "Command"
    assert out["hasInput"] and out["send"] == "Send" and out["calls"] == 0


# --- advice (the read-only path) ----------------------------------------------------------------------------------
def test_advice_is_answered_read_only_and_never_touches_the_flow():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: %(advice)s };
show();
await submit("what should I fix first?");
out.answer = document.querySelector("div.cmd-answer") ? document.querySelector("div.cmd-answer").textContent : null;
out.foot = document.querySelectorAll("p.cmd-foot").map(p => p.textContent).join(" ");
out.flowPosts = postBodies("flow").length;      // an advice intent NEVER advances the flow
out.classify = postBodies("assistant/command")[0];
""" % {"advice": json.dumps(_ADVICE)})
    assert out["answer"] == "Fix the admin login first."
    assert "2 of your confirmed findings" in out["foot"] and "never a new finding" in out["foot"]
    assert out["flowPosts"] == 0 and out["classify"] == {"line": "what should I fix first?"}


# --- launch: the money doctrine -----------------------------------------------------------------------------------
def test_launch_stops_at_confirm_and_only_an_explicit_click_reserves():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "launch", host: "apme.cm", depth: "" } };
server["POST api/customer/flow"] = b => b.confirm === true ? { data: %(started)s } : { data: %(await)s };
show();
await submit("launch apme.cm");
out.afterClassify = document.querySelectorAll("button").map(b => b.textContent).find(t => t === "Confirm and launch") || null;
out.firstFlow = postBodies("flow")[0];           // the typed command alone: NO confirm
out.startedBefore = document.body.textContent.indexOf("Assessment started") >= 0;
btn("Confirm and launch").click();
await flush();
out.secondFlow = postBodies("flow")[1];          // the explicit click: confirm=true
out.startedAfter = document.body.textContent.indexOf("Assessment started") >= 0;
""" % {"started": json.dumps(_STARTED), "await": json.dumps(_AWAIT)})
    assert out["afterClassify"] == "Confirm and launch"       # it stopped at awaiting_confirm, showed the button
    assert out["firstFlow"]["confirm"] is False and out["startedBefore"] is False   # nothing reserved yet
    assert out["secondFlow"]["confirm"] is True and out["secondFlow"]["host"] == "apme.cm"
    assert out["secondFlow"]["product_id"] == "p_quick" and out["startedAfter"] is True


def test_never_auto_confirms_a_spend_the_confirm_is_a_strict_boolean():
    # Mutation-sensitive: the first flow step must carry confirm as a real False, never True and never a truthy
    # string — a launch command that auto-confirmed would reserve on the typed line alone.
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "launch", host: "apme.cm", depth: "deep" } };
server["POST api/customer/flow"] = b => b.confirm === true ? { data: %(started)s } : { data: %(await)s };
show();
await submit("deep scan apme.cm");
const first = postBodies("flow")[0];
out.confirmType = typeof first.confirm;
out.confirmValue = first.confirm;
out.flowPosts = postBodies("flow").length;       // exactly ONE step, and it did not reserve
""" % {"started": json.dumps(_STARTED), "await": json.dumps(_AWAIT)})
    assert out["confirmType"] == "boolean" and out["confirmValue"] is False and out["flowPosts"] == 1


# --- verify: the explicit authorization affirmation ---------------------------------------------------------------
def test_verify_requires_the_explicit_authorization_checkbox_and_sends_nothing_without_it():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "verify", host: "apme.cm" } };
server["POST api/customer/flow"] = b => b.authorized === true ? { data: %(verified)s } : { data: %(challenge)s };
show();
await submit("verify apme.cm");
out.challengeShown = !!document.querySelector("div.cmd-verify-card");
out.hasCheckbox = !!document.querySelector("input.cmd-affirm");
out.tokenShown = document.querySelectorAll("code.cmd-kv-v").map(c => c.textContent).indexOf("vigil=TOK") >= 0;
// click Verify WITHOUT ticking: the box must send nothing and nudge honestly
btn("Verify ownership").click();
await flush();
out.verifyPostsUnticked = postBodies("flow").filter(b => b.intent === "verify" && b.method).length;
out.nudged = document.querySelector("div.cmd-note") ? document.querySelector("div.cmd-note").textContent : "";
// now tick the box and Verify: authorized=true goes through, host becomes ready
document.querySelector("input.cmd-affirm").checked = true;
btn("Verify ownership").click();
await flush();
const verifyStep = postBodies("flow").find(b => b.intent === "verify" && b.authorized === true);
out.verifyBody = verifyStep || null;
out.ready = document.body.textContent.indexOf("Ownership verified") >= 0;
""" % {"verified": json.dumps(_VERIFIED), "challenge": json.dumps(_CHALLENGE)})
    assert out["challengeShown"] and out["hasCheckbox"] and out["tokenShown"]
    assert out["verifyPostsUnticked"] == 0 and "authorized" in out["nudged"]
    assert out["verifyBody"] and out["verifyBody"]["authorized"] is True
    assert out["verifyBody"]["method"] == "well-known" and out["verifyBody"]["host"] == "apme.cm"
    assert out["ready"] is True


def test_the_authorized_affirmation_is_a_strict_boolean_in_the_body():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "verify", host: "apme.cm" } };
server["POST api/customer/flow"] = b => b.authorized === true ? { data: %(verified)s } : { data: %(challenge)s };
show();
await submit("verify apme.cm");
const first = postBodies("flow")[0];             // the challenge step: authorized strictly false
out.firstAuthType = typeof first.authorized;
out.firstAuth = first.authorized;
document.querySelector("input.cmd-affirm").checked = true;
btn("Verify ownership").click();
await flush();
const vstep = postBodies("flow").find(b => b.authorized === true);
out.secondAuthType = typeof vstep.authorized;
""" % {"verified": json.dumps(_VERIFIED), "challenge": json.dumps(_CHALLENGE)})
    assert out["firstAuthType"] == "boolean" and out["firstAuth"] is False and out["secondAuthType"] == "boolean"


# --- the session owns org / requester / mfa_at --------------------------------------------------------------------
def test_no_session_fields_are_ever_put_in_a_body_by_the_box():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "launch", host: "apme.cm", depth: "" } };
server["POST api/customer/flow"] = b => b.confirm === true ? { data: %(started)s } : { data: %(await)s };
show();
await submit("launch apme.cm");
btn("Confirm and launch").click();
await flush();
const bodies = calls.filter(c => c[0] === "POST").map(c => c[2]);
const banned = ["org_id", "requester", "username", "mfa_at", "ip"];
out.leaks = bodies.map(b => banned.filter(k => Object.prototype.hasOwnProperty.call(b, k))).filter(x => x.length);
out.bodyCount = bodies.length;
""" % {"started": json.dumps(_STARTED), "await": json.dumps(_AWAIT)})
    assert out["leaks"] == [] and out["bodyCount"] >= 2


# --- status / control ---------------------------------------------------------------------------------------------
def test_status_renders_the_existing_activity_feed():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "status", host: "apme.cm" } };
server["POST api/customer/flow"] = { data: { intent: "status", host: "apme.cm", state: "running", launch: { slug: "sl" },
  activity: { rows: [{ seq: 0, label: "Scanning the surface" }, { seq: 1, label: "Recording the evidence" }] } } };
show();
await submit("status");
out.steps = document.querySelectorAll("li.cmd-step").map(li => li.textContent);
""")
    assert out["steps"] == ["Scanning the surface", "Recording the evidence"]


def test_control_with_no_running_launch_is_blocked_honestly():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { data: { intent: "pause", host: "apme.cm" } };
server["POST api/customer/flow"] = { data: { intent: "pause", host: "apme.cm", state: "ready",
  blocked: "no active assessment on this host to control", need: "running_launch" } };
show();
await submit("pause apme.cm");
out.blocked = document.querySelectorAll("p.cmd-blocked").map(p => p.textContent);
""")
    assert out["blocked"] and "no active assessment" in out["blocked"][0]


# --- honest error surfaces ----------------------------------------------------------------------------------------
def test_error_from_the_edge_is_shown_and_a_401_bounces_to_sign_in():
    out = _node(r"""
server["POST api/customer/assistant/command"] = { status: 403, data: { error: "not your engagement" } };
show();
await submit("launch apme.cm");
out.err = document.querySelectorAll("p.cmd-err").map(p => p.textContent).join(" ");
// a 401 instead: refresh who, then bounce to sign in (no error card)
server["POST api/customer/assistant/command"] = { status: 401, data: { error: "login required" } };
await submit("launch apme.cm");
out.navs = navs;
out.whoRefreshed = whoRefreshes;
""")
    assert "not your engagement" in out["err"]
    assert out["navs"] == ["#/login"] and out["whoRefreshed"] == 1


# --- the edge flag ------------------------------------------------------------------------------------------------
def test_edge_writes_the_command_flag_into_the_page(tmp_path, monkeypatch):
    # DEFAULT ON (same switch as the assistant): unset => "1"; only an explicit off forces "0".
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT", raising=False)
    on, build_on = _page_and_build(tmp_path / "a")
    assert 'data-command="1"' in on and "__VIGIL_COMMAND__" not in on
    for v in ("0", "no", "off", "false"):
        monkeypatch.setenv("VIGIL_CUSTOMER_ASSISTANT", v)
        off, build_off = _page_and_build(tmp_path / f"c{v}")
        assert 'data-command="0"' in off, v
        assert build_off != build_on                              # the flag counts in the build id
