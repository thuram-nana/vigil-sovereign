"""Gate 5 — the hands-on end-to-end validation harness for the WHOLE customer app (HANDOFF §13.2 / §7 / §15.11).

This is NOT a per-screen slice test and it does NOT claim Gate 5 passes. It is the APPARATUS the owner runs to sign
Gate 5 off with evidence: one machine-checkable walk of every customer-app screen that asserts, in one place,

  * NO DEAD ROUTE  — every route app.js knows renders ITS OWN live screen (its own heading, its own reads) — never the
    "being wired" placeholder, never a load error, never a silent fall-back to the Overview — and every top-bar tab,
    CLICKED the way a person clicks it, lands on a real route showing that route's screen;
  * NO DEAD BUTTON — every button on every screen (with representative data, so the real controls render: Buy,
    Launch / Pause, Change role / Remove, Turn on / Turn off, Re-check / Re-issue …) is wired to a click handler and
    enabled (a disabled control is not live, whatever handler it keeps), and each screen's real controls are on it
    LIVE exactly as many times as that data renders them — a label still on the page never makes up for one of a
    same-label pair that stopped rendering, and a label any screen shows more than once is always one it counts;
  * REAL ROUTES    — every read the app fires is a path the keyless edge routes (custui's own route table), and over
    the REAL loopback hop every one of those reads RESOLVES (401 "sign in first" for an anonymous caller — the route is
    present — never 404 "absent"); a flag-off screen's route is genuinely absent (404, fail-closed); merely viewing
    every screen sends no write and nothing leaves through a raw fetch;
  * HONEST REFUSAL — a billing role is told "no" (403) on a testing read, never shown data.

HOW. There is no browser here, so the walk boots the REAL page under a node DOM: exactly the scripts index.html loads,
in its order (ui.js, pwa.js, guide.js, … app.js — read from index.html, so a script a later slice adds is loaded too),
app.js verbatim (no function is extracted, so every page-flag constant — GUIDE_ON, TEAM_ON, MONITORING_ON, LAUNCH_ON,
and any later one — is defined by app.js's own line from the page's data-* flags; none can go stale in a stub). The
page talks to a fake same-origin server (no network: the global fetch is replaced and must never be called), and
navigation behaves as in a browser: assigning location.hash fires hashchange asynchronously.

NAMED STAGES, skip-with-reason. Customer screens land in parallel (§15.11 C/B). Each screen not yet on this branch is
its OWN test that SKIPS with a reason and a TODO naming the screen, and auto-activates — walks the screen and asserts
it is live, its own, and dead-button-free — the moment its route (or control) appears; so the gate is COMPLETE in
shape now and goes green as the slices merge. A new route that no stage claims fails the census test (loud, never a
silent skip).

EVIDENCE. ``VIGIL_GATE5_EVIDENCE=/path/census.json`` writes the per-screen census (status, heading, the live controls
and how many of each, reads, pending stages with their reasons, and the sha256 of every page script walked) for the
sign-off. The owner's full checklist — hands-on and at-scale, each criterion mapped to its automated check or marked
owner-manual — is ``docs/gate5/GATE5-CHECKLIST.md``; guards here keep it in step with the app's routes, the §13.2
journey and the test files it cites.

Mutation-verify targets (each neuter reds a NAMED test here):
  * a button loses its click wiring                    -> test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button
  * a screen silently falls back to the Overview       -> test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button
  * a screen's async render throws                     -> test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button
  * one of a same-label pair stops rendering           -> test_a_real_regression_in_app_js_reds_the_census,
                                                          test_dropping_or_disabling_any_control_reds_its_screen
  * a listed control renders disabled, handler kept    -> test_a_real_regression_in_app_js_reds_the_census,
                                                          test_dropping_or_disabling_any_control_reds_its_screen
  * any other button renders disabled                  -> test_dropping_or_disabling_any_control_reds_its_screen
  * a control renders once more than its data says     -> test_dropping_or_disabling_any_control_reds_its_screen
  * a same-label group no control list counts          -> test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button,
                                                          test_dropping_or_disabling_any_control_reds_its_screen
  * a screen's control list names a route not walked   -> test_the_screen_map_matches_app_routes
  * a top-bar tab points at a route that does not exist -> test_every_top_bar_tab_clicked_lands_on_its_own_screen
  * the app reads a path the edge never routes         -> test_viewing_every_screen_reads_only_edge_routes_and_writes_nothing
  * viewing a screen sends a write                     -> test_viewing_every_screen_reads_only_edge_routes_and_writes_nothing
  * the edge stops serving a read the app makes        -> test_every_read_the_walk_makes_resolves_on_the_real_edge
  * a flag-off route stops being absent                -> test_a_flag_off_screen_route_is_absent
  * a pending screen merges but falls back home        -> test_stage_account_security_screen
  * the checklist drops a screen                       -> test_the_gate5_checklist_covers_every_route_and_the_journey
  * the checklist cites a test file that does not exist -> test_the_checklist_cites_only_test_files_that_exist
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: Part B stands up the stack; keep the shared SIGIL_HOME owner state pristine for the P7 run)

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
REPO = Path(__file__).resolve().parents[3]
CHECKLIST = REPO / "docs" / "gate5" / "GATE5-CHECKLIST.md"
EVIDENCE_ENV = "VIGIL_GATE5_EVIDENCE"


def _need_node() -> str:
    """The node binary (callers use it as argv[0]), or a SKIP where node is absent — except in CI (GITHUB_ACTIONS) or
    where VIGIL_REQUIRE_NODE is set (every CI job that runs this file sets it): there a missing node FAILS, so this
    executed-JS gate can never go green unrun."""
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH: this job must "
                        "EXECUTE the Gate 5 customer walk")
        pytest.skip("node not installed")
    return node


# ---- the screens -------------------------------------------------------------------------------------------------
# Every customer screen MERGED on this branch: route -> (the screen's own <h2>, the reads it fires on arrival). The
# pre-auth screens are walked signed out. The census test keeps (merged | pre-auth | pending stages) == app.js ROUTES.
_SCREENS: dict[str, tuple[str, tuple[str, ...]]] = {
    "#/": ("Overview", ()),
    "#/billing": ("Billing", ("api/customer/billing", "api/customer/billing/offers")),
    "#/billing/return": ("Payment received", ("api/customer/billing",)),
    "#/invoices": ("Invoices", ("api/customer/invoices",)),
    "#/assets": ("Authorized assets", ("api/customer/assets",)),
    "#/assessments": ("Assessments", ("api/customer/assessments", "api/customer/launches")),
    "#/team": ("Team", ("api/customer/members",)),
    "#/connect": ("Connect", ("api/customer/connect",)),
    "#/monitoring": ("Monitoring", ("api/customer/monitoring", "api/customer/monitoring/events")),
    "#/live": ("Live Control", ("api/customer/launches", "api/customer/live/activity")),   # Live Control (steer+watch)
    "#/fix-first": ("Fix first", ("api/customer/posture",)),
    "#/attack-path": ("Attack path", ("api/customer/assessments/findings",)),
    "#/settings": ("Settings", ("api/customer/preferences",)),
    "#/settings/authorizations": ("Authorizations", ("api/customer/authorizations",)),   # legal/governance S12
    "#/privacy": ("Privacy", ("api/customer/privacy",)),                           # legal/governance S2
    "#/data-rights": ("Data rights", ("api/customer/data-rights",)),             # legal/governance S3
    "#/ai-governance": ("How VIGIL uses AI", ("api/customer/ai-governance",)),      # legal/governance S5
    "#/seller-identity": ("Seller identity", ("api/customer/seller-identity",)),      # legal/governance S7
    "#/guide": ("Guide", ()),
    "#/plans": ("Plans", ("api/customer/billing/plans",)),                       # PR-G (Area 6)
    "#/reports": ("Reports", ("api/customer/compliance",)),                       # PR-G: the download is a click
}
_PREAUTH: dict[str, str] = {"#/login": "Sign in", "#/signup": "Create your account",
                            "#/recover": "Reset your password", "#/google-code": "Finish signing in with Google"}
# The controls each screen must SHOW with the representative data below (a prefix ends with a space), and HOW MANY:
# each one LIVE (wired to a click handler and not disabled) exactly as many times as that data renders it. This is what
# makes "no dead button" mean something: the real buttons are on the page, every one of them — not just an empty
# state, and not just their labels (one of a same-label pair that stops rendering, a control left disabled with its
# handler still on, or a row rendered twice, each fails the walk).
_CONTROLS: dict[str, dict[str, int]] = {
    "#/billing": {"Buy ": 1},                                       # the one credit top-up on offer
    "#/billing/return": {"Back to Billing": 1},
    "#/assets": {"Request ownership challenge": 1,
                 "Re-check now": 1,                                 # the pending host: it has a challenge
                 "Re-issue challenge": 2},                          # every host, the verified and the pending one
    "#/assessments": {"Launch": 1,                                  # cust_a: no launch of it in progress
                      "Pause": 1,                                   # cust_b: running, and pause is offered
                      "View findings": 2},                          # every assessment
    "#/team": {"Add member": 1, "Change role": 1, "Remove": 1},     # cust_ben (the founder's row is read-only)
    # Website: Continue a half-finished proof, Prove again a lapsed one, Connect a website; Code repository: Connect
    # GitHub, Open Code; Cloud account: Cancel / Continue a connection not finished, Connect again / Disconnect a lapsed
    # one, Disconnect a connected one, Connect an AWS account
    "#/connect": {"Continue": 2, "Prove again": 1, "Connect a website": 1, "Connect GitHub": 1, "Open Code": 1,
                  "Cancel": 1, "Connect again": 1, "Disconnect": 2, "Connect an AWS account": 1},
    "#/monitoring": {"Turn on Observe": 1, "Turn on Respond": 1,    # b.example: proved, unmonitored, a free slot
                     "Switch to Respond": 1, "Turn off": 1},        # a.example: monitored in Observe
    # Live Control: cust_b is running on b.example (pause offered) -> one Pause; the steer box's one Send to VIGIL.
    # The activity feed rows are <li> steps, not buttons.
    "#/live": {"Pause": 1, "Send to VIGIL": 1},
    "#/attack-path": {"View findings": 1},                          # F1's one chain card (its steps unlisted)
    "#/settings": {"Save": 1, "Account security & sign-in": 1,      # the General tab's one Save; the hub's links
                   "Authorized administrators": 1,
                   "Authorizations": 1,                             # S12: the hub's link to the Authorizations screen
                   "Data rights": 1,                                # S3: the hub's Data-rights link
                   "How VIGIL uses AI": 1,                          # S5: the hub's link to the AI-governance sub-screen
                   "Billing": 2},                                   # the hub's Billing link, and the top bar's tab
    # S12 Authorizations: the representative data has one active authority (no button), one expired authority and one
    # not-authorized host — each non-active host offers a "Request authorization" (the expired one + the pending one).
    "#/settings/authorizations": {"Request authorization": 2},
    "#/data-rights": {"Export my data": 1,                          # S3: the own-data export and the deletion request
                      "Request account deletion": 1},
    "#/guide": {"Replay the welcome tour": 1,
                "Mark as done": 7},   # the open chapter, Get started: six steps + the onlyIfShown Authorizations
                                      # step (listed here because the gate enables VIGIL_CUSTOMER_AUTHORIZATIONS)
    "#/plans": {"Upgrade": 1, "Downgrade": 1, "Cancel plan": 1, "Buy credits on Billing": 1},
    "#/reports": {"Download report": 1, "Download PDF": 1},
    # signed out, the top bar's own Sign in is on every one of these, so the sign-in screen shows that label twice
    "#/login": {"Sign in": 2, "Sign in with a passkey": 1, "Create an account": 1, "Forgot your password?": 1},
    "#/signup": {"Sign in": 1, "Send verification": 1, "I already have a code": 1, "Back to sign in": 1},
    "#/recover": {"Sign in": 1, "Send reset email": 1, "I already have a code": 1, "Back to sign in": 1},
    "#/google-code": {"Sign in": 1, "Back to sign in": 1},          # no Google sign-in is waiting on this device
}
# The pending screens that will add a ROUTE: stage -> (route, its own <h2> or None, its read or None, TODO, why
# pending). The other pending items (Retest, the W6 billing dashboard, the Overview aggregation) live inside merged
# screens and are detected by their controls in the stages below.
_ROUTE_STAGES: dict[str, tuple[str, "str | None", "str | None", str, str]] = {
    "account_security": ("#/security", "Account security", "api/customer/security",
                         "§15.11 C3 — authenticator-app and passkey set-up, passkey sign-in, the step-up prompt",
                         "merged on main as #1147 but not in this branch's base; it auto-activates at the rebase"),
    "code_redpen": ("#/code", None, None,
                    ("§15.11 C6 — Connect GitHub, the repositories, merge-blocking threshold and monthly spending "
                     "limit, System review, Fix this, Disconnect"),
                    "not built yet"),
}
_PENDING_ROUTES = {stage[0] for stage in _ROUTE_STAGES.values()}
# The page flags the walk turns ON (the merged screens). security / passkey are read by no script on this base; they
# switch Account security and passkey sign-in on once #1147 is in the branch. A screen that lands with a NEW flag must
# add it here (its stage then reds loudly — the screen fell back home — until it does). connect / cloudConnect
# (data-connect / data-cloud-connect) switch the Connect screen and its Cloud account tile on.
_WALK_FLAGS = {"onboarding": "1", "launchUi": "1", "monitoring": "1", "liveControl": "1", "team": "1", "security": "1", "passkey": "1",
               "code": "1", "connect": "1", "cloudConnect": "1", "posture": "1", "attackPath": "1", "blindVuln": "1",
               "settings": "1", "authorizations": "1", "privacyCenter": "1", "dataRights": "1", "aiGovernance": "1", "sellerIdentity": "1", "googleSignin": "0", "oidcHandoff": "0", "iosInstall": "0",
               "plans": "1", "reportExport": "1", "compliance": "1"}   # PR-G (Area 6): the last three; S5: aiGovernance; S7: sellerIdentity
# The server switches that serve those screens' routes on the real edge (Part B). Checkout serves billing/offers
# (the Buy section): Gate 5 buys credits, so the gate's configuration has it on. VIGIL_CUSTOMER_CONNECT serves
# api/customer/connect; VIGIL_CUSTOMER_CLOUD_CONNECT is the cloud leg the walk's cloudConnect flag stands for (the edge
# writes data-cloud-connect="1" only with both on). Fix first (PR-B) is served only with its own switch AND its
# master switch, VIGIL_APEX_PRESENTATION.
_GATE5_ENV = ("VIGIL_CUSTOMER_TEAM_UI", "VIGIL_CUSTOMER_MONITORING_ENABLED", "VIGIL_CUSTOMER_LIVE_CONTROL", "VIGIL_CUSTOMER_LAUNCH_UI",
              "VIGIL_CUSTOMER_ONBOARDING", "VIGIL_CUSTOMER_CHECKOUT_ENABLED", "VIGIL_CUSTOMER_SECURITY_UI",
              "VIGIL_CUSTOMER_CONNECT", "VIGIL_CUSTOMER_CLOUD_CONNECT", "VIGIL_CUSTOMER_POSTURE", "VIGIL_APEX_PRESENTATION",
              "VIGIL_CUSTOMER_PLANS", "VIGIL_CUSTOMER_PDF_REPORT", "VIGIL_CUSTOMER_COMPLIANCE_MAP",   # + PR-G
              "VIGIL_CUSTOMER_SETTINGS", "VIGIL_CUSTOMER_AUTHORIZATIONS",   # + S12 (legal/governance)
              "VIGIL_CUSTOMER_PRIVACY_CENTER", "VIGIL_CUSTOMER_DATA_RIGHTS",   # + S2, S3 (legal/governance)
              "VIGIL_CUSTOMER_AI_GOVERNANCE", "VIGIL_CUSTOMER_SELLER_IDENTITY")   # + S5, S7 (legal/governance)


def _page_scripts(app_dir: Path = APP) -> list[str]:
    """The scripts index.html loads, in its order (the edge stamps ?v= digests at serve time; the source has none)."""
    html = (app_dir / "index.html").read_text(encoding="utf-8")
    return [s.split("?", 1)[0] for s in re.findall(r'<script src="([^"]+)"></script>', html)]


def _app_routes(app_dir: Path = APP) -> set[str]:
    """Every route in app.js's own ROUTES table (parsed from source: the single source of truth)."""
    src = (app_dir / "app.js").read_text(encoding="utf-8")
    i = src.index("  var ROUTES = {")
    return set(re.findall(r'^    "(#/[^"]*)": function', src[i:src.index("\n  };", i)], re.M))


def _nav_targets(app_dir: Path = APP) -> set[str]:
    """Every route a top-bar link can point at: navLink(<any label>, "#/...") — a literal label or a computed one (the
    account-name link of #1147)."""
    src = (app_dir / "app.js").read_text(encoding="utf-8")
    return set(re.findall(r'navLink\(\s*[^,()]+?\s*,\s*"(#/[^"]*)"\s*\)', src))


def _edge_get_routes() -> set[str]:
    """Every customer GET path the keyless edge routes, relative to api/customer/: its _READS table plus every path
    its GET router names (flag-gated or not). Parsed from custui itself, so a route a later slice adds is included."""
    import inspect
    from sigil.ui import custui
    named = set(re.findall(r'"/api/customer/([^"]+)"', inspect.getsource(custui.CustomerHandler._route_get)))
    return named | {p[len("/api/customer/"):] for p in custui._READS}


# ---- a node DOM rich enough to BOOT the page -----------------------------------------------------------------------
# A superset of the slice harnesses' _DOM: #id selectors, getElementById, window events, a location whose hash
# assignment fires hashchange asynchronously (as a browser does), history, matchMedia, navigator (with WebAuthn
# CAPABILITY shims — nothing is clicked, so no WebAuthn call is ever made; they only let the passkey controls of #1147
# render so their wiring is checked), storage, a fetch that refuses (no network), and timers that never fire (a poll
# must not loop in the walk).
_GATE5_DOM = r"""
class Node {}
class Text extends Node { constructor(t){super(); this.nodeValue=String(t); this.parentNode=null;} get textContent(){return this.nodeValue;} }
class ClassList { constructor(el){this.el=el;} _get(){return (this.el.className||"").split(/\s+/).filter(Boolean);}
  add(c){const s=this._get(); if(s.indexOf(c)<0)s.push(c); this.el.className=s.join(" ");}
  remove(c){this.el.className=this._get().filter(x=>x!==c).join(" ");} contains(c){return this._get().indexOf(c)>=0;}
  toggle(c,on){ if(on===undefined)on=!this.contains(c); if(on)this.add(c); else this.remove(c); return on; } }
// A form control's `disabled` REFLECTS its content attribute, as in a browser: the kit's h("button", {disabled: true})
// sets the attribute, app code sets btn.disabled = true — either way the control is disabled, and the census sees it.
const DISABLEABLE=new Set(["BUTTON","INPUT","SELECT","TEXTAREA","OPTION","OPTGROUP","FIELDSET"]);
class El extends Node {
  constructor(tag){ super(); this.tagName=String(tag).toUpperCase(); this.attrs={}; this.children=[]; this.dataset={};
    this.style={setProperty(k,v){this[k]=v;}, removeProperty(k){delete this[k];}}; this.className=""; this.id="";
    this.parentNode=null; this.hidden=false; this.classList=new ClassList(this); this.listeners={}; }
  setAttribute(k,v){this.attrs[k]=String(v);}
  getAttribute(k){ if(k.indexOf("data-")===0){const d=k.slice(5).replace(/-([a-z])/g,(_,c)=>c.toUpperCase());
    if(d in this.dataset)return String(this.dataset[d]);} return k in this.attrs?this.attrs[k]:null; }
  removeAttribute(k){delete this.attrs[k];}
  get disabled(){ return DISABLEABLE.has(this.tagName) ? ("disabled" in this.attrs) : this._disabled; }
  set disabled(v){ if(!DISABLEABLE.has(this.tagName)){ this._disabled=v; return; }
    if(v)this.attrs.disabled=""; else delete this.attrs.disabled; }
  appendChild(c){ if(c.parentNode)c.parentNode.removeChild(c); this.children.push(c); c.parentNode=this; return c; }
  removeChild(c){ this.children=this.children.filter(x=>x!==c); c.parentNode=null; return c; }
  replaceChild(n,o){ const i=this.children.indexOf(o); if(i<0)return o; if(n.parentNode)n.parentNode.removeChild(n);
    this.children[i]=n; n.parentNode=this; o.parentNode=null; return o; }
  remove(){ if(this.parentNode)this.parentNode.removeChild(this); }
  get firstChild(){return this.children[0]||null;}
  set textContent(v){ this.children=[]; if(String(v))this.appendChild(new Text(v)); }
  get textContent(){return this.children.map(c=>c.textContent).join("");}
  set innerHTML(v){ this._html=String(v); this.children=[]; }     // the kit's static icons only; never parsed
  get innerHTML(){return this._html||"";}
  addEventListener(t,f){(this.listeners[t]=this.listeners[t]||[]).push(f);}
  removeEventListener(t,f){this.listeners[t]=(this.listeners[t]||[]).filter(x=>x!==f);}
  dispatch(t,ev){(this.listeners[t]||[]).slice().forEach(f=>f(ev||{preventDefault(){}, stopPropagation(){}}));}
  click(){this.dispatch("click");}
  focus(){globalThis.__focused=this;}
  scrollIntoView(){}
  getBoundingClientRect(){return {top:0,left:0,right:0,bottom:0,width:0,height:0};}
  _all(out){this.children.forEach(c=>{if(c instanceof El){out.push(c); c._all(out);}}); return out;}
  querySelectorAll(sel){return this._all([]).filter(e=>matches(e,sel));}
  querySelector(sel){return this.querySelectorAll(sel)[0]||null;}
}
function matches(e,sel){
  const m=sel.match(/^([a-z][a-z0-9]*)?(#[\w-]+)?((?:\.[\w-]+)*)(?:\[([\w-]+)="([^"]*)"\])?$/i);
  if(!m)throw new Error("selector not supported by the Gate 5 DOM: "+sel);
  if(m[1]&&e.tagName!==m[1].toUpperCase())return false;
  if(m[2]&&e.id!==m[2].slice(1))return false;
  const cls=(m[3]||"").split(".").filter(Boolean);
  if(cls.some(c=>!e.classList.contains(c)))return false;
  if(m[4]&&e.getAttribute(m[4])!==m[5])return false;
  return true;
}
globalThis.Node=Node;
globalThis.window=globalThis;
const body=new El("body");
const appRoot=new El("div"); appRoot.id="app"; body.appendChild(appRoot);
function memStore(){const m={}; return {getItem:k=>k in m?m[k]:null, setItem:(k,v)=>{m[k]=String(v);}, removeItem:k=>{delete m[k];}, _m:m};}
const docListeners={};
globalThis.document={
  body, documentElement:body, hidden:false,
  createElement:t=>new El(t), createElementNS:(ns,t)=>new El(t), createTextNode:t=>new Text(t),
  getElementById:id=>body._all([]).filter(e=>e.id===id)[0]||null,
  querySelector:s=>body.querySelector(s), querySelectorAll:s=>body.querySelectorAll(s),
  addEventListener:(t,f)=>{(docListeners[t]=docListeners[t]||[]).push(f);},
  removeEventListener:(t,f)=>{docListeners[t]=(docListeners[t]||[]).filter(x=>x!==f);},
};
const winListeners={};
window.addEventListener=(t,f)=>{(winListeners[t]=winListeners[t]||[]).push(f);};
window.removeEventListener=(t,f)=>{winListeners[t]=(winListeners[t]||[]).filter(x=>x!==f);};
window.dispatchEvent=(ev)=>{(winListeners[ev.type]||[]).slice().forEach(f=>f(ev)); return true;};
function fireWin(type){(winListeners[type]||[]).slice().forEach(f=>f({type}));}
let _hash="#/";
const assigns=[];
globalThis.location={
  get hash(){return _hash;},
  set hash(v){ let n=String(v); if(n&&n[0]!=="#")n="#"+n; if(n!==_hash){ _hash=n; setImmediate(()=>fireWin("hashchange")); } },
  search:"", pathname:"/", href:"http://127.0.0.1/", reload(){}, assign:u=>{assigns.push(String(u));},
};
globalThis.history={replaceState:(s,t,u)=>{ if(typeof u==="string"){const i=u.indexOf("#"); _hash=i>=0?u.slice(i):"";} }};
Object.defineProperty(globalThis,"navigator",{configurable:true, writable:true, value:{standalone:false, userAgent:"node",
  credentials:{create(){return Promise.reject(new Error("no WebAuthn in the walk"));}, get(){return Promise.reject(new Error("no WebAuthn in the walk"));}}}});
window.PublicKeyCredential=function PublicKeyCredential(){};
window.AuthenticatorAttestationResponse=function AuthenticatorAttestationResponse(){};
window.AuthenticatorAttestationResponse.prototype.getPublicKey=function(){return null;};
window.matchMedia=(q)=>({matches:false, media:q, addListener(){}, removeListener(){}, addEventListener(){}, removeEventListener(){}});
Object.defineProperty(globalThis,"localStorage",{value:memStore(),configurable:true,writable:true});
Object.defineProperty(globalThis,"sessionStorage",{value:memStore(),configurable:true,writable:true});
globalThis.indexedDB=undefined;
globalThis.Audio=class{constructor(){} play(){return Promise.resolve();}};
const fetches=[];
globalThis.fetch=(u)=>{fetches.push(String(u)); return Promise.reject(new Error("no network in the Gate 5 walk"));};
globalThis.setTimeout=(fn,ms)=>({fn,ms});
globalThis.clearTimeout=()=>{};
globalThis.setInterval=(fn,ms)=>({fn,ms});
globalThis.clearInterval=()=>{};
globalThis.requestAnimationFrame=()=>0;
const errors=[];
process.on("unhandledRejection",e=>{errors.push(String(e&&e.stack||e));});
const tick=()=>new Promise(r=>setImmediate(r));    // a real event-loop turn, independent of the stubbed timers
"""


def _connect_challenge(host: str, token: str) -> dict:
    """A site's outstanding challenge exactly as ``asset_ownership.assets_overview`` projects it into the Connect read:
    the three placements and the marker (``vigil-site-verification=<token>``; the meta tag carries the bare token)."""
    marker = "vigil-site-verification=" + token
    return {"dns_name": "_vigil-challenge." + host, "dns_value": marker,
            "well_known_url": "https://" + host + "/.well-known/vigil-site-verification.txt", "well_known_body": marker,
            "meta_tag": '<meta name="vigil-site-verification" content="' + token + '">', "marker": marker}


# What a signed-in founder's workspace answers: enough that every merged screen's real controls render (a credit
# top-up to buy, a verified and a pending host, an assessment ready to launch and one running, a teammate, a site
# proven / lapsed / half-proven with a connected repository and an AWS account connected / lapsed / not finished, a
# monitored and an unmonitored host on a plan, an invoice). Catalog-shaped (the processor's own amount for a pack); no
# figure for what an assessment costs anywhere.
_FAKE_SERVER = {
    "api/customer/onboarding": {"ok": True, "state": "done"},
    "api/customer/data-rights": {"ok": True, "sla_days": 30, "contact": "info@sigilsovereign.com", "requests": []},
    "api/customer/notifications": {"notifications": [], "count": 0},
    "api/customer/billing": {"org_id": "org_acme", "active": False, "subscription": None,
                             "credits": {"available": 12, "persistent": 10, "plan_live": 2},
                             "wallet": {"granted": 20, "debited": 8, "available": 12}},
    "api/customer/billing/offers": {"has_active_plan": False, "plan_checkout_pending": False,
                                    "has_monitoring_plan": False, "monitoring_checkout_pending": False,
                                    "offers": [{"price_id": "price_topup", "name": "Credit top-up",
                                                "kind": "topup_purchased", "credits": 50, "amount_minor": 500,
                                                "currency": "usd"}]},
    "api/customer/billing/usage": {"scans": []},
    "api/customer/invoices": {"count": 1, "invoices": [{"issued_at": 1700000000, "kind": "topup_purchased",
                                                        "price_id": "price_topup", "amount_minor": 500,
                                                        "currency": "usd", "credits": 50}]},
    "api/customer/assets": {"assets": [
        {"host": "a.example", "status": "verified", "method": "dns_txt", "verified_at": 1700000000,
         "expires_at": 1800000000},
        {"host": "p.example", "status": "pending",
         "challenge": {"host": "p.example", "dns_name": "_vigil-challenge.p.example", "token": "t"}}]},
    "api/customer/assessments": {"assessments": [{"slug": "cust_a", "host": "a.example", "findings": 2},
                                                 {"slug": "cust_b", "host": "b.example", "findings": 0}]},
    # the Attack-path screen reads this on arrival (PR-L); a finding carrying the inert attack_path chain so the
    # SVG narrative + "View findings" control render (and an oob_attestation so the blind-vuln badge has data).
    "api/customer/assessments/findings": {"count": 1, "findings": [
        {"engagement_slug": "cust_a", "finding_ref": "F1", "bug_class": "ssrf", "surface": "https://a.example/in",
         "severity": "critical", "title": "SSRF to cloud metadata", "confidence": "high",
         "attack_path": {"schema": 1, "destination": "customer records in S3", "impact": "data access",
                         "steps": [{"src": "unauthenticated request", "edge": "SSRF", "dst": "cloud metadata",
                                    "technique": "169.254.169.254", "oracle": "ssrf_oob_oracle", "finding_ref": "F1"},
                                   {"src": "cloud metadata", "edge": "credential theft", "dst": "IAM credentials",
                                    "oracle": "metadata_read_oracle", "finding_ref": "F1"},
                                   {"src": "IAM credentials", "edge": "s3:GetObject", "dst": "S3 object read",
                                    "oracle": "s3_read_oracle", "finding_ref": "F2"}]},
         "oob_attestation": {"schema": 1, "method": "dns", "collector_key_id": "oob-collector-ed25519-7f3a",
                             "canary": "a1b2c3d4e5f6", "received_at": 1700000000,
                             "receipt_digest": "sha256:9c1e4f2a7b8d"}}]},
    "api/customer/launches": {"org_id": "org_acme", "pause_resume": True,
                              "launches": [{"slug": "cust_b", "host": "b.example", "launch": "n1", "state": "running",
                                            "depth": "quick", "actions": ["pause"], "lease": {}}],
                              "finished": [{"slug": "cust_a", "launch": "n0", "state": "completed", "ended_at": 10}],
                              "choices": [{"product_id": "vigil_launch_quick", "depth": "quick"},
                                          {"product_id": "vigil_launch_deep", "depth": "deep"}]},
    # Live Control's customer-safe activity feed for the running engagement (cust_b): phase transitions only, no secrets
    # or target detail. The screen reads this on arrival for the running host (query-stripped key matches any ?host=…).
    "api/customer/live/activity": {"ok": True, "slug": "cust_b", "cursor": 1, "rows": [
        {"seq": 0, "ts": 1700000000.0, "phase": "scan", "label": "Scanning the surface", "status": "started"},
        {"seq": 1, "ts": 1700000001.0, "phase": "scan", "label": "Scanning the surface", "status": "completed"}]},
    "api/customer/members": {"org_id": "org_acme", "members": [
        {"username": "cust_ana", "email": "ana@acme.com", "role": "founder"},
        {"username": "cust_ben", "email": "ben@acme.com", "role": "analyst", "since": 1700000000}]},
    # Connect: the real Provisioner.customer_connect_overview shape — connect.connect_overview's three legs (sites =
    # assets_overview rows, each still carrying its challenge; repos = the allowlisted row with the one-way slug; cloud
    # = cloud_overview rows, a not-finished one carrying only provider + account) plus `available`, every flow on, so
    # each tile renders its real buttons (90-day proofs and grants, as the registries record them).
    "api/customer/connect": {
        "org_id": "org_acme",
        "sites": [
            {"host": "a.example", "method": "dns-txt", "verified_at": 1700000000.0, "expires_at": 1800000000.0,
             "status": "verified", "challenge": _connect_challenge("a.example", "ta")},
            {"host": "c.example", "method": "dns-txt", "verified_at": 1692224000.0, "expires_at": 1700000000.0,
             "status": "expired", "challenge": _connect_challenge("c.example", "tc")},
            {"host": "p.example", "status": "pending", "challenge": _connect_challenge("p.example", "t")}],
        "repos": [{"repo": "github.com/acme/api", "slug": "cust_cb6a4aaca84a658370d13b8b",
                   "block_threshold": "critical_high", "monthly_limit_credits": 0}],
        "cloud": [
            {"provider": "aws", "account_id": "111111111111",
             "role_ref": "arn:aws:iam::111111111111:role/VigilSecurityAudit", "verified_at": 1792224000.0,
             "expires_at": 1800000000.0, "access": "read-only", "status": "connected"},
            {"provider": "aws", "account_id": "222222222222",
             "role_ref": "arn:aws:iam::222222222222:role/VigilSecurityAudit", "verified_at": 1692224000.0,
             "expires_at": 1700000000.0, "access": "read-only", "status": "expired"},
            {"provider": "aws", "account_id": "333333333333", "access": "read-only", "status": "pending"}],
        "available": {"site_check": True, "site_auto_recheck": True, "repos": True, "repo_connect": True,
                      "cloud_connect": True}},
    "api/customer/monitoring": {"org_id": "org_acme", "can_manage": True,
                                "grants": [{"host": "a.example", "mode": "observe", "not_before": 1.0,
                                            "not_after": 1800000000.0, "active": True}],
                                "hosts": [{"host": "b.example", "expires_at": 1800086400.0},
                                          {"host": "a.example", "expires_at": 1800000000.0}],
                                "plan": {"host_slots": 5, "respond": True, "period_end": 1800000000.0}},
    "api/customer/monitoring/events": {"org_id": "org_acme", "events": []},
    "api/customer/security": {"ok": True, "totp": False, "passkeys": [], "account_name": "ana@acme.com"},
    # the Settings hub's General tab (legal/governance S1): the account's stored legal-entity / contact profile
    "api/customer/preferences": {"ok": True, "preferences": {
        "legal_entity_name": "Acme SAS", "registered_address": "1 Example Street, Example City",
        "contractual_contact_email": "legal@acme.com", "emergency_contact_name": "Dana Ops",
        "emergency_contact_phone": "+1 555 0100", "emergency_contact_email": "soc@acme.com"}},
    # S12 the read-only Authorizations surface: one ACTIVE owner-signed authority (no button), one EXPIRED and one
    # NOT-authorized host — so two hosts offer "Request authorization"; one of them already has an open review request.
    "api/customer/authorizations": {"org_id": "org_acme", "can_request": True, "requested": ["p.example"], "authorities": [
        {"host": "a.example", "slug": "cust_a1", "authorized": True, "bound": True, "verified": True, "trusted": True,
         "active": True, "scope": ["a.example"], "environment": "live", "not_before": "2024-01-01T00:00:00+00:00",
         "not_after": "2099-01-01T00:00:00+00:00", "allow_destructive": False, "live_destructive_acknowledged": False,
         "issued_by": "customer:org_acme", "note": ""},
        {"host": "c.example", "slug": "cust_c1", "authorized": True, "bound": True, "verified": True, "trusted": True,
         "active": False, "scope": ["c.example"], "environment": "live", "not_before": "2024-01-01T00:00:00+00:00",
         "not_after": "2024-02-01T00:00:00+00:00", "allow_destructive": False, "live_destructive_acknowledged": False,
         "issued_by": "customer:org_acme", "note": ""},
        {"host": "p.example", "slug": "cust_p1", "authorized": False, "active": False}]},
    # the Privacy centre (legal/governance S2): the published cookie inventory, subprocessor list and the links to the
    # full pages, exactly as privacy_center_store reads them from the public pages (org-independent, read-only).
    "api/customer/privacy": {"ok": True,
        "cookies": [{"name": "sigil_session", "purpose": "Operator/owner console session", "category": "Strictly necessary"},
                    {"name": "vigil_customer_session", "purpose": "Customer-plane session (hosted mode)", "category": "Strictly necessary"},
                    {"name": "OIDC binding cookie", "purpose": "Binds a sign-in flow to your browser (anti-CSRF), short-lived", "category": "Strictly necessary"}],
        "cookie_summary": {"strictly_necessary": 3, "optional": 0,
                           "note": "Short version: the product uses only strictly-necessary session cookies, so there's nothing to consent to."},
        "subprocessors": [{"name": "Amazon Web Services (AWS)", "detail": "Amazon Web Services (AWS), eu-west-1 (Ireland) — hosting, encrypted backups, and account email."},
                          {"name": "Cloudflare", "detail": "Cloudflare — DNS, content delivery and DDoS protection."},
                          {"name": "Stripe", "detail": "Stripe — card payments in US dollars."},
                          {"name": "Google", "detail": "Google — sign-in, only if you choose Continue with Google."},
                          {"name": "GitHub", "detail": "GitHub — only if you connect a repository for code review."},
                          {"name": "Anthropic", "detail": "Anthropic (Claude API) — the AI features."}],
        "links": {"cookies": "/cookies", "privacy": "/privacy", "trust": "/trust"}},
    # the Seller identity screen (legal/governance S7): the GLOBAL published seller-identity block (ui/seller_identity.py)
    "api/customer/seller-identity": {"ok": True, "seller": {
        "legal_name": "SIGIL SARL", "legal_name_expansion": "Sovereign Integrity Governance Infrastructure Labs",
        "legal_form": "Société à responsabilité limitée (SARL)", "registered_city": "Buea",
        "registered_country": "Cameroon", "registration_number": "RCCM RC.BUA.2026.B.0190",
        "contact_email": "info@sigilsovereign.com", "website": "sigilsovereign.com",
        "governing_law": "the laws of the Republic of Cameroon, including the applicable OHADA Uniform Acts"}},
    # PR-B Fix first: one verified host tested — two open findings worst first (the critical one with its signed
    # plain-language parts and fix), one a retest proved fixed, the first six weeks not measured yet. The scores are the
    # server's own arithmetic over these severities (100 x 100 // (100 + 45 + 22 [+ 9 while the medium was open])).
    "api/customer/posture": {
        "org_id": "org_acme", "measured": True, "posture_score": 59, "hosts_total": 1, "findings_total": 3,
        "open_total": 2, "fixed_total": 1,
        "severity_counts": {"critical": 1, "high": 1, "unrated": 0, "medium": 0, "low": 0, "info": 0},
        "fix_first": [
            {"finding_ref": "sqli-login", "engagement_slug": "cust_a", "bug_class": "sqli",
             "surface": "https://a.example/login", "title": "SQL injection at /login", "severity": "critical",
             "severity_basis": "certificate", "priority_score": 1.6667, "effort": "L", "tier": 1,
             "tier_label": "Tier 1", "presentation_signed": True,
             "standards_chips": [{"framework": "owasp", "label": "OWASP Top 10", "version": "OWASP Top 10:2021",
                                  "ids": ["A03:2021"]},
                                 {"framework": "cwe", "label": "CWE", "version": "CWE 4.x", "ids": ["CWE-89"]}],
             "plain_impact": {"what": "The sign-in form builds a database query from what a visitor types.",
                              "category_consequence": "Someone could read or change the data the database holds.",
                              "established": "that the sign-in form's input changed the database query's result.",
                              "description_on_file": True},
             "remediation": "Pass `username` to the query as a bound parameter on `POST /login`.",
             "oracle_context_digest": "d-sqli", "host": "a.example", "status": "open"},
            {"finding_ref": "xss-search", "engagement_slug": "cust_a", "bug_class": "xss",
             "surface": "https://a.example/search", "title": "Reflected XSS at /search", "severity": "high",
             "severity_basis": "certificate", "priority_score": 2.0, "effort": "M", "tier": 1, "tier_label": "Tier 1",
             "presentation_signed": False, "oracle_context_digest": "d-xss", "host": "a.example", "status": "open",
             "standards_chips": [{"framework": "owasp", "label": "OWASP Top 10", "version": "OWASP Top 10:2021",
                                  "ids": ["A03:2021"]}]}],
        "fixed": [{"finding_ref": "redir-go", "engagement_slug": "cust_a", "bug_class": "open_redirect",
                   "title": "Open redirect at /go", "severity": "medium", "host": "a.example", "status": "fixed",
                   "status_at": 1798000000.0}],
        "standards_summary": {"frameworks": [{"framework": "owasp", "label": "OWASP Top 10",
                                              "version": "OWASP Top 10:2021", "findings": 2}]},
        "trend": {"points": [{"at": 1792800000 + 604800 * k, "posture_score": None if k < 6 else (56 if k < 8 else 59),
                              "open": 0 if k < 6 else (3 if k < 8 else 2), "fixed": 0 if k < 8 else 1}
                             for k in range(12)],
                  "step_seconds": 604800, "current": 59, "since": 1792800000 + 604800 * 6, "change": 3},
        "basis": {"method": "100 × 100 // (100 + Σ severity penalties) over the org's OPEN oracle-confirmed findings",
                  "weights": {"critical": 45, "high": 22, "unrated": 12, "medium": 9, "low": 3, "info": 1},
                  "counts_fixes": True, "note": "an honest heuristic for prioritising, not a measured or certified rating"},
        "generated_from": "proven_findings"},
    # PR-G (Area 6): a workspace on the middle plan (so Upgrade, Downgrade and Cancel plan all render), and the
    # standards mapping of one proven finding. Catalog-shaped prices; nothing about what an assessment costs.
    "api/customer/billing/plans": {
        "org_id": "org_acme", "can_manage": True, "scheduled_change": None, "depths": [],
        "current": {"plan_id": "pro", "status": "active", "period_end": 1800000000.0, "credits_per_period": 6000,
                    "active": True, "price_id": "price_pro", "name": "Pro (monthly)", "amount_minor": 9900,
                    "currency": "USD", "period_days": 30.0, "retired": False},
        "trial": {"credits": 100, "had_trial": True, "preview_locked": False, "rules": ["One trial per workspace."]},
        "pay_as_you_go": {"packs": [{"price_id": "price_topup", "name": "Credit top-up", "credits": 50,
                                     "amount_minor": 500, "currency": "USD"}], "rules": ["Bought credits never expire."]},
        "tiers": [{"id": p, "price_id": p, "name": n, "amount_minor": a, "currency": "USD", "credits_per_period": c,
                   "period_days": 30.0, "current": act == "current", "scheduled": False, "action": act, "rules": []}
                  for p, n, a, c, act in (("price_research", "Research (monthly)", 2900, 2000, "downgrade"),
                                          ("price_pro", "Pro (monthly)", 9900, 6000, "current"),
                                          ("price_team", "Team (monthly)", 29900, 20000, "upgrade"))],
        "actions": {"checkout": False, "change": True, "cancel": True, "change_unavailable_reason": "",
                    "plan_checkout_pending": False}},
    "api/customer/compliance": {
        "org_id": "org_acme", "findings_total": 1, "generated_from": "proven_findings", "findings_elsewhere": [],
        "statement": "x",
        "frameworks": [{"framework": "owasp", "label": "OWASP Top 10", "version": "OWASP Top 10:2021", "summary": {},
                        "controls": [{"id": "A03:2021", "name": "Injection", "status": "weakness_proven",
                                      "findings": [{"finding_ref": "f1", "title": "SQL injection",
                                                    "host": "a.example", "retest": None}]}]}]},
    # S5: the AI / human-in-the-loop governance disclosure (ui/ai_governance) — the fixed statement and the cited
    # sections. A pure display: no control, so the screen adds no button to the census.
    "api/customer/ai-governance": {
        "ok": True, "org_id": "org_acme",
        "statement": "VIGIL uses AI to assist and advise — never as an authority.",
        "sections": [{"title": "What AI does",
                      "points": [{"text": "Parts of the Service use AI models to plan and prioritise testing.",
                                  "source": "Terms of Service, §11"}]},
                     {"title": "What AI never does",
                      "points": [{"text": "AI never decides what you are charged or which hosts you may test.",
                                  "source": "Terms of Service, §11"}]}]},
}


def _boot_program(*, authed: bool, flags: dict, routes: "list[str] | None" = None, click_tabs: bool = False,
                  probes: "dict[str, list[str]] | None" = None, app_dir: Path = APP) -> str:
    """A node program that boots the page under the DOM above (every script index.html loads, in order; the kit's
    network replaced right after ui.js, before any script captures it), signed in or not, then either walks
    ``routes`` (assigning location.hash, as a link would) or clicks every top-bar tab, and prints the census. On each
    walked route that ``probes`` names (route -> its listed controls) it also makes, one at a time and each undone
    before the next, the regressions the census must catch (probeScreen), each with its own snapshot."""
    who = ({"authenticated": True, "username": "cust_ana", "org_id": "org_acme"} if authed
           else {"authenticated": False})
    probe_spec = json.dumps(probes or {})
    loads = "\n".join(f"require({json.dumps(str(app_dir / s))}); loaded.push({json.dumps(s)}); installNet();"
                      for s in _page_scripts(app_dir))
    return _GATE5_DOM + f"""
const FLAGS={json.dumps(flags)};
for (const k in FLAGS) body.dataset[k]=FLAGS[k];
body.dataset.build="gate5";     // not a 12-hex build id: pwa.js never asks the edge for version.json
const SERVER={json.dumps(_FAKE_SERVER)};
const WHO={json.dumps(who)};
const calls=[], unknown=[], loaded=[];
let netInstalled=false;
function installNet(){{
  if(netInstalled||!window.VUI) return;
  netInstalled=true;
  window.VUI.getJSON=async(p)=>{{
    calls.push(["GET",p]);
    const k=String(p).split("?")[0];
    if(k==="api/customer/whoami") return JSON.parse(JSON.stringify(WHO));
    if(Object.prototype.hasOwnProperty.call(SERVER,k)) return JSON.parse(JSON.stringify(SERVER[k]));
    unknown.push(k); return {{}};
  }};
  window.VUI.postJSON=async(p,b)=>{{calls.push(["POST",p]); return {{ok:true}};}};
}}
{loads}
const PLACEHOLDER="is being wired to this workspace";
async function settle(){{ let n=-1; for(let i=0;i<12&&n!==calls.length;i++){{ n=calls.length; await tick(); await tick(); }} }}
// LIVE = wired (a click handler, or a submit) AND enabled: a disabled control is not live, whatever handler it keeps.
const wired=b=>!!(b.listeners.click&&b.listeners.click.length) || (b.getAttribute("type")||"button")==="submit";
function snap(r, before){{
  const btns=appRoot.querySelectorAll("button"), label=b=>b.textContent;
  const txt=appRoot.textContent, h2=appRoot.querySelector("h2");
  return {{route:r, hash:location.hash, heading:h2?h2.textContent:null, nonEmpty:txt.length>0,
          placeholder:txt.indexOf(PLACEHOLDER)>=0, loadError:txt.indexOf("Could not load")>=0,
          roleDenied:txt.indexOf("Your role does not have access")>=0, buttons:btns.map(label),
          deadButtons:btns.filter(b=>!wired(b)).map(label),
          disabledButtons:btns.filter(b=>b.disabled===true).map(label),
          liveButtons:btns.filter(b=>wired(b)&&b.disabled!==true).map(label),
          reads:calls.slice(before).filter(c=>c[0]==="GET").map(c=>c[1].split("?")[0]), text:txt.slice(0,3000)}};
}}
const PROBES={probe_spec};
const isControl=(b,w)=>b.textContent===w||(w.endsWith(" ")&&b.textContent.startsWith(w));
// A wired twin of button b, right after it (the same label, rendered once more); the caller removes it.
function twinOf(b){{ const par=b.parentNode, t=document.createElement("button");
  t.setAttribute("type","button"); t.textContent=b.textContent; t.addEventListener("click",()=>{{}});
  par.children.splice(par.children.indexOf(b)+1,0,t); t.parentNode=par; return t; }}
// The regressions the census must catch, made on the rendered screen one at a time, each undone before the next: for
// each listed control, ONE of its buttons dropped (a row that stops rendering it), ONE disabled while it keeps its
// click handler, and ONE rendered twice; then some other button of the screen (none listed) disabled, and that same
// button rendered twice (a same-label group no list counts).
function probeScreen(r, before, wants){{
  const out={{controls:{{}}, other:null}};
  const find=w=>appRoot.querySelectorAll("button").filter(b=>isControl(b,w));
  for(const w of wants){{
    const p={{}};
    let m=find(w);
    if(m.length){{ const b=m[m.length-1], par=b.parentNode, i=par.children.indexOf(b);
      par.removeChild(b); p.drop=snap(r,before); par.children.splice(i,0,b); b.parentNode=par; }}
    m=find(w);
    if(m.length){{ const b=m[0], was=b.disabled; b.disabled=true; p.disable=snap(r,before); b.disabled=was; }}
    m=find(w);
    if(m.length){{ const t=twinOf(m[0]); p.extra=snap(r,before); t.remove(); }}
    out.controls[w]=p;
  }}
  const o=appRoot.querySelectorAll("button").filter(b=>!wants.some(w=>isControl(b,w)))[0];
  if(o){{ const was=o.disabled; o.disabled=true;
    out.other={{label:o.textContent, disable:snap(r,before)}}; o.disabled=was;
    const t=twinOf(o); out.other.twin=snap(r,before); t.remove(); }}
  out.after=snap(r,before);
  return out;
}}
(async()=>{{
  await settle();                                   // boot: refreshWho resolves, the first screen renders
  const census={{}}, tabs=[], probes={{}};
  for(const r of {json.dumps(routes or [])}){{
    const before=calls.length;
    location.hash=r; await settle();
    census[r]=snap(r, before);
    if(Object.prototype.hasOwnProperty.call(PROBES,r)) probes[r]=probeScreen(r, before, PROBES[r]);
  }}
  if({json.dumps(click_tabs)}){{
    const topLabels=()=>{{ const bar=appRoot.querySelector("div.cust-topbar");
      return bar?bar.querySelectorAll("button.cust-nav-link").map(b=>b.textContent):[]; }};
    for(const label of topLabels()){{
      if(label.indexOf("Sign out")===0) continue;     // signing out is a separate journey; its wiring is checked above
      const bar=appRoot.querySelector("div.cust-topbar");
      const btn=bar.querySelectorAll("button.cust-nav-link").filter(b=>b.textContent===label)[0];
      const before=calls.length;
      btn.click(); await settle();
      const s=snap(label, before); s.label=label; tabs.push(s);
    }}
  }}
  process.stdout.write(JSON.stringify({{census, tabs, probes, calls, unknown, fetches, errors, assigns, loaded}}));
}})().catch(e=>{{ console.error("GATE5 BOOT/WALK FAILED:", e&&e.stack||e); process.exit(3); }});
"""


def _walk(*, authed: bool = True, routes: "list[str] | None" = None, click_tabs: bool = False,
          flags: "dict | None" = None, probes: "dict[str, list[str]] | None" = None, app_dir: Path = APP) -> dict:
    prog = _boot_program(authed=authed, flags=flags or _WALK_FLAGS, routes=routes, click_tabs=click_tabs,
                         probes=probes, app_dir=app_dir)
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _count(labels: list[str], want: str) -> int:
    """How many of ``labels`` are the control ``want``: its exact label, or — when ``want`` ends with a space, a
    prefix — every label it begins ("Buy " is each Buy button, whatever amount it names)."""
    return sum(1 for b in labels if b == want or (want.endswith(" ") and b.startswith(want)))


def _screen_problems(c: dict, heading: "str | None", reads: tuple[str, ...] = (),
                     controls: "dict[str, int] | None" = None) -> list[str]:
    """Everything that makes a walked screen NOT its own live, wired screen (an empty list = it is). Each control in
    ``controls`` must be on it LIVE (wired and enabled) exactly as many times as its data renders it — a COUNT of live
    buttons, never a label match, so one of a same-label pair gone, a disabled one that keeps its handler, or one too
    many is a problem. A label the screen shows more than once must be one of those counted controls: an uncounted
    same-label group is a problem in itself (one of its buttons could stop rendering behind the others' label). And no
    button may be dead or disabled (a disabled control is not live)."""
    bad = []
    if not c["nonEmpty"]:
        bad.append("rendered nothing")
    if c["placeholder"]:
        bad.append("is the 'being wired' placeholder")
    if c["loadError"]:
        bad.append("showed 'Could not load'")
    if c["roleDenied"]:
        bad.append("role-denied the founder")
    if heading is not None and c["heading"] != heading:
        bad.append(f"shows {c['heading']!r}, not its own {heading!r} (a fall-back to another screen?)")
    if heading is None and c["route"] != "#/" and c["heading"] in (None, "Overview"):
        bad.append(f"shows {c['heading']!r} — it fell back to the Overview")
    missing_reads = [p for p in reads if p not in c["reads"]]
    if missing_reads:
        bad.append(f"never read {missing_reads}")
    for want, n in (controls or {}).items():
        live = _count(c["liveButtons"], want)
        if live != n:
            why = [f"{k} {what}" for k, what in ((_count(c["disabledButtons"], want), "disabled"),
                                                 (_count(c["deadButtons"], want), "unwired")) if k]
            bad.append(f"shows {live} live {want!r} control(s), not the {n} its data renders"
                       + (f" ({', '.join(why)})" if why else "") + f" (buttons: {c['buttons']})")
    for label, k in sorted(Counter(c["buttons"]).items()):
        if k >= 2 and not any(_count([label], want) for want in (controls or {})):
            bad.append(f"shows {k} {label!r} buttons, a same-label group no listed control counts: list it in "
                       "_CONTROLS with the number its data renders")
    if c["deadButtons"]:
        bad.append(f"has dead button(s) {c['deadButtons']}")
    if c["disabledButtons"]:
        bad.append(f"has disabled button(s) {c['disabledButtons']}: a disabled control is not live")
    return bad


# =====================================================================================================================
# Part A — the page, walked: no dead route, no dead button, real routes only (executed under node)
# =====================================================================================================================
def test_the_walk_boots_every_script_the_page_loads():
    """Positive control: the walk loaded exactly index.html's scripts, in order (the kit first, app.js last), each a
    real shipped file — so it walks the page a browser gets, not a partial or stub copy — and nothing went to the
    network."""
    scripts = _page_scripts()
    assert scripts[0] == "ui.js" and scripts[-1] == "app.js", scripts
    assert all((APP / s).is_file() and (APP / s).stat().st_size > 500 for s in scripts), scripts
    out = _walk(routes=["#/"])
    assert out["loaded"] == scripts
    assert out["fetches"] == [] and out["errors"] == []


def test_the_screen_map_matches_app_routes():
    """The census: (merged screens | pre-auth screens | pending stages that have merged) == app.js ROUTES — a route a
    new slice adds fails here until the walk covers it or a stage claims it, so no live screen can go unwalked. And
    every screen _CONTROLS lists controls for is one a walk visits: a misspelt route would leave its controls, and
    their counts, checked nowhere."""
    routes = _app_routes()
    covered = set(_SCREENS) | set(_PREAUTH) | (_PENDING_ROUTES & routes)
    assert routes - covered == set(), (f"app.js route(s) {sorted(routes - covered)} are neither walked nor a pending "
                                       "stage: add each to _SCREENS / _PREAUTH (merged) or to _ROUTE_STAGES (pending)")
    walked = set(_SCREENS) | set(_PREAUTH)
    assert walked <= routes, f"walked route(s) app.js no longer has: {sorted(walked - routes)}"
    unwalked = set(_CONTROLS) - walked - _PENDING_ROUTES
    assert unwalked == set(), f"_CONTROLS lists the controls of route(s) no walk visits: {sorted(unwalked)}"


def test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button():
    """Signed in, every merged screen shows ITS OWN screen (its heading, its reads), never the placeholder, a load
    error or a role refusal; its real controls are on the page, each LIVE exactly as many times as its data renders
    it; every button is wired and enabled; no async render threw."""
    out = _walk(routes=list(_SCREENS))
    problems = {r: _screen_problems(out["census"][r], heading, reads, _CONTROLS.get(r))
                for r, (heading, reads) in _SCREENS.items()}
    assert {r: p for r, p in problems.items() if p} == {}
    assert out["errors"] == [], out["errors"]


_BUTTON_KEYS = ("buttons", "liveButtons", "disabledButtons", "deadButtons")


def test_dropping_or_disabling_any_control_reds_its_screen():
    """The census is count- and disabled-aware, exercised in the walk itself on every screen of _SCREENS and _PREAUTH
    (the merged #/security and #/code screens are covered by their stage tests and the tab walk, not by this probe). On
    each probed screen,
    for each listed control in turn: ONE of its buttons dropped (a row that stops rendering it — for a control its data
    renders twice, its label is still on the page), ONE disabled while it keeps its click handler (it is still wired),
    and ONE rendered twice; then some other button of the screen disabled, and that button rendered twice (a
    same-label group no list counts). Each regression reds that screen, naming it; the untouched screen passes, and is
    untouched again after every probe. A label-only census passes the dropped one of a pair and every one rendered
    twice; a wiring-only census passes every disabled one."""
    walks = (
        (_walk(routes=list(_SCREENS), probes={r: list(_CONTROLS.get(r, {})) for r in _SCREENS}),
         {r: (heading, reads) for r, (heading, reads) in _SCREENS.items()}),
        (_walk(authed=False, routes=list(_PREAUTH), probes={r: list(_CONTROLS.get(r, {})) for r in _PREAUTH}),
         {r: (heading, ()) for r, heading in _PREAUTH.items()}),
    )
    pairs = {(r, w) for r, want in _CONTROLS.items() for w, n in want.items() if n >= 2}
    assert pairs, "no screen's data renders a control twice: dropping one of a same-label pair would go unexercised"
    dropped_pairs, others = set(), []
    for out, screens in walks:
        assert out["errors"] == [], out["errors"]
        for r, (heading, reads) in screens.items():
            want, clean, probe = _CONTROLS.get(r, {}), out["census"][r], out["probes"][r]
            assert _screen_problems(clean, heading, reads, want) == [], r
            assert {k: probe["after"][k] for k in _BUTTON_KEYS} == {k: clean[k] for k in _BUTTON_KEYS}, r
            for w, n in want.items():
                p = probe["controls"][w]
                assert set(p) == {"drop", "disable", "extra"}, (r, w, sorted(p))
                short, extra = (f"shows {k} live {w!r} control(s), not the {n} its data renders"
                                for k in (n - 1, n + 1))
                # one dropped: for a pair the label is still on the page, yet the screen reds
                assert _count(p["drop"]["buttons"], w) == n - 1, (r, w, p["drop"]["buttons"])
                gone = _screen_problems(p["drop"], heading, reads, want)
                assert len(gone) == 1 and gone[0].startswith(short), (r, w, gone)
                if n >= 2:
                    dropped_pairs.add((r, w))
                # one disabled, its click handler kept (not dead): not live, so the screen reds — twice over
                assert _count(p["disable"]["deadButtons"], w) == 0 and _count(p["disable"]["disabledButtons"], w) == 1
                off = _screen_problems(p["disable"], heading, reads, want)
                assert len(off) == 2 and off[0].startswith(short + " (1 disabled)"), (r, w, off)
                assert off[1].startswith("has disabled button(s) "), (r, w, off)
                # one rendered twice
                more = _screen_problems(p["extra"], heading, reads, want)
                assert len(more) == 1 and more[0].startswith(extra), (r, w, more)
            unlisted = [b for b in clean["buttons"] if not any(_count([b], w) for w in want)]
            assert (probe["other"] is None) == (not unlisted), (r, unlisted, probe["other"])
            if probe["other"] is not None:
                o = probe["other"]                       # a button no list names, disabled: only the disabled check
                others.append(r)
                assert _screen_problems(o["disable"], heading, reads, want) == [
                    f"has disabled button(s) {[o['label']]}: a disabled control is not live"], (r, o["label"])
                # the same button rendered twice: an uncounted same-label group, which only the group check sees
                assert _count(o["twin"]["liveButtons"], o["label"]) == 2, (r, o["label"])
                twin = _screen_problems(o["twin"], heading, reads, want)
                assert len(twin) == 1 and twin[0].startswith(
                    f"shows 2 {o['label']!r} buttons, a same-label group no listed control counts"), (r, twin)
    assert dropped_pairs == pairs, f"pair(s) never dropped by a walk: {sorted(pairs - dropped_pairs)}"
    assert others, ("no screen had a button outside its list: the disabled check alone, and the same-label group "
                    "check, went unexercised")


# Two regressions made for real in app.js: the blind spots of a label-only, wiring-only census. Each is (route, the
# control, the code as shipped, the code regressed); the shipped code must occur in app.js exactly once.
_REGRESSIONS: dict[str, tuple[str, str, str, str]] = {
    # the verified host stops rendering its Re-issue challenge: the pending host's still shows the label
    "dropped-one-of-a-pair": ("#/assets", "Re-issue challenge",
                              'actions.push(h("button.btn", { type: "button", text: "Re-issue challenge",',
                              'if (a.status !== "verified") actions.push(h("button.btn", { type: "button", '
                              'text: "Re-issue challenge",'),
    # Launch renders disabled (a busy flag stuck on) and keeps its click handler: wired, so never counted dead
    "disabled-with-its-handler": ("#/assessments", "Launch", 'text: "Launch", disabled: busy,',
                                  'text: "Launch", disabled: true,'),
}


@pytest.mark.parametrize("regression", sorted(_REGRESSIONS))
def test_a_real_regression_in_app_js_reds_the_census(regression, tmp_path):
    """The two blind spots of a label-only, wiring-only census, made for real in a copy of the page's app.js and
    walked: one of a same-label pair stops rendering (its label is still on the page), and a listed control renders
    disabled but keeps its click handler (it is still wired). Each reds its screen, naming the control."""
    route, label, shipped, regressed = _REGRESSIONS[regression]
    app = tmp_path / "customer_app"
    shutil.copytree(APP, app)
    src = (app / "app.js").read_text(encoding="utf-8")
    assert src.count(shipped) == 1, f"{regression}: app.js no longer has {shipped!r} exactly once: re-aim it"
    (app / "app.js").write_text(src.replace(shipped, regressed), encoding="utf-8")
    out = _walk(routes=[route], app_dir=app)
    c = out["census"][route]
    heading, reads = _SCREENS[route]
    n = _CONTROLS[route][label]
    # what a label-only, wiring-only census saw: the label on the page, and no dead button
    assert _count(c["buttons"], label) >= 1 and c["deadButtons"] == [], c["buttons"]
    bad = _screen_problems(c, heading, reads, _CONTROLS[route])
    assert bad and bad[0].startswith(f"shows {n - 1} live {label!r} control(s), not the {n} its data renders"), bad
    if regression == "disabled-with-its-handler":
        assert c["disabledButtons"] == [label] and bad[1:] == [
            f"has disabled button(s) {[label]}: a disabled control is not live"], bad
    else:
        assert len(bad) == 1 and _count(c["buttons"], label) == n - 1, bad
    assert out["errors"] == [], out["errors"]


def test_the_sign_in_screens_render_their_forms_with_no_dead_button():
    """Signed out, the four pre-auth screens render their own forms (their own heading — never a redirect into the
    app) with their own actions, each LIVE exactly as many times as the screen renders it, and no dead or disabled
    button."""
    out = _walk(authed=False, routes=list(_PREAUTH))
    for route, heading in _PREAUTH.items():
        c = out["census"][route]
        bad = _screen_problems(c, heading, (), _CONTROLS.get(route))
        assert bad == [], (route, bad)
        assert c["liveButtons"], f"{route} offers no action"
        assert not any(b.startswith("Sign out") for b in c["buttons"]), f"{route} rendered a signed-in view"
    assert out["errors"] == [], out["errors"]


def test_every_top_bar_tab_clicked_lands_on_its_own_screen():
    """Click every top-bar tab, as a person does: each lands on a real route and shows THAT route's screen (its
    heading), live and wired, its listed controls each LIVE as many times as its data renders them. And every top-bar
    target in app.js's source is a real route (a tab hidden behind a flag the walk does not turn on is still checked
    here)."""
    routes = _app_routes()
    assert _nav_targets() <= routes, f"top-bar link(s) to no route: {sorted(_nav_targets() - routes)}"
    out = _walk(click_tabs=True)
    expected: dict[str, "str | None"] = {r: h for r, (h, _reads) in _SCREENS.items()}
    expected.update({stage[0]: stage[1] for stage in _ROUTE_STAGES.values()})
    assert len(out["tabs"]) >= len({r for r in _nav_targets() if r in _SCREENS}), [t["label"] for t in out["tabs"]]
    for t in out["tabs"]:
        assert t["hash"] in routes, f"tab {t['label']!r} went to {t['hash']!r}, which is not a route"
        bad = _screen_problems(t, expected.get(t["hash"]), (), _CONTROLS.get(t["hash"]))
        assert bad == [], (t["label"], bad)
    assert out["errors"] == [], out["errors"]


def test_viewing_every_screen_reads_only_edge_routes_and_writes_nothing():
    """Every read the page fires while every screen is viewed is a path the edge routes (custui's own table); viewing
    sends no write (no POST) and nothing leaves through a raw fetch; every read is one the walk's server answers (so
    the census reflects deliberate data)."""
    edge = _edge_get_routes()
    out = _walk(routes=list(_SCREENS))
    gets = {p.split("?")[0][len("api/customer/"):] for m, p in out["calls"] if m == "GET"}
    assert gets and "whoami" in gets
    assert gets - edge == set(), f"the page read path(s) the edge does not route: {sorted(gets - edge)}"
    assert [p for m, p in out["calls"] if m == "POST"] == [], "viewing a screen sent a write"
    assert out["fetches"] == [] and out["assigns"] == [], (out["fetches"], out["assigns"])
    assert out["unknown"] == [], f"read(s) the walk's server has no answer for: {out['unknown']}"


# =====================================================================================================================
# Part B — over the REAL loopback hop: every read the page makes resolves; refusals are honest
# =====================================================================================================================
def _stack_gate5(tmp_path, monkeypatch, on=True):
    from test_custui import _stack
    for env in _GATE5_ENV:
        if on:
            monkeypatch.setenv(env, "1")
        else:
            monkeypatch.delenv(env, raising=False)
    return _stack(tmp_path, monkeypatch)


def test_every_read_the_walk_makes_resolves_on_the_real_edge(tmp_path, monkeypatch):
    """The exact paths the real page fired in the walk, sent to the REAL edge over the loopback hop with no session:
    each answers 401 "sign in first" (the route is present) — never 404 "absent"; whoami answers anonymously; a
    made-up route is 404. This ties the app's calls to routes that exist end to end."""
    from test_custui import _get, _opener
    out = _walk(routes=list(_SCREENS))
    paths = sorted({p.split("?")[0] for m, p in out["calls"] if m == "GET"} - {"api/customer/whoami"})
    assert len(paths) >= 10, paths
    sov, edge, ep, _sp = _stack_gate5(tmp_path, monkeypatch)
    try:
        got = {p: _get(_opener(), ep, "/" + p)[0] for p in paths}
        assert {p: c for p, c in got.items() if c != 401} == {}, got
        assert _get(_opener(), ep, "/api/customer/whoami")[1] == {"authenticated": False}
        assert _get(_opener(), ep, "/api/customer/does-not-exist")[0] == 404
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_flag_off_screen_route_is_absent(tmp_path, monkeypatch):
    """Fail-closed: with the screens' switches OFF their routes are genuinely ABSENT (404), not a masked 401 — the
    backend is gone exactly as the tab is."""
    from test_custui import _get, _opener
    sov, edge, ep, _sp = _stack_gate5(tmp_path, monkeypatch, on=False)
    try:
        for p in ("members", "monitoring", "monitoring/events", "live/activity", "launches", "onboarding", "billing/offers", "connect",
                  "posture", "posture/trend", "billing/plans", "report", "report/pdf", "compliance",   # + PR-G (Area 6)
                  "preferences", "authorizations", "privacy",   # + S12, S2
                  "data-rights", "data-rights/export",   # + S3
                  "ai-governance", "seller-identity"):                                   # + S5, S7
            assert _get(_opener(), ep, "/api/customer/" + p)[0] == 404, p
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_billing_role_is_honestly_refused_a_testing_read(tmp_path, monkeypatch):
    """Honest refusal (billing != testing): an org_admin — the default sign-up role — is told 403 on the assessment
    launches read, never shown another role's data, and still reads billing."""
    from test_custui import _get, _opener, _post
    monkeypatch.delenv("VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", raising=False)
    sov, edge, ep, _sp = _stack_gate5(tmp_path, monkeypatch)
    try:
        op = _opener()
        tok = _post(op, ep, "/api/customer/signup/request", {"email": "admin@acme.com"})[1]["dev_token"]
        assert _post(op, ep, "/api/customer/signup/confirm",
                     {"token": tok, "password": "customer-pw-1", "org_name": "Acme"})[0] == 200
        assert _get(op, ep, "/api/customer/launches")[0] == 403
        assert _get(op, ep, "/api/customer/billing")[0] == 200
    finally:
        sov.shutdown(); edge.shutdown()


# =====================================================================================================================
# Part C — the pending screens: one NAMED stage each, skip-with-reason + TODO, auto-activating when they merge
# =====================================================================================================================
def _route_stage(name: str, tmp_path=None, monkeypatch=None) -> None:
    route, heading, read, todo, why = _ROUTE_STAGES[name]
    if route not in _app_routes():
        pytest.skip(f"PENDING: {name} ({route}) — {why}. TODO {todo}")
    out = _walk(routes=[route])
    c = out["census"][route]
    bad = _screen_problems(c, heading, (read,) if read else (), _CONTROLS.get(route))
    assert bad == [], (route, bad)
    assert out["errors"] == [], out["errors"]
    if read and tmp_path is not None:                  # the read it fires resolves on the real edge, and only while on
        from test_custui import _get, _opener
        sov, edge, ep, _sp = _stack_gate5(tmp_path / "on", monkeypatch)
        try:
            assert _get(_opener(), ep, "/" + read)[0] == 401, read
        finally:
            sov.shutdown(); edge.shutdown()
        sov, edge, ep, _sp = _stack_gate5(tmp_path / "off", monkeypatch, on=False)
        try:
            assert _get(_opener(), ep, "/" + read)[0] == 404, read
        finally:
            sov.shutdown(); edge.shutdown()


def test_stage_account_security_screen(tmp_path, monkeypatch):
    """§15.11 C3 — Account security (#/security): set up an authenticator app, add a passkey, passkey sign-in, the
    step-up prompt. Merged on main as #1147; walks for real once it is in this branch."""
    _route_stage("account_security", tmp_path, monkeypatch)


def test_stage_code_redpen_screen():
    """§15.11 C6 / D — Code (Red-Pen). The R1 / R2 backend has merged; the screen has not."""
    _route_stage("code_redpen")


def test_stage_assessments_retest_action():
    """§15.11 C1 — Retest on a finding (a re-checked run). The guide names it; the app does not offer it yet. Detected
    by its control in app.js; when it lands, the Assessments screen must still be live and dead-button-free."""
    if not re.search(r'text: "Retest', (APP / "app.js").read_text(encoding="utf-8")):
        pytest.skip("PENDING: Retest on a finding — not in this branch. TODO §15.11 C1 (Retest -> a re-checked run)")
    out = _walk(routes=["#/assessments"])
    assert _screen_problems(out["census"]["#/assessments"], "Assessments", (), _CONTROLS["#/assessments"]) == []


def test_stage_billing_w6_dashboard_and_auto_topup():
    """§15.11 C5 / B9 — the W6 billing dashboard (a rates view, the statement with balance-after, credits on hold per
    running assessment, the low-balance notice) and A1 auto top-up. The reads exist (billing/rates, billing/usage); the
    screens do not. Detected by a rates read or an auto top-up control in app.js."""
    src = (APP / "app.js").read_text(encoding="utf-8")
    if "/billing/rates" not in src and not re.search(r"auto[- ]?top[- ]?up", src, re.IGNORECASE):
        pytest.skip("PENDING: W6 billing dashboard + A1 auto top-up — not in this branch. TODO §15.11 C5/B9 (rates, "
                    "balance-after statement, holds, low-balance notice, auto top-up)")
    out = _walk(routes=["#/billing"])
    assert _screen_problems(out["census"]["#/billing"], "Billing", (), _CONTROLS["#/billing"]) == []


def test_stage_overview_aggregation():
    """§15.11 C7 — the Overview bringing credits, hosts, assessments and monitoring together (today: the account and
    workspace only). Detected when the Overview fires a read of its own."""
    out = _walk(routes=["#/"])
    if not out["census"]["#/"]["reads"]:
        pytest.skip("PENDING: Overview aggregation — the Overview reads nothing yet. TODO §15.11 C7 (credits, hosts, "
                    "assessments and monitoring together)")
    assert _screen_problems(out["census"]["#/"], "Overview", (), _CONTROLS.get("#/")) == []


# =====================================================================================================================
# Part D — the owner's checklist stays in step with the app and cites only real tests
# =====================================================================================================================
def test_the_gate5_checklist_covers_every_route_and_the_journey():
    """The checklist names every customer route (merged and pending) so no screen is missed on the hands-on pass, and
    every step of the §13.2 journey, the fold-cache repeat and the §13.1 at-scale targets."""
    doc = CHECKLIST.read_text(encoding="utf-8")
    for route in _app_routes() | _PENDING_ROUTES:
        assert f"`{route}`" in doc, f"the checklist does not list the {route} screen"
    journey = ["sign up", "buy credits", "webhook", "prove", "launch", "no estimate", "live consumption", "exhaust",
               "pause", "top-up", "resume", "fact", "settle", "statement", "reconcile", "failure injection",
               "doctor", "ready", "VIGIL_FOLD_CACHE_ENABLED=1", "100,000", "1,000,000", "10,000", "500 ms"]
    missing = [k for k in journey if k.lower() not in doc.lower()]
    assert missing == [], f"the checklist is missing §13.2 / §13.1 step(s): {missing}"


def test_the_checklist_marks_each_criterion_automated_or_owner():
    """Every criterion row says how it is checked — AUTOMATED (named tests), OWNER (hands-on) or PENDING (a slice not
    merged) — and the document never pre-declares a pass."""
    doc = CHECKLIST.read_text(encoding="utf-8")
    rows = [ln for ln in doc.splitlines() if ln.startswith("| ") and not set(ln) <= set("|- ")]
    criteria = [ln for ln in rows if not ln.startswith(("| Screen |", "| Step |", "| Criterion |", "| Pending screen |",
                                                        "| Sign-off |"))]
    untagged = [ln for ln in criteria if not re.search(r"`(?:AUTOMATED|OWNER|PENDING)`", ln)]
    assert len(criteria) >= 25 and untagged == [], untagged
    assert not re.search(r"Gate 5 (?:is )?(?:PASSED|passed|: ?PASS)", doc)


def test_the_checklist_cites_only_test_files_that_exist():
    """Claim discipline: every test file the checklist names (a glob counts if it matches) exists in the repository,
    and every Gate 5 test it names is a test in this file."""
    doc = CHECKLIST.read_text(encoding="utf-8")
    files = set(re.findall(r"`(test_[\w*]+\.py)", doc))
    assert files, "the checklist cites no tests"
    present = {p.name for root in ("apps", "integration", "engine", "packages", "gateway") if (REPO / root).is_dir()
               for p in (REPO / root).rglob("test_*.py") if "node_modules" not in p.parts}
    missing = [f for f in sorted(files) if not any(Path(n).match(f) for n in present)]
    assert missing == [], f"the checklist cites test file(s) that do not exist: {missing}"
    mine = Path(__file__).read_text(encoding="utf-8")
    named = set(re.findall(r"`(test_[a-z0-9_]+)`", doc))
    assert named, "the checklist names none of the Gate 5 tests"
    assert sorted(t for t in named if f"def {t}(" not in mine) == []


# =====================================================================================================================
# Part E — the census, as evidence for the sign-off
# =====================================================================================================================
def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_the_census_accounts_for_every_screen_and_is_saved_as_evidence(tmp_path):
    """The automated half of Gate 5 as one record: every route is either a walked screen (pass, with its heading,
    its live controls and how many of each, and reads) or a pending stage with its reason — none unaccounted for,
    none failing — bound to the sha256 of every page script walked. Written to $VIGIL_GATE5_EVIDENCE when set (and
    always round-tripped here). It records the OWNER rows as still to do; it never says Gate 5 passed."""
    signed_in = _walk(routes=list(_SCREENS))
    signed_out = _walk(authed=False, routes=list(_PREAUTH))
    routes = _app_routes()
    screens = {}
    for r, (heading, reads) in _SCREENS.items():
        c = signed_in["census"][r]
        bad = _screen_problems(c, heading, reads, _CONTROLS.get(r))
        screens[r] = {"status": "fail" if bad else "pass", "problems": bad, "heading": c["heading"],
                      "buttons": len(c["buttons"]), "controls": dict(sorted(Counter(c["liveButtons"]).items())),
                      "reads": c["reads"]}
    for r, heading in _PREAUTH.items():
        c = signed_out["census"][r]
        bad = _screen_problems(c, heading, (), _CONTROLS.get(r))
        screens[r] = {"status": "fail" if bad else "pass", "problems": bad, "heading": c["heading"],
                      "buttons": len(c["buttons"]), "controls": dict(sorted(Counter(c["liveButtons"]).items())),
                      "reads": c["reads"]}
    pending = {name: {"route": route, "status": "merged: walked by its stage" if route in routes else "pending",
                      "why": why, "todo": todo} for name, (route, _h, _r, todo, why) in _ROUTE_STAGES.items()}
    census = {
        "gate": "Gate 5: the automated customer-app walk (docs/gate5/GATE5-CHECKLIST.md)",
        "scripts": {s: _sha256(APP / s) for s in _page_scripts()},
        "screens": screens,
        "pending_stages": pending,
        "not_covered_here": "every OWNER row of the checklist (the Stripe test-mode journey, a real FACT, doctor / "
                            "ready, the S4 at-scale run): this record is the automated half only",
    }
    unaccounted = routes - set(screens) - (_PENDING_ROUTES & routes)
    assert unaccounted == set(), f"route(s) the census does not account for: {sorted(unaccounted)}"
    assert {r: s["problems"] for r, s in screens.items() if s["status"] != "pass"} == {}
    blob = json.dumps(census, indent=2, sort_keys=True)
    assert "PASSED" not in blob
    (tmp_path / "census.json").write_text(blob, encoding="utf-8")
    assert json.loads((tmp_path / "census.json").read_text(encoding="utf-8")) == census
    target = os.environ.get(EVIDENCE_ENV, "").strip()
    if target:
        Path(target).write_text(blob, encoding="utf-8")
