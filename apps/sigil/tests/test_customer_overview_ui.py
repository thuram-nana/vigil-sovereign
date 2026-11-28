"""C7 — the customer app's fuller Overview home screen, executed under node and over the real edge hop.

* The edge writes data-overview="1" into the page only while VIGIL_CUSTOMER_OVERVIEW is on, and "0" otherwise: the
  same bytes for every off value, and the value counts in the build id (toggling it is a new build the open pages learn
  about). With it off the home screen (viewDashboard) is node-for-node what it was before C7 — app.js's own function
  without its one Overview gate line — and no card's read is made.
* With it on the home screen is the Overview: compact summary cards that each pull from the SAME session-org-scoped
  read the full screen uses — credits available (billing), verified / lapsed / awaiting hosts (assets), assessments and
  their findings (assessments), monitoring (only while that screen is on) and unread notifications (the bell's read and
  its read-state) — each card opening its full screen. The UI sends NO org id (every call is just the relative path). A
  card whose read a role may not make says so in fixed words; an empty read reads as "none yet"; a read the edge does
  not serve or that fails is "could not load" — never a raw error and never the server's own words. A session that
  ended sends the customer to sign-in once (not once per card); a read that resolves after the customer left changes
  nothing. No card shows an estimate, a money amount or an engine name.
* The guide's "The Overview" step describes what the screen shows.

app.js's own functions are extracted verbatim and run on the customer UI kit (ui.js) with a minimal DOM; the edge and
the reads are exercised over the real hop with the test_custui stack.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the app ignores the page flag / the gate always shows the Overview -> test_with_the_flag_off_the_dashboard_is_byte_identical
  * the gate never shows the Overview                                   -> test_the_overview_brings_the_cards_from_the_session_reads
  * a card counts the wrong thing / drops its Open link / unread ignores the bell's read-state
                                                                        -> test_the_overview_brings_the_cards_from_the_session_reads
  * a forbidden read shows the server's words or an Open button          -> test_a_role_forbidden_card_shows_the_honest_message_not_an_error
  * a failed read shows the server's words / every card asks for sign-in -> test_an_absent_read_or_an_ended_session_is_handled_honestly
  * a read lands on (or redirects from) a screen the customer left       -> test_a_read_that_resolves_after_the_customer_left_changes_nothing
  * the Monitoring card without its flag                                 -> test_the_monitoring_card_appears_only_when_monitoring_is_on
  * "no plan" told to a member the server did not tell                   -> test_the_monitoring_card_tells_only_what_the_server_sent
  * Open notifications closes a bell already open                        -> test_open_notifications_opens_the_bell_and_never_closes_it
  * the cards ignore the branded loader                                  -> test_cards_load_with_the_branded_loader_when_the_guide_is_on
  * an estimate, a money amount or an engine name in the copy            -> test_the_overview_shows_no_estimate_or_engine_name
  * the guide stops describing the cards                                 -> test_the_guide_describes_the_overview_the_app_shows
  * the edge (or the config) always writes "1"                           -> test_the_edge_writes_the_overview_flag_into_the_page
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_monitoring_screen import _DOM, _fn, _var
from test_customer_onboarding import _guide, _need_node, _page_and_build

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS, APP_JS, GUIDE_JS = APP / "ui.js", APP / "app.js", APP / "guide.js"


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


# The app's world, stubbed: who is signed in, where the page is, what the server answers, and every call made.
_WORLD = r"""
document.body.dataset.overview = %(overview)s;
document.body.dataset.monitoring = %(monitoring)s;
document.body.dataset.onboarding = %(guide)s;
// Every page-flag constant the extracted code may reference is DEFINED here. Those these tests never turn on are plain
// false; OVERVIEW_ON, MONITORING_ON and GUIDE_ON are app.js's own pageFlag(...) lines (appended below) — false unless a
// test sets the page's data-overview / data-monitoring / data-onboarding to "1".
var SECURITY_ON = false;
var TEAM_ON = false;
var LAUNCH_ON = false;
let who = { authenticated: true, username: "ana", org_id: "org_x" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
var ntf = { open: false };          // the bell's state; its own toggle is tested with the bell, here it is a boundary
let ntfOpened = 0; function toggleNtf() { ntfOpened++; ntf.open = !ntf.open; }
const VUI = window.VUI;
const calls = [];
let server = {};            // "GET <path>" -> {data} | {status, data} | {wait: <promise of the data>}
async function answer(key) {
  const r = server[key];
  if (!r) { const e = new Error("404"); e.status = 404; e.data = { error: "not found" }; throw e; }
  if (r.wait) return await r.wait;
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data; throw e; }
  return r.data;
}
VUI.getJSON = async p => { calls.push(["GET", p]); return answer("GET " + p); };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); return answer("POST " + p); };
function memStore() { const m = {}; return { getItem: k => (k in m ? m[k] : null),
  setItem: (k, v) => { m[k] = String(v); }, removeItem: k => { delete m[k]; } }; }
Object.defineProperty(globalThis, "localStorage", { value: memStore(), configurable: true, writable: true });
const tick = () => new Promise(r => setTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
const card = t => document.querySelectorAll("div.card").filter(c => ((c.querySelectorAll("h3")[0] || {}).textContent) === t)[0];
const titles = () => document.querySelectorAll("div.card").map(c => (c.querySelectorAll("h3")[0] || {}).textContent);
const out = {};
"""

_APP_FUNCS = ("pageFlag", "here", "loadingHolder", "kv", "viewDashboard", "viewOverview", "overviewCard",
              "overviewLink", "creditsFill", "hostsFill", "assessFill", "monFill", "ntfFill",
              "threatActivity", "loadThreatActivity", "threatText", "fmtN", "fmtAsOf",
              "seenSet", "seenIds", "seenKey", "lsGet")
_APP_VARS = ("API", "GUIDE", "GUIDE_ON", "OVERVIEW_ON", "MONITORING_ON")


def _harness(overview: str, monitoring: str, guide: str) -> str:
    """The stubbed world plus app.js's own Overview code (and the bell's read-state helpers it reuses), extracted
    verbatim so the harness runs what ships."""
    src = _src()
    return "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", f"require({json.dumps(str(GUIDE_JS))});",
                      "const h = window.VUI.h;",
                      _WORLD % {"overview": json.dumps(overview), "monitoring": json.dumps(monitoring),
                                "guide": json.dumps(guide)}]
                     + [_fn(src, n) for n in _APP_FUNCS] + [_var(src, n) for n in _APP_VARS])


def _node(script: str, *, overview: str = "1", monitoring: str = "0", guide: str = "0") -> dict:
    prog = (_harness(overview, monitoring, guide) + "\n(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
            " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# What the server sends a founder who may read every card (a member who manages monitoring, on a 5-host plan).
_SERVER = r"""
server = {
  "GET api/customer/billing": { data: { org_id: "org_x", credits: { available: 500, persistent: 500, plan_live: 0 } } },
  "GET api/customer/assets": { data: { assets: [{ host: "a.example", status: "verified" },
                                                 { host: "b.example", status: "expired" },
                                                 { host: "c.example", status: "pending" }] } },
  "GET api/customer/assessments": { data: { assessments: [{ slug: "s1", host: "a.example", findings: 2 },
                                                           { slug: "s2", host: "c.example", findings: 1 }] } },
  "GET api/customer/monitoring": { data: { grants: [{ host: "a.example", active: true }, { host: "b.example", active: false }],
                                           can_manage: true, plan: { host_slots: 5, respond: true, period_end: 1 } } },
  "GET api/customer/notifications": { data: { notifications: [{ id: "f1", severity: "high" },
                                                              { id: "f2", severity: "low" }], count: 2 } },
};
localStorage.setItem("vigil.ntf.seen.ana", JSON.stringify(["f1"]));     // f1 was already read at the bell
"""
_EMPTY = r"""
server = { "GET api/customer/billing": { data: { credits: {} } }, "GET api/customer/assets": { data: { assets: [] } },
           "GET api/customer/assessments": { data: { assessments: [] } },
           "GET api/customer/notifications": { data: { notifications: [] } } };
"""

# The one line C7 added inside viewDashboard; without it the function is the pre-C7 dashboard byte for byte.
_GATE = "    if (OVERVIEW_ON) { return viewOverview(); }\n"
_SER = r"""
function ser(n) {
  return (n instanceof El) ? [n.tagName, n.className, n.id, n.attrs, n.dataset, Object.keys(n.listeners).sort(),
                              n.children.map(ser)]
                           : ["#text", n.textContent];
}
"""


def _before(src: str) -> str:
    """viewDashboard as it was before C7: app.js's own function with its one Overview gate line removed, renamed."""
    fn = _fn(src, "viewDashboard")
    assert fn.count(_GATE) == 1, "viewDashboard's Overview gate changed shape: update this proof"
    return fn.replace(_GATE, "").replace("function viewDashboard(", "function viewDashboardBefore(")


# --- flag off: the dashboard is byte-identical -------------------------------------------------------------------
def test_with_the_flag_off_the_dashboard_is_byte_identical():
    before = _before(_src())
    for flag in ("0", "", "__VIGIL_OVERVIEW__", "true"):
        out = _node(_SER + before + r"""
const view = viewDashboard();
out.same = JSON.stringify(ser(view)) === JSON.stringify(ser(viewDashboardBefore()));
document.body.appendChild(view);
out.cards = titles();
out.kv = document.querySelectorAll("div.cust-kv").map(e => e.textContent);
out.note = (document.querySelectorAll("p.cust-muted")[0] || {}).textContent;
out.buttons = document.querySelectorAll("button").length; out.current = view.dataset.current;
await flush(); out.calls = calls.length;
""", overview=flag)
        assert out["same"] is True, flag                                # node for node the pre-C7 dashboard
        assert out["cards"] == ["Account"], flag                        # the one Account card, nothing else
        assert out["kv"] == ["Signed in asana", "Workspaceorg_x"], flag
        assert out["note"] == ("Billing, invoices, authorized assets and assessments appear here as those "
                               "panels come online. Every panel is scoped to this workspace by the server."), flag
        assert out["buttons"] == 0 and out["calls"] == 0 and out["current"] == "#/", flag   # and no read is made


# --- flag on: the cards come from the session reads --------------------------------------------------------------
def test_the_overview_brings_the_cards_from_the_session_reads():
    out = _node(_SERVER + r"""
const view = viewDashboard();               // the home screen itself, with the flag on
document.body.appendChild(view);
await flush();
out.cards = titles();
out.rows = {};
["Account", "Credits", "Authorized hosts", "Assessments", "Monitoring", "Notifications"].forEach(t => {
  out.rows[t] = card(t).querySelectorAll("div.cust-kv").map(e => e.textContent); });
out.opens = document.querySelectorAll("button").map(b => b.textContent);
out.calls = calls.slice();
["Open Billing", "Open Assets", "Open Assessments", "Open Monitoring"].forEach(l => button(view, l).click());
out.navs = navs;
""", monitoring="1")
    assert out["cards"] == ["Account", "Credits", "Authorized hosts", "Assessments", "Monitoring", "Notifications"]
    assert out["rows"] == {
        "Account": ["Signed in asana", "Workspaceorg_x"],
        "Credits": ["Available500"],                                    # the balance the server sent, as Billing shows it
        "Authorized hosts": ["Verified1", "Expired1", "Awaiting proof1"],
        "Assessments": ["Authorized2", "Findings3"],
        "Monitoring": ["Monitored1 of 5"],                              # active grants of the plan's host slots
        "Notifications": ["Unread1", "Total2"],                         # f1 was read at the bell
    }
    assert out["opens"] == ["Open Billing", "Open Assets", "Open Assessments", "Open Monitoring", "Open notifications"]
    # the UI sends NO org id: every call is just ["GET", <relative path>] (no body, no org selector)
    assert out["calls"] == [["GET", "api/customer/billing"], ["GET", "api/customer/assets"],
                            ["GET", "api/customer/assessments"], ["GET", "api/customer/monitoring"],
                            ["GET", "api/customer/notifications"]]
    assert out["navs"] == ["#/billing", "#/assets", "#/assessments", "#/monitoring"]   # each card opens its screen


# --- an empty read reads as "none yet", never an error ------------------------------------------------------------
def test_an_empty_read_degrades_to_an_honest_none_line():
    out = _node(_EMPTY + r"""
const view = viewDashboard(); document.body.appendChild(view); await flush();
out.text = {};
["Credits", "Authorized hosts", "Assessments", "Notifications"].forEach(t => { out.text[t] = text(card(t)); });
out.opens = document.querySelectorAll("button").map(b => b.textContent);
""")
    assert out["text"] == {
        "Credits": "CreditsAvailable—Open Billing",                 # no balance in the answer: a dash, never a 0
        "Authorized hosts": "Authorized hostsNo hosts registered yet.Open Assets",
        "Assessments": "AssessmentsNo authorized assessments yet.Open Assessments",
        "Notifications": "NotificationsNo notifications yet.Open notifications",
    }
    # an empty card still opens its screen, where the customer can begin (buy credits, register a host)
    assert out["opens"] == ["Open Billing", "Open Assets", "Open Assessments", "Open notifications"]


# --- a role-forbidden card is honest, never a raw error -----------------------------------------------------------
def test_a_role_forbidden_card_shows_the_honest_message_not_an_error():
    """A billing role (org_admin) reads Credits but may not read hosts or assessments (billing is not testing): those
    cards say so in fixed words, with no Open button to a screen that would refuse too and never the server's text."""
    out = _node(r"""
const deny = { status: 403, data: { error: "requester may not read this org (view_assessments)" } };
server = { "GET api/customer/billing": { data: { credits: { available: 120 } } },
           "GET api/customer/assets": deny, "GET api/customer/assessments": deny,
           "GET api/customer/notifications": { data: { notifications: [] } } };
const view = viewDashboard(); document.body.appendChild(view); await flush();
out.hosts = text(card("Authorized hosts")); out.assess = text(card("Assessments")); out.credits = text(card("Credits"));
out.forbiddenOpens = card("Authorized hosts").querySelectorAll("button").length
                     + card("Assessments").querySelectorAll("button").length;
""")
    assert out["hosts"] == "Authorized hostsYour role does not have access to Assets."
    assert out["assess"] == "AssessmentsYour role does not have access to Assessments."
    assert out["forbiddenOpens"] == 0
    assert out["credits"] == "CreditsAvailable120Open Billing"          # a card the role may read still renders


# --- a read the edge does not serve, a failure, an ended session ----------------------------------------------------
def test_an_absent_read_or_an_ended_session_is_handled_honestly():
    out = _node(r"""
server = { "GET api/customer/billing": { status: 404, data: { error: "unknown route /api/customer/billing" } },
           "GET api/customer/assets": { status: 502, data: { error: "upstream relay timed out at 10.0.0.7" } },
           "GET api/customer/assessments": { data: { assessments: [] } },
           "GET api/customer/notifications": { data: { notifications: [] } } };
const view = viewDashboard(); document.body.appendChild(view); await flush();
out.credits = text(card("Credits")); out.hosts = text(card("Authorized hosts")); out.navs = navs.slice();
""")
    assert out["credits"] == "CreditsCould not load Billing right now."          # never the server's own words
    assert out["hosts"] == "Authorized hostsCould not load Assets right now."
    assert out["navs"] == []
    # every read answers 401 (the session ended): ONE card asks who is signed in and routes to sign-in; the rest stand down
    ended = _node(r"""
server = {};
["billing", "assets", "assessments", "monitoring", "notifications"].forEach(p => {
  server["GET api/customer/" + p] = { status: 401, data: { error: "login required" } }; });
const view = viewDashboard(); document.body.appendChild(view); await flush();
out.whoRefreshes = whoRefreshes; out.navs = navs;
out.cells = document.querySelectorAll("div.cust-ov-cell").map(e => e.textContent);
""", monitoring="1")
    assert ended["whoRefreshes"] == 1 and ended["navs"] == ["#/login"]
    assert ended["cells"] == ["Loading…"] * 5                       # nothing rendered as an error on the way out


# --- a read that comes back after the customer left -----------------------------------------------------------------
def test_a_read_that_resolves_after_the_customer_left_changes_nothing():
    out = _node(r"""
let release; const gate = new Promise(r => { release = r; });
const fail = s => gate.then(() => { const e = new Error("x"); e.status = s; e.data = {}; throw e; });
server = { "GET api/customer/billing": { wait: gate.then(() => ({ credits: { available: 9 } })) },
           "GET api/customer/assets": { wait: fail(401) },
           "GET api/customer/assessments": { wait: fail(403) },
           "GET api/customer/notifications": { wait: gate.then(() => ({ notifications: [] })) } };
const view = viewDashboard(); document.body.appendChild(view);
location.hash = "#/billing";                   // the customer opened another screen before the reads came back
release(); await flush();
out.cells = document.querySelectorAll("div.cust-ov-cell").map(e => e.textContent);
out.navs = navs; out.whoRefreshes = whoRefreshes;
""")
    assert out["cells"] == ["Loading…"] * 4                         # nothing mounted into a screen no longer shown
    assert out["navs"] == [] and out["whoRefreshes"] == 0               # and no sign-in redirect from it either


# --- the Monitoring card ----------------------------------------------------------------------------------------------
def test_the_monitoring_card_appears_only_when_monitoring_is_on():
    script = _EMPTY + r"""
server["GET api/customer/monitoring"] = { data: { grants: [], can_manage: false } };
const view = viewDashboard(); document.body.appendChild(view); await flush();
out.cards = titles(); out.reads = calls.map(c => c[1]);
"""
    on = _node(script, monitoring="1")
    assert "Monitoring" in on["cards"] and "api/customer/monitoring" in on["reads"]
    for flag in ("0", "", "__VIGIL_MONITORING__"):
        off = _node(script, monitoring=flag)
        assert "Monitoring" not in off["cards"] and "api/customer/monitoring" not in off["reads"], flag


def test_the_monitoring_card_tells_only_what_the_server_sent():
    def mon(answer: dict) -> dict:
        return _node(_EMPTY + r"""
server["GET api/customer/monitoring"] = { data: ANSWER };
const view = viewDashboard(); document.body.appendChild(view); await flush();
out.rows = card("Monitoring").querySelectorAll("div.cust-kv").map(e => e.textContent);
out.text = text(card("Monitoring"));
""".replace("ANSWER", json.dumps(answer)), monitoring="1")

    def g(host: str, active: bool) -> dict:
        return {"host": host, "active": active}

    # a member who manages monitoring, on a plan: the hosts monitored of the plan's host slots
    m = mon({"grants": [g("a.example", True), g("b.example", False)], "can_manage": True,
             "plan": {"host_slots": 5, "respond": False, "period_end": 1}})
    assert m["rows"] == ["Monitored1 of 5"] and "No active AEGIS plan." not in m["text"]
    # a manager the server told has no plan
    m = mon({"grants": [], "can_manage": True, "plan": None})
    assert m["rows"] == ["Monitored0"] and "No active AEGIS plan." in m["text"]
    # anyone else is never sent the plan, so the card claims nothing about one — just what is monitored
    m = mon({"grants": [g("a.example", True), g("b.example", True)], "can_manage": False})
    assert m["rows"] == ["Monitored2"] and "plan" not in m["text"].lower()


# --- the Notifications card opens the bell -------------------------------------------------------------------------
def test_open_notifications_opens_the_bell_and_never_closes_it():
    out = _node(_EMPTY + r"""
server["GET api/customer/notifications"] = { data: { notifications: [{ id: "n1", severity: "high" }] } };
const view = viewDashboard(); document.body.appendChild(view); await flush();
const open = button(card("Notifications"), "Open notifications");
open.click(); out.first = [ntfOpened, ntf.open];
open.click(); out.second = [ntfOpened, ntf.open];
""")
    assert out["first"] == [1, True]                                   # the bell's own toggle opened its panel
    assert out["second"] == [1, True]                                  # already open: left open, never closed


# --- loading ----------------------------------------------------------------------------------------------------------
def test_cards_load_with_the_branded_loader_when_the_guide_is_on():
    script = r"""
const view = viewDashboard(); document.body.appendChild(view);          // looked at before any read answers
out.cells = document.querySelectorAll("div.cust-ov-cell").map(c => c.children.map(k => k.tagName + "." + k.className));
"""
    on = _node(script, guide="1")
    off = _node(script, guide="0")
    assert on["cells"] == [["DIV.cust-loader"]] * 4                    # the VIGIL wordmark, as every screen with the guide on
    assert off["cells"] == [["P.cust-muted"]] * 4                      # the plain "Loading…" line otherwise


# --- no estimate, no money amount, no engine name ---------------------------------------------------------------------
_ENGINE = re.compile(r"\b(claude|anthropic|opus|sonnet|haiku|fable|strix|nyx|ultracode|gpt|openai|llm)\b", re.I)
_ESTIMATE = re.compile(r"estimat|quote|predict|forecast|\bcost", re.I)
_MONEY = re.compile(r"[$€£]\s?\d|\b(usd|eur|gbp)\b", re.I)


def test_the_overview_shows_no_estimate_or_engine_name():
    out = _node(_SERVER + r"""
const view = viewDashboard(); document.body.appendChild(view); await flush();
out.blob = view.textContent;
""", monitoring="1")
    for rx in (_ENGINE, _ESTIMATE, _MONEY):
        hit = rx.search(out["blob"])
        assert not hit, hit and hit.group(0)
    # and none in any words the Overview's code can put on screen (its string literals; comments are not shown)
    code = "\n".join(_fn(_src(), n) for n in ("viewOverview", "overviewCard", "overviewLink", "creditsFill",
                                               "hostsFill", "assessFill", "monFill", "ntfFill"))
    words = "\n".join(re.findall(r'"((?:[^"\\]|\\.)*)"', code))
    for rx in (_ENGINE, _ESTIMATE, _MONEY):
        hit = rx.search(words)
        assert not hit, hit and hit.group(0)


# --- the guide ----------------------------------------------------------------------------------------------------------
def test_the_guide_describes_the_overview_the_app_shows():
    step = next(st for ch in _guide()["chapters"] for st in ch["steps"] if (ch["id"], st["id"]) == ("workspace", "overview"))
    clicks = " ".join(step["clicks"])
    assert (step["title"], step["where"], step["route"]) == ("The Overview", "Overview", "#/")
    for what in ("credits", "hosts", "assessments", "monitoring"):       # what the cards bring together
        assert what in clicks, what
    assert "opens its full screen" in clicks                            # each card's Open button
    assert "says so plainly" in clicks and "never shows an error" in clicks   # a card a role cannot see


# --- the edge flag (real hop) -------------------------------------------------------------------------------------
def test_the_edge_writes_the_overview_flag_into_the_page(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_OVERVIEW", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-overview="0"' in off and "__VIGIL_OVERVIEW__" not in off
    monkeypatch.setenv("VIGIL_CUSTOMER_OVERVIEW", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-overview="1"' in on and build_on != build_off
    # the ONLY difference the flag makes to the page is its own value + the build id (byte-identical otherwise)
    assert on.replace('data-overview="1"', 'data-overview="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv("VIGIL_CUSTOMER_OVERVIEW", v)
        assert 'data-overview="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v


# --- the Overview's reads over the real edge hop, role-scoped, no org id ------------------------------------------
def test_overview_card_reads_over_the_edge_role_scoped(tmp_path, monkeypatch):
    """Every card reads an EXISTING session-org-scoped read: over the real edge hop a signup org_admin reads its Credits
    (billing) and its notifications, but the Hosts and Assessments cards' reads are refused (billing is not testing) —
    the honest-card path — and the UI sends no org id (the edge scopes every read to the SESSION org)."""
    from sigil.ui.custui import _READS
    for p in ("billing", "assets", "assessments", "notifications"):      # monitoring is its own flagged route
        assert f"/api/customer/{p}" in _READS, p
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        oid = conf["org_id"]
        c, ov = _get(op, ep, "/api/customer/billing")
        assert c == 200 and ov["org_id"] == oid and "available" in ov["credits"]   # Credits card data, session-scoped
        assert _get(op, ep, "/api/customer/assessments")[0] == 403                  # Assessments card -> honest line
        assert _get(op, ep, "/api/customer/assets")[0] == 403                       # Hosts card -> honest line
        c, n = _get(op, ep, "/api/customer/notifications")
        assert c == 200 and isinstance(n.get("notifications"), list)                # Notifications card read is served
    finally:
        sov.shutdown(); edge.shutdown()
