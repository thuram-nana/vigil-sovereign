"""The customer app's onboarding guide (customer_app/guide.js, wired by app.js) and the edge flag behind it.

* The edge writes data-onboarding="1" into the page at startup only while VIGIL_CUSTOMER_ONBOARDING is on; otherwise
  "0". The value counts in the build id, so turning the guide on or off is a new build the open pages are told about.
* With the flag on: after a sign-in the app asks the SERVER (api/customer/onboarding, see
  test_customer_onboarding_state.py) whether this account still has the tour ahead of it — "pending" until the person
  finishes or skips it, on any device. Pending opens the click-through tour (once per page load); done/skipped never
  does; a tour finished in this browser whose record did not reach the server is sent again rather than re-shown; and
  when the server cannot be asked, this browser's memory decides. Skip guide (or Esc) and Finish both record the
  outcome, here and on the server, and the tab a step happens on lights up in the top bar.
* The Guide screen (#/guide) covers the WHOLE app, chapter by chapter, step by step — account and sign-in, the
  workspace and team, credits and plans, proving a host, testing it, Red-Pen on GitHub, AEGIS monitoring, statement and
  invoices — plus the questions first-time users ask, and replays the tour. Every screen the app routes to is covered
  (a new screen fails the coverage census until the guide covers it). While a screen loads, the VIGIL wordmark
  brightens and dims.
* With the flag off: no tour, no server call, no Guide tab, #/guide is the home screen, and every loading state is the
  exact text node it was before.
* The copy names no model or engine, quotes no price or credit amount, and mentions an estimate only to rule it out.

guide.js and the customer UI kit run under node with a minimal DOM; app.js's wiring functions are extracted verbatim.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the tour ignores a finished/skipped record           -> test_the_tour_opens_once_per_account_until_finished_or_skipped
  * skipping does not record the outcome                 -> test_skip_and_escape_close_the_tour_for_good
  * Esc does not close the tour                          -> test_skip_and_escape_close_the_tour_for_good
  * Finish does not record the outcome                   -> test_finish_records_the_tour_as_done
  * the tab a step happens on is not lit                 -> test_the_tour_walks_every_step_and_lights_its_tab
  * the app ignores the page flag                        -> test_with_the_flag_off_the_app_is_unchanged
  * the edge always writes "1"                           -> test_the_edge_writes_the_flag_into_the_page
  * a model / engine name or a price in the copy         -> test_the_copy_follows_the_product_rules
  * the app ignores the server's done/skipped            -> test_the_server_decides_whether_the_tour_opens
  * the app never re-sends a locally finished tour       -> test_the_server_decides_whether_the_tour_opens
  * the tour's outcome is not sent to the server         -> test_closing_the_tour_records_it_on_the_server
  * a screen of the app missing from the guide           -> test_the_guide_covers_every_screen_of_the_app
  * the Team step offers a role a customer cannot grant  -> test_the_team_step_offers_only_the_roles_a_customer_can_grant
"""
from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from sigil.ui.custui import build_customer_server

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
GUIDE_JS, UI_JS, APP_JS = APP / "guide.js", APP / "ui.js", APP / "app.js"


def _need_node() -> str:
    """The node binary (callers use it as argv[0]), or a SKIP where node is absent — except in CI
    (GITHUB_ACTIONS) or where VIGIL_REQUIRE_NODE is set (every CI job that runs this file sets it): there a
    missing node FAILS, so these executed-JS proofs can never go green unrun."""
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH: this job must "
                        "EXECUTE these JS tests")
        pytest.skip("node not installed")
    return node


# A minimal DOM: what ui.js's h() and guide.js touch (elements, text, classes, data-*, events, simple selectors).
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
    this.classList = new ClassList(this); this.listeners = {};
  }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) {
    if (k.indexOf("data-") === 0) { const d = k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      if (d in this.dataset) return String(this.dataset[d]); }
    return k in this.attrs ? this.attrs[k] : null;
  }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); this.children.push(c); c.parentNode = this; return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); c.parentNode = null; return c; }
  get firstChild() { return this.children[0] || null; }
  set textContent(v) { this.children = []; if (String(v)) this.appendChild(new Text(v)); }
  get textContent() { return this.children.map(c => c.textContent).join(""); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter(x => x !== f); }
  dispatch(t, ev) { (this.listeners[t] || []).slice().forEach(f => f(ev || { preventDefault() {} })); }
  click() { this.dispatch("click"); }
  focus() { globalThis.__focused = this; }
  _all(out) { this.children.forEach(c => { if (c instanceof El) { out.push(c); c._all(out); } }); return out; }
  querySelectorAll(sel) { return this._all([]).filter(e => matches(e, sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
function matches(e, sel) {
  const m = sel.match(/^([a-z][a-z0-9]*)?((?:\.[\w-]+)*)(?:\[([\w-]+)="([^"]*)"\])?$/i);
  if (!m) throw new Error("selector not supported by the test DOM: " + sel);
  if (m[1] && e.tagName !== m[1].toUpperCase()) return false;
  const cls = (m[2] || "").split(".").filter(Boolean);
  if (cls.some(c => !e.classList.contains(c))) return false;
  if (m[3] && e.getAttribute(m[3]) !== m[4]) return false;
  return true;
}
globalThis.Node = Node;
globalThis.window = globalThis;
const body = new El("body");
const docListeners = {};
globalThis.document = {
  body, documentElement: body,
  createElement: t => new El(t), createTextNode: t => new Text(t),
  querySelector: s => body.querySelector(s), querySelectorAll: s => body.querySelectorAll(s),
  addEventListener: (t, f) => { (docListeners[t] = docListeners[t] || []).push(f); },
  removeEventListener: (t, f) => { docListeners[t] = (docListeners[t] || []).filter(x => x !== f); },
  key: k => (docListeners.keydown || []).slice().forEach(f => f({ key: k, preventDefault() {} })),
};
function memStore(throws) {
  const m = {};
  return {
    getItem: k => { if (throws) throw new Error("blocked"); return k in m ? m[k] : null; },
    setItem: (k, v) => { if (throws) throw new Error("blocked"); m[k] = String(v); },
    removeItem: k => { if (throws) throw new Error("blocked"); delete m[k]; },
    _m: m,
  };
}
function text(e) { return e ? e.textContent : null; }
function buttons(root) { return root.querySelectorAll("button").map(b => b.textContent); }
function button(root, label) { return root.querySelectorAll("button").filter(b => b.textContent === label)[0]; }
"""


def _node(script: str, *, is_async: bool = False) -> dict:
    head = (_DOM + f"\nrequire({json.dumps(str(UI_JS))});\nrequire({json.dumps(str(GUIDE_JS))});\n"
            "const G = window.VIGIL_GUIDE; const h = window.VUI.h; const out = {};\n")
    if is_async:      # the scenario awaits the app's async calls; anything that throws fails the run
        prog = (head + "const tick = () => new Promise(r => setTimeout(r, 0));\n(async () => {\n" + script
                + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
                " e => { console.error(e && e.stack || e); process.exit(3); });")
    else:
        prog = head + script + "\nprocess.stdout.write(JSON.stringify(out));"
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# --- the edge flag ------------------------------------------------------------------------------------------------
def _page_and_build(tmp_path):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "s"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
        r = c.getresponse()
        return r.read().decode(), r.getheader("X-Vigil-Build")
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_edge_writes_the_flag_into_the_page(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_ONBOARDING", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-onboarding="0"' in off and "__VIGIL_ONBOARDING__" not in off
    assert re.search(r'<script src="guide\.js\?v=[0-9a-f]+"></script>', off)
    assert off.index('<script src="pwa.js') < off.index('<script src="guide.js') < off.index('<script src="app.js')
    monkeypatch.setenv("VIGIL_CUSTOMER_ONBOARDING", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-onboarding="1"' in on and build_on != build_off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv("VIGIL_CUSTOMER_ONBOARDING", v)
        assert 'data-onboarding="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v


# --- when the tour opens ------------------------------------------------------------------------------------------
def test_the_tour_opens_once_per_account_until_finished_or_skipped():
    out = _node(r"""
const s = memStore(false);
out.off = G.shouldOpen({ enabled: false, username: "ana", storage: s });
out.anon = G.shouldOpen({ enabled: true, username: "", storage: s });
out.fresh = G.shouldOpen({ enabled: true, username: "ana", storage: s });
G.markDone("ana", s, "skipped");
G._resetForTests();
out.afterSkip = G.shouldOpen({ enabled: true, username: "ana", storage: s });
out.stored = s._m["vigil.guide.v1.ana"];
out.other = G.shouldOpen({ enabled: true, username: "ben", storage: s });
G.markDone("ben", s, "done");
G._resetForTests();
out.afterDone = G.shouldOpen({ enabled: true, username: "ben", storage: s });
const blocked = memStore(true);
out.blockedFirst = G.shouldOpen({ enabled: true, username: "cy", storage: blocked });
const t = G.openTour({ h, doc: document, username: "cy", storage: blocked });
out.blockedReopen = G.shouldOpen({ enabled: true, username: "cy", storage: blocked });
t.close("skipped");
out.blockedAfterClose = G.shouldOpen({ enabled: true, username: "cy", storage: blocked });
""")
    assert out["off"] is False and out["anon"] is False and out["fresh"] is True
    assert out["afterSkip"] is False and out["stored"] == "skipped" and out["other"] is True
    assert out["afterDone"] is False
    # storage blocked (a private window): the tour still opens once, never again in that page load, and nothing breaks
    assert out["blockedFirst"] is True and out["blockedReopen"] is False and out["blockedAfterClose"] is False


# --- the tour -------------------------------------------------------------------------------------------------------
_NAV = r"""
const navbar = h("div.cust-topbar", {}, ["#/billing", "#/team", "#/assets", "#/assessments", "#/guide",
                                         "#/security"].map(r =>
  h("button.cust-nav-link", { type: "button", dataset: { route: r }, text: r })));
document.body.appendChild(navbar);
const lit = () => document.querySelectorAll(".cust-nav-spot").map(e => e.dataset.route);
"""


def test_the_tour_walks_every_step_and_lights_its_tab():
    out = _node(_NAV + r"""
const s = memStore(false);
const t = G.openTour({ h, doc: document, username: "ana", storage: s });
const panel = () => t.el.querySelector(".cust-tour-panel");
out.dialog = [panel().getAttribute("role"), panel().getAttribute("aria-modal")];
out.first = [text(panel().querySelector("h2")), text(panel().querySelector(".cust-tour-count")), buttons(panel())];
out.touring = document.body.classList.contains("cust-touring");
out.steps = [];
for (let i = 0; i < G.TOUR.length; i++) {
  out.steps.push({ title: text(panel().querySelector("h2")), lit: lit(),
                   clicks: panel().querySelectorAll("li").length, where: text(panel().querySelector(".cust-tour-where")) });
  if (i < G.TOUR.length - 1) button(panel(), "Next").click();
}
out.last = buttons(panel());
button(panel(), "Back").click();
out.back = text(panel().querySelector(".cust-tour-count"));
""")
    assert out["dialog"] == ["dialog", "true"] and out["touring"] is True
    title, count, btns = out["first"]
    assert title == "Welcome to VIGIL" and count.startswith("Step 1 of ") and "Skip guide" in btns
    assert "Next" in btns and "Back" not in btns
    steps = out["steps"]
    assert steps[-1]["title"] == "You're ready" and "Finish" in out["last"]
    assert out["back"] == f"Step {len(steps) - 1} of {len(steps)}"
    by_title = {s["title"]: s for s in steps}
    # each step that happens on a top-bar screen lights exactly that tab; the others light nothing
    assert by_title["Buy credits"]["lit"] == ["#/billing"] and by_title["Bring in your team"]["lit"] == ["#/team"]
    assert by_title["Register the host"]["lit"] == ["#/assets"] and by_title["Launch an assessment"]["lit"] == ["#/assessments"]
    assert by_title["Read your statement"]["lit"] == ["#/billing"] and by_title["You're ready"]["lit"] == ["#/guide"]
    # Account security opens from the account's name in the top bar (a cust-nav-link carrying its route)
    assert by_title["Protect your account"]["lit"] == ["#/security"]
    for title in ("Welcome to VIGIL", "Notifications", "Connect your GitHub account", "Turn on monitoring for a host"):
        assert by_title[title]["lit"] == [], title
    # the journey is click by click: every chapter step in the tour lists its clicks and where they happen
    for s in steps[1:-1]:
        assert s["clicks"] >= 3 and s["where"].startswith("Where: "), s
    assert [s["title"] for s in steps] == [
        "Welcome to VIGIL", "Protect your account", "Bring in your team", "Notifications", "Buy credits",
        "How credits are spent", "Register the host", "Publish one proof", "Confirm and verify", "Launch an assessment",
        "Follow it while it runs", "Read your findings", "Connect your GitHub account",
        "Red-Pen reviews every pull request", "Fix a finding", "Choose an AEGIS plan", "Turn on monitoring for a host",
        "Read your statement", "You're ready"]


def test_skip_and_escape_close_the_tour_for_good():
    out = _node(_NAV + r"""
const s = memStore(false);
let t = G.openTour({ h, doc: document, username: "ana", storage: s, onClose: how => { out.how1 = how; } });
button(t.el, "Next").click(); button(t.el, "Next").click();
out.litBefore = lit();
button(t.el, "Skip guide").click();
out.gone = !t.el.parentNode; out.litAfter = lit(); out.touring = document.body.classList.contains("cust-touring");
out.stored1 = s._m["vigil.guide.v1.ana"];
G._resetForTests();
const s2 = memStore(false);
t = G.openTour({ h, doc: document, username: "ben", storage: s2 });
document.key("ArrowRight"); out.afterArrow = text(t.el.querySelector(".cust-tour-count"));
document.key("ArrowLeft"); out.afterLeft = text(t.el.querySelector(".cust-tour-count"));
document.key("Escape");
out.escGone = !t.el.parentNode; out.stored2 = s2._m["vigil.guide.v1.ben"];
out.reopen = G.shouldOpen({ enabled: true, username: "ben", storage: s2 });
""")
    assert out["how1"] == "skipped" and out["gone"] is True and out["stored1"] == "skipped"
    assert out["litBefore"] == ["#/team"] and out["litAfter"] == [] and out["touring"] is False
    assert out["afterArrow"].startswith("Step 2 of") and out["afterLeft"].startswith("Step 1 of")
    assert out["escGone"] is True and out["stored2"] == "skipped" and out["reopen"] is False


def test_finish_records_the_tour_as_done():
    out = _node(r"""
const s = memStore(false);
const t = G.openTour({ h, doc: document, username: "ana", storage: s });
t.go(G.TOUR.length - 1);
button(t.el, "Finish").click();
out.gone = !t.el.parentNode; out.stored = s._m["vigil.guide.v1.ana"];
""")
    assert out["gone"] is True and out["stored"] == "done"


# --- the Guide screen --------------------------------------------------------------------------------------------------
def test_the_guide_screen_shows_every_chapter_step_by_step():
    out = _node(r"""
const s = memStore(false);
const navs = []; let replays = 0;
const g = G.viewGuide({ h, username: "ana", storage: s, nav: r => navs.push(r), replayTour: () => { replays++; } });
document.body.appendChild(g);
const tabs = () => g.querySelectorAll(".cust-guide-tab");
out.tabs = tabs().map(b => b.textContent);
out.pressed = tabs().map(b => b.getAttribute("aria-pressed"));
const steps = () => g.querySelectorAll(".cust-guide-step");
out.openFirst = steps().map(e => !e.querySelector(".cust-guide-detail").hidden);
steps()[1].querySelector(".cust-guide-step-head").click();
out.afterToggle = steps().map(e => !e.querySelector(".cust-guide-detail").hidden);
out.goFirst = g.querySelectorAll("button").filter(b => b.textContent.indexOf("Go to ") === 0).map(b => b.textContent);
button(g, "Go to Account security").click();
button(steps()[0], "Mark as done").click();
out.doneLabel = steps()[0].querySelectorAll("button").map(b => b.textContent);
out.doneKey = Object.keys(s._m);
button(g, "Replay the welcome tour").click();
const tab = name => tabs().filter(b => b.textContent === name)[0].click();
const titles = () => steps().map(e => e.querySelector(".cust-guide-step-title").textContent);
tab("Your workspace");
out.workspace = titles();
button(g, "Go to Team").click(); button(g, "Go to Overview").click();
tab("Red-Pen and GitHub");
out.redpen = titles();
out.redpenClicks = steps().map(e => e.querySelectorAll("li").map(li => li.textContent));
tab("AEGIS monitoring");
out.aegis = titles();
out.aegisClicks = steps()[0].querySelectorAll("li").map(li => li.textContent);
tab("Statement and invoices");
button(g, "Go to Invoices").click();
tab("Questions");
out.faqPressed = tabs().map(b => b.getAttribute("aria-pressed"));
out.faq = g.querySelectorAll("details").map(d => [d.querySelector("summary").textContent, text(d.querySelector("p"))]);
out.faqSteps = steps().length;
tab("Get started");
out.backToFirst = titles()[0];
out.navs = navs; out.replays = replays;
""")
    assert out["tabs"] == ["Get started", "Your workspace", "Credits and plans", "Prove you control a host",
                           "Test a host", "Red-Pen and GitHub", "AEGIS monitoring", "Statement and invoices", "Questions"]
    assert out["pressed"][0] == "true" and set(out["pressed"][1:]) == {"false"}
    assert out["openFirst"] == [True] + [False] * 5 and out["afterToggle"] == [True, True] + [False] * 4
    # the sign-in steps happen before the top bar; only Account security (opened from the name in it) has a "Go to"
    assert out["goFirst"] == ["Go to Account security"]
    assert out["navs"] == ["#/security", "#/team", "#/", "#/invoices"] and out["replays"] == 1
    assert "✓ Done" in out["doneLabel"] and out["doneKey"] == ["vigil.guide.v1.step.ana.start.account"]
    assert out["workspace"] == ["The Overview", "Bring in your team", "Notifications"]
    assert out["redpen"] == ["Connect your GitHub account", "Red-Pen reviews every pull request",
                             "Choose what blocks a merge", "Review a whole repository", "Fix a finding",
                             "Disconnect a repository"]
    connect, pr = out["redpenClicks"][0], out["redpenClicks"][1]
    assert any("Connect GitHub" in c for c in connect) and any("Only select repositories" in c for c in connect)
    assert any("Install" in c for c in connect)
    assert any("reproduce" in c for c in pr) and any("block the merge" in c for c in pr)
    assert out["aegis"] == ["Choose an AEGIS plan", "Turn on monitoring for a host", "Connect your traffic and see events",
                            "Change or stop monitoring"]
    assert any("Observe" in c for c in out["aegisClicks"]) and any("Respond" in c for c in out["aegisClicks"])
    assert out["faqPressed"][-1] == "true" and set(out["faqPressed"][:-1]) == {"false"}
    assert len(out["faq"]) >= 8 and out["faqSteps"] == 0 and all(q and a for q, a in out["faq"])
    assert "How much will an assessment cost?" in [q for q, _ in out["faq"]]
    assert out["backToFirst"] == "Create your account"


def test_the_loader_is_the_wordmark():
    out = _node(r"""
const l = G.loader(h, "Loading…");
out.cls = l.className; out.role = l.getAttribute("role"); out.label = l.getAttribute("aria-label");
out.imgs = l.querySelectorAll("img").map(i => [i.getAttribute("src"), i.className]);
""")
    assert out["cls"] == "cust-loader" and out["role"] == "status" and out["label"] == "Loading…"
    assert out["imgs"] == [["brand/vigil-wordmark-white.svg", "vigil-logo for-dark cust-loader-mark"],
                           ["brand/vigil-wordmark.svg", "vigil-logo for-light cust-loader-mark"]]
    css = (APP / "app.css").read_text(encoding="utf-8")
    assert "animation: cust-breathe" in css and "@keyframes cust-breathe" in css
    assert re.search(r"prefers-reduced-motion: reduce\)[^}]*\.cust-loader-mark \{ animation: none", css)


# --- the copy -----------------------------------------------------------------------------------------------------------
_FORBIDDEN = re.compile(r"\b(claude|anthropic|opus|sonnet|haiku|fable|strix|nyx|ultracode|gpt|openai|llm)\b"
                        r"|[$€£]\s?\d|\b\d[\d,.]*\s*credits?\b|\bmargin\b", re.IGNORECASE)


def _guide() -> dict:
    return _node("out.chapters = G.CHAPTERS; out.tour = G.TOUR; out.faq = G.FAQ;")


def test_the_copy_follows_the_product_rules():
    out = _guide()
    texts = []
    for ch in out["chapters"]:
        texts += [ch["title"], ch["lead"]]
        for st in ch["steps"]:
            texts += [st["title"], st["where"], st["why"], *st["clicks"]]
    for t in out["tour"]:
        texts += [t.get("title", ""), *t.get("body", [])]
    for f in out["faq"]:
        texts += [f["q"], f["a"]]
    blob = "\n".join(texts)
    assert not _FORBIDDEN.search(blob), _FORBIDDEN.search(blob).group(0)
    for sentence in re.split(r"(?<=[.!?])\s+", blob):          # an estimate is only ever mentioned to rule it out
        if re.search(r"estimat|quote|predict", sentence, re.IGNORECASE):
            assert re.search(r"\bnever\b|\bno\b|\bnot\b", sentence, re.IGNORECASE), sentence
    ids = {ch["id"]: [s["id"] for s in ch["steps"]] for ch in out["chapters"]}
    assert ids["redpen"] == ["connect", "pr", "settings", "system", "fix", "disconnect"]
    assert ids["aegis"] == ["plans", "monitor", "events", "manage"]
    for t in out["tour"]:                                       # every tour step points at a real guide step
        if "chapter" in t:
            assert t["step"] in ids[t["chapter"]], t
    assert {t["chapter"] for t in out["tour"] if "chapter" in t} == set(ids)    # the tour visits every chapter
    for ch in out["chapters"]:                                  # every step is complete: where, clicks, why
        assert len(ch["steps"]) == len(set(ids[ch["id"]])), ch["id"]
        for st in ch["steps"]:
            assert st["where"] and st["why"] and len(st["clicks"]) >= 2, (ch["id"], st["id"])


def test_the_team_step_offers_only_the_roles_a_customer_can_grant():
    """The Team step names exactly the roles the provisioner lets a customer grant (never one that carries testing),
    and the roles answer in the Questions tab agrees: only the founder, and an Operator VIGIL grants, read findings."""
    from sigil.ui.provision import _CUSTOMER_GRANTABLE_ROLES
    shown = {"org_admin": "Admin", "analyst": "Analyst", "viewer": "Viewer"}
    out = _guide()
    team = next(st for ch in out["chapters"] for st in ch["steps"] if (ch["id"], st["id"]) == ("workspace", "team"))
    offer = next(c for c in team["clicks"] if "choose a role:" in c)
    named = set(re.findall(r"[A-Z][a-z]+", offer.split("choose a role:", 1)[1]))
    assert named == {shown[r] for r in _CUSTOMER_GRANTABLE_ROLES}, (named, sorted(_CUSTOMER_GRANTABLE_ROLES))
    assert any("Operator" in c and "only by VIGIL" in c for c in team["clicks"])
    faq = {f["q"]: f["a"] for f in out["faq"]}["Who in my organization can see our findings?"]
    assert "founder" in faq and "VIGIL has made an Operator" in faq


def test_the_guide_covers_every_screen_of_the_app():
    """The census: every route app.js knows is covered by the guide — a top-bar screen by steps that happen on it
    (with its "Go to" button), the screens before sign-in, the payment return page and Account security (opened from
    the account's name) by name — and so are the bell, sign-out, installing the app, and the screens still to come
    (Code, Monitoring). A new screen in app.js fails here until the guide covers it."""
    src = APP_JS.read_text(encoding="utf-8")
    i = src.index("  var ROUTES = {")
    routes = set(re.findall(r'^    "(#/[^"]*)": function', src[i:src.index("\n  };", i)], re.M))
    top_bar = set(re.findall(r'navLink\("[^"]+", "(#/[^"]*)"\)', src))
    out = _guide()
    steps = {(ch["id"], st["id"]): st for ch in out["chapters"] for st in ch["steps"]}
    step_routes = {st["route"] for st in steps.values() if st.get("route")}
    # the screens that have no tab, each with the guide step that walks through it and words that step must use
    by_name = {
        "#/login": (("start", "signin"), "Sign in"),
        "#/signup": (("start", "account"), "Create an account"),
        "#/recover": (("start", "recover"), "Forgot your password?"),
        "#/google-code": (("start", "signin"), "6-digit code"),
        "#/billing/return": (("credits", "buy"), "Payment received"),
        "#/security": (("start", "security"), "Open Account security from your name in the top bar"),
    }
    assert routes == top_bar | set(by_name), "a new screen in app.js must be added to the guide (and to this census)"
    assert top_bar - {"#/guide"} <= step_routes                                  # every tab has its steps
    assert "#/guide" in {t["route"] for t in out["tour"] if t.get("route")}       # the tour ends on the Guide
    for route, (key, words) in by_name.items():
        st = steps[key]
        assert any(words in c for c in st["clicks"]), (route, words)
    assert any("Payment not completed" in c for c in steps[("billing", "payments")]["clicks"])
    # the parts of the app that are not a screen of their own
    for key in (("workspace", "notifications"), ("start", "signout"), ("start", "install"), ("start", "security")):
        assert key in steps, key
    # the screens still to come are described where they will be
    wheres = {st["where"] for st in steps.values()}
    assert {"Account security", "Code", "Monitoring", "GitHub"} <= wheres
    # the questions tab answers the cost question without a number
    faq = {f["q"]: f["a"] for f in out["faq"]}
    assert "does not estimate" in faq["How much will an assessment cost?"]


# --- app.js wiring --------------------------------------------------------------------------------------------------------
def _fn(src: str, name: str) -> str:
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


def _line(src: str, pattern: str) -> str:
    """One of app.js's own module-level lines, verbatim (so the harness runs what ships, not a copy of it)."""
    m = re.search(pattern, src, re.M)
    assert m, f"app.js no longer has a line matching {pattern!r}"
    return m.group(0)


def _flag_lines(src: str) -> str:
    """app.js's own two lines that decide whether the guide is on (verbatim)."""
    return (_line(src, r"^  var GUIDE = window\.VIGIL_GUIDE;$") + "\n" + _line(src, r"^  var GUIDE_ON = .*;$"))


# The app's world, stubbed: who is signed in, what the server answers about the tour, and every call made to it.
_APP_ENV = r"""
document.body.dataset.onboarding = %(flag)s;
let who = %(who)s;
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const navs = []; function nav(r) { navs.push(r); }
const calls = [];
let server = %(server)s;            // {state} answers 200; {status} fails with that status
let postFails = false;
const VUI = window.VUI;
VUI.getJSON = async p => { calls.push(["GET", p]); if (server.status) { const e = new Error("x"); e.status = server.status; throw e; }
                           return { ok: true, state: server.state }; };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); if (postFails) { const e = new Error("x"); e.status = 502; throw e; }
                                 return { ok: true, state: b.state }; };
const ls = memStore(false);
Object.defineProperty(globalThis, "localStorage", { value: ls, configurable: true, writable: true });
let opened = 0;
"""


def _app(flag: str = "1", *, authed: bool = True, username: str = "ana", server: "dict | None" = None,
         real_open: bool = False) -> str:
    """The harness: the stubs above plus app.js's own guide wiring, extracted verbatim."""
    src = APP_JS.read_text(encoding="utf-8")
    env = _APP_ENV % {"flag": json.dumps(flag), "who": json.dumps({"authenticated": authed, "username": username}),
                      "server": json.dumps(server or {"state": "pending"})}
    opener = (_fn(src, "openGuideTour") if real_open else "function openGuideTour() { opened++; }")
    return "\n".join([env, _fn(src, "pageFlag"), _flag_lines(src), _line(src, r"^  var API = \"[^\"]*\";"),
                      _fn(src, "guideStore"), _fn(src, "loadingHolder"), _fn(src, "recordTour"), opener,
                      _line(src, r"^  var tourChecked = .*;$"), _fn(src, "maybeOpenTour")])


def test_with_the_flag_off_the_app_is_unchanged():
    for flag in ("0", "__VIGIL_ONBOARDING__", ""):
        out = _node(_app(flag) + r"""
const holder = loadingHolder("Loading…");
out.holder = [holder.tagName, holder.className, holder.textContent];
maybeOpenTour(); await tick();
out.opened = opened; out.calls = calls;
""", is_async=True)
        assert out["holder"] == ["P", "cust-muted", "Loading…"], flag          # exactly the node every screen showed
        assert out["opened"] == 0 and out["calls"] == [], flag                 # no tour and no call to the server
    src = APP_JS.read_text(encoding="utf-8")
    assert '"#/guide": function () { return authed() ? (GUIDE_ON ? viewGuideScreen() : viewDashboard()) : viewLogin(); }' in src
    assert '.concat(GUIDE_ON ? [navLink("Guide", "#/guide")] : [])' in src
    assert "if (GUIDE_ON) props.dataset = { route: hash };" in src
    render = _fn(src, "render")
    assert render.index("syncNtf();") < render.index("maybeOpenTour();")
    assert 'loadingHolder("Loading…")' in render


def test_with_the_flag_on_the_app_loads_with_the_wordmark_and_opens_the_tour_after_sign_in():
    out = _node(_app("1") + r"""
const holder = loadingHolder("Loading…");
out.holder = [holder.tagName, holder.className];
maybeOpenTour(); await tick();
out.opened = opened; out.calls = calls;
""", is_async=True)
    assert out["holder"] == ["DIV", "cust-loader"] and out["opened"] == 1
    assert out["calls"] == [["GET", "api/customer/onboarding"]]
    anon = _node(_app("1", authed=False) + "maybeOpenTour(); await tick(); out.opened = opened; out.calls = calls;",
                 is_async=True)
    assert anon == {"opened": 0, "calls": []}                               # never on the sign-in screens


def _decide(server: dict, local: "str | None" = None, *, then: str = "") -> dict:
    pre = f'ls.setItem("vigil.guide.v1.ana", {json.dumps(local)});' if local else ""
    return _node(_app("1", server=server) + pre + r"""
maybeOpenTour(); await tick();
maybeOpenTour(); await tick();                      // render() runs again and again: asked once per page load
""" + then + r"""
out.opened = opened; out.calls = calls; out.local = G.localState("ana", ls);
out.again = G.shouldOpen({ enabled: true, username: "ana", storage: ls });
""", is_async=True)


def test_the_server_decides_whether_the_tour_opens():
    get = ["GET", "api/customer/onboarding"]
    # a first sign-in (the server says pending): the tour opens, once
    out = _decide({"state": "pending"})
    assert out["opened"] == 1 and out["calls"] == [get]
    # finished or skipped on ANY device: never opens here, and this browser now remembers it too
    for answer in ("done", "skipped"):
        out = _decide({"state": answer})
        assert out["opened"] == 0 and out["calls"] == [get] and out["local"] == answer, answer
        assert out["again"] is False
    # the server still says pending but the tour was closed in this browser (that record did not land): it is sent
    # again, and the tour is not shown again
    for local in ("done", "skipped"):
        out = _decide({"state": "pending"}, local)
        assert out["opened"] == 0, local
        assert out["calls"] == [get, ["POST", "api/customer/onboarding", {"state": local}]], local
    # the server cannot be asked: this browser's memory decides
    for status in (500, 502, 503, 404):
        assert _decide({"status": status})["opened"] == 1, status
        out = _decide({"status": status}, "skipped")
        assert out["opened"] == 0 and out["calls"] == [get], status           # nothing is sent on a guess
    # the session ended (401): no tour and no guess — each render asks again, so the sign-in that follows gets its answer
    out = _decide({"status": 401}, then=r"""
out.before = opened;
server = { state: "pending" }; maybeOpenTour(); await tick();
""")
    assert out["before"] == 0 and out["opened"] == 1 and out["calls"] == [get, get, get]


def test_a_sign_out_or_account_switch_while_asking_opens_nothing():
    out = _node(_app("1") + r"""
let release;
VUI.getJSON = p => { calls.push(["GET", p]); return new Promise(r => { release = () => r({ ok: true, state: "pending" }); }); };
maybeOpenTour();
who = { authenticated: true, username: "ben" };      // another account signed in before the answer came back
release(); await tick();
out.switched = opened;
who = { authenticated: false };
maybeOpenTour(); await tick();
out.signedOut = opened; out.calls = calls.length;
""", is_async=True)
    assert out == {"switched": 0, "signedOut": 0, "calls": 1}


def test_closing_the_tour_records_it_on_the_server():
    out = _node(_app("1", real_open=True) + r"""
maybeOpenTour(); await tick();                        // pending: the real tour opens
const t1 = document.body.querySelector(".cust-tour");
out.open = !!t1;
button(t1, "Skip guide").click(); await tick();
out.afterSkip = calls.slice(1);
openGuideTour();                                      // the Guide screen's "Replay the welcome tour"
const t2 = document.body.querySelector(".cust-tour");
for (let i = 0; i < G.TOUR.length - 1; i++) button(t2, "Next").click();
button(t2, "Finish").click(); await tick();
out.afterFinish = calls.slice(1 + out.afterSkip.length);
postFails = true;                                     // the record cannot be sent: nothing breaks, it is kept here
openGuideTour();
document.key("Escape"); await tick(); await tick();
out.failedSend = calls[calls.length - 1];
out.local = G.localState("ana", ls);
""", is_async=True)
    url = "api/customer/onboarding"
    assert out["open"] is True
    assert out["afterSkip"] == [["POST", url, {"state": "skipped"}]]
    assert out["afterFinish"] == [["POST", url, {"state": "done"}]]
    assert out["failedSend"] == ["POST", url, {"state": "skipped"}] and out["local"] == "skipped"
