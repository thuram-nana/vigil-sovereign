"""The customer app's "new version" notice (customer_app/pwa.js), executed under node against a scripted edge:

* the page knows its build (body data-build); pwa.js asks GET version.json (relative, no-store, no cookie sent)
  on load, when the tab becomes visible, on focus, every 10 minutes, after a failed script/stylesheet/image load
  and after a 404 the app reports (VIGIL_PWA.notFound);
* when the edge's build differs it shows ONE notice — "A new version of VIGIL is available — Refresh" — and
  reloads only when Refresh is tapped; the same build, an unreachable edge or an unstamped page show nothing;
* app.js passes every 404 its requests meet to pwa.js and still rejects with the same error.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

A, B = "aaaaaaaaaaaa", "bbbbbbbbbbbb"

# A tiny DOM + clock + fetch. ACTIONS run in order; each is followed by a microtask flush. Prints a JSON summary.
_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const [CFG, PWA] = process.argv.slice(-2);
const cfg = JSON.parse(CFG);
const out = { fetches: [], reloads: 0, intervals: [], captureError: false };
let clock = 1000000, served = 0, tick = null;
function El(tag) {
  return { tagName: String(tag).toUpperCase(), children: [], attrs: {}, listeners: {}, textContent: "", id: "",
    appendChild(c) { this.children.push(c); return c; }, setAttribute(k, v) { this.attrs[k] = String(v); },
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); } };
}
const body = El("body"); body.dataset = { build: cfg.build };
const docL = {}, winL = {};
const document = { body, hidden: false, createElement: El,
  addEventListener(t, f) { (docL[t] = docL[t] || []).push(f); } };
const window = { addEventListener(t, f, cap) { (winL[t] = winL[t] || []).push(f); if (t === "error" && cap === true) out.captureError = true; } };
const ctx = { window, document, console, Promise, JSON, String, RegExp,
  Date: { now: () => clock },
  location: { pathname: "/", reload() { out.reloads++; } },
  navigator: {},
  setInterval(f, ms) { out.intervals.push(ms); tick = f; return 1; },
  setTimeout(f, ms) { return 0; },
  fetch: async (url, opts) => {
    out.fetches.push([url, opts]);
    const b = cfg.server[Math.min(served++, cfg.server.length - 1)];
    if (b === null) throw new Error("offline");
    return { ok: true, json: async () => ({ build: b }) };
  } };
window.document = document;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(PWA, "utf8"), ctx);
const flush = async () => { for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r)); };
const notices = () => body.children.filter(c => c.id === "vigil-update");
(async () => {
  await flush();
  for (const a of cfg.actions) {
    if (a.startsWith("advance:")) clock += Number(a.slice(8));
    else if (a === "visible") { document.hidden = false; (docL.visibilitychange || []).forEach(f => f()); }
    else if (a === "hidden") { document.hidden = true; (docL.visibilitychange || []).forEach(f => f()); }
    else if (a === "focus") (winL.focus || []).forEach(f => f());
    else if (a === "tick") tick();
    else if (a.startsWith("resource-error:")) (winL.error || []).forEach(f => f({ target: El(a.slice(15)) }));
    else if (a === "window-error") (winL.error || []).forEach(f => f({ target: window }));
    else if (a === "notfound") window.VIGIL_PWA.notFound();
    else if (a === "click") notices()[0].children[1].listeners.click.forEach(f => f());
    await flush();
  }
  const n = notices();
  out.notices = n.length;
  out.text = n.length ? n[0].children.map(c => c.textContent).join("") : "";
  out.role = n.length ? n[0].attrs.role : "";
  out.button = n.length ? [n[0].children[1].tagName, n[0].children[1].type] : [];
  console.log(JSON.stringify(out));
})();
"""


def _run(build, server, actions=()):
    cfg = json.dumps({"build": build, "server": server, "actions": list(actions)})
    r = subprocess.run(["node", "-e", _HARNESS, cfg, str(APP / "pwa.js")], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_the_same_build_shows_nothing_and_the_check_is_unauthenticated_and_uncached():
    out = _run(A, [A])
    assert out["notices"] == 0 and out["reloads"] == 0
    assert out["fetches"] == [["version.json", {"cache": "no-store", "credentials": "omit"}]]


def test_a_new_build_shows_one_notice_and_reloads_only_on_refresh():
    out = _run(A, [B], ["advance:6000", "focus", "advance:6000", "visible", "tick"])
    assert out["notices"] == 1 and out["role"] == "status"
    assert out["text"] == "A new version of VIGIL is available — Refresh"
    assert out["button"] == ["BUTTON", "button"] and out["reloads"] == 0
    assert _run(A, [B], ["click"])["reloads"] == 1


@pytest.mark.parametrize("server", [[None], [""], ["not-a-build"]])
def test_an_unreachable_edge_or_a_bad_answer_shows_nothing(server):
    out = _run(A, server)
    assert out["notices"] == 0 and len(out["fetches"]) == 1


def test_an_unstamped_page_never_asks():
    out = _run("__VIGIL_BUILD__", [B], ["advance:6000", "focus", "tick", "notfound"])
    assert out["fetches"] == [] and out["notices"] == 0


@pytest.mark.parametrize("trigger", ["visible", "focus", "tick", "resource-error:script", "resource-error:link",
                                     "resource-error:img", "notfound"])
def test_each_trigger_asks_again_and_finds_a_new_build(trigger):
    out = _run(A, [A, B], ["advance:6000", trigger])
    assert len(out["fetches"]) == 2 and out["notices"] == 1, (trigger, out)


@pytest.mark.parametrize("trigger", ["hidden", "window-error", "resource-error:div"])
def test_other_events_do_not_ask(trigger):
    out = _run(A, [A, B], ["advance:6000", trigger])
    assert len(out["fetches"]) == 1 and out["notices"] == 0, (trigger, out)


def test_a_burst_asks_once_and_the_timer_runs_every_ten_minutes():
    out = _run(A, [A], ["advance:6000", "focus", "visible", "notfound"])
    assert len(out["fetches"]) == 2                              # load + one for the burst
    assert out["intervals"] == [600000] and out["captureError"] is True


_HOOK_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const src = fs.readFileSync(process.argv[process.argv.length - 1], "utf8");
const start = src.indexOf("  (function () {\n    var P = window.VIGIL_PWA;");
const end = src.indexOf("})();", start) + 5;
let notFound = 0;
const fail = (status) => Promise.reject(Object.assign(new Error("e" + status), { status }));
const VUI = { getJSON: (u) => fail(Number(u)), postJSON: (u) => fail(Number(u)) };
const ctx = { window: { VIGIL_PWA: { notFound: () => { notFound++; } } }, VUI };
vm.createContext(ctx);
vm.runInContext(src.slice(start, end), ctx);
(async () => {
  const errs = [];
  for (const [k, s] of [["getJSON", 404], ["postJSON", 404], ["getJSON", 401], ["postJSON", 503]]) {
    try { await ctx.VUI[k](String(s)); errs.push("resolved"); } catch (e) { errs.push(e.status); }
  }
  console.log(JSON.stringify({ notFound, errs }));
})();
"""


def test_app_js_reports_every_404_and_still_rejects():
    r = subprocess.run(["node", "-e", _HOOK_HARNESS, str(APP / "app.js")], capture_output=True, text=True,
                       timeout=30)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"notFound": 2, "errs": [404, 404, 401, 503]}


def test_the_page_loads_pwa_js_before_the_app():
    html = (APP / "index.html").read_text(encoding="utf-8")
    assert html.index('<script src="ui.js">') < html.index('<script src="pwa.js">') < html.index('<script src="app.js">')
