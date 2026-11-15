"""The customer app's service worker (customer_app/sw.js) — the shell of one build, never an account's data.

In the style of test_bridge_webapp.py, these assert:
  1. CSP-safety and doctrine by inspection: no external origin, no importScripts/eval, NO cache.put (nothing is
     stored at run time), no Background Sync / periodic sync / background fetch;
  2. the routing, parsed from sw.js: every /api/* path (the Google sign-in redirect and callback included),
     /healthz, /readyz and /version.json is network-only, checked before anything else; every non-GET too;
  3. the same, EXECUTED under node against fake caches and fetch: those requests never get a respondWith (the
     browser sends them as if no worker existed) and nothing is ever written to a cache; the shell is served from
     the build's cache; the root page goes to the network first and falls back to the stored root only offline;
     install stores exactly the shell; activate deletes every other cache; SKIP_WAITING is the only message obeyed;
  4. the edge writes the build and a shell of only this build's ?v= files into the worker it serves, keeps its URL
     stable (no-cache, never ?v=), and refuses to start if the worker lost its placeholders;
  5. pwa.js registers the worker only at the customer origin's root (never under /customer/), and the update flow:
     a waiting worker + an older page -> the notice -> Refresh -> SKIP_WAITING -> reload on controllerchange.
"""
from __future__ import annotations

import http.client
import os
import json
import re
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from sigil.ui import custui
from sigil.ui.custui import build_app_snapshot, build_customer_server


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

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
SW = (APP / "sw.js").read_text(encoding="utf-8")

# every path (relative to the scope) the worker must leave to the network
NETWORK_ONLY_PATHS = ["api/customer/whoami", "api/customer/billing", "api/customer/notifications",
                      "api/customer/oidc/login", "api/customer/oidc/callback", "api/customer/login", "api",
                      "healthz", "readyz", "version.json"]


# ---- 1. doctrine by inspection -------------------------------------------------------------------------------
def test_the_worker_stores_nothing_at_run_time_and_loads_nothing_else():
    code = re.sub(r"/\*.*?\*/", "", SW, flags=re.S)                 # the code, without the header comment
    for banned in (".put(", "importScripts", "eval(", "Function(", "http://", "https://", '"sync"', "'sync'",
                   "periodicsync", "backgroundfetch", "BackgroundFetch", "indexedDB", "localStorage"):
        assert banned not in code, f"sw.js must not use {banned!r}"
    assert code.count("addAll(") == 1 and "addAll(SHELL.map(" in code       # the only write: the shell, at install
    assert 'var CACHE = "vigil-shell-" + BUILD;' in code                      # one cache per build


# ---- 2. the routing, parsed ----------------------------------------------------------------------------------
def _network_only_patterns() -> list[re.Pattern]:
    m = re.search(r"var NETWORK_ONLY = \[(.*?)\];", SW)
    assert m, "sw.js lost its NETWORK_ONLY list"
    out = []
    for lit in re.findall(r"/((?:\\/|[^/])+)/", m.group(1)):
        out.append(re.compile(lit.replace("\\/", "/")))
    return out


def test_the_parsed_routing_sends_every_api_probe_and_version_path_to_the_network():
    pats = _network_only_patterns()
    for p in NETWORK_ONLY_PATHS:
        assert any(r.search(p) for r in pats), f"{p} is not network-only in sw.js"
    for p in ("", "index.html", "app.js", "brand/icon-192.png", "apiary.css"):
        assert not any(r.search(p) for r in pats), f"{p} is wrongly network-only"
    route = SW[SW.index("function route(req)"):]
    route = route[: route.index("\n}\n")]
    body = [ln.strip() for ln in route.splitlines()[1:]]
    # the order is the guarantee: non-GET, then foreign origin, then outside the scope, then NETWORK_ONLY —
    # all before a navigation or a shell match can be answered
    assert body[0] == 'if (req.method !== "GET") return "network";'
    first_answer = next(i for i, ln in enumerate(body) if '"page"' in ln or '"shell"' in ln)
    assert next(i for i, ln in enumerate(body) if "NETWORK_ONLY[i].test(rel)" in ln) < first_answer
    fetch = SW[SW.index('self.addEventListener("fetch"'):]
    assert 'if (how === "network") return;' in fetch and fetch.index('if (how === "network") return;') < \
        fetch.index("respondWith")


# ---- 3. executed under node ----------------------------------------------------------------------------------
_SW_HARNESS = r"""
const vm = require("vm");
const [SRC, CFG] = process.argv.slice(-2);
const cfg = JSON.parse(CFG);
const log = { responded: [], puts: 0, added: [], deleted: [], skip: 0, fetched: [] };
const store = {};   // cache name -> {url: body}
const listeners = {};
function Resp(body, ok = true) { return { body, ok, clone() { return this; } }; }
const caches = {
  open: async (name) => { store[name] = store[name] || {}; const c = store[name];
    return { addAll: async (reqs) => { for (const r of reqs) { log.added.push([name, r.url, r.opts]); c[r.url] = "cached:" + r.url; } },
             put: async () => { log.puts++; },
             match: async (req) => { const u = typeof req === "string" ? req : req.url; return c[u] ? Resp(c[u]) : undefined; } }; },
  keys: async () => Object.keys(store),
  delete: async (k) => { log.deleted.push(k); delete store[k]; return true; },
};
class Request { constructor(u, opts) { this.url = new URL(u, cfg.scope).href; this.opts = opts; } }
const self = {
  registration: { scope: cfg.scope }, location: { origin: new URL(cfg.scope).origin },
  addEventListener: (t, f) => { listeners[t] = f; }, skipWaiting: () => { log.skip++; },
};
const ctx = { self, caches, Request, URL, console, Promise,
  Response: { error: () => Resp("network-error", false) },
  fetch: async (req) => { const u = req.url || req; log.fetched.push(u); if (cfg.offline) throw new TypeError("offline"); return Resp("net:" + u); } };
vm.createContext(ctx);
vm.runInContext(SRC, ctx);
(async () => {
  await (async () => { let p; listeners.install({ waitUntil: (x) => { p = x; } }); await p; })();
  caches.open("vigil-shell-OLD"); caches.open("other-cache");
  await (async () => { let p; listeners.activate({ waitUntil: (x) => { p = x; } }); await p; })();
  const answers = {};
  for (const [method, url, mode] of cfg.requests) {
    let res = null;
    listeners.fetch({ request: { method, url, mode: mode || "cors" }, respondWith: (p) => { res = p; } });
    answers[method + " " + url + " " + (mode || "")] = res === null ? null : (await res).body;
  }
  listeners.message({ origin: self.location.origin, data: { type: "OTHER" } });
  listeners.message({ origin: "https://evil.example", data: { type: "SKIP_WAITING" } });   // another origin: ignored
  listeners.message({ origin: self.location.origin, data: { type: "SKIP_WAITING" } });
  log.answers = answers;
  log.caches = Object.keys(store);
  console.log(JSON.stringify(log));
})();
"""

SCOPE = "https://app.example/"
SHELL = ["./", "tokens.css?v=aaaaaaaaaaaa", "app.js?v=bbbbbbbbbbbb"]


def _worker_src(build="cccccccccccc", shell=SHELL) -> str:
    return (SW.replace('var BUILD = "__VIGIL_BUILD__";', f"var BUILD = {json.dumps(build)};")
              .replace('var SHELL = ["__VIGIL_SHELL__"];', f"var SHELL = {json.dumps(shell)};"))


def _run_worker(requests, *, offline=False, src=None):
    cfg = json.dumps({"scope": SCOPE, "offline": offline, "requests": requests})
    r = subprocess.run([_need_node(), "-e", _SW_HARNESS, src or _worker_src(), cfg], capture_output=True, text=True,
                       timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


_LEFT_ALONE = ([["GET", SCOPE + p] for p in NETWORK_ONLY_PATHS]
               + [["GET", SCOPE + "api/customer/oidc/login", "navigate"],
                  ["GET", SCOPE + "api/customer/oidc/callback?code=c&state=s", "navigate"],
                  ["GET", SCOPE + "healthz", "navigate"],
                  ["POST", SCOPE + "api/customer/login"], ["POST", SCOPE + "api/customer/launch/reserve"],
                  ["POST", SCOPE], ["PUT", SCOPE + "app.js?v=bbbbbbbbbbbb"], ["DELETE", SCOPE + "tokens.css?v=aaaaaaaaaaaa"],
                  ["HEAD", SCOPE + "app.js?v=bbbbbbbbbbbb"],
                  ["GET", "https://evil.example/app.js?v=bbbbbbbbbbbb"],
                  ["GET", SCOPE + "app.js"], ["GET", SCOPE + "app.js?v=000000000000"],
                  ["GET", SCOPE + "unknown.css"], ["GET", SCOPE + "deep/route", "navigate"]])


def test_api_probes_version_and_every_non_get_are_never_answered_or_stored():
    out = _run_worker(_LEFT_ALONE)
    for key, ans in out["answers"].items():
        assert ans is None, f"the worker answered {key!r}"
    assert out["puts"] == 0 and out["fetched"] == []            # never stored, never even fetched by the worker


def test_the_shell_is_served_from_this_builds_cache():
    out = _run_worker([["GET", SCOPE + "tokens.css?v=aaaaaaaaaaaa"], ["GET", SCOPE + "app.js?v=bbbbbbbbbbbb"]])
    assert list(out["answers"].values()) == ["cached:" + SCOPE + "tokens.css?v=aaaaaaaaaaaa",
                                             "cached:" + SCOPE + "app.js?v=bbbbbbbbbbbb"]
    assert out["puts"] == 0


def test_the_root_page_goes_to_the_network_first_and_falls_back_only_offline():
    reqs = [["GET", SCOPE, "navigate"], ["GET", SCOPE + "index.html", "navigate"],
            ["GET", SCOPE + "?status=successful", "navigate"]]
    online = _run_worker(reqs)
    assert list(online["answers"].values()) == ["net:" + SCOPE, "net:" + SCOPE + "index.html",
                                                "net:" + SCOPE + "?status=successful"]
    offline = _run_worker(reqs, offline=True)
    assert set(offline["answers"].values()) == {"cached:" + SCOPE}
    assert online["puts"] == 0 and offline["puts"] == 0
    # any other navigation is the edge's to answer (a 404 stays a 404), online or not
    assert _run_worker([["GET", SCOPE + "nope", "navigate"]], offline=True)["answers"] == {
        "GET " + SCOPE + "nope navigate": None}


def test_install_stores_exactly_the_shell_and_activate_deletes_every_other_cache():
    out = _run_worker([])
    assert [a[1] for a in out["added"]] == [SCOPE, SCOPE + "tokens.css?v=aaaaaaaaaaaa", SCOPE + "app.js?v=bbbbbbbbbbbb"]
    assert {a[0] for a in out["added"]} == {"vigil-shell-cccccccccccc"}
    assert all(a[2] == {"cache": "reload", "credentials": "omit"} for a in out["added"])
    assert sorted(out["deleted"]) == ["other-cache", "vigil-shell-OLD"]
    assert out["caches"] == ["vigil-shell-cccccccccccc"]
    assert out["skip"] == 1                                       # SKIP_WAITING obeyed, the other message not


def test_the_check_fails_when_the_worker_would_answer_an_api_request():
    # negative control: a worker that drops the api rule answers (and could serve) an api path — the test sees it
    broken = _worker_src().replace("var NETWORK_ONLY = [/^api\\//, /^api$/,", "var NETWORK_ONLY = [")
    broken = broken.replace('return shellUrls().indexOf(url.href) !== -1 ? "shell" : "network";', 'return "shell";')
    assert broken != _worker_src()
    out = _run_worker([["GET", SCOPE + "api/customer/billing"]], src=broken)
    assert out["answers"]["GET " + SCOPE + "api/customer/billing "] is not None


# ---- 4. the worker the edge serves ---------------------------------------------------------------------------
@pytest.fixture()
def edge(tmp_path):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "s"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def get(path):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
        r = c.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    yield get
    srv.shutdown()
    srv.server_close()


def test_the_served_worker_names_this_build_and_only_its_static_shell(edge):
    status, h, body = edge("/sw.js")
    assert status == 200 and h["content-type"].startswith("application/javascript")
    assert h["cache-control"] == "no-cache" and h["etag"]           # a stable URL the browser re-checks
    text = body.decode()
    build = json.loads(edge("/version.json")[2])["build"]
    assert f'var BUILD = "{build}";' in text and "__VIGIL_" not in text
    shell = json.loads(re.search(r"var SHELL = (\[.*?\]);", text).group(1))
    assert shell[0] == "./" and len(shell) > 5
    pats = _network_only_patterns()
    for u in shell[1:]:
        path, _, q = u.partition("?")
        assert re.fullmatch(r"v=[0-9a-f]{12}", q), u
        assert not any(r.search(path) for r in pats), f"the shell names a network-only path {u}"
        st, h2, _ = edge("/" + u)
        assert st == 200 and h2["cache-control"] == "public, max-age=31536000, immutable", u
    page = edge("/")[2].decode()
    assert "sw.js?v=" not in page and "pwa.js?v=" in page


def test_the_edge_refuses_to_start_with_a_worker_that_lost_its_placeholders(tmp_path, monkeypatch):
    for f in ("index.html", "app.js"):
        (tmp_path / f).write_bytes((APP / f).read_bytes())
    (tmp_path / "sw.js").write_text(SW.replace('var BUILD = "__VIGIL_BUILD__";', 'var BUILD = "x";'),
                                    encoding="utf-8")
    monkeypatch.setattr(custui, "_APP_ROOT", tmp_path)
    with pytest.raises(ValueError, match="placeholder"):
        build_app_snapshot()


# ---- 5. registration and the update flow (pwa.js) ------------------------------------------------------------
_PWA_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const [CFG, PWA] = process.argv.slice(-2);
const cfg = JSON.parse(CFG);
const out = { registered: [], posted: [], reloads: 0, notices: 0 };
function El(tag) { return { tagName: tag.toUpperCase(), children: [], attrs: {}, listeners: {}, textContent: "",
  appendChild(c) { this.children.push(c); return c; }, setAttribute(k, v) { this.attrs[k] = v; },
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); } }; }
const body = El("body"); body.dataset = { build: cfg.page };
const swL = {};
const waiting = cfg.waiting ? { postMessage: (m) => out.posted.push(m) } : null;
const reg = { waiting, installing: null, update: async () => {}, addEventListener() {} };
const navigator = cfg.sw === false ? {} : { serviceWorker: {
  controller: cfg.controller ? {} : null,
  addEventListener: (t, f) => { swL[t] = f; },
  register: async (u, o) => { out.registered.push([u, o]); return reg; } } };
const ctx = { console, Promise, JSON, String, RegExp, navigator, Date: { now: () => 1e6 },
  document: { body, hidden: false, createElement: El, addEventListener() {} },
  window: { addEventListener() {} }, location: { pathname: cfg.path, reload() { out.reloads++; } },
  setInterval() {}, setTimeout(f) { out.timer = true; },
  fetch: async () => ({ ok: true, json: async () => ({ build: cfg.server }) }) };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(PWA, "utf8"), ctx);
const flush = async () => { for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r)); };
(async () => {
  await flush();
  const bar = () => body.children.find(c => c.id === "vigil-update");
  if (cfg.click && bar()) { bar().children[1].listeners.click.forEach(f => f()); await flush(); }
  if (cfg.controllerchange && swL.controllerchange) { swL.controllerchange(); await flush(); }
  out.notices = body.children.filter(c => c.id === "vigil-update").length;
  console.log(JSON.stringify(out));
})();
"""

A, B = "aaaaaaaaaaaa", "bbbbbbbbbbbb"


def _pwa(**cfg):
    base = {"page": A, "server": A, "path": "/", "controller": True, "waiting": False}
    base.update(cfg)
    r = subprocess.run([_need_node(), "-e", _PWA_HARNESS, json.dumps(base), str(APP / "pwa.js")], capture_output=True,
                       text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_the_worker_is_registered_only_at_the_origin_root():
    assert _pwa()["registered"] == [["sw.js", {"scope": "./"}]]
    for path in ("/customer/", "/customer", "/index.html", "/x/"):
        assert _pwa(path=path)["registered"] == [], path
    assert _pwa(sw=False)["registered"] == []                       # no service worker support: nothing breaks


def test_a_waiting_worker_behind_an_older_page_shows_the_notice_and_switches_only_on_refresh():
    out = _pwa(page=A, server=B, waiting=True)
    assert out["notices"] == 1 and out["posted"] == [] and out["reloads"] == 0
    out = _pwa(page=A, server=B, waiting=True, click=True, controllerchange=True)
    assert out["posted"] == [{"type": "SKIP_WAITING"}] and out["reloads"] == 1


def test_a_waiting_worker_behind_a_current_page_switches_quietly_without_a_reload():
    out = _pwa(page=B, server=B, waiting=True, controllerchange=True)
    assert out["posted"] == [{"type": "SKIP_WAITING"}] and out["notices"] == 0 and out["reloads"] == 0


def test_the_first_install_needs_no_switch():
    out = _pwa(page=A, server=A, waiting=True, controller=False, controllerchange=True)
    assert out["posted"] == [] and out["notices"] == 0 and out["reloads"] == 0
