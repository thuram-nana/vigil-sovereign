"""Signing out of the customer app deletes this origin's CacheStorage (customer_app/app.js doLogout ->
VIGIL_PWA.clearCaches in pwa.js), whether or not the sign-out request itself succeeded, and before the app
re-reads the session. Executed under node: the real doLogout and the real clearCaches against fake caches.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const [CFG, APPJS, PWAJS] = process.argv.slice(-3);
const cfg = JSON.parse(CFG);
const order = [];
const store = { "vigil-shell-aaaaaaaaaaaa": 1, "vigil-shell-bbbbbbbbbbbb": 1 };
const caches = { keys: async () => Object.keys(store),
                 delete: async (k) => { order.push("delete:" + k); delete store[k]; return true; } };
// pwa.js, for its real clearCaches
const pctx = { console, Promise, JSON, String, RegExp, caches, Date: { now: () => 1 },
  document: { body: { dataset: {}, appendChild() {} }, createElement() { return {}; }, addEventListener() {} },
  window: { addEventListener() {} }, navigator: {}, location: { pathname: "/x" },
  setInterval() {}, setTimeout() {}, fetch: async () => ({ ok: false }) };
vm.createContext(pctx);
vm.runInContext(fs.readFileSync(PWAJS, "utf8"), pctx);
// app.js's doLogout, extracted verbatim and run with stand-ins for the helpers it calls
const src = fs.readFileSync(APPJS, "utf8");
const start = src.indexOf("  async function doLogout() {");
const end = src.indexOf("\n  }\n", start) + 4;
const actx = { console, Promise,
  window: { VIGIL_PWA: cfg.noPwa ? undefined : pctx.window.VIGIL_PWA },
  VUI: { postJSON: async () => { order.push("post"); if (cfg.postFails) throw new Error("x"); return { ok: true }; },
         toast: () => order.push("toast") },
  API: "api/customer", resetNtf: () => order.push("resetNtf"), refreshWho: async () => order.push("refreshWho"),
  authed: () => false, nav: () => {}, err: () => {} };
vm.createContext(actx);
vm.runInContext(src.slice(start, end) + "\nthis.doLogout = doLogout;", actx);
actx.doLogout().then(() => console.log(JSON.stringify({ order, left: Object.keys(store) })),
                     (e) => console.log(JSON.stringify({ error: String(e) })));
"""


def _run(**cfg):
    r = subprocess.run(["node", "-e", _HARNESS, json.dumps(cfg), str(APP / "app.js"), str(APP / "pwa.js")],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@pytest.mark.parametrize("post_fails", [False, True])
def test_sign_out_deletes_every_cache_before_reading_the_session_again(post_fails):
    out = _run(postFails=post_fails)
    assert out["left"] == []
    o = out["order"]
    assert o[0] == "post" and "refreshWho" in o
    deletes = [i for i, x in enumerate(o) if x.startswith("delete:")]
    assert len(deletes) == 2 and max(deletes) < o.index("refreshWho")


def test_sign_out_still_works_without_the_pwa_script():
    out = _run(noPwa=True)
    assert "refreshWho" in out["order"] and len(out["left"]) == 2   # nothing to clear with, nothing breaks
