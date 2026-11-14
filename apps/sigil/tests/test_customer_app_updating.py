"""The customer app's request helpers (customer_app/ui.js), executed under node against a scripted fetch:

* a READ that meets a 503 with Retry-After (the edge's `{"error":"updating"}`, or the reverse proxy's maintenance
  answer) is sent again — at most three more times — and succeeds once VIGIL is back;
* a POST is sent exactly ONCE whatever comes back: on `updating` the person is told nothing was changed and
  decides whether to repeat it;
* nothing else changes: a 4xx/5xx without Retry-After is reported at once, as before.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_UI_JS = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app" / "ui.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

# Loads ui.js in a sandbox whose fetch replays SCRIPT (a list of [status, retryAfter|null, body]) and records every
# call; setTimeout records the requested wait and runs at once. Prints {calls, waits, result|error}.
_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const [SCRIPT_JSON, OP, UI_JS] = process.argv.slice(-3); const SCRIPT = JSON.parse(SCRIPT_JSON);
const calls = [], waits = [];
const ctx = {
  window: {}, console, Promise, JSON, Object, Array, Error, parseInt, isFinite, Math, String, Set,
  sessionStorage: { getItem: () => "", setItem: () => {}, removeItem: () => {} },
  setTimeout: (fn, ms) => { waits.push(ms); fn(); return 0; },
  fetch: async (url, opts) => {
    calls.push([(opts && opts.method) || "GET", url]);
    const [status, ra, body] = SCRIPT[Math.min(calls.length - 1, SCRIPT.length - 1)];
    return { ok: status >= 200 && status < 300, status,
             headers: { get: (h) => (h === "Retry-After" && ra != null ? String(ra) : null) },
             text: async () => body };
  },
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(UI_JS, "utf8"), ctx);
const VUI = ctx.window.VUI;
const p = OP === "get" ? VUI.getJSON("/api/customer/billing") : VUI.postJSON("/api/customer/launch/reserve", {host: "h"});
p.then(r => console.log(JSON.stringify({calls, waits, result: r})),
       e => console.log(JSON.stringify({calls, waits, error: e.message, status: e.status})));
"""

_UPD = json.dumps({"error": "updating"})
_OK = json.dumps({"ok": True})
_PAGE = "<!doctype html><title>VIGIL is updating</title>"


def _run(script, op):
    r = subprocess.run(["node", "-e", _HARNESS, json.dumps(script), op, str(_UI_JS)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_a_read_is_retried_through_an_update_and_succeeds():
    out = _run([[503, 5, _UPD], [503, 5, _UPD], [200, None, _OK]], "get")
    assert out["result"] == {"ok": True}
    assert [m for m, _u in out["calls"]] == ["GET", "GET", "GET"]
    assert out["waits"] == [5000, 5000]


def test_a_read_retries_the_reverse_proxy_maintenance_answer_too():
    out = _run([[503, 5, _PAGE], [200, None, _OK]], "get")
    assert out["result"] == {"ok": True} and len(out["calls"]) == 2


def test_a_read_gives_up_after_three_retries_with_a_plain_message():
    out = _run([[503, 30, _UPD]], "get")
    assert len(out["calls"]) == 4 and out["waits"] == [10000, 10000, 10000]     # Retry-After capped at 10 s
    assert out["status"] == 503 and out["error"] == "VIGIL is updating. Back in a few seconds."


def test_a_post_is_sent_exactly_once_and_says_nothing_changed():
    out = _run([[503, 5, _UPD], [200, None, _OK]], "post")
    assert out["calls"] == [["POST", "/api/customer/launch/reserve"]] and out["waits"] == []
    assert out["error"] == "VIGIL is updating. Nothing was changed. Please try again in a few seconds."


@pytest.mark.parametrize("status,ra,body", [(502, None, json.dumps({"error": "provisioner unreachable"})),
                                            (503, 5, _PAGE), (504, None, "")])
def test_a_post_is_never_resent_whatever_the_failure(status, ra, body):
    out = _run([[status, ra, body], [200, None, _OK]], "post")
    assert len(out["calls"]) == 1 and out["waits"] == [] and out["status"] == status
    assert "Nothing was changed" not in out["error"]       # only an `updating` answer guarantees that


@pytest.mark.parametrize("status,ra", [(401, None), (500, None), (503, None)])
def test_other_read_errors_are_reported_at_once(status, ra):
    out = _run([[status, ra, json.dumps({"error": "nope"})], [200, None, _OK]], "get")
    assert len(out["calls"]) == 1 and out["error"] == "nope" and out["status"] == status
