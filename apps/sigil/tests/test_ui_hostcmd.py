"""Wave 6 (parity) — the sovereign HOST-RUN BROKER: launch a CLOSED-SET long `sigil` host op as a tracked
background subprocess. The single highest-risk architectural addition, so the tests hammer the invariants:
closed verb set, no free-text/path/injection in argv, owner-only launch, viewer+ reads, pid+boot orphan-
reconcile, traversal-safe run-id. Owner-gated at the route; the broker validates verb+flags itself."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from unittest import mock

from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui import hostcmd
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-hostcmd"


# ---------------- the broker, unit-level (the injection surface) ----------------

def test_argv_is_fixed_and_injection_proof():
    assert hostcmd._argv("index", []) == [__import__("sys").executable, "-m", "sigil", "index"]
    # only allowlisted flags survive; an injected flag / free-text is dropped
    with mock.patch("subprocess.Popen") as P:
        P.return_value.communicate.return_value = ("out", ""); P.return_value.returncode = 0; P.return_value.pid = 7
        r = hostcmd.launch("ingest", ["reset", "docs", "--git-only", "; rm -rf", "evil"])
    assert r["ok"] is True and r["flags"] == ["docs", "reset"]   # sorted, only allowlisted


def test_unknown_verb_is_refused():
    r = hostcmd.launch("rm", [])
    assert r["ok"] is False and "unknown host verb" in r["error"]
    r = hostcmd.launch("sign", [])                              # a real sigil verb, but NOT in the closed set
    assert r["ok"] is False


def test_run_id_is_traversal_safe():
    # the SEPARATOR/dot/empty inputs must be rejected by the isalnum GUARD ("bad run id") — NOT merely by
    # "no such run" (which would still pass if the guard were deleted). This distinguishes guard-present.
    for bad in ("../../etc/passwd", "a/b", "..", "", "a.b", "foo/../bar", "/etc/passwd"):
        r = hostcmd.run_status(bad)
        assert r["ok"] is False and r["error"] == "bad run id", f"{bad!r} must hit the id guard, got {r}"
    # a well-formed alnum id that simply does not exist is a CLEAN not-found (the guard passed, no file)
    r = hostcmd.run_status("deadbeefcafef00d")
    assert r["ok"] is False and r["error"] == "no such run"


def test_orphan_reconcile_marks_a_dead_running_run_interrupted(monkeypatch, tmp_path):
    monkeypatch.setattr("sigil.config.SIGIL_HOME", tmp_path)
    # write a 'running' meta whose pid is dead and boot matches → must reconcile to interrupted
    monkeypatch.setattr(hostcmd, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(hostcmd, "_boot_id", lambda: "boot-x")
    hostcmd._write("abc123", {"run_id": "abc123", "verb": "index", "status": "running", "pid": 999, "boot_id": "boot-x"})
    s = hostcmd.run_status("abc123")
    assert s["ok"] is True and s["status"] == "interrupted"


# ---------------- the routes: owner-only launch, viewer+ reads ------------------

def _serve():
    ensure_owner_keypair()
    s = build_server(token=TOKEN, port=0, spine_path=None)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _req(port, path, *, method="GET", token=TOKEN, body=None):
    h = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    data = None
    if body is not None:
        h["Content-Type"] = "application/json"; data = json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:  # noqa: BLE001
            return e.code, {}


def _make_account(port, username, role):
    code, d = _req(port, "/api/action", method="POST",
                   body={"action": "create_account", "username": username, "role": role})
    assert code == 200, d
    return d["bearer_token"]


def test_launch_and_reads_are_all_owner_only(monkeypatch):
    # stub the real spawn so the route test never runs the heavy `sigil index`
    monkeypatch.setattr(hostcmd, "launch", lambda verb, flags: {"ok": True, "run_id": "stub", "verb": verb, "flags": []})
    _s, port = _serve()
    viewer = _make_account(port, "vera", "viewer")
    operator = _make_account(port, "otto", "operator")
    # launch: owner (shared token) OK; viewer + operator refused (owner-only `secrets`), NOTHING spawned
    assert _req(port, "/api/hostcmd/index", method="POST", body={})[0] == 200
    assert _req(port, "/api/hostcmd/index", method="POST", body={}, token=viewer)[0] == 403
    assert _req(port, "/api/hostcmd/index", method="POST", body={}, token=operator)[0] == 403
    # reads are ALSO owner-only — the run tail can embed memory content (consolidate report), not for a viewer
    assert _req(port, "/api/hostcmd/runs")[0] == 200                          # owner
    assert _req(port, "/api/hostcmd/runs", token=viewer)[0] == 403
    assert _req(port, "/api/hostcmd/status?run_id=nope", token=operator)[0] == 403
    # unauthenticated read → 401
    assert _req(port, "/api/hostcmd/runs", token=None)[0] == 401
