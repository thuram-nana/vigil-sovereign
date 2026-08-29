"""Wave 8 (parity) — read-only sovereign anti-rollback status (`sigil floor status` / `sigil spine status`).
Fixed argv (no request input), shell=False; viewer+ reads; the reset/rotate/compact mutations stay CLI-only."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui import antirollback
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-antirollback"


class _P:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def test_status_shells_fixed_argv(monkeypatch):
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda a, **k: (seen.append(a) or _P(0, "floor last_seq=42, 1 anchor")))
    r = antirollback.floor_status()
    assert r["ok"] is True and r["verb"] == "floor" and "last_seq" in r["text"]
    assert seen[0] == [sys.executable, "-m", "sigil", "floor", "status"]      # fixed, no request input
    seen.clear()
    antirollback.spine_status()
    assert seen[0] == [sys.executable, "-m", "sigil", "spine", "status"]


def test_status_failcloses(monkeypatch):
    def _boom(*a, **k):
        raise OSError("no exec")
    monkeypatch.setattr(subprocess, "run", _boom)
    assert antirollback.floor_status()["ok"] is False


def test_bad_state_exit_is_not_ok(monkeypatch):
    # a floor in a bad state exits non-zero (e.g. UNREADABLE/tamper) — that must surface ok:false, never a
    # false ok, even with the status text present. `ok` is derived from the EXIT CODE.
    monkeypatch.setattr(subprocess, "run", lambda a, **k: _P(2, "floor: UNREADABLE — possible tamper"))
    r = antirollback.floor_status()
    assert r["ok"] is False and r["exit_code"] == 2 and "UNREADABLE" in r["text"]


def _serve():
    ensure_owner_keypair()
    s = build_server(token=TOKEN, port=0, spine_path=None)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _get(port, path, token=TOKEN):
    h = {}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:  # noqa: BLE001
            return e.code, {}


def _make_account(port, username, role):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}",
         "X-SIGIL-Token": TOKEN}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/action",
                                 data=json.dumps({"action": "create_account", "username": username, "role": role}).encode(),
                                 headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())["bearer_token"]


def test_routes_are_viewer_plus(monkeypatch):
    # stub the real spawn so the route test never runs `sigil floor status`
    monkeypatch.setattr(antirollback, "floor_status", lambda: {"ok": True, "verb": "floor", "text": "ok"})
    monkeypatch.setattr(antirollback, "spine_status", lambda: {"ok": True, "verb": "spine", "text": "ok"})
    _s, port = _serve()
    viewer = _make_account(port, "vera", "viewer")
    assert _get(port, "/api/antirollback/floor")[0] == 200                    # owner
    assert _get(port, "/api/antirollback/floor", token=viewer)[0] == 200      # viewer+
    assert _get(port, "/api/antirollback/spine", token=viewer)[0] == 200
    assert _get(port, "/api/antirollback/floor", token=None)[0] == 401        # unauth
