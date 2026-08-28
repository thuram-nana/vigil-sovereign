"""Slice 1c-i — authentication audit events + /api/logout + the production owner-token positive control.

Invariants:
  * every login OUTCOME (success AND failure) appends a `source="authn"` spine record with the method,
    username, outcome and a coarse reason — a real audit trail where there was none;
  * audit payloads are SECRET-FREE — never the bearer, password, challenge, or signature;
  * /api/logout records an auditable logout (same-origin gated);
  * PRODUCTION positive control: under VIGIL_POSTURE=production the legacy owner TOKEN grants NOTHING
    (whoami=false, /api/accounts=401, /api/action=403) — the same token is owner with posture unset.
"""
from __future__ import annotations

import itertools
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.identity import ensure_owner_keypair
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-authn-audit"
_iss = itertools.count(1)


def _serve(spine_path):
    ensure_owner_keypair()
    s = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _post(port, path, body, *, token=TOKEN):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}",
         "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _get(port, path, *, token=TOKEN):
    h = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:  # noqa: BLE001
            return e.code, {}


def _authn_events(server):
    return [r.payload for r in server.store().iter_records()
            if getattr(r, "source", None) == "authn"]


# --- audit events on login outcomes ---------------------------------------------

def test_password_login_success_and_failure_are_audited_secret_free():
    s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    # owner creates a teammate + sets a password (over the owner-token action plane)
    assert _post(port, "/api/action", {"action": "create_account", "username": "tim", "role": "operator"})[0] == 200
    assert _post(port, "/api/action", {"action": "set_password", "username": "tim",
                                       "password": "correct-horse-battery"})[0] == 200
    # a WRONG password → 401 + a failure audit
    code, _ = _post(port, "/api/login", {"username": "tim", "password": "wrong-password"}, token=None)
    assert code == 401
    # the RIGHT password → 200 + a success audit, and a working bearer
    code, ok = _post(port, "/api/login", {"username": "tim", "password": "correct-horse-battery"}, token=None)
    assert code == 200 and ok["authenticated"] and ok.get("bearer")

    ev = _authn_events(s)
    succ = [e for e in ev if e.get("event") == "authn.login.success" and e.get("method") == "password"]
    fail = [e for e in ev if e.get("event") == "authn.login.failure" and e.get("method") == "password"]
    assert succ and succ[-1]["username"] == "tim" and succ[-1]["outcome"] == "success"
    assert fail and fail[-1]["reason"] == "bad_credentials"
    # SECRET-FREE: the minted bearer, the password, and the token appear in NO audit payload
    blob = json.dumps(ev)
    assert ok["bearer"] not in blob
    assert "correct-horse-battery" not in blob and "wrong-password" not in blob and TOKEN not in blob


def test_bearer_login_failure_is_audited():
    s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    code, _ = _post(port, "/api/login", {"token": "not-a-real-bearer-token"}, token=None)
    assert code == 401
    ev = _authn_events(s)
    assert any(e.get("event") == "authn.login.failure" and e.get("method") == "bearer"
               and e.get("reason") == "invalid_token" for e in ev)


def test_logout_is_audited():
    s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    code, ok = _post(port, "/api/logout", {})     # the owner token is same-origin authenticated
    assert code == 200 and ok["ok"]
    assert any(e.get("event") == "authn.logout" for e in _authn_events(s))


# --- PRODUCTION positive control: the owner token grants nothing ------------------

def test_production_owner_token_grants_nothing(monkeypatch):
    s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    # baseline (dev): the owner token IS owner
    code, who = _get(port, "/api/whoami")
    assert code == 200 and who["authenticated"] and who["role"] == "owner"

    monkeypatch.setenv("VIGIL_POSTURE", "production")
    # whoami now reports NOT authenticated for the same token; the owner-only + action planes refuse it
    code, who = _get(port, "/api/whoami")
    assert code == 200 and who.get("authenticated") is False, "prod: URL/shared token must not be owner"
    assert _get(port, "/api/accounts")[0] == 401
    assert _post(port, "/api/action", {"action": "create_account", "username": "x", "role": "viewer"})[0] == 403
