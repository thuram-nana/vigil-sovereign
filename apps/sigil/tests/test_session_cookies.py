"""Slice 1c-ii — cookie-backed sessions end-to-end over the HTTP handler.

  * a password login sets an HttpOnly + SameSite=Strict `sigil_session` cookie (NOT Secure over dev http);
  * a request carrying ONLY that cookie (no X-SIGIL-Token) authenticates as the teammate;
  * logout invalidates the cookie session SERVER-SIDE (the id stops authenticating);
  * the owner `revoke_sessions` action signs out every cookie session at once;
  * revoking the ACCOUNT kills its cookie session immediately (re-validated each request);
  * under production posture the cookie carries Secure.
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.identity import ensure_owner_keypair
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-cookie-test"


def _serve(spine_path):
    ensure_owner_keypair()
    s = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _req(port, path, *, method="GET", body=None, token=None, cookie=None):
    h = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    if cookie is not None:
        h["Cookie"] = cookie
    data = None
    if body is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            j = json.loads(e.read().decode() or "{}")
        except Exception:  # noqa: BLE001
            j = {}
        return e.code, dict(e.headers), j


def _make_teammate(port):
    _req(port, "/api/action", method="POST", token=TOKEN,
         body={"action": "create_account", "username": "tina", "role": "operator"})
    _req(port, "/api/action", method="POST", token=TOKEN,
         body={"action": "set_password", "username": "tina", "password": "hunter2hunter2"})


def _login_cookie(port):
    code, headers, j = _req(port, "/api/login", method="POST",
                            body={"username": "tina", "password": "hunter2hunter2"})
    assert code == 200 and j["authenticated"], j
    sc = headers.get("Set-Cookie", "")
    assert "sigil_session=" in sc, sc
    sid = sc.split("sigil_session=", 1)[1].split(";", 1)[0]
    return sc, sid


def test_login_sets_httponly_cookie_and_it_authenticates():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    _make_teammate(port)
    sc, sid = _login_cookie(port)
    assert "HttpOnly" in sc and "SameSite=Strict" in sc and "Secure" not in sc   # dev: no Secure over http
    # a request with ONLY the cookie (no header token) authenticates as the teammate
    code, _h, who = _req(port, "/api/whoami", cookie=f"sigil_session={sid}")
    assert code == 200 and who["authenticated"] and who["username"] == "tina" and who["role"] == "operator"
    # a bogus cookie does not
    _c, _h, who2 = _req(port, "/api/whoami", cookie="sigil_session=not-a-real-session")
    assert who2.get("authenticated") is False


def test_logout_invalidates_the_cookie_session_serverside():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    _make_teammate(port)
    _sc, sid = _login_cookie(port)
    assert _req(port, "/api/whoami", cookie=f"sigil_session={sid}")[2]["authenticated"] is True
    code, headers, _j = _req(port, "/api/logout", method="POST", body={}, cookie=f"sigil_session={sid}")
    assert code == 200 and "Max-Age=0" in headers.get("Set-Cookie", "")
    assert _req(port, "/api/whoami", cookie=f"sigil_session={sid}")[2].get("authenticated") is False


def test_owner_revoke_sessions_signs_out_all():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    _make_teammate(port)
    _sc, sid = _login_cookie(port)
    assert _req(port, "/api/whoami", cookie=f"sigil_session={sid}")[2]["authenticated"] is True
    code, _h, j = _req(port, "/api/action", method="POST", token=TOKEN, body={"action": "revoke_sessions"})
    assert code == 200 and j["ok"] and j["revoked"] >= 1
    assert _req(port, "/api/whoami", cookie=f"sigil_session={sid}")[2].get("authenticated") is False


def test_revoking_the_account_kills_its_cookie_session():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    _make_teammate(port)
    _sc, sid = _login_cookie(port)
    assert _req(port, "/api/whoami", cookie=f"sigil_session={sid}")[2]["authenticated"] is True
    _req(port, "/api/action", method="POST", token=TOKEN,
         body={"action": "revoke_account", "username": "tina"})
    # re-validated against the account fold each request → the session is dead the moment the account is
    assert _req(port, "/api/whoami", cookie=f"sigil_session={sid}")[2].get("authenticated") is False


def test_production_cookie_is_secure(monkeypatch):
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    _make_teammate(port)                                        # created in dev over the owner action plane
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    code, headers, _j = _req(port, "/api/login", method="POST",
                             body={"username": "tina", "password": "hunter2hunter2"})
    assert code == 200
    sc = headers.get("Set-Cookie", "")
    assert "Secure" in sc and "HttpOnly" in sc and "SameSite=Strict" in sc
