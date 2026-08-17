"""Claim 6 — the cockpit HTTP surface for RBAC: _principal(), reads-require-auth, /api/login,
/api/whoami, /api/accounts (owner-only), and PermissionDenied → 403.

The same X-SIGIL-Token carrier now bears EITHER the legacy owner token (→ OWNER_PRINCIPAL, fail-open
restricted to that EXACT token) OR a per-user bearer (→ its principal); anything else → 401. A per-user
operator can read + do operator ops but is refused owner-only ops with a 403 (distinct from a 400).
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-abc123"


def _spine():
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _serve(spine_path):
    ensure_owner_keypair()                                   # the persisted owner identity signs grants
    srv = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _get(port, path, *, token=TOKEN):
    h = {}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _post(port, path, body, *, token=TOKEN, origin=True):
    h = {"Content-Type": "application/json"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    if origin:
        h["Origin"] = f"http://127.0.0.1:{port}"
        h["Host"] = f"127.0.0.1:{port}"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _make_account(port, username, role):
    """Owner-create an account over HTTP; return its one-time bearer."""
    code, body = _post(port, "/api/action",
                       {"action": "create_account", "username": username, "role": role})
    assert code == 200, body
    return json.loads(body)["bearer_token"]


# --- reads require an authenticated principal ------------------------------------

def test_reads_require_a_principal():
    srv, port = _serve(_spine())
    try:
        assert _get(port, "/api/snapshot", token=None)[0] == 401       # no token
        assert _get(port, "/api/snapshot")[0] == 200                    # owner token → OWNER_PRINCIPAL
        assert _get(port, "/api/snapshot", token="WRONG")[0] == 401     # wrong token
        # a well-formed but UNKNOWN per-user token is refused too (fail-closed, never fail-open)
        assert _get(port, "/api/snapshot", token="unknown-but-wellformed-xyzxyz")[0] == 401
    finally:
        srv.shutdown()


def test_whoami_owner_and_anonymous():
    srv, port = _serve(_spine())
    try:
        code, body = _get(port, "/api/whoami")                          # token-optional
        d = json.loads(body)
        assert code == 200 and d["authenticated"] is True and d["role"] == "owner"
        assert "manage_users" in d["permissions"]
        code, body = _get(port, "/api/whoami", token=None)
        assert code == 200 and json.loads(body)["authenticated"] is False   # login gate case, NOT a 401
    finally:
        srv.shutdown()


# --- per-user bearer: login, reads, operator ops, owner-only refusals ------------

def test_login_verifies_a_bearer_and_reports_the_role():
    srv, port = _serve(_spine())
    try:
        bearer = _make_account(port, "otto", "operator")
        code, body = _post(port, "/api/login", {"token": bearer})
        d = json.loads(body)
        assert code == 200 and d["authenticated"] is True and d["username"] == "otto"
        assert d["role"] == "operator" and "approve_a2" in d["permissions"]
        # a bad token → 401 not-authenticated
        code, body = _post(port, "/api/login", {"token": "nope-nope-nope"})
        assert code == 401 and json.loads(body)["authenticated"] is False
    finally:
        srv.shutdown()


def test_per_user_operator_can_read_and_do_operator_ops_but_not_owner_ops():
    srv, port = _serve(_spine())
    try:
        bearer = _make_account(port, "otto", "operator")
        # the operator bearer is a valid principal → reads work
        assert _get(port, "/api/snapshot", token=bearer)[0] == 200
        # kill (safe direction, `read`) is allowed
        assert _post(port, "/api/action", {"action": "kill"}, token=bearer)[0] == 200
        # release (owner-only kill_release) → 403 PermissionDenied, NOT 400
        code, body = _post(port, "/api/action", {"action": "release"}, token=bearer)
        assert code == 403 and "permission denied" in body.lower()
        # user management → 403 for the operator
        assert _post(port, "/api/action",
                     {"action": "create_account", "username": "x", "role": "viewer"}, token=bearer)[0] == 403
    finally:
        srv.shutdown()


def test_viewer_bearer_is_refused_operator_and_owner_ops():
    srv, port = _serve(_spine())
    try:
        bearer = _make_account(port, "vera", "viewer")
        assert _get(port, "/api/snapshot", token=bearer)[0] == 200         # viewer can read
        # a viewer cannot even engage config (config_nonsecret is operator+) → 403
        assert _post(port, "/api/action",
                     {"action": "set_config", "env": "CRUCIBLE_LLM_MAX_WORKERS", "value": "8"},
                     token=bearer)[0] == 403
    finally:
        srv.shutdown()


# --- /api/accounts is owner-only -------------------------------------------------

def test_accounts_route_is_owner_only():
    srv, port = _serve(_spine())
    try:
        _make_account(port, "otto", "operator")
        # owner token → the list (usernames/roles only; no cred material)
        code, body = _get(port, "/api/accounts")
        d = json.loads(body)
        assert code == 200 and any(a["username"] == "otto" for a in d["accounts"])
        assert all("cred_hash" not in a and "cred_salt" not in a for a in d["accounts"])
        # a per-user operator bearer → 403 (manage_users is owner-only)
        opbearer = _make_account(port, "op2", "operator")
        assert _get(port, "/api/accounts", token=opbearer)[0] == 403
        # no token → 401
        assert _get(port, "/api/accounts", token=None)[0] == 401
    finally:
        srv.shutdown()


# --- owner shared-token fail-open is EXACT-MATCH only ----------------------------

def test_owner_token_is_the_only_fail_open_path():
    srv, port = _serve(_spine())
    try:
        # the owner token authenticates as owner
        assert json.loads(_get(port, "/api/whoami")[1])["role"] == "owner"
        # a token that merely SHARES a prefix with the owner token is not the owner (constant-time exact)
        assert _get(port, "/api/snapshot", token=TOKEN + "x")[0] == 401
        assert _get(port, "/api/snapshot", token=TOKEN[:-1])[0] == 401
    finally:
        srv.shutdown()
