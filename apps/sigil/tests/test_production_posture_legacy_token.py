"""W10-7 — the legacy embedded shared owner token is gated OUT of the PRODUCTION posture.

The cockpit's printed shared session token maps to `OWNER_PRINCIPAL` (`server._principal_for_token`) — a
deliberate fail-open so the operator physically at the host is never locked out. That is a development
convenience, indefensible in a deployment someone else runs. Under `VIGIL_POSTURE=production` the shared
token MUST be refused (per-user proof-of-possession auth is required there); outside production it MUST keep
working so nothing already deployed breaks, and it can be opted out of with `SIGIL_LEGACY_OWNER_TOKEN=0`.

These tests exercise the RUNTIME auth refusal end-to-end over HTTP:

* the shared token authenticates outside production (negative control / backcompat) — reads, whoami-owner,
  the `/api/ask` owner action gate, and the `/api/action` plane;
* under `VIGIL_POSTURE=production` the SAME shared token is refused everywhere (whoami→anonymous, reads 401,
  actions 403) — THIS FAILS WITHOUT THE CHANGE (the pre-W10-7 server resolves it to owner regardless of
  posture);
* the gate is TARGETED, not a blanket lockout: a per-user bearer minted before the flip STILL authenticates
  under production, so per-user auth keeps working;
* the explicit opt-out (`SIGIL_LEGACY_OWNER_TOKEN=0`) refuses the shared token even OUT of production;
* a wrong / unknown token is refused in every posture (the gate is not a no-op that flips everything).

Pure-sovereign — imports `sigil.*` only; runs in the required `sigil-governor` CI job (the whole
`apps/sigil/tests/` dir is collected there, guarded by `test_ci_sigil_tests_all_run.py`).
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest

from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-prod-gate-xyz789"


def _spine():
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _serve():
    ensure_owner_keypair()                                   # persisted owner identity signs grants
    srv = build_server(token=TOKEN, port=0, spine_path=_spine())
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _get(port, path, *, token=TOKEN):
    h = {"X-SIGIL-Token": token} if token is not None else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _post(port, path, body, *, token=TOKEN):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}",
         "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _whoami(port, token):
    code, body = _get(port, "/api/whoami", token=token)
    assert code == 200, body                                  # whoami is token-optional (never 401)
    return json.loads(body)


# ---------------------------------------------------------------- backcompat: works outside production

def test_shared_token_is_accepted_outside_production(monkeypatch):
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    monkeypatch.delenv("SIGIL_LEGACY_OWNER_TOKEN", raising=False)
    srv, port = _serve()
    try:
        who = _whoami(port, TOKEN)
        assert who["authenticated"] is True and who["role"] == "owner"
        assert _get(port, "/api/snapshot")[0] == 200                 # read plane
        # /api/action plane authenticates the owner too (a trivial action shape is enough to prove auth)
        assert _post(port, "/api/action", {"action": "create_account",
                                           "username": "alice", "role": "operator"})[0] == 200
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- W10-7: refused under production

def test_shared_token_is_refused_under_production(monkeypatch):
    # THIS FAILS WITHOUT THE CHANGE: the pre-W10-7 server resolves the shared token to OWNER regardless of
    # posture, so whoami would report owner and the reads/actions would succeed.
    monkeypatch.delenv("SIGIL_LEGACY_OWNER_TOKEN", raising=False)
    srv, port = _serve()
    try:
        monkeypatch.setenv("VIGIL_POSTURE", "production")
        who = _whoami(port, TOKEN)
        assert who["authenticated"] is False                         # no longer resolves to owner
        assert _get(port, "/api/snapshot")[0] == 401                 # read plane refused
        assert _get(port, "/api/ask?q=hi")[0] == 401                 # /api/ask closed at the principal gate
        assert _post(port, "/api/action", {"action": "create_account",
                                           "username": "bob", "role": "operator"})[0] == 403
        # prod / Prod / PRODUCTION all select the posture (case-insensitive) — same refusal.
        for val in ("prod", "PRODUCTION", "Prod"):
            monkeypatch.setenv("VIGIL_POSTURE", val)
            assert _whoami(port, TOKEN)["authenticated"] is False, val
    finally:
        srv.shutdown()


def test_per_user_bearer_still_authenticates_under_production(monkeypatch):
    # The gate is TARGETED: only the shared owner token is refused. A per-user bearer minted BEFORE the flip
    # keeps authenticating under production — per-user auth is the intended replacement, not collateral.
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    monkeypatch.delenv("SIGIL_LEGACY_OWNER_TOKEN", raising=False)
    srv, port = _serve()
    try:
        code, body = _post(port, "/api/action",
                           {"action": "create_account", "username": "carol", "role": "operator"})
        assert code == 200, body
        bearer = json.loads(body)["bearer_token"]
        # sanity: both credentials work out of production
        assert _whoami(port, TOKEN)["role"] == "owner"
        assert _whoami(port, bearer)["role"] == "operator"
        # flip to production: the shared token dies, the per-user bearer lives.
        monkeypatch.setenv("VIGIL_POSTURE", "production")
        assert _whoami(port, TOKEN)["authenticated"] is False
        who = _whoami(port, bearer)
        assert who["authenticated"] is True and who["role"] == "operator"
        assert _get(port, "/api/snapshot", token=bearer)[0] == 200
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- explicit opt-out + negative control

def test_shared_token_opt_out_refuses_even_outside_production(monkeypatch):
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    srv, port = _serve()
    try:
        monkeypatch.setenv("SIGIL_LEGACY_OWNER_TOKEN", "0")          # operator opts into per-user-only auth
        assert _whoami(port, TOKEN)["authenticated"] is False
        assert _get(port, "/api/snapshot")[0] == 401
        # a truthy / unset value keeps the default fail-open behaviour
        monkeypatch.setenv("SIGIL_LEGACY_OWNER_TOKEN", "1")
        assert _whoami(port, TOKEN)["role"] == "owner"
    finally:
        srv.shutdown()


@pytest.mark.parametrize("posture", [None, "production"])
def test_unknown_token_is_refused_in_every_posture(monkeypatch, posture):
    # NEGATIVE CONTROL: the gate never turns into a fail-open for a wrong/unknown token in ANY posture.
    monkeypatch.delenv("SIGIL_LEGACY_OWNER_TOKEN", raising=False)
    if posture is None:
        monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    else:
        monkeypatch.setenv("VIGIL_POSTURE", posture)
    srv, port = _serve()
    try:
        assert _get(port, "/api/snapshot", token="wrong-token-000000")[0] == 401
        assert _get(port, "/api/snapshot", token=None)[0] == 401
        assert _whoami(port, "unknown-but-wellformed-aaaaaa")["authenticated"] is False
    finally:
        srv.shutdown()
