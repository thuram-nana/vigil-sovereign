"""Wave 2b (parity) — the sovereign `/api/doctor` read: the in-process install/health report the
`sigil doctor --json` CLI emits. Operator+ (it surfaces the redacted config + posture); token required."""
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

TOKEN = "owner-shared-token-doctor"


def _spine():
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _serve(sp):
    ensure_owner_keypair()
    s = build_server(token=TOKEN, port=0, spine_path=sp)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _get(port, path, token=TOKEN):
    h = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
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


def _post(port, path, body, token=TOKEN):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:  # noqa: BLE001
            return e.code, {}


def _make_account(port, username, role):
    code, d = _post(port, "/api/action", {"action": "create_account", "username": username, "role": role})
    assert code == 200, d
    return d["bearer_token"]


def test_doctor_route_returns_the_report():
    _s, port = _serve(_spine())
    code, d = _get(port, "/api/doctor")
    assert code == 200
    assert isinstance(d.get("ok"), bool)
    assert isinstance(d.get("checks"), list) and d["checks"], "the doctor report carries at least one check"
    # each check is the shape the SPA renders
    c0 = d["checks"][0]
    assert {"id", "ok", "required"} <= set(c0.keys())
    # the report surfaces posture + the production gate (both diagnostic, no secret)
    assert "posture" in d and "production_gate" in d


def test_doctor_route_requires_a_token():
    _s, port = _serve(_spine())
    code, _d = _get(port, "/api/doctor", token=None)
    assert code == 401


def test_doctor_route_is_operator_plus_viewer_refused():
    # the report shows the redacted config + posture → operator+ (config_nonsecret). A viewer bearer is 403.
    _s, port = _serve(_spine())
    viewer = _make_account(port, "vera", "viewer")
    code, _d = _get(port, "/api/doctor", token=viewer)
    assert code == 403
    # an operator bearer is admitted
    operator = _make_account(port, "otto", "operator")
    code2, d2 = _get(port, "/api/doctor", token=operator)
    assert code2 == 200 and isinstance(d2.get("checks"), list)


def test_doctor_route_redacts_a_real_injected_secret(monkeypatch):
    # MUTATION-SENSITIVE negative control: inject KNOWN secrets, then assert the report both (a) omits the
    # raw value AND (b) shows the field REDACTED — so this flips red if `_redact` (config.py) is bypassed.
    # A blanket "no secret substring" check alone is vacuous when nothing secret is set (RED-PEN BLOCK-1).
    api_key = "sk-ant-DOCTORTEST-SUPERSECRET-abc123"
    # NB: the password carries an UNESCAPED `@` (`hunter2@PASSWORD`) — a functioning DSN (urllib splits
    # userinfo on the LAST @), so a first-@ strip would leak the `PASSWORD` tail to operator+ (RED-PEN BLOCK-2).
    qdrant = "http://vera:hunter2@PASSWORD@10.0.0.5:6333"  # creds embedded in a NON-secret-named key (C-1)
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", api_key)
    monkeypatch.setenv("SIGIL_QDRANT_URL", qdrant)
    _s, port = _serve(_spine())
    _code, d = _get(port, "/api/doctor")
    cfg = d.get("effective_config") or {}
    # (a) the field carrying the API key is REDACTED (name-hint) — not merely "the value happens to be unset"
    assert cfg.get("ANTHROPIC_API_KEY") == "***redacted***", cfg.get("ANTHROPIC_API_KEY")
    # (b) the WHOLE userinfo (up to the last @) is stripped, host preserved — no password tail survives
    assert cfg.get("QDRANT_URL") == "http://***@10.0.0.5:6333", cfg.get("QDRANT_URL")
    # (c) neither raw secret nor ANY distinctive fragment (incl. the post-@ password tail) appears in the JSON
    blob = json.dumps(d)
    for needle in (api_key, "hunter2", "PASSWORD", "vera:hunter2"):
        assert needle not in blob, f"doctor report leaked {needle!r}"


def test_doctor_route_leaks_no_key_material():
    # a broader sweep: with no secret injected the report still carries no key/cred material shapes
    _s, port = _serve(_spine())
    _code, d = _get(port, "/api/doctor")
    blob = json.dumps(d).lower()
    for needle in ("-----begin", "private key", "bearer_token", "cred_hash", "cred_salt"):
        assert needle not in blob, f"doctor report leaked {needle!r}"
