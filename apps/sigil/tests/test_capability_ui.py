"""W0 — the cockpit Settings section: the owner-signed capability actions on the action plane + the
`capabilities` field on the read plane. Reuses the WS-C action-plane gate (token + exact Origin + Host).

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_capability_ui.py -q
"""
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.spine.store import SpineStore
from sigil.ui.server import build_server

TOKEN = "cap-test-token-xyz"


def _spine():
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _serve(spine_path):
    srv = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _get(port, path, *, token=TOKEN, headers=None):
    h = dict(headers or {})
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _post(port, path, body, *, token=TOKEN, headers=None):
    h = dict(headers or {})
    if token is not None:
        h["X-SIGIL-Token"] = token
    h["Content-Type"] = "application/json"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _caps(port):
    return json.loads(_get(port, "/api/snapshot")[1])["capabilities"]


def test_snapshot_exposes_capability_state():
    srv, port = _serve(_spine())
    try:
        caps = _caps(port)
        assert caps == {"gesture": "enabled", "voice": "enabled", "autolearn": "enabled"}
    finally:
        srv.shutdown()


def test_disable_and_enable_gesture_via_action_plane():
    srv, port = _serve(_spine())
    try:
        good = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
        assert _post(port, "/api/action", {"action": "disable_gesture"}, headers=good)[0] == 200
        assert _caps(port)["gesture"] == "disabled" and _caps(port)["voice"] == "enabled"
        assert _post(port, "/api/action", {"action": "enable_gesture"}, headers=good)[0] == 200
        assert _caps(port)["gesture"] == "enabled"
    finally:
        srv.shutdown()


def test_disable_both():
    srv, port = _serve(_spine())
    try:
        good = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
        assert _post(port, "/api/action", {"action": "disable_both"}, headers=good)[0] == 200
        # "both" is gesture+voice only — autolearn is an independent toggle and stays enabled.
        assert _caps(port) == {"gesture": "disabled", "voice": "disabled", "autolearn": "enabled"}
    finally:
        srv.shutdown()


def test_typed_ask_survives_a_voice_disable():
    """End-to-end: disabling voice must NOT break the cockpit's typed /api/ask box (the shared KernelDispatch
    is channel-ungated). The response is whatever the kernel returns (no kernel in CI) but NEVER the
    voice-disabled message."""
    srv, port = _serve(_spine())
    try:
        good = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
        assert _post(port, "/api/action", {"action": "disable_voice"}, headers=good)[0] == 200
        assert _caps(port)["voice"] == "disabled"
        code, body = _get(port, "/api/ask?q=hello", headers=good)   # /api/ask carries the action gate
        assert code == 200 and "voice control is disabled" not in body, \
            "typed asks stay ungated by the voice latch"
    finally:
        srv.shutdown()


def test_capability_action_is_gated_like_every_action():
    """A capability action still needs the token + exact Origin + Host (reuses the WS-C action gate)."""
    srv, port = _serve(_spine())
    try:
        # no token → 403
        assert _post(port, "/api/action", {"action": "disable_gesture"}, token=None,
                     headers={"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"})[0] == 403
        # cross-origin → 403
        assert _post(port, "/api/action", {"action": "disable_gesture"},
                     headers={"Origin": "http://evil.example", "Host": f"127.0.0.1:{port}"})[0] == 403
        assert _caps(port)["gesture"] == "enabled", "no gated action took effect"
    finally:
        srv.shutdown()
