"""W6-1 — real /healthz (liveness) and /readyz (dependency-checking readiness) on the sovereign
servers (the glass-cockpit UI and the WireGuard bridge).

Both probes are UNAUTHENTICATED and Host-UNGATED (a k8s/LB probe presents neither the session token /
device envelope nor the operator's Host) and expose NO secret. `/readyz` checks the server's REAL
dependency — the sovereign spine store — so it returns 200 only when the spine opens and 503 when it
does not. The 200/503 split is proven not-a-constant by driving a genuinely broken spine (its home is a
regular file, so the store cannot be created).

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=packages/core/vigil_core:apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest -q apps/sigil/tests/test_health_readyz.py
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.bridge.server import build_server as build_bridge
from sigil.spine.store import SpineStore
from sigil.ui.server import build_server as build_ui

TOKEN = "owner-shared-token-abc123"


def _healthy_spine() -> str:
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _broken_spine() -> str:
    """A spine path whose HOME is a regular file — SpineStore cannot mkdir its parent, so the store
    genuinely fails to open (the dependency is deliberately down)."""
    d = tempfile.mkdtemp()
    f = os.path.join(d, "not-a-dir")
    with open(f, "w", encoding="utf-8") as fh:
        fh.write("x")
    return os.path.join(f, "spine.jsonl")


def _get(port: int, path: str, *, host: str | None = None, token: str | None = None):
    h = {}
    if host is not None:
        h["Host"] = host
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _serve_ui(spine_path):
    srv = build_ui(token=TOKEN, port=0, spine_path=spine_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _serve_bridge(spine_path):
    srv = build_bridge(addr="127.0.0.1", port=0, spine_path=spine_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


# ---- glass-cockpit UI --------------------------------------------------------------------------

def test_ui_healthz_is_unauthenticated_and_host_ungated():
    srv, port = _serve_ui(_healthy_spine())
    try:
        # no token, and a Host a probe would send (not the anti-rebind allowlist) -> still 200.
        code, body = _get(port, "/healthz", host="kube-probe/1.0", token=None)
        assert code == 200, body
        assert json.loads(body) == {"ok": True}
    finally:
        srv.shutdown(); srv.server_close()


def test_ui_readyz_200_when_spine_opens():
    srv, port = _serve_ui(_healthy_spine())
    try:
        code, body = _get(port, "/readyz", host="kube-probe/1.0", token=None)
        assert code == 200, body
        d = json.loads(body)
        assert d["ok"] is True
        assert any(c["name"] == "spine" and c["ok"] for c in d["checks"])
    finally:
        srv.shutdown(); srv.server_close()


def test_ui_readyz_503_when_spine_down_negative_control():
    """NEGATIVE CONTROL: a genuinely broken spine flips /readyz to 503 — the endpoint is not a constant."""
    srv, port = _serve_ui(_broken_spine())
    try:
        code, body = _get(port, "/readyz", host="kube-probe/1.0", token=None)
        assert code == 503, body
        d = json.loads(body)
        assert d["ok"] is False
        assert any(c["name"] == "spine" and not c["ok"] for c in d["checks"])
    finally:
        srv.shutdown(); srv.server_close()


# ---- WireGuard bridge --------------------------------------------------------------------------

def test_bridge_healthz_is_unauthenticated_and_host_ungated():
    srv, port = _serve_bridge(_healthy_spine())
    try:
        code, body = _get(port, "/healthz", host="kube-probe/1.0")
        assert code == 200, body
        assert json.loads(body) == {"ok": True}
    finally:
        srv.shutdown(); srv.server_close()


def test_bridge_readyz_200_up_503_down_negative_control():
    srv, port = _serve_bridge(_healthy_spine())
    try:
        code, body = _get(port, "/readyz", host="kube-probe/1.0")
        assert code == 200, body
        assert json.loads(body)["ok"] is True
    finally:
        srv.shutdown(); srv.server_close()

    srv, port = _serve_bridge(_broken_spine())
    try:
        code, body = _get(port, "/readyz", host="kube-probe/1.0")
        assert code == 503, body
        assert json.loads(body)["ok"] is False
    finally:
        srv.shutdown(); srv.server_close()


# ---- no secret leaks on either probe -----------------------------------------------------------

def test_probes_expose_no_secret():
    """The probe bodies must never carry the session token, a spine PATH, or account state."""
    srv, port = _serve_ui(_broken_spine())        # failure path is where a path/exc-message could leak
    try:
        for path in ("/healthz", "/readyz"):
            _, body = _get(port, path, host="kube-probe/1.0", token=None)
            low = body.lower()
            assert TOKEN not in body
            assert "/" not in body                 # no filesystem path in the body
            assert "spine.jsonl" not in low
            assert "traceback" not in low
    finally:
        srv.shutdown(); srv.server_close()
