"""HLTH-1 — real /healthz (liveness) and /readyz (dependency-checking readiness) on the keyless CUSTOMER
edge (`sigil serve-customer`, the `sigil-customer.service` long-running edge).

Every real customer route is cookie-authenticated and relayed to the sovereign provisioner. A k8s/LB probe
can present no customer cookie, so /healthz and /readyz are answered by the edge itself BEFORE the session
and relay plane — UNAUTHENTICATED, side-effect-free, and carrying no secret. /readyz is a LIVE port probe
of the edge's REAL dependency (the provisioner it federates every customer read/action to), returning 503
when that backend is down — proven not-a-constant by pointing the edge at a dead provisioner port.

Run: PYTHONPATH=apps/sigil:packages/core/vigil_core:. SIGIL_HOME=$(mktemp -d) \
     .venv-sovereign/bin/python -m pytest -q apps/sigil/tests/test_custui_health_readyz.py
"""
from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request

from sigil.ui import custui
from sigil.ui.custui import build_customer_server

_HOP = "hop-secret-should-never-appear-in-a-probe-body"


def _listen_sink() -> tuple[socket.socket, int]:
    """A bare LISTENING socket: a TCP connect to it completes (kernel backlog) without an accept, which is
    exactly what the edge's `/readyz` liveness connect needs — no provisioner semantics required."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    return s, s.getsockname()[1]


def _dead_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _edge(tmp_path, *, provisioner_port: int):
    custui._readyz_cache.clear()
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key=_HOP,
                                provision_base=f"http://127.0.0.1:{provisioner_port}",
                                sessions_dir=str(sessions))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", sessions


def _get(url: str):
    """A probe request: NO cookie, as a k8s/LB probe would send."""
    try:
        with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def test_healthz_unauthenticated_liveness(tmp_path):
    sink, pport = _listen_sink()
    srv, base, _ = _edge(tmp_path, provisioner_port=pport)
    try:
        st, hdrs, body = _get(base + "/healthz")
        assert st == 200, body
        assert json.loads(body) == {"ok": True}
        assert "Set-Cookie" not in hdrs            # a liveness probe mints nothing
    finally:
        srv.shutdown(); sink.close()


def test_readyz_200_when_provisioner_up(tmp_path):
    sink, pport = _listen_sink()
    srv, base, sessions = _edge(tmp_path, provisioner_port=pport)
    try:
        st, hdrs, body = _get(base + "/readyz")
        assert st == 200, body
        d = json.loads(body)
        assert d["ok"] is True
        assert any(c["name"] == "provisioner" and c["ok"] for c in d["checks"])
        assert "Set-Cookie" not in hdrs
        # reaches NO privileged state: the probe created no session on disk.
        assert list(sessions.iterdir()) == []
    finally:
        srv.shutdown(); sink.close()


def test_readyz_503_when_provisioner_down_negative_control(tmp_path):
    """NEGATIVE CONTROL: point the edge's provisioner at a dead port — /readyz flips to 503. Not a constant."""
    srv, base, _ = _edge(tmp_path, provisioner_port=_dead_port())
    try:
        st, _hdrs, body = _get(base + "/readyz")
        assert st == 503, body
        d = json.loads(body)
        assert d["ok"] is False
        assert any(c["name"] == "provisioner" and not c["ok"] for c in d["checks"])
    finally:
        srv.shutdown()


def test_probes_bypass_a_live_auth_gate_and_leak_no_secret(tmp_path):
    """The probes answer with no cookie, yet a real customer read with no cookie is refused 401 — proving
    the probes sit ahead of a LIVE gate (not an always-open edge), and neither probe body leaks a secret."""
    sink, pport = _listen_sink()
    srv, base, _ = _edge(tmp_path, provisioner_port=pport)
    try:
        # control: an ordinary customer READ with no session is refused BEFORE any hop.
        st, _h, _b = _get(base + "/api/customer/billing")
        assert st == 401
        for path in ("/healthz", "/readyz"):
            _st, _h, body = _get(base + path)
            low = body.lower()
            assert "127.0.0.1" not in body        # no provisioner address leaks
            assert _HOP not in body               # no hop secret leaks
            assert "token" not in low
            assert "traceback" not in low
    finally:
        srv.shutdown(); sink.close()


def test_readyz_debounces_backend_connects_no_amplification(tmp_path, monkeypatch):
    """An UNAUTHENTICATED /readyz must not let a caller amplify: many rapid probes collapse to at most one
    live provisioner connect within the debounce TTL (`_READYZ_TTL`)."""
    custui._readyz_cache.clear()
    calls = {"n": 0}
    real = custui._listening

    def _counting(host, port):
        calls["n"] += 1
        return real(host, port)

    monkeypatch.setattr(custui, "_listening", _counting)
    sink, pport = _listen_sink()
    srv, base, _ = _edge(tmp_path, provisioner_port=pport)
    try:
        for _ in range(25):
            st, _h, _b = _get(base + "/readyz")
            assert st == 200
        assert calls["n"] == 1, f"expected 1 debounced provisioner connect, got {calls['n']}"
    finally:
        srv.shutdown(); sink.close()
        custui._readyz_cache.clear()
