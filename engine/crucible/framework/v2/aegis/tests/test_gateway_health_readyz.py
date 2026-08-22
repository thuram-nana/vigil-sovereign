"""W6-1 — real /healthz (liveness) and /readyz (dependency-checking readiness) on the AEGIS gateway.

The gateway is a transparent reverse-proxy: normally EVERY path is forwarded to the fixed upstream. The
two probe routes are the deliberate exception — answered LOCALLY (GET/HEAD only, exact path), so a
k8s/LB probe can reach the firewall itself without a credential. /readyz is a LIVE port probe of the
gateway's REAL dependency (the operator's fixed upstream) and returns 503 when it is down — proven
not-a-constant by taking the upstream offline.
"""
from __future__ import annotations

import http.server
import json
import socketserver
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.models import AegisConfig


class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):  # noqa: D401 — quiet
        return

    def _reply(self):
        body = f"UPSTREAM-OK path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _run_gateway(upstream_port: int):
    cfg = AegisConfig(deployment_secret="k", mode="observe", honeypot_paths=[])
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:  # noqa: S310
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _free_port() -> int:
    """A port with nothing listening — a genuinely down upstream for the negative control."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_healthz_answered_locally_not_forwarded(upstream):
    gw, port = _run_gateway(upstream)
    try:
        st, body = _get(port, "/healthz")
        assert st == 200, body
        assert json.loads(body) == {"ok": True}
        assert "UPSTREAM-OK" not in body            # answered by the gateway, not the upstream
    finally:
        gw.shutdown(); gw.server_close()


def test_readyz_200_when_upstream_up(upstream):
    gw, port = _run_gateway(upstream)
    try:
        st, body = _get(port, "/readyz")
        assert st == 200, body
        d = json.loads(body)
        assert d["ok"] is True
        assert any(c["name"] == "upstream" and c["ok"] for c in d["checks"])
    finally:
        gw.shutdown(); gw.server_close()


def test_readyz_503_when_upstream_down_negative_control():
    """NEGATIVE CONTROL: point the gateway at a dead upstream port — /readyz flips to 503, not a constant."""
    gw, port = _run_gateway(_free_port())
    try:
        st, body = _get(port, "/readyz")
        assert st == 503, body
        d = json.loads(body)
        assert d["ok"] is False
        assert any(c["name"] == "upstream" and not c["ok"] for c in d["checks"])
    finally:
        gw.shutdown(); gw.server_close()


def test_non_probe_path_still_forwards(upstream):
    """The interception is exact-path only: an ordinary request still reaches the upstream unchanged."""
    gw, port = _run_gateway(upstream)
    try:
        st, body = _get(port, "/api/thing")
        assert st == 200
        assert "UPSTREAM-OK path=/api/thing" in body
    finally:
        gw.shutdown(); gw.server_close()


def test_probes_expose_no_secret():
    gw, port = _run_gateway(_free_port())
    try:
        for path in ("/healthz", "/readyz"):
            _, body = _get(port, path)
            low = body.lower()
            assert "127.0.0.1" not in body          # no upstream address leaks
            assert "secret" not in low
            assert "traceback" not in low
    finally:
        gw.shutdown(); gw.server_close()
