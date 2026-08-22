"""W6-1 — real /healthz (liveness) and /readyz (dependency-checking readiness) on the unified reverse
proxy (`vigil up`).

Every real proxy route is per-user authenticated (delegated to the sovereign whoami) and the plane
control surface is private-peer/Host/token-gated. A k8s/LB probe can satisfy none of that, so /healthz
and /readyz are answered by the proxy itself BEFORE plane control, routing, and auth — UNAUTHENTICATED
and carrying no secret. /readyz is a LIVE port probe of the proxy's REAL dependency (the sovereign
backend it federates every authenticated request to), returning 503 when that writer is down — proven
not-a-constant by pointing the sovereign backend at a dead port.

Run: PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core \
     .venv-offense/bin/python -m pytest -q integration/tests/test_uiproxy_health_readyz.py
"""
from __future__ import annotations

import http.server
import json
import socket
import threading
import urllib.error
import urllib.request

import pytest

from vigil_integration import uiproxy


class _Sink(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):  # noqa: D401 — quiet
        return

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def _start_sink() -> tuple[http.server.ThreadingHTTPServer, int]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _serve_dir(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "tokens.css").write_text(":root{--a:1}", encoding="utf-8")
    (src / "components.css").write_text(".btn{}", encoding="utf-8")
    for j in uiproxy.BUNDLE_JS:
        (src / j).write_text(f"/*{j}*/", encoding="utf-8")
    (src / "index.html").write_text("<body></body>", encoding="utf-8")
    serve = tmp_path / "serve"
    uiproxy.assemble_serve_dir(src, serve, token="T")
    return serve


def _build_proxy(serve, *, sov_port: int):
    backends = {"sovereign": ("127.0.0.1", sov_port),
                "console": ("127.0.0.1", _free_port()),
                "api": ("127.0.0.1", _free_port())}
    httpd = uiproxy.make_proxy_server("127.0.0.1", _free_port(), serve, token="T", backends=backends)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def _get(url: str, *, host: str | None = None):
    """A probe request: NO token, and a caller-chosen Host a k8s/LB probe would send."""
    h = {}
    if host is not None:
        h["Host"] = host
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_forwarded_route_still_requires_auth(tmp_path):
    """Control: an ordinary proxied route with no token is refused — the probes below bypass a live gate."""
    sink, sov = _start_sink()
    httpd, base = _build_proxy(_serve_dir(tmp_path), sov_port=sov)
    try:
        st, _ = _get(base + "/sovereign/api/snapshot", host="kube-probe/1.0")
        assert st == 401
    finally:
        httpd.shutdown(); httpd.server_close(); sink.shutdown(); sink.server_close()


def test_healthz_unauthenticated_and_host_ungated(tmp_path):
    sink, sov = _start_sink()
    httpd, base = _build_proxy(_serve_dir(tmp_path), sov_port=sov)
    try:
        st, body = _get(base + "/healthz", host="kube-probe/1.0")
        assert st == 200, body
        assert json.loads(body) == {"ok": True}
    finally:
        httpd.shutdown(); httpd.server_close(); sink.shutdown(); sink.server_close()


def test_readyz_200_when_sovereign_up(tmp_path):
    sink, sov = _start_sink()
    httpd, base = _build_proxy(_serve_dir(tmp_path), sov_port=sov)
    try:
        st, body = _get(base + "/readyz", host="kube-probe/1.0")
        assert st == 200, body
        d = json.loads(body)
        assert d["ok"] is True
        assert any(c["name"] == "sovereign" and c["ok"] for c in d["checks"])
    finally:
        httpd.shutdown(); httpd.server_close(); sink.shutdown(); sink.server_close()


def test_readyz_503_when_sovereign_down_negative_control(tmp_path):
    """NEGATIVE CONTROL: point the proxy's sovereign backend at a dead port — /readyz flips to 503."""
    httpd, base = _build_proxy(_serve_dir(tmp_path), sov_port=_free_port())
    try:
        st, body = _get(base + "/readyz", host="kube-probe/1.0")
        assert st == 503, body
        d = json.loads(body)
        assert d["ok"] is False
        assert any(c["name"] == "sovereign" and not c["ok"] for c in d["checks"])
    finally:
        httpd.shutdown(); httpd.server_close()


def test_probes_expose_no_secret(tmp_path):
    httpd, base = _build_proxy(_serve_dir(tmp_path), sov_port=_free_port())
    try:
        for path in ("/healthz", "/readyz"):
            _, body = _get(base + path, host="kube-probe/1.0")
            low = body.lower()
            assert "127.0.0.1" not in body       # no backend address leaks
            assert "token" not in low
            assert "traceback" not in low
    finally:
        httpd.shutdown(); httpd.server_close()


def test_readyz_debounces_backend_connects_no_amplification(tmp_path, monkeypatch):
    """An UNAUTHENTICATED /readyz must not let a caller amplify: many rapid probes collapse to at most one
    live backend connect within the debounce TTL (`_READYZ_TTL`), so a probe flood cannot become a flood of
    sovereign connects."""
    uiproxy._readyz_cache.clear()
    calls = {"n": 0}
    real = uiproxy._listening

    def _counting(host, port):
        calls["n"] += 1
        return real(host, port)

    monkeypatch.setattr(uiproxy, "_listening", _counting)
    sink, sov = _start_sink()
    httpd, base = _build_proxy(_serve_dir(tmp_path), sov_port=sov)
    try:
        for _ in range(25):
            st, _b = _get(base + "/readyz", host="kube-probe/1.0")
            assert st == 200
        assert calls["n"] == 1, f"expected 1 debounced backend connect, got {calls['n']}"
    finally:
        httpd.shutdown(); httpd.server_close(); sink.shutdown(); sink.server_close()
        uiproxy._readyz_cache.clear()
