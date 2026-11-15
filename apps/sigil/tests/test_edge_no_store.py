"""Every customer-edge `/api/*` response and every cockpit JSON response carries `Cache-Control: no-store`, so
no browser or intermediary keeps a tenant's or the owner's data — whatever the CDN in front is configured to
do. The customer edge's static app assets and the cockpit's two static assets keep their own caching.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:packages/core/vigil_core \
     .venv-sovereign/bin/python -m pytest -q apps/sigil/tests/test_edge_no_store.py
"""
from __future__ import annotations

import json
import socket
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sigil.spine.store import SpineStore
from sigil.ui import custui
from sigil.ui.custui import build_customer_server
from sigil.ui.server import build_server

_HOP = "hop-key-for-the-no-store-tests"
_TOKEN = "no-store-test-token"


class _Provisioner(BaseHTTPRequestHandler):
    """Answers every provisioner hop with a fixed JSON body (the edge only relays it)."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(n)
        body = json.dumps({"ok": True, "username": "", "items": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(srv):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture()
def edge(tmp_path):
    custui._readyz_cache.clear()
    prov = _serve(ThreadingHTTPServer(("127.0.0.1", 0), _Provisioner))
    (tmp_path / "sessions").mkdir()
    srv = _serve(build_customer_server(host="127.0.0.1", port=0, hop_key=_HOP,
                                       provision_base=f"http://127.0.0.1:{prov.server_address[1]}",
                                       sessions_dir=str(tmp_path / "sessions")))
    port = srv.server_address[1]
    yield port
    srv.shutdown()
    prov.shutdown()


def _req(port, path, *, method="GET", body=None, headers=None):
    h = {"Host": f"127.0.0.1:{port}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.update({"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"})
    h.update(headers or {})
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers=h)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=5) as r:
            return r.status, r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/api/customer/whoami", None),
    ("GET", "/api/customer/billing", None),                 # 401: no session
    ("GET", "/api/customer/not-a-route", None),             # 404 under /api/
    ("POST", "/api/customer/login", {"email": "a@example.test", "password": "x"}),
    ("POST", "/api/customer/logout", {}),
    ("POST", "/api/customer/no-such-action", {}),
    ("GET", "/healthz", None),
    ("GET", "/readyz", None),
])
def test_every_customer_api_response_is_no_store(edge, method, path, body):
    status, headers = _req(edge, path, method=method, body=body)
    assert status < 500, status
    assert headers.get("Cache-Control") == "no-store", (path, status, dict(headers))


def test_a_cross_origin_refusal_is_no_store_too(edge):
    status, headers = _req(edge, "/api/customer/login", method="POST", body={"email": "x"},
                           headers={"Origin": "https://evil.example"})
    assert status == 403 and headers.get("Cache-Control") == "no-store"


def test_customer_static_app_assets_keep_their_own_caching(edge):
    status, headers = _req(edge, "/")
    assert status == 200 and headers.get("Content-Type", "").startswith("text/html")
    assert headers.get("Cache-Control") != "no-store"


def _cockpit():
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hello"})
    srv = _serve(build_server(token=_TOKEN, port=0, spine_path=p))
    return srv, srv.server_address[1]


@pytest.mark.parametrize("path", ["/healthz", "/readyz", "/api/whoami", "/api/snapshot", "/api/no-such-route", "/"])
def test_every_cockpit_json_and_page_response_is_no_store(path):
    srv, port = _cockpit()
    try:
        status, headers = _req(port, path, headers={"X-SIGIL-Token": _TOKEN})
        assert status < 500, (path, status)
        assert headers.get("Cache-Control") == "no-store", (path, status, dict(headers))
    finally:
        srv.shutdown()


@pytest.mark.parametrize("asset", ["/static/app.js", "/static/style.css"])
def test_cockpit_static_assets_keep_their_own_caching(asset):
    srv, port = _cockpit()
    try:
        status, headers = _req(port, asset)
        assert status == 200, asset
        assert headers.get("Cache-Control") != "no-store"
    finally:
        srv.shutdown()


def test_the_no_store_tests_reach_a_live_listener():
    # negative control: the fixture really serves (a dead port is refused, not silently "no-store")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(urllib.error.URLError):
        _req(port, "/api/customer/whoami")


@pytest.mark.parametrize("path,ctype,expected", [
    ("/api/customer/oidc/login", "text/html", True),        # a redirect or any non-JSON body under /api/
    ("/api/customer/whoami?x=1", "application/json", True),
    ("/healthz", "application/json", True),
    ("/", "text/html; charset=utf-8", False),                # the SPA shell keeps its own caching
    ("/app.js", "application/javascript", False),
])
def test_the_customer_edge_no_store_rule(path, ctype, expected):
    h = custui.CustomerHandler.__new__(custui.CustomerHandler)
    h.path = path
    assert h._no_store(ctype) is expected
