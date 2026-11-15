"""The console's "new build — reload" check works on the login screen too: GET /__vigil/plane/version answers
before sign-in (a content hash of the served bundle; nothing secret or per-user), still only to a private peer
naming this proxy in Host/Origin, GET/HEAD only, no-store. Every other plane route still needs a session.
"""
from __future__ import annotations

import http.client
import json
import re
import socket
import threading
from pathlib import Path

import pytest

from vigil_integration import uiproxy

KIT = Path(__file__).resolve().parents[2] / "packages" / "vigil-ui"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def console(tmp_path):
    serve = tmp_path / "serve"
    uiproxy.assemble_serve_dir(KIT, serve, token="T")
    port = _free_port()
    httpd = uiproxy.make_proxy_server("127.0.0.1", port, serve, token="owner-token")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield port, (serve / ".build-id").read_text(encoding="utf-8")
    finally:
        httpd.shutdown()
        httpd.server_close()


def _req(port, method, path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, body=b"{}" if method == "POST" else None,
              headers={"Host": f"127.0.0.1:{port}", **(headers or {})})
    r = c.getresponse()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()


def test_the_build_answers_without_a_session(console):
    port, build = console
    status, h, body = _req(port, "GET", uiproxy.PLANE_VERSION_PATH)
    assert status == 200 and json.loads(body) == {"ok": True, "build": build}
    assert re.fullmatch(r"[0-9a-f]{12}", build)
    assert h["cache-control"] == "no-store" and "set-cookie" not in h


@pytest.mark.parametrize("headers", [{"Host": "evil.example"}, {"Origin": "https://evil.example"}])
def test_a_rebound_or_cross_origin_request_is_still_refused(console, headers):
    port, _build = console
    status, _h, body = _req(port, "GET", uiproxy.PLANE_VERSION_PATH, headers)
    assert status == 403 and b"build" not in body


def test_only_get_and_head(console):
    port, _build = console
    assert _req(port, "POST", uiproxy.PLANE_VERSION_PATH)[0] == 405
    status, _h, body = _req(port, "HEAD", uiproxy.PLANE_VERSION_PATH)
    assert status == 200 and body == b""


def test_every_other_plane_route_still_needs_a_session(console):
    port, _build = console
    status, _h, body = _req(port, "GET", uiproxy.PLANE_STATUS_PATH)
    assert status == 401 and b"build" not in body


def test_the_console_checks_its_build_from_boot_whatever_the_sign_in_state():
    app = (KIT / "app.js").read_text(encoding="utf-8")
    boot = app[app.index("function boot() {"):]
    boot = boot[: boot.index("\n  }\n")]
    assert "watchBuildVersion();" in boot
    assert 'const OFFENSE_VERSION_URL = "/__vigil/plane/version";' in app
