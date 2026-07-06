"""
Browser egress control — the headless browser is confined at the resolver layer
to an allowlist (+ loopback), so the dynamic path is safe to run against a remote
target: the browser confirms in-scope DOM-XSS but CANNOT reach off-scope hosts.

Skip-gated on Chromium; all traffic is loopback.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from framework.v2.scanner.cdp import CdpBrowser, cdp_available

pytestmark = pytest.mark.skipif(not cdp_available(), reason="no Chromium/Chrome for the CDP driver")


class _OffScopeApp(BaseHTTPRequestHandler):
    """In-scope loopback page that (a) fetches an OFF-scope hostname and (b) has a
    DOM-XSS sink fed by ?q — so we can watch both the block and the in-scope fire."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = (
            b"<div id=o></div><script>"
            b"fetch('http://off-scope.example/x').then(()=>window.__r('REACHED')).catch(()=>window.__r('BLOCKED'));"
            b"document.getElementById('o').innerHTML=new URLSearchParams(location.search).get('q')||'';"
            b"</script>"
        )
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OffScopeApp)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def test_allowed_hosts_blocks_off_scope_but_keeps_in_scope_dom_xss() -> None:
    # allowlist has only a placeholder in-scope host; loopback is auto-allowed,
    # off-scope.example is NOT — its fetch must be refused at the resolver.
    with CdpBrowser(allowed_hosts={"in-scope.test"}) as br:
        sess = br.session()
        sess.add_binding("__r")
        with _server() as base:
            payload = "<img src=x onerror=window.__r('XSS')>"
            sess.navigate(base + "?q=" + urllib.parse.quote(payload), settle=1.3)
            calls = sess.binding_calls("__r")
    assert "XSS" in calls, "in-scope DOM-XSS should still execute"
    assert "BLOCKED" in calls, "off-scope fetch should be refused"
    assert "REACHED" not in calls, "off-scope host must never be reached"


def test_unrestricted_browser_is_the_default() -> None:
    # No allowed_hosts => no resolver rule added (loopback scan stays as before).
    br = CdpBrowser()
    assert br._allowed_hosts is None  # noqa: SLF001 (documents the default)
