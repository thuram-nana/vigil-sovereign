"""
Dynamic DOM-XSS confirmation in a real headless browser.

A vulnerable page sinks the URL fragment into innerHTML; a safe page uses
textContent. The injected <img onerror> sets a marker attribute on <body> only if
it executes, so the side-effect oracle confirms the vulnerable page and stays
silent on the safe one. Skipped where no browser is installed.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from framework.v2.scanner.browser import find_browser, render_dom, scan_dom_xss

pytestmark = pytest.mark.skipif(find_browser() is None, reason="no headless Chromium/Chrome installed")

_VULN = b"""<html><body><div id="out"></div><script>
  var h = decodeURIComponent(location.hash.slice(1));
  document.getElementById("out").innerHTML = h;   // DOM-XSS sink
</script></body></html>"""

_SAFE = b"""<html><body><div id="out"></div><script>
  var h = decodeURIComponent(location.hash.slice(1));
  document.getElementById("out").textContent = h;  // safe: no HTML parsing
</script></body></html>"""


def _make(page: bytes) -> type[BaseHTTPRequestHandler]:
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

    return _H


@contextlib.contextmanager
def _server(page: bytes) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make(page))
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def test_render_dom_executes_javascript() -> None:
    with _server(_VULN) as base:
        dom = render_dom(base + "#%3Cb%3EHELLO_DOM%3C/b%3E")  # #<b>HELLO_DOM</b>
        assert dom is not None and "HELLO_DOM" in dom


def test_dom_xss_confirmed_in_browser_on_vulnerable_page() -> None:
    with _server(_VULN) as base:
        confirmed = scan_dom_xss(base, inject="fragment", timeout=30.0)
        assert confirmed is not None, "browser did not confirm DOM-XSS on the vulnerable page"
        assert confirmed.bug_class == "dom_xss"
        assert confirmed.confirmed_by.value == "side_effect"


def test_dom_xss_not_confirmed_on_safe_page() -> None:
    with _server(_SAFE) as base:
        confirmed = scan_dom_xss(base, inject="fragment", timeout=30.0)
        assert confirmed is None, "textContent page must not be confirmed as DOM-XSS"
