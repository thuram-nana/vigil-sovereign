"""
Headless-browser DOM rendering — the dynamic half of DOM-XSS analysis.

``render_dom`` drives headless Chromium/Chrome and returns the post-JavaScript
DOM, so a static source->sink candidate (``scanner.domxss``) can be checked
against what actually renders. Skipped where no working browser is installed.

DOM-XSS *confirmation* is deliberately NOT done here: a marker found in the
rendered DOM is substring detection — the exact false positive the
``DOM_EXECUTION`` oracle exists to refuse. Proven DOM-XSS execution is confirmed
by ``scanner.browser_xss`` (CDP binding call carrying a canary + the
``DOM_EXECUTION`` oracle); see ``test_browser_xss.py`` / ``test_domxss*.py``.
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from framework.v2.scanner.browser import browser_usable, render_dom

pytestmark = pytest.mark.skipif(
    not browser_usable(),
    reason="no WORKING headless Chromium/Chrome (a binary may be installed but unable to render here)")

_VULN = b"""<html><body><div id="out"></div><script>
  var h = decodeURIComponent(location.hash.slice(1));
  document.getElementById("out").innerHTML = h;   // DOM-XSS sink
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
