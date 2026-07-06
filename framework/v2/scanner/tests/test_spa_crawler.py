"""
The CDP-driven SPA crawler against a real headless browser. Skip-gated on a
Chromium/Chrome binary being present — a browser check never guesses, so with no
browser there is simply nothing to run.

A local loopback ThreadingHTTPServer serves a crafted single-page app that: marks
itself Angular (``ng-version``); on load fires ``fetch('/api/items')`` and an XHR
``POST /api/save``; exposes a same-origin ``<a href="/dashboard">`` and a
``<form action="/submit">``; and attaches an open shadow root containing
``<a href="/shadow-link">``. The crawl must recover all of it — the API calls the
served HTML never mentions, the route hidden behind the shadow boundary, and the
framework — proving the dynamic crawler sees what a static pass cannot. The browser
is launched once per module to amortise the cost.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from framework.v2.scanner.cdp import CdpBrowser, cdp_available
from framework.v2.scanner.spa_crawler import SpaEndpoint, crawl_spa, detect_framework

pytestmark = pytest.mark.skipif(not cdp_available(), reason="no Chromium/Chrome for the CDP driver")


# The SPA fixture. Everything of interest is built by JavaScript AFTER load or hidden
# behind a shadow boundary — none of the endpoints or the shadow link is reachable
# by parsing this HTML statically.
_SPA_HTML = """<!doctype html>
<html>
<head><title>crucible-spa</title></head>
<body>
  <div id="app" ng-version="17.0.0">
    <a href="/dashboard">dashboard</a>
    <form action="/submit" method="post"><input name="q"></form>
  </div>
  <script>
    fetch('/api/items');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/save');
    xhr.send();
    var host = document.createElement('div');
    document.body.appendChild(host);
    host.attachShadow({mode: 'open'}).innerHTML = '<a href="/shadow-link">x</a>';
  </script>
</body>
</html>
"""


class _SpaHandler(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def _respond(self, body: str, ctype: str = "text/html") -> None:
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/" or self.path.startswith("/?") or self.path.startswith("/#"):
            self._respond(_SPA_HTML)
        else:  # /api/items and friends — the fetch target
            self._respond("{}", "application/json")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._respond("{}", "application/json")


@contextlib.contextmanager
def _serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _data(html: str) -> str:
    return "data:text/html," + urllib.parse.quote(html)


@pytest.fixture(scope="module")
def browser() -> Iterator[CdpBrowser]:
    with CdpBrowser() as br:
        yield br


def test_crawl_spa_recovers_full_surface(browser: CdpBrowser) -> None:
    with _serve(_SpaHandler) as base:
        result = crawl_spa(base, browser=browser, settle=0.8, max_routes=5)

    # framework detected from the ng-version marker
    assert result.framework == "angular"

    # the app-initiated API calls the served HTML never mentions
    assert SpaEndpoint(method="GET", url="/api/items") in result.endpoints
    assert SpaEndpoint(method="POST", url="/api/save") in result.endpoints

    # a light-DOM route AND a route that lives only inside the shadow root
    assert "/dashboard" in result.routes
    assert "/shadow-link" in result.routes

    # the form target, and at least the one shadow host we attached
    assert "/submit" in result.forms
    assert result.shadow_hosts >= 1


def test_endpoints_are_deduplicated(browser: CdpBrowser) -> None:
    with _serve(_SpaHandler) as base:
        result = crawl_spa(base, browser=browser, settle=0.8, max_routes=0)
    keys = [(e.method, e.url) for e in result.endpoints]
    assert len(keys) == len(set(keys)), "endpoints must be unique by (method, url)"


def test_detect_framework_recognises_vue(browser: CdpBrowser) -> None:
    sess = browser.session()
    sess.navigate(_data("<div id=a></div><script>window.Vue = {};</script>"))
    assert detect_framework(sess) == "vue"


def test_detect_framework_none_for_plain_page(browser: CdpBrowser) -> None:
    sess = browser.session()
    sess.navigate(_data("<p>just html</p>"))
    assert detect_framework(sess) == "none"
