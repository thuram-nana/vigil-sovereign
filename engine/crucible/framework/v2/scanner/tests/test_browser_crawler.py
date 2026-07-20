"""
JS-aware (SPA) crawling — the browser crawler discovers links that only exist
after JavaScript runs, which the static crawler cannot see.

Each route's initial HTML contains no <a> tags; a script injects the nav after
load. The static crawler (raw HTML) finds nothing beyond the seed; the browser
crawler renders each page and follows the JS-injected links. Skipped without a
browser.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from framework.v2.scanner.browser import find_browser
from framework.v2.scanner.browser_crawler import BrowserCrawler
from framework.v2.scanner.crawler import Crawler
from framework.v2.scanner.insertion import HttpRequest

pytestmark = pytest.mark.skipif(find_browser() is None, reason="no headless browser installed")

# route -> links its JavaScript injects after load (never present in the raw HTML)
_ROUTES = {
    "/": ["/dashboard", "/api/users?id=1"],
    "/dashboard": ["/settings"],
    "/api/users": [],
    "/settings": [],
}


def _page(links: list[str]) -> bytes:
    anchors = "".join(f'<a href=\\"{href}\\">x</a>' for href in links)
    return (
        "<html><body><div id=nav></div><script>"
        f'document.getElementById("nav").innerHTML = "{anchors}";'
        "</script></body></html>"
    ).encode()


class _SpaApp(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        body = _page(_ROUTES.get(path, []))
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SpaApp)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _static_send(req: HttpRequest) -> dict:
    with urllib.request.urlopen(req.url, timeout=5) as resp:  # noqa: S310 (loopback)
        return {"status": resp.status, "headers": list(resp.headers.items()),
                "body": resp.read().decode("utf-8", "replace")}


def _paths(result) -> set[str]:
    return {urllib.parse.urlsplit(p.url).path for p in result.pages}


def test_static_crawler_misses_js_injected_nav() -> None:
    with _server() as base:
        result = Crawler(_static_send, max_pages=10, max_depth=3).crawl(base + "/")
        # the raw HTML has the links only inside a <script> string, so none are followed
        assert _paths(result) == {"/"}


def test_browser_crawler_discovers_spa_routes() -> None:
    with _server() as base:
        result = BrowserCrawler(max_pages=8, max_depth=3, timeout=30.0).crawl(base + "/")
        found = _paths(result)
        assert "/dashboard" in found, f"JS-injected route not discovered: {found}"
        assert "/api/users" in found
        assert "/settings" in found, "second-level JS route (via /dashboard) not reached"
