"""
Crawler — real discovery against a live multi-page localhost site, and the full
crawl → scan → confirm loop.

A purpose-built site links across pages (with a cycle), exposes a parameterised
endpoint and a login form, and links off-host. The crawler must discover the
in-scope endpoints + the form-as-request, avoid the cycle and the id-trap, refuse
the off-host link, and stay bounded. The final test chains the crawler into the
AuditEngine and confirms a real vulnerability with zero manual steps.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner import AuditEngine, Crawler, HttpRequest, InsertionKind

_PAGES: dict[str, bytes] = {
    "/": b"""<html><body>
        <a href="/products?id=1">p1</a>
        <a href="/products?id=2">p2</a>
        <a href="/search?q=hello">search</a>
        <a href="/about">about</a>
        <a href="http://evil.example/steal">off-site</a>
        <form action="/login" method="post">
          <input name="user" value="">
          <input name="password" type="password">
          <input type="submit" value="go">
        </form>
    </body></html>""",
    "/about": b'<html><body><a href="/">home</a> just text</body></html>',
}


class _SiteHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        qs = urllib.parse.urlsplit(self.path).query
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)
        if path == "/search":
            q = params.get("q", [""])[0]
            rows = "id=1 a\nid=2 b admin\nid=3 c" if ("'1'='1" in q or "1=1" in q) else "no results"
            body = f"query=[{q}]:\n{rows}".encode()
        elif path == "/products":
            body = b"a product page"
        else:
            body = _PAGES.get(path, b"<html><body>404</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _site() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SiteHandler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _send(req: HttpRequest) -> dict:
    r = urllib.request.Request(req.url, method=req.method, headers=dict(req.headers))
    if req.body is not None:
        r.data = req.body.encode("utf-8")
    with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 (loopback only)
        return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}


def _paths(reqs) -> set[str]:
    return {urllib.parse.urlsplit(r.url).path for r in reqs}


def test_crawler_discovers_scoped_surface_and_forms() -> None:
    with _site() as base:
        result = Crawler(_send).crawl(base + "/")
        paths = _paths(result.requests)
        assert {"/", "/products", "/search", "/about"} <= paths, paths
        # the POST login form was turned into a fuzzable request
        posts = [r for r in result.requests if r.method == "POST"]
        assert any(urllib.parse.urlsplit(r.url).path == "/login" for r in posts)
        login = next(r for r in posts if r.url.endswith("/login"))
        assert "user=" in (login.body or "") and "password=" in (login.body or "")


def test_crawler_refuses_offsite_and_collapses_id_trap() -> None:
    with _site() as base:
        result = Crawler(_send).crawl(base + "/")
        hosts = {urllib.parse.urlsplit(r.url).netloc for r in result.requests}
        assert all(h == urllib.parse.urlsplit(base).netloc for h in hosts), "off-host link was followed"
        # ?id=1 and ?id=2 are one location, not two crawl targets
        product_reqs = [r for r in result.requests if urllib.parse.urlsplit(r.url).path == "/products"]
        assert len(product_reqs) == 1, "the id-trap was not collapsed"


def test_crawl_is_bounded() -> None:
    with _site() as base:
        result = Crawler(_send, max_pages=2).crawl(base + "/")
        assert len(result.pages) <= 2, "max_pages budget not enforced"


def test_full_loop_crawl_then_scan_then_confirm() -> None:
    # The zero-manual pipeline: crawl finds /search?q=, the audit engine fuzzes
    # its insertion points, the oracle confirms the boolean-SQLi — end to end.
    with _site() as base:
        crawl = Crawler(_send).crawl(base + "/")
        engine = AuditEngine(_send)
        confirmed = []
        for req in crawl.requests:
            confirmed += engine.audit(req, insertion_kinds=(InsertionKind.QUERY_VALUE,))
        sqli = [f for f in confirmed if f.bug_class == "boolean_sqli"]
        assert sqli, "crawl->scan->confirm did not surface the SQLi on /search?q="
        assert sqli[0].confirmed_by == "differential_response"
        assert sqli[0].param == "q"
