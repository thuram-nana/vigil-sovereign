"""
Wave C / slice C1 — the discovery parsers wired into the crawl, and the
ApiOperation -> HttpRequest bridge.

Two properties are under test:

  1. The bridge (``scanner.insertion.request_from_api_operation``) turns one
     discovered OpenAPI operation into a valid, fuzzable request with the correct
     method + content-type — the structural link the audit engine needs.
  2. With ``enable_discovery=True`` the built-but-previously-unwired parsers
     (robots / sitemap / OpenAPI / param mining) contribute extra requests to the
     audit surface, each scope-filtered and routed through the same gated ``send``;
     and the GOLD STANDARD: a planted OpenAPI spec whose operation, once bridged and
     audited, lets the EXISTING reflected-XSS oracle confirm a planted bug — surface
     -> existing oracle -> FACT — proving discovery never mints a fact by itself but
     does deliver more surface to the oracle-gated engine.

Every property is default-OFF: the last test pins that a discovery-off run adds no
surface and no leads (the make-gate byte-identity contract at the unit level).
"""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import urlsplit

from framework.v2.scanner import (
    HttpRequest,
    InsertionKind,
    WebScanCampaign,
    request_from_api_operation,
)
from framework.v2.scanner.campaign import WebScanCampaign as _Camp
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.crawler import CrawlResult, Page
from framework.v2.scanner.discovery import ApiOperation


# ---------------------------------------------------------------------------
# 1. the ApiOperation -> HttpRequest bridge (pure)
# ---------------------------------------------------------------------------


def test_bridge_body_method_renders_json_with_correct_content_type() -> None:
    op = ApiOperation(method="post", path="/api/users/{id}", params=["id", "name", "q"])
    req = request_from_api_operation(op, "http://h/")
    assert req.method == "POST"
    # {id} filled inline and NOT duplicated into the body
    assert req.url == "http://h/api/users/1"
    assert req.content_type() == "application/json"
    assert json.loads(req.body) == {"name": "1", "q": "1"}
    # Content-Length matches the rendered body
    assert ("Content-Length", str(len(req.body.encode("utf-8")))) in req.headers


def test_bridge_non_body_method_renders_query() -> None:
    op = ApiOperation(method="GET", path="/search", params=["q", "lang"])
    req = request_from_api_operation(op, "http://h/")
    assert req.method == "GET"
    assert req.body is None
    assert "q=1" in req.url and "lang=1" in req.url
    assert req.content_type() == ""  # no body, no content-type


def test_bridge_form_media_type() -> None:
    op = ApiOperation(method="PUT", path="/f", params=["a", "b"])
    req = request_from_api_operation(
        op, "http://h/", body_media_type="application/x-www-form-urlencoded")
    assert req.content_type() == "application/x-www-form-urlencoded"
    assert req.body == "a=1&b=1"


def test_bridge_no_free_params_is_bare_request() -> None:
    op = ApiOperation(method="GET", path="/ping", params=[])
    req = request_from_api_operation(op, "http://h/")
    assert req.method == "GET" and req.url == "http://h/ping" and req.body is None


def test_bridge_renders_into_real_insertion_points() -> None:
    """The whole point: the bridged request decomposes into the insertion points the
    audit engine fuzzes — a JSON body field becomes a JSON_VALUE point."""
    from framework.v2.scanner.insertion import RequestTemplate

    op = ApiOperation(method="POST", path="/api/submit", params=["name"])
    req = request_from_api_operation(op, "http://h/")
    kinds = {p.kind for p in RequestTemplate(req).insertion_points()}
    assert InsertionKind.JSON_VALUE in kinds


# ---------------------------------------------------------------------------
# 2. the parsers wired as crawl seeds (fake, deterministic send)
# ---------------------------------------------------------------------------

_HOST = "testhost"
_SEED = f"http://{_HOST}/"

_SPEC = json.dumps({
    "openapi": "3.0.0",
    "paths": {"/api/echo": {"get": {"parameters": [{"name": "q", "in": "query"}]}}},
})


def _recording_send(sitemap_locs: list[str], record: list[str]):
    """A deterministic fake ``send``: serves the index (with a mineable param in a
    script), robots.txt, sitemap.xml and openapi.json; 404s everything else. Records
    every URL it is asked to fetch so scope-filtering can be asserted on the wire."""

    def send(req: HttpRequest) -> dict:
        record.append(req.url)
        path = urlsplit(req.url).path
        if path == "/":
            body = "<html><body><script>var v = req.query.mined_param;</script></body></html>"
        elif path == "/robots.txt":
            body = f"User-agent: *\nDisallow: /admin-panel\nSitemap: {_SEED}sitemap.xml\n"
        elif path == "/sitemap.xml":
            locs = "".join(f"<url><loc>{u}</loc></url>" for u in sitemap_locs)
            body = f'<?xml version="1.0"?><urlset>{locs}</urlset>'
        elif path == "/openapi.json":
            body = _SPEC
        else:
            return {"status": 404, "headers": [], "body": ""}
        return {"status": 200, "headers": [("Content-Type", "text/html")], "body": body}

    return send


def test_discovery_seeds_reach_the_audit_surface() -> None:
    record: list[str] = []
    send = _recording_send([f"{_SEED}sitemap-page"], record)
    report = WebScanCampaign(send, enable_oob=False, enable_discovery=True).run(_SEED)

    surfaces = set(report.discovered_surfaces)
    # robots Disallow -> seed ; robots Sitemap -> sitemap <loc> ; OpenAPI op -> bridge ;
    # mined param -> query probe. Each parser's seed reaches the audit surface.
    assert "GET /admin-panel" in surfaces          # parse_robots
    assert "GET /sitemap-page" in surfaces          # parse_sitemap (via robots Sitemap:)
    assert "GET /api/echo?q=1" in surfaces          # parse_openapi -> bridge
    assert "GET /?mined_param=1" in surfaces         # mine_params


def test_discovery_seeds_are_scope_filtered_on_the_wire() -> None:
    """A hostile sitemap entry pointing off-host must never become an audit request:
    the parsed document is untrusted, so it is dropped BEFORE the gated send sees it."""
    record: list[str] = []
    send = _recording_send([f"{_SEED}good", "http://evil.example/pwned"], record)
    report = WebScanCampaign(send, enable_oob=False, enable_discovery=True).run(_SEED)

    surfaces = set(report.discovered_surfaces)
    assert "GET /good" in surfaces                    # in-scope entry kept
    # the off-host entry never reached the surface AND never reached the send at all
    assert not any(urlsplit(u).netloc == "evil.example" for u in record)
    assert not any("evil" in s for s in surfaces)


def test_robots_sitemap_url_is_scope_filtered_before_fetch() -> None:
    """Negative control for the robots ``Sitemap:`` INTERMEDIATE fetch: a Sitemap: URL is
    lifted VERBATIM from the untrusted robots.txt, so an off-host one (evil.example, a
    cloud-metadata IP) must be dropped BEFORE it is fetched — it must never reach ``send``.
    An in-scope Sitemap: is still fetched and its ``<loc>`` still reaches the surface."""
    record: list[str] = []

    def send(req: HttpRequest) -> dict:
        record.append(req.url)
        parts = urlsplit(req.url)
        if parts.netloc != _HOST:
            # Reaching here for an off-host URL would mean the scope hole is open; the
            # assertions below fail on `record`. This benign body just avoids masking it.
            return {"status": 200, "headers": [], "body": ""}
        if parts.path == "/":
            body = "<html><body>home</body></html>"
        elif parts.path == "/robots.txt":
            body = ("User-agent: *\n"
                    "Sitemap: http://evil.example/sitemap.xml\n"
                    "Sitemap: http://169.254.169.254/latest/meta-data/\n"
                    f"Sitemap: {_SEED}sitemap-in-scope.xml\n")
        elif parts.path == "/sitemap-in-scope.xml":
            body = ('<?xml version="1.0"?><urlset><url>'
                    f"<loc>{_SEED}deep-page</loc></url></urlset>")
        else:
            return {"status": 404, "headers": [], "body": ""}
        return {"status": 200, "headers": [("Content-Type", "text/html")], "body": body}

    report = WebScanCampaign(send, enable_oob=False, enable_discovery=True).run(_SEED)
    surfaces = set(report.discovered_surfaces)

    # the IN-SCOPE Sitemap: was fetched and its <loc> reached the audit surface
    assert "GET /deep-page" in surfaces
    assert any(urlsplit(u).path == "/sitemap-in-scope.xml" and urlsplit(u).netloc == _HOST
               for u in record)
    # the OFF-HOST Sitemap: URLs were NEVER fetched — the BLOCK fix
    assert not any(urlsplit(u).netloc == "evil.example" for u in record)
    assert not any(urlsplit(u).netloc == "169.254.169.254" for u in record)


def test_discovery_off_by_default_adds_no_surface_or_leads() -> None:
    record: list[str] = []
    send = _recording_send([f"{_SEED}sitemap-page"], record)
    report = WebScanCampaign(send, enable_oob=False).run(_SEED)  # discovery OFF (default)

    surfaces = set(report.discovered_surfaces)
    assert "GET /admin-panel" not in surfaces
    assert "GET /api/echo?q=1" not in surfaces
    assert report.discovery_leads == []
    # the discovery-only documents were never fetched
    assert not any(urlsplit(u).path == "/openapi.json" for u in record)


# ---------------------------------------------------------------------------
# 3. non-GET SPA endpoints routed into the audit surface
# ---------------------------------------------------------------------------


def test_spa_non_get_endpoints_routed_into_audit_surface(monkeypatch) -> None:
    from framework.v2.scanner import spa_crawler
    from framework.v2.scanner.spa_crawler import SpaCrawlResult, SpaEndpoint

    def fake_crawl_spa(url, *, browser=None):  # noqa: ANN001
        return SpaCrawlResult(url=url, endpoints=[
            SpaEndpoint(method="POST", url="/api/orders"),        # non-GET -> routed (new)
            SpaEndpoint(method="GET", url="/api/items"),          # bare GET -> not routed
            SpaEndpoint(method="GET", url="/api/items?id=1"),     # GET w/ query -> routed
        ])

    monkeypatch.setattr(spa_crawler, "crawl_spa", fake_crawl_spa)

    camp = _Camp(lambda r: {"status": 200, "body": "", "headers": []}, enable_oob=False)
    crawl = CrawlResult(requests=[], pages=[Page(url="http://127.0.0.1/", body="", status=200)])
    _endpoints, extra = camp._spa_discover(crawl, browser=object())

    by = {(r.method, urlsplit(r.url).path, bool(urlsplit(r.url).query)) for r in extra}
    assert ("POST", "/api/orders", False) in by            # the new routing
    assert ("GET", "/api/items", True) in by                # GET with a query still routed
    assert ("GET", "/api/items", False) not in by           # a bare GET is not (crawl covers it)


# ---------------------------------------------------------------------------
# 4. GOLD STANDARD — planted OpenAPI op, bridged + audited, confirmed by the oracle
# ---------------------------------------------------------------------------

_GOLD_SPEC = json.dumps({
    "openapi": "3.0.0",
    "paths": {
        # GET query param — bridged to a query-string request
        "/api/echo": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
        # body param — bridged to a JSON body request (Swagger-2 style `in: body`)
        "/api/submit": {"post": {"parameters": [{"name": "name", "in": "body"}]}},
    },
})


class _GoldApp(BaseHTTPRequestHandler):
    """An app whose /api/* routes are documented in /openapi.json but linked NOWHERE,
    and which reflects the audited input verbatim into an HTML response — so the only
    path from surface to the reflected-XSS oracle is the OpenAPI bridge."""

    def log_message(self, *a: object) -> None:
        return

    def _html(self, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        sp = urlsplit(self.path)
        if sp.path == "/":
            self._html("<html><body>home</body></html>")
        elif sp.path == "/openapi.json":
            raw = _GOLD_SPEC.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        elif sp.path == "/api/echo":
            from urllib.parse import parse_qs
            q = parse_qs(sp.query, keep_blank_values=True).get("q", [""])[0]
            self._html(f"<html><body>you said: {q}</body></html>")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        sp = urlsplit(self.path)
        if sp.path == "/api/submit":
            try:
                name = json.loads(raw).get("name", "")
            except Exception:
                name = ""
            self._html(f"<html><body>hi {name}</body></html>")
        else:
            self._html("{}")


@contextlib.contextmanager
def _serve() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _GoldApp)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def test_openapi_bridge_lets_the_oracle_confirm_a_planted_bug() -> None:
    with _serve() as base:
        report = WebScanCampaign(
            loopback_send,
            enable_oob=False,
            enable_discovery=True,
            insertion_kinds=(InsertionKind.QUERY_VALUE, InsertionKind.JSON_VALUE),
        ).run(base + "/")

    # nothing links /api/* — the only route to these is the bridged OpenAPI spec
    assert f"GET /api/echo?q=1" in set(report.discovered_surfaces)
    xss = [f for f in report.active_findings if f.bug_class == "xss"]
    params = {f.param for f in xss}
    # the bridged GET query param, confirmed by the reflection oracle (a real FACT)
    assert "q" in params, f"query-param bridge did not reach the oracle: {params}"
    echo = next(f for f in xss if f.param == "q")
    assert echo.confirmed_by == "reflection_context"
    assert "/api/echo" in (echo.endpoint or "")
    # the bridged JSON body field, confirmed the same way
    assert any(f.param == "/name" and "/api/submit" in (f.endpoint or "") for f in xss), \
        f"JSON-body bridge did not reach the oracle: {[(f.param, f.endpoint) for f in xss]}"
