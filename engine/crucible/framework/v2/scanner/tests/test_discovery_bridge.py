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
    RequestTemplate,
    WebScanCampaign,
    request_from_api_operation,
    request_from_graphql_operation,
)
from framework.v2.scanner.campaign import WebScanCampaign as _Camp
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.crawler import CrawlResult, Page
from framework.v2.scanner.discovery import ApiOperation, GraphQLArg, GraphQLOperation


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


def test_bridge_builds_a_typed_nested_body_from_the_request_schema() -> None:
    """W1 — a requestBody schema renders a TYPED, NESTED baseline body (not a flat {name:"1"}), so the
    insertion engine fuzzes every nested leaf. Query params ride alongside, spec-typed; it is deterministic."""
    from framework.v2.scanner.insertion import InsertionKind as _IK
    from framework.v2.scanner.insertion import RequestTemplate

    schema = {"type": "object", "required": ["name"], "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer"},
        "active": {"type": "boolean"},
        "address": {"type": "object", "properties": {"city": {"type": "string"}}},
        "tags": {"type": "array", "items": {"type": "string"}},
    }}
    op = ApiOperation(method="POST", path="/api/submit", params=["dry"],
                      request_schema=schema, param_types={"dry": "boolean"})
    req = request_from_api_operation(op, "http://h/")
    # typed + nested, not a flat {name:"1"}
    assert json.loads(req.body) == {"name": "1", "age": 1, "active": True,
                                    "address": {"city": "1"}, "tags": ["1"]}
    assert req.content_type() == "application/json"
    assert ("Content-Length", str(len(req.body.encode("utf-8")))) in req.headers
    # the non-body (query) param rides alongside the body, spec-typed (boolean -> "true")
    assert "dry=true" in req.url
    # deterministic: same op -> same bytes
    assert request_from_api_operation(op, "http://h/").body == req.body
    # the NESTED leaves are now real JSON_VALUE insertion points (the coverage win)
    names = {p.name for p in RequestTemplate(req).insertion_points(kinds=[_IK.JSON_VALUE])}
    assert "/name" in names
    assert any(n.startswith("/address") for n in names), names      # nested object leaf exposed
    assert any(n.startswith("/tags") for n in names), names         # array element leaf exposed


def test_bridge_body_schema_with_no_free_params_still_sends_the_typed_body() -> None:
    # a documented requestBody with NO query params must NOT fall back to a bare request.
    op = ApiOperation(method="POST", path="/api/submit", params=[],
                      request_schema={"type": "object", "properties": {"q": {"type": "string"}}})
    req = request_from_api_operation(op, "http://h/")
    assert json.loads(req.body) == {"q": "1"} and req.content_type() == "application/json"


def test_bridge_baseline_ignores_spec_enum() -> None:
    # W1 red-pen HIGH+LOW: a spec-provided enum must NOT appear in the benign baseline body — a hostile spec
    # could otherwise plant a destructive/injection payload (or an unbounded blob) in our own control request.
    schema = {"type": "object", "properties": {
        "mode": {"type": "string", "enum": ["'; DROP TABLE t; --", "safe"]},
        "n": {"type": "integer", "enum": [999]},
    }}
    op = ApiOperation(method="POST", path="/s", params=[], request_schema=schema)
    body = json.loads(request_from_api_operation(op, "http://h/").body)
    assert body == {"mode": "1", "n": 1}                         # typed scalars, NEVER the enum value


def test_bridge_tolerates_nonstring_required() -> None:
    # W1 red-pen MED: a spec-controlled required[] with a non-string/unhashable element must not crash
    # _example_from_schema (it would drop the whole op from the audit surface).
    schema = {"type": "object", "required": [{"x": 1}, ["y"], "a"],
              "properties": {"a": {"type": "string"}, "b": {"type": "integer"}}}
    op = ApiOperation(method="POST", path="/u", params=[], request_schema=schema)
    body = json.loads(request_from_api_operation(op, "http://h/").body)   # must not raise
    assert body == {"a": "1", "b": 1}


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


# ---------------------------------------------------------------------------
# 4. the GraphQL discovery-seed wiring (end-to-end) — W2-b dispatch
#    A query root operation is synthesized into a fuzzable request the real audit
#    engine exercises; a mutation is surfaced as a LEAD and NEVER auto-sent.
# ---------------------------------------------------------------------------

_GQL_INTROSPECTION_RESULT = json.dumps({
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [
                {"name": "user", "args": [
                    {"name": "id", "type": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                ]},
            ]},
            {"name": "Mutation", "fields": [
                {"name": "deleteUser", "args": [
                    {"name": "id", "type": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                ]},
            ]},
        ],
    }},
})


class _GqlApp(BaseHTTPRequestHandler):
    """A GraphQL endpoint linked from `/`. It answers an introspection POST with a schema
    declaring a `user(id)` query root field and a `deleteUser(id)` mutation root field, and
    records every POST body it receives so the test can prove (a) the query op was synthesized
    and fuzzed through the real audit engine, and (b) the mutation was never auto-sent."""

    received: list[str] = []

    def log_message(self, *a: object) -> None:
        return

    def _send(self, body: str, ctype: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        sp = urlsplit(self.path)
        if sp.path == "/":
            self._send('<html><body><a href="/graphql">api</a></body></html>', "text/html")
        elif sp.path == "/graphql":
            # a GET so the crawler registers the /graphql URL (endpoint discovery)
            self._send('{"message":"POST a query"}', "application/json")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        sp = urlsplit(self.path)
        if sp.path == "/graphql":
            type(self).received.append(raw)
            if "__schema" in raw:
                self._send(_GQL_INTROSPECTION_RESULT, "application/json")
            else:
                self._send('{"data":{"user":null}}', "application/json")
        else:
            self._send("{}", "application/json")


@contextlib.contextmanager
def _serve_gql() -> Iterator[str]:
    _GqlApp.received = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _GqlApp)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def test_graphql_discovery_wires_query_ops_into_audit_and_leaves_mutations_as_leads() -> None:
    with _serve_gql() as base:
        report = WebScanCampaign(
            loopback_send,
            enable_oob=False,
            enable_discovery=True,
            insertion_kinds=(InsertionKind.JSON_VALUE,),
        ).run(base + "/")

    posts = [b for b in _GqlApp.received if "__schema" not in b]
    # (a) the QUERY root op was synthesized and reached the audit engine as a POST query
    assert any('"query"' in b and "user(" in b and "variables" in b for b in posts), \
        f"query op was not synthesized into an audited request: {posts!r}"
    # (b) and its /variables/id value was actually FUZZED — more than the one baseline value
    id_values = set()
    for b in posts:
        try:
            v = json.loads(b).get("variables", {})
        except Exception:
            continue
        if isinstance(v, dict) and "id" in v:
            id_values.add(repr(v["id"]))
    assert len(id_values) >= 2, f"the /variables/id point was not fuzzed: {id_values!r}"
    # the synthesized request joined the discovered audit surface
    assert "POST /graphql" in set(report.discovered_surfaces)

    # (c) the MUTATION was surfaced as a LEAD ...
    assert any(lead.startswith("graphql-operation mutation deleteUser")
               for lead in report.discovery_leads), report.discovery_leads
    # ... and NEVER auto-sent: `deleteUser` appears only in a synthesized mutation op, which
    # the wiring refuses to send (state-changing — doctrine: ask before destruction).
    assert not any("deleteUser" in b for b in _GqlApp.received), \
        f"a state-changing mutation was auto-sent: {[b for b in _GqlApp.received if 'deleteUser' in b]!r}"


# ---------------------------------------------------------------------------
# 3. the GraphQLOperation -> HttpRequest bridge (pure) — W2-b
# ---------------------------------------------------------------------------


def test_graphql_bridge_builds_a_parameterized_query_with_fuzzable_variables() -> None:
    """A discovered Query root field with typed args becomes a parameterized POST whose argument values ride
    a JSON ``variables`` object — so the EXISTING JSON decomposer exposes each ``/variables/<arg>`` as its own
    fuzzable point. No GraphQL-aware insertion kind; the injection classes stay LEAD-capped (this bridge adds
    no oracle). Deterministic: identical bytes every call."""
    op = GraphQLOperation(
        name="user",
        kind="query",
        args=[
            GraphQLArg(name="id", type_name="ID"),
            GraphQLArg(name="n", type_name="Int"),
            GraphQLArg(name="ok", type_name="Boolean"),
        ],
    )
    req = request_from_graphql_operation(op, "http://h/")

    assert req.method == "POST"
    assert req.url == "http://h/graphql"
    assert req.content_type() == "application/json"
    assert ("Content-Length", str(len(req.body.encode("utf-8")))) in req.headers

    payload = json.loads(req.body)
    # the query is parameterized: typed $var decls on the op, $var binds on the field, a __typename leaf
    assert payload["query"] == (
        "query($id: ID, $n: Int, $ok: Boolean)"
        "{user(id: $id, n: $n, ok: $ok){__typename}}"
    )
    # typed, VIGIL-controlled baseline values (ID/String->fill, Int/Float->1, Boolean->True)
    assert payload["variables"] == {"id": "1", "n": 1, "ok": True}

    # the whole point: each argument is an independent, fuzzable JSON value point
    pts = RequestTemplate(req).insertion_points(kinds=[InsertionKind.JSON_VALUE])
    names = {p.name for p in pts}
    assert {"/variables/id", "/variables/n", "/variables/ok"} <= names, names
    # determinism — same operation, same bytes
    assert request_from_graphql_operation(op, "http://h/").body == req.body


def test_graphql_bridge_mutation_and_argless_are_well_formed() -> None:
    """An argless root field emits no ``variables`` key (nothing to parameterize), and a mutation is rendered
    as ``mutation{…}`` so the upstream destructive-confirm gate recognizes it as state-changing. Unknown /
    input-object arg types fall back to a ``String`` variable the string fill satisfies; a list arg is wrapped
    ``[...]``."""
    argless = GraphQLOperation(name="deleteUser", kind="mutation")
    req = request_from_graphql_operation(argless, "http://h/")
    payload = json.loads(req.body)
    assert payload == {"query": "mutation{deleteUser{__typename}}"}
    assert "variables" not in payload  # no args -> no variables object

    # unknown/input-object type -> String variable; list -> [String]; the fill satisfies both
    typed = GraphQLOperation(
        name="createOrder",
        kind="mutation",
        args=[
            GraphQLArg(name="input", type_name="OrderInput"),      # input object -> String
            GraphQLArg(name="tags", type_name="String", is_list=True),  # list -> [String]
        ],
    )
    p2 = json.loads(request_from_graphql_operation(typed, "http://h/").body)
    assert p2["query"] == (
        "mutation($input: String, $tags: [String])"
        "{createOrder(input: $input, tags: $tags){__typename}}"
    )
    assert p2["variables"] == {"input": "1", "tags": "1"}
    # the mutation keyword is present verbatim for the destructive-confirm gate to match
    assert p2["query"].startswith("mutation")
