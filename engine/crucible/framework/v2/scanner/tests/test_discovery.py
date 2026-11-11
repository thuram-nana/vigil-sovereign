"""
Attack-surface discovery — content probing against a live localhost site, plus
unit coverage of the pure parsers/miners.

Content discovery is exercised against a purpose-built server that serves two
"sensitive" paths (``/.env``, ``/actuator/env``) as 200 and everything else as
404; the module must report exactly the reachable pair and none of the 404s. The
parsers (robots, sitemap, OpenAPI, GraphQL) and the JS miners (endpoints,
secrets, params) are unit-tested with literal inputs, including a benign JS blob
that must yield zero secrets — the precision property that makes secret mining
usable.
"""

from __future__ import annotations

import contextlib
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.discovery import (
    ApiOperation,
    CONTENT_WORDLIST,
    JsFindings,
    _MAX_DOC_NODES,
    discover_content,
    mine_js,
    mine_params,
    parse_graphql_operations,
    parse_graphql_schema,
    parse_openapi,
    parse_robots,
    parse_sitemap,
)

_SENSITIVE = {"/.env", "/actuator/env"}
_SECRET_BODY = b"SECRET_KEY=super-secret-value\nDB_PASSWORD=hunter2\n"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if path in _SENSITIVE:
            body, status, ctype = _SECRET_BODY, 200, "text/plain; charset=utf-8"
        else:
            body, status, ctype = b"not found\n", 404, "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _site() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


# ---------------------------------------------------------------------------
# content discovery (live loopback)
# ---------------------------------------------------------------------------


def test_content_discovery_finds_reachable_paths_only() -> None:
    with _site() as base:
        found = discover_content(base, loopback_send)
    paths = {d.path for d in found}
    assert paths == _SENSITIVE, paths
    # a wordlist path the server 404s must not be reported
    assert "/admin" not in paths
    assert "/wp-config.php" not in paths


def test_content_discovery_captures_status_type_and_excerpt() -> None:
    with _site() as base:
        found = discover_content(base, loopback_send)
    env = next(d for d in found if d.path == "/.env")
    assert env.status == 200
    assert "text/plain" in env.content_type
    assert "SECRET_KEY" in env.excerpt


def test_content_discovery_ignores_404s_as_uninteresting() -> None:
    # everything except the two sensitive paths is a 404 -> nothing else surfaces
    with _site() as base:
        found = discover_content(base, loopback_send)
    assert all(d.status in (200, 401, 403, 500) for d in found)
    assert len(found) == 2


def test_content_discovery_bounded_by_max() -> None:
    # /.env is the first wordlist entry, so max=1 probes exactly it
    assert CONTENT_WORDLIST[0] == "/.env"
    with _site() as base:
        found = discover_content(base, loopback_send, max=1)
    assert {d.path for d in found} == {"/.env"}


def test_content_discovery_honours_custom_wordlist_and_extensions() -> None:
    with _site() as base:
        found = discover_content(
            base, loopback_send, wordlist=("/actuator/env", "/nope"), extensions=(".bak",)
        )
    # /actuator/env is 200; /actuator/env.bak, /nope, /nope.bak are all 404
    assert {d.path for d in found} == {"/actuator/env"}


# ---------------------------------------------------------------------------
# robots.txt / sitemap.xml
# ---------------------------------------------------------------------------

_ROBOTS = """
# example policy
User-agent: *
Disallow: /admin/
Disallow: /private/secret
Allow: /public/
Disallow:
Crawl-delay: 5
Sitemap: https://example.com/sitemap.xml
"""


def test_parse_robots_extracts_paths_and_sitemap() -> None:
    seeds = parse_robots(_ROBOTS)
    assert "/admin/" in seeds
    assert "/private/secret" in seeds
    assert "/public/" in seeds
    assert "https://example.com/sitemap.xml" in seeds
    # an empty "Disallow:" (allow-all) and non-path directives are not seeds
    assert "" not in seeds
    assert "5" not in seeds


_SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/products?id=1&amp;ref=2</loc></url>
  <url><loc>  https://example.com/about  </loc></url>
</urlset>
"""


def test_parse_sitemap_extracts_and_unescapes_locs() -> None:
    locs = parse_sitemap(_SITEMAP)
    assert "https://example.com/" in locs
    assert "https://example.com/about" in locs  # surrounding whitespace stripped
    assert "https://example.com/products?id=1&ref=2" in locs  # &amp; unescaped


# ---------------------------------------------------------------------------
# JS endpoint + secret mining
# ---------------------------------------------------------------------------

_AKIA = "AKIA" + "1234567890ABCDEF"          # AKIA + 16 => valid AWS key id
_AIZA = "AIza" + "0123456789" * 3 + "01234"  # AIza + 35 => valid Google API key


def test_mine_js_finds_endpoints_and_secrets() -> None:
    js = f"""
    const KEY = "{_AKIA}";
    const GKEY = "{_AIZA}";
    fetch("/api/user?id=1").then(r => r.json());
    axios.get("https://api.example.com/v2/orders");
    const re = /^[0-9]+$/;   // a bare regex literal, not a quoted endpoint
    """
    f = mine_js(js)
    assert isinstance(f, JsFindings)
    assert "/api/user?id=1" in f.endpoints
    assert "https://api.example.com/v2/orders" in f.endpoints
    kinds = {s.kind for s in f.secrets}
    assert "aws_access_key_id" in kinds
    assert "google_api_key" in kinds
    aws = next(s for s in f.secrets if s.kind == "aws_access_key_id")
    assert aws.value == _AKIA


def test_mine_js_benign_blob_has_no_false_positive_secrets() -> None:
    benign = """
    const API_URL = "/api/health";
    function load() { return fetch(API_URL).then(r => r.json()); }
    const RETRIES = 3;
    let message = "Loading, please wait...";
    const color = "#ffcc00";
    const version = "v1.2.3";
    """
    f = mine_js(benign)
    assert f.secrets == []               # precision: nothing secret-shaped here
    assert "/api/health" in f.endpoints  # but the endpoint is still mined


def test_mine_js_generic_secret_behind_plausibility_guard() -> None:
    # a real-looking token value is caught; a placeholder is not
    caught = mine_js('const apiKey = "aB3xY9zK12mnQ7wR";')
    assert any(s.kind == "generic_secret" and s.value == "aB3xY9zK12mnQ7wR"
               for s in caught.secrets)
    placeholder = mine_js('const apiKey = "your_api_key_here";')
    assert placeholder.secrets == []


def test_mine_js_resolves_paths_against_base_url() -> None:
    f = mine_js('fetch("/api/x");', base_url="https://target.example/app/")
    assert "https://target.example/api/x" in f.endpoints


def test_mine_js_catches_jwt_and_private_key() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456"
    src = f'const t = "{jwt}";\nconst pk = "-----BEGIN RSA PRIVATE KEY-----";'
    kinds = {s.kind for s in mine_js(src).secrets}
    assert "jwt" in kinds
    assert "private_key" in kinds


# ---------------------------------------------------------------------------
# OpenAPI / GraphQL ingestion
# ---------------------------------------------------------------------------

_OPENAPI = {
    "openapi": "3.0.0",
    "paths": {
        "/users": {
            "get": {"parameters": [{"name": "limit", "in": "query"},
                                   {"name": "offset", "in": "query"}]},
            "post": {"requestBody": {}},
        },
        "/users/{id}": {
            "parameters": [{"name": "id", "in": "path"}],
            "get": {"parameters": [{"name": "expand", "in": "query"}]},
            "delete": {},
        },
    },
}


def test_parse_openapi_walks_paths_to_operations() -> None:
    ops = parse_openapi(_OPENAPI)
    assert all(isinstance(o, ApiOperation) for o in ops)

    get_users = next(o for o in ops if o.method == "GET" and o.path == "/users")
    assert get_users.params == ["limit", "offset"]

    assert any(o.method == "POST" and o.path == "/users" for o in ops)

    get_by_id = next(o for o in ops if o.method == "GET" and o.path == "/users/{id}")
    # path-level 'id' merged in ahead of the operation-level 'expand'
    assert get_by_id.params == ["id", "expand"]

    # a method with no parameters still becomes an operation (with the shared one)
    delete_by_id = next(o for o in ops if o.method == "DELETE" and o.path == "/users/{id}")
    assert delete_by_id.params == ["id"]


def test_parse_openapi_accepts_json_string() -> None:
    ops = parse_openapi(json.dumps(_OPENAPI))
    assert {(o.method, o.path) for o in ops} >= {
        ("GET", "/users"), ("POST", "/users"), ("GET", "/users/{id}"),
        ("DELETE", "/users/{id}"),
    }


def test_parse_openapi_bad_input_is_empty() -> None:
    assert parse_openapi("not json") == []
    assert parse_openapi({"no": "paths"}) == []


_OPENAPI_BODY = {
    "openapi": "3.0.0",
    "components": {"schemas": {
        "Address": {"type": "object",
                    "properties": {"city": {"type": "string"}, "zip": {"type": "integer"}}},
        "CreateUser": {"type": "object", "required": ["name"], "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
            "address": {"$ref": "#/components/schemas/Address"},
            "tags": {"type": "array", "items": {"type": "string"}},
        }},
    }},
    "paths": {"/users": {"post": {
        "parameters": [{"name": "dry", "in": "query", "schema": {"type": "boolean"}}],
        "requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/CreateUser"}}}},
    }}},
}


def test_parse_openapi_lifts_requestbody_schema_and_param_types() -> None:
    op = next(o for o in parse_openapi(_OPENAPI_BODY) if o.method == "POST" and o.path == "/users")
    # the $ref'd requestBody is resolved into a SELF-CONTAINED nested schema (no $ref left to chase)
    assert op.request_schema is not None
    props = op.request_schema["properties"]
    assert props["name"]["type"] == "string"
    assert props["address"]["properties"]["city"]["type"] == "string"   # nested $ref inlined
    assert props["tags"]["items"]["type"] == "string"
    # the query parameter's declared type is carried; the body is the schema, NOT a flat param
    assert op.param_types.get("dry") == "boolean"
    assert op.params == ["dry"] and "name" not in op.params


def test_parse_openapi_cyclic_ref_terminates_bounded() -> None:
    doc = {
        "openapi": "3.0.0",
        "components": {"schemas": {"Node": {"type": "object", "properties": {
            "value": {"type": "string"}, "next": {"$ref": "#/components/schemas/Node"}}}}},
        "paths": {"/n": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Node"}}}}}}},
    }
    op = next(o for o in parse_openapi(doc) if o.path == "/n")   # must not hang / blow the stack
    assert isinstance(op.request_schema, dict)                   # bounded: the cycle collapses to {} at the floor
    assert op.request_schema["properties"]["value"]["type"] == "string"


def test_parse_openapi_dangling_ref_is_fail_closed() -> None:
    doc = {"openapi": "3.0.0", "paths": {"/x": {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"$ref": "#/components/schemas/Missing"}}}}}}}}
    op = next(o for o in parse_openapi(doc) if o.path == "/x")
    assert op.request_schema is None                             # unresolved ref -> no typed body (fail-closed)


# ---- W1 red-pen hardening (wllz0lhkn): a hostile/malformed spec must never crash or OOM the scan ----------
def test_parse_openapi_nondict_content_does_not_crash() -> None:
    # HIGH: a crafted requestBody.content['application/json'] that is NOT a dict must not raise (whole-scan DoS).
    for bad in ("x", ["a"], 7, True):
        doc = {"openapi": "3.0.0", "paths": {"/x": {"post": {"requestBody": {"content": {
            "application/json": bad}}}}}}
        ops = parse_openapi(doc)                                  # must return, not raise
        op = next(o for o in ops if o.path == "/x")
        assert op.request_schema is None, bad
    # also a non-dict requestBody / content at the higher levels
    for doc in ({"openapi": "3.0.0", "paths": {"/y": {"post": {"requestBody": "nope"}}}},
                {"openapi": "3.0.0", "paths": {"/y": {"post": {"requestBody": {"content": "nope"}}}}}):
        assert any(o.path == "/y" for o in parse_openapi(doc))


def test_parse_openapi_strips_spec_data_keywords() -> None:
    # HIGH+LOW: enum/const/default/example VALUES are dropped at parse — never retained in request_schema,
    # so they can never reach the baseline body (no injection payload, no deep/wide-blob DoS).
    doc = {"openapi": "3.0.0", "paths": {"/x": {"post": {"requestBody": {"content": {"application/json": {
        "schema": {"type": "object", "properties": {
            "mode": {"type": "string", "enum": ["'; DROP TABLE t; --", "safe"], "default": "safe"},
            "blob": {"type": "object", "example": {"deep": {"deeper": [1, 2, 3]}}},
        }}}}}}}}}
    op = next(o for o in parse_openapi(doc) if o.path == "/x")
    props = op.request_schema["properties"]
    assert "enum" not in props["mode"] and "default" not in props["mode"]
    assert props["mode"]["type"] == "string"                     # structure kept, data dropped
    assert "example" not in props["blob"]


def test_parse_openapi_doc_wide_budget_bounds_a_hostile_spec() -> None:
    # MED: K ops each $ref'ing one wide shared schema must NOT multiply into an OOM — the doc-wide node
    # budget caps TOTAL resolved nodes well below K*width (later ops truncate once the budget is spent).
    wide = {"type": "object", "properties": {f"p{i}": {"type": "string"} for i in range(300)}}
    doc = {"openapi": "3.0.0", "components": {"schemas": {"W": wide}},
           "paths": {f"/op{k}": {"post": {"requestBody": {"content": {"application/json": {
               "schema": {"$ref": "#/components/schemas/W"}}}}}} for k in range(200)}}
    ops = parse_openapi(doc)                                      # completes; must not OOM
    total_props = sum(len((o.request_schema or {}).get("properties", {})) for o in ops)
    assert total_props <= _MAX_DOC_NODES + 500, total_props       # bounded (not 200*300 = 60000)


def test_parse_openapi_swagger2_body_name_fallback_on_unresolvable_schema() -> None:
    # MED: a Swagger-2 in:body whose schema does not resolve keeps the body param NAME as a flat field
    # (pre-W1 body surface preserved, not silently dropped).
    doc = {"swagger": "2.0", "paths": {"/b": {"post": {"parameters": [
        {"name": "payload", "in": "body", "schema": {"$ref": "#/definitions/Missing"}}]}}}}
    op = next(o for o in parse_openapi(doc) if o.path == "/b")
    assert op.request_schema is None and "payload" in op.params   # name re-attached as a flat field
    # a RESOLVABLE body schema uses the schema and does NOT leak the name into params
    doc2 = {"swagger": "2.0", "definitions": {"U": {"type": "object", "properties": {"n": {"type": "string"}}}},
            "paths": {"/b": {"post": {"parameters": [
                {"name": "payload", "in": "body", "schema": {"$ref": "#/definitions/U"}}]}}}}
    op2 = next(o for o in parse_openapi(doc2) if o.path == "/b")
    assert op2.request_schema is not None and "payload" not in op2.params


_INTROSPECTION = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"name": "User", "fields": [{"name": "id"}, {"name": "email"},
                                        {"name": "isAdmin"}]},
            {"name": "Query", "fields": [{"name": "user"}, {"name": "users"}]},
            {"name": "__Type", "fields": [{"name": "name"}]},  # meta -> skipped
        ],
    }},
}


def test_parse_graphql_schema_extracts_type_and_field_names() -> None:
    names = parse_graphql_schema(_INTROSPECTION)
    assert "User" in names
    assert "email" in names and "isAdmin" in names
    assert "user" in names and "users" in names
    # introspection meta types are filtered out
    assert "__Type" not in names


def test_parse_graphql_schema_accepts_json_string() -> None:
    names = parse_graphql_schema(json.dumps(_INTROSPECTION))
    assert "User" in names and "email" in names


# ---- W2: structured GraphQL operation surface (roots + fields + typed args) ------------------------------
_INTROSPECTION_OPS = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [
                {"name": "user", "args": [
                    {"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}},
                    {"name": "verbose", "type": {"kind": "SCALAR", "name": "Boolean"}}]},
                {"name": "search", "args": [
                    {"name": "q", "type": {"kind": "SCALAR", "name": "String"}},
                    {"name": "tags", "type": {"kind": "LIST", "ofType": {"kind": "SCALAR", "name": "String"}}}]},
            ]},
            {"name": "Mutation", "fields": [
                {"name": "deleteUser", "args": [
                    {"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}]}]},
            {"name": "__Type", "fields": [{"name": "name", "args": []}]},   # meta -> skipped
        ],
    }},
}


def test_parse_graphql_operations_extracts_roots_fields_args_and_kind() -> None:
    ops = parse_graphql_operations(_INTROSPECTION_OPS)
    by = {(o.kind, o.name): o for o in ops}
    assert ("query", "user") in by and ("query", "search") in by
    assert ("mutation", "deleteUser") in by                     # the Mutation root is identified as state-changing
    atypes = {a.name: a.type_name for a in by[("query", "user")].args}
    assert atypes == {"id": "ID", "verbose": "Boolean"}         # NON_NULL unwrapped to its named scalar
    tags = next(a for a in by[("query", "search")].args if a.name == "tags")
    assert tags.type_name == "String" and tags.is_list          # LIST unwrapped + flagged
    assert not any(o.name == "name" for o in ops)               # meta (__Type) fields are not operations


def test_parse_graphql_operations_bounded_and_robust() -> None:
    from framework.v2.scanner.discovery import _gql_unwrap_type
    big = {"__schema": {"queryType": {"name": "Query"}, "types": [
        {"name": "Query", "fields": [{"name": f"f{i}", "args": [
            {"name": f"a{j}", "type": {"kind": "SCALAR", "name": "String"}} for j in range(200)]}
            for i in range(2000)]}]}}
    ops = parse_graphql_operations(big)
    assert len(ops) <= 500 and all(len(o.args) <= 50 for o in ops)   # _GQL_MAX_OPS / _GQL_MAX_ARGS
    assert parse_graphql_operations("not json") == [] and parse_graphql_operations({"no": "schema"}) == []
    # a deeply-wrapped type-ref unwrap terminates (bounded), never hangs
    node: dict = {"kind": "NON_NULL", "ofType": None}
    cur = node
    for _ in range(50):
        cur["ofType"] = {"kind": "LIST", "ofType": None}
        cur = cur["ofType"]
    name, is_list = _gql_unwrap_type(node)
    assert name == "" and is_list is True


def test_parse_graphql_operations_fails_closed_when_mutation_type_is_declared_the_query_root() -> None:
    """Root classification is the ONLY destruction-safety signal the dispatch layer has, and the
    introspection response is UNTRUSTED. A hostile schema that declares the mutation-bearing type
    as its queryType must NOT be able to relabel mutation-root fields as fuzzable queries —
    mutation wins the conflict (fail-closed toward state-changing)."""
    hostile = {"data": {"__schema": {
        "queryType": {"name": "Mutation"},      # hostile: the mutation-bearing type named as query root
        "mutationType": {"name": "Query"},      # ...and the benign type named as the mutation root
        "types": [
            {"name": "Mutation", "fields": [{"name": "deleteUser", "args": []}]},
            {"name": "Query", "fields": [{"name": "me", "args": []}]},
        ],
    }}}
    kinds = {o.name: o.kind for o in parse_graphql_operations(hostile)}
    # deleteUser lives on the type named "Mutation" -> stays a mutation (never relabeled a query)
    assert kinds.get("deleteUser") == "mutation", kinds
    # and the "Query"-named type, declared as the mutation root, is ALSO treated as state-changing
    assert kinds.get("me") == "mutation", kinds


def test_parse_graphql_operations_identifies_a_declared_custom_mutation_root() -> None:
    """With the enriched introspection requesting mutationType, a custom-named mutation root
    (not literally "Mutation") is correctly classified state-changing — it is not silently
    dropped (the W2 red-pen's secondary gap)."""
    schema = {"data": {"__schema": {
        "queryType": {"name": "RootQuery"},
        "mutationType": {"name": "RootMutation"},
        "types": [
            {"name": "RootQuery", "fields": [{"name": "me", "args": []}]},
            {"name": "RootMutation", "fields": [{"name": "wipe", "args": []}]},
        ],
    }}}
    kinds = {o.name: o.kind for o in parse_graphql_operations(schema)}
    assert kinds.get("me") == "query"
    assert kinds.get("wipe") == "mutation"     # custom mutation root identified via declared mutationType


# ---------------------------------------------------------------------------
# parameter mining
# ---------------------------------------------------------------------------


def test_mine_params_harvests_names_from_html_and_js() -> None:
    src = """
    <input name="csrf_token" type="hidden">
    <input name="username">
    <select id="role"></select>
    const q = req.query.redirect;
    const b = req.body.amount;
    const d = params.get("debug");
    const u = data["userId"];
    """
    names = mine_params(src)
    for expected in ("csrf_token", "username", "role", "redirect", "amount",
                     "debug", "userId"):
        assert expected in names, expected
    # accessor method names are dropped, not treated as parameters
    assert "get" not in names


def test_mine_params_dedupes_in_first_seen_order() -> None:
    names = mine_params('name="a" name="a" name="b"')
    assert names == ["a", "b"]
