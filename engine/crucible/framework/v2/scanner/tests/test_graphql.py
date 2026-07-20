"""
GraphQL checks — introspection and field-suggestion leakage, confirmed on the
actual schema/suggestion, clean when the endpoint is locked down.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.graphql import GraphQLIntrospectionCheck, GraphQLSuggestionsCheck
from framework.v2.scanner.insertion import HttpRequest


def _make(introspection: bool, suggestions: bool) -> type[BaseHTTPRequestHandler]:
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                query = json.loads(self.rfile.read(n)).get("query", "")
            except Exception:
                query = ""
            if "__schema" in query:
                if introspection:
                    out = {"data": {"__schema": {"queryType": {"name": "Query"},
                                                 "types": [{"name": "User"}, {"name": "Query"}]}}}
                else:
                    out = {"errors": [{"message": "GraphQL introspection is not allowed"}]}
            elif "__crucible_no_such_field" in query:
                msg = "Cannot query field '__crucible_no_such_field_xyz' on type 'Query'."
                if suggestions:
                    msg += " Did you mean 'user'?"
                out = {"errors": [{"message": msg}]}
            else:
                out = {"data": {}}
            body = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _H


class _Srv(ThreadingHTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def _server(introspection: bool, suggestions: bool) -> Iterator[tuple[str, int]]:
    srv = _Srv(("127.0.0.1", 0), _make(introspection, suggestions))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield "127.0.0.1", srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _send(host: str, port: int):
    def send(req: HttpRequest) -> dict:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request(req.method, "/graphql", body=(req.body or "").encode(), headers=dict(req.headers))
            resp = conn.getresponse()
            return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}
        finally:
            conn.close()
    return send


def test_introspection_confirmed_and_clean() -> None:
    with _server(introspection=True, suggestions=False) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/graphql")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(GraphQLIntrospectionCheck(),))
        assert [x for x in f if x.bug_class == "graphql_introspection"], "introspection leak not confirmed"

    with _server(introspection=False, suggestions=False) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/graphql")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(GraphQLIntrospectionCheck(),))
        assert f == [], "introspection-disabled endpoint must be clean"


def test_field_suggestions_confirmed_and_clean() -> None:
    with _server(introspection=False, suggestions=True) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/graphql")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(GraphQLSuggestionsCheck(),))
        assert [x for x in f if x.bug_class == "graphql_suggestions"], "field-suggestion leak not confirmed"

    with _server(introspection=False, suggestions=False) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/graphql")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(GraphQLSuggestionsCheck(),))
        assert f == [], "an endpoint without suggestions must be clean"
