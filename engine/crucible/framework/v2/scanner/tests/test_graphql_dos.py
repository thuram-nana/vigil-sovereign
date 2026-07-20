"""
GraphQL DoS/abuse checks — unbounded query DEPTH, ALIAS overloading, request
BATCHING, and query COST.

The confirmable classes (depth/alias/batching) fire ONLY on a real amplified
response (routed through the predicate oracle), stay silent when a guard rejects
the probe, and are absent from the default scan roster. Query COST is an honest
LEAD (a minimal probe being accepted cannot prove a cost limit is absent), as is
depth when introspection is disabled. The whole surface is opt-in
(``enable_graphql_dos``), so the default scan sends exactly the same traffic.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.campaign import DEFAULT_REQUEST_CHECKS, WebScanCampaign
from framework.v2.scanner.crawler import Scope
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.graphql import (
    GRAPHQL_DOS_CHECKS,
    GraphQLAliasCheck,
    GraphQLBatchingCheck,
    GraphQLCostCheck,
    GraphQLDepthCheck,
)
from framework.v2.scanner.insertion import HttpRequest, RequestTemplate

_ALIAS_RE = re.compile(r"a(\d+)\s*:\s*__typename")


def _make(
    *, introspection: bool = True, depth_guard: bool = False, alias_guard: bool = False,
    batch_enabled: bool = True, cost_guard: bool = False,
) -> type[BaseHTTPRequestHandler]:
    """A configurable GraphQL endpoint. Routes DoS probes by their operationName
    and honours (or rejects) each amplification per the flags."""

    def _introspection_off() -> dict:
        return {"data": None, "errors": [{"message": "GraphQL introspection is not allowed"}]}

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802 — lets the crawler reach the seed
            body = b"<html><body>graphql</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace")
            out = self._route(raw)
            body = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _route(self, raw: str) -> object:
            try:
                doc = json.loads(raw)
            except ValueError:
                return {"errors": [{"message": "bad request"}]}

            # Array-batched request.
            if isinstance(doc, list):
                if batch_enabled:
                    return [{"data": {"__typename": "Query"}} for _ in doc]
                return {"errors": [{"message": "batch requests are not supported"}]}

            query = doc.get("query", "") if isinstance(doc, dict) else ""
            op = doc.get("operationName") if isinstance(doc, dict) else None

            if op == "CrucibleDosDepthProbe":
                if depth_guard:
                    return {"data": None, "errors": [{"message": "Query is too deep (max depth 7)"}]}
                if not introspection:
                    return _introspection_off()
                return {"data": {"__type": {"ofType": None}}}

            if op == "CrucibleDosAliasProbe":
                count = len(_ALIAS_RE.findall(query))
                if alias_guard:
                    return {"data": None, "errors": [{"message": "Too many aliases in the query"}]}
                return {"data": {f"a{i}": "Query" for i in range(count)}}

            if op == "CrucibleDosCostProbe":
                if cost_guard:
                    return {"data": None,
                            "errors": [{"message": "Query cost 900 exceeds the maximum cost 100"}]}
                if not introspection:
                    return _introspection_off()
                return {"data": {"c0": {"name": "__Schema", "fields": [{"name": "types"}]}}}

            return {"data": {"__typename": "Query"}}

    return _H


class _Srv(ThreadingHTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def _server(**flags: bool) -> Iterator[tuple[str, int]]:
    srv = _Srv(("127.0.0.1", 0), _make(**flags))
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
            from urllib.parse import urlsplit
            path = urlsplit(req.url).path or "/graphql"
            conn.request(req.method, path, body=(req.body or "").encode(), headers=dict(req.headers))
            resp = conn.getresponse()
            return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}
        finally:
            conn.close()
    return send


def _template(host: str, port: int) -> RequestTemplate:
    return RequestTemplate(HttpRequest(method="POST", url=f"http://{host}:{port}/graphql"))


# --------------------------------------------------------------------------
# Per-check: confirmed on a vulnerable endpoint, clean on a guarded one.
# --------------------------------------------------------------------------


def test_depth_confirmed_and_clean() -> None:
    with _server(introspection=True, depth_guard=False) as (h, p):
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLDepthCheck(),))
        assert [x for x in f if x.bug_class == "graphql_depth_limit"], "unbounded depth not confirmed"

    with _server(introspection=True, depth_guard=True) as (h, p):
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLDepthCheck(),))
        assert f == [], "a depth-limited endpoint must be clean"


def test_depth_introspection_off_is_a_lead_not_confirmed() -> None:
    with _server(introspection=False) as (h, p):
        res = GraphQLDepthCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None, "must not confirm depth without introspection"
        assert res.lead, "should surface a depth lead when introspection is off"


def test_alias_confirmed_and_clean() -> None:
    with _server(alias_guard=False) as (h, p):
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLAliasCheck(),))
        assert [x for x in f if x.bug_class == "graphql_alias_overloading"], "alias overloading not confirmed"

    with _server(alias_guard=True) as (h, p):
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLAliasCheck(),))
        assert f == [], "an alias-limited endpoint must be clean"


def test_alias_confirmed_even_when_introspection_disabled() -> None:
    # __typename is a spec meta-field present even with introspection off.
    with _server(introspection=False, alias_guard=False) as (h, p):
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLAliasCheck(),))
        assert [x for x in f if x.bug_class == "graphql_alias_overloading"]


def test_batching_confirmed_and_clean() -> None:
    with _server(batch_enabled=True) as (h, p):
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLBatchingCheck(),))
        assert [x for x in f if x.bug_class == "graphql_batching"], "batching not confirmed"

    with _server(batch_enabled=False) as (h, p):
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLBatchingCheck(),))
        assert f == [], "a non-batching endpoint must be clean"


def test_cost_is_a_lead_never_confirmed() -> None:
    with _server(introspection=True, cost_guard=False) as (h, p):
        res = GraphQLCostCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None, "cost must never be oracle-confirmed"
        assert res.lead, "an accepted cost probe should surface a lead"

    with _server(cost_guard=True) as (h, p):
        res = GraphQLCostCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None and res.lead is None, "a cost-limited endpoint is silent"


# --------------------------------------------------------------------------
# Roster invariants — the DoS surface is opt-in and out of the default path.
# --------------------------------------------------------------------------


def test_dos_checks_are_not_in_the_default_request_roster() -> None:
    default_ids = {getattr(c, "id", None) for c in DEFAULT_REQUEST_CHECKS}
    dos_ids = {c.id for c in GRAPHQL_DOS_CHECKS}
    assert dos_ids.isdisjoint(default_ids), "DoS checks must not be in the default roster"
    assert dos_ids == {"graphql-depth", "graphql-alias", "graphql-batching", "graphql-cost"}


def test_enable_graphql_dos_defaults_off() -> None:
    camp = WebScanCampaign(lambda req: {"status": 200, "body": ""})
    assert camp.enable_graphql_dos is False


# --------------------------------------------------------------------------
# End-to-end campaign integration (gated).
# --------------------------------------------------------------------------


def _campaign(host: str, port: int, *, dos: bool) -> WebScanCampaign:
    scope = Scope.from_seed(f"http://{host}:{port}/graphql")
    return WebScanCampaign(
        _send(host, port), scope=scope, enable_oob=False, enable_graphql_dos=dos,
    )


def test_campaign_off_yields_no_dos_findings_or_leads() -> None:
    with _server(introspection=True, batch_enabled=True) as (h, p):
        report = _campaign(h, p, dos=False).run(f"http://{h}:{p}/graphql")
    assert report.graphql_leads == []
    assert not [f for f in report.active_findings
                if f.bug_class.startswith("graphql_") and f.check_id.startswith("graphql-")
                and f.bug_class in {"graphql_depth_limit", "graphql_alias_overloading", "graphql_batching"}]


def test_campaign_on_confirms_amplifications_and_records_cost_lead() -> None:
    with _server(introspection=True, batch_enabled=True, cost_guard=False) as (h, p):
        report = _campaign(h, p, dos=True).run(f"http://{h}:{p}/graphql")
    classes = {f.bug_class for f in report.active_findings}
    assert {"graphql_depth_limit", "graphql_alias_overloading", "graphql_batching"} <= classes
    # cost stays a LEAD, never an active finding.
    assert "graphql_cost" not in classes
    assert any("graphql-cost" in lead for lead in report.graphql_leads), report.graphql_leads


def test_campaign_on_stays_clean_against_a_fully_guarded_endpoint() -> None:
    with _server(introspection=False, depth_guard=True, alias_guard=True,
                 batch_enabled=False, cost_guard=True) as (h, p):
        report = _campaign(h, p, dos=True).run(f"http://{h}:{p}/graphql")
    dos_classes = {"graphql_depth_limit", "graphql_alias_overloading", "graphql_batching", "graphql_cost"}
    assert not (dos_classes & {f.bug_class for f in report.active_findings}), "guarded endpoint must not fire"
