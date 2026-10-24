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
_BATCH_ALIAS_RE = re.compile(r"(\w+)\s*:\s*__typename")


def _batch_alias(op: object) -> str:
    """The alias VIGIL put on ``__typename`` in one batched op (``{ v0: __typename }`` → ``v0``); a real
    GraphQL server returns that op's result under that alias. Falls back to ``__typename`` for a bare op."""
    q = op.get("query", "") if isinstance(op, dict) else ""
    m = _BATCH_ALIAS_RE.search(q)
    return m.group(1) if m else "__typename"


def _make(
    *, introspection: bool = True, depth_guard: bool = False, alias_guard: bool = False,
    batch_enabled: bool = True, cost_guard: bool = False, benign_array: bool = False,
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
                if benign_array:
                    # Same-shape negative control: a benign, non-GraphQL >=2-element data array (a static
                    # list / REST collection feed) that NEVER carries VIGIL's distinct v{i} aliases.
                    return [{"id": 1, "data": {"t": "A"}}, {"id": 2, "data": {"t": "B"}}]
                if batch_enabled:
                    # A real batching server runs each op and echoes its VIGIL-chosen alias v{i}.
                    return [{"data": {_batch_alias(op): "Query"}} for op in doc]
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


def test_depth_accepted_is_a_lead_never_confirmed() -> None:
    # A bounded depth probe being ACCEPTED proves only 'limit (if any) >= probe', NOT 'limit absent' — so a
    # benign higher-limit origin would mint a false FACT. Depth is a LEAD, never an oracle-confirmed FACT.
    with _server(introspection=True, depth_guard=False) as (h, p):
        res = GraphQLDepthCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None, "an accepted depth probe must NOT be a confirmed FACT (acceptance != absence)"
        assert res.lead, "an accepted depth probe should surface a lead"

    with _server(introspection=True, depth_guard=True) as (h, p):
        res = GraphQLDepthCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None and res.lead is None, "a depth-limited endpoint is silent"


def test_depth_introspection_off_is_a_lead_not_confirmed() -> None:
    with _server(introspection=False) as (h, p):
        res = GraphQLDepthCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None, "must not confirm depth without introspection"
        assert res.lead, "should surface a depth lead when introspection is off"


def test_alias_accepted_is_a_lead_never_confirmed() -> None:
    # Same reasoning as depth: an N-alias probe resolving proves only 'limit >= N', never 'limit absent'.
    with _server(alias_guard=False) as (h, p):
        res = GraphQLAliasCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None, "an accepted alias probe must NOT be a confirmed FACT (acceptance != absence)"
        assert res.lead, "an accepted alias probe should surface a lead"

    with _server(alias_guard=True) as (h, p):
        res = GraphQLAliasCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None and res.lead is None, "an alias-limited endpoint is silent"


def test_alias_lead_even_when_introspection_disabled() -> None:
    # __typename is a spec meta-field present even with introspection off: the probe still resolves → a LEAD.
    with _server(introspection=False, alias_guard=False) as (h, p):
        res = GraphQLAliasCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None and res.lead


def test_batching_confirmed_and_clean() -> None:
    with _server(batch_enabled=True) as (h, p):
        res = GraphQLBatchingCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is not None, "batching not confirmed"
        # F7 capture-bound: the context retains the RAW body and declares the VIGIL reduction as a
        # provenance-ref (so eq[batch_result_count, sent_batch] is a sound PD3 the verifier re-executes —
        # the count is of positions echoing VIGIL's distinct v{i} aliases, bound to the ops VIGIL sent).
        ctx = res.context.to_verifier_context()
        observed = ctx.get("observed_evidence") or {}
        assert "response_body" in observed and observed.get("batch_result_count", 0) >= 2
        assert observed.get("batch_result_count") == observed.get("sent_batch"), (
            "the fire requires every sent op to have echoed its VIGIL alias (count == sent_batch)")
        assert (res.context.provenance_refs or {}).get("batch_result_count") == "reduction"
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLBatchingCheck(),))
        assert [x for x in f if x.bug_class == "graphql_batching"], "batching not confirmed via audit"

    with _server(batch_enabled=False) as (h, p):
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLBatchingCheck(),))
        assert f == [], "a non-batching endpoint must be clean"


def test_batching_benign_array_mints_nothing() -> None:
    """DECISIVE same-shape negative control (the one the first batching slice was missing): a benign origin
    answering VIGIL's IDENTICAL M-op array POST with a static >=2-element JSON array of data-bearing objects
    that NEVER carry VIGIL's distinct v{i} aliases (a REST/collection feed, a static list) scores
    batch_result_count 0 — eq[count, sent_batch] cannot fire. The pre-fix gt[count,1]-over-any-data-element
    form minted a FALSE graphql_batching FACT on exactly this body."""
    with _server(benign_array=True) as (h, p):
        res = GraphQLBatchingCheck().probe_dos(_template(h, p), _send(h, p))
        assert res.context is None, "a benign >=2-element data array must NOT confirm batching"
        f = AuditEngine(_send(h, p)).audit(
            _template(h, p).request, checks=(), request_checks=(GraphQLBatchingCheck(),))
        assert [x for x in f if x.bug_class == "graphql_batching"] == [], (
            "a benign data array (no VIGIL aliases) must be clean — no graphql_batching FACT")


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


def test_campaign_on_confirms_batching_and_records_depth_alias_cost_leads() -> None:
    with _server(introspection=True, batch_enabled=True, cost_guard=False) as (h, p):
        report = _campaign(h, p, dos=True).run(f"http://{h}:{p}/graphql")
    classes = {f.bug_class for f in report.active_findings}
    # batching is the ONLY DoS class that is soundly a FACT (binary capability, same-shape differential).
    assert "graphql_batching" in classes
    # depth/alias/cost stay LEADs (acceptance != absence-of-limit), never active findings.
    assert "graphql_depth_limit" not in classes
    assert "graphql_alias_overloading" not in classes
    assert "graphql_cost" not in classes
    assert any("graphql-depth" in lead for lead in report.graphql_leads), report.graphql_leads
    assert any("graphql-alias" in lead for lead in report.graphql_leads), report.graphql_leads
    assert any("graphql-cost" in lead for lead in report.graphql_leads), report.graphql_leads


def test_campaign_on_stays_clean_against_a_fully_guarded_endpoint() -> None:
    with _server(introspection=False, depth_guard=True, alias_guard=True,
                 batch_enabled=False, cost_guard=True) as (h, p):
        report = _campaign(h, p, dos=True).run(f"http://{h}:{p}/graphql")
    dos_classes = {"graphql_depth_limit", "graphql_alias_overloading", "graphql_batching", "graphql_cost"}
    assert not (dos_classes & {f.bug_class for f in report.active_findings}), "guarded endpoint must not fire"
