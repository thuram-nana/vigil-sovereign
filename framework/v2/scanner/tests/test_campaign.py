"""
WebScanCampaign — the single autonomous entrypoint, end to end, plus world-model
wiring back to the planner substrate.

One call against a live multi-page localhost app must: crawl it, passively flag
the missing security headers, actively confirm the boolean-SQLi on the vulnerable
endpoint via a fired oracle, and consolidate it all into one report — with the
active-request budget honored. Then the report populates the world-model with
ENDPOINT + FINDING nodes so the planner can chain from what was found.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner import (
    HttpRequest,
    InsertionKind,
    ScanReport,
    WebScanCampaign,
    populate_worldmodel,
)
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind, NodeKind

_INDEX = b"""<html><body>
    <a href="/search?q=hello">search</a>
    <a href="/about">about</a>
    <a href="/items?id=1">item</a>
</body></html>"""


class _App(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        sp = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(sp.query, keep_blank_values=True)
        if sp.path == "/search":
            q = params.get("q", [""])[0]
            rows = "id=1 a\nid=2 b admin\nid=3 c" if ("'1'='1" in q or "1=1" in q) else "no results"
            body = f"query=[{q}]:\n{rows}".encode()
        elif sp.path == "/about":
            body = b"<html><body>about, no user input</body></html>"
        elif sp.path == "/items":
            body = b"an item"
        else:
            body = _INDEX
        # Deliberately NO security headers -> passive checks must flag them.
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _app() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _App)
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
        return {"status": resp.status, "headers": list(resp.headers.items()),
                "body": resp.read().decode("utf-8", "replace")}


def test_campaign_one_call_crawls_scans_confirms_and_consolidates() -> None:
    with _app() as base:
        report = WebScanCampaign(
            _send, insertion_kinds=(InsertionKind.QUERY_VALUE,),
        ).run(base + "/")

        assert isinstance(report, ScanReport)
        assert report.pages_crawled >= 4  # index + search + about + items
        assert report.requests_discovered >= 4

        # active: the boolean-SQLi on /search?q= is oracle-confirmed
        sqli = [f for f in report.active_findings if f.bug_class == "boolean_sqli"]
        assert sqli and sqli[0].confirmed_by == "differential_response" and sqli[0].param == "q"

        # passive: missing security headers surfaced across the crawl
        pids = {f.check_id for f in report.passive_findings}
        assert "missing-content-security-policy" in pids

        # consolidated severity view includes both halves
        sev = report.by_severity()
        assert sev.get("Confirmed", 0) >= 1 and sum(sev.values()) >= 2


def test_campaign_report_populates_worldmodel_for_the_planner() -> None:
    with _app() as base:
        report = WebScanCampaign(_send, insertion_kinds=(InsertionKind.QUERY_VALUE,)).run(base + "/")
        world = WorldModel()
        populate_worldmodel(report, world, seq=1)

        endpoints = world.nodes_of_kind(NodeKind.ENDPOINT)
        findings = world.nodes_of_kind(NodeKind.FINDING)
        assert endpoints and findings, "scan results were not written into the world-model"
        # every finding EVIDENCES an endpoint — the chain the planner reasons over
        ev = world.edges_of_kind(EdgeKind.EVIDENCES)
        assert ev and all(e.confidence > 0 for e in ev)
        # the SQLi finding node records its oracle provenance
        assert any(n.attrs.get("bug_class") == "boolean_sqli"
                   and n.attrs.get("confirmed_by") == "differential_response"
                   for n in findings)


def test_campaign_audit_budget_is_enforced() -> None:
    with _app() as base:
        report = WebScanCampaign(
            _send, insertion_kinds=(InsertionKind.QUERY_VALUE,), max_audit_requests=2,
        ).run(base + "/")
        assert report.audit_requests_sent <= 2, "campaign active-traffic budget not enforced"
