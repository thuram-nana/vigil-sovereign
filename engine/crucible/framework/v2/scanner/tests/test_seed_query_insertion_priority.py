"""
#827 — a query-bearing SEED must have its query value audited, even on the gated
``engage`` path.

The insertion sweep enumerates points path -> query (``RequestTemplate.insertion_points``).
On ``scan`` the loopback send is UNBOUNDED, so a multi-segment query-bearing seed such as
``http://127.0.0.1/records/search?q=1`` gets every point audited and the q-param SQLi/XSS is
confirmed at ``query_value:0``. On ``engage`` every request funnels through the gated
executor's PER-ENGAGEMENT ``request_budget``; the two leading path segments, swept with the
full check roster, can exhaust that budget before the sweep ever reaches the seed's query
value — so ``engage`` audited only ``url_path_seg`` and silently MISSED the q-param finding
(the false-clean failure the no-truncation doctrine refuses).

The fix prioritises the SEED request's query insertion points (``WebScanCampaign.run`` ->
``AuditEngine.audit(priority_kinds=...)``) so the operator's explicit parameter is reached
within budget. It is scoped to the seed request and only when the seed carries a query, so a
path-only / site-root seed (where query params come from CRAWLING, not the seed) keeps the
byte-identical path->query order and no crawled request is reordered.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterator

from framework.v2.scanner import HttpRequest, InsertionKind, WebScanCampaign
from framework.v2.scanner.engine import AuditEngine


# --- a tiny app: the q-param reflects (reflected XSS at query_value), path segments do not ---
class _App(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        sp = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(sp.query, keep_blank_values=True)
        # Only the query value flows into the body; the path segments are inert. So the ONLY
        # confirmable finding is at query_value — exactly the surface the budget starved.
        q = params.get("q", [""])[0]
        body = f"<html><body>results for {q}</body></html>".encode()
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


def _raw_send(req: HttpRequest) -> dict:
    r = urllib.request.Request(req.url, method=req.method, headers=dict(req.headers))
    if req.body is not None:
        r.data = req.body.encode("utf-8")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 (loopback only)
            return {"status": resp.status, "headers": list(resp.headers.items()),
                    "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:  # a fuzzed path may 404/500 — still a real response
        return {"status": e.code, "headers": list(e.headers.items()),
                "body": e.read().decode("utf-8", "replace")}


def _budgeted(real_send: Callable[[HttpRequest], dict], budget: int) -> Callable[[HttpRequest], dict]:
    """Wrap ``real_send`` so it returns the gated executor's SOFT per-engagement request-budget
    refusal once ``budget`` requests have gone out — byte-for-byte the shape
    ``engine._is_request_budget_refusal`` matches (status 0 + a 'request budget … exhausted'
    note), so this reproduces the ``engage`` truncation without a charter or the real executor."""
    sent = {"n": 0}

    def send(req: HttpRequest) -> dict:
        sent["n"] += 1
        if sent["n"] > budget:
            return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0,
                    "refused": f"per-engagement request budget {budget} exhausted"}
        return real_send(req)

    return send


# ---------------------------------------------------------------------------
# 1. The faithful engage-path reproduction: under a gated request budget, a
#    multi-segment query-bearing SEED still audits (and confirms at) its query value.
# ---------------------------------------------------------------------------


def test_query_bearing_seed_query_value_audited_under_request_budget() -> None:
    with _app() as base:
        seed = base + "/records/search?q=1"   # TWO path segments before the query
        # A budget wide enough for the seed's query value (first point under the fix: its
        # cheap reflected probe fires within a handful of requests) but far too narrow to
        # sweep both leading path segments with the full roster (the boolean SPRT alone is
        # ~64 requests per point) — the exact shape that starved the query on engage.
        send = _budgeted(_raw_send, budget=40)
        report = WebScanCampaign(send, max_pages=3, enable_oob=False).run(seed)

        audited = {p.insertion_point for p in report.exercised_probes}
        # The seed's query value WAS reached within budget (parity with unbounded `scan`).
        assert "query_value:0" in audited, (
            f"the seed's query value was starved by the request budget; audited={sorted(audited)}")
        # …and the q-param finding is confirmed there (not silently missed).
        assert any(f.insertion_point == "query_value:0" for f in report.active_findings), (
            "no confirmed finding at the seed's query value: "
            f"{[(f.bug_class, f.insertion_point) for f in report.active_findings]}")


# ---------------------------------------------------------------------------
# 2. The guard itself, deterministic and budget-free: AuditEngine.audit sweeps the
#    priority kinds (query) BEFORE the rest (path) when asked, and is byte-identical
#    (path first) when not. This is the exact lever WebScanCampaign.run pulls.
# ---------------------------------------------------------------------------


def _first_index(records: list, prefix: str) -> int:
    for i, p in enumerate(records):
        if p.insertion_point.startswith(prefix):
            return i
    return 10**9


def test_audit_priority_kinds_sweeps_query_before_path() -> None:
    req = HttpRequest(method="GET", url="http://127.0.0.1/records/search?q=1")
    benign = lambda _r: {"status": 200, "body": "ok", "headers": [], "latency_ms": 1.0}  # noqa: E731

    # Default (no priority): the enumerated order is path -> query, as today.
    eng = AuditEngine(benign)
    eng.audit(req)
    default_order = list(eng.exercised)
    assert _first_index(default_order, "url_path_seg") < _first_index(default_order, "query_value"), (
        "baseline order is expected to be path-first (the enumeration order)")

    # With the query kinds prioritised: the query value is swept FIRST.
    eng2 = AuditEngine(benign)
    eng2.audit(req, priority_kinds=(InsertionKind.QUERY_VALUE, InsertionKind.QUERY_NAME))
    pri_order = list(eng2.exercised)
    assert _first_index(pri_order, "query_value") < _first_index(pri_order, "url_path_seg"), (
        "priority_kinds did not move the query value ahead of the path segments")

    # Same SET of points either way — priority only reorders, never drops or adds.
    assert {p.insertion_point for p in default_order} == {p.insertion_point for p in pri_order}


# ---------------------------------------------------------------------------
# 3. Byte-identical for a path-only / site-root seed: the campaign applies NO priority
#    (the gate/benchmark seeds, where query params come from crawling), so the audit
#    order is the unchanged path-first enumeration and nothing is reordered.
# ---------------------------------------------------------------------------


def test_path_only_seed_audit_order_is_unchanged() -> None:
    # The seed carries NO query, so WebScanCampaign must pass priority_kinds=() for it —
    # proven by the engine sweeping this seed request path-first exactly as the default does.
    req = HttpRequest(method="GET", url="http://127.0.0.1/records/search")
    benign = lambda _r: {"status": 200, "body": "ok", "headers": [], "latency_ms": 1.0}  # noqa: E731

    eng = AuditEngine(benign)
    eng.audit(req, priority_kinds=())   # what run() computes when urlsplit(seed).query == ""
    order = [p.insertion_point for p in eng.exercised]
    # no query points exist here; the path segments are swept in enumerated order.
    assert order == sorted(order, key=lambda ip: int(ip.split(":")[1])), order
    assert all(ip.startswith("url_path_seg") for ip in order), order
