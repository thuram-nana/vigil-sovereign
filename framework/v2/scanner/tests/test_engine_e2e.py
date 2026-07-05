"""
Audit engine end to end — checks fired across insertion points against a REAL
localhost target, confirmed by the deterministic oracle layer.

This is the autonomous scan the whole package exists for, proven against traffic
(no fixtures): a purpose-built loopback target is vulnerable on the `q` query
parameter (boolean-SQLi differential + reflects its input) and ignores a `safe`
parameter. The engine, given only the request, must (1) confirm findings on `q`
via a fired oracle, and (2) confirm NOTHING on `safe` — the prove-don't-guess
contract, now driven across a live insertion sweep instead of one hardcoded probe.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind


class _VulnHandler(BaseHTTPRequestHandler):
    """Vulnerable ONLY on `q`: a boolean-SQLi differential (an OR-tautology
    returns many rows, a benign term returns none) AND it reflects `q` verbatim.
    `safe` is read but never influences the response — a true negative control."""

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        qs = urllib.parse.urlsplit(self.path).query
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)
        q = params.get("q", [""])[0]
        if "'1'='1" in q or "1=1" in q:
            rows = "id=1 alice\nid=2 bob admin\nid=3 carol\nid=4 dan\nid=5 eve"
        else:
            rows = "no results"
        body = f"query=[{q}] results:\n{rows}".encode("utf-8")  # reflects q
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SafeHandler(BaseHTTPRequestHandler):
    """A constant, non-reflecting, non-differential response — nothing is
    exploitable, so a correct engine confirms zero findings."""

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"static content, no user input echoed"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
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


def test_engine_confirms_vulnerable_param_and_not_the_safe_one() -> None:
    with _server(_VulnHandler) as base:
        req = HttpRequest(method="GET", url=f"{base}/search?q=hello&safe=world")
        engine = AuditEngine(_send)
        findings = engine.audit(req, insertion_kinds=(InsertionKind.QUERY_VALUE,))

        params = {f.param for f in findings}
        assert "q" in params, "the vulnerable q parameter was not found"
        assert "safe" not in params, "the safe parameter was falsely flagged"

        # the boolean-SQLi differential is confirmed on q by a fired oracle
        sqli = [f for f in findings if f.bug_class == "boolean_sqli" and f.param == "q"]
        assert sqli, "boolean-SQLi on q not oracle-confirmed"
        f = sqli[0]
        assert f.confirmed_by == "differential_response"
        assert 0.0 < f.confidence <= 1.0
        assert f.insertion_point.startswith("query_value:")


def test_engine_confirms_nothing_on_a_safe_target() -> None:
    with _server(_SafeHandler) as base:
        req = HttpRequest(method="GET", url=f"{base}/page?q=hello&id=1")
        engine = AuditEngine(_send)
        findings = engine.audit(req, insertion_kinds=(InsertionKind.QUERY_VALUE,))
        assert findings == [], "a non-vulnerable target must yield zero confirmed findings"


def test_request_budget_bounds_the_sweep() -> None:
    with _server(_VulnHandler) as base:
        req = HttpRequest(method="GET", url=f"{base}/search?q=hello&safe=world")
        engine = AuditEngine(_send, max_requests=1)
        engine.audit(req, insertion_kinds=(InsertionKind.QUERY_VALUE,))
        assert engine.requests_sent <= 1, "the request budget must cap traffic"
