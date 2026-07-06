"""
M2e — error-based SQL injection as data, confirmed by the error-signature oracle.

The ErrorSignatureCheck (and the library entries that compile to it) confirm
error-based injection against a fixture that leaks a DBMS error on a syntax-
breaking payload, and correctly refuse a fixture that always shows the error (the
control has it too) — so a permanently-broken page is not a false positive.
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.checks import ErrorSignatureCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import compile_entry, load_library
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

_MYSQL_ERR = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"


class _ErrApp(BaseHTTPRequestHandler):
    """Leaks a MySQL error ONLY when the input breaks quoting (a lone quote /
    backtick / unbalanced paren) — like a vulnerable app echoing the DB error."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        if any(c in q for c in ("'", '"', "`")) or q.endswith(")"):
            body = f"<html>Query failed: {_MYSQL_ERR} near '{q}'</html>".encode()
        else:
            body = b"<html>results: 3 rows</html>"
        self._send(body)

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _AlwaysErrApp(_ErrApp):
    """Always shows the DB error, regardless of input — the control has it too, so
    it must NOT be attributed to the payload (safe twin for error-based)."""

    def do_GET(self) -> None:  # noqa: N802
        self._send(f"<html>Query failed: {_MYSQL_ERR}</html>".encode())


@contextlib.contextmanager
def _server(handler) -> Iterator[str]:
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


def _send_for(base: str):
    import urllib.request

    def send(req: HttpRequest) -> dict:
        with urllib.request.urlopen(req.url, timeout=5) as resp:  # noqa: S310 (loopback)
            return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}
    return send


def _confirms(check, base: str) -> bool:
    tmpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/search?q=hi"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q"]
    ctx = check.probe(tmpl, pt, _send_for(base))
    if ctx is None:
        return False
    return confirm_finding(
        finding={"bug_class": check.bug_class, "title": "t", "severity": "High",
                 "surface": "s", "summary": "x"},
        context=ctx, verifier=OracleVerifier(),
    ) is not None


def test_error_check_confirms_when_payload_provokes_the_error() -> None:
    check = ErrorSignatureCheck(id="err", bug_class="error_based_sqli", probe_payload="'")
    with _server(_ErrApp) as base:
        assert _confirms(check, base)


def test_error_check_refuses_when_error_is_permanent() -> None:
    check = ErrorSignatureCheck(id="err", bug_class="error_based_sqli", probe_payload="'")
    with _server(_AlwaysErrApp) as base:
        assert not _confirms(check, base)


def test_error_library_entries_compile_and_confirm() -> None:
    entries = [e for e in load_library() if e.id.startswith("m2-errsqli-")]
    assert len(entries) >= 6
    assert all(e.oracle.kind == "error_signature" for e in entries)
    rep = next(e for e in entries if e.id == "m2-errsqli-single-quote")
    with _server(_ErrApp) as base:
        assert _confirms(compile_entry(rep), base)
    with _server(_AlwaysErrApp) as base:
        assert not _confirms(compile_entry(rep), base)
