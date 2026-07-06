"""
M2d — SSTI as data + confirmed by evaluation, end to end.

The EvaluationCheck (and the library entries that compile to it) confirm SSTI
against a fixture that EVALUATES the injected arithmetic, and correctly refuse a
fixture that only REFLECTS it — so template injection is now a real, oracle-
anchored confirmation across engines, not a reflection guess.
"""

from __future__ import annotations

import contextlib
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.checks import EvaluationCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import compile_entry, load_library
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

_RESULT = str(31337 * 31337)


class _EvalApp(BaseHTTPRequestHandler):
    """A fake template engine: it EVALUATES `a*b` found in the input (like a
    vulnerable server rendering user input as template source) and does NOT echo
    the raw payload."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        m = re.search(r"(\d+)\s*\*\s*(\d+)", q)
        rendered = str(int(m.group(1)) * int(m.group(2))) if m else "no-op"
        body = f"<html>top\nrendered={rendered}\nbottom</html>".encode()
        self._send(body)

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ReflectApp(_EvalApp):
    """Reflects the raw input verbatim — the engine did NOT evaluate it (safe
    twin for SSTI: reflection is not template injection)."""

    def do_GET(self) -> None:  # noqa: N802
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = f"<html>echo: {q}</html>".encode()
        self._send(body)


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


def _point(base: str):
    tmpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/render?q=hi"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q"]
    return tmpl, pt


def _confirms(check, base: str) -> bool:
    tmpl, pt = _point(base)
    ctx = check.probe(tmpl, pt, _send_for(base))
    if ctx is None:
        return False
    return confirm_finding(
        finding={"bug_class": check.bug_class, "title": "t", "severity": "Critical",
                 "surface": "s", "summary": "x"},
        context=ctx, verifier=OracleVerifier(),
    ) is not None


def test_evaluation_check_confirms_on_evaluating_target() -> None:
    check = EvaluationCheck(id="ssti-jinja", bug_class="ssti",
                            probe_expr=f"{{{{31337*31337}}}}", expected_result=_RESULT)
    with _server(_EvalApp) as base:
        assert _confirms(check, base)


def test_evaluation_check_refuses_reflecting_target() -> None:
    check = EvaluationCheck(id="ssti-jinja", bug_class="ssti",
                            probe_expr=f"{{{{31337*31337}}}}", expected_result=_RESULT)
    with _server(_ReflectApp) as base:
        assert not _confirms(check, base)


def test_ssti_library_entries_compile_and_a_representative_confirms() -> None:
    ssti = [e for e in load_library() if e.id.startswith("m2-ssti-")]
    assert len(ssti) >= 8, "expected SSTI-per-engine coverage"
    assert all(e.oracle.kind == "evaluation" for e in ssti)
    assert all(e.oracle.expected_result == _RESULT for e in ssti)

    # a compiled entry whose syntax the fixture's `a*b` extractor evaluates
    gen = next(e for e in ssti if e.id == "m2-ssti-generic")
    with _server(_EvalApp) as base:
        assert _confirms(compile_entry(gen), base)
    with _server(_ReflectApp) as base:
        assert not _confirms(compile_entry(gen), base)
