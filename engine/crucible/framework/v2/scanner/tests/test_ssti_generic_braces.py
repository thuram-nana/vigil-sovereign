"""
Always-on generic {{...}} SSTI library entry (m2-ssti-generic-braces).

Every {{...}} library SSTI entry was language-gated (jinja2->python, twig->php, ...), and the only
ALWAYS-ON generic entries probed ${...} (m2-ssti-generic) and #{...} (pug) — so a double-brace template
target NOT fingerprinted to a language got no FIRING library SSTI probe. This entry closes that
general-coverage gap for the ubiquitous {{...}} family (Jinja2/Twig/Nunjucks/Handlebars/Liquid).

It reuses the EXISTING, proven EVALUATION oracle (no oracle change): a fire needs the COMPUTED product
present AND the raw probe absent (substituted, not echoed) AND absent from a benign control. The vuln
fixture GENUINELY evaluates the arithmetic (ast-based), so the product is a property of evaluation, not
canned text; a reflecting fixture that echoes the raw {{...}} does NOT fire (raw present).
"""

from __future__ import annotations

import ast
import contextlib
import html
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import compile_entry, load_library
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

_TEMPLATE_RE = re.compile(r"\{\{(.*?)\}\}")


def _eval_arith(expr: str) -> int:
    """Genuinely evaluate a tiny arithmetic expression (so the product is a real evaluation, never
    canned): integer constants and * / + only. Anything else raises."""
    node = ast.parse(expr.strip(), mode="eval").body

    def ev(n: ast.AST) -> int:
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.BinOp):
            lo, ro = ev(n.left), ev(n.right)
            if isinstance(n.op, ast.Mult):
                return lo * ro
            if isinstance(n.op, ast.Add):
                return lo + ro
        raise ValueError("unsupported expression")

    return ev(node)


class _Evaluates(BaseHTTPRequestHandler):
    """VULNERABLE: substitutes {{expr}} with the server-side EVALUATED product (raw token gone)."""

    def log_message(self, *a: object) -> None:
        return

    def _title(self) -> str:
        return parse_qs(urlsplit(self.path).query).get("title", [""])[0]

    def do_GET(self) -> None:  # noqa: N802
        def repl(m: "re.Match[str]") -> str:
            try:
                return str(_eval_arith(m.group(1)))
            except Exception:
                return m.group(0)
        body = f"<h1>{_TEMPLATE_RE.sub(repl, self._title())}</h1>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ReflectsRaw(_Evaluates):
    """NOT vulnerable: echoes the raw title verbatim (the raw {{...}} survives) — reflection, not
    evaluation. The hardened template twin behaves the same for the oracle (raw present => no fire)."""

    def do_GET(self) -> None:  # noqa: N802
        body = f"<h1>{html.escape(self._title())}</h1>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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


def _entry():
    e = next((e for e in load_library() if e.id == "m2-ssti-generic-braces"), None)
    assert e is not None, "m2-ssti-generic-braces did not load from the library"
    return e


def _confirms(check, base: str) -> bool:
    tmpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/reports/run?title=x"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "title"]
    ctx = check.probe(tmpl, pt, loopback_send)
    if ctx is None:
        return False
    return confirm_finding(
        finding={"bug_class": check.bug_class, "title": "t", "severity": "High",
                 "surface": "s", "summary": "x"},
        context=ctx, verifier=OracleVerifier()) is not None


def test_entry_loads_always_on_double_brace() -> None:
    e = _entry()
    assert e.bug_class == "ssti"
    assert e.applies_when == {"always": True}
    assert "{{31337*31337}}" in e.oracle.probe_expr
    assert e.oracle.expected_result == "982007569"


def test_confirms_on_genuine_double_brace_evaluation() -> None:
    with _server(_Evaluates) as base:
        assert _confirms(compile_entry(_entry()), base)


def test_does_not_confirm_on_reflection_only() -> None:
    # the raw {{...}} is echoed back (reflection / hardened escape) -> no computed product -> silent
    with _server(_ReflectsRaw) as base:
        assert not _confirms(compile_entry(_entry()), base)


def test_library_ids_unique_with_new_entry() -> None:
    ids = [e.id for e in load_library()]
    assert len(ids) == len(set(ids)), "duplicate library ids after adding m2-ssti-generic-braces"
