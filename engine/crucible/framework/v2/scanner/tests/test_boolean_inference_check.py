"""
Wave 5 — the BooleanInferenceCheck confirms boolean SQLi end to end via SPRT.

Against a loopback target where a tautology returns the table and a contradiction
returns nothing (stable), the check's sequential probes drive the boolean-
inference oracle to a confirmation; against a target that ignores the clause it
refutes; against a per-request-random target the dynamic-page control refuses it.
"""

from __future__ import annotations

import contextlib
import random
import secrets
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.checks import BooleanInferenceCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier


class _VulnApp(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        if "'1'='1" in q:
            body = ("id=%d\n" * 20 % tuple(range(20))).encode()
        else:
            body = b"no results"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SafeApp(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"constant page, injection ignored"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _DynamicApp(BaseHTTPRequestHandler):
    """A PURELY DYNAMIC page: a long per-request random token dominates the body, so ANY two responses
    (including two byte-identical repeats) diverge. The same-request stability control must refuse it —
    this is the autonomous-scanner regression for the boolean false-FACT defect."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = (f"<html><body>session {secrets.token_hex(64)} — no results</body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# A COARSE (low-cardinality) dynamic page: the body is one of only K=2 distinct variants chosen at RANDOM,
# INDEPENDENT of the injected clause. There is NO boolean channel — yet on the pre-fix base AND on the
# single-identical-repeat commit (59dba95e) its coincidental per-round agreement minted a FALSE boolean_sqli
# FACT a few percent of the time (the red-pen BLOCK). The determinism PRE-GATE (an up-front run of identical
# false-clause sends must be all-identical) proves the page non-deterministic and refuses it every time.
_COARSE_VARIANTS = [b"no results variant A" + b"A" * 60, b"no results variant B" + b"B" * 60]


class _CoarseApp(BaseHTTPRequestHandler):
    _rng = random.Random(1234)

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = _CoarseApp._rng.choice(_COARSE_VARIANTS)   # 1-of-K at random, independent of the clause
        self.send_response(200)
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
    with urllib.request.urlopen(req.url, timeout=10) as r:  # noqa: S310 (loopback)
        return {"status": r.status, "body": r.read().decode("utf-8", "replace")}


def _q_point(base: str):
    tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/search?q=x"))
    point = next(p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q")
    return tpl, point


def _check() -> BooleanInferenceCheck:
    return BooleanInferenceCheck(
        id="bool-sqli-sprt", bug_class="boolean_sqli",
        true_clause="x' OR '1'='1", false_clause="x' OR '1'='2",
    )


def _confirm(ctx) -> object:
    return confirm_finding(
        finding={"bug_class": "boolean_sqli"}, context=ctx, verifier=OracleVerifier(),
    )


def test_sprt_check_confirms_boolean_sqli() -> None:
    with _server(_VulnApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm(_check().probe(tpl, point, _send))
        assert confirmed is not None
        assert confirmed.confirmed_by.value == "boolean_inference"


def test_sprt_check_refutes_non_injectable_target() -> None:
    with _server(_SafeApp) as base:
        tpl, point = _q_point(base)
        assert _confirm(_check().probe(tpl, point, _send)) is None


def test_sprt_check_refutes_a_dynamic_page_autonomous_path() -> None:
    # AUTONOMOUS-PATH regression for the boolean false-FACT defect: a purely-dynamic page (varies with any
    # input) driven through BooleanInferenceCheck → confirm_finding must NOT mint a FACT. The same-request
    # stability control trips every round → the SPRT refutes → no confirmed finding.
    with _server(_DynamicApp) as base:
        tpl, point = _q_point(base)
        assert _confirm(_check().probe(tpl, point, _send)) is None


def test_sprt_check_refutes_a_coarse_dynamic_page_looped() -> None:
    # RED-PEN BLOCK regression (the COARSE class): a page whose body is one of only K=2 distinct variants
    # chosen INDEPENDENTLY of the input. It has no boolean channel, but on the pre-fix base AND on the
    # single-identical-repeat commit (59dba95e) its coincidental per-round agreement minted a FALSE FACT a few
    # percent of the runs — so this loop FAILS on both of those and passes ONLY with the determinism pre-gate.
    # Driven through the real mint path (BooleanInferenceCheck.probe → confirm_finding → OracleVerifier).
    facts = 0
    with _server(_CoarseApp) as base:
        tpl, point = _q_point(base)
        for _ in range(150):
            if _confirm(_check().probe(tpl, point, _send)) is not None:
                facts += 1
    assert facts == 0, f"a coarse K=2 input-independent page minted {facts}/150 FALSE boolean_sqli FACTs"
