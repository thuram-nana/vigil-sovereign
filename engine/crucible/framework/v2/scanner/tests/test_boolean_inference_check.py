"""
Wave 5 — BooleanInferenceCheck confirms boolean SQLi end to end via an SPRT whose per-round
signal is a TRUTH-VALUE ATTRIBUTION test.

Against a loopback target that really EVALUATES the injected comparison (a tautology returns the
table, a contradiction returns nothing) the check's varied always-true / always-false clauses
split cleanly by truth value and the oracle confirms. Against a target that ignores the clause it
refutes. Against pages whose body varies INDEPENDENTLY of the input — per-request random, coarse
uniform 1-of-K, and the SKEWED 1-of-K that defeated a determinism pre-gate — it must never mint.
"""

from __future__ import annotations

import contextlib
import random
import re
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

# K_T = K_F = 4 DISTINCT, syntactically-VARIED clauses per truth value, all in ONE breakout shape.
_TRUE_CLAUSES = ("x' OR '1'='1", "x' OR '7'='7", "x' OR 'ab'='ab", "x' OR 'q9'='q9")
_FALSE_CLAUSES = ("x' OR '1'='2", "x' OR '7'='8", "x' OR 'ab'='ac", "x' OR 'q9'='q8")

_CMP = re.compile(r"(?:OR|AND)\s+(.+?)\s*=\s*(.+?)\s*(?:--.*)?$", re.I)


def _clause_is_true(q: str) -> bool:
    """A stand-in for the origin's DB EVALUATING the injected comparison — so the app answers the
    clause's TRUTH VALUE, not a hard-coded payload string. Any of the varied always-true clauses
    yields the rows page; any always-false clause yields "no results"."""
    m = _CMP.search(q)
    if not m:
        return False
    a, b = (x.strip().strip("'\"") for x in m.groups())
    return a == b


class _VulnApp(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = ("id=%d\n" * 20 % tuple(range(20))).encode() if _clause_is_true(q) else b"no results"
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
    """A PURELY DYNAMIC page: a long per-request random token dominates the body, so ANY two
    responses (including two byte-identical repeats) diverge."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = (f"<html><body>session {secrets.token_hex(64)} — no results</body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# An INPUT-INDEPENDENT page: the body is one of only K=2 distinct variants, chosen at random with
# NO dependence on the injected clause. There is no boolean channel, so every FACT here is FALSE.
_VARIANTS = [b"no results variant A" + b"A" * 60, b"no results variant B" + b"B" * 60]


class _CoarseApp(BaseHTTPRequestHandler):
    """UNIFORM 1-of-2 (p = 0.5)."""

    _rng = random.Random(1234)

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = _CoarseApp._rng.choice(_VARIANTS)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SkewedApp(BaseHTTPRequestHandler):
    """SKEWED 1-of-2 (dominant variant p = 0.9) — THE red-pen BLOCK class.

    A 16-sample identical-request determinism pre-gate passes ~0.9**16 ≈ 19% of the time on this
    page, and INSIDE that self-consistent window the "true" probe coincidentally draws the rare
    variant while the "false" probes stay dominant — so on every pre-fix commit (a97e982e,
    59dba95e and the determinism-gate commit 70c6b95a) the within-pair + stability controls all
    hold and the SPRT CONFIRMS a boolean_sqli FACT on a page with no boolean channel.

    Truth-value attribution kills it: with 3 distinct clauses per truth value each sent twice, a
    clean 2-cluster split needs all 6 true-side draws to be one variant and all 6 false-side draws
    the other — 2 * 0.9**6 * 0.1**6 ≈ 1.1e-6 per round.
    """

    _rng = random.Random(97531)

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = _SkewedApp._rng.choices(_VARIANTS, weights=[0.9, 0.1], k=1)[0]
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
    try:
        return BooleanInferenceCheck(
            id="bool-sqli-sprt", bug_class="boolean_sqli",
            true_clauses=_TRUE_CLAUSES, false_clauses=_FALSE_CLAUSES,
        )
    except TypeError:  # pragma: no cover - see the note below
        # DELIBERATE pre-fix compatibility shim, and the only reason it exists: the skewed
        # regression below is the falsifiability claim for this fix, so it must be RUNNABLE
        # against a97e982e / 59dba95e / 70c6b95a (which take a single clause per truth value) and
        # FAIL there for the RIGHT reason — a real false FACT — rather than erroring on the
        # constructor. On this tree the multi-clause path above always succeeds.
        return BooleanInferenceCheck(
            id="bool-sqli-sprt", bug_class="boolean_sqli",
            true_clause=_TRUE_CLAUSES[0], false_clause=_FALSE_CLAUSES[0],
        )


def _confirm(ctx) -> object:
    return confirm_finding(
        finding={"bug_class": "boolean_sqli"}, context=ctx, verifier=OracleVerifier(),
    )


def _false_facts(handler: type[BaseHTTPRequestHandler], loops: int) -> int:
    facts = 0
    with _server(handler) as base:
        tpl, point = _q_point(base)
        for _ in range(loops):
            if _confirm(_check().probe(tpl, point, _send)) is not None:
                facts += 1
    return facts


def test_sprt_check_confirms_boolean_sqli() -> None:
    # THE TRUE POSITIVE: an origin that really evaluates the clause. Every varied always-true
    # clause lands on the rows page, every always-false clause on "no results" — a clean
    # 2-cluster split by TRUTH VALUE, so the FACT still mints.
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
    # a purely-dynamic page (a per-request token) hard-refutes on the byte-identical repeats
    assert _false_facts(_DynamicApp, 5) == 0


def test_sprt_check_refutes_a_uniform_coarse_page_looped() -> None:
    # UNIFORM 1-of-2, input-independent. Kept as the cheap companion to the skewed loop below —
    # the red-pen showed this cell alone CANNOT catch the skewed class: it is 18/150 on a97e982e and
    # 5/150 on 59dba95e, but already 0/150 on 70c6b95a, which still mints on the skewed page.
    facts = _false_facts(_CoarseApp, 150)
    assert facts == 0, f"a uniform coarse K=2 page minted {facts}/150 FALSE boolean_sqli FACTs"


def test_sprt_check_refutes_a_skewed_input_independent_page_looped() -> None:
    # THE red-pen BLOCK regression, through the REAL mint path (BooleanInferenceCheck.probe →
    # confirm_finding → OracleVerifier). A SKEWED (p = 0.9) input-independent K=2 page minted
    # FALSE FACTs on a97e982e, 59dba95e AND 70c6b95a — the 16-sample determinism pre-gate passes
    # ~0.9**16 ≈ 19% of the time on it, and the coincidence lives INSIDE that self-consistent window.
    # The page RNG is SEEDED, so the outcome is deterministic per commit; this loop is sized so all
    # three fail it: measured 37/3000 on a97e982e, 24/3000 on 59dba95e, 3/3000 on 70c6b95a — and 0
    # here. (70c6b95a's own rate is only ~1.3e-3, so its margin is the thin one; the direct
    # Monte-Carlo sweep over p 0.5-0.95 x variant-count 2-4 at 5000 trials/cell is the wider evidence.)
    loops = 3000
    facts = _false_facts(_SkewedApp, loops)
    assert facts == 0, (
        f"a SKEWED (p=0.9) K=2 input-independent page minted {facts}/{loops} FALSE boolean_sqli "
        "FACTs — the response is not a function of the injected truth value")
