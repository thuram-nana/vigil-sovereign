"""
Integration of the advanced pillars into the live loop: the bandit learns inside
the audit engine, the quantum-inspired annealer picks the path portfolio in the
orchestrator, and the self-improvement loop turns a gap into a governance-gated
proposal.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.checks import DEFAULT_CHECKS
from framework.v2.scanner.engine import AuditFinding, AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind
from framework.v2.scanner.learning import ContextualBandit
from framework.v2.scanner.orchestrator import AutonomousCampaign
from framework.v2.scanner.self_improve import MergeGate, Verdict, analyze_gaps, draft_proposals


# ---------------------------------------------------------------------------
# ① the bandit learns inside the audit engine
# ---------------------------------------------------------------------------


class _SqliOnly(BaseHTTPRequestHandler):
    """A boolean-SQLi differential on `q` that does NOT echo input, so only the
    differential (boolean_sqli) check confirms — the reflection checks miss."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("q", [""])[0]
        rows = "id=1\nid=2\nid=3\nid=4\nid=5" if ("'1'='1" in q or "1=1" in q) else "none"
        body = f"results:\n{rows}".encode()  # deliberately does NOT reflect q
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
    with urllib.request.urlopen(req.url, timeout=5) as resp:  # noqa: S310 (loopback)
        return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}


def test_bandit_learns_which_class_confirms_inside_the_engine() -> None:
    with _server(_SqliOnly) as base:
        bandit = ContextualBandit()
        engine = AuditEngine(_send, bandit=bandit, bandit_context="sqli-app")
        req = HttpRequest(method="GET", url=f"{base}/search?q=hello")
        engine.audit(req, checks=DEFAULT_CHECKS, insertion_kinds=(InsertionKind.QUERY_VALUE,))

        # boolean_sqli confirmed (reward True); the reflection classes missed (False)
        ev_sqli = bandit.expected_value("sqli-app", "boolean_sqli")
        ev_xss = bandit.expected_value("sqli-app", "xss")
        assert ev_sqli > ev_xss, (ev_sqli, ev_xss)
        assert bandit.rank("sqli-app", ["xss", "boolean_sqli", "path_traversal"])[0] == "boolean_sqli"


# ---------------------------------------------------------------------------
# ② the annealer picks the stealthy path portfolio in the orchestrator
# ---------------------------------------------------------------------------


def _finding(bug_class: str, param: str, confirmed_by: str) -> AuditFinding:
    return AuditFinding(check_id=bug_class, bug_class=bug_class, insertion_point=f"query_value:{param}",
                        param=param, confidence=0.9, confirmed_by=confirmed_by)


def test_orchestrator_returns_annealed_path_portfolio() -> None:
    report = ScanReport(target="http://t/", active_findings=[
        _finding("ssrf", "url", "oob_callback"),
        _finding("idor", "id", "achieved_state"),
    ])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""},
                                detection_budget=2.0).chain_findings(report)

    assert result.attack_paths, "no attack paths to select from"
    assert result.path_portfolio, "annealer returned an empty portfolio"
    # the portfolio is a real subset of the paths and fits the detection budget
    assert all(p in result.attack_paths for p in result.path_portfolio)
    assert sum(p.detection_cost for p in result.path_portfolio) <= 2.0 + 1e-9


# ---------------------------------------------------------------------------
# ③ the self-improvement loop: gap -> proposal -> governance gate
# ---------------------------------------------------------------------------


def test_self_improvement_gap_to_gated_proposal() -> None:
    # a routed bug class with no producing check is a real gap the loop should find
    gaps = analyze_gaps(checks=DEFAULT_CHECKS)
    assert gaps, "no capability gaps found against the shipped check set"
    proposals = draft_proposals(gaps)
    assert proposals, "no proposals drafted for the gaps"

    prop = proposals[0]
    gate = MergeGate()
    # rejected without sign-off or with red eval; approved only when both hold
    assert gate.evaluate(prop, eval_green=True, approvals=0, threshold=2).verdict == Verdict.REJECTED
    assert gate.evaluate(prop, eval_green=False, approvals=5, threshold=2).verdict == Verdict.REJECTED
    assert gate.evaluate(prop, eval_green=True, approvals=2, threshold=2).verdict == Verdict.APPROVED

    # the module never self-applies: there is no writer/apply entry point
    import framework.v2.scanner.self_improve as si
    assert not any(n for n in dir(si) if n.lower() in ("apply", "apply_proposal", "write_check"))
