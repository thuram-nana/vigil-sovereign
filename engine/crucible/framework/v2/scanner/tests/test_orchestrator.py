"""
Autonomous chaining — the scanner confirms an SSRF, and the platform reasons
forward from it: server-side fetch ⇒ (via the technique operators) the endpoint
can reach an internal-only cloud-metadata resource. One run, oracle-confirmed
finding + a sound derived escalation over the world-model.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.insertion import HttpRequest, InsertionKind
from framework.v2.scanner.orchestrator import AutonomousCampaign
from framework.v2.worldmodel.models import EdgeKind


def _finding(bug_class: str, param: str, confirmed_by: str) -> AuditFinding:
    return AuditFinding(check_id=bug_class, bug_class=bug_class, insertion_point=f"query_value:{param}",
                        param=param, confidence=0.9, confirmed_by=confirmed_by)


def test_chain_findings_builds_multihop_attack_paths() -> None:
    # Fast, deterministic: feed confirmed findings straight to the reasoning stage.
    report = ScanReport(target="http://t/", active_findings=[
        _finding("ssrf", "url", "oob_callback"),
        _finding("idor", "id", "achieved_state"),
    ])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)

    all_paths = [p.describe() for p in result.attack_paths]

    # SSRF chained: attacker -> endpoint:url -> an internal resource (2 hops), via the operator
    ssrf_paths = [p for p in result.attack_paths
                  if p.destination.startswith("internal:")
                  and any(s.technique == "ssrf-internal-reach" for s in p.steps)]
    assert ssrf_paths and ssrf_paths[0].hops >= 2, all_paths
    assert ssrf_paths[0].steps[0].src == "attacker:self"
    assert "endpoint:url" in {s.src for s in ssrf_paths[0].steps} | {s.dst for s in ssrf_paths[0].steps}

    # IDOR chained: attacker -> endpoint:id -> a backing datastore (2 hops), via the operator
    idor_paths = [p for p in result.attack_paths
                  if p.destination.startswith("datastore:")
                  and any(s.technique == "unauth-endpoint-read" for s in p.steps)]
    assert idor_paths and idor_paths[0].hops >= 2, all_paths

    # both crown-jewel classes were reached from the same run
    dests = {p.destination for p in result.attack_paths}
    assert any(d.startswith("internal:") for d in dests) and any(d.startswith("datastore:") for d in dests)


class _SsrfApp(BaseHTTPRequestHandler):
    """`/fetch?url=` performs a real server-side fetch of the parameter — the SSRF.
    The index links to it so the crawler discovers the surface."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        sp = urllib.parse.urlsplit(self.path)
        if sp.path == "/":
            body = b'<html><body><a href="/fetch?url=probe">fetch</a></body></html>'
        elif sp.path == "/fetch":
            url = urllib.parse.parse_qs(sp.query).get("url", [""])[0]
            if url and url != "probe":
                with contextlib.suppress(Exception):
                    urllib.request.urlopen(url, timeout=3).read()  # SSRF: fetch attacker URL
            body = b"fetched"
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SsrfApp)
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
    with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 (loopback)
        return {"status": resp.status, "headers": list(resp.headers.items()),
                "body": resp.read().decode("utf-8", "replace")}


def test_leaked_credential_chains_via_extended_operators_to_a_grant() -> None:
    # A passive private-key disclosure feeds the extended catalog: the leaked
    # credential is captured and, via role-assumption, grants over a crown jewel.
    from framework.v2.scanner.passive import PassiveFinding
    report = ScanReport(target="http://t/", passive_findings=[
        PassiveFinding(check_id="info-private-key", title="Private key disclosed",
                       severity="High", confidence="Certain", url="http://t/backup.pem",
                       evidence="-----BEGIN RSA PRIVATE KEY-----"),
    ])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)

    techniques = {c.technique for c in result.chained_conclusions}
    assert "credential-leak-capture" in techniques, techniques
    assert "role-assumption" in techniques, techniques

    grant_paths = [p for p in result.attack_paths if p.destination.startswith("internal:")]
    assert grant_paths, [p.describe() for p in result.attack_paths]

    # detection cost is populated and paths are sorted stealthiest-first
    costs = [p.detection_cost for p in result.attack_paths]
    assert costs == sorted(costs) and all(0.0 <= c <= 1.0 for c in costs)


def test_autonomous_campaign_confirms_ssrf_and_chains_to_internal_reach() -> None:
    with _server() as base:
        result = AutonomousCampaign(
            _send, insertion_kinds=(InsertionKind.QUERY_VALUE,),
        ).run(base + "/")

        # 1. the SSRF itself is oracle-confirmed (out-of-band callback fired)
        ssrf = [f for f in result.scan_report.active_findings if f.bug_class == "ssrf"]
        assert ssrf, f"SSRF not confirmed: {[f.bug_class for f in result.scan_report.active_findings]}"
        assert ssrf[0].confirmed_by == "oob_callback"

        # 2. the platform CHAINED it: an operator derived internal reach from the finding
        internal = [c for c in result.chained_conclusions
                    if c.technique == "ssrf-internal-reach" and c.dst.startswith("internal:")]
        assert internal, f"SSRF was not chained to internal reach: {[c.describe() for c in result.chained_conclusions]}"

        # 3. the escalation is in the attack graph as a real derived edge
        assert result.world is not None
        reach = [e for e in result.world.edges_of_kind(EdgeKind.REACHABLE_FROM)
                 if e.dst.startswith("internal:") and e.provenance.startswith("operator:")]
        assert reach, "no operator-derived REACHABLE_FROM edge to an internal resource"
        assert reach[0].src.startswith("endpoint:")
