"""
Wave 1 — the autonomous campaign drives the full arsenal, not just the 9
default point-checks: request-level checks (CORS/host-header/JWT/GraphQL) run
once per host, a self-learning bandit orders effort and persists across runs,
and static DOM-XSS leads are surfaced (as candidates, never confirmed).

Everything is oracle-confirmed against a local fixture and its safe twin, so the
prove-don't-guess property holds: the CORS finding appears only when the fixture
actually reflects a hostile origin with credentials.
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner import cli as scanner_cli
from framework.v2.scanner.campaign import WebScanCampaign
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.learning import ContextualBandit


class _VulnApp(BaseHTTPRequestHandler):
    """A deliberately-vulnerable local fixture: reflects a hostile Origin with
    credentials (CORS), diverges on a SQL tautology (boolean SQLi), reflects raw
    input (XSS/reflection), and ships an inline DOM-XSS source->sink flow."""

    reflect_origin = True

    def log_message(self, *a: object) -> None:
        return

    def _cors(self) -> None:
        origin = self.headers.get("Origin")
        if origin and self.reflect_origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path == "/":
            body = (
                b'<html><a href="/search?q=hi">search</a>'
                b"<script>var x=location.hash;document.write(x)</script></html>"
            )
        elif parts.path == "/search":
            q = parse_qs(parts.query).get("q", [""])[0]
            # boolean differential: a tautology dumps the whole table (a large,
            # unmistakable divergence); q is also reflected raw, so a planted
            # marker surfaces in the sink (reflection/XSS side-effect).
            dump = "".join(f"user{i}:secret{i}\n" for i in range(40)) if (
                "'1'='1" in q or "1=1" in q) else ""
            body = f"<html>echo:{q}\n{dump}</html>".encode()
        else:
            body = b"not found"
        self.send_response(200)
        self._cors()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SafeApp(_VulnApp):
    """Same app, but a properly-scoped CORS policy (never reflects the origin)."""

    reflect_origin = False


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


def test_arsenal_confirms_multiple_oracle_kinds_including_request_level() -> None:
    with _server(_VulnApp) as base:
        bandit = ContextualBandit()
        # OOB off so the blind checks don't each poll for 2s against a fixture
        # that never calls back — this test targets the visible-signal classes.
        report = WebScanCampaign(
            loopback_send, bandit=bandit, max_pages=10, enable_oob=False,
        ).run(base + "/")

        classes = {f.bug_class for f in report.active_findings}
        kinds = {f.confirmed_by for f in report.active_findings}
        # the request-level CORS check fired (its evidence: reflected evil origin)
        assert "cors" in classes, classes
        # at least three DISTINCT oracle kinds confirmed something
        assert len(kinds) >= 3, kinds
        # the bandit learned from real outcomes: a class that landed a confirmed
        # hit has alpha>1 (a reward folded in). alpha = mean*(observations+2),
        # recovered from the public posterior view.
        def _alpha(arm: str) -> float:
            return bandit.expected_value("default", arm) * (bandit.observations("default", arm) + 2.0)
        assert any(_alpha(c) > 1.0 for c in ("xss", "boolean_sqli")), \
            {c: (_alpha(c), bandit.observations("default", c)) for c in ("xss", "boolean_sqli")}


def test_bandit_persists_and_warm_starts(tmp_path) -> None:
    bfile = tmp_path / "bandit.json"
    with _server(_VulnApp) as base:
        WebScanCampaign(loopback_send, bandit_path=bfile, max_pages=10, enable_oob=False).run(base + "/")
        assert bfile.is_file(), "bandit was not persisted"
        loaded = ContextualBandit.load(bfile)
        assert loaded.arms("default"), "no posteriors persisted"
        assert any(loaded.observations("default", a) >= 1 for a in loaded.arms("default"))
        # a second run warm-starts from the file and re-persists without error
        WebScanCampaign(loopback_send, bandit_path=bfile, max_pages=10, enable_oob=False).run(base + "/")
        assert bfile.is_file()


def test_cors_does_not_fire_on_safe_twin() -> None:
    with _server(_SafeApp) as base:
        report = WebScanCampaign(loopback_send, max_pages=10, enable_oob=False).run(base + "/")
        assert not any(f.bug_class == "cors" for f in report.active_findings), \
            "CORS confirmed against a properly-scoped policy (false positive)"


def test_domxss_opt_in_surfaces_leads_only_when_enabled() -> None:
    with _server(_VulnApp) as base:
        off = WebScanCampaign(loopback_send, max_pages=10, enable_oob=False).run(base + "/")
        assert off.dom_xss_candidates == [], "DOM-XSS leads leaked without opt-in"
        on = WebScanCampaign(
            loopback_send, max_pages=10, enable_oob=False, enable_domxss=True,
        ).run(base + "/")
        assert any(c.sink == "document.write" for c in on.dom_xss_candidates)
        # leads are candidates, never mixed into oracle-confirmed active findings
        assert all(f.bug_class != "dom_xss" for f in on.active_findings)


def test_scan_cli_refuses_remote_targets() -> None:
    # a remote host is refused BEFORE any traffic — the gate is a pure host check
    assert scanner_cli.main(["https://example.com/"]) == 2
    assert scanner_cli.main(["http://10.0.0.5/"]) == 2
