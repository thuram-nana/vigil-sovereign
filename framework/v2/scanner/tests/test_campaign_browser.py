"""
M4 integration — the dynamic browser passes wired into the scan loop.

A library-free campaign with `enable_browser_xss`/`enable_spa_crawl` runs a real
headless browser over the crawled surface: DOM-XSS is confirmed by EXECUTION (and
lands in active_findings with a dom_execution certificate), and the SPA crawler's
fetch/XHR endpoints are surfaced. Skip-gated on Chromium; loopback only.
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

from framework.v2.scanner.campaign import WebScanCampaign
from framework.v2.scanner.cdp import cdp_available
from framework.v2.scanner.cli import loopback_send
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

pytestmark = pytest.mark.skipif(not cdp_available(), reason="no Chromium/Chrome for the CDP driver")


class _DomXssApp(BaseHTTPRequestHandler):
    """Home page links to a search page whose `q` flows into innerHTML (DOM-XSS),
    and which also fires a fetch to an API endpoint on load (SPA surface)."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/":
            body = b'<a href="/search?q=hi">search</a>'
        elif path == "/search":
            body = (
                b"<div id=o></div><script>"
                b"fetch('/api/items');"
                b"document.getElementById('o').innerHTML="
                b"new URLSearchParams(location.search).get('q')||'';"
                b"</script>"
            )
        else:
            body = b"{}"
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


def test_campaign_browser_xss_confirms_by_execution_and_captures_spa_endpoints() -> None:
    with _server(_DomXssApp) as base:
        report = WebScanCampaign(
            loopback_send, max_pages=5, enable_oob=False,
            enable_browser_xss=True, enable_spa_crawl=True,
        ).run(base + "/")

        # DOM-XSS confirmed by execution, in active_findings, with a re-verifiable cert
        dom = [f for f in report.active_findings if f.bug_class == "dom_xss"]
        assert dom, "browser pass did not confirm the DOM-XSS by execution"
        f = dom[0]
        assert f.confirmed_by == "dom_execution" and f.oracle_context is not None
        ctx = FindingContext.model_validate(f.oracle_context)
        assert confirm_finding(
            finding={"bug_class": "dom_xss", "title": "t", "severity": "High", "surface": "s", "summary": "x"},
            context=ctx, verifier=OracleVerifier()) is not None

        # the SPA crawler surfaced the fetch('/api/items') endpoint
        assert any("/api/items" in ep for ep in report.discovered_endpoints)


def test_campaign_browser_off_by_default() -> None:
    with _server(_DomXssApp) as base:
        report = WebScanCampaign(loopback_send, max_pages=5, enable_oob=False).run(base + "/")
        assert report.discovered_endpoints == []
        assert not any(f.confirmed_by == "dom_execution" for f in report.active_findings)
