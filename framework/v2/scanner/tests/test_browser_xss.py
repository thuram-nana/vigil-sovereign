"""
DOM-XSS confirmed by EXECUTION in a real headless browser (CDP). Skip-gated on a
Chromium/Chrome binary being present — a browser check never guesses, so with no
browser there is simply nothing to run.

The vulnerable fixture flows a query parameter into ``innerHTML`` unsanitised; the
execution payload's event handler fires and calls the driver's binding, so the
dom-execution oracle confirms. The safe twin uses ``textContent`` — no execution,
no finding (the precision guarantee).
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from framework.v2.scanner.browser_xss import confirm_dom_xss
from framework.v2.scanner.cdp import CdpBrowser, cdp_available
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

pytestmark = pytest.mark.skipif(not cdp_available(), reason="no Chromium/Chrome for the CDP driver")


class _VulnDom(BaseHTTPRequestHandler):
    sink = "innerHTML"

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = (
            f"<div id=o></div><script>document.getElementById('o').{self.sink}="
            "new URLSearchParams(location.search).get('q')||''</script>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SafeDom(_VulnDom):
    sink = "textContent"  # inert sink — the payload is shown as text, never executes


@contextlib.contextmanager
def _serve(handler) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


@pytest.fixture(scope="module")
def browser() -> Iterator[CdpBrowser]:
    with CdpBrowser() as br:
        yield br


def test_dom_xss_confirmed_by_execution(browser: CdpBrowser) -> None:
    with _serve(_VulnDom) as base:
        results = confirm_dom_xss(base, param="q", browser=browser)
        executed = [r for r in results if r.executed]
        assert executed, "no execution payload ran against a genuinely DOM-XSS-vulnerable sink"
        # the execution certificate independently re-confirms via the oracle
        confirmed = confirm_finding(
            finding={"bug_class": "dom_xss", "title": "t", "severity": "High",
                     "surface": "s", "summary": "x"},
            context=executed[0].context, verifier=OracleVerifier(),
        )
        assert confirmed is not None and confirmed.confirmed_by.value == "dom_execution"


def test_no_execution_on_safe_sink(browser: CdpBrowser) -> None:
    with _serve(_SafeDom) as base:
        results = confirm_dom_xss(base, param="q", browser=browser)
        assert not any(r.executed for r in results), "textContent sink must not execute the payload"
