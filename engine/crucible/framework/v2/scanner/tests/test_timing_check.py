"""
Wave 4 — the TimingCheck confirms a conditional sleep end to end.

Against a loopback target that sleeps only when the payload injects a delay, the
check's paired latency samples drive the timing oracle to a confirmation; against
a target that never conditionally delays, nothing fires. The oracle — a real
rank-sum test with an effect-size floor — is the authority, never a threshold.
"""

from __future__ import annotations

import contextlib
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.checks import TimingCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier


class _SleepApp(BaseHTTPRequestHandler):
    sleep_on = "SLEEP"

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        if self.sleep_on and self.sleep_on in q:
            time.sleep(0.2)  # a conditional 200ms delay — the time-based signal
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _NoSleepApp(_SleepApp):
    sleep_on = ""  # never conditionally delays


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
    points = tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
    q = next(p for p in points if p.name == "q")
    return tpl, q


def _check() -> TimingCheck:
    return TimingCheck(
        id="time-sqli", bug_class="time_based_sqli",
        benign="1", sleep_payload="1 SLEEP", injected_ms=200.0, samples=8,
    )


def test_timing_check_confirms_conditional_sleep() -> None:
    with _server(_SleepApp) as base:
        tpl, point = _q_point(base)
        ctx = _check().probe(tpl, point, _send)
        confirmed = confirm_finding(
            finding={"bug_class": "time_based_sqli"}, context=ctx, verifier=OracleVerifier(),
        )
        assert confirmed is not None
        assert confirmed.confirmed_by.value == "timing"


def test_timing_check_does_not_fire_without_conditional_delay() -> None:
    with _server(_NoSleepApp) as base:
        tpl, point = _q_point(base)
        ctx = _check().probe(tpl, point, _send)
        confirmed = confirm_finding(
            finding={"bug_class": "time_based_sqli"}, context=ctx, verifier=OracleVerifier(),
        )
        assert confirmed is None
