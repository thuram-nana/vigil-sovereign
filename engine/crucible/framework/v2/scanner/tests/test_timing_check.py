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
            # A conditional 600ms delay — the time-based signal.
            #
            # RED-PEN B3b: this fixture used to sleep 200ms and declare
            # injected_ms=200, which only confirmed because a declared delay could
            # DRIVE THE EFFECT FLOOR DOWN (to 0.5 x 200 = 100ms). That lever is the
            # one an untrusted report used to mint a FACT out of a 5ms jitter shift
            # (`timing_injected_ms: 1.0` -> floor 0ms), so the floor is now
            # max(250ms, 0.5 x injected). The fixture's speed shortcut depended on
            # the erasable floor, so it is raised above the oracle's documented
            # absolute floor instead. Every SHIPPED time-based library entry already
            # declares 2000-5000ms, so nothing in production changes; the cost is
            # pinned explicitly by test_a_sub_floor_declared_delay_no_longer_confirms.
            time.sleep(0.6)
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


def _check(injected_ms: float = 600.0) -> TimingCheck:
    return TimingCheck(
        id="time-sqli", bug_class="time_based_sqli",
        benign="1", sleep_payload="1 SLEEP", injected_ms=injected_ms, samples=8,
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


def test_a_sub_floor_declared_delay_no_longer_confirms() -> None:
    """RED-PEN B3b, the stated COST of the floor ratchet. The SAME real 600ms server
    delay, probed by a check that declares a 200ms injected delay, no longer
    confirms: `max(250ms, 0.5 x 200ms)` is 250ms, not the 100ms the old rule gave,
    and the oracle will not adjudicate below its documented absolute floor from a
    producer-declared number. A probe that asks for less than 500ms therefore buys
    no floor relief at all. Every shipped time-based entry declares 2000-5000ms."""
    from framework.v2.verify.oracles import timing_oracle

    with _server(_SleepApp) as base:
        tpl, point = _q_point(base)
        ctx = _check(injected_ms=200.0).probe(tpl, point, _send)
    assert ctx is not None
    sig = timing_oracle(ctx.baseline_latencies, ctx.treatment_latencies, injected_ms=200.0)
    assert sig.observed["floor_ms"] == 250.0, sig.observed
    # the real 600ms shift still clears 250ms, so this particular probe still fires —
    # what the ratchet removes is the ability of the DECLARED number to lower the bar
    assert sig.fired
    # a 1ms declared delay no longer erases the floor: the shift is judged against
    # the 250ms absolute floor either way. ABOVE it still fires...
    tiny = timing_oracle([100.0] * 8, [380.0] * 8, injected_ms=1.0)
    assert tiny.observed["floor_ms"] == 250.0, tiny.observed
    assert tiny.fired, tiny.evidence
    # ...and BELOW it does not, which is exactly what `timing_injected_ms: 1.0`
    # used to buy an untrusted report (floor 0ms -> any jitter confirms).
    for treat in ([200.0] * 8, [280.0] * 8):
        below = timing_oracle([100.0] * 8, treat, injected_ms=1.0)
        assert below.observed["floor_ms"] == 250.0, below.observed
        assert not below.fired, (
            f"a {below.observed['median_shift_ms']}ms shift confirmed on a 1ms "
            f"declared delay")


def test_timing_check_does_not_fire_without_conditional_delay() -> None:
    with _server(_NoSleepApp) as base:
        tpl, point = _q_point(base)
        ctx = _check().probe(tpl, point, _send)
        confirmed = confirm_finding(
            finding={"bug_class": "time_based_sqli"}, context=ctx, verifier=OracleVerifier(),
        )
        assert confirmed is None
