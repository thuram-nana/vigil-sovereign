"""
Single-packet race engine — driven against a REAL loopback target that carries
an intentional TOCTOU bug.

The vulnerable endpoint models a single-use coupon guarded by a NON-atomic
read-modify-write: it reads `redeemed`, sleeps briefly (the check-then-act
window), then sets it. Under a synchronised burst every request reads
`redeemed == False` before any has written, so the coupon is redeemed more than
once. The locked twin wraps the same read-modify-write in a `threading.Lock`, so
exactly one request wins no matter the concurrency.

The engine must confirm the over-redemption on the naive endpoint and return
None on the locked one. The verdict is count-based (successes > limit), so it is
deterministic — not a timing measurement.
"""

from __future__ import annotations

import contextlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.race import (
    RaceResult,
    race_burst,
    race_check,
    raw_race,
)


# ---------------------------------------------------------------------------
# A deliberately-racy coupon target, and its correctly-locked twin
# ---------------------------------------------------------------------------


class _CouponState:
    """One single-use coupon. `naive_redeem` has a TOCTOU window; `locked_redeem`
    closes it with a lock. Both increment `redemptions` on a win so the test can
    read the ground truth directly, independent of the engine's own count."""

    def __init__(self, window_s: float = 0.10) -> None:
        self.redeemed = False
        self.redemptions = 0
        self.window_s = window_s
        self._lock = threading.Lock()

    def naive_redeem(self) -> bool:
        # check ...
        if self.redeemed:
            return False
        # ... then a window where concurrent requests slip through ...
        time.sleep(self.window_s)
        # ... then act (too late to be atomic).
        self.redeemed = True
        self.redemptions += 1
        return True

    def locked_redeem(self) -> bool:
        with self._lock:
            if self.redeemed:
                return False
            time.sleep(self.window_s)
            self.redeemed = True
            self.redemptions += 1
            return True


def _make_handler(state: _CouponState, atomic: bool) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # keep the test quiet
            return

        def _drain_body(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)

        def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
            self._drain_body()
            won = state.locked_redeem() if atomic else state.naive_redeem()
            if won:
                status, payload = 200, b"redeemed"
            else:
                status, payload = 409, b"already redeemed"
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return _Handler


@contextlib.contextmanager
def _server(state: _CouponState, *, atomic: bool) -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state, atomic))
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_naive_coupon_is_over_redeemed_and_confirmed() -> None:
    state = _CouponState(window_s=0.10)
    with _server(state, atomic=False) as base_url:
        confirmed = race_check(base_url, "/redeem", count=8, max_allowed=1)

    # Ground truth on the server: the coupon was redeemed more than once.
    assert state.redemptions > 1, "test target failed to exhibit the race"

    assert confirmed is not None
    assert confirmed.confirmed is True
    assert confirmed.bug_class == "request_race"
    assert confirmed.confirmed_by.value == "achieved_state"
    assert confirmed.confidence >= 0.7


def test_locked_coupon_is_not_flagged() -> None:
    state = _CouponState(window_s=0.10)
    with _server(state, atomic=True) as base_url:
        confirmed = race_check(base_url, "/redeem", count=8, max_allowed=1)

    # Exactly one request wins against the lock — no over-redemption.
    assert state.redemptions == 1
    assert confirmed is None


def test_race_burst_reports_counts_without_confirming() -> None:
    state = _CouponState(window_s=0.10)
    with _server(state, atomic=False) as base_url:
        result = race_burst(base_url, "/redeem", count=6, max_allowed=1)

    assert isinstance(result, RaceResult)
    assert result.count == 6
    assert result.successes == state.redemptions
    assert result.successes > 1
    assert result.over_run is True
    assert result.statuses.count(200) == result.successes


def test_raw_race_last_byte_sync_delivers_all_requests() -> None:
    # Every connection must actually complete: N successes on the naive endpoint
    # equals N 200s here only if all N won, but at minimum all N get a parseable
    # HTTP status back (200 winners + 409 losers), proving the burst delivered.
    state = _CouponState(window_s=0.05)
    with _server(state, atomic=True) as base_url:
        import urllib.parse

        parts = urllib.parse.urlsplit(base_url)
        req = (
            f"POST /redeem HTTP/1.1\r\nHost: {parts.hostname}:{parts.port}\r\n"
            f"Content-Length: 0\r\nConnection: close\r\n\r\n"
        ).encode("latin-1")
        outcomes = raw_race(parts.hostname, parts.port, req, 5, timeout=5.0)

    assert len(outcomes) == 5
    statuses = [s for s, _, _ in outcomes]
    assert all(s in (200, 409) for s in statuses)
    # Locked endpoint: exactly one winner across the burst.
    assert statuses.count(200) == 1
    assert state.redemptions == 1


def test_success_predicate_is_honoured() -> None:
    # A custom predicate keys off the body marker instead of the status code.
    state = _CouponState(window_s=0.10)
    with _server(state, atomic=False) as base_url:
        confirmed = race_check(
            base_url,
            "/redeem",
            count=8,
            max_allowed=1,
            success_predicate=lambda status, body: b"redeemed" == body,
        )
    assert confirmed is not None
    assert confirmed.bug_class == "request_race"
