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
from pathlib import Path
from typing import Iterator

import pytest

from framework.v2.common import paths as _paths
from framework.v2.common.errors import SovereigntyViolation
from framework.v2.scanner.race import (
    RaceResult,
    race_burst,
    race_check,
    raw_race,
)

# A signed loopback charter for the race tests: the raw-socket burst is now re-gated through
# validate_action (Wave-4.4), so every burst is authorized against a signed charter naming
# 127.0.0.1 in scope. This slug is materialised by the ``race_slug`` fixture below.
_RACE_SLUG = "race-loopback-test"

_LOOPBACK_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Loopback race test target | Yes |
| `localhost` | Loopback race test target | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def race_slug(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Materialise a signed loopback charter for ``_RACE_SLUG`` and point ``paths`` at it, so
    the Wave-4.4 raw_race gate (validate_action over 127.0.0.1) authorizes the burst."""
    targets_root = tmp_path / "targets"
    td = targets_root / _RACE_SLUG
    td.mkdir(parents=True)
    (td / "charter.md").write_text(_LOOPBACK_CHARTER.format(slug=_RACE_SLUG), encoding="utf-8")
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    return _RACE_SLUG


def _allow_loopback(url: str) -> bool:
    """A minimal fail-closed gate for the direct raw_race test: loopback only."""
    import urllib.parse as _u
    return (_u.urlsplit(url).hostname or "") in {"127.0.0.1", "localhost", "::1"}


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


def test_naive_coupon_is_over_redeemed_and_confirmed(race_slug: str) -> None:
    state = _CouponState(window_s=0.10)
    with _server(state, atomic=False) as base_url:
        confirmed = race_check(base_url, "/redeem", count=8, max_allowed=1, slug=race_slug)

    # Ground truth on the server: the coupon was redeemed more than once.
    assert state.redemptions > 1, "test target failed to exhibit the race"

    assert confirmed is not None
    assert confirmed.confirmed is True
    assert confirmed.bug_class == "request_race"
    assert confirmed.confirmed_by.value == "achieved_state"
    assert confirmed.confidence >= 0.7
    # A12: the count-invariant oracle fired (successes > max_allowed), but WITHOUT a semantic success
    # predicate a 2xx count cannot prove a real over-consumption vs a benignly-idempotent endpoint — so it is
    # an honest LEAD (Low / UNCONFIRMED), not a High confirmed exploit.
    assert confirmed.severity == "Low"
    assert "UNCONFIRMED" in confirmed.title


def test_locked_coupon_is_not_flagged(race_slug: str) -> None:
    state = _CouponState(window_s=0.10)
    with _server(state, atomic=True) as base_url:
        confirmed = race_check(base_url, "/redeem", count=8, max_allowed=1, slug=race_slug)

    # Exactly one request wins against the lock — no over-redemption.
    assert state.redemptions == 1
    assert confirmed is None


def test_race_burst_reports_counts_without_confirming(race_slug: str) -> None:
    state = _CouponState(window_s=0.10)
    with _server(state, atomic=False) as base_url:
        result = race_burst(base_url, "/redeem", count=6, max_allowed=1, slug=race_slug)

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
        outcomes = raw_race(parts.hostname, parts.port, req, 5, timeout=5.0,
                            authorize=_allow_loopback, target_url=base_url + "/redeem")

    assert len(outcomes) == 5
    statuses = [s for s, _, _ in outcomes]
    assert all(s in (200, 409) for s in statuses)
    # Locked endpoint: exactly one winner across the burst.
    assert statuses.count(200) == 1
    assert state.redemptions == 1


def test_success_predicate_is_honoured(race_slug: str) -> None:
    # A custom predicate keys off the body marker instead of the status code.
    state = _CouponState(window_s=0.10)
    with _server(state, atomic=False) as base_url:
        confirmed = race_check(
            base_url,
            "/redeem",
            count=8,
            max_allowed=1,
            success_predicate=lambda status, body: b"redeemed" == body,
            slug=race_slug,
        )
    assert confirmed is not None
    assert confirmed.bug_class == "request_race"
    assert confirmed.severity == "High"   # A12: a semantic success predicate earns the confirmed claim


def test_a12_all_2xx_no_predicate_is_a_lead_not_a_confirmed_race(race_slug: str) -> None:
    # A12: when EVERY concurrent request returns 2xx (no losers) under the DEFAULT any-2xx predicate, the
    # verdict cannot distinguish a real over-consumption from a benignly-idempotent endpoint — it is a LEAD.
    import http.server
    import socketserver
    import threading

    class _AllOk(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            return

        def do_POST(self):   # every concurrent POST "succeeds" — no atomic resource, no losers
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _AllOk)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        confirmed = race_check(base, "/redeem", count=6, max_allowed=1, slug=race_slug)   # naive: no predicate
    finally:
        srv.shutdown()
        srv.server_close()
    assert confirmed is not None                       # the oracle still fires (over-run count > max_allowed)
    assert confirmed.severity == "Low"                 # ...but it is a LEAD, not a High confirmed race
    assert "UNCONFIRMED" in confirmed.title


def test_raw_race_refuses_an_unauthorized_burst() -> None:
    # SECURITY (Wave-4.4): raw_race fails CLOSED when the pre-flight gate denies — a burst at a
    # host the scope/charter/kill-switch gate rejects raises SovereigntyViolation and NO byte
    # leaves the box. Here the gate denies a non-loopback target; the socket burst never runs.
    req = b"POST /redeem HTTP/1.1\r\nHost: evil.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    with pytest.raises(SovereigntyViolation):
        raw_race("evil.example", 80, req, 4, timeout=1.0,
                 authorize=_allow_loopback, target_url="http://evil.example/redeem")


def test_race_burst_requires_an_authorization_gate() -> None:
    # A raw-socket burst may NEVER run ungated: with neither slug nor authorize, race_burst
    # fails closed with a ValueError before any traffic.
    with pytest.raises(ValueError):
        race_burst("http://127.0.0.1:1/", "/redeem", count=2, max_allowed=1)


def test_gate_denial_blocks_the_burst_before_any_traffic(race_slug: str) -> None:
    # A tripped/denying gate blocks the burst even against a live loopback target: no redemption
    # is recorded because the sockets are never opened.
    state = _CouponState(window_s=0.05)
    with _server(state, atomic=False) as base_url:
        with pytest.raises(SovereigntyViolation):
            race_burst(base_url, "/redeem", count=6, max_allowed=1, authorize=lambda _u: False)
    assert state.redemptions == 0   # the gate refusal happened BEFORE any byte left the box
