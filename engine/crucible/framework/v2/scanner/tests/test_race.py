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
    # Drives raw_race through the WS1.1b egress floor, which imports vigil_gateway.denylist and fail-closes
    # without it. SKIP in the gateway-less CRUCIBLE-core job, RUN in the offense leg (ships gateway).
    pytest.importorskip("vigil_gateway")
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
    # Drives raw_race through the WS1.1b egress floor, which imports vigil_gateway.denylist and fail-closes
    # without it. SKIP in the gateway-less CRUCIBLE-core job, RUN in the offense leg (ships gateway).
    pytest.importorskip("vigil_gateway")
    state = _CouponState(window_s=0.10)
    with _server(state, atomic=True) as base_url:
        confirmed = race_check(base_url, "/redeem", count=8, max_allowed=1, slug=race_slug)

    # Exactly one request wins against the lock — no over-redemption.
    assert state.redemptions == 1
    assert confirmed is None


def test_race_burst_reports_counts_without_confirming(race_slug: str) -> None:
    # Drives raw_race through the WS1.1b egress floor, which imports vigil_gateway.denylist and fail-closes
    # without it. SKIP in the gateway-less CRUCIBLE-core job, RUN in the offense leg (ships gateway).
    pytest.importorskip("vigil_gateway")
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
    # Drives raw_race through the WS1.1b egress floor, which imports vigil_gateway.denylist and fail-closes
    # without it. SKIP in the gateway-less CRUCIBLE-core job, RUN in the offense leg (ships gateway).
    pytest.importorskip("vigil_gateway")
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
    # Drives raw_race through the WS1.1b egress floor, which imports vigil_gateway.denylist and fail-closes
    # without it. SKIP in the gateway-less CRUCIBLE-core job, RUN in the offense leg (ships gateway).
    pytest.importorskip("vigil_gateway")
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
    # Drives raw_race through the WS1.1b egress floor, which imports vigil_gateway.denylist and fail-closes
    # without it. SKIP in the gateway-less CRUCIBLE-core job, RUN in the offense leg (ships gateway).
    pytest.importorskip("vigil_gateway")
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


# ---------------------------------------------------------------------------
# WS1.1b — the never-liftable L3/L4 EGRESS FLOOR + anti-rebinding connect-pin.
#
# The NAME gate above (charter_authorize_gate -> validate_action) is string-matching only: a
# charter that lists an in-scope NAME passes it, and the OS then used to resolve that name at
# connect time — so a DNS-rebinding answer of 169.254.169.254 / an RFC1918 addr / an IPv6-mapped
# metadata addr could be dialled with the gate none the wiser. raw_race now runs
# common.egress_pin.resolve_and_pin AFTER the name gate: it resolves once, refuses every
# metadata/link-local/RFC1918/reserved address (never-liftable), and pins the connect to the
# validated IP. These controls prove the refusal (zero packets, no result) and the pin.
# ---------------------------------------------------------------------------


_REBIND_SLUG = "race-rebind-test"

_REBIND_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `meridian.test` | An in-scope NAME (the name gate passes; the floor still judges the IP) | Yes |
| `127.0.0.1` | Loopback race target (charter IP literal — lifts the loopback tier) | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def rebind_slug(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A signed charter that lists an in-scope NAME (``meridian.test``) plus the ``127.0.0.1``
    literal. The name passes the string name gate, so any refusal in the controls below comes
    purely from the L3/L4 floor judging the resolved IP — never from the name gate."""
    targets_root = tmp_path / "targets"
    td = targets_root / _REBIND_SLUG
    td.mkdir(parents=True)
    (td / "charter.md").write_text(_REBIND_CHARTER.format(slug=_REBIND_SLUG), encoding="utf-8")
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    return _REBIND_SLUG


def _hermetic_resolver(mapping: "dict[str, str]"):
    """A getaddrinfo-shaped stand-in mapping a hostname to ONE address (the rebinding answer). An
    UNMAPPED host delegates to the real getaddrinfo — so an IP literal (e.g. the pinned 127.0.0.1
    that the real ``socket.create_connection`` re-resolves internally) still resolves to itself,
    while the mapped name returns the hostile answer we are testing the floor against."""
    import socket as _socket

    _real_gai = _socket.getaddrinfo

    def _gai(host, port, *a, **k):
        addr = mapping.get(host)
        if addr is None:
            return _real_gai(host, port, *a, **k)
        fam = _socket.AF_INET6 if ":" in addr else _socket.AF_INET
        sockaddr = (addr, int(port or 0), 0, 0) if fam == _socket.AF_INET6 else (addr, int(port or 0))
        return [(fam, _socket.SOCK_STREAM, _socket.IPPROTO_TCP, "", sockaddr)]

    return _gai


class _ConnectSpy:
    """Stands in for socket.create_connection. Records every dialled address. When ``real`` is
    given it delegates (positive control); otherwise a call is a floor breach (a socket must
    never open on a refused destination)."""

    def __init__(self, real=None) -> None:
        self.calls: list[tuple] = []
        self._real = real

    def __call__(self, address, *args, **kwargs):
        self.calls.append(tuple(address))
        if self._real is None:
            raise AssertionError(f"FLOOR BREACHED: a socket was opened to {address!r}")
        return self._real(address, *args, **kwargs)


@pytest.mark.parametrize(
    "rebind_addr, why",
    [
        ("169.254.169.254", "cloud instance metadata (IMDS) via link-local"),
        ("10.0.0.5", "RFC1918 private address"),
        ("::ffff:169.254.169.254", "IPv6-mapped metadata address"),
    ],
)
def test_rawrace_floor_refuses_a_rebinding_answer_zero_packets(
    rebind_addr: str, why: str, rebind_slug: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An in-scope charter NAME that the name gate authorises, but whose resolver answer is a denied
    # address, must be REFUSED by the floor with ZERO packets and no result. This is the DNS-rebind
    # / SSRF-to-metadata bypass the floor closes.
    import socket as _socket

    from framework.v2.scanner.race import charter_authorize_gate

    monkeypatch.setattr(_socket, "getaddrinfo", _hermetic_resolver({"meridian.test": rebind_addr}))
    spy = _ConnectSpy()
    monkeypatch.setattr(_socket, "create_connection", spy)

    gate = charter_authorize_gate(rebind_slug)          # the name gate genuinely passes for meridian.test
    assert gate("http://meridian.test/redeem") is True  # ...proving the refusal below is the FLOOR, not the gate
    req = b"POST /redeem HTTP/1.1\r\nHost: meridian.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

    with pytest.raises(SovereigntyViolation):
        raw_race("meridian.test", 80, req, 4, timeout=1.0,
                 authorize=gate, target_url="http://meridian.test/redeem")

    assert spy.calls == [], f"floor must send zero packets for {why}, but a socket was opened"


def test_rawrace_floor_refuses_a_bracketed_ipv6_metadata_literal(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    # A bracketed-IPv6 literal target (here AWS IMDS-over-IPv6 ULA) must be refused by the floor even
    # when the name gate is fully permissive — the metadata/reserved tier is never-liftable.
    import socket as _socket

    spy = _ConnectSpy()
    monkeypatch.setattr(_socket, "create_connection", spy)
    req = b"POST /redeem HTTP/1.1\r\nHost: [fd00:ec2::254]\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

    with pytest.raises(SovereigntyViolation):
        raw_race("[fd00:ec2::254]", 80, req, 3, timeout=1.0,
                 authorize=lambda _u: True, target_url="http://[fd00:ec2::254]/redeem")

    assert spy.calls == [], "a bracketed-IPv6 metadata literal must send zero packets"


def test_rawrace_floor_allows_loopback_baseline_no_slug_no_new_reach() -> None:
    # Drives raw_race through the WS1.1b egress floor, which imports vigil_gateway.denylist and fail-closes
    # without it. SKIP in the gateway-less CRUCIBLE-core job, RUN in the offense leg (ships gateway).
    pytest.importorskip("vigil_gateway")
    # NO-REGRESSION control: this engine is loopback-oriented and dialled loopback freely before the
    # floor existed, so 127.0.0.1 stays an in-scope baseline even with NO slug — the floor ADDS the
    # metadata/RFC1918 refusal without removing this legitimate reach. A live loopback burst still
    # delivers (parseable statuses), exactly as the pre-floor scan/arsenal paths did.
    state = _CouponState(window_s=0.05)
    with _server(state, atomic=True) as base_url:
        import urllib.parse

        parts = urllib.parse.urlsplit(base_url)
        req = (
            f"POST /redeem HTTP/1.1\r\nHost: {parts.hostname}:{parts.port}\r\n"
            f"Content-Length: 0\r\nConnection: close\r\n\r\n"
        ).encode("latin-1")
        outcomes = raw_race(parts.hostname, parts.port, req, 3, timeout=5.0,
                            authorize=_allow_loopback, target_url=base_url + "/redeem")  # no slug

    assert len(outcomes) == 3
    assert all(s in (200, 409) for s, _, _ in outcomes)


def test_rawrace_pins_the_resolved_ip_not_the_name(
    rebind_slug: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Drives raw_race through the WS1.1b egress floor, which imports vigil_gateway.denylist and fail-closes
    # without it. SKIP in the gateway-less CRUCIBLE-core job, RUN in the offense leg (ships gateway).
    pytest.importorskip("vigil_gateway")
    # POSITIVE control + pin proof: an in-scope charter name that resolves to a charter-listed
    # loopback literal connects, AND the socket is opened to the PINNED IP (127.0.0.1), never to the
    # re-resolvable name — so a resolver that later flipped the name could not redirect the dial.
    import socket as _socket

    from framework.v2.scanner.race import charter_authorize_gate

    real_create_connection = _socket.create_connection
    state = _CouponState(window_s=0.02)
    with _server(state, atomic=True) as base_url:
        import urllib.parse

        port = urllib.parse.urlsplit(base_url).port
        # meridian.test -> 127.0.0.1 (the charter lists BOTH the name and the 127.0.0.1 literal).
        monkeypatch.setattr(_socket, "getaddrinfo", _hermetic_resolver({"meridian.test": "127.0.0.1"}))
        spy = _ConnectSpy(real=real_create_connection)
        monkeypatch.setattr(_socket, "create_connection", spy)

        req = (
            f"POST /redeem HTTP/1.1\r\nHost: meridian.test:{port}\r\n"
            f"Content-Length: 0\r\nConnection: close\r\n\r\n"
        ).encode("latin-1")
        outcomes = raw_race("meridian.test", port, req, 3, timeout=5.0,
                            authorize=charter_authorize_gate(rebind_slug),
                            target_url=f"http://meridian.test:{port}/redeem")

    # It connected (parseable statuses came back) ...
    assert len(outcomes) == 3
    assert all(s in (200, 409) for s, _, _ in outcomes)
    # ... and EVERY dial targeted the pinned IP literal, never the hostname.
    assert spy.calls, "the burst must have opened sockets"
    assert all(addr == ("127.0.0.1", port) for addr in spy.calls), spy.calls


def test_race_module_imports_no_integration_layer() -> None:
    # FATAL-2 layer check: importing scanner.race (and the egress_pin floor it now uses) must pull in
    # NO vigil_integration module — the engine floor re-uses vigil_gateway only. Run in a clean
    # subprocess so a prior import in this session cannot mask a real layer violation.
    import subprocess
    import sys

    code = (
        "import framework.v2.scanner.race as r\n"
        "import framework.v2.common.egress_pin\n"
        "r.raw_race\n"  # touch the symbol so lazy imports resolve
        "import sys\n"
        "leaked = sorted(m for m in sys.modules if m == 'vigil_integration' "
        "or m.startswith('vigil_integration.'))\n"
        "assert not leaked, leaked\n"
        "print('OK')\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, f"layer check failed:\nSTDOUT:{proc.stdout}\nSTDERR:{proc.stderr}"
    assert "OK" in proc.stdout
