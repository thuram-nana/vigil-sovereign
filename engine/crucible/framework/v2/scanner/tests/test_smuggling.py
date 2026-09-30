"""
HTTP request-smuggling detection — raw-socket probing + timing, against a server
that simulates a desync hang on the CL.TE/TE.CL probe signature.

The test server does the one thing a real front-end/back-end desync produces: it
holds the connection open when it sees a request carrying BOTH Content-Length and
Transfer-Encoding (the back-end waiting for a chunk that never arrives), and
answers a normal request immediately. The detector must flag the timing delta on
the delaying server and stay clean on the fast one.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import Iterator

import contextlib

import pytest

from framework.v2.scanner.smuggling import detect, detect_desync, raw_send


class _RawServer(threading.Thread):
    def __init__(self, delay_on_probe: float) -> None:
        super().__init__(daemon=True)
        self.delay = delay_on_probe
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    def _serve_conn(self, conn: socket.socket) -> None:
        conn.settimeout(1.0)
        data = b""
        with contextlib.suppress(OSError, socket.timeout):
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            with contextlib.suppress(socket.timeout):
                data += conn.recv(4096)
        low = data.lower()
        is_probe = b"transfer-encoding: chunked" in low and b"content-length" in low
        if self.delay and is_probe:
            time.sleep(self.delay)  # simulate the back-end hanging on a chunk that never comes
        with contextlib.suppress(OSError):
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncontrol")
        conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


@contextlib.contextmanager
def _server(delay: float) -> Iterator[int]:
    srv = _RawServer(delay)
    srv.start()
    try:
        yield srv.port
    finally:
        srv.stop()


def test_raw_send_reaches_a_server() -> None:
    with _server(0.0) as port:
        elapsed, data = raw_send("127.0.0.1", port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        assert b"200 OK" in data and elapsed >= 0


def test_smuggling_timing_hang_raises_an_unconfirmed_lead() -> None:
    with _server(delay=2.0) as port:
        results = detect("127.0.0.1", port, timeout=5.0, delay_threshold_ms=1200.0)
        hits = [r for r in results if r.lead]
        assert hits, f"no lead raised on a hanging server: {[r.model_dump() for r in results]}"
        assert hits[0].probe_ms - hits[0].control_ms >= 1200.0
        # A12/RED-PEN: a timing delta is a LEAD, never a confirmed desync (a normal origin awaiting an
        # incomplete declared body delays identically). No oracle is consulted, so there is no confidence
        # and nothing is ever `detected`.
        assert "UNCONFIRMED TIMING LEAD" in hits[0].rationale
        assert all(not r.detected and r.confidence == 0.0 for r in results), \
            f"a timing probe claimed a confirmed desync: {[r.model_dump() for r in results if r.detected]}"


def test_no_false_positive_on_fast_server() -> None:
    with _server(delay=0.0) as port:
        results = detect("127.0.0.1", port, timeout=5.0, delay_threshold_ms=1200.0)
        assert all(not r.lead for r in results), \
            f"false lead on a non-desyncing server: {[r.model_dump() for r in results]}"
        assert all(not r.detected for r in results)


# ===========================================================================
# WS1.1b — the never-liftable egress floor at BOTH raw-socket sites
# (raw_send + _desync_leg). A raw socket must REFUSE metadata/link-local/
# RFC1918/reserved — directly or via a DNS-rebinding answer — with ZERO
# packets and no FACT (smuggling is RETIRED to LEAD, so it mints nothing
# either way; the floor only ADDS a refusal, never reach).
# ===========================================================================

# The floor's L3/L4 denylist lives in vigil_gateway (the engine reuses that shared primitive). The
# "CRUCIBLE core on vigil_core" CI job runs the framework tree WITHOUT gateway on the path, where
# resolve_and_pin fails closed for lack of the module — so the floor's resolve/pin cases are gated on
# gateway being importable (same pattern as verify/tests/test_egress_pin.py). The loopback-literal
# short-circuit and the layer check need no gateway and always run.
_HAS_GATEWAY = True
try:  # pragma: no cover - environment probe
    import vigil_gateway  # noqa: F401
except Exception:  # pragma: no cover
    _HAS_GATEWAY = False

_requires_gateway = pytest.mark.skipif(not _HAS_GATEWAY, reason="floor L3/L4 denylist needs vigil_gateway")

_SMUG_SLUG = "smug-egress-floor-test"

# A signed charter that lists BOTH a loopback literal (the positive detection target) and two
# hostnames (used by the DNS-rebinding negative + the pin-proof positive). The name floor
# (validate_action) authorises the NAME as a string; the L3/L4 floor then judges the RESOLVED
# address, so a name that rebinds to an internal/metadata address is still refused.
_FLOOR_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Loopback smuggling test target | Yes |
| `localhost` | Loopback smuggling test target | Yes |
| `smug-target.test` | In-scope NAME (rebinding negative control) | Yes |
| `pin-target.test` | In-scope NAME (anti-rebinding pin proof) | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def smug_slug(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Materialise a signed charter for ``_SMUG_SLUG`` and point ``paths`` at it, so the name floor
    (validate_action over the in-scope hosts) authorises the NAME and charter_ip_literals lifts the
    loopback literal for the positive detection path."""
    from framework.v2.common import paths as _paths
    targets_root = tmp_path / "targets"
    td = targets_root / _SMUG_SLUG
    td.mkdir(parents=True)
    (td / "charter.md").write_text(_FLOOR_CHARTER.format(slug=_SMUG_SLUG), encoding="utf-8")
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    return _SMUG_SLUG


def _resolver_to(addr: str, family: int = socket.AF_INET):
    """A fake getaddrinfo that maps ANY name to ``addr`` — the DNS-rebinding adversary."""
    def fake(host, port, proto=0):  # noqa: ANN001
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port or 0))]
    return fake


class _ForbiddenConnect:
    """A create_connection stand-in that FAILS the test if it is ever called — proves ZERO packets
    left the box when the floor refused (the floor must refuse BEFORE any socket is opened)."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __call__(self, address, *a, **k):  # noqa: ANN001
        self.calls.append(address)
        raise AssertionError(f"a socket was opened to {address!r} despite an egress-floor refusal")


# --- negative controls: an in-scope NAME rebinding to an internal/metadata address is refused -----


@_requires_gateway
@pytest.mark.parametrize(
    "bad_addr, family",
    [
        ("169.254.169.254", socket.AF_INET),        # cloud instance metadata (IMDS)
        ("10.0.0.5", socket.AF_INET),               # RFC1918
        ("::ffff:169.254.169.254", socket.AF_INET6),  # IPv4-mapped IPv6 metadata
    ],
)
def test_raw_send_refuses_dns_rebinding_to_internal(
    smug_slug: str, monkeypatch: pytest.MonkeyPatch, bad_addr: str, family: int
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_to(bad_addr, family))
    forbidden = _ForbiddenConnect()
    monkeypatch.setattr(socket, "create_connection", forbidden)
    # smug-target.test is IN the signed charter, so the NAME floor PASSES — the L3/L4 floor is what
    # catches the rebinding. ZERO packets, empty response, and no confirmed anything.
    elapsed_ms, data = raw_send(
        "smug-target.test", 80, b"GET / HTTP/1.1\r\nHost: smug-target.test\r\n\r\n",
        timeout=1.0, slug=smug_slug)
    assert data == b"", f"a rebinding to {bad_addr} produced a response — floor bypassed"
    assert forbidden.calls == [], f"a socket was opened despite the floor: {forbidden.calls}"
    assert elapsed_ms >= 0


@_requires_gateway
def test_raw_send_refuses_bracketed_ipv6_metadata_literal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A bracketed IPv6 metadata literal passed DIRECTLY as the target host — never-liftable Tier 1a.
    forbidden = _ForbiddenConnect()
    monkeypatch.setattr(socket, "create_connection", forbidden)
    elapsed_ms, data = raw_send(
        "[::ffff:169.254.169.254]", 80, b"GET / HTTP/1.1\r\n\r\n", timeout=1.0)
    assert data == b"" and forbidden.calls == [] and elapsed_ms >= 0


@_requires_gateway
def test_detect_desync_refuses_dns_rebinding_to_internal(
    smug_slug: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The SECOND create_connection site (_desync_leg) must floor too. A rebinding to metadata yields
    # a non-adjudicable probe (no channel), ZERO packets, and no canary echo (no FACT).
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_to("169.254.169.254"))
    forbidden = _ForbiddenConnect()
    monkeypatch.setattr(socket, "create_connection", forbidden)
    probes = detect_desync("smug-target.test", 80, timeout=1.0, slug=smug_slug)
    assert probes, "detect_desync returned no probes"
    assert forbidden.calls == [], f"_desync_leg opened a socket despite the floor: {forbidden.calls}"
    for p in probes:
        assert not p.adjudicable, "a floored probe claimed an adjudicable channel"
        assert not p.canary_echo_differential, "a floored probe reported a canary leak"
        assert "egress floor refused" in p.note


@_requires_gateway
def test_out_of_scope_name_is_refused_by_the_name_floor(
    smug_slug: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A name NOT in the signed charter is refused by the NAME floor before the resolver is consulted.
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_to("93.184.216.34"))  # would be public/global
    forbidden = _ForbiddenConnect()
    monkeypatch.setattr(socket, "create_connection", forbidden)
    _elapsed, data = raw_send("not-in-charter.test", 80, b"GET / HTTP/1.1\r\n\r\n",
                              timeout=1.0, slug=smug_slug)
    assert data == b"" and forbidden.calls == []


# --- positive controls: authorised destinations still connect, and the PIN (not the name) is dialled


def test_charter_listed_loopback_with_slug_still_connects(smug_slug: str) -> None:
    # The authorised loopback detection target still connects and the timing probe still fires — the
    # floor ADDS a refusal for internal/metadata, it does not remove reach for a charter-listed target.
    with _server(delay=2.0) as port:
        results = detect("127.0.0.1", port, timeout=5.0, delay_threshold_ms=1200.0, slug=smug_slug)
        hits = [r for r in results if r.lead]
        assert hits, f"charter-listed loopback did not connect/lead under the floor: {results}"
        assert all(not r.detected and r.confidence == 0.0 for r in results)


@_requires_gateway
def test_connect_targets_the_pinned_ip_not_the_name(
    smug_slug: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Anti-rebinding: on a floor PASS the dial must go to the resolved-and-pinned IP, never the
    # re-resolvable name. pin-target.test is in the charter and resolves to a public IP.
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_to("93.184.216.34"))
    dialed: list = []

    class _FakeSock:
        def settimeout(self, *_a): ...
        def sendall(self, *_a): ...
        def recv(self, *_a): return b""       # end the read loop immediately — no real network
        def close(self): ...

    def rec(address, *a, **k):  # noqa: ANN001
        dialed.append(address[0])
        return _FakeSock()

    monkeypatch.setattr(socket, "create_connection", rec)
    raw_send("pin-target.test", 80, b"GET / HTTP/1.1\r\nHost: pin-target.test\r\n\r\n",
             timeout=1.0, slug=smug_slug)
    assert dialed == ["93.184.216.34"], f"dialed the name/other, not the pinned IP: {dialed}"


# --- layer boundary (FATAL-2): the engine module pulls in NO integration layer ---------------------


def test_smuggling_import_pulls_in_no_integration_layer() -> None:
    import sys
    import importlib
    importlib.import_module("framework.v2.scanner.smuggling")
    leaked = [m for m in sys.modules if m.startswith("vigil_integration")]
    assert leaked == [], f"engine module leaked the integration layer: {leaked}"
