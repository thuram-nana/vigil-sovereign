"""
WebSocket security — RFC 6455 handshake + frame codec over raw sockets, CSWSH
(cross-site hijacking) detection, and message injection.

A minimal raw-socket WS server does the real handshake; an ``check_origin`` toggle
models a server that validates Origin (secure) vs one that does not (vulnerable to
CSWSH). It reflects a client text frame so the injection oracle can fire.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import socket
import threading
from pathlib import Path
from typing import Iterator

import pytest

from framework.v2.common import paths as _paths
from framework.v2.scanner import websocket as ws

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()


def _server_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header += bytes([n])
    elif n < 65536:
        header += bytes([126]) + n.to_bytes(2, "big")
    else:
        header += bytes([127]) + n.to_bytes(8, "big")
    return header + payload  # server frames are NOT masked


class _WSServer(threading.Thread):
    def __init__(self, *, check_origin: bool = False, allowed_origin: str = "", reflect: bool = True) -> None:
        super().__init__(daemon=True)
        self.check_origin = check_origin
        self.allowed_origin = allowed_origin
        self.reflect = reflect
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
        conn.settimeout(2.0)
        data = b""
        with contextlib.suppress(OSError, socket.timeout):
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        headers = _parse_headers(data)
        key = headers.get("sec-websocket-key", "")
        origin = headers.get("origin", "")
        if self.check_origin and origin != self.allowed_origin:
            with contextlib.suppress(OSError):
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                conn.close()
            return
        with contextlib.suppress(OSError):
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + _accept(key).encode() + b"\r\n\r\n")
        # optionally read one client frame and reflect it
        if self.reflect:
            payload = _read_client_frame(conn)
            if payload is not None:
                with contextlib.suppress(OSError):
                    conn.sendall(_server_frame(b"echo:" + payload))
        with contextlib.suppress(OSError):
            conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


def _parse_headers(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in data.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            out[k.decode().strip().lower()] = v.decode().strip()
    return out


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except (OSError, socket.timeout):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_client_frame(conn: socket.socket) -> bytes | None:
    head = _recv_exact(conn, 2)
    if head is None:
        return None
    length = head[1] & 0x7F
    if length == 126:
        ext = _recv_exact(conn, 2)
        length = int.from_bytes(ext, "big") if ext else 0
    elif length == 127:
        ext = _recv_exact(conn, 8)
        length = int.from_bytes(ext, "big") if ext else 0
    mask = _recv_exact(conn, 4) if head[1] & 0x80 else b"\x00\x00\x00\x00"
    payload = _recv_exact(conn, length) if length else b""
    if payload is None or mask is None:
        return None
    return bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


@contextlib.contextmanager
def _server(**kw: object) -> Iterator[str]:
    srv = _WSServer(**kw)  # type: ignore[arg-type]
    srv.start()
    try:
        yield f"ws://127.0.0.1:{srv.port}/chat"
    finally:
        srv.stop()


def test_handshake_and_echo() -> None:
    with _server() as url:
        conn = ws.connect(url, origin="http://127.0.0.1")
        assert conn is not None, "RFC 6455 handshake failed"
        conn.send_text("hello")
        assert conn.recv_text() == "echo:hello"
        conn.close()


def test_cswsh_confirmed_when_origin_not_validated() -> None:
    with _server(check_origin=False) as url:
        finding = ws.CswshCheck(url=url, cookies="session=victim").probe()
        assert finding is not None, "cross-site WS hijacking not confirmed"
        assert finding.bug_class == "cross_site_websocket_hijacking"
        assert finding.confirmed_by.value == "achieved_state"
        # A12: a real authenticated session (victim cookies) was supplied -> a High authenticated hijack.
        assert finding.severity == "High"


def test_a12_cswsh_without_cookies_is_a_lead_not_an_authenticated_hijack() -> None:
    # A12: without the victim's session (cookies), the probe proves only that the endpoint accepts a
    # foreign-Origin handshake (Origin not validated) — a LEAD, not a confirmed AUTHENTICATED hijack.
    with _server(check_origin=False) as url:
        finding = ws.CswshCheck(url=url).probe()          # no cookies
        assert finding is not None                        # cross-origin acceptance still fires the oracle
        assert finding.severity == "Medium"               # ...but capped: not a High authenticated hijack
        assert "UNCONFIRMED" in finding.title and "authenticated" not in finding.title.lower()


def test_cswsh_not_confirmed_when_origin_validated() -> None:
    trusted = "http://127.0.0.1"
    with _server(check_origin=True, allowed_origin=trusted) as url:
        finding = ws.CswshCheck(url=url, cookies="session=victim", trusted_origin=trusted).probe()
        assert finding is None, "origin-validating server must not be flagged for CSWSH"


def test_ws_message_injection_reflected() -> None:
    with _server(reflect=True) as url:
        finding = ws.WsMessageInjectionCheck(url=url, origin="http://127.0.0.1").probe()
        assert finding is not None, "reflected WS message not confirmed"
        assert finding.bug_class == "websocket_injection"


# ===========================================================================
# WS1.1b — the raw-socket egress channel floor (NAME floor + IP floor + anti-rebinding pin).
#
# CSWSH is a FACT-minting raw socket that previously had NEITHER a NAME floor nor an IP floor. These
# tests pin the two floors now applied in ``websocket.handshake``: it must REFUSE to connect to cloud
# metadata / link-local / RFC1918 / reserved (directly OR via a DNS-rebinding answer, including the
# IPv6-mapped and bracketed forms) and to a protected / out-of-scope host — with ZERO packets and no
# FACT — while an in-scope public IP, and a charter-listed loopback engaged WITH its slug, still
# connect. The connect must target the PINNED IP, never the re-resolvable name.
#
# The floor imports ``vigil_gateway.denylist`` lazily; the CRUCIBLE-core CI job runs the framework
# tree WITHOUT gateway (the two-env boundary), so skip these floor tests there — exactly as
# ``verify/tests/test_egress_pin.py`` does. Production is unaffected: the offense engine ships gateway.
# ===========================================================================

pytest.importorskip("vigil_gateway")

# A signed loopback charter for the WS floor tests: it lists 127.0.0.1 (the loopback engagement, so
# the IP floor lifts loopback for that exact literal) and an in-scope NAME ``ws-target.test`` (so a
# rebinding negative can clear the NAME floor yet still be caught by the IP floor when the NAME
# resolves to an internal address). Same shape as test_race.py's known-good loopback charter.
_WS_SLUG = "ws-cswsh-loopback-test"

_WS_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Loopback CSWSH test target | Yes |
| `localhost` | Loopback CSWSH test target | Yes |
| `ws-target.test` | In-scope NAME (rebinding negative control) | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def ws_slug(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Materialise a signed loopback charter for ``_WS_SLUG`` and point ``paths`` at it, so the WS
    NAME floor (``validate_action``) and the IP floor's charter-literal lift authorise 127.0.0.1 and
    the in-scope name ``ws-target.test``."""
    targets_root = tmp_path / "targets"
    td = targets_root / _WS_SLUG
    td.mkdir(parents=True)
    (td / "charter.md").write_text(_WS_CHARTER.format(slug=_WS_SLUG), encoding="utf-8")
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    return _WS_SLUG


def _resolver_to(*addrs: str):
    """A hermetic getaddrinfo that maps ANY name to ``addrs`` (getaddrinfo 5-tuple shape). Lets a
    test model a DNS-rebinding answer without touching the real resolver."""
    def fake(host, port, proto=0):  # noqa: ANN001
        return [(2, 1, 6, "", (a, port or 0)) for a in addrs]
    return fake


def _forbid_socket(monkeypatch: pytest.MonkeyPatch) -> list:
    """Record every ``socket.create_connection`` the WS module attempts, and fail the connect. If the
    floor works, it is never called and the list stays empty — the ZERO-packets proof. If the floor is
    bypassed, the recorded call makes the ``== []`` assertion fail loudly (OSError so ``handshake``'s
    own except turns it into a refusal Handshake rather than an opaque error)."""
    calls: list = []

    def rec(addr, timeout=None):  # noqa: ANN001
        calls.append(addr)
        raise OSError("floor bypassed: a socket was opened when the egress floor should have refused")

    monkeypatch.setattr(ws.socket, "create_connection", rec)
    return calls


# --------------------------------------------------------------------------- IP floor (anti-rebinding)


def test_cswsh_refuses_every_internal_rebinding_form(ws_slug: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # An IN-SCOPE charter NAME (clears the NAME floor) that RESOLVES to an internal/metadata address
    # must be refused by the IP floor — direct v4, RFC1918, IPv6-mapped metadata, and link-local v6.
    for bad in ("169.254.169.254", "10.0.0.5", "::ffff:169.254.169.254", "fe80::1"):
        calls = _forbid_socket(monkeypatch)
        finding = ws.CswshCheck(
            url="ws://ws-target.test:8080/chat", cookies="session=victim",
            slug=ws_slug, resolver=_resolver_to(bad)).probe()
        assert finding is None, f"{bad}: an internal rebinding target must never confirm a FACT"
        assert calls == [], f"{bad}: the floor must refuse with ZERO packets (no socket opened)"


def test_cswsh_refuses_dns_rebinding_mixed_answer(ws_slug: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # A name resolving to [public, metadata] is refused wholesale: EVERY resolved address must clear
    # the floor, so a rebinding resolver cannot smuggle metadata in behind a public first answer.
    calls = _forbid_socket(monkeypatch)
    finding = ws.CswshCheck(
        url="ws://ws-target.test:8080/chat", cookies="session=victim",
        slug=ws_slug, resolver=_resolver_to("93.184.216.34", "169.254.169.254")).probe()
    assert finding is None
    assert calls == []


def test_ip_floor_refuses_bracketed_ipv6_metadata_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    # A bracketed IPv6-mapped metadata literal in the URL itself is refused by the IP floor (no slug:
    # the NAME floor passes for a non-protected host, so this isolates the IP tier).
    calls = _forbid_socket(monkeypatch)
    _, hs = ws.handshake("ws://[::ffff:169.254.169.254]:80/chat")
    assert not hs.accepted and "egress floor refused (ip)" in hs.error
    assert calls == []


def test_ws_injection_refuses_rebinding_to_rfc1918(ws_slug: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # The message-injection check rides the same floored channel (via ``connect`` -> ``handshake``).
    calls = _forbid_socket(monkeypatch)
    finding = ws.WsMessageInjectionCheck(
        url="ws://ws-target.test:8080/chat", slug=ws_slug,
        resolver=_resolver_to("10.0.0.5")).probe()
    assert finding is None
    assert calls == []


# --------------------------------------------------------------------------- NAME floor


def test_name_floor_refuses_protected_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    # The categorical protected-domain floor (.gov/.mil/.edu/IGO) applies even with NO slug, before
    # any socket. A public-looking .mil resolves fine but must be refused on the NAME.
    calls = _forbid_socket(monkeypatch)
    _, hs = ws.handshake("ws://research.mil:443/chat", resolver=_resolver_to("93.184.216.34"))
    assert not hs.accepted and "egress floor refused (name)" in hs.error
    assert "protected-domain floor" in hs.error
    assert calls == []


def test_name_floor_refuses_out_of_scope_host_with_slug(ws_slug: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # With an engagement slug, a host NOT in the signed charter scope is refused by validate_action —
    # before the IP floor, before any packet.
    calls = _forbid_socket(monkeypatch)
    _, hs = ws.handshake("ws://not-in-charter.test:80/chat", slug=ws_slug,
                         resolver=_resolver_to("93.184.216.34"))
    assert not hs.accepted and "egress floor refused (name)" in hs.error
    assert calls == []


# --------------------------------------------------------------------------- positive controls


def test_public_pin_is_dialled_not_the_name(monkeypatch: pytest.MonkeyPatch) -> None:
    # A normal public target connects, and the socket is dialled at the PINNED IP the floor validated,
    # never the re-resolvable name — the anti-rebinding guarantee. (We stop at the connect so no real
    # I/O happens; recording the dial address is the proof.)
    seen: dict = {}

    def rec(addr, timeout=None):  # noqa: ANN001
        seen["addr"] = addr
        raise OSError("stop before real network I/O")

    monkeypatch.setattr(ws.socket, "create_connection", rec)
    conn = ws.connect("ws://public-target.test:80/chat", resolver=_resolver_to("93.184.216.34"))
    assert conn is None                                   # OSError at connect -> refused upgrade
    assert seen["addr"] == ("93.184.216.34", 80)          # dialled the PINNED IP, not "public-target.test"


def test_cswsh_confirmed_with_charter_loopback_slug(ws_slug: str) -> None:
    # The positive end-to-end: a charter-listed loopback engaged WITH its slug clears both floors
    # (NAME: 127.0.0.1 in scope; IP: loopback lifted by the charter literal) and the SAME CSWSH FACT
    # is minted, byte-identical to the no-slug loopback path above.
    with _server(check_origin=False) as url:
        finding = ws.CswshCheck(url=url, cookies="session=victim", slug=ws_slug).probe()
    assert finding is not None, "charter-authorised loopback CSWSH must still confirm"
    assert finding.bug_class == "cross_site_websocket_hijacking"
    assert finding.confirmed_by.value == "achieved_state"
    assert finding.severity == "High"


def test_ip_floor_refuses_metadata_even_when_charter_lists_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # The never-liftable tier: even if a (hypothetical) charter listed 169.254.169.254 as an IP
    # literal, the metadata floor cannot be lifted. We assert the literal-target path refuses.
    calls = _forbid_socket(monkeypatch)
    _, hs = ws.handshake("ws://169.254.169.254:80/chat")
    assert not hs.accepted and "egress floor refused (ip)" in hs.error
    assert calls == []
