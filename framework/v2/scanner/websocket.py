"""
scanner.websocket — WebSocket security testing (RFC 6455, raw sockets).

WebSockets are a protocol below the HTTP-client abstraction: an Upgrade handshake,
then bidirectional masked frames. They carry their own high-value bugs — most
notably **Cross-Site WebSocket Hijacking (CSWSH)**, where a server opens an
*authenticated* socket for a request that carries the victim's cookies but a
foreign ``Origin``, letting any web page read/write the victim's channel — and
message-level injection where WS input reaches a sink unsanitised.

This module speaks RFC 6455 over stdlib sockets (with ``ssl`` for ``wss://``):
the handshake with ``Sec-WebSocket-Key``/``Accept`` validation, and a masked
client frame codec. Two checks confirm real bugs, not heuristics:

  * :class:`CswshCheck` — hand the server the victim's cookies with a FOREIGN
    ``Origin``; if the handshake still succeeds (101) it is not validating origin,
    and an authenticated cross-origin socket is possible. Confirmed via
    achieved-state only when a same-cookies + *trusted* origin succeeds too (so we
    are flagging missing origin-validation, not a closed endpoint).
  * :class:`WsMessageInjectionCheck` — send a unique marker over the socket and
    fire the side-effect oracle iff it reaches the reply sink.

Detection/verification only, against operator-authorised endpoints (loopback in
tests).
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field

from ..verify.confirmation import ConfirmedFinding, confirm_finding
from ..verify.adapter import FindingContext

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # RFC 6455 magic


class WSError(RuntimeError):
    """A WebSocket protocol/transport error."""


def _accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")


def _parse_ws_url(url: str) -> tuple[bool, str, int, str]:
    """(is_tls, host, port, path_with_query) from a ws:// or wss:// URL."""
    p = urllib.parse.urlsplit(url)
    tls = p.scheme == "wss"
    if p.scheme not in ("ws", "wss"):
        raise WSError(f"not a ws/wss URL: {url!r}")
    host = p.hostname or "127.0.0.1"
    port = p.port or (443 if tls else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return tls, host, port, path


class WSConnection:
    """A live client WebSocket: handshake done, frames flowing. Masks outbound
    frames (RFC 6455 requires clients to mask); parses inbound server frames."""

    def __init__(self, sock: socket.socket, host: str, path: str) -> None:
        self.sock = sock
        self.host = host
        self.path = path

    def send_text(self, message: str) -> None:
        self.sock.sendall(self._frame(message.encode("utf-8"), opcode=0x1))

    def recv_text(self, *, timeout: float = 5.0) -> str:
        self.sock.settimeout(timeout)
        try:
            opcode, payload = self._read_frame()
        except (socket.timeout, OSError):
            return ""
        if opcode == 0x8:  # close
            return ""
        return payload.decode("utf-8", "replace")

    def close(self) -> None:
        with _suppress():
            self.sock.sendall(self._frame(b"", opcode=0x8))
        with _suppress():
            self.sock.close()

    # -- framing -----------------------------------------------------------

    @staticmethod
    def _frame(payload: bytes, *, opcode: int) -> bytes:
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + n.to_bytes(2, "big")
        else:
            header += bytes([0x80 | 127]) + n.to_bytes(8, "big")
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return header + mask + masked

    def _read_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise WSError("connection closed mid-frame")
            buf += chunk
        return buf

    def _read_frame(self) -> tuple[int, bytes]:
        b0, b1 = self._read_exact(2)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            length = int.from_bytes(self._read_exact(2), "big")
        elif length == 127:
            length = int.from_bytes(self._read_exact(8), "big")
        mask = self._read_exact(4) if masked else b""
        payload = self._read_exact(length) if length else b""
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload


def connect(
    url: str,
    *,
    origin: str | None = None,
    cookies: str | None = None,
    extra_headers: list[tuple[str, str]] | None = None,
    timeout: float = 5.0,
) -> WSConnection | None:
    """Perform the RFC 6455 handshake and return a WSConnection, or None if the
    server refused the upgrade (any non-101 status). ``origin``/``cookies`` model
    a browser-originated connection for CSWSH testing."""
    tls, host, port, path = _parse_ws_url(url)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    if cookies:
        lines.append(f"Cookie: {cookies}")
    for k, v in extra_headers or []:
        lines.append(f"{k}: {v}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

    try:
        sock: socket.socket = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request)
        sock.settimeout(timeout)
        resp = _read_headers(sock)
    except (OSError, WSError):
        return None

    status = _status_of(resp)
    if status != 101 or _accept_key(key).encode() not in resp:
        with _suppress():
            sock.close()
        return None
    return WSConnection(sock, host, path)


def _read_headers(sock: socket.socket) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def _status_of(resp: bytes) -> int:
    try:
        return int(resp.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CswshCheck:
    """Cross-Site WebSocket Hijacking: the endpoint accepts an authenticated
    handshake carrying the victim's cookies from a FOREIGN Origin.

    Confirmed via achieved-state only when the trusted-origin handshake also
    succeeds (proving the endpoint works and is cookie-authenticated) while the
    foreign-origin handshake ALSO succeeds — i.e. Origin is not validated. If the
    foreign origin is rejected, no finding."""

    url: str
    cookies: str = ""
    id: str = "cswsh"
    bug_class: str = "cross_site_websocket_hijacking"
    evil_origin: str = "https://crucible-evil-origin.test"
    trusted_origin: str | None = None  # defaults to the target's own origin

    def probe(self) -> ConfirmedFinding | None:
        tls, host, port, _ = _parse_ws_url(self.url)
        trusted = self.trusted_origin or f"{'https' if tls else 'http'}://{host}:{port}"
        legit = connect(self.url, origin=trusted, cookies=self.cookies or None)
        with _closing(legit):
            legit_ok = legit is not None
        evil = connect(self.url, origin=self.evil_origin, cookies=self.cookies or None)
        with _closing(evil):
            evil_ok = evil is not None
        hijackable = legit_ok and evil_ok  # works legitimately AND ignores origin
        ctx = FindingContext.from_state(
            {"cross_origin_ws_accepted": True},
            {"cross_origin_ws_accepted": hijackable},
            bug_class=self.bug_class,
        )
        return confirm_finding(
            {"bug_class": self.bug_class, "title": "Cross-Site WebSocket Hijacking",
             "severity": "High", "surface": self.url, "summary": "authenticated WS handshake accepted cross-origin"},
            ctx,
        )


@dataclass(frozen=True)
class WsMessageInjectionCheck:
    """WebSocket message injection: send a unique marker over the socket and
    confirm via the side-effect oracle iff it reaches the reply. ``wrap`` frames
    the marker into the app's message format (e.g. a JSON envelope)."""

    url: str
    cookies: str = ""
    origin: str | None = None
    wrap: str = "{marker}"
    id: str = "ws-injection"
    bug_class: str = "websocket_injection"

    def probe(self) -> ConfirmedFinding | None:
        conn = connect(self.url, origin=self.origin, cookies=self.cookies or None)
        if conn is None:
            return None
        marker = "cruciblews" + base64.b16encode(os.urandom(4)).decode("ascii").lower()
        with _closing(conn):
            conn.send_text(self.wrap.format(marker=marker))
            reply = conn.recv_text()
        ctx = FindingContext.from_side_effect(marker, reply, bug_class=self.bug_class)
        return confirm_finding(
            {"bug_class": self.bug_class, "title": "WebSocket message injection",
             "severity": "Medium", "surface": self.url, "summary": "input reflected over the WS channel"},
            ctx,
        )


# ---------------------------------------------------------------------------
# tiny context-manager helpers (stdlib contextlib avoided to keep imports lean)
# ---------------------------------------------------------------------------


@dataclass
class _closing:
    conn: object | None = field(default=None)

    def __enter__(self) -> object | None:
        return self.conn

    def __exit__(self, *exc: object) -> None:
        if self.conn is not None and hasattr(self.conn, "close"):
            with _suppress():
                self.conn.close()  # type: ignore[attr-defined]


class _suppress:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> bool:
        return True  # swallow any teardown error
