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


@dataclass(frozen=True)
class Handshake:
    """The RAW bytes of ONE handshake attempt — what a CSWSH certificate must retain.

    ``response`` is the target's verbatim response header block (F7: the only
    target-DERIVED evidence in the exchange); ``request`` is the exact block VIGIL sent,
    so the certificate states which ``Origin`` was actually offered. ``accept_key`` is the
    RFC 6455 ``Sec-WebSocket-Accept`` value VIGIL computed from its OWN per-handshake
    nonce — a response carrying it is cryptographically bound to THIS exchange, so an
    oracle re-run over the retained bytes cannot be satisfied by an edited transcript."""

    request: str = ""
    response: str = ""
    status: int | None = None
    accept_key: str = ""
    accepted: bool = False
    error: str = ""


def handshake(
    url: str,
    *,
    origin: str | None = None,
    cookies: str | None = None,
    extra_headers: list[tuple[str, str]] | None = None,
    timeout: float = 5.0,
) -> tuple["WSConnection | None", Handshake]:
    """Perform the RFC 6455 handshake and return ``(connection_or_None, raw_record)``.

    The connection half is exactly :func:`connect`'s contract; the second half RETAINS
    the raw bytes of the exchange so a check can hand real target bytes to an oracle
    instead of its own boolean."""
    tls, host, port, path = _parse_ws_url(url)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    expected_accept = _accept_key(key)
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
    sent = request.decode("latin-1", "replace")

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
    except (OSError, WSError) as exc:
        return None, Handshake(request=sent, accept_key=expected_accept,
                               error=f"{type(exc).__name__}: {exc}")

    record = Handshake(
        request=sent, response=resp.decode("latin-1", "replace"),
        status=_status_of(resp) or None, accept_key=expected_accept,
        accepted=(_status_of(resp) == 101 and expected_accept.encode() in resp),
    )
    if not record.accepted:
        with _suppress():
            sock.close()
        return None, record
    return WSConnection(sock, host, path), record


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
    return handshake(url, origin=origin, cookies=cookies,
                     extra_headers=extra_headers, timeout=timeout)[0]


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
        return self.probe_with_context()[0]

    def probe_with_context(self) -> "tuple[ConfirmedFinding | None, FindingContext]":
        """The probe plus the RAW-BYTES certificate it was adjudicated on (F7).

        The old context was ``from_state({"cross_origin_ws_accepted": True}, {...: hijackable})``
        — this check's own boolean handed back to ``achieved_state_oracle`` to be re-asserted,
        the "achieved-state rubber-stamp" ``predicate_oracle``'s docstring exists to retire.
        (In ``scanner.campaign`` it was worse still: BOTH sides were the literal ``True``, so
        the certificate re-confirmed forever regardless of the target, the fix state, or
        whether the endpoint ever existed.) Now the certificate carries the two handshakes'
        RAW request/response blocks and the ORACLE decides, over those bytes, whether the
        dangerous condition holds: both handshakes returned ``HTTP/1.1 101`` carrying the
        ``Sec-WebSocket-Accept`` value derived from VIGIL's own per-handshake nonce, and the
        foreign-``Origin`` request really did offer the foreign origin. Tampering with any
        retained byte breaks the accept-key binding and the offline re-verification FAILS."""
        tls, host, port, _ = _parse_ws_url(self.url)
        trusted = self.trusted_origin or f"{'https' if tls else 'http'}://{host}:{port}"
        legit, legit_hs = handshake(self.url, origin=trusted, cookies=self.cookies or None)
        with _closing(legit):
            pass
        evil, evil_hs = handshake(self.url, origin=self.evil_origin, cookies=self.cookies or None)
        with _closing(evil):
            pass
        ctx = FindingContext.from_predicate(
            {
                "url": self.url,
                "trusted_origin": trusted,
                "evil_origin": self.evil_origin,
                "trusted_origin_header": f"Origin: {trusted}",
                "evil_origin_header": f"Origin: {self.evil_origin}",
                "trusted_request": legit_hs.request,
                "trusted_response": legit_hs.response,
                "trusted_accept_key": legit_hs.accept_key,
                "evil_request": evil_hs.request,
                "evil_response": evil_hs.response,
                "evil_accept_key": evil_hs.accept_key,
            },
            {"all": [
                # The endpoint really is a live, working WebSocket for the trusted origin ...
                {"icontains": [{"var": "trusted_request"}, {"var": "trusted_origin_header"}]},
                {"icontains": [{"var": "trusted_response"}, "http/1.1 101"]},
                {"contains": [{"var": "trusted_response"}, {"var": "trusted_accept_key"}]},
                # ... and it ALSO switched protocols for a request that offered a FOREIGN
                # Origin, so Origin is not validated. The accept key binds each response to
                # VIGIL's own nonce for THAT handshake — an edited transcript cannot satisfy it.
                {"icontains": [{"var": "evil_request"}, {"var": "evil_origin_header"}]},
                {"icontains": [{"var": "evil_response"}, "http/1.1 101"]},
                {"contains": [{"var": "evil_response"}, {"var": "evil_accept_key"}]},
            ]},
            bug_class=self.bug_class,
        )
        # A12: an authenticated HIJACK requires the victim's SESSION (cookies). Without cookies the probe
        # proves only that the endpoint accepts a foreign-Origin handshake (Origin not validated) — a LEAD,
        # not a confirmed authenticated hijack. Over TLS the peer is unverified (CERT_NONE), so note that the
        # channel identity is not validated. Only a real authenticated session (cookies) earns "High hijack".
        tls_note = " (over an UNVERIFIED TLS channel — the peer identity is not validated)" if tls else ""
        if self.cookies:
            finding = {
                "bug_class": self.bug_class, "title": "Cross-Site WebSocket Hijacking",
                "severity": "High", "surface": self.url,
                "summary": f"authenticated WS handshake (victim session cookies) accepted cross-origin{tls_note}",
            }
        else:
            finding = {
                "bug_class": self.bug_class,
                "title": "Cross-origin WebSocket handshake accepted (possible CSWSH — UNCONFIRMED)",
                "severity": "Medium", "surface": self.url,
                "summary": (f"the endpoint accepted a foreign-Origin handshake, so it does not validate the "
                            f"Origin — a LEAD{tls_note}. NO authenticated session was supplied (no cookies), "
                            f"so an authenticated hijack is NOT proven; supply the victim's cookies to confirm "
                            f"a real cross-site WebSocket hijack."),
            }
        return confirm_finding(finding, ctx), ctx


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
