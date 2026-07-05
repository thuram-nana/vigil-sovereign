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
from typing import Iterator

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
