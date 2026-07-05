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
from typing import Iterator

import contextlib

from framework.v2.scanner.smuggling import detect, raw_send


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


def test_smuggling_timing_desync_detected() -> None:
    with _server(delay=2.0) as port:
        results = detect("127.0.0.1", port, timeout=5.0, delay_threshold_ms=1200.0)
        hits = [r for r in results if r.detected]
        assert hits, f"desync not detected: {[r.model_dump() for r in results]}"
        assert hits[0].probe_ms - hits[0].control_ms >= 1200.0
        assert hits[0].confidence > 0.0


def test_no_false_positive_on_fast_server() -> None:
    with _server(delay=0.0) as port:
        results = detect("127.0.0.1", port, timeout=5.0, delay_threshold_ms=1200.0)
        assert all(not r.detected for r in results), \
            f"false positive on a non-desyncing server: {[r.model_dump() for r in results]}"
