"""
M3 smuggling extensions — obfuscated Transfer-Encoding desync variants, CL.0,
TE.TE, and honest h2c-upgrade capability detection.

The detector is timing-based: it flags a technique only when its probe hangs
past a threshold AND the latency oracle fires. These tests stand up a raw TCP
server that HANGS (sleeps) when it sees a specific obfuscation marker in the raw
request bytes and answers immediately otherwise — the minimal simulation of a
front-end/back-end that desync on exactly one obfuscation. We assert the matching
technique is ``detected`` and that a benign server (which never hangs) produces
no detection at all (no false positive). A separate pair of fixed-response
servers exercises ``detect_h2c_upgrade``: one advertises the h2c upgrade, one
does not.

Timings are kept small — the delaying server sleeps ~0.35 s and the detector is
called with a low ``delay_threshold_ms`` (which now also drives the oracle's
latency threshold), so the suite stays fast while still exercising the full
two-part confirmation gate.

Python 3.13 note: the connection handler is named ``_serve_conn`` (NOT
``_handle``) so it cannot shadow ``threading.Thread`` internals — same gotcha the
sibling ``test_smuggling.py`` documents.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from typing import Iterator

import pytest

from framework.v2.scanner.smuggling import detect, detect_h2c_upgrade


# Delay the server sleeps on a marker hit, and the detector threshold. The delay
# comfortably clears the threshold (and the oracle's latency floor, which detect()
# wires to the same threshold), while staying small enough to keep the test fast.
_DELAY_S = 0.35
_THRESHOLD_MS = 150.0

# Per-technique obfuscation markers, each verified to appear in ONLY that
# technique's raw probe bytes (see the collision check that guards this file).
_MARKERS: dict[str, bytes] = {
    "TE.CL-space": b"transfer-encoding : chunked",
    "TE.CL-tab": b"transfer-encoding:\tchunked",
    "TE.CL-dupe": b"transfer-encoding: x\r\n",
    "TE.CL-xchunked": b"transfer-encoding: xchunked",
    "TE.CL-fold": b"transfer-encoding:\nchunked",
    "TE.CL-vtab": b"\x0bchunked",
    "TE.CL-formfeed": b"\x0cchunked",
    "TE.TE": b"transfer-encoding: cow",
    "CL.0": b"/obsidian-cl0",
}


# ---------------------------------------------------------------------------
# A raw TCP server that hangs on a specific obfuscation marker
# ---------------------------------------------------------------------------


class _MarkerDelayServer(threading.Thread):
    """Raw TCP server that sleeps ``delay`` when the raw request bytes contain
    ``marker`` (case-insensitive) and answers a normal 200 immediately otherwise.
    ``marker=None`` is the benign control that never hangs."""

    def __init__(self, marker: bytes | None, delay: float) -> None:
        super().__init__(daemon=True)
        self.marker = marker.lower() if marker is not None else None
        self.delay = delay
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
        # Drain any already-buffered body (e.g. the CL.0 marker) WITHOUT blocking:
        # on loopback the whole small request is delivered in one segment, so the
        # body is already here. A non-blocking drain captures it with ~zero wait
        # instead of stalling on a read timeout for every probe.
        conn.setblocking(False)
        with contextlib.suppress(BlockingIOError, OSError):
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        conn.setblocking(True)
        if self.marker is not None and self.delay and self.marker in data.lower():
            time.sleep(self.delay)  # simulate the back-end hanging on the desync
        with contextlib.suppress(OSError):
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncontrol"
            )
        conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


@contextlib.contextmanager
def _server(marker: bytes | None, delay: float) -> Iterator[int]:
    srv = _MarkerDelayServer(marker, delay)
    srv.start()
    try:
        yield srv.port
    finally:
        srv.stop()


# ---------------------------------------------------------------------------
# A fixed-response server for the h2c capability probe
# ---------------------------------------------------------------------------


class _FixedResponseServer(threading.Thread):
    """Raw TCP server that reads the request and replies with a fixed byte
    response, then closes — enough to exercise the h2c-upgrade parser."""

    def __init__(self, response: bytes) -> None:
        super().__init__(daemon=True)
        self.response = response
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
        with contextlib.suppress(OSError, socket.timeout):
            conn.recv(4096)
        with contextlib.suppress(OSError):
            conn.sendall(self.response)
        conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


@contextlib.contextmanager
def _fixed_server(response: bytes) -> Iterator[int]:
    srv = _FixedResponseServer(response)
    srv.start()
    try:
        yield srv.port
    finally:
        srv.stop()


# ---------------------------------------------------------------------------
# Obfuscation-variant detection
# ---------------------------------------------------------------------------


def test_marker_uniqueness_is_maintained() -> None:
    """Guard the negative-control assertions below: each technique's marker must
    appear in ONLY that technique's probe, or a delaying server would trip more
    than one result and the 'others not detected' checks would be meaningless."""
    from framework.v2.scanner.smuggling import _TECHNIQUES

    probes = {name: builder("127.0.0.1").lower() for name, builder in _TECHNIQUES}
    for technique, marker in _MARKERS.items():
        matched = [name for name, raw in probes.items() if marker.lower() in raw]
        assert matched == [technique], f"{technique} marker also matched {matched}"


@pytest.mark.parametrize("technique", list(_MARKERS.keys()))
def test_obfuscation_variant_detected(technique: str) -> None:
    """A server that hangs only on ``technique``'s obfuscation marker makes the
    detector flag exactly that technique (with confirmed confidence), and NO
    other technique — no false positive on the ones that did not hang."""
    marker = _MARKERS[technique]
    with _server(marker=marker, delay=_DELAY_S) as port:
        results = detect("127.0.0.1", port, timeout=5.0, delay_threshold_ms=_THRESHOLD_MS)
    by = {r.technique: r for r in results}

    hit = by[technique]
    assert hit.detected, f"{technique} not detected: {hit.model_dump()}"
    assert hit.confidence > 0.0
    assert hit.probe_ms - hit.control_ms >= _THRESHOLD_MS

    others = [r for name, r in by.items() if name != technique]
    assert all(not r.detected for r in others), (
        f"false positive on non-hanging techniques while probing {technique}: "
        f"{[r.model_dump() for r in others if r.detected]}"
    )


def test_no_false_positive_on_benign_server() -> None:
    """A server that never hangs (no marker) yields no detection for ANY
    technique — the whole suite stays clean against a non-desyncing peer."""
    with _server(marker=None, delay=0.0) as port:
        results = detect("127.0.0.1", port, timeout=5.0, delay_threshold_ms=_THRESHOLD_MS)
    assert results, "detect() returned no results"
    assert all(not r.detected for r in results), (
        f"false positive on a benign server: "
        f"{[r.model_dump() for r in results if r.detected]}"
    )


def test_detect_reports_the_full_technique_suite() -> None:
    """The extended detector reports every technique — the base pair plus the new
    obfuscation variants, CL.0 and TE.TE — with CL.TE/TE.CL still leading."""
    with _server(marker=None, delay=0.0) as port:
        results = detect("127.0.0.1", port, timeout=5.0, delay_threshold_ms=_THRESHOLD_MS)
    names = [r.technique for r in results]
    assert names[:2] == ["CL.TE", "TE.CL"], names
    for expected in ("CL.TE", "TE.CL", "CL.0", "TE.TE", *_MARKERS.keys()):
        assert expected in names, f"{expected} missing from {names}"


# ---------------------------------------------------------------------------
# h2c upgrade capability detection (honest scope: capability, not exploitation)
# ---------------------------------------------------------------------------


def test_h2c_upgrade_offered() -> None:
    """A server that answers ``101 Switching Protocols`` with ``Upgrade: h2c``
    is reported as offering the h2c upgrade surface."""
    response = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: h2c\r\n\r\n"
    )
    with _fixed_server(response) as port:
        assert detect_h2c_upgrade("127.0.0.1", port, timeout=3.0) is True


def test_h2c_upgrade_not_offered_on_plain_200() -> None:
    """A server that returns a normal 200 with no ``Upgrade`` header does NOT
    offer h2c — the negative control."""
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: close\r\n\r\nok"
    )
    with _fixed_server(response) as port:
        assert detect_h2c_upgrade("127.0.0.1", port, timeout=3.0) is False


def test_h2c_not_confused_by_body_mention() -> None:
    """The token must sit in an actual ``Upgrade`` header — a 200 whose BODY
    merely mentions ``h2c`` must not be mistaken for an upgrade offer."""
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 20\r\n"
        b"Connection: close\r\n\r\nh2c is not offered!!"
    )
    with _fixed_server(response) as port:
        assert detect_h2c_upgrade("127.0.0.1", port, timeout=3.0) is False
