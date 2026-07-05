"""
scanner.smuggling — HTTP request-smuggling detection (raw sockets, timing-based).

Request smuggling lives below the HTTP-client abstraction: it needs *exact bytes*
on the wire — a request carrying both ``Content-Length`` and ``Transfer-Encoding``
so a front-end and back-end disagree on where it ends. This module drops to raw
sockets to send those bytes and times the response: when the two parsers disagree,
the back-end waits for a chunk that never comes and the connection HANGS, so a
CL.TE / TE.CL probe returns far slower than a control request. That timing delta,
confirmed by the differential oracle's latency dimension and gated by an absolute
threshold (so jitter cannot false-positive), is the signal.

Detection only — it identifies the desync and stops; it does not smuggle a
weaponised request. Targets must be operator-authorised (loopback in tests).
"""

from __future__ import annotations

import socket
import time

from pydantic import BaseModel, ConfigDict, Field

from ..verify.confirmation import confirm_finding
from ..verify.adapter import FindingContext


class SmugglingResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique: str = Field(description="CL.TE or TE.CL")
    detected: bool
    control_ms: float
    probe_ms: float
    confidence: float = 0.0
    rationale: str = ""


def raw_send(host: str, port: int, raw: bytes, *, timeout: float = 6.0) -> tuple[float, bytes]:
    """Send exact bytes on a fresh connection and read the response until the peer
    closes or ``timeout`` elapses. Returns (elapsed_ms, data). A hang (the desync
    signal) shows up as elapsed ≈ timeout."""
    start = time.monotonic()
    data = b""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return (time.monotonic() - start) * 1000.0, b""
    try:
        s.settimeout(timeout)
        s.sendall(raw)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data and len(chunk) < 4096:
                break
    finally:
        s.close()
    return (time.monotonic() - start) * 1000.0, data


def _control(host: str) -> bytes:
    return (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode("latin-1")


def _clte(host: str) -> bytes:
    # Front-end uses Content-Length (4), back-end uses Transfer-Encoding: the
    # back-end reads chunk "1\r\nA" then waits for the next chunk that never comes.
    body = "1\r\nA\r\nX"
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n{body}"
    ).encode("latin-1")


def _tecl(host: str) -> bytes:
    # Front-end uses Transfer-Encoding, back-end uses Content-Length: a large
    # declared chunk the back-end (CL) never fully receives -> it waits.
    body = "0\r\n\r\nG"
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n{body}"
    ).encode("latin-1")


def detect(
    host: str,
    port: int,
    *,
    timeout: float = 6.0,
    delay_threshold_ms: float = 1500.0,
) -> list[SmugglingResult]:
    """Probe ``host:port`` for CL.TE and TE.CL desync. Returns a result per
    technique; ``detected`` is True only when the probe is slower than the control
    by ``delay_threshold_ms`` AND the differential oracle's latency signal fires."""
    control_ms, _ = raw_send(host, port, _control(host), timeout=timeout)
    results: list[SmugglingResult] = []
    for technique, probe in (("CL.TE", _clte(host)), ("TE.CL", _tecl(host))):
        probe_ms, _ = raw_send(host, port, probe, timeout=timeout)
        delta = probe_ms - control_ms

        ctx = FindingContext.from_http_responses(
            {"status": 200, "body": "control"},
            {"status": 200, "body": "control"},   # identical content: latency is the only signal
            bug_class="request_smuggling",
            baseline_latency_ms=control_ms,
            mutated_latency_ms=probe_ms,
            discriminator={"dimensions": ["latency"]},
        )
        confirmed = confirm_finding(
            {"bug_class": "request_smuggling", "title": f"{technique} desync",
             "severity": "High", "surface": technique, "summary": f"{technique} timing probe"},
            ctx,
        )
        detected = delta >= delay_threshold_ms and confirmed is not None
        results.append(SmugglingResult(
            technique=technique,
            detected=detected,
            control_ms=round(control_ms, 1),
            probe_ms=round(probe_ms, 1),
            confidence=confirmed.confidence if confirmed else 0.0,
            rationale=(
                f"{technique} probe hung {delta:.0f}ms beyond the control"
                if detected else f"no significant delay ({delta:.0f}ms)"
            ),
        ))
    return results
