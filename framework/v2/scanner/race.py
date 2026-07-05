"""
scanner.race — single-packet / high-concurrency race engine (raw sockets).

TOCTOU and limit-overrun bugs (double-spend, coupon reuse, once-token bypass)
hide *below* the HTTP-client abstraction: they only fire when N requests reach
the check-then-act window with near-zero dispersion, before the first one has
committed its write. An ordinary client serialises TLS/connection setup and
loses that window. So this engine drops to raw sockets and uses a last-byte-
synchronised dispatch — an HTTP/1.1 approximation of Burp's single-packet
attack:

  1. open N connections,
  2. send each request up to (but not including) its final byte,
  3. wait on a barrier until every connection has its head buffered,
  4. release the final byte on all N connections together.

Every request is then completed by the server within a tiny window, so the
should-be-atomic action is evaluated concurrently on all N.

The verdict is deterministic and count-based, never timing-based: if an action
that must succeed at most `max_allowed` time(s) succeeded MORE than that under
the burst, the invariant was violated. That over-count is the signal, and it is
promoted to a `ConfirmedFinding` through the achieved-state oracle (the observed
over-redemption matches the attacker-predicted state).

Detection/verification only, loopback/authorised targets only.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
import urllib.parse
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

from ..verify.adapter import FindingContext
from ..verify.confirmation import ConfirmedFinding, confirm_finding

# A predicate over one completed response: (status, body) -> "did the action
# take effect?". Default: any 2xx status counts as a success.
SuccessPredicate = Callable[["int | None", bytes], bool]

_USER_AGENT = "CRUCIBLE-race/1.0 (localhost single-packet race)"


def _default_success(status: "int | None", body: bytes) -> bool:
    return status is not None and 200 <= status < 300


# ---------------------------------------------------------------------------
# Raw response parsing
# ---------------------------------------------------------------------------


def _parse_status(data: bytes) -> "int | None":
    """Pull the status code out of an HTTP/1.x status line, or None if the
    response never arrived / is unparseable."""
    if not data:
        return None
    line, _, _ = data.partition(b"\r\n")
    parts = line.split(b" ", 2)
    if len(parts) < 2 or not parts[0].upper().startswith(b"HTTP/"):
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _split_body(data: bytes) -> bytes:
    _, sep, body = data.partition(b"\r\n\r\n")
    return body if sep else b""


def _read_response(sock: socket.socket, timeout: float) -> bytes:
    """Read a whole response off `sock` until the peer closes or `timeout`
    elapses. The requests this engine builds carry `Connection: close`, so the
    server closes when done and the read terminates cleanly."""
    sock.settimeout(timeout)
    data = b""
    with contextlib.suppress(OSError):
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    return data


# ---------------------------------------------------------------------------
# The single-packet burst
# ---------------------------------------------------------------------------


def raw_race(
    host: str,
    port: int,
    request_bytes: bytes,
    count: int,
    *,
    timeout: float = 6.0,
) -> list[tuple["int | None", bytes, float]]:
    """Fire `count` copies of `request_bytes` with minimal dispersion.

    Uses a last-byte-synchronised dispatch: each of `count` connections sends
    everything but the final byte, all wait on a barrier, then the final byte is
    released on all connections together so the server completes them within a
    tiny window. Returns one `(status, body, elapsed_seconds)` tuple per
    connection, in connection-launch order; `status` is None for a connection
    that failed to connect or produced no parseable response. `elapsed` is
    measured from the barrier release (final-byte send) to full response read,
    so it reflects only the raced portion, not connection setup.
    """
    if count < 1:
        return []
    if not request_bytes:
        raise ValueError("request_bytes must be non-empty")

    head, last = request_bytes[:-1], request_bytes[-1:]
    barrier = threading.Barrier(count)
    results: list[tuple["int | None", bytes, float]] = [(None, b"", 0.0)] * count

    def worker(idx: int) -> None:
        elapsed = 0.0
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError:
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.abort()
            return
        try:
            sock.sendall(head)
            # Everyone lines up here with their head fully buffered on the wire;
            # the barrier release is the single-packet trigger.
            try:
                barrier.wait(timeout=timeout)
            except threading.BrokenBarrierError:
                return
            start = time.monotonic()
            sock.sendall(last)
            data = _read_response(sock, timeout)
            elapsed = time.monotonic() - start
            results[idx] = (_parse_status(data), _split_body(data), elapsed)
        except OSError:
            results[idx] = (None, b"", elapsed)
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 2.0)
    return results


# ---------------------------------------------------------------------------
# High-level race check
# ---------------------------------------------------------------------------


class RaceResult(BaseModel):
    """The count-based verdict of a burst against one action."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(description="The raced action path.")
    count: int = Field(description="Requests fired in the burst.")
    successes: int = Field(description="Responses the predicate judged successful.")
    max_allowed: int = Field(description="Max successes the invariant permits.")
    over_run: bool = Field(description="True iff successes > max_allowed.")
    statuses: list["int | None"] = Field(default_factory=list)
    max_dispersion_ms: float = Field(
        default=0.0, description="Spread between the earliest and latest raced "
        "response, for opsec/reporting only — NOT part of the verdict.",
    )


def _build_request(host: str, port: int, action_path: str, *, body: bytes = b"") -> bytes:
    if not action_path.startswith("/"):
        action_path = "/" + action_path
    host_hdr = host if port in (80, 0) else f"{host}:{port}"
    return (
        f"POST {action_path} HTTP/1.1\r\n"
        f"Host: {host_hdr}\r\n"
        f"User-Agent: {_USER_AGENT}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1") + body


def race_burst(
    base_url: str,
    action_path: str,
    *,
    count: int = 8,
    max_allowed: int = 1,
    body: bytes = b"",
    success_predicate: SuccessPredicate | None = None,
    timeout: float = 6.0,
) -> RaceResult:
    """Fire a single-packet burst of `count` requests at `action_path` and count
    the successes. Pure measurement — no oracle, no confirmation; `race_check`
    layers the confirmation authority on top."""
    predicate = success_predicate or _default_success
    parts = urllib.parse.urlsplit(base_url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (80 if parts.scheme != "https" else 443)

    request_bytes = _build_request(host, port, action_path, body=body)
    outcomes = raw_race(host, port, request_bytes, count, timeout=timeout)

    statuses = [status for status, _, _ in outcomes]
    successes = sum(1 for status, b, _ in outcomes if predicate(status, b))
    elapsed = [e for _, _, e in outcomes if e > 0.0]
    dispersion = (max(elapsed) - min(elapsed)) * 1000.0 if len(elapsed) >= 2 else 0.0

    return RaceResult(
        action=action_path,
        count=count,
        successes=successes,
        max_allowed=max_allowed,
        over_run=successes > max_allowed,
        statuses=statuses,
        max_dispersion_ms=dispersion,
    )


def race_check(
    base_url: str,
    action_path: str,
    *,
    count: int = 8,
    max_allowed: int = 1,
    body: bytes = b"",
    success_predicate: SuccessPredicate | None = None,
    timeout: float = 6.0,
) -> ConfirmedFinding | None:
    """Race `action_path` and confirm a `request_race` finding iff the action
    overran its atomicity limit.

    A should-be-atomic action (single-use coupon, once-token, balance debit) is
    expected to succeed at most `max_allowed` time(s) no matter how many
    concurrent requests hit it. This fires a single-packet burst of `count`
    requests and counts the successes. If the count exceeds `max_allowed`, the
    TOCTOU window was won more than once — a real limit-overrun race — and the
    over-redemption is promoted to a `ConfirmedFinding` through the achieved-
    state oracle (observed over-run == attacker-predicted over-run). A correctly
    locked endpoint yields exactly `max_allowed` successes and returns `None`.

    The verdict is count-based and deterministic; `max_dispersion_ms` is carried
    for reporting but never gates the finding.
    """
    result = race_burst(
        base_url,
        action_path,
        count=count,
        max_allowed=max_allowed,
        body=body,
        success_predicate=success_predicate,
        timeout=timeout,
    )

    if not result.over_run:
        return None

    # The attacker predicted the action would commit more than its limit; the
    # burst observed exactly that. A full match fires the achieved-state oracle.
    # bug_class 'request_race' is unknown to the verifier's routing table, so it
    # falls back to all oracles and the from_state context confirms via
    # achieved_state.
    over_state = {
        "action": action_path,
        "max_allowed": max_allowed,
        "successes": result.successes,
        "atomicity_violated": True,
    }
    context = FindingContext.from_state(
        over_state, over_state, bug_class="request_race"
    )
    finding = {
        "title": f"Limit-overrun race on {action_path}",
        "bug_class": "request_race",
        "severity": "High",
        "surface": f"POST {action_path}",
        "summary": (
            f"A should-be-atomic action succeeded {result.successes} times under a "
            f"{count}-request single-packet burst, exceeding its limit of "
            f"{max_allowed}. The check-then-act window is not guarded, so "
            f"concurrent requests all pass the check before any commits — a "
            f"TOCTOU limit-overrun (double-spend / reuse) race."
        ),
    }
    return confirm_finding(finding, context)
