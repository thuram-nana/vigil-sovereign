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

from ..common.errors import SovereigntyViolation
from ..verify.adapter import FindingContext
from ..verify.confirmation import ConfirmedFinding, confirm_finding

# A predicate over one completed response: (status, body) -> "did the action
# take effect?". Default: any 2xx status counts as a success.
SuccessPredicate = Callable[["int | None", bytes], bool]

# A pre-flight authorization gate over the target URL: returns True iff the RAW-SOCKET
# burst is authorized to leave the box (scope + charter + kill-switch + never-liftable
# egress floor + posture). It is fail-closed by contract — a False OR a raised exception
# means no byte is sent.
AuthorizeGate = Callable[[str], bool]

_USER_AGENT = "CRUCIBLE-race/1.0 (localhost single-packet race)"


def charter_authorize_gate(
    slug: str, *, posture: str = "TEST", killswitch: "object | None" = None,
) -> AuthorizeGate:
    """Build the standing scope/charter/kill-switch/posture authorization gate for a
    RAW-SOCKET race burst, bound to an engagement ``slug`` — the SAME chain
    ``agents.http_executor`` runs before every gated fetch, and identical in shape to the
    ``engage`` runner's ``arsenal_authz``. The kill-switch is checked FIRST (so a tripped
    switch halts even an in-scope target), then :func:`agents.scope_gate.validate_action`
    (which itself enforces the never-liftable protected-domain egress floor, the charter
    signature, and scope). Fail-closed: any error is a refusal, never an allow.

    Imports are FUNCTION-LOCAL to keep ``scanner.race`` importable without pulling the
    agents/authority stack at module load (and to avoid any import cycle)."""
    from ..agents.scope_gate import validate_action  # noqa: PLC0415
    from ..authority import KillSwitch  # noqa: PLC0415

    ks = killswitch if killswitch is not None else KillSwitch(slug)

    def authorize(url: str) -> bool:
        try:
            if ks.is_tripped():
                return False
            return bool(validate_action(
                slug=slug, method="POST", target_url=url, posture=posture).allowed)
        except Exception:
            return False   # fail closed on any gate error — never assume authorized

    return authorize


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
    authorize: AuthorizeGate,
    target_url: str,
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

    SECURITY GATE (Wave-4.4): this engine speaks bytes on the wire via RAW SOCKETS, so it
    BYPASSES ``SovereignHttpxTransport`` and its egress allowlist. Left ungated that is an
    egress hole — a burst could reach an out-of-scope / kill-switched / protected host with
    no check. So it is re-gated here, INSIDE the engine (defense in depth, not only at the
    caller): ``authorize(target_url)`` — the scope/charter/kill-switch/never-liftable egress
    floor/posture chain (see :func:`charter_authorize_gate`) — is evaluated BEFORE any socket
    is opened and FAILS CLOSED. A False verdict or a gate error raises
    :class:`SovereigntyViolation` and NO byte leaves the box; the callers (``race_burst`` /
    ``scanner.campaign``) supply a ``validate_action``-backed gate.
    """
    # Fail-closed authorization BEFORE any traffic. A gate error is a refusal, never an allow.
    try:
        allowed = bool(authorize(target_url))
    except Exception as exc:  # noqa: BLE001 — any gate error is a refusal
        raise SovereigntyViolation(
            f"race burst refused: authorization gate error for {target_url!r}: "
            f"{type(exc).__name__}: {exc}") from exc
    if not allowed:
        raise SovereigntyViolation(
            f"race burst refused: {target_url!r} failed the scope/charter/kill-switch/"
            f"egress-floor gate — raw-socket burst not authorized")

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


def _resolve_authorize(
    authorize: "AuthorizeGate | None", slug: "str | None", posture: str,
    killswitch: "object | None",
) -> AuthorizeGate:
    """The effective pre-flight gate for a burst: an explicit ``authorize`` callable wins
    (``scanner.campaign`` passes its ``_arsenal_host_allowed``); otherwise one is built from
    a signed engagement ``slug`` via :func:`charter_authorize_gate`. Neither ⇒ fail closed
    (a ``ValueError`` — a raw-socket burst may NEVER run without an authorization gate)."""
    if authorize is not None:
        return authorize
    if slug:
        return charter_authorize_gate(slug, posture=posture, killswitch=killswitch)
    raise ValueError(
        "race burst requires an authorization gate: pass slug=<signed engagement> or "
        "authorize=<scope/charter/kill-switch gate> — a raw-socket burst is never ungated")


def race_burst(
    base_url: str,
    action_path: str,
    *,
    count: int = 8,
    max_allowed: int = 1,
    body: bytes = b"",
    success_predicate: SuccessPredicate | None = None,
    timeout: float = 6.0,
    slug: "str | None" = None,
    authorize: "AuthorizeGate | None" = None,
    posture: str = "TEST",
    killswitch: "object | None" = None,
) -> RaceResult:
    """Fire a single-packet burst of `count` requests at `action_path` and count
    the successes. Pure measurement — no oracle, no confirmation; `race_check`
    layers the confirmation authority on top.

    The RAW-SOCKET burst is authorized fail-closed BEFORE any byte leaves the box: pass a
    signed engagement ``slug`` (a ``validate_action``-backed scope/charter/kill-switch/egress
    gate is built for it) or an explicit ``authorize`` callable (``scanner.campaign`` passes
    its own gate). Without either the call raises ``ValueError`` — never an ungated burst."""
    predicate = success_predicate or _default_success
    parts = urllib.parse.urlsplit(base_url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (80 if parts.scheme != "https" else 443)
    gate = _resolve_authorize(authorize, slug, posture, killswitch)
    target_url = urllib.parse.urljoin(
        base_url if base_url.endswith("/") else base_url + "/", action_path.lstrip("/"))

    request_bytes = _build_request(host, port, action_path, body=body)
    outcomes = raw_race(host, port, request_bytes, count, timeout=timeout,
                        authorize=gate, target_url=target_url)

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
    slug: "str | None" = None,
    authorize: "AuthorizeGate | None" = None,
    posture: str = "TEST",
    killswitch: "object | None" = None,
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
        slug=slug,
        authorize=authorize,
        posture=posture,
        killswitch=killswitch,
    )

    if not result.over_run:
        return None

    # The oracle decides the invariant break over the RAW counts: the number of
    # successes actually exceeded the permitted maximum. (The old code passed the
    # same dict as both expected and observed, so the achieved-state oracle could
    # never NOT fire — a pure rubber-stamp. The predicate oracle evaluates the
    # real condition, successes > max_allowed, and cites the counts as evidence.)
    context = FindingContext.from_predicate(
        {"action": action_path, "successes": result.successes, "max_allowed": max_allowed},
        {"gt": [{"var": "successes"}, {"var": "max_allowed"}]},
        bug_class="request_race",
    )
    # A12: a status-code count ("any 2xx") does not prove a should-be-atomic resource was over-CONSUMED — a
    # benignly-idempotent endpoint returns 2xx to every concurrent POST, indistinguishable (from the response
    # side) from a real limit-overrun. So the naive verdict is a LEAD; only a caller-supplied SEMANTIC success
    # predicate (proving the action actually committed, e.g. the body echoes a one-time redemption) earns the
    # high-severity limit-overrun claim.
    if success_predicate is not None:
        finding = {
            "title": f"Limit-overrun race on {action_path}",
            "bug_class": "request_race",
            "severity": "High",
            "surface": f"POST {action_path}",
            "summary": (
                f"A should-be-atomic action succeeded {result.successes} of {count} times in a single-packet "
                f"burst, exceeding its limit of {max_allowed} (a SEMANTIC success predicate proved each "
                f"commit). The check-then-act window is not guarded, so concurrent requests all pass the "
                f"check before any commits — a TOCTOU limit-overrun (double-spend / reuse) race."
            ),
        }
    else:
        finding = {
            "title": f"Concurrent-success observation on {action_path} (possible race — UNCONFIRMED)",
            "bug_class": "request_race",
            "severity": "Low",
            "surface": f"POST {action_path}",
            "summary": (
                f"{result.successes} of {count} concurrent requests returned 2xx under the DEFAULT any-2xx "
                f"predicate, over the limit of {max_allowed}. This is a LEAD, not proof: a 2xx count does not "
                f"prove a should-be-atomic resource was over-consumed (a benignly-idempotent endpoint returns "
                f"2xx to every concurrent request). Supply a semantic success predicate proving the action "
                f"actually committed more than {max_allowed} times to confirm the race."
            ),
        }
    return confirm_finding(finding, context)
