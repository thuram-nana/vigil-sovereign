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

The base CL.TE / TE.CL pair only catches parsers that disagree on the *presence*
of both headers. Real front-ends are stricter than that, so the desync usually
hides behind an OBFUSCATED ``Transfer-Encoding`` header that one parser honours and
the other silently drops — a space before the colon, a tab, a duplicate header, a
bogus coding name, a folded value, a control-character prefix. Each of those is a
distinct technique here (``TE.CL-space``, ``TE.CL-tab``, ``TE.CL-dupe``, …), plus
two framing-disagreement classes that need no CL/TE pair at all: ``CL.0`` (the
back-end ignores a body the front-end forwarded) and ``TE.TE`` (two conflicting
Transfer-Encoding headers). Every one of them is confirmed the SAME way — a timing
delta past ``delay_threshold_ms`` AND the latency oracle firing — because a
false smuggling report is dangerous: we never claim a smuggle without the hang.

HTTP/2 note: genuine h2/h2c request smuggling (h2.CL, h2.TE, CRLF-in-header,
:path splitting) needs HPACK and HTTP/2 frame encoding, which the standard library
does not provide. Rather than fake it, this module offers ``detect_h2c_upgrade`` —
honest CAPABILITY detection of the cleartext-HTTP/2 upgrade surface, not h2
smuggling exploitation. See that function's docstring for the exact boundary.

Detection only — it identifies the desync and stops; it does not smuggle a
weaponised request. Targets must be operator-authorised (loopback in tests).
"""

from __future__ import annotations

import socket
import time
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

from ..verify.confirmation import confirm_finding
from ..verify.adapter import FindingContext


class SmugglingResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique: str = Field(
        description="Desync technique probed: CL.TE, TE.CL, an obfuscation "
        "variant (TE.CL-space/-tab/-dupe/-xchunked/-fold/-vtab/-formfeed), "
        "CL.0, or TE.TE."
    )
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


# ---------------------------------------------------------------------------
# Obfuscated Transfer-Encoding variants — the desync a stricter front-end hides
# ---------------------------------------------------------------------------
#
# A modern front-end usually rejects a request that carries BOTH Content-Length
# and a literal ``Transfer-Encoding: chunked`` (or normalises one away), so the
# naive CL.TE / TE.CL pair no longer fires against it. The desync survives only
# when the ``Transfer-Encoding`` header is *malformed just enough* that exactly
# one of the two parsers still reads it as "chunked" while the other treats it as
# unknown and falls back to Content-Length. Each variant below carries the same
# hang-inducing tail: a lone terminating chunk (5 bytes on the wire) under a
# Content-Length that declares MORE bytes than are sent, so whichever end honours
# Content-Length waits for bytes that never arrive — the hang a timing probe
# measures. The OBFUSCATION is what splits the two parsers in the first place.

_HANG_TAIL = "0\r\n\r\n"   # terminating chunk only: 5 bytes on the wire
_HANG_CL = 24              # a CL parser waits for 24 bytes, receives 5 -> hangs


def _te_cl_space(host: str) -> bytes:
    """TE.CL-space — a space between the field-name and the colon
    (``Transfer-Encoding : chunked``). RFC 7230 §3.2.4 forbids whitespace before
    the ``:``, so a strict parser drops the header (and falls back to
    Content-Length) while a lax one still reads ``chunked`` — they desync."""
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {_HANG_CL}\r\n"
        f"Transfer-Encoding : chunked\r\n\r\n{_HANG_TAIL}"
    ).encode("latin-1")


def _te_cl_tab(host: str) -> bytes:
    """TE.CL-tab — a horizontal tab instead of a space after the colon
    (``Transfer-Encoding:\\tchunked``). Parsers that trim only SP disagree with
    those that trim SP+HTAB over whether the coding is ``chunked``."""
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {_HANG_CL}\r\n"
        f"Transfer-Encoding:\tchunked\r\n\r\n{_HANG_TAIL}"
    ).encode("latin-1")


def _te_cl_dupe(host: str) -> bytes:
    """TE.CL-dupe — two Transfer-Encoding headers, the second a bogus coding
    (``Transfer-Encoding: chunked`` then ``Transfer-Encoding: x``). The RFC says
    the last value wins, but front and back routinely disagree on WHICH to
    honour; one reads ``chunked`` and the other the junk coding (falling back to
    Content-Length) — desync. (This variant carries a literal
    ``Transfer-Encoding: chunked``, so a naive both-headers detector also trips
    on it — that is by design; the obfuscation is the DUPLICATE, not the hiding.)"""
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {_HANG_CL}\r\n"
        f"Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n{_HANG_TAIL}"
    ).encode("latin-1")


def _te_cl_xchunked(host: str) -> bytes:
    """TE.CL-xchunked — a coding name that is a superstring of ``chunked``
    (``Transfer-Encoding: xchunked``). A parser doing a substring/``endswith``
    match reads it as chunked; a strict token match rejects it — they disagree."""
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {_HANG_CL}\r\n"
        f"Transfer-Encoding: xchunked\r\n\r\n{_HANG_TAIL}"
    ).encode("latin-1")


def _te_cl_fold(host: str) -> bytes:
    """TE.CL-fold — a bare LF folds the value onto the next line
    (``Transfer-Encoding:<LF>chunked``). A parser that treats the lone LF as a
    line terminator sees an empty coding; one that folds on it reads ``chunked``.
    Obsolete line folding (RFC 7230 §3.2.4) is a classic front/back split."""
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {_HANG_CL}\r\n"
        f"Transfer-Encoding:\nchunked\r\n\r\n{_HANG_TAIL}"
    ).encode("latin-1")


def _te_cl_vtab(host: str) -> bytes:
    """TE.CL-vtab — the coding is prefixed with a vertical tab (0x0B)
    (``Transfer-Encoding:<VT>chunked``). Parsers that strip VT as whitespace read
    ``chunked``; those that only strip SP/HTAB see an unknown coding — desync."""
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {_HANG_CL}\r\n"
        f"Transfer-Encoding:\x0bchunked\r\n\r\n{_HANG_TAIL}"
    ).encode("latin-1")


def _te_cl_formfeed(host: str) -> bytes:
    """TE.CL-formfeed — the coding is prefixed with a form feed (0x0C)
    (``Transfer-Encoding:<FF>chunked``). Same split as the vertical-tab variant:
    only parsers that treat FF as trimmable whitespace read ``chunked``."""
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {_HANG_CL}\r\n"
        f"Transfer-Encoding:\x0cchunked\r\n\r\n{_HANG_TAIL}"
    ).encode("latin-1")


def _te_te(host: str) -> bytes:
    """TE.TE — two conflicting Transfer-Encoding headers, the SECOND obfuscated
    with an unknown coding (``Transfer-Encoding: chunked`` +
    ``Transfer-Encoding: cow``). BOTH ends support chunked, but only one honours
    the obfuscated header, so they disagree on the framing. No Content-Length:
    this is a pure TE-vs-TE split. The body is a single data chunk with NO
    terminating 0-chunk, so a TE parser waits for the next chunk — the hang."""
    body = "1\r\nA\r\n"   # one data chunk, no 0-terminator -> TE parser waits
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Transfer-Encoding: chunked\r\nTransfer-Encoding: cow\r\n\r\n{body}"
    ).encode("latin-1")


def _cl_0(host: str) -> bytes:
    """CL.0 — a POST whose body the BACK-END ignores. The front-end honours
    Content-Length and forwards the body; a back-end that treats the connection
    as body-less for this route leaves the body bytes at the head of the socket,
    where they are parsed as the START of the NEXT request — desync. The smuggled
    prefix carries a distinctive ``/obsidian-cl0`` marker; detection here is the
    timing skew the framing mismatch induces (there is no TE header at all, so
    this is invisible to any CL/TE-pair detector)."""
    smuggled = "GET /obsidian-cl0 HTTP/1.1\r\nX-Obsidian: cl0\r\nFoo: bar\r\n\r\n"
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {len(smuggled)}\r\n\r\n{smuggled}"
    ).encode("latin-1")


# The probe suite, in the order detect() reports them. CL.TE and TE.CL stay
# FIRST so their long-standing result positions do not move.
_TECHNIQUES: tuple[tuple[str, Callable[[str], bytes]], ...] = (
    ("CL.TE", _clte),
    ("TE.CL", _tecl),
    ("TE.CL-space", _te_cl_space),
    ("TE.CL-tab", _te_cl_tab),
    ("TE.CL-dupe", _te_cl_dupe),
    ("TE.CL-xchunked", _te_cl_xchunked),
    ("TE.CL-fold", _te_cl_fold),
    ("TE.CL-vtab", _te_cl_vtab),
    ("TE.CL-formfeed", _te_cl_formfeed),
    ("TE.TE", _te_te),
    ("CL.0", _cl_0),
)


def detect(
    host: str,
    port: int,
    *,
    timeout: float = 6.0,
    delay_threshold_ms: float = 1500.0,
) -> list[SmugglingResult]:
    """Probe ``host:port`` for request-smuggling desync across the full technique
    suite (CL.TE, TE.CL, the obfuscated TE variants, CL.0 and TE.TE — see
    ``_TECHNIQUES``). Returns one result per technique, reported in that order.

    ``detected`` is True for a technique only when its probe is slower than the
    control by ``delay_threshold_ms`` AND the differential oracle's latency signal
    fires — the exact same two-part gate the original CL.TE/TE.CL probes used, so
    an obfuscation variant can no more false-positive than the base pair could. We
    never claim a smuggle without the timing hang.

    Note ``delay_threshold_ms`` is wired straight into the oracle's latency
    threshold, so the parameter governs BOTH halves of the gate. (For any
    ``delay_threshold_ms`` >= the oracle's old 1000 ms default this is behaviour-
    identical to before — the parameter was already the binding constraint there;
    it merely lets a caller probe with a lower, faster threshold when the network
    path is quiet, e.g. loopback.)"""
    control_ms, _ = raw_send(host, port, _control(host), timeout=timeout)
    results: list[SmugglingResult] = []
    for technique, builder in _TECHNIQUES:
        probe_ms, _ = raw_send(host, port, builder(host), timeout=timeout)
        delta = probe_ms - control_ms

        ctx = FindingContext.from_http_responses(
            {"status": 200, "body": "control"},
            {"status": 200, "body": "control"},   # identical content: latency is the only signal
            bug_class="request_smuggling",
            baseline_latency_ms=control_ms,
            mutated_latency_ms=probe_ms,
            # The latency oracle's threshold tracks delay_threshold_ms so the one
            # knob governs both the raw delta gate and the oracle's firing.
            discriminator={"dimensions": ["latency"], "latency_threshold_ms": delay_threshold_ms},
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


# ---------------------------------------------------------------------------
# HTTP/2 — honest capability detection, NOT h2 smuggling exploitation
# ---------------------------------------------------------------------------


def _h2c_upgrade_request(host: str) -> bytes:
    """An HTTP/1.1 request that advertises an upgrade to cleartext HTTP/2 (h2c)
    per RFC 7540 §3.2. The ``HTTP2-Settings`` value is a base64url-encoded SETTINGS
    payload; its exact contents are irrelevant to capability detection — we never
    complete the handshake, we only read whether the server AGREES to switch."""
    return (
        f"GET / HTTP/1.1\r\nHost: {host}\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: AAMAAABkAAQAAP__AAIAAAAA\r\n"
        f"\r\n"
    ).encode("latin-1")


def _offers_h2c(data: bytes) -> bool:
    """True iff the response headers advertise an h2c upgrade — an ``Upgrade``
    header whose value names the ``h2c`` token (as sent in a ``101 Switching
    Protocols`` acceptance, or a ``426 Upgrade Required`` advertisement). The
    token must live in an actual ``Upgrade`` header, not merely anywhere in the
    bytes, so a body that happens to mention ``h2c`` cannot false-positive."""
    if not data:
        return False
    head = data.split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    for line in lines[1:]:  # skip the status line
        name, sep, value = line.partition(b":")
        if sep and name.strip().lower() == b"upgrade" and b"h2c" in value.lower():
            return True
    return False


def detect_h2c_upgrade(host: str, port: int, *, timeout: float = 6.0) -> bool:
    """Capability detection ONLY — does the server OFFER a cleartext-HTTP/2 (h2c)
    upgrade? Sends one HTTP/1.1 request advertising ``Upgrade: h2c`` and returns
    True iff the server answers by advertising the h2c upgrade (a ``101 Switching
    Protocols`` carrying ``Upgrade: h2c``, or an equivalent ``Upgrade: h2c``
    advertisement); False otherwise.

    THIS IS NOT HTTP/2 REQUEST SMUGGLING. Genuine h2/h2c desync — h2.CL, h2.TE,
    CRLF-injection into an HTTP/2 header value, ``:path``/``:method`` request
    splitting, h2c tunnelling past a front-end — requires HPACK header compression
    and HTTP/2 binary frame encoding, which the standard library does not provide.
    Faking that would be dishonest, so it is deliberately OUT OF SCOPE here.

    What this DOES establish: h2c is a reachable, smuggling-relevant surface on
    this host — a strong signal to escalate to a purpose-built h2 tool
    (e.g. h2csmuggler) under the engagement charter. What it does NOT do: send a
    single HTTP/2 frame, complete the upgrade handshake, or prove any desync.
    Detection, not exploitation — consistent with the rest of this module."""
    _elapsed_ms, data = raw_send(host, port, _h2c_upgrade_request(host), timeout=timeout)
    return _offers_h2c(data)
