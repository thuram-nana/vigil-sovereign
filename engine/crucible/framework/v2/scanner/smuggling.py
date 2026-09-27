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
from .rawhttp import RawResponseReader


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
        # A12: the latency oracle confirms a TIMING ANOMALY, not request smuggling. Timing alone is a LEAD —
        # a normal origin awaiting an incomplete declared body produces the same delay — so this is reported
        # as a low-severity, explicitly-UNCONFIRMED hypothesis, never a "High desync" confirmed exploit.
        confirmed = confirm_finding(
            {"bug_class": "request_smuggling",
             "title": f"{technique} timing anomaly (possible desync — UNCONFIRMED)",
             "severity": "Low", "surface": technique,
             "summary": (f"{technique} probe delayed vs the control — a TIMING LEAD, not proof of smuggling. "
                         f"A normal origin waiting for an incomplete declared body produces the same delay; "
                         f"manual confirmation over a real desync is required before this is an exploit.")},
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
                f"{technique} probe hung {delta:.0f}ms beyond the control — a TIMING LEAD (timing alone does "
                f"not prove smuggling; a server awaiting an incomplete body delays identically)"
                if detected else f"no significant delay ({delta:.0f}ms)"
            ),
        ))
    return results


# ---------------------------------------------------------------------------
# The ACHIEVED-DESYNC differential — the timing-free proof (CWE-444, Wave-4.2)
# ---------------------------------------------------------------------------
#
# Everything above this line is TIMING, and timing is a LEAD: a normal origin that
# merely honours RFC 7230 §3.3.3 (Transfer-Encoding wins over Content-Length) hangs
# waiting for a chunk that never comes, exactly like a desynced one. Audit A12 (#269)
# capped that signal at an UNCONFIRMED Low, and `detect()` above reports it that way.
#
# What follows is the CANARY DIFFERENTIAL, and on this path it is an UNCONFIRMED LEAD —
# NOT a CWE-444 fact. VIGIL opens ONE connection it owns and sends TWO requests. The FIRST
# carries a framing conflict whose smuggled tail is a request to a reflect surface embedding
# a UNIQUE, high-entropy per-probe canary; the SECOND is VIGIL's OWN ordinary follow-up,
# carrying NO canary. On a SECOND VIGIL-owned connection it sends the SAME bytes WELL-FORMED
# (no conflict) plus the SAME follow-up, so the framing conflict is the ONLY variable. If the
# canary comes back in the conflict leg's second response and not in the control leg's, the
# origin treated the smuggled prefix as the start of the next request ON THAT CONNECTION.
#
# WHY THAT IS A LEAD AND NOT A FACT (measured; audit-A red-pen B1). CWE-444 is TWO PARSERS
# DISAGREEING across a trust boundary. This differential is observed on the one connection
# VIGIL itself pipelined the prefix onto, so the "smuggled" request is VIGIL's own request to
# itself and no second parser is involved. A BENIGN SINGLE ORIGIN with no proxy at all —
# preferring Transfer-Encoding over Content-Length (permitted by RFC 9112 6.1) and doing
# ordinary keep-alive pipelining, with a stock path-echoing 404 (the default of Apache httpd,
# Express and Tomcat) — reproduces it exactly. The decisive control: TWO ORDINARY PIPELINED
# REQUESTS with no framing conflict anywhere produce the IDENTICAL canary echo against that
# origin (scanner/tests/test_audit_a_soundness.py::test_b1_plain_pipelining_reproduces_the_
# whole_differential). What the differential actually measures is "does this origin honour
# TE over CL and pipeline the remainder" — ONE parser — not a disagreement between two.
#
# The clause in the old comment that gave it away was "NO victim is poisoned": with no victim
# there is also no evidence of a second hop. So the campaign reports this as an UNCONFIRMED
# LEAD (`WebScanCampaign._smuggling_leads`) and the evidence branch
# `request_smuggling.differential_desync` carries the FACT as named blocking_work.
#
# WHAT WOULD MAKE IT A FACT, and why it is not done here: the corruption must be observed on
# a connection VIGIL did NOT pipeline the prefix onto (poison connection A, observe it on
# connection B). That is sound only if the front-end POOLS connections — and VIGIL cannot
# know whether that pool is shared with real users, so a queued prefix could land in front of
# a third party's request. That is a live victim, which the ROE forbids; it needs explicit
# operator authorisation for a co-tenant-affecting probe. Both requests on both connections
# here are VIGIL's own, on VIGIL's own sockets: nothing is poisoned — and nothing is proven
# about a second parser either.


class DesyncLeg(BaseModel):
    """One leg's RAW second-request response — the bytes the oracle adjudicates."""

    model_config = ConfigDict(extra="forbid")

    channel: bool = Field(default=False, description="A complete response was read for the SECOND request.")
    status: int | None = None
    reason: str = ""
    body: str = ""


class DesyncProbe(BaseModel):
    """One (technique, canary) single-connection capture: both legs' raw second responses.

    Carries NO verdict. The campaign reports a canary differential over these bytes as an
    UNCONFIRMED LEAD (audit-A B1); the gated live re-drive hands the same shape to
    ``smuggling_desync_oracle``. ``note`` explains a leg that established no channel (an
    honest INCONCLUSIVE, never a CLEAN and never a fabricated leak)."""

    model_config = ConfigDict(extra="forbid")

    technique: str
    canary: str
    conflict: DesyncLeg = Field(default_factory=DesyncLeg)
    control: DesyncLeg = Field(default_factory=DesyncLeg)
    note: str = ""

    @property
    def adjudicable(self) -> bool:
        """Both VIGIL-owned second requests read a COMPLETE, well-formed response, so the
        differential exists.

        A plausible status is required on BOTH legs, not just ``channel``: before the shared
        reader was corrected, an UNDER-DECLARED ``Content-Length`` on the first response made
        the surplus bytes (which include a benign echo of the first request, canary and all)
        come back as a "second response" with ``channel=True, status=None``. The reader now
        refuses such a blob outright; this is the producer-side belt-and-braces, because the
        differential must never be computed over bytes that are not a response."""
        return (self.conflict.channel and self.control.channel
                and self.conflict.status is not None and self.control.status is not None)

    @property
    def canary_echo_differential(self) -> bool:
        """The per-probe canary came back in the CONFLICT leg's second response and NOT in the
        WELL-FORMED control leg's — the observation the campaign reports as an UNCONFIRMED
        LEAD (see the section comment above for why it is not a CWE-444 fact)."""
        return (self.adjudicable and bool(self.canary)
                and self.canary in self.conflict.body and self.canary not in self.control.body)


# The framing conflicts driven over the connection VIGIL owns. Kept to the two base
# classes: an obfuscation variant changes only which parser is fooled, and each extra
# technique costs two more connections against the operator's origin.
DESYNC_TECHNIQUES: tuple[str, ...] = ("CL.TE", "TE.CL")

_DESYNC_MAX_RAW = 65536   # bounded read — the differential needs only the first two responses


def _smuggled_prefix(host: str, canary: str) -> str:
    """The smuggled request embedded in the conflict leg's first request: a GET to a
    reflect surface carrying the UNIQUE per-probe canary. If the back-end desyncs, this
    is served as VIGIL's OWN second response on the socket, echoing the canary.

    The ``/vigil-*`` path shapes are deliberately the SAME ones the gated live re-drive
    (``vigil_integration.live.smuggling_redrive``) uses, so ONE set of fixtures
    (``eval.benchmark_app.serve_smuggling_{desync,benign,reflect_error}``) exercises both
    producers: the positive, the safe twin and the echo-the-request red-pen twin."""
    return (f"GET /vigil-reflect?c={canary} HTTP/1.1\r\nHost: {host}\r\n"
            f"X-Vigil-Canary: {canary}\r\nConnection: keep-alive\r\n\r\n")


def _desync_follow_up(host: str) -> bytes:
    """VIGIL's OWN DISTINCT second request, actually sent on the SAME socket after the
    first response has been fully consumed. It deliberately carries NO canary: if ITS
    genuine response echoes the per-probe canary, that canary can ONLY have come from the
    leftover smuggled prefix a desynced back-end prepended to it — never from an endpoint
    that merely reflects this request's own bytes."""
    return f"GET /vigil-follow HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("latin-1")


def _desync_conflict_first(technique: str, host: str, canary: str) -> bytes:
    """The CONFLICT leg's first request: a CL/TE framing conflict whose smuggled tail is
    :func:`_smuggled_prefix`. ``Connection: keep-alive`` (on BOTH legs, so it is not the
    variable) keeps the socket open for VIGIL's genuine second request."""
    smuggled = _smuggled_prefix(host, canary)
    if technique == "TE.CL":
        body = f"{len(smuggled):x}\r\n{smuggled}\r\n0\r\n\r\n"
        return (f"POST /vigil-start HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
                f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n{body}").encode("latin-1")
    body = f"0\r\n\r\n{smuggled}"
    return (f"POST /vigil-start HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
            f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n\r\n{body}").encode("latin-1")


def _desync_control_first(host: str, canary: str) -> bytes:
    """The CONTROL leg's first request: the SAME reflect surface + the SAME canary, but
    WELL-FORMED (one honest Content-Length, no Transfer-Encoding), so no leftover prefix
    exists. The only variable vs the conflict leg is the framing conflict itself."""
    body = _smuggled_prefix(host, canary)
    return (f"POST /vigil-start HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}").encode("latin-1")


class _RawResponseReader(RawResponseReader):
    """The shared core reader (:mod:`scanner.rawhttp`) with its records typed as
    :class:`DesyncLeg`.

    The ~110-line body that used to live here was DUPLICATED verbatim in
    ``vigil_integration.live.smuggling_redrive`` and carried three framing defects in both
    copies (a 1xx interim returned as a complete response; an under-declared Content-Length
    turning the surplus into "response 2"; unconsumed chunked trailers). ``scanner.rawhttp``
    now owns the framing for THIS path — see it for the measured defects it fixes and
    ``scanner.tests.test_rawhttp_reader`` for the unit tests and the drift guard.

    Audit-A red-pen BLOCK-7a: that last sentence used to read as though the migration were
    complete on every path. It is not. ``vigil_integration/live/smuggling_redrive.py:119``
    STILL DEFINES its own ``class _RawResponseReader`` with the pre-fix framing; that file is
    owned by a concurrent change and is not edited here. The drift guard's ``_PENDING`` /
    ``_PENDING_DIVERGENT`` allowlist is the authority on that outstanding copy and fires the
    day it is migrated."""

    def read_response(self) -> DesyncLeg:      # type: ignore[override]
        return DesyncLeg(**super().read_response())


def _desync_leg(host: str, port: int, first: bytes, follow_up: bytes,
                *, timeout: float) -> tuple[DesyncLeg, str]:
    """Drive ONE fresh socket: send ``first``, CONSUME EXACTLY its first response by that
    response's own framing, then ACTUALLY SEND ``follow_up`` on the SAME socket and read
    ITS genuine response. Returns (second response, note). A connection that does not
    persist past the first response yields ``channel=False`` — an honest INCONCLUSIVE."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return DesyncLeg(), f"connect error (no channel): {type(exc).__name__}"
    try:
        s.settimeout(timeout)
        reader = _RawResponseReader(s)
        s.sendall(first)
        if not reader.read_response().channel:
            return DesyncLeg(), (f"no complete first response observed (no channel to drive the "
                                 f"second request): {reader.last_error}")
        if reader.exhausted:
            return DesyncLeg(), "connection did not persist after the first response — no second request driven"
        s.sendall(follow_up)
        second = reader.read_response()
        # A leg whose SECOND read was not a complete, well-formed response established no
        # channel: the reason (a broken frame, a truncated body, junk where a status line
        # belongs) is carried through so the campaign reports an honest INCONCLUSIVE rather
        # than adjudicating a differential over bytes that are not a response at all.
        return second, ("" if second.channel else f"second response not framed: {reader.last_error}")
    except OSError as exc:
        return DesyncLeg(), f"transport error: {type(exc).__name__}"
    finally:
        try:
            s.close()
        except OSError:
            pass


def detect_desync(
    host: str,
    port: int,
    *,
    techniques: "tuple[str, ...]" = DESYNC_TECHNIQUES,
    timeout: float = 6.0,
    authorize: "Callable[[str], bool] | None" = None,
    canary: "Callable[[], str] | None" = None,
) -> list[DesyncProbe]:
    """Capture the single-connection canary differential for each technique — the
    timing-free OBSERVATION the campaign reports as an UNCONFIRMED LEAD.

    Returns one :class:`DesyncProbe` per technique carrying BOTH legs' RAW second-request
    responses. It renders NO verdict of its own. Read the section comment above before
    wiring this anywhere: the differential is observed on the one connection VIGIL itself
    pipelined the prefix onto, so it cannot distinguish a genuine front-end/back-end desync
    from a single benign origin that honours TE over CL and pipelines the remainder. It is a
    LEAD; the cross-connection FACT is named blocking_work on the evidence branch. ``authorize`` (when given) is
    re-checked before EVERY probe and a falsy/raising gate means no byte leaves the box.
    ``canary`` is injectable for tests; the default mints a fresh high-entropy token per
    probe from ``secrets`` (never the global RNG, which a determinism test seeds)."""
    import secrets

    def _mint() -> str:
        return "crsmug" + secrets.token_hex(13)   # unique, high-entropy, >= 12 alnum chars

    mint = canary or _mint
    origin_url = f"http://{host}:{port}/"
    follow_up = _desync_follow_up(host)
    probes: list[DesyncProbe] = []
    for technique in techniques:
        if authorize is not None:
            try:
                if not authorize(origin_url):
                    continue
            except Exception:       # a gate that raises fails CLOSED
                continue
        token = mint()
        conflict, why_c = _desync_leg(
            host, port, _desync_conflict_first(technique, host, token), follow_up, timeout=timeout)
        if not conflict.channel:
            probes.append(DesyncProbe(technique=technique, canary=token,
                                      note=f"conflict leg: {why_c}"))
            continue
        control, why_k = _desync_leg(
            host, port, _desync_control_first(host, token), follow_up, timeout=timeout)
        probes.append(DesyncProbe(technique=technique, canary=token, conflict=conflict,
                                  control=control,
                                  note=("" if control.channel else f"control leg: {why_k}")))
    return probes


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
