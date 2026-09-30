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
from typing import Any, Callable

from ..verify.confirmation import ConfirmedFinding, confirm_finding
from ..verify.adapter import FindingContext

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # RFC 6455 magic

# The no-engagement (``slug=""``) scan posture: loopback is the ONLY private/loopback address the
# egress floor lifts, mirroring ``scanner.campaign._arsenal_host_allowed``'s no-gate discipline
# (loopback-only, never off-box). It is a STATIC structural constant — NOT re-derived from the
# target or any untrusted lookup (so it is not the allowlist-self-reference trap) — and it lifts
# ONLY the loopback tier: the metadata / link-local / RFC1918 / reserved floor is never liftable
# by it. When an engagement ``slug`` IS threaded, this is unused and the charter's own IP literals
# (``egress_pin.charter_ip_literals``) are the sole lift, exactly as the floor's soundness rule
# requires (an exact charter IP LITERAL sourced from the signed scope).
_LOOPBACK_SCAN_ALLOWED = frozenset({"127.0.0.1", "::1"})


def _probe_http_url(url: str) -> str:
    """Map a ``ws://``/``wss://`` URL to the ``http(s)`` form the scope/charter gate parses.

    ``agents.scope_gate.validate_action`` (and the categorical protected-domain floor) reason over an
    ``http``/``https`` URL; a raw ``ws://`` scheme would be rejected as unparseable. The host/port/path
    are preserved verbatim, so the gate validates the SAME host the socket dials."""
    if url.startswith("wss://"):
        return "https://" + url[len("wss://"):]
    if url.startswith("ws://"):
        return "http://" + url[len("ws://"):]
    return url


def _authorize_ws_name(probe_url: str, slug: str) -> "str | None":
    """The NAME floor for the WS raw socket: return a refusal reason, or ``None`` to proceed.

    Two layers, in ``validate_action``'s own order, both fail-closed:

      * The categorical protected-domain floor (``.gov``/``.mil``/``.edu``/IGO) is charter-INDEPENDENT
        and applies even with no engagement ``slug`` — a protected host is refused with ZERO packets.
      * When an engagement ``slug`` is threaded, the FULL chain must also pass: kill-switch (checked
        first, so a tripped switch halts even an in-scope target), then
        :func:`agents.scope_gate.validate_action` (charter present AND signed, URL parseable, the
        protected-domain NAME floor, host in the signed scope, posture). GET-only method, matching the
        engine's GET-only default.

    Imports are FUNCTION-LOCAL to keep ``scanner.websocket`` importable without pulling the
    agents/authority stack at module load (and to avoid an import cycle). This layer touches ONLY
    ``vigil_core`` + the engine's own ``agents``/``authority`` — never the integration layer (FATAL-2)."""
    try:
        from vigil_core.hard_guardrail import is_hard_blocked, protected_guard_enabled
        if protected_guard_enabled():
            blocked, why = is_hard_blocked(probe_url)
            if blocked:
                return f"protected-domain floor: {why}"
    except Exception as e:  # a floor that errored refuses
        return f"protected-domain floor errored (fail-closed): {type(e).__name__}: {e}"
    if not slug:
        # No engagement context: the categorical floor is the only NAME check (the scan/legacy
        # posture). Signed-scope + kill-switch require a charter, which a slug-less call has none of.
        return None
    try:
        from ..agents.scope_gate import validate_action
        from ..agents.http_executor import parse_posture
        from ..authority import KillSwitch
        if KillSwitch(slug).is_tripped():
            return "kill-switch tripped"
        decision = validate_action(
            slug=slug, method="GET", target_url=probe_url, posture=parse_posture(slug))
        if not decision.allowed:
            return f"scope/charter gate refused: {decision.reason}"
    except Exception as e:  # any gate error is a refusal, never an allow
        return f"name-floor gate errored (fail-closed): {type(e).__name__}: {e}"
    return None


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

    ``response`` is the target's verbatim response HEADER BLOCK — bounded at the
    terminating CRLFCRLF (B3: ``_read_headers`` returns whatever ``recv`` happened to
    deliver, which can include body/frame bytes, and those bytes must not be searched for
    the handshake's markers). ``status_line`` is that block's FIRST line, so a predicate can
    be anchored to the status line instead of matching "http/1.1 101" anywhere in the block.
    ``request`` is the exact block VIGIL sent, so the certificate states which ``Origin`` was
    actually offered. ``accept_key`` is the RFC 6455 ``Sec-WebSocket-Accept`` value VIGIL
    computed from its OWN per-handshake nonce.

    N1 — what the accept key does and does NOT buy. It binds the response to the nonce VIGIL
    chose for THIS handshake, so a SINGLE-FIELD edit of the retained transcript (swap the
    response, keep the key) breaks re-verification. It does NOT bind provenance: re-executing
    an oracle over retained bytes can only ask whether those bytes satisfy the predicate, so
    a CONSISTENTLY rewritten transcript — or a wholly fabricated one, with a key and a
    response computed together — re-verifies ``ok`` even though no target was ever contacted.
    MEASURED, both ways. Binding a certificate to a real exchange is the job of the
    signing / evidence-certificate layer (the signed spine and the DSSE/receipt chain), never
    of re-execution."""

    request: str = ""
    response: str = ""
    status: int | None = None
    status_line: str = ""
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
    slug: str = "",
    resolver: "Callable[..., Any] | None" = None,
) -> tuple["WSConnection | None", Handshake]:
    """Perform the RFC 6455 handshake and return ``(connection_or_None, raw_record)``.

    The connection half is exactly :func:`connect`'s contract; the second half RETAINS
    the raw bytes of the exchange so a check can hand real target bytes to an oracle
    instead of its own boolean.

    CHANNEL FLOOR (defensive, adds a refusal — never reach). Before ANY byte leaves the box this
    raw socket is now floored twice, both fail-closed and returning a zero-packet refusal Handshake:

      * NAME floor — :func:`_authorize_ws_name` (categorical protected-domain floor always; the full
        kill-switch + signed-scope + posture chain when an engagement ``slug`` is threaded).
      * IP floor + anti-rebinding pin — ``common.egress_pin.resolve_and_pin`` resolves the host ONCE,
        refuses a metadata / link-local / RFC1918 / reserved destination (directly OR via a
        DNS-rebinding answer), and returns the exact validated address to DIAL. The socket connects to
        that PINNED IP, never the re-resolvable name; the ``Host`` header and (for ``wss``) the TLS
        ``server_hostname`` keep the ORIGINAL hostname so vhosts/SNI/cert matching are unaffected. The
        metadata/link-local/reserved tier is never liftable; loopback/private lift ONLY for an exact
        charter IP literal from ``slug`` (or, with no slug, the loopback-only scan posture).

    The CSWSH/injection oracle still decides the FACT over the live bytes — this only hardens the
    channel it runs over, mints no FACT, and adds no oracle."""
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

    # NAME floor — refuse a protected/out-of-scope host with ZERO packets (no socket opened).
    name_refusal = _authorize_ws_name(_probe_http_url(url), slug)
    if name_refusal is not None:
        return None, Handshake(request=sent, accept_key=expected_accept,
                               error=f"egress floor refused (name): {name_refusal}")
    # IP floor + anti-rebinding pin — resolve once, refuse metadata/link-local/RFC1918/reserved, and
    # dial the validated address directly. Fail-closed: any refusal/resolve error yields a zero-packet
    # refusal Handshake rather than an unguarded connect.
    try:
        from ..common.egress_pin import resolve_and_pin
        allowed_ips = None if slug else _LOOPBACK_SCAN_ALLOWED
        dial_ip = resolve_and_pin(host, port, slug=slug, allowed_ips=allowed_ips, resolver=resolver)
    except Exception as exc:  # EgressFloorRefused and any other error both fail closed
        return None, Handshake(request=sent, accept_key=expected_accept,
                               error=f"egress floor refused (ip): {type(exc).__name__}: {exc}")

    try:
        sock: socket.socket = socket.create_connection((dial_ip, port), timeout=timeout)
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

    head = _header_block(resp)
    record = Handshake(
        request=sent, response=head.decode("latin-1", "replace"),
        status=_status_of(head) or None,
        status_line=_status_line(head),
        accept_key=expected_accept,
        # The producer's verdict is ALREADY status-line anchored (``_status_of`` reads the
        # status line's own token, not the block). B3: the CSWSH predicate used to throw this
        # away and re-derive the verdict with an unanchored substring match.
        accepted=(_status_of(head) == 101 and expected_accept.encode() in head),
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
    slug: str = "",
    resolver: "Callable[..., Any] | None" = None,
) -> WSConnection | None:
    """Perform the RFC 6455 handshake and return a WSConnection, or None if the
    server refused the upgrade (any non-101 status) OR the channel floor refused the
    destination. ``origin``/``cookies`` model a browser-originated connection for CSWSH
    testing; ``slug`` threads the engagement charter to the egress floor (see :func:`handshake`)."""
    return handshake(url, origin=origin, cookies=cookies,
                     extra_headers=extra_headers, timeout=timeout,
                     slug=slug, resolver=resolver)[0]


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


def _header_block(resp: bytes) -> bytes:
    """Only the response's HEADER BLOCK, through the terminating CRLFCRLF.

    B3 — ``_read_headers`` stops once it has SEEN the terminator but returns the whole recv
    buffer, so body / already-arrived WebSocket frame bytes ride along. Anything retained as
    "the response" is later searched for handshake markers, so it must be the headers and
    nothing else."""
    i = resp.find(b"\r\n\r\n")
    return resp if i < 0 else resp[: i + 4]


def _status_line(resp: bytes) -> str:
    """The response's FIRST line, verbatim — the only place a status may be read from."""
    return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------


def _refused_ctx(bug_class: str, url: str, legit: Handshake, evil: Handshake) -> "FindingContext":
    """The certificate for a CSWSH probe the PRODUCER refused: the two status lines it read,
    with a predicate that is FALSE by construction. It exists so the refusal is still
    re-verifiable evidence (and so ``probe_with_context`` always returns a context)."""
    return FindingContext.from_predicate(
        {"url": url, "refused": "the handshake pair is not two status-line-anchored 101s",
         "trusted_status_line": legit.status_line, "trusted_accepted": legit.accepted,
         "evil_status_line": evil.status_line, "evil_accepted": evil.accepted},
        {"all": [{"eq": [{"var": "trusted_accepted"}, True]},
                 {"eq": [{"var": "evil_accepted"}, True]}]},
        bug_class=bug_class,
    )


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
    slug: str = ""  # engagement slug — threads the charter to the egress floor (see handshake)
    resolver: "Callable[..., Any] | None" = None  # injectable getaddrinfo for the IP floor (tests)

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
        legit, legit_hs = handshake(self.url, origin=trusted, cookies=self.cookies or None,
                                    slug=self.slug, resolver=self.resolver)
        with _closing(legit):
            pass
        evil, evil_hs = handshake(self.url, origin=self.evil_origin, cookies=self.cookies or None,
                                  slug=self.slug, resolver=self.resolver)
        with _closing(evil):
            pass
        # B3 — the PRODUCER's verdict is status-line anchored (``_status_of`` reads the
        # status line's own token). Refuse before building a certificate when either
        # handshake was not actually a 101 carrying VIGIL's own accept key. This can only
        # DEMOTE: the oracle below still has to agree over the retained bytes.
        if not (legit_hs.accepted and evil_hs.accepted):
            return None, _refused_ctx(self.bug_class, self.url, legit_hs, evil_hs)
        ctx = FindingContext.from_predicate(
            {
                "url": self.url,
                "trusted_origin": trusted,
                "evil_origin": self.evil_origin,
                "trusted_origin_header": f"Origin: {trusted}",
                "evil_origin_header": f"Origin: {self.evil_origin}",
                "trusted_request": legit_hs.request,
                "trusted_response": legit_hs.response,
                "trusted_status_line": legit_hs.status_line,
                "trusted_accept_key": legit_hs.accept_key,
                "evil_request": evil_hs.request,
                "evil_response": evil_hs.response,
                "evil_status_line": evil_hs.status_line,
                "evil_accept_key": evil_hs.accept_key,
            },
            {"all": [
                # The endpoint really is a live, working WebSocket for the trusted origin ...
                {"icontains": [{"var": "trusted_request"}, {"var": "trusted_origin_header"}]},
                # ... and it said so ON THE STATUS LINE. B3: these two clauses used to read
                # ``{"icontains": [{"var": "trusted_response"}, "http/1.1 101"]}`` over the
                # WHOLE retained block, so a server answering ``HTTP/1.1 403 Forbidden`` whose
                # headers merely CONTAIN the substring "HTTP/1.1 101 Switching Protocols" (and
                # the computed accept value) satisfied them — measured, BASE 0 findings vs
                # HEAD 1 finding at conf 0.9. ``*_status_line`` is by construction the
                # response's FIRST line AT PRODUCTION TIME; the companion ``contains`` clause
                # pins that line to the retained block, so editing the status line alone out
                # of a certificate breaks re-verification.
                #
                # Audit-A red-pen (B3 offline residual) — "a match inside it is anchored" is
                # true only at PRODUCTION time, NOT at re-verification. Re-execution reads
                # ``trusted_status_line`` as a plain string, so a HAND-EDITED certificate
                # carrying ``"HTTP/1.1 403 Forbidden  http/1.1 101"`` (consistently mirrored
                # into ``trusted_response``) re-verifies ``ok`` — measured. It is unreachable
                # live because the producer gate above reads the status line's OWN token via
                # ``_status_of`` and refuses anything that is not a real 101; this is exactly
                # the limit ``Handshake``'s N1 note states, and binding a certificate to a
                # real exchange is the signing layer's job, never re-execution's. That gate
                # is therefore load-bearing, and
                # ``test_block4_cswsh_producer_refusal_is_load_bearing`` pins a LIVE origin
                # (a 403 whose verbose reason phrase itself contains "HTTP/1.1 101 Switching
                # Protocols", echoing VIGIL's own accept key) on which EVERY clause below
                # holds and only the producer refuses.
                {"icontains": [{"var": "trusted_status_line"}, "http/1.1 101"]},
                {"contains": [{"var": "trusted_response"}, {"var": "trusted_status_line"}]},
                {"contains": [{"var": "trusted_response"}, {"var": "trusted_accept_key"}]},
                # ... and it ALSO switched protocols for a request that offered a FOREIGN
                # Origin, so Origin is not validated. The accept key binds each response to
                # VIGIL's own nonce for THAT handshake, so a SINGLE-FIELD edit of the retained
                # transcript fails (it cannot bind provenance — see ``Handshake``'s N1 note).
                {"icontains": [{"var": "evil_request"}, {"var": "evil_origin_header"}]},
                {"icontains": [{"var": "evil_status_line"}, "http/1.1 101"]},
                {"contains": [{"var": "evil_response"}, {"var": "evil_status_line"}]},
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
    slug: str = ""  # engagement slug — threads the charter to the egress floor (see handshake)
    resolver: "Callable[..., Any] | None" = None  # injectable getaddrinfo for the IP floor (tests)

    def probe(self) -> ConfirmedFinding | None:
        conn = connect(self.url, origin=self.origin, cookies=self.cookies or None,
                       slug=self.slug, resolver=self.resolver)
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
