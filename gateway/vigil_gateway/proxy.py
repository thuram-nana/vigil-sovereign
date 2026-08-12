"""
proxy — the host-side filtering forward proxy (L7 egress enforcement).

The offense sandbox is directed here for all HTTP/HTTPS egress. Unlike Strix's in-sandbox
Caido proxy (which the agent can reconfigure or bypass), this proxy runs OUTSIDE the
sandbox's control, on the host/gateway side, and refuses out-of-scope or unsafe
destinations before a single byte reaches them. It is one of two enforcement layers: the
nftables layer (netfilter.py) is the L3/L4 boundary that a proxy bug or a proxy-env unset
cannot cross; this proxy is the L7 policy that understands hostnames and defeats DNS
rebinding.

The security decision is the pure function ``authorize()`` — no sockets, fully unit
testable. Its contract:

  1. The destination host must be in the charter scope (CRUCIBLE ``host_matches_scope``).
  2. The host is resolved ONCE; if ANY resolved address is on the egress denylist
     (metadata/loopback/link-local/reserved, or private-and-not-charter-authorized), the
     whole connection is refused — a legitimate in-scope host does not resolve to the
     instance-metadata service, and refusing on *any* bad answer defeats a DNS-rebinding
     response that mixes a public and an internal address.
  3. The connection is pinned to the exact validated IP (never re-resolved), closing the
     resolve-then-connect TOCTOU that rebinding relies on.

Fail-closed everywhere: an unparseable request, a resolution failure, or any exception
denies. Refusals are logged so the operator can correlate them (OBSIDIAN opsec: the agent
is correlatable, not stealthy).
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Callable

from . import denylist
from .scope_source import ScopeSource

logger = logging.getLogger("vigil.gateway.proxy")

Resolver = Callable[[str, int], list]

_CONNECT_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"
_MAX_HEADER_BYTES = 64 * 1024  # a request head larger than this is refused, not buffered
_DEFAULT_CONNECT_TIMEOUT = 15.0
# A7 hardening defaults ------------------------------------------------------------------
# BOTH CONNECT tunnels AND absolute-form HTTP are gated to these ports, or the proxy becomes a
# generic pivot to any port of an in-scope host (SSH/RDP/SMTP/DB) — reachable via CONNECT
# host:22 OR the absolute-form GET http://host:22/ (red-pen BLOCK-1: gating only CONNECT left
# the HTTP path wide open). Default to the standard web ports; an engagement widens this via
# VIGIL_GATEWAY_ALLOWED_PORTS.
_DEFAULT_ALLOWED_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})
_DEFAULT_HEADER_TIMEOUT = 10.0   # seconds to read the whole request head (slow-loris defence)
_DEFAULT_MAX_CONNECTIONS = 256   # concurrent client connections; refuse (503) beyond this
# Idle timeout for the HTTP response relay: a silent in-scope upstream that accepts then holds
# the connection open would otherwise wedge _do_http forever and never free the connection slot
# (a slow path to 503-for-everyone). Generous, so it does not cut a legitimately-slow response.
_DEFAULT_RESPONSE_IDLE_TIMEOUT = 120.0
# RFC 7230 header field-name = 1*tchar. A valid name contains ONLY these bytes — so any space,
# tab, control char, or other byte before the colon makes it not-a-name and we refuse (a lenient
# upstream that trims such bytes would parse a smuggled header our "name:" checks never saw).
_TCHAR: frozenset[int] = frozenset(
    b"!#$%&'*+-.^_`|~0123456789"
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
_PROXY_AUTH_USER = "vigil"       # the fixed username half of the Basic proxy credential

# The proxy may bind ONLY to an address an operator can see and reach on purpose: loopback,
# an RFC1918 private address, the CGNAT/Tailscale range, or an IPv6 ULA/link-local. A public
# or unspecified (0.0.0.0 / ::) bind is refused — an unauthenticated forward proxy on a public
# interface is an open relay. Mirrors witness_service.bind_ok.
_BIND_ALLOW_NETS: tuple = (
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("10.0.0.0/8"),     # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC1918
    ipaddress.ip_network("192.168.0.0/16"), # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT (Tailscale)
    ipaddress.ip_network("::1/128"),        # loopback
    ipaddress.ip_network("fc00::/7"),       # IPv6 ULA (WireGuard/Tailscale)
    ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
)


def bind_ok(host: str) -> tuple[bool, str]:
    """Whether the forward proxy may bind to ``host``. Fail-closed: refuse anything that is
    not an explicit loopback/private/tunnel IP literal (never a hostname, never public,
    never the unspecified address). Returns ``(ok, reason)``."""
    h = (host or "").strip().strip("[]")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False, f"bind host {host!r} must be an explicit loopback/tunnel IP literal (fail-closed)"
    if ip.is_unspecified:
        return False, (
            f"refusing to bind the forward proxy to {h}: the unspecified address exposes an "
            "unauthenticated proxy on every interface — pin loopback or a tunnel IP"
        )
    if any(ip.version == n.version and ip in n for n in _BIND_ALLOW_NETS):
        return True, f"allowed ({h} is loopback/private/tunnel)"
    return False, (
        f"refusing to bind the forward proxy to the public/non-tunnel address {h}: bind "
        "loopback or a WireGuard/Tailscale/LAN address and firewall the port to the sandbox"
    )


def _refusal_response(reason: str, *, code: int = 403, phrase: str = "Forbidden",
                      extra_headers: bytes = b"") -> bytes:
    body = (f"vigil-gateway refused this request: {reason}\n").encode("utf-8", "replace")
    return (
        f"HTTP/1.1 {code} {phrase}\r\n".encode("ascii")
        + extra_headers
        + b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )


@dataclass(frozen=True)
class ConnectDecision:
    """The verdict for one egress connection request."""

    allowed: bool
    reason: str
    host: str
    port: int
    pinned_ip: str | None  # the exact IP to dial (TOCTOU-safe); None when denied
    family: int | None = None  # socket.AF_INET / AF_INET6 for the pinned IP


def _is_ip_literal(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host.strip().strip("[]"))
    except ValueError:
        return None


def _resolve(host: str, port: int, resolver: Resolver) -> list[tuple[int, str]]:
    """Return [(family, ip), ...] for ``host``. Empty on failure (→ fail-closed deny)."""
    try:
        infos = resolver(host, port or None)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    out: list[tuple[int, str]] = []
    for info in infos:
        family = info[0]
        sockaddr = info[4]
        if sockaddr and sockaddr[0]:
            out.append((family, sockaddr[0]))
    return out


def authorize(
    host: str,
    port: int,
    *,
    scope: ScopeSource,
    allowed_ips: frozenset[str] | None = None,
    resolver: Resolver = socket.getaddrinfo,
) -> ConnectDecision:
    """Pure egress authorization. See module docstring for the contract."""
    host = (host or "").strip().strip("[]")
    if not host:
        return ConnectDecision(False, "empty host (fail-closed)", host, port, None)
    if port <= 0 or port > 65535:
        return ConnectDecision(False, f"invalid port {port}", host, port, None)

    # 1. Charter scope. host_matches_scope handles hostnames, *.wildcards, and IP literals.
    if not scope.matches(host):
        return ConnectDecision(False, f"host {host!r} is not in the charter scope", host, port, None)

    allowed = allowed_ips if allowed_ips is not None else scope.resolved_allowed_ips(resolver=resolver)

    # 2. Enumerate the concrete addresses this connection could reach.
    literal = _is_ip_literal(host)
    if literal is not None:
        candidates = [(socket.AF_INET6 if literal.version == 6 else socket.AF_INET, str(literal))]
    else:
        candidates = _resolve(host, port, resolver)
        if not candidates:
            return ConnectDecision(False, f"host {host!r} did not resolve (fail-closed)", host, port, None)

    # 3. Refuse if ANY resolved address is denied (rebinding defence). Then pin the first
    #    allowed address and dial exactly that one.
    pinned: tuple[int, str] | None = None
    for family, ip in candidates:
        denied, why = denylist.is_egress_denied(ip, allowed)
        if denied:
            return ConnectDecision(
                False,
                f"host {host!r} resolves to a denied address {ip} ({why})",
                host,
                port,
                None,
            )
        if pinned is None:
            pinned = (family, ip)

    assert pinned is not None  # candidates non-empty and none denied
    return ConnectDecision(True, "allowed", host, port, pinned[1], pinned[0])


class EgressProxy:
    """An asyncio forward proxy enforcing :func:`authorize` on every connection."""

    def __init__(
        self,
        scope: ScopeSource,
        *,
        resolver: Resolver = socket.getaddrinfo,
        connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
        refresh_allowed_ips: bool = True,
        proxy_secret: str | None = None,
        allowed_ports: frozenset[int] | None = None,
        header_timeout: float = _DEFAULT_HEADER_TIMEOUT,
        max_connections: int = _DEFAULT_MAX_CONNECTIONS,
    ):
        self.scope = scope
        self.resolver = resolver
        self.connect_timeout = connect_timeout
        self.refresh_allowed_ips = refresh_allowed_ips
        # A7: client authentication (opt-in). When set, every request must carry a matching
        # Proxy-Authorization: Basic header; the credential is stripped before forwarding.
        self._proxy_secret = proxy_secret or None
        # A7: BOTH CONNECT and absolute-form HTTP are restricted to these destination ports
        # (reaching any port would turn the proxy into a generic pivot). None → web default.
        self._allowed_ports = _DEFAULT_ALLOWED_PORTS if allowed_ports is None else frozenset(allowed_ports)
        # A7: bound the head read (slow-loris) and the number of concurrent connections (flood).
        self._header_timeout = header_timeout
        self._max_connections = max_connections
        self._response_idle_timeout = _DEFAULT_RESPONSE_IDLE_TIMEOUT  # HTTP response-relay idle cap
        self._active = 0  # live connection count (single-threaded asyncio; no lock needed)

    def _allowed_ips(self) -> frozenset[str]:
        # Recomputed per connection when refresh is on, so a charter re-sign is honoured
        # mid-engagement. Cheap: it is only the resolved concrete scope hosts.
        return self.scope.resolved_allowed_ips(resolver=self.resolver)

    async def _read_head(self, reader: asyncio.StreamReader) -> bytes | None:
        """Read up to the end of the HTTP request head. None if malformed/oversized."""
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            if len(buf) > _MAX_HEADER_BYTES:
                return None
            chunk = await reader.read(4096)
            if not chunk:
                return bytes(buf) if buf else None
            buf.extend(chunk)
        return bytes(buf)

    def decide(self, host: str, port: int) -> ConnectDecision:
        return authorize(
            host,
            port,
            scope=self.scope,
            allowed_ips=self._allowed_ips() if self.refresh_allowed_ips else None,
            resolver=self.resolver,
        )

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        # A7: refuse immediately (do not queue) once at capacity, so a flood or a pile of
        # slow-loris connections cannot exhaust memory/file descriptors.
        if self._active >= self._max_connections:
            logger.warning("REFUSE at capacity (%d) from %s", self._max_connections, peer)
            with _suppress():
                writer.write(_refusal_response("proxy at capacity", code=503,
                                               phrase="Service Unavailable"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            return
        self._active += 1
        try:
            # A7: bound the head read — a slow-loris that never sends the terminating blank
            # line otherwise holds a coroutine (and its socket) open indefinitely.
            try:
                head = await asyncio.wait_for(self._read_head(reader), timeout=self._header_timeout)
            except asyncio.TimeoutError:
                await self._deny(writer, "request header read timed out (slow-loris defence)")
                return
            if not head:
                await self._deny(writer, "malformed or empty request")
                return
            # A7 (red-pen BLOCK-2a/2b): reject a request head that contains a bare CR or bare
            # LF. Our header parser splits on \r\n, but a lenient upstream may split on a bare
            # \n, so a value like "X: a\nHost: evil" would smuggle a second Host (or re-inject
            # the stripped Proxy-Authorization) past our line-start checks. Require strict CRLF
            # framing in the header section (the body after \r\n\r\n is opaque and exempt).
            _sep = head.find(b"\r\n\r\n")
            _hdr_section = head if _sep == -1 else head[:_sep]
            _stripped = _hdr_section.replace(b"\r\n", b"")
            if b"\n" in _stripped or b"\r" in _stripped:
                await self._deny(writer, "malformed header framing: a bare CR or LF is a "
                                         "request-smuggling vector (strict CRLF required)")
                return
            # A7 (re-red-pen BLOCK): reject any header line whose field-name is not a single
            # whitespace-free token immediately before its colon — i.e. "Host :", "Content-
            # Length\t:", or an obs-fold continuation line. Our Host/TE/CL/credential checks
            # match "name:" at line start, but a lenient upstream (RFC 7230 §3.2.4 says it MUST
            # 400, but accepting is a known desync gadget) may read "name :" as the real header,
            # smuggling a second Host / a chunked TE / a conflicting CL past those checks. Strict
            # framing here makes the proxy the normalizer it claims to be.
            _bad_frame = False
            for _hl in _hdr_section.split(b"\r\n")[1:]:  # skip the request line
                if not _hl:
                    continue
                _c = _hl.find(b":")
                _name = _hl if _c == -1 else _hl[:_c]
                if _c == -1 or not _name or any(b not in _TCHAR for b in _name):
                    _bad_frame = True
                    break
            if _bad_frame:
                await self._deny(writer, "malformed header framing: a header field-name has "
                                         "whitespace or no colon (request-smuggling vector)")
                return
            # A7: authenticate the client BEFORE parsing/dispatching, so an unauthenticated
            # peer learns nothing and reaches no upstream.
            if not self._auth_ok(head):
                await self._deny_proxy_auth(writer)
                logger.warning("REFUSE (proxy auth) from %s", peer)
                return
            line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = line.split()
            if len(parts) < 3:
                await self._deny(writer, "malformed request line")
                return
            method, target = parts[0].upper(), parts[1]
            # Bytes the client coalesced after the head (a request body, or the first tunnel
            # bytes) must be forwarded once the connection is authorized — never dropped.
            sep = head.find(b"\r\n\r\n")
            leftover = head[sep + 4:] if sep != -1 else b""

            if method == "CONNECT":
                host, port = self._split_authority(target, default_port=443)
                await self._do_connect(reader, writer, host, port, peer, leftover)
            else:
                host, port, rewritten, content_length, herr = self._parse_absolute(method, target, head)
                if herr is not None:
                    await self._deny(writer, herr)
                    return
                await self._do_http(reader, writer, host, port, rewritten, content_length, peer, leftover)
        except Exception as exc:  # fail-closed: never leak a half-open tunnel on error
            logger.warning("proxy error from %s: %s", peer, exc)
            with _suppress():
                await self._deny(writer, "internal proxy error")
        finally:
            self._active -= 1
            with _suppress():
                writer.close()
                await writer.wait_closed()

    def _auth_ok(self, head: bytes) -> bool:
        """A7: constant-time check of a ``Proxy-Authorization: Basic`` credential. No secret
        configured → auth disabled (returns True). A missing or malformed credential → False."""
        if not self._proxy_secret:
            return True
        expected = base64.b64encode(
            f"{_PROXY_AUTH_USER}:{self._proxy_secret}".encode("utf-8")
        ).decode("ascii")
        head_part = head.split(b"\r\n\r\n", 1)[0]
        for raw in head_part.split(b"\r\n")[1:]:
            if raw.lower().startswith(b"proxy-authorization:"):
                val = raw.split(b":", 1)[1].strip()
                scheme, _, cred = val.partition(b" ")
                if scheme.lower() != b"basic" or not cred:
                    return False
                return hmac.compare_digest(cred.strip().decode("latin-1", "replace"), expected)
        return False

    async def _refuse_port(self, writer, kind: str, host, port, peer) -> None:
        logger.warning("DROP %s %s:%s from %s — port not in allowlist %s",
                       kind, host, port, peer, sorted(self._allowed_ports))
        await self._deny(
            writer,
            f"{kind} to port {port} is not allowed; the gateway permits only "
            f"{sorted(self._allowed_ports)} (set VIGIL_GATEWAY_ALLOWED_PORTS to widen)",
        )

    async def _do_connect(self, reader, writer, host, port, peer, leftover: bytes = b"") -> None:
        # A7: a CONNECT tunnel is opaque, so its port must be on the allowlist or the proxy
        # becomes a generic pivot (SSH/RDP/SMTP/DB) to any port of an in-scope host.
        if port not in self._allowed_ports:
            await self._refuse_port(writer, "CONNECT", host, port, peer)
            return
        decision = self.decide(host, port)
        if not decision.allowed:
            logger.warning("DROP CONNECT %s:%s from %s — %s", host, port, peer, decision.reason)
            await self._deny(writer, decision.reason)
            return
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(host=decision.pinned_ip, port=port),
                timeout=self.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            await self._deny(writer, f"upstream connect failed: {exc}")
            return
        logger.info("ALLOW CONNECT %s:%s→%s from %s", host, port, decision.pinned_ip, peer)
        writer.write(_CONNECT_ESTABLISHED)
        await writer.drain()
        if leftover:  # first tunnel bytes the client coalesced with the CONNECT line
            up_writer.write(leftover)
            await up_writer.drain()
        await self._pump(reader, writer, up_reader, up_writer)

    async def _do_http(self, reader, writer, host, port, rewritten_head, content_length, peer,
                       leftover: bytes = b"") -> None:
        # A7 (red-pen BLOCK-1): the absolute-form path is port-gated too, not just CONNECT.
        if port not in self._allowed_ports:
            await self._refuse_port(writer, "HTTP", host, port, peer)
            return
        decision = self.decide(host, port)
        if not decision.allowed:
            logger.warning("DROP HTTP %s:%s from %s — %s", host, port, peer, decision.reason)
            await self._deny(writer, decision.reason)
            return
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(host=decision.pinned_ip, port=port),
                timeout=self.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            await self._deny(writer, f"upstream connect failed: {exc}")
            return
        logger.info("ALLOW HTTP %s:%s→%s from %s", host, port, decision.pinned_ip, peer)
        up_writer.write(rewritten_head)
        # A7 (red-pen BLOCK-2c): forward EXACTLY the declared body and nothing more. Any bytes
        # the client coalesced or sends beyond Content-Length are a pipelined second request
        # that would reach the pinned in-scope IP UNPARSED (bypassing scope + Host binding) —
        # they are dropped, never forwarded. We half-close the upstream write side and relay
        # ONLY upstream→client, so no further client byte can smuggle a second request.
        # KNOWN LIMITATION (non-security): a client that STRICTLY waits for a "100 Continue"
        # before sending an Expect: 100-continue body will stall until header_timeout, then its
        # (empty) body is relayed. We do not synthesise the interim 100 here — the security
        # property (exact Content-Length framing, no pipelined relay) takes precedence over that
        # rarely-used handshake; the offense tooling that uses this proxy sends the body anyway.
        body = leftover[:content_length]
        if body:
            up_writer.write(body)
        await up_writer.drain()
        remaining = content_length - len(body)
        while remaining > 0:
            try:
                chunk = await asyncio.wait_for(reader.read(min(65536, remaining)),
                                               timeout=self._header_timeout)
            except asyncio.TimeoutError:
                break  # a stalled body: stop; the upstream times out / closes on its own
            if not chunk:
                break
            up_writer.write(chunk)
            await up_writer.drain()
            remaining -= len(chunk)
        with _suppress():
            up_writer.write_eof()
        await self._pump_one(up_reader, writer)
        with _suppress():  # release the upstream fd (the response relay only closes the client)
            up_writer.close()

    async def _pump_one(self, src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        """Relay src→dst only (the upstream response) — never dst→src. Used for absolute-form
        HTTP so a pipelined second client request can never reach the upstream unparsed. The read
        is idle-bounded so a silent upstream cannot wedge the connection (and its slot) forever."""
        try:
            while True:
                try:
                    data = await asyncio.wait_for(src.read(65536), timeout=self._response_idle_timeout)
                except asyncio.TimeoutError:
                    break  # silent upstream: stop waiting so the slot frees (fail-closed)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (OSError, ConnectionError):
            pass
        finally:
            with _suppress():
                dst.close()

    @staticmethod
    def _split_authority(authority: str, *, default_port: int) -> tuple[str, int]:
        authority = authority.strip()
        if authority.startswith("["):  # [ipv6]:port
            host, _, rest = authority[1:].partition("]")
            port = int(rest.lstrip(":")) if rest.lstrip(":").isdigit() else default_port
            return host, port
        if authority.count(":") == 1:
            host, _, p = authority.partition(":")
            return host, (int(p) if p.isdigit() else default_port)
        return authority, default_port  # bare host or bare IPv6 literal

    def _parse_absolute(self, method: str, target: str, head: bytes):
        """Rewrite an absolute-form request (GET http://h/p) to origin-form for upstream.

        Returns ``(host, port, rewritten_head, content_length, error)``. On any parse failure,
        a Host-header that does not match the URL authority (A7 vhost-confusion), or an
        unsafe/ambiguous body framing (chunked / conflicting Content-Length), returns
        ``(None, None, None, 0, <reason>)`` so the caller refuses.
        """
        from urllib.parse import urlsplit

        if "://" not in target:
            return None, None, None, 0, "only absolute-form HTTP or CONNECT is proxied"
        u = urlsplit(target)
        host = u.hostname
        if not host:
            return None, None, None, 0, "unparseable absolute-form URL"
        port = u.port or 80
        path = u.path or "/"
        if u.query:
            path += "?" + u.query

        # A7 Host-header binding: the URL authority is what was scope-checked and IP-pinned.
        # A client-supplied Host naming a DIFFERENT host is an attempt to reach a co-hosted
        # virtual service off-scope on the same IP — refuse it. We then emit exactly one
        # canonical Host so the upstream can never see a conflicting pair.
        canon = (host.lower(), port)
        # Split off the body: leftover bytes after the head are forwarded separately.
        head_only = head.split(b"\r\n\r\n", 1)[0]
        header_lines = head_only.split(b"\r\n")[1:]  # drop the request line
        drop = (b"proxy-connection:", b"connection:", b"host:",
                b"proxy-authorization:", b"proxy-authenticate:")
        kept: list[bytes] = []
        content_lengths: set[int] = set()
        for raw in header_lines:
            low = raw.lower()
            if low.startswith(b"host:"):
                val = raw.split(b":", 1)[1].strip().decode("latin-1", "replace")
                if self._normalize_host(val, port) != canon:
                    return None, None, None, 0, (
                        f"Host header {val!r} does not match the request URL host {host!r} "
                        "(co-hosted virtual-service scope-evasion refused)"
                    )
                continue  # replaced by the canonical Host below
            if low.startswith(b"transfer-encoding:"):
                # A7 (BLOCK-2c): a chunked body cannot be length-framed, so we could not tell
                # where it ends vs a pipelined request. Refuse chunked; drop any other TE and
                # rely on Content-Length for framing.
                if b"chunked" in low:
                    return None, None, None, 0, ("chunked request bodies are not proxied "
                                                 "(anti-smuggling; fail-closed)")
                continue
            if low.startswith(b"content-length:"):
                digits = raw.split(b":", 1)[1].strip()
                if not digits.isdigit():
                    return None, None, None, 0, "invalid Content-Length header (fail-closed)"
                content_lengths.add(int(digits))
                continue  # re-emitted as ONE canonical Content-Length below
            if any(low.startswith(d) for d in drop):
                continue
            kept.append(raw)
        if len(content_lengths) > 1:
            # Conflicting Content-Length values are a classic request-smuggling desync.
            return None, None, None, 0, "conflicting Content-Length headers (anti-smuggling)"
        content_length = next(iter(content_lengths), 0)
        canon_host_hdr = host if port == 80 else f"{host}:{port}"
        out = [
            f"{method} {path} HTTP/1.1".encode("latin-1"),
            f"Host: {canon_host_hdr}".encode("latin-1"),
            *kept,
        ]
        if content_lengths:  # re-emit exactly one canonical Content-Length
            out.append(f"Content-Length: {content_length}".encode("latin-1"))
        out += [
            b"Connection: close",  # force close: no keep-alive framing to reason about
            b"",
            b"",
        ]
        return host, port, b"\r\n".join(out), content_length, None

    @staticmethod
    def _normalize_host(value: str, default_port: int) -> tuple[str, int]:
        """Normalise a Host-header / authority value to ``(lowercased-host, port)`` for a
        case- and port-insensitive comparison against the URL authority."""
        v = value.strip()
        if v.startswith("["):  # [ipv6]:port
            h, _, rest = v[1:].partition("]")
            p = rest.lstrip(":")
            return h.strip().lower(), (int(p) if p.isdigit() else default_port)
        if v.count(":") == 1:
            h, _, p = v.partition(":")
            return h.strip().lower(), (int(p) if p.isdigit() else default_port)
        return v.lower(), default_port

    async def _pump(self, c_reader, c_writer, u_reader, u_writer) -> None:
        async def one(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (OSError, ConnectionError):
                pass
            finally:
                with _suppress():
                    dst.close()
        await asyncio.gather(one(c_reader, u_writer), one(u_reader, c_writer))

    async def _deny(self, writer: asyncio.StreamWriter, reason: str) -> None:
        writer.write(_refusal_response(reason))
        with _suppress():
            await writer.drain()

    async def _deny_proxy_auth(self, writer: asyncio.StreamWriter) -> None:
        writer.write(_refusal_response(
            "proxy authentication required",
            code=407, phrase="Proxy Authentication Required",
            extra_headers=b'Proxy-Authenticate: Basic realm="vigil-gateway"\r\n',
        ))
        with _suppress():
            await writer.drain()

    async def serve(self, host: str, port: int) -> asyncio.AbstractServer:
        # A7: fail closed before opening a socket if the bind address is public/unspecified —
        # an unauthenticated forward proxy on a public interface is an open relay.
        ok, why = bind_ok(host)
        if not ok:
            raise RuntimeError(f"vigil-gateway proxy bind refused: {why}")
        if not self._proxy_secret:
            logger.warning(
                "vigil-gateway proxy has NO client authentication (VIGIL_GATEWAY_PROXY_TOKEN "
                "unset); rely on the bind address + nftables to keep it reachable only by the sandbox"
            )
        server = await asyncio.start_server(self.handle, host=host, port=port)
        socknames = ", ".join(str(s.getsockname()) for s in server.sockets)
        logger.info("vigil-gateway proxy listening on %s (auth=%s, allowed_ports=%s)",
                    socknames, "on" if self._proxy_secret else "off", sorted(self._allowed_ports))
        return server


class _suppress:
    """A tiny sync/async context manager that swallows benign teardown errors."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True
