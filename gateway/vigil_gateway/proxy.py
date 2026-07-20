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


def _refusal_response(reason: str) -> bytes:
    body = (f"vigil-gateway refused this request: {reason}\n").encode("utf-8", "replace")
    return (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
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
    ):
        self.scope = scope
        self.resolver = resolver
        self.connect_timeout = connect_timeout
        self.refresh_allowed_ips = refresh_allowed_ips

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
        try:
            head = await self._read_head(reader)
            if not head:
                await self._deny(writer, "malformed or empty request")
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
                host, port, rewritten = self._parse_absolute(method, target, head)
                if host is None:
                    await self._deny(writer, "only absolute-form HTTP or CONNECT is proxied")
                    return
                await self._do_http(reader, writer, host, port, rewritten, peer, leftover)
        except Exception as exc:  # fail-closed: never leak a half-open tunnel on error
            logger.warning("proxy error from %s: %s", peer, exc)
            with _suppress():
                await self._deny(writer, "internal proxy error")
        finally:
            with _suppress():
                writer.close()
                await writer.wait_closed()

    async def _do_connect(self, reader, writer, host, port, peer, leftover: bytes = b"") -> None:
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

    async def _do_http(self, reader, writer, host, port, rewritten_head, peer, leftover: bytes = b"") -> None:
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
        if leftover:  # a request body coalesced into the head buffer
            up_writer.write(leftover)
        await up_writer.drain()
        await self._pump(reader, writer, up_reader, up_writer)

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
        """Rewrite an absolute-form request (GET http://h/p) to origin-form for upstream."""
        from urllib.parse import urlsplit

        if "://" not in target:
            return None, None, None
        u = urlsplit(target)
        host = u.hostname
        if not host:
            return None, None, None
        port = u.port or 80
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        rest = head.split(b"\r\n", 1)[1] if b"\r\n" in head else b"\r\n"
        # Strip proxy-hop headers; force close so we need no keep-alive framing.
        new_first = f"{method} {path} HTTP/1.1\r\n".encode("latin-1")
        filtered = self._filter_headers(rest)
        return host, port, new_first + filtered

    @staticmethod
    def _filter_headers(header_block: bytes) -> bytes:
        drop = (b"proxy-connection:", b"connection:")
        out_lines = []
        for raw in header_block.split(b"\r\n"):
            low = raw.lower()
            if any(low.startswith(d) for d in drop):
                continue
            out_lines.append(raw)
        block = b"\r\n".join(out_lines)
        if not block.endswith(b"\r\n\r\n"):
            block = block.rstrip(b"\r\n") + b"\r\nConnection: close\r\n\r\n"
        return block

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

    async def serve(self, host: str, port: int) -> asyncio.AbstractServer:
        server = await asyncio.start_server(self.handle, host=host, port=port)
        socknames = ", ".join(str(s.getsockname()) for s in server.sockets)
        logger.info("vigil-gateway proxy listening on %s", socknames)
        return server


class _suppress:
    """A tiny sync/async context manager that swallows benign teardown errors."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True
