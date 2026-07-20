"""proxy — the L7 enforcement: pure authorize() decisions + real-socket refusals.

Security policy is exercised against the REAL denylist in the pure ``authorize`` tests and
the socket refusal tests. The single ALLOW-plumbing socket test patches the denylist (a
test echo server can only live on loopback, which is correctly hard-denied) so it proves
only that an allowed decision produces a working tunnel — the decision itself is covered by
the pure tests and test_denylist.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from vigil_gateway import denylist, proxy
from vigil_gateway.proxy import EgressProxy, authorize
from vigil_gateway.scope_source import StaticScopeSource


def _resolver(mapping):
    def r(host, port):
        if host not in mapping:
            raise socket.gaierror(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port or 0)) for ip in mapping[host]]
    return r


# --------------------------- pure authorize() (real denylist) ---------------------------

def test_authorize_allows_in_scope_public_and_pins_ip():
    scope = StaticScopeSource(["target.test"])
    d = authorize("target.test", 443, scope=scope, allowed_ips=frozenset(),
                  resolver=_resolver({"target.test": ["93.184.216.34"]}))
    assert d.allowed
    assert d.pinned_ip == "93.184.216.34"   # the exact validated IP is pinned (TOCTOU-safe)


def test_authorize_denies_out_of_scope():
    scope = StaticScopeSource(["target.test"])
    d = authorize("evil.test", 443, scope=scope, allowed_ips=frozenset(),
                  resolver=_resolver({"evil.test": ["93.184.216.34"]}))
    assert not d.allowed and "not in the charter scope" in d.reason


def test_authorize_denies_rebinding_to_metadata():
    # In scope by NAME, but the name resolves to the cloud-metadata address.
    scope = StaticScopeSource(["target.test"])
    d = authorize("target.test", 80, scope=scope, allowed_ips=frozenset(),
                  resolver=_resolver({"target.test": ["169.254.169.254"]}))
    assert not d.allowed and "denied address" in d.reason


def test_authorize_denies_if_any_resolved_ip_denied():
    # A rebinding answer mixes a public and an internal address → refuse the whole thing.
    scope = StaticScopeSource(["target.test"])
    d = authorize("target.test", 443, scope=scope, allowed_ips=frozenset(),
                  resolver=_resolver({"target.test": ["93.184.216.34", "10.0.0.5"]}))
    assert not d.allowed and "denied address" in d.reason


def test_authorize_denies_metadata_ip_literal():
    scope = StaticScopeSource(["169.254.169.254"])  # even if someone lists it
    d = authorize("169.254.169.254", 80, scope=scope, allowed_ips={"169.254.169.254"},
                  resolver=_resolver({}))
    assert not d.allowed


def test_authorize_allows_ip_literal_in_scope_public():
    scope = StaticScopeSource(["93.184.216.34"])
    d = authorize("93.184.216.34", 443, scope=scope, allowed_ips=frozenset(), resolver=_resolver({}))
    assert d.allowed and d.pinned_ip == "93.184.216.34"


def test_authorize_allows_scoped_private_ip():
    # Operator scoped an internal staging host by IP: reachable, but only that exact IP.
    scope = StaticScopeSource(["10.0.0.5"])
    d = authorize("10.0.0.5", 8080, scope=scope, allowed_ips={"10.0.0.5"}, resolver=_resolver({}))
    assert d.allowed


def test_authorize_rejects_bad_inputs():
    scope = StaticScopeSource(["target.test"])
    assert not authorize("", 443, scope=scope, resolver=_resolver({})).allowed
    assert not authorize("target.test", 0, scope=scope, resolver=_resolver({})).allowed
    assert not authorize("target.test", 70000, scope=scope, resolver=_resolver({})).allowed
    # in scope but does not resolve → fail closed
    d = authorize("target.test", 443, scope=scope, allowed_ips=frozenset(), resolver=_resolver({}))
    assert not d.allowed and "did not resolve" in d.reason


# ------------------------------- real-socket enforcement -------------------------------

async def _send_request(port: int, request: bytes, read_bytes: int = 4096) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    data = await reader.read(read_bytes)
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return data


async def _serve_proxy(scope, resolver):
    p = EgressProxy(scope, resolver=resolver)
    server = await p.serve("127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def test_socket_refuses_out_of_scope_connect():
    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"evil.test": ["93.184.216.34"]}))
        try:
            resp = await _send_request(port, b"CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test\r\n\r\n")
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 403"), resp


def test_socket_refuses_rebinding_to_metadata():
    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["169.254.169.254"]}))
        try:
            resp = await _send_request(port, b"CONNECT target.test:80 HTTP/1.1\r\n\r\n")
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 403"), resp


def test_socket_allow_plumbing_tunnels_bytes(monkeypatch):
    # Prove an allowed CONNECT yields a working bidirectional tunnel. The echo upstream is
    # on loopback (hard-denied), so we patch the denylist for THIS test only; the policy is
    # covered by the pure tests above and test_denylist.
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "test-allow"))

    async def scenario():
        # echo upstream
        async def echo(reader, writer):
            data = await reader.read(1024)
            writer.write(data)
            await writer.drain()
            writer.close()
        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        echo_port = echo_server.sockets[0].getsockname()[1]

        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}))
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"CONNECT target.test:{echo_port} HTTP/1.1\r\n\r\n".encode())
            await writer.drain()
            established = await reader.readuntil(b"\r\n\r\n")
            assert established.startswith(b"HTTP/1.1 200"), established
            writer.write(b"ping-through-tunnel")
            await writer.drain()
            echoed = await reader.read(64)
            writer.close()
            return echoed
        finally:
            server.close()
            await server.wait_closed()
            echo_server.close()
            await echo_server.wait_closed()

    echoed = asyncio.run(scenario())
    assert echoed == b"ping-through-tunnel"


def test_socket_forwards_coalesced_leftover(monkeypatch):
    # A client that coalesces the first tunnel bytes into the CONNECT packet must have
    # them forwarded, not dropped (correctness regression guard).
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "test-allow"))

    async def scenario():
        async def echo(reader, writer):
            data = await reader.read(1024)
            writer.write(b"got:" + data)
            await writer.drain()
            writer.close()
        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        echo_port = echo_server.sockets[0].getsockname()[1]
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}))
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # CONNECT line AND first tunnel bytes ("EARLY") in ONE write.
            writer.write(f"CONNECT target.test:{echo_port} HTTP/1.1\r\n\r\nEARLY".encode())
            await writer.drain()
            established = await reader.readuntil(b"\r\n\r\n")
            tunneled = await reader.read(256)  # the echo of the coalesced leftover
            writer.close()
            return established, tunneled
        finally:
            server.close()
            await server.wait_closed()
            echo_server.close()
            await echo_server.wait_closed()

    established, tunneled = asyncio.run(scenario())
    assert established.startswith(b"HTTP/1.1 200")
    assert b"got:EARLY" in tunneled   # the coalesced leftover was forwarded upstream
