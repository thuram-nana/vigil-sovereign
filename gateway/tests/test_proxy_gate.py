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


async def _serve_proxy(scope, resolver, **proxy_kwargs):
    p = EgressProxy(scope, resolver=resolver, **proxy_kwargs)
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
            # Port 443 is on the CONNECT allowlist, so the refusal is the rebinding check, not the port.
            resp = await _send_request(port, b"CONNECT target.test:443 HTTP/1.1\r\n\r\n")
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
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}),
                                          allowed_ports=frozenset({echo_port}))
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
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}),
                                          allowed_ports=frozenset({echo_port}))
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


# =============================== A7 gateway hardening ===================================

import base64  # noqa: E402

from vigil_gateway.proxy import bind_ok  # noqa: E402


async def _send_and_read_all(port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    data = b""
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        data += chunk
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return data


async def _capture_upstream():
    """An upstream that returns the exact request bytes it received (as the response body),
    so a test can assert what the proxy forwarded."""
    captured: dict[str, bytes] = {}

    async def handler(reader, writer):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(4096)
            if not chunk:
                break
            data += chunk
        captured["req"] = data
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(data)).encode()
                     + b"\r\nConnection: close\r\n\r\n" + data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], captured


# --------------------------------- bind_ok (pure) --------------------------------------

def test_bind_ok_allows_loopback_private_tunnel_refuses_public_and_unspecified():
    for ok_host in ("127.0.0.1", "10.1.2.3", "172.16.5.5", "192.168.1.1",
                    "100.100.1.1", "::1", "fd12:3456::1", "fe80::1"):
        assert bind_ok(ok_host)[0], ok_host
    for bad_host in ("0.0.0.0", "::", "8.8.8.8", "1.2.3.4", "example.com", "", "169.254.169.254"):
        assert not bind_ok(bad_host)[0], bad_host


def test_serve_refuses_public_bind():
    async def scenario():
        scope = StaticScopeSource(["target.test"])
        p = EgressProxy(scope, resolver=_resolver({}))
        with pytest.raises(RuntimeError, match="bind refused"):
            await p.serve("0.0.0.0", 0)
    asyncio.run(scenario())


# --------------------------------- Basic proxy-auth ------------------------------------

def test_proxy_auth_required_when_secret_set():
    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["93.184.216.34"]}),
                                          proxy_secret="s3cr3t")
        try:
            resp = await _send_request(port, b"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n")
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 407"), resp
    assert b"Proxy-Authenticate: Basic" in resp, resp


def test_proxy_auth_rejects_wrong_credential():
    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["93.184.216.34"]}),
                                          proxy_secret="s3cr3t")
        try:
            bad = base64.b64encode(b"vigil:wrong").decode()
            resp = await _send_request(
                port, f"CONNECT target.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {bad}\r\n\r\n".encode())
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 407"), resp


def test_http_strips_proxy_credential_and_canonicalises_host(monkeypatch):
    # The proxy credential must never leak upstream, and a single canonical Host must be sent.
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "ok"))

    async def scenario():
        up, up_port, captured = await _capture_upstream()
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}),
                                          proxy_secret="s3cr3t",
                                          allowed_ports=frozenset({up_port}))
        try:
            cred = base64.b64encode(b"vigil:s3cr3t").decode()
            req = (f"GET http://target.test:{up_port}/x?y=1 HTTP/1.1\r\n"
                   f"Host: target.test:{up_port}\r\n"
                   f"Proxy-Authorization: Basic {cred}\r\n"
                   f"Proxy-Connection: keep-alive\r\n"
                   f"User-Agent: probe\r\n\r\n").encode()
            resp = await _send_and_read_all(port, req)
        finally:
            server.close()
            await server.wait_closed()
            up.close()
            await up.wait_closed()
        return resp, captured.get("req", b""), up_port

    resp, upstream_req, up_port = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 200"), resp
    low = upstream_req.lower()
    assert b"proxy-authorization" not in low, upstream_req      # credential stripped
    assert b"proxy-connection" not in low, upstream_req          # hop-by-hop header stripped
    host_lines = [ln for ln in upstream_req.split(b"\r\n") if ln.lower().startswith(b"host:")]
    assert host_lines == [f"Host: target.test:{up_port}".encode()], host_lines
    assert upstream_req.startswith(b"GET /x?y=1 HTTP/1.1"), upstream_req  # origin-form
    assert b"User-Agent: probe" in upstream_req                  # innocuous headers preserved


# --------------------------------- CONNECT port allowlist ------------------------------

def test_connect_to_non_web_port_refused():
    async def scenario():
        scope = StaticScopeSource(["target.test"])   # a PUBLIC IP: only the port gate can refuse
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["93.184.216.34"]}))
        try:
            resp = await _send_request(port, b"CONNECT target.test:22 HTTP/1.1\r\n\r\n")
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 403"), resp
    assert b"port 22 is not allowed" in resp, resp


# --------------------------------- Host-header binding ---------------------------------

def test_http_refuses_mismatched_host_header(monkeypatch):
    # In-scope URL host + a Host header naming a co-hosted vhost on the same IP → refuse.
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "ok"))

    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}))
        try:
            req = (b"GET http://target.test/ HTTP/1.1\r\n"
                   b"Host: admin.internal\r\n\r\n")   # different vhost, same pinned IP
            resp = await _send_request(port, req)
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 403"), resp
    assert b"does not match" in resp, resp


# --------------------------------- slow-loris / flood ----------------------------------

def test_header_read_timeout_denies_slowloris():
    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({}), header_timeout=0.2)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"CONNECT target.test:443 HTTP/1.1\r\n")  # never send the terminating blank line
            await writer.drain()
            resp = await reader.read(4096)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return resp
        finally:
            server.close()
            await server.wait_closed()
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 403"), resp
    assert b"timed out" in resp, resp


def test_at_capacity_refuses_503():
    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["93.184.216.34"]}),
                                          max_connections=1, header_timeout=5.0)
        try:
            # conn1 takes the single slot by starting a head it never finishes.
            r1, w1 = await asyncio.open_connection("127.0.0.1", port)
            w1.write(b"CONNECT target.test:443 HTTP/1.1\r\n")
            await w1.drain()
            await asyncio.sleep(0.2)  # let conn1's handler occupy the slot
            resp2 = await _send_request(port, b"CONNECT target.test:443 HTTP/1.1\r\n\r\n")
            w1.close()
            try:
                await w1.wait_closed()
            except OSError:
                pass
            return resp2
        finally:
            server.close()
            await server.wait_closed()
    resp2 = asyncio.run(scenario())
    assert resp2.startswith(b"HTTP/1.1 503"), resp2


# ===================== A7 red-pen fixes (BLOCK-1 / BLOCK-2 / BLOCK-3) ===================

def test_absolute_form_to_non_web_port_refused():
    # BLOCK-1: the port allowlist gates absolute-form HTTP too, not only CONNECT — otherwise
    # `GET http://host:22/` pivots to SSH/Redis/MySQL despite the CONNECT gate.
    async def scenario():
        scope = StaticScopeSource(["target.test"])   # PUBLIC IP: only the port gate can refuse
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["93.184.216.34"]}))
        try:
            resp = await _send_request(
                port, b"GET http://target.test:22/ HTTP/1.1\r\nHost: target.test:22\r\n\r\n")
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 403"), resp
    assert b"port 22 is not allowed" in resp, resp


def test_bare_lf_in_head_is_refused():
    # BLOCK-2a/2b: a bare LF lets a lenient upstream split "X: a\nHost: evil" into a smuggled
    # second Host (or re-inject the stripped Proxy-Authorization). Strict CRLF → whole-request
    # refusal, so nothing is forwarded.
    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}))
        try:
            req = b"GET http://target.test/ HTTP/1.1\r\nX-Foo: bar\nHost: evil.test\r\n\r\n"
            resp = await _send_request(port, req)
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 403"), resp
    assert b"bare CR or LF" in resp, resp


def test_http_does_not_forward_pipelined_request(monkeypatch):
    # BLOCK-2c: a pipelined second request after the first must NOT reach the pinned upstream
    # unparsed (it would bypass scope + Host binding). A content-length-0 GET drops all leftover.
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "ok"))

    async def scenario():
        up, up_port, captured = await _capture_upstream()
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}),
                                          allowed_ports=frozenset({up_port}))
        try:
            req = (f"GET http://target.test:{up_port}/first HTTP/1.1\r\n"
                   f"Host: target.test:{up_port}\r\n\r\n"
                   f"GET http://evil/secret HTTP/1.1\r\nHost: evil.internal\r\n\r\n").encode()
            await _send_and_read_all(port, req)
        finally:
            server.close()
            await server.wait_closed()
            up.close()
            await up.wait_closed()
        return captured.get("req", b"")
    upstream_req = asyncio.run(scenario())
    assert b"/first" in upstream_req, upstream_req
    assert b"/secret" not in upstream_req, upstream_req       # pipelined request dropped
    assert b"evil" not in upstream_req.lower(), upstream_req   # smuggled Host never forwarded


def test_http_forwards_exact_body_and_drops_trailing(monkeypatch):
    # BLOCK-2c positive: a legitimate Content-Length body is forwarded EXACTLY; any bytes
    # beyond it (a pipelined smuggle) are dropped.
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "ok"))

    async def scenario():
        cap: dict[str, bytes] = {}

        async def handler(reader, writer):
            data = b""
            while b"\r\n\r\n" not in data:
                c = await reader.read(4096)
                if not c:
                    break
                data += c
            head, _, rest = data.partition(b"\r\n\r\n")
            cl = 0
            for ln in head.split(b"\r\n"):
                if ln.lower().startswith(b"content-length:"):
                    cl = int(ln.split(b":", 1)[1].strip())
            body = rest
            while len(body) < cl:
                c = await reader.read(4096)
                if not c:
                    break
                body += c
            cap["head"], cap["body"] = head, body
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()

        up = await asyncio.start_server(handler, "127.0.0.1", 0)
        up_port = up.sockets[0].getsockname()[1]
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}),
                                          allowed_ports=frozenset({up_port}))
        try:
            payload = b"HELLO"
            req = (f"POST http://target.test:{up_port}/ HTTP/1.1\r\n"
                   f"Host: target.test:{up_port}\r\n"
                   f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload + b"GARBAGE-PIPELINED"
            await _send_and_read_all(port, req)
        finally:
            server.close()
            await server.wait_closed()
            up.close()
            await up.wait_closed()
        return cap
    cap = asyncio.run(scenario())
    assert cap.get("body") == b"HELLO", cap                 # exact body forwarded
    assert b"GARBAGE" not in cap.get("body", b""), cap       # trailing pipelined bytes dropped
    assert b"Content-Length: 5" in cap.get("head", b""), cap  # one canonical Content-Length


def test_chunked_request_body_refused(monkeypatch):
    # BLOCK-2c: a chunked body cannot be length-framed → refuse (fail-closed anti-smuggling).
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "ok"))

    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}))
        try:
            req = (b"POST http://target.test/ HTTP/1.1\r\nHost: target.test\r\n"
                   b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
            resp = await _send_request(port, req)
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 403"), resp
    assert b"chunked" in resp, resp


def test_conflicting_content_length_refused(monkeypatch):
    # BLOCK-2c: two different Content-Length values are a classic desync — refuse.
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "ok"))

    async def scenario():
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}))
        try:
            req = (b"POST http://target.test/ HTTP/1.1\r\nHost: target.test\r\n"
                   b"Content-Length: 4\r\nContent-Length: 8\r\n\r\nAAAA")
            resp = await _send_request(port, req)
        finally:
            server.close()
            await server.wait_closed()
        return resp
    resp = asyncio.run(scenario())
    assert resp.startswith(b"HTTP/1.1 403"), resp
    assert b"conflicting Content-Length" in resp, resp


def test_whitespace_before_colon_header_is_refused(monkeypatch):
    # Re-red-pen BLOCK: "Host :" / "Transfer-Encoding\t:" (whitespace before the colon) is not
    # matched by our "name:" checks, and a lenient upstream re-parses it as the real header —
    # smuggling a second Host / chunked TE / conflicting CL. The strict field-name gate refuses
    # the whole request BEFORE it reaches the upstream. Confirm nothing is forwarded.
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "ok"))

    async def scenario(smuggle: bytes):
        up, up_port, captured = await _capture_upstream()
        scope = StaticScopeSource(["target.test"])
        server, port = await _serve_proxy(scope, _resolver({"target.test": ["127.0.0.1"]}),
                                          allowed_ports=frozenset({up_port}))
        try:
            req = (f"GET http://target.test:{up_port}/ HTTP/1.1\r\n"
                   f"Host: target.test:{up_port}\r\n").encode() + smuggle + b"\r\n"
            resp = await _send_request(port, req)
        finally:
            server.close()
            await server.wait_closed()
            up.close()
            await up.wait_closed()
        return resp, captured.get("req", b"")

    for smuggle in (b"Host : evil.internal\r\n",
                    b"Transfer-Encoding : chunked\r\n",
                    b"Content-Length\t: 100\r\n",
                    b" obs-fold-continuation\r\n",
                    b"X\x0cFoo: bar\r\n",          # form-feed in the field-name (exotic WS)
                    b"Content-Length\x0b: 9\r\n"):  # vertical-tab before the colon
        resp, upstream_req = asyncio.run(scenario(smuggle))
        assert resp.startswith(b"HTTP/1.1 403"), (smuggle, resp)
        assert b"whitespace or no colon" in resp, (smuggle, resp)
        assert upstream_req == b"", (smuggle, upstream_req)   # nothing reached the upstream
