"""Log injection on the egress proxy's refusal / allow lines (`proxy.py`: DROP CONNECT / DROP HTTP / ALLOW /
"proxy error").

The proxy logs the host the CLIENT asked for, and the client is the sandboxed agent this proxy exists to
contain (client auth is off by default). `_split_authority` / `urlsplit` do not validate the host, so ESC,
NUL and DEL reached the WARNING line raw (terminal escape injection) and a 60 kB host became one 60 kB line.
The CLI's JSON handler escapes C0 controls but not the length, and any other handler got the raw bytes. The
LOGGED copy is now escaped (injectively — the backslash too) and capped; the refusal response and the
security decision are unchanged. These tests drive the REAL proxy over a raw socket and assert on the
emitted records."""
from __future__ import annotations

import asyncio
import logging
import re
import socket

from vigil_gateway import denylist, proxy
from vigil_gateway.proxy import EgressProxy
from vigil_gateway.scope_source import StaticScopeSource

_LOGGER = "vigil.gateway.proxy"


def _resolver(mapping):
    def r(host, port):
        if host not in mapping:
            raise socket.gaierror(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port or 0)) for ip in mapping[host]]
    return r


def _send_all(requests: list[bytes]) -> list[bytes]:
    async def scenario():
        p = EgressProxy(StaticScopeSource(["target.test"]),
                        resolver=_resolver({"target.test": ["93.184.216.34"]}), refresh_allowed_ips=False)
        server = await p.serve("127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        out = []
        try:
            for req in requests:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(req)
                await writer.drain()
                out.append(await reader.read())
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
        finally:
            server.close()
            await server.wait_closed()
        return out
    return asyncio.run(scenario())


def _records(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.name == _LOGGER and r.getMessage().startswith(("DROP", "ALLOW", "proxy error"))]


def _assert_inert(line: str) -> None:
    bad = [hex(ord(ch)) for ch in line if not ch.isprintable()]
    assert not bad, f"non-printable characters reached the proxy log: {bad} in {line!r}"


_PEER = r"\('127\.0\.0\.1', \d+\)"


def test_control_bytes_in_a_connect_host_are_escaped_at_the_port_gate(caplog):
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        resp, = _send_all([b"CONNECT evil\x1b[1A\x1b[2K\x00\x7f:22 HTTP/1.1\r\nHost: x\r\n\r\n"])
    assert resp.startswith(b"HTTP/1.1 403"), resp
    lines = _records(caplog)
    assert len(lines) == 1, lines
    _assert_inert(lines[0])
    assert re.fullmatch(r"DROP CONNECT evil\\x1b\[1A\\x1b\[2K\\x00\\x7f:22 from " + _PEER
                        + r" — port not in allowlist \[80, 443, 8080, 8443\]", lines[0]), lines[0]


def test_control_bytes_in_a_connect_host_are_escaped_at_the_scope_gate(caplog):
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        resp, = _send_all([b"CONNECT evil\x1b[2J\x7f:443 HTTP/1.1\r\nHost: x\r\n\r\n"])
    assert resp.startswith(b"HTTP/1.1 403"), resp
    lines = _records(caplog)
    assert len(lines) == 1, lines
    _assert_inert(lines[0])
    assert lines[0].startswith("DROP CONNECT evil\\x1b[2J\\x7f:443 from "), lines[0]
    assert "is not in the charter scope" in lines[0]


def test_control_bytes_in_an_absolute_form_host_are_escaped(caplog):
    # ESC c (terminal reset), BEL, DEL — no "[" (urlsplit would refuse it as a malformed IPv6 literal).
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        resps = _send_all([b"GET http://evil\x1bc\x07\x7f.test:22/ HTTP/1.1\r\n\r\n",
                           b"GET http://evil\x1bc\x07.test/ HTTP/1.1\r\n\r\n"])
    assert all(r.startswith(b"HTTP/1.1 403") for r in resps), resps
    lines = _records(caplog)
    assert len(lines) == 2, lines
    for line in lines:
        _assert_inert(line)
    assert re.fullmatch(r"DROP HTTP evil\\x1bc\\x07\\x7f\.test:22 from " + _PEER
                        + r" — port not in allowlist \[80, 443, 8080, 8443\]", lines[0]), lines[0]
    # the scope reason already carries repr(host); its backslashes are escaped again (injective, reversible).
    assert re.fullmatch(r"DROP HTTP evil\\x1bc\\x07\.test:80 from " + _PEER
                        + r" — host 'evil\\x5cx1bc\\x5cx07\.test' is not in the charter scope",
                        lines[1]), lines[1]


def test_an_exception_message_that_echoes_client_bytes_is_capped(caplog):
    # an absolute-form URL with a non-numeric port raises inside urlsplit().port, and the message echoes
    # the whole port: a 60 kB port was one 60 kB "proxy error" line.
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        resp, = _send_all([b"GET http://target.test:" + b"9x" * 30000 + b"/ HTTP/1.1\r\n\r\n"])
    assert resp.startswith(b"HTTP/1.1 403"), resp
    lines = _records(caplog)
    assert len(lines) == 1, [x[:80] for x in lines]
    _assert_inert(lines[0])
    assert lines[0].startswith("proxy error from ") and "9x9x9x" in lines[0], lines[0][:120]
    assert len(lines[0]) < 1200, f"a 60 kB port was logged as a {len(lines[0])}-character line"


def test_an_oversized_host_is_capped(caplog):
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        _send_all([b"CONNECT " + b"A" * 60000 + b":22 HTTP/1.1\r\n\r\n",
                   b"CONNECT " + b"B" * 60000 + b":443 HTTP/1.1\r\n\r\n"])
    lines = _records(caplog)
    assert len(lines) == 2, [x[:80] for x in lines]
    for line in lines:
        assert len(line) < 1200, f"a 60 kB host was logged as a {len(line)}-character line"
    assert "A" * 150 in lines[0] and "port not in allowlist" in lines[0]
    assert "B" * 150 in lines[1] and lines[1].startswith("DROP CONNECT ")


def test_control_bytes_in_an_allowed_wildcard_host_are_escaped(caplog, monkeypatch):
    # a `*.target.test` charter admits `evil<ESC>c<BEL>.target.test`, so the ALLOW lines see client bytes too.
    # The echo upstream is on loopback (hard-denied), so the denylist is patched for THIS test only, exactly
    # as the allow-plumbing test in test_proxy_gate does; the decision itself is covered there.
    monkeypatch.setattr(denylist, "is_egress_denied", lambda ip, allowed_ips=None: (False, "test-allow"))
    host = b"evil\x1bc\x07.target.test"

    async def scenario():
        async def echo(reader, writer):
            writer.write(await reader.read(1024))
            await writer.drain()
            writer.close()
        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        echo_port = echo_server.sockets[0].getsockname()[1]
        p = EgressProxy(StaticScopeSource(["*.target.test"]), refresh_allowed_ips=False,
                        resolver=lambda h, port: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))],
                        allowed_ports=frozenset({echo_port}))
        server = await p.serve("127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            for req in (b"CONNECT %s:%d HTTP/1.1\r\n\r\nping" % (host, echo_port),
                        b"GET http://%s:%d/ HTTP/1.1\r\n\r\n" % (host, echo_port)):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(req)
                await writer.drain()
                await reader.read()
                writer.close()
        finally:
            server.close()
            await server.wait_closed()
            echo_server.close()
            await echo_server.wait_closed()
        return echo_port

    with caplog.at_level(logging.INFO, logger=_LOGGER):
        echo_port = asyncio.run(scenario())
    lines = _records(caplog)
    assert len(lines) == 2, lines
    for line in lines:
        _assert_inert(line)
    assert re.fullmatch(r"ALLOW CONNECT evil\\x1bc\\x07\.target\.test:%d→127\.0\.0\.1 from %s"
                        % (echo_port, _PEER), lines[0]), lines[0]
    assert re.fullmatch(r"ALLOW HTTP evil\\x1bc\\x07\.target\.test:%d→127\.0\.0\.1 from %s"
                        % (echo_port, _PEER), lines[1]), lines[1]


def test_a_legitimate_refusal_line_is_unchanged(caplog):
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        _send_all([b"CONNECT target.test:22 HTTP/1.1\r\n\r\n", b"CONNECT other.test:443 HTTP/1.1\r\n\r\n"])
    lines = _records(caplog)
    assert len(lines) == 2, lines
    assert re.fullmatch(r"DROP CONNECT target\.test:22 from " + _PEER
                        + r" — port not in allowlist \[80, 443, 8080, 8443\]", lines[0]), lines[0]
    assert re.fullmatch(r"DROP CONNECT other\.test:443 from " + _PEER
                        + r" — host 'other\.test' is not in the charter scope", lines[1]), lines[1]


def test_log_safe_is_injective_capped_and_leaves_printable_text_alone():
    f = proxy._log_safe
    out = f("a\rb\nc\x0bd\x1be\x00f\x7fg\x85h\u2028i\u202ej\U000e0001k")
    assert out.isprintable() and len(out.splitlines()) == 1
    assert out == "a\\x0db\\x0ac\\x0bd\\x1be\\x00f\\x7fg\\x85h\\u2028i\\u202ej\\U000e0001k"
    assert f("\\") == "\\x5c" and f("x\x1bB") != f("x\\x1bB")          # injective
    for ok in ("target.test", "93.184.216.34", "2001:db8::1", "host 'a.test' is not in the charter scope"):
        assert f(ok) == ok
    assert f(None) == "None" and f(ValueError("bad\nport")) == "bad\\x0aport"
    capped = f("H" * 5000)
    assert len(capped) < 240 and capped.startswith("H" * 200) and "4800" in capped
    assert f("C" * 200) == "C" * 200
