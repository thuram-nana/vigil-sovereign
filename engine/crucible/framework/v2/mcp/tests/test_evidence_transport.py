"""
Module C — the floor-pinned HTTP transport for consuming an operator's external MCP EVIDENCE server
(``mcp.evidence_transport.FloorPinnedHttpTransport``).

These assert the transport's security contract WITHOUT real network I/O:
  * a fake (``MockTransport``) JSON-RPC exchange SUCCEEDS and is shaped as a bounded POST carrying the
    operator's bearer header, and drives cleanly through an ``MCPClient`` (the integrator's path);
  * a ``http://169.254.169.254/`` (cloud-metadata) URL is REFUSED fail-closed before any socket, and a
    charter-scoped hostname that RESOLVES to metadata is refused specifically BY THE NEVER-LIFTABLE
    FLOOR (so putting the name on the allowlist cannot lift it);
  * an off-allowlist host is refused by the NAME control before a byte reaches the inner transport;
  * a redirect is NEVER followed (``follow_redirects=False``);
  * the bearer token never appears in ``repr``; a non-http(s) URL, an oversized request/response, a
    non-2xx status and malformed JSON are all refused without a crash.

No ``vigil_gateway`` dependency: the floor refusals hold under the pure-stdlib backstop too
(``common.egress_pin._stdlib_floor_denied`` mirrors the never-liftable tier), and the success/name/redirect
cases go through an injected ``MockTransport``, so nothing here touches the network.
"""

from __future__ import annotations

import json
import socket

import httpx
import pytest

from framework.v2.agents.egress_guard import EgressAllowlist, SovereignHttpxTransport
from framework.v2.common.errors import SovereigntyViolation
from framework.v2.mcp.client import MCPClient, MCPClientError
from framework.v2.mcp.evidence_transport import FloorPinnedHttpTransport

_SERVER = "mcp.evidence.operator.example"
_URL = f"http://{_SERVER}/mcp"


def _resolver(*addrs: str):
    """A fake getaddrinfo returning the given addresses for any name (mirrors the egress-guard tests)."""
    def fake(host, port, proto=0):  # noqa: ANN001
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, 1, 6, "", (a, port or 0))
                for a in addrs]
    return fake


def _mock(handler):
    return httpx.MockTransport(handler)


def _allow(*hosts: str) -> EgressAllowlist:
    return EgressAllowlist(extra_hosts=hosts or (_SERVER,))


# ----------------------------------------------------------- success + request shaping (fake, no network)


def test_fake_request_succeeds_and_is_a_bounded_bearer_post():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = request.read()
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                         "result": {"tools": [{"name": "fetch_logs"}]}})

    t = FloorPinnedHttpTransport(_URL, _allow(), token="op-secret-123", inner=_mock(handler))
    try:
        resp = t({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    finally:
        t.close()

    assert resp == {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "fetch_logs"}]}}
    assert captured["method"] == "POST"
    assert captured["url"] == _URL
    assert captured["headers"]["authorization"] == "Bearer op-secret-123"
    assert captured["headers"]["content-type"] == "application/json"
    assert json.loads(captured["body"].decode()) == {
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def test_drives_through_mcpclient_as_a_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {
            "content": [], "isError": False, "structuredContent": {"services": []}}})

    t = FloorPinnedHttpTransport(_URL, _allow(), inner=_mock(handler))
    try:
        out = MCPClient(t, name="evidence").call_tool("fetch_logs", {"host": "10.0.0.5"})
    finally:
        t.close()
    assert out["ok"] is True and out["is_error"] is False and out["structured"] == {"services": []}


def test_no_authorization_header_when_no_token():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    t = FloorPinnedHttpTransport(_URL, _allow(), inner=_mock(handler))
    try:
        t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    finally:
        t.close()
    assert "authorization" not in captured["headers"]


# ----------------------------------------------------------- floor refusals (fail-closed, no socket)


def test_metadata_literal_url_is_refused_fail_closed():
    # http://169.254.169.254/ — even with the metadata IP forced onto the name allowlist, the request is
    # refused (fail-closed) before any socket opens. inner=None installs the real floor-pinned backend.
    t = FloorPinnedHttpTransport("http://169.254.169.254/mcp", _allow("169.254.169.254"))
    try:
        with pytest.raises(SovereigntyViolation):
            t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    finally:
        t.close()


def test_scoped_name_resolving_to_metadata_is_refused_by_the_floor():
    # The name IS on the allowlist (the name control passes); it RESOLVES to the metadata IP, so the
    # never-liftable L3/L4 FLOOR is what refuses it — proving the allowlist cannot lift the floor.
    t = FloorPinnedHttpTransport(_URL, _allow(), resolver=_resolver("169.254.169.254"))
    try:
        with pytest.raises(SovereigntyViolation) as exc:
            t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert "egress floor" in str(exc.value).lower()
    finally:
        t.close()


def test_scoped_name_resolving_to_rfc1918_is_refused_by_the_floor():
    t = FloorPinnedHttpTransport(_URL, _allow(), resolver=_resolver("10.0.0.5"))
    try:
        with pytest.raises(SovereigntyViolation):
            t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    finally:
        t.close()


# ----------------------------------------------------------- name control + redirects (fake inner)


def test_off_allowlist_host_is_refused_before_any_byte():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    # The allowlist permits only the evidence server; the URL points elsewhere.
    t = FloorPinnedHttpTransport("http://evil.off-allowlist.example/mcp", _allow(_SERVER),
                                 inner=_mock(handler))
    try:
        with pytest.raises(SovereigntyViolation) as exc:
            t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert "sovereign mode" in str(exc.value).lower()   # the NAME control, not the floor
        assert calls == []                                   # it fired BEFORE the inner transport
    finally:
        t.close()


def test_redirect_is_never_followed():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://elsewhere.example/moved"})

    # elsewhere.example is ALSO on the allowlist, so a follow would NOT be blocked by the name control —
    # proving it is follow_redirects=False (not the allowlist) that stops the hop.
    t = FloorPinnedHttpTransport(_URL, _allow(_SERVER, "elsewhere.example"), inner=_mock(handler))
    try:
        with pytest.raises(MCPClientError) as exc:
            t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert "302" in str(exc.value)
        assert calls == [_URL]          # only the original URL; the redirect target was never requested
    finally:
        t.close()


def test_non_2xx_status_is_an_error_not_a_parsed_result():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "bad token"})

    t = FloorPinnedHttpTransport(_URL, _allow(), inner=_mock(handler))
    try:
        with pytest.raises(MCPClientError) as exc:
            t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert "401" in str(exc.value)
    finally:
        t.close()


# ----------------------------------------------------------- bounds, malformed, URL + token hygiene


def test_oversize_request_is_refused_and_never_sent():
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, json={})

    t = FloorPinnedHttpTransport(_URL, _allow(), inner=_mock(handler), max_bytes=64)
    try:
        with pytest.raises(MCPClientError):
            t({"jsonrpc": "2.0", "id": 1, "method": "x", "params": {"blob": "A" * 500}})
        assert calls == []
    finally:
        t.close()


def test_oversize_response_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"jsonrpc":"2.0","id":1,"result":"' + b"A" * 5000 + b'"}')

    t = FloorPinnedHttpTransport(_URL, _allow(), inner=_mock(handler), max_bytes=256)
    try:
        with pytest.raises(MCPClientError):
            t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    finally:
        t.close()


def test_malformed_response_is_a_structured_error_not_a_crash():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"this is not json")

    t = FloorPinnedHttpTransport(_URL, _allow(), inner=_mock(handler))
    try:
        with pytest.raises(MCPClientError):
            t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    finally:
        t.close()


def test_non_object_json_response_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[1, 2, 3])

    t = FloorPinnedHttpTransport(_URL, _allow(), inner=_mock(handler))
    try:
        with pytest.raises(MCPClientError):
            t({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    finally:
        t.close()


@pytest.mark.parametrize("bad", ["file:///etc/passwd", "ftp://host/x", "not-a-url", "ssh://h", ""])
def test_non_http_url_is_refused_at_construction(bad):
    with pytest.raises(MCPClientError):
        FloorPinnedHttpTransport(bad, _allow())


def test_crlf_in_token_is_refused_at_construction():
    with pytest.raises(MCPClientError):
        FloorPinnedHttpTransport(_URL, _allow(), token="good\r\nX-Injected: 1")


def test_bad_allowlist_type_is_refused_at_construction():
    with pytest.raises(MCPClientError):
        FloorPinnedHttpTransport(_URL, allowlist={"not": "an allowlist"})  # type: ignore[arg-type]


def test_bearer_token_never_appears_in_repr():
    t = FloorPinnedHttpTransport(_URL, _allow(), token="super-secret-token-value",
                                 inner=_mock(lambda r: httpx.Response(200, json={})))
    try:
        assert "super-secret-token-value" not in repr(t)
        assert "<set>" in repr(t)
    finally:
        t.close()


def test_repr_shows_origin_only_never_path_or_query():
    # Redacted to scheme://host[:port] — a path/query (a possible ?api_key=… token vector) never appears.
    t = FloorPinnedHttpTransport(f"http://{_SERVER}/secret-path-xyz?k=tok",
                                 _allow(), inner=_mock(lambda r: httpx.Response(200, json={})))
    try:
        r = repr(t)
        assert "origin=" in r and _SERVER in r
        assert "secret-path-xyz" not in r and "k=tok" not in r   # path + query NOT shown
    finally:
        t.close()


# ----------------------------------------------------------- the SovereignHttpxTransport wiring (structural)


def test_wiring_is_sovereign_name_enforced_and_no_redirects():
    t = FloorPinnedHttpTransport(_URL, _allow(), inner=_mock(lambda r: httpx.Response(200, json={})))
    try:
        assert isinstance(t._sov, SovereignHttpxTransport)
        assert t._sov._sovereign_only is False          # the operator allowlist is ALWAYS enforced
        assert t._client.follow_redirects is False       # no redirect is ever followed
        assert callable(t)                                # it is a mcp.client Transport
    finally:
        t.close()
