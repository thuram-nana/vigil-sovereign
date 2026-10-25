"""
Tests for the PLATFORM MCP server (mcp.platform_server) — the MCP↔HTTP adapter.

A fake forward transport (records the request, returns a canned response — NO network) proves the adapter
is a pure translator that holds no authority: it forwards to the loopback proxy under the operator's bearer
and surfaces the gate's answer. The load-bearing safety properties are pinned here:
  * loopback-only base URL (never egress off-host),
  * the route is FIXED by the tool name — arguments only fill declared slots, URL-encoded (no path injection),
  * fail-closed BEFORE any HTTP on an unknown / out-of-profile tool or a missing required path arg,
  * a 4xx gate refusal is surfaced verbatim as isError.
"""

from __future__ import annotations

import json

import pytest

from framework.v2.mcp.platform_server import PlatformMCPServer, from_env, _require_loopback


class _Fake:
    """Records each forwarded request and returns a canned (status, body)."""
    def __init__(self, status: int = 200, body: bytes = b'{"ok": true}') -> None:
        self.calls: list[dict] = []
        self.status = status
        self.body = body

    def __call__(self, method, url, headers, data, timeout):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "data": data})
        return self.status, self.body


def _srv(profile="full", bearer="tok", status=200, body=b'{"ok": true}'):
    f = _Fake(status=status, body=body)
    s = PlatformMCPServer(base_url="http://127.0.0.1:8765", bearer=bearer, profile=profile, forward=f)
    return s, f


def _call(s, name, arguments=None):
    return s._invoke(name, arguments or {})


# ---- loopback-only --------------------------------------------------------------------------------

def test_loopback_hosts_accepted() -> None:
    for u in ("http://127.0.0.1:8765", "http://localhost:9", "https://[::1]:443", "http://127.0.0.1"):
        assert _require_loopback(u).startswith(("http://", "https://"))


def test_non_loopback_base_url_refused() -> None:
    for u in ("http://10.0.0.5:8765", "https://example.com", "http://169.254.169.254/", "ftp://127.0.0.1"):
        with pytest.raises(ValueError):
            PlatformMCPServer(base_url=u, forward=_Fake())


# ---- tools/list + profile -------------------------------------------------------------------------

def test_tools_list_returns_profile() -> None:
    s, _ = _srv("core")
    names = {t["name"] for t in s._tools_list(None)["tools"]}
    assert "get_status" in names and "post_instruct" in names
    assert "post_terminal_run" not in names  # owner-tier hidden in core
    s2, _ = _srv("full")
    assert "post_terminal_run" in {t["name"] for t in s2._tools_list(None)["tools"]}


# ---- forwarding: method / path / body rendering ---------------------------------------------------

def test_get_exact_forwards_plain() -> None:
    s, f = _srv()
    r = _call(s, "get_status")
    assert r["isError"] is False
    assert f.calls[0]["method"] == "GET"
    assert f.calls[0]["url"] == "http://127.0.0.1:8765/api/status"
    assert f.calls[0]["data"] is None


def test_get_scoped_adds_slug_query() -> None:
    s, f = _srv()
    _call(s, "get_runs", {"slug": "job-1"})
    assert f.calls[0]["url"] == "http://127.0.0.1:8765/api/runs?slug=job-1"


def test_get_prefix_appends_encoded_arg() -> None:
    s, f = _srv()
    _call(s, "get_report", {"arg": "run_42"})
    assert f.calls[0]["url"] == "http://127.0.0.1:8765/api/report/run_42"


def test_post_exact_sends_json_body_and_bearer() -> None:
    s, f = _srv(bearer="sekret")
    _call(s, "post_instruct", {"slug": "s", "text": "focus auth"})
    c = f.calls[0]
    assert c["method"] == "POST"
    assert c["url"] == "http://127.0.0.1:8765/api/instruct"
    assert json.loads(c["data"]) == {"slug": "s", "text": "focus auth"}
    assert c["headers"]["Authorization"] == "Bearer sekret"
    assert c["headers"]["Content-Type"] == "application/json"


def test_post_wildcard_fills_path_arg() -> None:
    s, f = _srv()
    _call(s, "post_run_cancel", {"run_id": "abc123"})
    assert f.calls[0]["url"] == "http://127.0.0.1:8765/api/run/abc123/cancel"
    assert f.calls[0]["method"] == "POST"


# ---- route fixed by tool name (no injection) ------------------------------------------------------

def test_path_arg_cannot_inject_segments() -> None:
    s, f = _srv()
    _call(s, "post_run_cancel", {"run_id": "../../terminal/run"})
    # the '/' is percent-encoded, so the arg stays one segment and cannot reach another route
    assert f.calls[0]["url"] == "http://127.0.0.1:8765/api/run/..%2F..%2Fterminal%2Frun/cancel"


def test_arguments_do_not_change_the_route() -> None:
    s, f = _srv()
    # a 'route'/'path'/'method' key in arguments is just body data; it never alters the fixed route
    _call(s, "post_instruct", {"route": "/api/terminal/run", "method": "GET", "x": 1})
    assert f.calls[0]["url"] == "http://127.0.0.1:8765/api/instruct"
    assert f.calls[0]["method"] == "POST"
    assert json.loads(f.calls[0]["data"]) == {"route": "/api/terminal/run", "method": "GET", "x": 1}


# ---- fail-closed BEFORE any HTTP ------------------------------------------------------------------

def test_unknown_tool_refused_without_forward() -> None:
    s, f = _srv("full")
    r = _call(s, "post_nonsuch")
    assert r["isError"] is True
    assert r["_meta"]["vigil"]["gate"] == "expose-profile"
    assert f.calls == []  # never reached the proxy


def test_out_of_profile_tool_refused_in_core() -> None:
    s, f = _srv("core")
    r = _call(s, "post_terminal_run", {"command": "id"})
    assert r["isError"] is True
    assert r["_meta"]["vigil"]["gate"] == "expose-profile"
    assert f.calls == []


def test_missing_required_path_arg_refused_without_forward() -> None:
    s, f = _srv()
    r = _call(s, "post_run_cancel", {})  # run_id missing
    assert r["isError"] is True
    assert r["_meta"]["vigil"]["gate"] == "render"
    assert f.calls == []


def test_missing_prefix_arg_refused() -> None:
    s, f = _srv()
    r = _call(s, "get_report", {})  # 'arg' missing
    assert r["isError"] is True and f.calls == []


# ---- response + refusal mapping -------------------------------------------------------------------

def test_200_json_maps_to_structured_content() -> None:
    s, _ = _srv(status=200, body=b'{"runs": [1, 2], "ok": true}')
    r = _call(s, "get_runs")
    assert r["isError"] is False
    assert r["structuredContent"] == {"runs": [1, 2], "ok": True}
    assert r["_meta"]["vigil"]["httpStatus"] == 200


def test_403_gate_refusal_surfaced_as_error() -> None:
    s, _ = _srv(status=403, body=b'{"error": "forbidden: role lacks offense_authority"}')
    r = _call(s, "post_terminal_run", {"command": "id"})
    assert r["isError"] is True
    assert "forbidden" in r["content"][0]["text"]
    assert r["_meta"]["vigil"]["httpStatus"] == 403


def test_no_bearer_sends_no_authorization_header() -> None:
    s, f = _srv(bearer=None)
    _call(s, "get_status")
    assert "Authorization" not in f.calls[0]["headers"]


def test_transport_failure_is_a_clean_refusal() -> None:
    def _boom(*_a, **_k):
        raise OSError("connection refused")
    s = PlatformMCPServer(base_url="http://127.0.0.1:8765", bearer="t", profile="full", forward=_boom)
    r = s._invoke("get_status", {})
    assert r["isError"] is True
    assert r["_meta"]["vigil"]["gate"] == "transport"


# ---- JSON-RPC envelope end-to-end -----------------------------------------------------------------

def test_handle_raw_initialize_and_tools_list() -> None:
    s, _ = _srv("core")
    init = json.loads(s.handle_raw(b'{"jsonrpc":"2.0","id":1,"method":"initialize"}'))
    assert init["result"]["serverInfo"]["name"] == "vigil-platform"
    lst = json.loads(s.handle_raw(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}'))
    assert any(t["name"] == "get_status" for t in lst["result"]["tools"])


def test_handle_raw_tools_call_forwards() -> None:
    s, f = _srv()
    out = json.loads(s.handle_raw(b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_status"}}'))
    assert out["result"]["isError"] is False
    assert f.calls[0]["url"].endswith("/api/status")


def test_ping_and_unknown_method() -> None:
    s, _ = _srv()
    assert json.loads(s.handle_raw(b'{"jsonrpc":"2.0","id":4,"method":"ping"}'))["result"] == {}
    bad = json.loads(s.handle_raw(b'{"jsonrpc":"2.0","id":5,"method":"frobnicate"}'))
    assert bad["error"]["code"] == -32601


# ---- from_env -------------------------------------------------------------------------------------

def test_from_env_defaults_loopback() -> None:
    s = from_env({"VIGIL_MCP_BEARER": "tok"})
    assert s.base_url == "http://127.0.0.1:8765" and s.profile == "core"


def test_from_env_non_loopback_refused() -> None:
    with pytest.raises(ValueError):
        from_env({"VIGIL_MCP_BASE_URL": "http://evil.example", "VIGIL_MCP_BEARER": "t"})
