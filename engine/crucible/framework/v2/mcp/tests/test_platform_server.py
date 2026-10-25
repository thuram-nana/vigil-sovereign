"""
Tests for the PLATFORM MCP server (mcp.platform_server) — the MCP↔HTTP adapter.

A fake forward transport (records the request, returns a canned response — NO network) proves the adapter
is a pure translator that holds no authority: it forwards to the loopback proxy under the operator's bearer
and surfaces the gate's answer. The load-bearing safety properties are pinned here against the REAL proxy
contract (not a stand-in): X-SIGIL-Token auth header, the /offense mount, port 8770, X-Requested-With CSRF.
  * loopback-only base URL (refused off-host) AND the production transport ignores proxy env (never egresses
    off-host via http_proxy/ALL_PROXY/system proxy),
  * the route is FIXED by the tool name — args only fill declared slots, URL-encoded, with '.'/'..' refused
    (no path injection / traversal),
  * fail-closed BEFORE any HTTP on an unknown / out-of-profile tool, a missing path arg, or a traversal arg,
  * a 4xx gate refusal is surfaced verbatim as isError.
"""

from __future__ import annotations

import http.server
import json
import threading

import pytest

from framework.v2.mcp.platform_server import PlatformMCPServer, from_env, _default_forward, _require_loopback


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
    s = PlatformMCPServer(base_url="http://127.0.0.1:8770", bearer=bearer, profile=profile, forward=f)
    return s, f


def _call(s, name, arguments=None):
    return s._invoke(name, arguments or {})


# ---- loopback-only + no proxy egress --------------------------------------------------------------

def test_loopback_hosts_accepted() -> None:
    for u in ("http://127.0.0.1:8770", "http://localhost:9", "https://[::1]:443", "http://127.0.0.1"):
        assert _require_loopback(u).startswith(("http://", "https://"))


def test_non_loopback_base_url_refused() -> None:
    for u in ("http://10.0.0.5:8770", "https://example.com", "http://169.254.169.254/", "ftp://127.0.0.1",
              "http://evil.com@127.0.0.1/", "http://127.0.0.1@evil.com/"):
        with pytest.raises(ValueError):
            PlatformMCPServer(base_url=u, forward=_Fake())


def test_default_forward_ignores_proxy_env(monkeypatch) -> None:
    """The production transport dials the loopback target DIRECTLY and never honours http_proxy/ALL_PROXY
    (the red-pen BLOCK: otherwise the bearer would egress off-host to the proxy). With a bogus proxy set,
    the request must still reach the loopback server."""
    hits: list[str] = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            return
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        for var in ("http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(var, "http://127.0.0.1:1")   # a closed, bogus proxy
        status, body = _default_forward("GET", f"http://127.0.0.1:{port}/offense/api/status",
                                        {"Accept": "application/json"}, None, 5.0)
        assert status == 200 and b"ok" in body
        assert hits == ["/offense/api/status"]   # hit DIRECTLY, not the bogus proxy (which would refuse)
    finally:
        srv.shutdown()
        srv.server_close()


# ---- tools/list + profile -------------------------------------------------------------------------

def test_tools_list_returns_profile() -> None:
    s, _ = _srv("core")
    names = {t["name"] for t in s._tools_list(None)["tools"]}
    assert "get_status" in names and "post_instruct" in names
    assert "post_terminal_run" not in names  # owner-tier hidden in core
    s2, _ = _srv("full")
    assert "post_terminal_run" in {t["name"] for t in s2._tools_list(None)["tools"]}


# ---- forwarding: method / path / body rendering against the REAL proxy contract -------------------

def test_get_exact_forwards_under_offense_mount() -> None:
    s, f = _srv()
    r = _call(s, "get_status")
    assert r["isError"] is False
    assert f.calls[0]["method"] == "GET"
    assert f.calls[0]["url"] == "http://127.0.0.1:8770/offense/api/status"
    assert f.calls[0]["data"] is None


def test_get_scoped_adds_slug_query() -> None:
    s, f = _srv()
    _call(s, "get_runs", {"slug": "job-1"})
    assert f.calls[0]["url"] == "http://127.0.0.1:8770/offense/api/runs?slug=job-1"


def test_get_prefix_appends_encoded_arg() -> None:
    s, f = _srv()
    _call(s, "get_report", {"arg": "run_42"})
    assert f.calls[0]["url"] == "http://127.0.0.1:8770/offense/api/report/run_42"


def test_post_exact_sends_json_body_and_sigil_token() -> None:
    s, f = _srv(bearer="sekret")
    _call(s, "post_instruct", {"slug": "s", "text": "focus auth"})
    c = f.calls[0]
    assert c["method"] == "POST"
    assert c["url"] == "http://127.0.0.1:8770/offense/api/instruct"
    assert json.loads(c["data"]) == {"slug": "s", "text": "focus auth"}
    assert c["headers"]["X-SIGIL-Token"] == "sekret"       # the header the proxy actually authenticates from
    assert "Authorization" not in c["headers"]             # NOT Authorization: Bearer (the red-pen WARN)
    assert c["headers"]["X-Requested-With"] == "vigil-mcp"  # CSRF conjunct the proxy requires on POST
    assert c["headers"]["Content-Type"] == "application/json"


def test_post_wildcard_fills_path_arg() -> None:
    s, f = _srv()
    _call(s, "post_run_cancel", {"run_id": "abc123"})
    assert f.calls[0]["url"] == "http://127.0.0.1:8770/offense/api/run/abc123/cancel"
    assert f.calls[0]["method"] == "POST"


# ---- route fixed by tool name (no injection / no traversal) ---------------------------------------

def test_path_arg_slash_cannot_inject_segments() -> None:
    s, f = _srv()
    _call(s, "post_run_cancel", {"run_id": "a/b/c"})
    # '/' is percent-encoded, so the arg stays one segment and cannot reach another route
    assert f.calls[0]["url"] == "http://127.0.0.1:8770/offense/api/run/a%2Fb%2Fc/cancel"


def test_dotdot_path_arg_refused_without_forward() -> None:
    s, f = _srv()
    for args in ({"run_id": ".."}, {"run_id": "."}):
        r = _call(s, "post_run_cancel", args)
        assert r["isError"] is True and r["_meta"]["vigil"]["gate"] == "render"
    r = _call(s, "get_report", {"arg": ".."})
    assert r["isError"] is True and r["_meta"]["vigil"]["gate"] == "render"
    assert f.calls == []  # none reached the proxy


def test_arguments_do_not_change_the_route() -> None:
    s, f = _srv()
    _call(s, "post_instruct", {"route": "/api/terminal/run", "method": "GET", "x": 1})
    assert f.calls[0]["url"] == "http://127.0.0.1:8770/offense/api/instruct"
    assert f.calls[0]["method"] == "POST"
    assert json.loads(f.calls[0]["data"]) == {"route": "/api/terminal/run", "method": "GET", "x": 1}


# ---- fail-closed BEFORE any HTTP ------------------------------------------------------------------

def test_unknown_tool_refused_without_forward() -> None:
    s, f = _srv("full")
    r = _call(s, "post_nonsuch")
    assert r["isError"] is True and r["_meta"]["vigil"]["gate"] == "expose-profile"
    assert f.calls == []


def test_out_of_profile_tool_refused_in_core() -> None:
    s, f = _srv("core")
    r = _call(s, "post_terminal_run", {"command": "id"})
    assert r["isError"] is True and r["_meta"]["vigil"]["gate"] == "expose-profile"
    assert f.calls == []


def test_missing_required_path_arg_refused_without_forward() -> None:
    s, f = _srv()
    r = _call(s, "post_run_cancel", {})
    assert r["isError"] is True and r["_meta"]["vigil"]["gate"] == "render"
    assert f.calls == []


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


def test_no_bearer_sends_no_token_header() -> None:
    s, f = _srv(bearer=None)
    _call(s, "get_status")
    assert "X-SIGIL-Token" not in f.calls[0]["headers"]


def test_transport_failure_is_a_clean_refusal() -> None:
    def _boom(*_a, **_k):
        raise OSError("connection refused")
    s = PlatformMCPServer(base_url="http://127.0.0.1:8770", bearer="t", profile="full", forward=_boom)
    r = s._invoke("get_status", {})
    assert r["isError"] is True and r["_meta"]["vigil"]["gate"] == "transport"


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
    assert f.calls[0]["url"].endswith("/offense/api/status")


def test_ping_and_unknown_method() -> None:
    s, _ = _srv()
    assert json.loads(s.handle_raw(b'{"jsonrpc":"2.0","id":4,"method":"ping"}'))["result"] == {}
    bad = json.loads(s.handle_raw(b'{"jsonrpc":"2.0","id":5,"method":"frobnicate"}'))
    assert bad["error"]["code"] == -32601


# ---- from_env -------------------------------------------------------------------------------------

def test_from_env_defaults_to_proxy_port() -> None:
    s = from_env({"VIGIL_MCP_BEARER": "tok"})
    assert s.base_url == "http://127.0.0.1:8770" and s.profile == "core"


def test_from_env_non_loopback_refused() -> None:
    with pytest.raises(ValueError):
        from_env({"VIGIL_MCP_BASE_URL": "http://evil.example", "VIGIL_MCP_BEARER": "t"})
