"""
Tests for mcp.server — the EXPOSE direction.

The load-bearing properties a downstream review will probe HARD:
  * DEFAULT-SAFE. Only the allowlisted, read-only capabilities are advertised; the active/offensive
    sensors and the local-file importers are NOT exposed.
  * NO GATE BYPASS. Every exposed ``tools/call`` runs through ``invoke_tool`` — an out-of-scope call,
    a tripped kill-switch, and an unentitled (force-exposed) call are all REFUSED over MCP and the
    tool NEVER runs. There is no ungated door.
  * SLUG IS SERVER-FIXED. The charter/scope binding is not read from the request.
  * UNTRUSTED WIRE. Malformed / bad-arg / unknown messages degrade to clean errors, invoking nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolRegistry, ToolResult
from framework.v2.entitlement import Capability
from framework.v2.mcp import protocol as P
from framework.v2.mcp.server import ExposePolicy, MCPServer, serve_stdio


_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `10.0.0.5` | Declared host | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate kill-switch + charter/scope paths so no test reads/writes the real targets/ tree."""
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    td = tmp_path / "alpha"
    td.mkdir(parents=True, exist_ok=True)
    (td / "charter.md").write_text(_CHARTER.format(slug="alpha"), encoding="utf-8")


@pytest.fixture()
def spine(tmp_path: Path):
    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.agents.spine_sink import SpineSink
    bb = open_blackboard(db_path=tmp_path / "spine.sqlite")
    yield SpineSink(bb, "alpha"), bb
    bb.close()


# ---- test doubles ----------------------------------------------------------


class _Spy:
    name = "spy"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def __init__(self) -> None:
        self.ran = False

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        self.ran = True
        return ToolResult(ok=True, summary="ran", output={"echo": args})


class _GatedSpy(_Spy):
    name = "gated_spy"
    tier = "T2"
    capability = Capability.EXPLOIT_EXECUTION


class _AllowAll(ExposePolicy):
    """A deliberately-permissive policy used ONLY to prove the GATE (not the policy) is the real
    block — it exposes anything, so a call still has to survive invoke_tool's gate chain."""

    def __init__(self) -> None:
        super().__init__(allow=frozenset())

    def exposable(self, tool) -> bool:  # noqa: D401
        return True


def _rpc(method: str, params=None, rid: int = 1) -> P.Request:
    req, err = P.parse_request(P.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                                        **({"params": params} if params is not None else {})}))
    assert err is None and req is not None
    return req


def _call(server: MCPServer, name: str, arguments: dict, rid: int = 1) -> dict:
    return server.handle(_rpc("tools/call", {"name": name, "arguments": arguments}, rid))


# ---- enumeration / handshake ----------------------------------------------


def test_initialize_advertises_a_tools_capability() -> None:
    resp = MCPServer(slug="alpha").handle(_rpc("initialize"))
    r = resp["result"]
    assert r["capabilities"]["tools"] == {"listChanged": False}
    assert r["serverInfo"]["name"] and "protocolVersion" in r


def test_tools_list_exposes_only_the_safe_allowlist() -> None:
    resp = MCPServer(slug="alpha").handle(_rpc("tools/list"))
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {"reverify_finding", "declared_service", "sbom_vuln"}
    # the active/offensive sensors and the egress importers are NOT advertised
    assert not ({"nmap", "nuclei_web", "nuclei_import", "tshark_flow", "burp_web"} & names)
    # every descriptor discloses that it is gated and its output is an observation
    for t in resp["result"]["tools"]:
        assert t["_meta"]["crucible"]["gated"] is True
        assert t["_meta"]["crucible"]["provenance"] == "observation"


def test_widened_allowlist_exposes_sbom_but_active_tools_stay_refused() -> None:
    # The deliberate widening: the passive, read-only SCA reader is now exposed; an ACTIVE sensor
    # present in the same registry is NOT exposed and a call to it is REFUSED by the expose policy
    # (before the invoker) — the property re-check (Tier-2 / active_recon) keeps it unreachable.
    server = MCPServer(slug="alpha")
    names = {t["name"] for t in server.handle(_rpc("tools/list"))["result"]["tools"]}
    assert "sbom_vuln" in names and "nmap" not in names
    resp = _call(server, "nmap", {"host": "10.0.0.5"})
    result = resp["result"]
    assert result["isError"] is True
    assert result["_meta"]["crucible"]["gate"] == "expose-policy"


# ---- a safe exposed call SUCCEEDS through the gate chain --------------------


def test_exposed_reverify_runs_through_the_gate_and_returns_an_observation(spine) -> None:
    sink, bb = spine
    server = MCPServer(slug="alpha", sink=sink)
    finding = {"bug_class": "reflected_xss", "oracle_context": {"bug_class": "reflected_xss"}}
    resp = _call(server, "reverify_finding", {"finding": finding})
    result = resp["result"]
    assert result["isError"] is False
    assert "is_fact" in result["structuredContent"]
    assert result["_meta"]["crucible"]["provenance"] == "observation"
    # the invocation was recorded on the immutable spine (tool_call before, tool_result after)
    assert bb.read(engagement="alpha", kinds=["tool_call"])
    assert bb.read(engagement="alpha", kinds=["tool_result"])


def test_exposed_declared_service_in_scope_succeeds() -> None:
    server = MCPServer(slug="alpha")
    resp = _call(server, "declared_service",
                 {"host": "10.0.0.5", "services": [{"port": 443, "protocol": "tcp"}]})
    result = resp["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["host"] == "10.0.0.5"


# ---- refusals: the gate blocks over MCP exactly as locally ------------------


def test_exposed_call_out_of_scope_host_is_refused_by_the_scope_gate() -> None:
    server = MCPServer(slug="alpha")
    resp = _call(server, "declared_service", {"host": "8.8.8.8", "services": []})
    result = resp["result"]
    assert result["isError"] is True
    assert result["_meta"]["crucible"]["refused"] is True
    assert result["_meta"]["crucible"]["gate"] == "scope"


def test_kill_switch_refuses_an_exposed_call_over_mcp() -> None:
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("test halt")
    server = MCPServer(slug="alpha")
    resp = _call(server, "declared_service", {"host": "10.0.0.5", "services": []})
    result = resp["result"]
    assert result["isError"] is True and result["_meta"]["crucible"]["gate"] == "kill-switch"


def test_a_non_exposed_tool_is_refused_by_policy_and_never_invoked() -> None:
    # A tool present in the registry but NOT on the allowlist is refused BEFORE the invoker — the
    # tool never runs (spy.ran stays False).
    reg = ToolRegistry()
    spy = _Spy()
    reg.register(spy)
    server = MCPServer(slug="alpha", registry=reg)          # default allowlist excludes "spy"
    resp = _call(server, "spy", {})
    result = resp["result"]
    assert result["isError"] is True and result["_meta"]["crucible"]["gate"] == "expose-policy"
    assert spy.ran is False


def test_the_gate_blocks_a_force_exposed_gated_tool_over_mcp(monkeypatch) -> None:
    # THE ANTI-BYPASS TEST. Even with a permissive policy that exposes a GATED tool, an unentitled
    # call must be REFUSED by invoke_tool over MCP and the tool must NOT run.
    from framework.v2 import entitlement

    def _deny(cap):
        raise RuntimeError(f"not entitled to {cap}")

    monkeypatch.setattr(entitlement, "require_capability", _deny)
    reg = ToolRegistry()
    gated = _GatedSpy()
    reg.register(gated)
    server = MCPServer(slug="alpha", registry=reg, expose=_AllowAll())
    resp = _call(server, "gated_spy", {})
    result = resp["result"]
    assert result["isError"] is True and result["_meta"]["crucible"]["gate"] == "entitlement"
    assert gated.ran is False                                # unentitled exposed call did NOTHING


def test_slug_is_server_fixed_not_taken_from_the_request() -> None:
    # A remote caller cannot widen scope by naming another charter: a 'slug' smuggled into params or
    # arguments is ignored — the out-of-scope host is still refused under the server's fixed slug.
    server = MCPServer(slug="alpha")
    assert server._ctx().slug == "alpha"                    # noqa: SLF001
    resp = server.handle(_rpc("tools/call", {"name": "declared_service", "slug": "attacker",
                                             "arguments": {"host": "8.8.8.8", "services": [],
                                                           "slug": "attacker"}}))
    assert resp["result"]["_meta"]["crucible"]["gate"] == "scope"


# ---- untrusted wire: malformed / bad-arg / unknown invoke nothing ----------


def test_tools_call_with_non_dict_arguments_is_invalid_params() -> None:
    server = MCPServer(slug="alpha")
    resp = server.handle(_rpc("tools/call", {"name": "declared_service", "arguments": "not-an-object"}))
    assert "error" in resp and resp["error"]["code"] == P.INVALID_PARAMS


def test_tools_call_missing_name_is_invalid_params() -> None:
    server = MCPServer(slug="alpha")
    resp = server.handle(_rpc("tools/call", {"arguments": {}}))
    assert "error" in resp and resp["error"]["code"] == P.INVALID_PARAMS


def test_unknown_tool_is_an_error_result_not_a_crash() -> None:
    server = MCPServer(slug="alpha")
    resp = _call(server, "does_not_exist", {})
    assert resp["result"]["isError"] is True
    assert "no such tool" in resp["result"]["_meta"]["crucible"]["note"]


def test_unknown_method_is_method_not_found() -> None:
    resp = MCPServer(slug="alpha").handle(_rpc("nonsense/method"))
    assert resp["error"]["code"] == P.METHOD_NOT_FOUND


def test_notifications_get_no_response() -> None:
    req, err = P.parse_request('{"jsonrpc":"2.0","method":"notifications/initialized"}')
    assert err is None
    assert MCPServer(slug="alpha").handle(req) is None


def test_handle_raw_rejects_malformed_json_cleanly() -> None:
    out = MCPServer(slug="alpha").handle_raw("{ not json")
    assert json.loads(out)["error"]["code"] == P.PARSE_ERROR


def test_handle_raw_enforces_the_size_bound() -> None:
    server = MCPServer(slug="alpha", max_bytes=256)
    big = P.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "declared_service", "arguments": {"blob": "A" * 4000}}})
    out = server.handle_raw(big)
    assert json.loads(out)["error"]["code"] == P.INVALID_REQUEST


# ---- stdio transport -------------------------------------------------------


def test_serve_stdio_roundtrips_newline_delimited_requests() -> None:
    import io
    server = MCPServer(slug="alpha")
    stdin = io.BytesIO(
        b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'   # notification: no response line
        b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
    stdout = io.BytesIO()
    serve_stdio(server, stdin=stdin, stdout=stdout)
    lines = [json.loads(x) for x in stdout.getvalue().splitlines() if x.strip()]
    assert [r["id"] for r in lines] == [1, 2]                 # exactly two responses (no notif reply)
    assert {t["name"] for t in lines[1]["result"]["tools"]} == {"reverify_finding", "declared_service",
                                                                "sbom_vuln"}


def test_serve_stdio_rejects_an_oversize_line_and_resyncs() -> None:
    import io
    server = MCPServer(slug="alpha", max_bytes=128)
    oversize = b'{"jsonrpc":"2.0","id":1,"method":"x","params":{"b":"' + b"A" * 500 + b'"}}\n'
    good = b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    stdout = io.BytesIO()
    serve_stdio(server, stdin=io.BytesIO(oversize + good), stdout=stdout)
    lines = [json.loads(x) for x in stdout.getvalue().splitlines() if x.strip()]
    # the oversize line is an error, and the stream re-syncs to answer the following valid request
    assert lines[0]["error"]["code"] == P.INVALID_REQUEST
    assert lines[1]["id"] == 2 and lines[1]["result"] == {}
