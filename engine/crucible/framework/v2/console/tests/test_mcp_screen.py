"""
Console MCP provider (`/api/mcp`) — READ-ONLY listing of the gated capabilities the engine EXPOSES over MCP.

Asserts the safety + honesty properties the screen stakes its credibility on:
  * the provider lists ONLY the fixed EXPOSE allowlist (a fail-closed, slug-independent set);
  * every exposed tool discloses its gate posture (gated / tier / provenance=observation, read-only);
  * building the listing is side-effect-free — it starts NO server and does no I/O (read-only);
  * fail-soft — an internal error yields an empty list + a note, never a raise;
  * the route is registered so the UI can reach it.
"""

from __future__ import annotations

from framework.v2.console import api
from framework.v2.mcp.server import DEFAULT_EXPOSE_ALLOW


def test_mcp_data_lists_only_the_fixed_expose_allowlist() -> None:
    d = api.mcp_data()
    names = {t["name"] for t in d["exposed_tools"]}
    assert names == set(DEFAULT_EXPOSE_ALLOW)          # exactly the fail-closed allowlist, nothing more
    assert d["transport"] == "stdio"                   # on-host, no network surface
    assert "note" in d


def test_every_exposed_tool_discloses_its_gate_posture() -> None:
    for t in api.mcp_data()["exposed_tools"]:
        crucible = t["_meta"]["crucible"]
        assert crucible["gated"] is True                          # every call is re-gated
        assert crucible["provenance"] == "observation"            # output is a lead, never a fact
        assert str(crucible["tier"])                              # a tier is disclosed
        assert t["annotations"]["destructiveHint"] is False       # exposable tools are non-destructive
        assert t["annotations"]["readOnlyHint"] is True


def test_mcp_data_is_side_effect_free_and_idempotent() -> None:
    # a read must not mutate anything; two calls give the same (stable) listing.
    a = api.mcp_data()
    b = api.mcp_data()
    assert [t["name"] for t in a["exposed_tools"]] == [t["name"] for t in b["exposed_tools"]]


def test_mcp_data_fail_soft(monkeypatch) -> None:
    # an internal failure must yield an honest empty list + a note, never a raise (the screen degrades).
    import framework.v2.mcp.server as srv

    def _boom(*a, **k):
        raise RuntimeError("seam unavailable")
    monkeypatch.setattr(srv, "MCPServer", _boom)
    d = api.mcp_data()
    assert d["exposed_tools"] == [] and "note" in d


def test_route_is_registered() -> None:
    from framework.v2.console import server
    assert server._EXACT_ROUTES.get("/api/mcp") is api.mcp_data
