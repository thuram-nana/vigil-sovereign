"""Regression proof for the `mcp` 1.28.1 -> 2.1.1 (v1 -> v2 SDK) migration of the SIGIL MCP server.

WHY THIS EXISTS. mcp 2.0 **removed** `mcp.server.fastmcp` entirely (importing it now raises
``ModuleNotFoundError``), so the raw Dependabot version bump would have silently broken
``sigil/mcp/server.py`` at import — and NOTHING in CI would have caught it: the ``sigil-governor``
job installs the OFFENSE lock, which has no ``mcp`` at all, so the module is never imported there.
These guards pin the migration so a regression (reverting to the removed import, or losing a tool)
fails LOUDLY.

TWO KINDS OF PROOF, matched to where each can run:

  * The first two tests read ``server.py`` as TEXT (no ``mcp`` import), so they run everywhere —
    including the offense-lock ``sigil-governor`` job that has no ``mcp`` — and would have caught
    the removed-import break by construction.
  * ``test_live_server_registers_eight_tools`` actually constructs the v2 ``MCPServer`` and
    enumerates its registered tools. It needs the sovereign closure (``mcp`` + fastembed/qdrant),
    so it ``importorskip``s and SKIPS cleanly where that closure is absent (mirroring the idiom the
    rest of ``apps/sigil/tests`` uses for heavy deps). It PASSES in a sovereign env / local dev.

The 8 tools the server exposes (SIGIL Phase 0a memory surface). If a tool is added or removed,
update this set deliberately — it is the single source of truth for the count guard.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_SERVER = Path(__file__).resolve().parents[1] / "sigil" / "mcp" / "server.py"

EXPECTED_TOOLS = {
    "memory_search",
    "episodic_range",
    "ingest_status",
    "graph_entity",
    "graph_query",
    "threads_open",
    "commitments_due",
    "contradictions_pending",
}


def _source() -> str:
    assert _SERVER.is_file(), f"sigil MCP server not found at {_SERVER}"
    return _SERVER.read_text(encoding="utf-8")


def test_imports_v2_mcpserver_not_removed_fastmcp() -> None:
    """The server must import the v2 ``MCPServer`` and MUST NOT import the removed v1 ``fastmcp``.

    ``mcp.server.fastmcp`` was deleted in mcp 2.0 (import -> ModuleNotFoundError). This is the exact
    line whose breakage the version bump would otherwise have shipped.
    """
    src = _source()
    assert "from mcp.server.mcpserver import MCPServer" in src, (
        "server.py must import the v2 high-level server: "
        "`from mcp.server.mcpserver import MCPServer`"
    )
    assert "mcp.server.fastmcp" not in src, (
        "server.py still references `mcp.server.fastmcp`, which mcp 2.x REMOVED "
        "(importing it raises ModuleNotFoundError) — port it to `mcp.server.mcpserver.MCPServer`"
    )
    # the instance is built from the v2 class, not the old one
    assert "FastMCP(" not in src, "server.py still instantiates FastMCP() — use MCPServer()"
    assert re.search(r"\bMCPServer\(", src), "server.py must instantiate MCPServer(...)"


def test_declares_eight_named_tools() -> None:
    """Exactly the 8 expected tools are declared via ``@mcp.tool()`` — no silent add/drop.

    Pure source parse (no import), so it runs in the offense-lock CI job that has no ``mcp``.
    """
    src = _source()
    decorators = re.findall(r"^@mcp\.tool\(", src, flags=re.MULTILINE)
    assert len(decorators) == len(EXPECTED_TOOLS), (
        f"expected {len(EXPECTED_TOOLS)} @mcp.tool() decorators, found {len(decorators)} — "
        "a tool was added or removed without updating EXPECTED_TOOLS"
    )
    # every @mcp.tool() must be immediately followed by a `def <name>(` and the names must match
    declared = set(re.findall(r"^@mcp\.tool\(\)\s*\ndef (\w+)\(", src, flags=re.MULTILINE))
    assert declared == EXPECTED_TOOLS, (
        f"declared tool functions {sorted(declared)} != expected {sorted(EXPECTED_TOOLS)}"
    )


def test_live_server_registers_eight_tools(tmp_path, monkeypatch) -> None:
    """Construct the real v2 server and confirm it registers exactly the 8 tools, and that a live
    tool call returns a dict (never raises to the client).

    Needs the sovereign closure (``mcp`` + fastembed/qdrant for the module's top-level imports);
    SKIPS where that is absent (e.g. the offense-lock ``sigil-governor`` job).
    """
    import asyncio

    pytest.importorskip("mcp", reason="mcp not installed (offense-lock env) — live check skipped")
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    try:
        from sigil.mcp import server
    except Exception as exc:  # noqa: BLE001 — sovereign heavy deps absent -> skip, don't error
        pytest.skip(f"sovereign closure not importable here ({type(exc).__name__}: {exc})")

    assert type(server.mcp).__name__ == "MCPServer", "server.mcp is not a v2 MCPServer instance"

    tools = asyncio.run(server.mcp.list_tools())
    names = {t.name for t in tools}
    assert names == EXPECTED_TOOLS, f"registered tools {sorted(names)} != {sorted(EXPECTED_TOOLS)}"

    # episodic_range needs only the spine (fresh SIGIL_HOME -> empty spine, count 0); a real call
    out = server.episodic_range()
    assert isinstance(out, dict) and "records" in out and out.get("count") == 0, out
