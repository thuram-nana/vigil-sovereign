"""
mcp.cli — `python3 -m framework.v2 mcp <subcommand>`.

    mcp serve --slug <slug>    Run the EXPOSE MCP tool-server over stdio (blocks, reading stdin).
    mcp list  --slug <slug>    Print the tools this engagement would expose (dry, no server, no I/O).

The EXPOSE server is DEFAULT-SAFE and FAIL-CLOSED: it advertises only Tier-1, entitlement-free,
non-destructive, no-egress capabilities, and every invocation is gated by ``invoke_tool`` under the
server-FIXED ``slug`` (the caller can never choose the charter/scope). stdio is on-host only — no
network surface. Nothing runs until you start it.
"""

from __future__ import annotations

import argparse
import json

from .server import MCPServer, serve_stdio


def _build_server(slug: str) -> MCPServer:
    return MCPServer(slug=slug)


def _cmd_list(slug: str) -> int:
    server = _build_server(slug)
    tools = [server._descriptor(t) for t in server.exposed()]   # noqa: SLF001 (own server)
    print(json.dumps({"slug": slug, "exposed_tools": tools}, indent=2, ensure_ascii=False, default=str))
    return 0


def _cmd_serve(slug: str) -> int:
    server = _build_server(slug)
    # A one-line banner on stderr so the operator sees it started; stdout is the JSON-RPC channel.
    import sys
    names = ", ".join(t.name for t in server.exposed()) or "(none)"
    print(f"crucible-mcp: EXPOSE server for slug={slug!r} on stdio — gated tools: {names}",
          file=sys.stderr, flush=True)
    serve_stdio(server)
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 mcp",
        description="MCP tool-server seam: EXPOSE CRUCIBLE's gated capabilities, or CONSUME external "
                    "MCP tools as gated sensors. This CLI drives the EXPOSE (stdio) server.")
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="Run the EXPOSE MCP server over stdio (blocks).")
    p_serve.add_argument("--slug", required=True, help="Engagement slug — the charter/scope binding.")

    p_list = sub.add_parser("list", help="Print the tools this engagement would expose (no server).")
    p_list.add_argument("--slug", required=True, help="Engagement slug — the charter/scope binding.")

    args = parser.parse_args(argv)
    if args.cmd == "serve":
        return _cmd_serve(args.slug)
    if args.cmd == "list":
        return _cmd_list(args.slug)
    parser.print_help()
    return 2
