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
from .platform_tools import DEFAULT_PROFILE, PROFILES, build_platform_tools


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


def _cmd_platform_list(profile: str) -> int:
    """Dry-print the PLATFORM MCP tool set (the console/REST operations) for ``profile`` — no server, no
    network, no console import of actions (just the registries)."""
    tools = build_platform_tools(profile)
    print(json.dumps({"profile": profile, "count": len(tools), "tools": tools},
                     indent=2, ensure_ascii=False, default=str))
    return 0


def _cmd_platform_serve(profile: str, base_url: str | None) -> int:
    """Run the PLATFORM MCP server over stdio. It forwards each call to the loopback ``vigil up`` proxy
    under the operator's bearer ($VIGIL_MCP_BEARER) — the proxy enforces per-user RBAC exactly as for the
    web UI. The base URL is loopback-validated (a non-loopback value refuses at construction)."""
    import os
    import sys
    from .platform_server import from_env
    env = dict(os.environ)
    env["VIGIL_MCP_PROFILE"] = profile
    if base_url:
        env["VIGIL_MCP_BASE_URL"] = base_url
    server = from_env(env)   # raises ValueError on a non-loopback base URL (fail-closed)
    n = len(server._tools_list(None)["tools"])   # noqa: SLF001 (own server)
    print(f"vigil-mcp: PLATFORM server (profile={profile!r}) on stdio -> {server.base_url} [{n} tools]; "
          f"auth via your bearer, every call gated by the console RBAC.", file=sys.stderr, flush=True)
    serve_stdio(server)   # type: ignore[arg-type]  # duck-typed: max_bytes + handle_raw
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

    p_plist = sub.add_parser("platform-list",
                             help="Print the PLATFORM MCP tools (console ops) for a profile (no server).")
    p_plist.add_argument("--profile", default=DEFAULT_PROFILE, choices=PROFILES,
                         help="core (read+run, default) or full (+owner-tier, still gated).")

    p_pserve = sub.add_parser("platform-serve",
                              help="Run the PLATFORM MCP server (console ops over the vigil-up hop) on stdio.")
    p_pserve.add_argument("--profile", default=DEFAULT_PROFILE, choices=PROFILES,
                          help="core (default) or full.")
    p_pserve.add_argument("--base-url", default=None,
                          help="loopback `vigil up` URL (else $VIGIL_MCP_BASE_URL). Non-loopback is refused.")

    args = parser.parse_args(argv)
    if args.cmd == "serve":
        return _cmd_serve(args.slug)
    if args.cmd == "list":
        return _cmd_list(args.slug)
    if args.cmd == "platform-list":
        return _cmd_platform_list(args.profile)
    if args.cmd == "platform-serve":
        return _cmd_platform_serve(args.profile, args.base_url)
    parser.print_help()
    return 2
