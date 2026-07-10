"""
mcp — the Model Context Protocol seam for CRUCIBLE (Wave 6b, platformization).

Two directions, one safety stack:

  * EXPOSE (:mod:`mcp.server`). Advertise + invoke CRUCIBLE's default-safe capabilities as MCP tools
    for other AI agents/clients. Every ``tools/call`` routes through the SAME fail-closed gate chain
    (``agents.tools.invoke_tool``) — kill-switch / entitlement / charter-scope / destructive / egress —
    so an unentitled or out-of-scope call is REFUSED over MCP exactly as locally, and the tool never
    runs. Nothing exposed is ungated; the charter binding (``slug``) is server-fixed, never
    request-chosen. Loopback/stdio only.

  * CONSUME (:mod:`mcp.client` + :mod:`mcp.sensor`). Wrap an external MCP tool as a gated
    :class:`sensors.base.Sensor` — the Wave-2 sensor interface over MCP. Its output enters the ONE
    world-model as a provenance-labelled OBSERVATION (a LEAD), never a fact, until a CRUCIBLE oracle
    re-verifies it.

Stdlib-only JSON-RPC 2.0 (:mod:`mcp.protocol`); all wire input is treated as untrusted (bounded, safe
parse, no eval, no shell). Additive and default-safe: nothing runs until a server is explicitly
started or a sensor is explicitly driven.
"""

from __future__ import annotations

from .client import MCPClient, MCPClientError, StdioSubprocessTransport
from .protocol import Request, parse_request
from .sensor import MCPSensor
from .server import ExposePolicy, MCPServer, default_exposed_registry, serve_stdio

__all__ = [
    "MCPServer",
    "ExposePolicy",
    "default_exposed_registry",
    "serve_stdio",
    "MCPClient",
    "MCPClientError",
    "StdioSubprocessTransport",
    "MCPSensor",
    "Request",
    "parse_request",
]
