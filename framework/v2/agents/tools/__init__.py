"""
agents.tools — the gated agentic tool-use / sensor-driving seam (W1.4).

The reasoning core drives capabilities through one uniform, fail-closed interface: a ``Tool``
protocol + a ``ToolRegistry``, invoked by ``invoke_tool`` which runs the full safety chain
(kill-switch / entitlement / scope / destructive-confirm / egress) and records typed
``tool_call`` / ``tool_result`` events on the immutable spine. Today it carries safe internal
tools (``reverify_finding``); in Wave 2 the same interface admits integrated sensors (Nmap, a
packet engine, Nuclei, cloud APIs), each a gated tool whose output an oracle re-verifies.
"""

from __future__ import annotations

from .base import Tool, ToolContext, ToolError, ToolRegistry, ToolResult
from .builtin import (
    ProbeSurfaceTool,
    ReverifyFindingTool,
    default_registry,
    probe_surface_registry,
    register_builtin_tools,
)
from .invoker import invoke_tool

__all__ = [
    "Tool", "ToolContext", "ToolError", "ToolRegistry", "ToolResult",
    "invoke_tool",
    "ReverifyFindingTool", "default_registry", "register_builtin_tools",
    "ProbeSurfaceTool", "probe_surface_registry",
]
