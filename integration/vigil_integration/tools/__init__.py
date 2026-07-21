"""
vigil_integration.tools — the governed MCP tool boundary (VIGIL-FUSION F3, slice 1).

``mcp_registry`` is redamon's pydantic manifest layer ported near-verbatim (trust-tiered validation,
secret redaction, phase-view) with the sovereign inversions (least-privilege default phases, deny an
unregistered tool). ``governance`` subordinates it to the sovereign core: the manifest phase → WARDEN
tier, destructive tools floored at A3 + m-of-n, and every call routed through the same injected
conjunctive gate the F2 ReAct core uses — all fail-closed. The live MCP client + tool executors are a
later slice; this slice is the pure, testable boundary.
"""

from .governance import (
    ToolCallVerdict,
    authorize_tool_call,
    authorized_tool_names,
    is_destructive_tool,
    is_tool_allowed_in_phase,
    redact_tool_args,
    tool_call_tier,
)
from .mcp_registry import (
    ALL_PHASES,
    LEAST_PRIVILEGE_PHASES,
    SYSTEM_SERVER_IDS,
    BearerAuth,
    MCPServer,
    ToolSpec,
    ValidationError,
    current,
    default_phases_for,
    manifest_tool_destructive_view,
    manifest_tool_names,
    manifest_tool_phase_view,
    parse_user_servers,
    redact_for_api,
    set_builtin_tool_names,
    set_current,
    to_client_config,
    validate_servers,
)

__all__ = [
    # registry
    "MCPServer", "ToolSpec", "BearerAuth", "ValidationError",
    "ALL_PHASES", "LEAST_PRIVILEGE_PHASES", "SYSTEM_SERVER_IDS",
    "validate_servers", "parse_user_servers", "to_client_config", "redact_for_api",
    "set_current", "current", "default_phases_for", "manifest_tool_names",
    "manifest_tool_phase_view", "manifest_tool_destructive_view", "set_builtin_tool_names",
    # governance
    "ToolCallVerdict", "authorize_tool_call", "authorized_tool_names",
    "is_tool_allowed_in_phase", "tool_call_tier", "is_destructive_tool", "redact_tool_args",
]
