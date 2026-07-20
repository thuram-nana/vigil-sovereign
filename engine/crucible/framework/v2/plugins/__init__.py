"""
plugins — CRUCIBLE's unified, read-only capability registry (Wave 6a).

One deterministic catalog over the framework's several independent rosters
(sensors, internal tools, oracles, operators, CLI commands) so a third party — or
a future MCP server / HTTP API / SDK — can DISCOVER "what capabilities exist,
what each produces, its gating tier, its graceful-absent behaviour" WITHOUT
changing how any of them execute. Registration is not invocation: everything
enumerated here stays gated at run time exactly as before.

    from framework.v2.plugins import capability_registry
    catalog = capability_registry()
    for d in catalog.sensors:
        print(d.name, d.tier, d.entitlement, d.produces)

    # extend it without editing core files (mirrors ToolRegistry.register):
    from framework.v2.plugins import register_sensor
    register_sensor(MyCustomSensor())
"""

from __future__ import annotations

from .registry import (
    CapabilityCatalog,
    CapabilityDescriptor,
    PluginError,
    PluginRegistry,
    capability_registry,
    default_plugins,
    register_operator,
    register_oracle,
    register_sensor,
    register_tool,
)

__all__ = [
    "CapabilityCatalog",
    "CapabilityDescriptor",
    "PluginError",
    "PluginRegistry",
    "capability_registry",
    "default_plugins",
    "register_operator",
    "register_oracle",
    "register_sensor",
    "register_tool",
]
