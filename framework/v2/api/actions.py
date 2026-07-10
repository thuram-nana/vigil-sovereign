"""
api.actions — the GATED action surface of the external API.

There is exactly one way an action runs: ``agents.tools.invoke_tool``. Every POST the
API accepts is translated into a tool invocation and threaded through the FULL
fail-closed gate chain — kill-switch, entitlement (per the tool's declared capability),
charter scope (if the tool acts on a host), destructive-confirm, egress allowlist. An
unauthorized action is therefore REFUSED over the API EXACTLY as it would be locally:
the tool never runs, nothing is sent, and the refusal (gate + reason) is returned.

No ungated capability is exposed. The registry the API drives (``default_registry``)
holds only SAFE tools — re-verify a finding (offline, no egress) and import a
third-party report (passive, no egress). Even if a caller names a dangerous tool it is
either absent (``no such tool``) or, if present, refused by the gate chain without an
entitlement. Prompt-driven destructive-confirm defaults to DENY (no interactive
operator on an API request), so a destructive tool can never be auto-approved here.
"""

from __future__ import annotations

from typing import Any

from ..agents.tools.base import ToolContext, ToolRegistry
from ..agents.tools.builtin import register_builtin_tools
from ..agents.tools.invoker import invoke_tool
from ..imports.tool import ImportFindingsTool


def default_registry(*, import_store_factory=None) -> ToolRegistry:
    """The SAFE tool registry the API drives: the built-in reference tools
    (``reverify_finding``) plus the external-tool importer (``import_findings``). No
    egress tool, no exploit tool. ``import_store_factory`` (tests) overrides the
    importer's persistence target; None uses the durable intel store."""
    registry = register_builtin_tools(ToolRegistry())
    if import_store_factory is not None:
        registry.register(ImportFindingsTool(store_factory=import_store_factory))
    else:
        registry.register(ImportFindingsTool())
    return registry


def _never_approve(_question: str, _timeout: float) -> bool:
    """destructive-confirm callback for an API request: always DENY. There is no
    interactive operator on an HTTP request, so a destructive tool must never be
    auto-approved — it fails the destructive-confirm gate (default-deny)."""
    return False


def _result_dict(result) -> dict[str, Any]:
    return {
        "ok": bool(result.ok),
        "refused": bool(result.refused),
        "gate": result.gate,
        "summary": result.summary,
        "note": result.note,
        "output": result.output,
    }


def invoke(registry: ToolRegistry, *, slug: str, tool: str, args: dict,
           world=None) -> dict[str, Any]:
    """Invoke ``tool`` through the fail-closed gate chain and return a JSON-safe result
    dict. ``slug`` binds the invocation to its charter/scope/kill-switch. Untrusted
    inputs are coerced defensively: a non-dict ``args`` becomes ``{}``."""
    if not isinstance(args, dict):
        args = {}
    ctx = ToolContext(slug=str(slug or ""), world=world, prompt_callback=_never_approve)
    result = invoke_tool(registry, str(tool or ""), args, ctx)
    return _result_dict(result)


def import_findings(registry: ToolRegistry, *, slug: str, fmt: str, report: str,
                    source_tool: str | None = None, world=None) -> dict[str, Any]:
    """Convenience wrapper for the importer action — still routed through
    ``invoke``/``invoke_tool`` so it passes the SAME gate chain (a tripped kill-switch
    refuses the import before it runs)."""
    args: dict[str, Any] = {"format": fmt, "report": report}
    if source_tool:
        args["source_tool"] = source_tool
    return invoke(registry, slug=slug, tool="import_findings", args=args, world=world)
