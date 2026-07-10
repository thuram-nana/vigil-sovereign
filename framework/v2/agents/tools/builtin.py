"""
agents.tools.builtin — the built-in reference tools (W1.4).

These are SAFE, deterministic, no-egress INTERNAL capabilities that exercise the tool seam
end-to-end today (before Wave 2 plugs in integrated sensors). They are Tier 1 (passive
observation over data CRUCIBLE already holds), require no entitlement, and reach no host.
"""

from __future__ import annotations

from .base import Tool, ToolContext, ToolRegistry, ToolResult


class ReverifyFindingTool:
    """Re-verify a finding's retained oracle certificate OFFLINE, on demand — prove-don't-guess
    as a callable capability. Given ``args['finding']`` (a dict carrying ``bug_class`` and the
    finding's ``oracle_context``), it re-executes that certificate through the veracity firewall
    against no live target and reports whether it still GROUNDS as a fact. The result is a
    provenance-labelled observation (GROUNDED / not), never a new finding — so the reasoning core
    can ask 'does this still hold?' at any point without weakening the oracle's authority.

    Safe: no egress, no entitlement, deterministic (the same certificate re-executes identically)."""

    name = "reverify_finding"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        finding = args.get("finding") if isinstance(args, dict) else None
        if not isinstance(finding, dict):
            return ToolResult(
                ok=False,
                note="reverify_finding requires args['finding'] — a dict with bug_class + oracle_context")
        try:
            from ...veracity import admit_finding
            admitted = admit_finding(finding, ctx.world)
        except Exception as e:
            return ToolResult(ok=False, note=f"re-verification error: {e}")
        is_fact = bool(getattr(admitted, "is_fact", False))
        verdict = getattr(getattr(admitted, "verdict", None), "value", "") or (
            "fact" if is_fact else "not-grounded")
        reason = str(getattr(admitted, "reason", ""))
        bug_class = str(finding.get("bug_class", "?"))
        return ToolResult(
            ok=True,
            summary=f"reverify {bug_class}: {'GROUNDED (fact)' if is_fact else 'NOT re-grounded'}",
            output={"is_fact": is_fact, "verdict": str(verdict), "reason": reason})


def register_builtin_tools(registry: ToolRegistry) -> ToolRegistry:
    """Register the built-in reference tools onto ``registry`` and return it."""
    registry.register(ReverifyFindingTool())
    return registry


def default_registry() -> ToolRegistry:
    """A fresh registry pre-loaded with the built-in reference tools."""
    return register_builtin_tools(ToolRegistry())
