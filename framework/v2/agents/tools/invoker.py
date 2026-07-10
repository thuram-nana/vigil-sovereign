"""
agents.tools.invoker — run a registered tool through the FAIL-CLOSED gate chain (W1.4).

There is no single reusable non-HTTP gate abstraction in the codebase (the 6-gate chain lives
inline in ``HttpExecutor._run_gates``), so this composes the standalone gates itself — the SAME
fail-closed checks, minus the HTTP-specific parts — before a tool ever runs:

    kill-switch  ->  entitlement (per the tool's declared capability)  ->  charter scope (if the
    tool acts on a host)  ->  destructive-confirm  ->  egress allowlist (if the tool reaches hosts)

Order is intentional and load-bearing: a tripped kill-switch or a missing entitlement refuses
before any scope/host work. Every gate is fail-closed — a denial OR an internal error in a gate
refuses the invocation (the tool never runs). Every invocation records a ``tool_call`` BEFORE it
runs (intent on the immutable stream even if it refuses) and a ``tool_result`` after; a refusal
also lands as a ``refusal`` event. Emission is via a duck-typed sink (``agents.SpineSink``) and is
best-effort — a spine write never perturbs the invocation.

Deterministic: registry lookup, gate composition and event emission are a pure function of
``(tool, args, gates, ctx)``. No wallclock, no rng.
"""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolContext, ToolRegistry, ToolResult


def _args_summary(args: object) -> str:
    """A short, redacted one-line view of the arguments — keys only for a dict (never the values,
    which may carry secrets/large payloads), truncated. Never the raw args."""
    if isinstance(args, dict):
        return "{" + ", ".join(sorted(str(k) for k in args)[:12]) + "}"
    return str(type(args).__name__)


def _as_hosts(value: object) -> tuple:
    """Normalise a tool's declared ``egress_hosts`` to a tuple of host strings — DEFENSIVELY and
    without ever raising (base.py's contract: metadata is read defensively, never a crash):

      * falsy (``()``/``None``/``""``) -> ``()`` (no egress gate);
      * a str -> ONE host (never iterated per character — the common author typo for a 1-tuple);
      * a proper iterable -> the hosts it yields;
      * a truthy NON-iterable (a misconfiguration, e.g. ``True``/an int) -> a sentinel host that
        the egress gate cannot match, so a tool that CLAIMS egress but declares it malformed is
        REFUSED (fail-closed) rather than crashing or silently skipping the gate."""
    try:
        if not value:                                   # inside the try: even a raising __bool__/
            return ()                                   # __len__ cannot escape
        if isinstance(value, (str, bytes)):
            return (value.decode("utf-8", "replace") if isinstance(value, bytes) else value,)
        return tuple(str(h) for h in value)             # type: ignore[union-attr]
    except Exception:
        # ANY failure (raising __bool__/__len__/__iter__, an element whose str() raises, a non-
        # iterable) -> a sentinel host the allowlist cannot match, so egress REFUSES (fail-closed).
        return ("<malformed-egress-hosts>",)


def _gate(tool: Tool, ctx: ToolContext, *, tier: str, capability: Any,
          destructive: bool, egress_hosts: tuple, target: str) -> tuple[str, str] | None:
    """Run the fail-closed gate chain. Returns ``(gate, reason)`` on the FIRST refusal, or None if
    every gate passes. Each gate is wrapped so a raised denial (or any internal error) becomes a
    refusal — fail-closed by construction."""
    # 1. kill-switch — a tripped switch halts everything, before any other work.
    try:
        from ...authority import KillSwitch
        ks = KillSwitch(ctx.slug)
        if ks.is_tripped():
            return ("kill-switch", ks.reason() or "kill-switch tripped")
    except Exception as e:
        return ("kill-switch", f"kill-switch check failed (fail-closed): {e}")

    # 2. entitlement — a tool that declares a capability must be entitled to it. require_capability
    #    RAISES on denial; any exception here refuses (fail-closed).
    if capability is not None:
        try:
            from ...entitlement import require_capability
            require_capability(capability)
        except Exception as e:
            return ("entitlement", f"capability {getattr(capability, 'value', capability)} not entitled: {e}")

    # 3. charter scope — only when the tool acts on a concrete host/target.
    if target:
        try:
            from ...agents.http_executor import parse_posture
            from ...agents.scope_gate import validate_action
            try:
                posture = parse_posture(ctx.slug)
            except Exception:
                posture = "TEST"
            decision = validate_action(slug=ctx.slug, method="GET", target_url=target, posture=posture)
            if not getattr(decision, "allowed", False):
                return ("scope", getattr(decision, "refusal_kind", "") or "target out of charter scope")
        except Exception as e:
            return ("scope", f"scope check failed (fail-closed): {e}")

    # 4. destructive-confirm — a destructive tool needs explicit operator approval (default-deny).
    if destructive:
        approved = False
        cb = ctx.prompt_callback
        if cb is not None:
            try:
                approved = bool(cb(f"tool {tool.name!r} is destructive — allow?", 30.0))
            except Exception:
                approved = False
        if not approved:
            return ("destructive-confirm", "destructive tool not confirmed by operator")

    # 5. egress allowlist — a tool that reaches hosts may only reach charter-allowlisted ones.
    if egress_hosts:
        try:
            from ...agents.egress_guard import build_engagement_allowlist
            allow = build_engagement_allowlist(slug=ctx.slug)
        except Exception as e:
            return ("egress", f"could not build egress allowlist (fail-closed): {e}")
        for host in egress_hosts:
            try:
                permitted = allow.permits(str(host))
            except Exception:
                permitted = False
            if not permitted:
                return ("egress", f"egress host not on charter allowlist: {host}")

    return None


def invoke_tool(registry: ToolRegistry, name: str, args: dict, ctx: ToolContext,
                *, sink: Any = None, parent_id: int | None = None) -> ToolResult:
    """Run the registered tool ``name`` under the fail-closed gate chain, recording ``tool_call``
    (before) and ``tool_result`` (after) on the event spine. A gate refusal returns a refused
    ``ToolResult`` and records a ``refusal`` event; the tool is never run. Best-effort emission —
    a ``sink`` of None simply omits the events."""
    tool = registry.get(name)
    if tool is None:
        _emit_result(sink, name, ToolResult(ok=False, note=f"no such tool: {name}"), None)
        return ToolResult(ok=False, note=f"no such tool: {name}")

    tier = str(getattr(tool, "tier", "T1"))
    capability = getattr(tool, "capability", None)
    destructive = bool(getattr(tool, "destructive", False))
    egress_hosts = _as_hosts(getattr(tool, "egress_hosts", ()))
    target = str(args.get("target", "")) if isinstance(args, dict) else ""

    # Record the intent BEFORE anything else — even a refused/failed call is on the stream.
    call_id = _emit_call(sink, tool.name, tier=tier, capability=capability, target=target,
                         args_summary=_args_summary(args), parent_id=parent_id)

    refusal = _gate(tool, ctx, tier=tier, capability=capability, destructive=destructive,
                    egress_hosts=egress_hosts, target=target)
    if refusal is not None:
        gate, reason = refusal
        _emit_refusal(sink, gate, tool.name, reason)
        result = ToolResult(ok=False, refused=True, gate=gate, note=reason)
        _emit_result(sink, tool.name, result, call_id)
        return result

    try:
        result = tool.run(args, ctx)
        if not isinstance(result, ToolResult):
            result = ToolResult(ok=result is not None, summary=str(result)[:200])
    except Exception as e:
        result = ToolResult(ok=False, note=f"tool error: {e}")
    _emit_result(sink, tool.name, result, call_id)
    return result


# ---- best-effort spine emission (duck-typed sink; None => no-op) --------------


def _emit_call(sink: Any, tool: str, *, tier: str, capability: Any, target: str,
               args_summary: str, parent_id: int | None) -> int | None:
    if sink is None:
        return None
    try:
        cap = getattr(capability, "value", "") if capability is not None else ""
        return sink.tool_call(tool, tier=tier, capability=str(cap), target=target,
                              args_summary=args_summary, parent_id=parent_id)
    except Exception:
        return None


def _emit_result(sink: Any, tool: str, result: ToolResult, call_id: int | None) -> None:
    if sink is None:
        return
    try:
        sink.tool_result(tool, ok=result.ok, refused=result.refused, gate=result.gate,
                         summary=result.summary, note=result.note, tool_call_id=call_id)
    except Exception:
        pass


def _emit_refusal(sink: Any, gate: str, tool: str, reason: str) -> None:
    if sink is None:
        return
    try:
        sink.refusal(gate, f"invoke tool {tool}", reason=reason, fatal=(gate == "kill-switch"))
    except Exception:
        pass
