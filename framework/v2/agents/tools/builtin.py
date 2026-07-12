"""
agents.tools.builtin — the built-in reference tools (W1.4).

These are SAFE, deterministic, no-egress INTERNAL capabilities that exercise the tool seam
end-to-end today (before Wave 2 plugs in integrated sensors). They are Tier 1 (passive
observation over data CRUCIBLE already holds), require no entitlement, and reach no host.
"""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolContext, ToolRegistry, ToolResult

# The entitlement capability an ACTIVE probe honestly declares ("active probing within scope").
# Imported guardedly so the tool module never hard-couples on the entitlement package: on any import
# trouble the capability degrades to None (the entitlement gate is then a no-op, exactly as for the
# safe built-in tools) — a fail-open on the ADVISORY entitlement metadata only; scope still authorizes.
try:
    from ...entitlement import Capability as _Capability
    _ACTIVE_RECON = _Capability.ACTIVE_RECON
except Exception:                                   # pragma: no cover - entitlement always importable
    _ACTIVE_RECON = None


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


class ProbeSurfaceTool:
    """DISCOVERY probe (W-C, first slice): run ONE existing scanner check against a localhost endpoint
    and mint a NEW oracle-confirmed finding ONLY when the check's deterministic oracle FIRES over the
    evidence it collected. This is the first honest step toward a DISCOVERING autonomous loop — today
    the loop only RE-VERIFIES (``reverify_finding``). A probe-leaf on an unexplored ENDPOINT drives
    this tool; the wrapped check probes the surface; and the ORACLE — never the planner, never this
    tool — decides confirmation.

    REUSE, not new offense. It wraps ONE existing ``scanner.checks.Check`` (default ``REFLECTED_XSS``,
    a marker-reflection side-effect probe — one request, deterministic canary) driven by the existing
    ``scanner.engine.AuditEngine``, whose ``confirm_finding`` gate is the SOLE authority for a finding.
    No new attack capability is built here; this is autonomy plumbing over an existing check.

    Gated + localhost/authorized-only. It declares ``capability=ACTIVE_RECON`` (active probing within
    scope) and acts on ``args['target']``, so the FULL ``invoke_tool`` chain (kill-switch → entitlement
    → scope → destructive → egress) authorizes the probe BEFORE ``run``; a tripped kill-switch or an
    out-of-scope target REFUSES it and it probes nothing. The actual HTTP is issued by an INJECTED
    ``send`` — in production the charter/scope/egress/rate-gated executor (``HttpExecutor.gated_fetch``,
    exactly the send the whole scanner rides), in tests a loopback send — so egress stays enforced at
    the point of I/O too. ``egress_hosts`` is left empty at this seam (the injected send is what reaches
    the host, mirroring the ``declared_service`` sensor); the load-bearing host authorization is the
    scope gate over ``args['target']``.

    Prove-don't-guess. The ToolResult carries the NEW AuditFinding(s) — serialised, with their retained
    ``oracle_context`` — ONLY when the oracle fired (``minted=True``); otherwise it honestly reports the
    probe ran and confirmed nothing (``minted=False``). The tool never promotes a finding on its own."""

    name = "probe_surface"
    tier = "T2"
    capability = _ACTIVE_RECON     # active probing within scope; None-degraded if entitlement absent
    destructive = False
    egress_hosts: tuple = ()       # the injected send performs (gated) egress; scope authorizes the target

    def __init__(self, send: Any, *, check: Any = None, max_requests: int = 8) -> None:
        self._send = send
        self._check = check
        self._max_requests = max(1, int(max_requests))

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        target = args.get("target") if isinstance(args, dict) else None
        if not isinstance(target, str) or not target.strip():
            return ToolResult(
                ok=False,
                note="probe_surface requires args['target'] — a localhost endpoint URL to probe")
        if not callable(self._send):
            return ToolResult(
                ok=False, note="probe_surface has no injected send (misconfigured — no discovery I/O)")
        try:
            from ...scanner.checks import REFLECTED_XSS
            from ...scanner.engine import AuditEngine
            from ...scanner.insertion import HttpRequest, InsertionKind
        except Exception as e:
            return ToolResult(ok=False, note=f"probe_surface could not load the scanner check to wrap: {e}")
        check = self._check if self._check is not None else REFLECTED_XSS
        request = HttpRequest(
            method="GET", url=target.strip(),
            headers=[("User-Agent", "OBSIDIAN/1.0 (authorized owner-test)")])
        try:
            engine = AuditEngine(self._send, max_requests=self._max_requests)
            # Target the endpoint lead's QUERY-VALUE parameters — the canonical reflected-parameter
            # surface a URL lead exposes. Scoping the probe to the values (not path segments / param
            # names) keeps it precise and bounded: it never rewrites the path, so it cannot trip a
            # server's own not-found/error page, and it confirms only a real parameter reflection.
            findings = engine.audit(request, checks=(check,),
                                    insertion_kinds=(InsertionKind.QUERY_VALUE,))
        except Exception as e:
            return ToolResult(ok=False, note=f"probe error: {e}")
        minted = bool(findings)
        dumps: list = []
        for f in findings:
            try:
                dumps.append(f.model_dump(mode="json"))
            except Exception:
                pass
        bug = str(getattr(check, "bug_class", "?"))
        return ToolResult(
            ok=True,
            summary=(f"probe {bug} @ {target.strip()}: oracle FIRED — {len(dumps)} new finding(s)"
                     if minted else f"probe {bug} @ {target.strip()}: oracle did not fire (no finding)"),
            output={"minted": minted, "findings": dumps, "check_id": str(getattr(check, "id", "")),
                    "bug_class": bug, "endpoint": target.strip()})


def probe_surface_registry(send: Any, *, check: Any = None, max_requests: int = 8) -> ToolRegistry:
    """A fresh registry carrying ONLY the gated ``probe_surface`` discovery tool, wired with the
    injected ``send`` (production: the gated executor's ``gated_fetch``; tests: a loopback send).
    Built ON DEMAND so the default autonomous path (discovery OFF) never constructs it and stays
    byte-identical. Deliberately NOT part of ``default_registry`` — discovery is opt-in only."""
    reg = ToolRegistry()
    reg.register(ProbeSurfaceTool(send, check=check, max_requests=max_requests))
    return reg


def register_builtin_tools(registry: ToolRegistry) -> ToolRegistry:
    """Register the built-in reference tools onto ``registry`` and return it."""
    registry.register(ReverifyFindingTool())
    return registry


def default_registry() -> ToolRegistry:
    """A fresh registry pre-loaded with the built-in reference tools."""
    return register_builtin_tools(ToolRegistry())
