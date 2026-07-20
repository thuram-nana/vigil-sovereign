"""
agents.tools.builtin — the built-in reference tools (W1.4).

These are SAFE, deterministic, no-egress INTERNAL capabilities that exercise the tool seam
end-to-end today (before Wave 2 plugs in integrated sensors). They are Tier 1 (passive
observation over data CRUCIBLE already holds), require no entitlement, and reach no host.
"""

from __future__ import annotations

import re
from typing import Any

from .base import Tool, ToolContext, ToolRegistry, ToolResult

# The reflection marker the wrapped reflection check plants — `crucible<slugified-point-id>mark`, where
# the slug is alphanumeric (`scanner.checks._slugify`). Used by the discovery probe's content-type gate
# to find WHICH response actually reflected the marker (so the gate keys on the reflecting response).
_MARKER_RE = re.compile(r"crucible[A-Za-z0-9]*mark")

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

    def __init__(self, send: Any, *, check: Any = None, checks: Any = None,
                 max_requests: int = 8) -> None:
        self._send = send
        # The check set to run over the discovered surface. Default: the single REFLECTED_XSS check
        # (byte-identical to the pre-generalisation probe). ``checks`` (Slice-3, opt-in) runs a CURATED,
        # near-zero-FP set — each check already oracle-adjudicated and evidence-carrying — so ONE probe
        # tests a discovered endpoint for more than one bug class. ``check`` (singular) stays for
        # back-compat; ``checks`` wins when both are given.
        if checks:
            self._checks = tuple(checks)
        elif check is not None:
            self._checks = (check,)
        else:
            self._checks = None   # resolved to (REFLECTED_XSS,) lazily in run()
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
        checks = self._checks if self._checks is not None else (REFLECTED_XSS,)
        request = HttpRequest(
            method="GET", url=target.strip(),
            headers=[("User-Agent", "OBSIDIAN/1.0 (authorized owner-test)")])
        _raw_send = self._send

        # Run each curated check over the discovered surface. Each iteration gets its OWN recording
        # buffer so the XSS content-type gate keys on THIS check's reflecting response — never a sibling
        # check's HTML page (the multi-param cross-contamination FP a prior review caught). All checks are
        # scoped to QUERY-VALUE insertion (never path rewriting → cannot trip a server's own not-found
        # page) and each is oracle-adjudicated + evidence-carrying, so the shared oracle / benchmark stay
        # byte-identical (this generalisation lives entirely in the discover-only probe path).
        all_dumps: list = []
        minted_any = False
        ct_gated_any = False
        checks_run: list[str] = []
        for check in checks:
            seen: list[tuple[bool, str]] = []   # (is_affirmatively_html, body) per response THIS check saw

            def _recording_send(req: Any, _seen: list = seen):
                resp = _raw_send(req)
                try:
                    headers = resp.get("headers", []) if isinstance(resp, dict) else []
                    ctype = ""
                    for k, v in headers or []:
                        if str(k).lower() == "content-type":
                            ctype = str(v).lower()
                            break
                    body = resp.get("body", "") if isinstance(resp, dict) else ""
                    _seen.append(("text/html" in ctype, body or ""))
                except Exception:
                    pass
                return resp

            try:
                engine = AuditEngine(_recording_send, max_requests=self._max_requests)
                findings = engine.audit(request, checks=(check,),
                                        insertion_kinds=(InsertionKind.QUERY_VALUE,))
            except Exception:
                continue   # one check erroring never aborts the probe — the others still run
            checks_run.append(str(getattr(check, "id", "")))
            # near-zero-FP gate: mint an XSS-family finding only when the marker was REFLECTED INTO an
            # affirmatively-HTML response (a MIME-sniff-only / JSON / text reflection is inert). Applied
            # per-check on THIS check's own `seen`, so a sibling check's HTML page can never license it.
            bug_lower = str(getattr(check, "bug_class", "")).lower()
            if findings and "xss" in bug_lower:
                reflected_in_html = any(is_html and _MARKER_RE.search(body) for is_html, body in seen)
                if not reflected_in_html:
                    findings = []
                    ct_gated_any = True
            for f in findings:
                try:
                    all_dumps.append(f.model_dump(mode="json"))
                except Exception:
                    pass
            minted_any |= bool(findings)

        # deterministic order (the fold key) regardless of check-iteration order
        all_dumps.sort(key=lambda d: (str(d.get("bug_class", "")), str(d.get("endpoint", "")),
                                      str(d.get("insertion_point", ""))))
        target_s = target.strip()
        if minted_any:
            summary = (f"probe @ {target_s}: oracle FIRED — {len(all_dumps)} new finding(s) "
                       f"across {len(checks_run)} check(s)")
        elif ct_gated_any:
            summary = (f"probe @ {target_s}: reflection under a non-HTML content-type "
                       f"— not executable, not minted")
        else:
            summary = f"probe @ {target_s}: oracle did not fire (no finding)"
        return ToolResult(
            ok=True, summary=summary,
            output={"minted": minted_any, "findings": all_dumps, "checks_run": checks_run,
                    "endpoint": target_s, "content_type_gated": ct_gated_any})


def curated_probe_checks() -> tuple:
    """The CURATED, near-zero-FP check set the generalised discovery probe runs (Slice-3). Every check
    is EVIDENCE-CARRYING — it confirms only on a re-runnable oracle proof a benign response cannot
    trigger — and is scoped to QUERY-VALUE insertion:
      * REFLECTED_XSS   — a marker reflected into an affirmatively-HTML response (+ the content-type gate);
      * OPEN_REDIRECT   — a real redirect to the injected canary host (safe to run everywhere);
      * PATH_TRAVERSAL  — the target file's content signature appears in the response;
      * SSTI_EVAL_*     — the server COMPUTED the injected arithmetic (raw expression absent).

    DELIBERATELY EXCLUDED as an unsupervised discovery probe (review wcqss59lb, CRITICAL): the single-shot
    ``BOOLEAN_SQLI`` DifferentialCheck. A lone benign-vs-payload differential fires on ANY endpoint whose
    response legitimately differs between the two fixed strings — most perversely an app that VALIDATES
    input / WAF-blocks a quote (200 vs 403) — minting a FALSE confirmed boolean_sqli fact that folds into
    the report. A differential without a multi-round control (SPRT) cannot be near-zero-FP unsupervised,
    so it is not in the curated set; sound boolean-SQLi discovery would need the SPRT BooleanInferenceCheck
    under a dedicated FP review. OOB checks (SSRF/XXE/RCE) are likewise excluded — they self-skip without an
    OOBReceiver, a separate explicitly-gated step. Returns a fresh tuple; a missing check is skipped."""
    try:
        from ...scanner.checks import (
            OPEN_REDIRECT,
            PATH_TRAVERSAL,
            REFLECTED_XSS,
            SSTI_EVAL_BRACES,
            SSTI_EVAL_DOLLAR,
        )
    except Exception:
        return ()
    return (REFLECTED_XSS, OPEN_REDIRECT, PATH_TRAVERSAL, SSTI_EVAL_BRACES, SSTI_EVAL_DOLLAR)


def probe_surface_registry(send: Any, *, check: Any = None, checks: Any = None,
                           max_requests: int = 8) -> ToolRegistry:
    """A fresh registry carrying ONLY the gated ``probe_surface`` discovery tool, wired with the
    injected ``send`` (production: the gated executor's ``gated_fetch``; tests: a loopback send).
    Built ON DEMAND so the default autonomous path (discovery OFF) never constructs it and stays
    byte-identical. Deliberately NOT part of ``default_registry`` — discovery is opt-in only.

    ``checks`` (Slice-3, opt-in) runs the curated multi-class set (:func:`curated_probe_checks`) instead
    of the single REFLECTED_XSS default, so one probe tests a discovered surface for several bug classes."""
    reg = ToolRegistry()
    reg.register(ProbeSurfaceTool(send, check=check, checks=checks, max_requests=max_requests))
    return reg


def register_builtin_tools(registry: ToolRegistry) -> ToolRegistry:
    """Register the built-in reference tools onto ``registry`` and return it."""
    registry.register(ReverifyFindingTool())
    return registry


def default_registry() -> ToolRegistry:
    """A fresh registry pre-loaded with the built-in reference tools."""
    return register_builtin_tools(ToolRegistry())
