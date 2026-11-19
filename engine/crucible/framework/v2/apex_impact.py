"""apex_impact — APEX PR-3, Deliverable 1: chaining-to-DEMONSTRATED-impact (default OFF, ``VIGIL_APEX_IMPACT``).

The engagement's chaining phase (``scanner.orchestrator.AutonomousCampaign.chain_findings``) reasons FORWARD
over the oracle-confirmed facts and derives the multi-hop ATTACK PATHS from the attacker to the crown-jewel
nodes — but it is PURE reasoning (it sends no traffic, it mints nothing). This module is the opt-in extension
that turns those reasoned paths into a DEMONSTRATED-IMPACT report, honouring the sovereign rule end-to-end:

  * A path hop is marked DEMONSTRATED only when the confirmed finding anchoring it RE-FIRES NOW — the same
    deterministic oracle re-execution the veracity firewall uses (``verify.reverify.reverify_context``), over
    the finding's OWN retained ``oracle_context``. A hop whose finding no longer reproduces stays REASONED.
    This NEVER promotes anything (re-execution can only corroborate an already-confirmed fact or demote it);
    it mints no new fact and changes no oracle verdict.
  * The terminal impact class (data-access / account-takeover / privilege-escalation / host-control /
    cloud-takeover) is read from the crown-jewel node's KIND and the achieved-effect findings on the path —
    it describes WHAT the reasoned path reaches, not a new claim.
  * Actually PURSUING impact against the live target (the ``live_prover`` arm) is a TARGET-TOUCHING action, so
    it is taken ONLY when the injected ``gate`` (``conjunctive_gate.build_offense_gate``) ALLOWS it AND a
    ``live_prover`` is injected by an authorized caller. The in-engagement call passes NEITHER (it demonstrates
    via offline oracle re-execution only), so the default engage path sends no new traffic and ``make gate`` is
    byte-identical; the live arm is exercised by an authorized owner/prod-execution caller (and by the tests).

Flag OFF (the default) ⇒ ``apex_impact_enabled()`` is False, the ``engage._do_chaining`` tail never calls
:func:`pursue_impact`, ``EngagementResult.impact_report`` stays ``None``, and the engagement is byte-identical.

Pure/total/best-effort: any malformation (a torn path, an unbuildable context, a raising gate/prover) degrades
that path to a reasoned demonstration or is skipped — it NEVER sinks the engagement.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# ---- the master flag (keyless, offense-plane; mirrors redpen.engine.redpen_enabled) -----------------

APEX_IMPACT_ENV = "VIGIL_APEX_IMPACT"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def apex_impact_enabled() -> bool:
    """True iff APEX Impact & Closure is switched on (``VIGIL_APEX_IMPACT`` ∈ {1,true,yes,on}). Default OFF:
    unset / empty / any other value is OFF, and the chaining-to-impact pass is then never invoked. Keyless: it
    reads an env flag, never a secret — FATAL-2 clean. The sovereign plane reads the SAME var via
    ``sigil.config.apex_impact_enabled``; the integration plane via ``vigil_integration.apex_flags``."""
    return (os.environ.get(APEX_IMPACT_ENV) or "").strip().lower() in _TRUTHY


# ---- the demonstrated-impact model ------------------------------------------------------------------

#: crown-jewel node KIND (``worldmodel.models.NodeKind`` value) → the impact class a path reaching it achieves.
_IMPACT_BY_KIND: dict[str, str] = {
    "datastore": "data_access",
    "credential": "account_takeover",
    "principal": "account_takeover",
    "host": "host_control",
    "cloud_resource": "cloud_takeover",
}

#: achieved-effect finding bug_class → the impact it demonstrates, overriding the destination-kind heuristic
#: when such a finding anchors the path (these are the E-series oracle-confirmed achieved effects).
_IMPACT_BY_BUGCLASS: dict[str, str] = {
    "imds_credential_capture": "account_takeover",
    "secret_credential_validity": "account_takeover",
    "gcp_sa_impersonation": "account_takeover",
    "iam_escalation_primitive": "privilege_escalation",
    "k8s_rbac_privilege_grant": "privilege_escalation",
    "k8s_workload_misconfiguration": "privilege_escalation",
    "idor": "data_access",
    "bola": "data_access",
    "broken_access_control": "data_access",
    "deserialization": "host_control",
    "ssrf": "cloud_takeover",
}


@dataclass(frozen=True)
class ImpactStep:
    """One hop of a demonstrated-impact path. ``demonstrated`` is True iff a confirmed finding anchoring this
    hop re-fired NOW (oracle re-execution over its retained ``oracle_context``); else the hop is REASONED."""

    src: str
    dst: str
    edge: str
    technique: str
    demonstrated: bool = False


@dataclass
class ImpactDemonstration:
    """The demonstrated-impact assessment of ONE attack path. It restates a reasoned path and records which of
    its hops re-reproduce NOW; it mints no fact. ``demonstrated`` ⇒ the path is anchored on at least one
    confirmed finding whose oracle RE-FIRES over retained evidence (a live-reproducing foothold)."""

    destination: str
    terminal_impact: str
    hops: int
    foothold_findings: list[str]          # check_ids of confirmed findings on this path that RE-FIRE now
    demonstrated: bool                    # ≥1 foothold finding re-fires ⇒ the path's foothold is live-reproducing
    authorization: str                    # "unchecked" | "allowed" | "denied:<reason>" — the gate verdict for live pursuit
    live_demonstrated: bool = False       # gate ALLOWED + an injected live_prover confirmed the terminal step live
    steps: list[ImpactStep] = field(default_factory=list)
    note: str = ""


@dataclass
class ImpactReport:
    """The engagement's demonstrated-impact deliverable (``EngagementResult.impact_report``). Empty / absent on
    the default path (flag OFF) ⇒ byte-identical. Mints nothing; every DEMONSTRATED label is an oracle re-fire."""

    demonstrations: list[ImpactDemonstration] = field(default_factory=list)
    demonstrated_paths: int = 0           # paths whose foothold finding re-fires now
    live_pursued: int = 0                 # paths where the gate ALLOWED live pursuit and a prover ran
    note: str = ""


def _node_kind_name(world: Any, node_id: str) -> str:
    try:
        node = world.get_node(node_id)
    except Exception:  # noqa: BLE001
        return ""
    if node is None:
        return ""
    kind = getattr(node, "kind", None)
    return str(getattr(kind, "value", kind) or "").strip().lower()


def _path_node_ids(path: Any) -> list[str]:
    steps = list(getattr(path, "steps", None) or [])
    if not steps:
        return []
    ids = [str(getattr(steps[0], "src", ""))]
    ids.extend(str(getattr(s, "dst", "")) for s in steps)
    return [i for i in ids if i]


def _classify_terminal_impact(world: Any, destination: str, foothold_bugclasses: "list[str]") -> str:
    """Impact class a path reaching ``destination`` achieves. An achieved-effect finding bug_class on the path
    wins (it is the oracle-confirmed effect); otherwise fall back to the crown-jewel node KIND; else 'reach'."""
    for bc in foothold_bugclasses:
        got = _IMPACT_BY_BUGCLASS.get(str(bc or "").strip().lower())
        if got:
            return got
    kind = _node_kind_name(world, destination)
    return _IMPACT_BY_KIND.get(kind, "reach")


def pursue_impact(
    report: Any,
    world: Any,
    attack_paths: "list[Any]",
    *,
    slug: str = "",
    target_url: str = "",
    gate: Optional[Callable[..., Any]] = None,
    live_prover: Optional[Callable[[Any], bool]] = None,
    reverify: Optional[Callable[..., Any]] = None,
    max_paths: int = 5,
) -> ImpactReport:
    """Turn the reasoned ATTACK PATHS into a DEMONSTRATED-IMPACT report (APEX PR-3 Deliverable 1).

    For each of the top ``max_paths`` paths: find the confirmed findings anchoring it (their ``endpoint:``
    nodes lie on the path), RE-FIRE each one's retained ``oracle_context`` (``reverify_context`` — the firewall
    primitive; injected as ``reverify`` for tests), classify the terminal impact, and — ONLY where the injected
    ``gate`` ALLOWS live pursuit AND a ``live_prover`` is supplied by an authorized caller — attempt the live
    demonstration of the terminal step. Mints NO fact; re-execution can only corroborate or demote. Total: a
    malformed path is skipped, a raising gate/prover degrades that path to reasoned, never a crash.

    ``gate`` is ``conjunctive_gate.build_offense_gate``'s per-call ``gate(tool, url, destructive=False)``; when
    ``None`` (the in-engagement call), no live pursuit is attempted and ``authorization`` is 'unchecked' — the
    demonstration is the offline oracle re-execution, which touches no target. The live arm (the ONLY
    target-touching step) is unconditionally gated: it runs only after ``gate(...).allowed`` is True."""
    rep = ImpactReport()
    try:
        if reverify is None:
            from .verify.reverify import reverify_context as reverify  # lazy — framework sibling
        actives = list(getattr(report, "active_findings", None) or [])
        # endpoint node id -> list of confirmed findings projected onto it (its oracle_context drives the re-fire)
        by_endpoint: dict[str, list[Any]] = {}
        for f in actives:
            param = str(getattr(f, "param", "") or "")
            if param:
                by_endpoint.setdefault(f"endpoint:{param}", []).append(f)
        # re-fire each confirmed finding at most once (memoised by identity) → reproduced-now map
        refired: dict[int, bool] = {}

        def _refires(f: Any) -> bool:
            key = id(f)
            if key in refired:
                return refired[key]
            ok = False
            ctx = getattr(f, "oracle_context", None)
            bc = str(getattr(f, "bug_class", "") or "")
            if isinstance(ctx, dict) and ctx and bc:
                try:
                    rr = reverify(ctx, bug_class=bc, ref=str(getattr(f, "check_id", "") or "finding"))
                    ok = bool(getattr(rr, "reproduced", False))
                except Exception:  # noqa: BLE001 — a context we cannot re-fire is simply not demonstrated
                    ok = False
            refired[key] = ok
            return ok

        for path in list(attack_paths or [])[: max(0, int(max_paths))]:
            try:
                node_ids = _path_node_ids(path)
                if not node_ids:
                    continue
                on_path = set(node_ids)
                foothold = [f for ep, fs in by_endpoint.items() if ep in on_path for f in fs]
                reproduced = [f for f in foothold if _refires(f)]
                foothold_refs = sorted({str(getattr(f, "check_id", "") or "") for f in reproduced} - {""})
                demonstrated = bool(reproduced)
                bugclasses = [str(getattr(f, "bug_class", "") or "") for f in reproduced] or \
                             [str(getattr(f, "bug_class", "") or "") for f in foothold]
                destination = str(getattr(path, "destination", "") or (node_ids[-1] if node_ids else ""))
                terminal = _classify_terminal_impact(world, destination, bugclasses)

                # the demonstrated flag per hop: a hop is demonstrated iff a RE-FIRING foothold finding's
                # endpoint is its destination (the live-reproducing exploit established that reach).
                demo_nodes = {f"endpoint:{getattr(f, 'param', '')}" for f in reproduced}
                steps: list[ImpactStep] = []
                for s in list(getattr(path, "steps", None) or []):
                    steps.append(ImpactStep(
                        src=str(getattr(s, "src", "")), dst=str(getattr(s, "dst", "")),
                        edge=str(getattr(s, "edge", "")), technique=str(getattr(s, "technique", "")),
                        demonstrated=(str(getattr(s, "dst", "")) in demo_nodes)))

                # AUTHORIZATION for live pursuit — the ONLY target-touching step goes through the gate.
                authorization = "unchecked"
                live_demonstrated = False
                if gate is not None:
                    try:
                        verdict = gate("apex_impact_pursue", target_url or destination, destructive=False)
                        allowed = bool(getattr(verdict, "allowed", False))
                        authorization = "allowed" if allowed else \
                            "denied:" + (str(getattr(verdict, "reason", "") or "refused")[:120])
                    except Exception as exc:  # noqa: BLE001 — a raising gate is a DENY (fail-closed)
                        allowed = False
                        authorization = "denied:gate-error:" + type(exc).__name__
                    # live demonstration: gated AND an authorized caller injected a prover AND a re-firing foothold
                    if allowed and live_prover is not None and reproduced:
                        try:
                            live_demonstrated = bool(live_prover(reproduced[0]))
                            rep.live_pursued += 1
                        except Exception:  # noqa: BLE001 — a prover failure is not a demonstration
                            live_demonstrated = False

                if demonstrated:
                    rep.demonstrated_paths += 1
                rep.demonstrations.append(ImpactDemonstration(
                    destination=destination, terminal_impact=terminal, hops=len(steps),
                    foothold_findings=foothold_refs, demonstrated=demonstrated,
                    authorization=authorization, live_demonstrated=live_demonstrated, steps=steps,
                    note=("" if foothold else "no confirmed finding anchors this reasoned path")))
            except Exception:  # noqa: BLE001 — one torn path never aborts the pass
                continue
        rep.note = (f"{rep.demonstrated_paths}/{len(rep.demonstrations)} path(s) anchored on a live-reproducing "
                    f"foothold; {rep.live_pursued} live-pursued under the gate")
    except Exception:  # noqa: BLE001 — the whole pass is best-effort; a failure yields an empty report
        return ImpactReport(note="impact pass failed (best-effort) — the scan report stands")
    return rep


__all__ = ["apex_impact_enabled", "APEX_IMPACT_ENV", "ImpactStep", "ImpactDemonstration",
           "ImpactReport", "pursue_impact"]
