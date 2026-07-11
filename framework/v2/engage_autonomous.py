"""
framework.v2.engage_autonomous — the opt-in AUTONOMOUS OODA cycle (Workstream A, first slice).

Today ``engage.run_engagement`` is a fixed pipeline: crawl → audit → confirm → chain → score. The
reasoning/planning/tool-driving machinery (``planner.Planner``, ``agents.coordinator.Coordinator``,
and the gated tool seam ``agents.tools.invoker.invoke_tool``) is built but never RUN in a real
engagement. This module wires that dormant loop into ONE real, bounded OODA cycle that runs ONLY
when the operator opts in with ``engage --autonomous`` — the default engage path never imports or
touches anything here, so it stays byte-identical.

One cycle, over the AUTHORITATIVE ``EngagementResult`` the scan already produced:

  * OBSERVE  — the run's shared ``WorldModel`` (post-scan: WEBAPP/ENDPOINT/finding nodes + the
    chained attack facts) and the oracle-confirmed findings.
  * ORIENT   — build a goal tree over the confirmed findings and construct the ``Planner`` over the
    run world-model (objectives = crown-jewel node kinds, source = the attacker foothold). The
    planner's world-aware selection PICKS the next action (a leaf on the highest-value route to a
    crown jewel, not merely the greediest one).
  * ACT      — drive the picked action as a GATED tool call through ``invoke_tool`` (the full
    fail-closed chain: kill-switch → entitlement → scope → destructive-confirm → egress). The first
    slice drives the SAFE built-in ``reverify_finding`` tool (re-execute a finding's own retained
    oracle certificate) — deterministic, Tier-1, no egress. Every call is gated; a tripped
    kill-switch REFUSES it and the tool never runs.
  * UPDATE   — fold the tool's observation back into the world-model (annotate the finding's node
    with the live re-grounding verdict) and update the goal tree (leaf succeeded / failed).
  * RE-ORIENT— re-run the planner's selection over the now-updated tree/world; the pick changes,
    proving the loop closed.

The A/B/F interface contract (so WS-B and WS-F compose WITHOUT editing engage.py). Each hook is
imported with a graceful ImportError/attribute fallback to a no-op, so ``--autonomous`` works
standalone TODAY and lights up automatically when B/F land their modules:

  * ``from .engage_fusion import fuse_sensors`` — ``fuse_sensors(world, slug, ctx) -> list``
    (WS-B: fold gated-SENSOR observations into the run world-model). Absent → skipped (0 fused).
  * ``from .engage_reasoning import reason_step`` — ``reason_step(world, findings, ctx) -> object``
    (WS-F: LLM/planner reasoning advice). Absent → skipped (None).

Doctrine, by construction:
  * PROVE-DON'T-GUESS. The cycle NEVER promotes a finding or overrides an oracle. ``reverify_finding``
    can only re-confirm or DEMOTE via the veracity firewall; the tool output is a provenance-labelled
    observation, never a new fact. The authoritative ``ScanReport`` is untouched.
  * FAIL-CLOSED, GATED, LOCALHOST/AUTHORIZED-ONLY. Every tool call flows through ``invoke_tool``'s
    gate chain. Preflight (in ``engage.run_engagement``) already refused an out-of-scope / kill-
    switched engagement before this cycle can run; each tool call is re-gated regardless.
  * DETERMINISM. Selection (``goal_tree.best_open_leaf_pathaware`` over ``pathsearch.best_paths``),
    the gated invoke, and the fold are pure functions of ``(result, world, tree)`` — no wallclock,
    no rng. Running the cycle twice over the same result yields the same step sequence.
  * ADDITIVE + DEFAULT-OFF. Nothing here runs unless ``engage --autonomous`` is passed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoid import-time coupling on the default engage path
    from .engage import EngagementResult
    from .worldmodel.graph import WorldModel


# ---------------------------------------------------------------------------
# A/B/F interface hooks — graceful ImportError/attribute fallback to a no-op.
# These call sites + fallbacks are the CONTRACT WS-B and WS-F build against.
# ---------------------------------------------------------------------------


def _fuse_sensors(world: "WorldModel | None", slug: str, ctx: Any) -> list:
    """WS-B seam. Calls ``engage_fusion.fuse_sensors(world, slug, ctx) -> list`` to fold gated-
    sensor observations into the run world-model. Absent module / bad signature / any error → ``[]``
    (a clean skip). Best-effort, total: this hook can never sink the autonomous cycle."""
    try:
        from .engage_fusion import fuse_sensors  # type: ignore[attr-defined]
    except Exception:
        return []          # WS-B not present yet → no extra sensor fusion (standalone)
    try:
        out = fuse_sensors(world, slug, ctx)
        return list(out) if out else []
    except Exception:
        return []


def _reason_step(world: "WorldModel | None", findings: list, ctx: Any) -> Any:
    """WS-F seam. Calls ``engage_reasoning.reason_step(world, findings, ctx) -> object`` for LLM/
    planner reasoning ADVICE (advisory only — it never promotes a finding or overrides an oracle).
    Absent module / bad signature / any error → ``None``. Best-effort, total."""
    try:
        from .engage_reasoning import reason_step  # type: ignore[attr-defined]
    except Exception:
        return None        # WS-F not present yet → no reasoning advice (standalone)
    try:
        return reason_step(world, findings, ctx)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# result types
# ---------------------------------------------------------------------------


@dataclass
class AutonomyStep:
    """One OODA cycle's outcome — the picked action, the gated tool call, the folded observation,
    and where the planner re-oriented afterwards."""

    cycle: int
    picked_leaf_id: int | None = None
    picked_label: str = ""
    picked_surface: str = ""
    picked_bug_class: str = ""
    tool: str = ""
    gated: bool = False           # the call went through the invoke_tool gate chain
    refused: bool = False         # a fail-closed gate declined it (tool never ran)
    gate: str = ""                # which gate refused (when refused)
    tool_ok: bool = False         # the tool ran and produced a result
    verdict: str = ""             # the tool's observation (e.g. reverify grounding verdict)
    folded_node: str = ""         # world-model node id the observation was folded onto ("" if none)
    reoriented_to: str = ""       # the next action the planner selected after the update


@dataclass
class AutonomyResult:
    """The full outcome of the opt-in autonomous cycle: the underlying authoritative engagement
    (UNCHANGED) plus the OODA telemetry over it."""

    engagement: "EngagementResult"
    slug: str
    cycles: list[AutonomyStep] = field(default_factory=list)
    fused_observations: int = 0        # count returned by the WS-B fuse_sensors hook
    reasoning_advice: Any = None       # object returned by the WS-F reason_step hook (or None)
    planner_constructed: bool = False  # a real Planner was constructed over the run world-model
    planner_source: str | None = None  # the foothold node the planner reasons from
    objectives: list[str] = field(default_factory=list)
    world_nodes_before: int = 0
    world_nodes_after: int = 0
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ORIENT — goal tree, foothold, objectives, planner
# ---------------------------------------------------------------------------


def _objective_kinds() -> list:
    """Crown-jewel node kinds the planner biases its route search toward."""
    from .worldmodel.models import NodeKind
    return [NodeKind.DATASTORE, NodeKind.CLOUD_RESOURCE]


def _finding_surface(f: object) -> str:
    """The surface a finding sits on, for goal-tree leaf + world-node resolution."""
    return str(getattr(f, "endpoint", "") or getattr(f, "insertion_point", "") or "")


def _build_goal_tree(findings: list) -> tuple[Any, dict[int, object]]:
    """Build a goal tree whose leaves are the confirmed findings — one leaf per finding, its prior
    seeded from the finding's confidence, tagged with the finding's bug_class + surface. Returns the
    tree and a ``leaf_id -> finding`` map so the ACT step can recover the finding to re-verify."""
    from .planner.goal_tree import CostEstimate, GoalTree

    tree = GoalTree()
    root = tree.add(label="autonomous OODA", kind="root", prior=1.0, value=1.0)
    leaf_to_finding: dict[int, object] = {}
    for f in findings:
        bug_class = str(getattr(f, "bug_class", "") or "")
        surface = _finding_surface(f)
        conf = float(getattr(f, "confidence", 0.5) or 0.5)
        conf = min(max(conf, 0.0), 1.0)
        lid = tree.add(
            parent_id=root, kind="leaf",
            label=f"reverify {bug_class} @ {surface}"[:120],
            prior=conf, value=1.0, bug_class=bug_class, surface=surface,
            estimate=CostEstimate(requests=1),
        )
        leaf_to_finding[lid] = f
    return tree, leaf_to_finding


def _foothold(world: "WorldModel | None") -> str | None:
    """The planner's source node: the attacker foothold if the chainer modelled one, else the
    lowest-id WEBAPP/ENDPOINT/HOST node (deterministic), else None (→ selection is plain greedy)."""
    if world is None:
        return None
    try:
        from .worldmodel.attacker import ATTACKER_ID
        from .worldmodel.models import NodeKind
        if world.has_node(ATTACKER_ID):
            return ATTACKER_ID
        for kind in (NodeKind.WEBAPP, NodeKind.ENDPOINT, NodeKind.HOST):
            ids = sorted(n.id for n in world.nodes_of_kind(kind))
            if ids:
                return ids[0]
    except Exception:
        return None
    return None


def _select(tree: Any, world: "WorldModel | None", objectives: list, source: str | None) -> Any:
    """Pick the next action: the planner's world-aware leaf selection (highest-value route to a
    crown jewel), degrading VERBATIM to greedy ``prior*value/cost`` when the world/objectives/
    foothold are absent or no crown jewel is reachable. Deterministic and read-only on the world."""
    try:
        return tree.best_open_leaf_pathaware(
            world=world, objective_kinds=objectives or None, source=source)
    except Exception:
        try:
            return tree.best_open_leaf()
        except Exception:
            return None


def _construct_planner(world: "WorldModel | None", slug: str, tree: Any, objectives: list,
                       source: str | None, request_budget: int, blackboard: Any) -> Any:
    """Construct the real ``Planner`` over the run world-model — the substrate the multi-cycle
    roadmap loop (``planner.run``) will drive. Needs a blackboard (its event substrate); when none
    is available it is skipped (None) and the cycle still runs on the shared tree selection, which is
    byte-for-byte what the planner itself would select. Best-effort — never raises."""
    if blackboard is None:
        return None
    try:
        from .agents.coordinator import Coordinator
        from .planner import Budget, Planner, Pruner, Watchdog

        try:
            blackboard.engagement_id(slug)
        except Exception:
            pass
        coord = Coordinator(blackboard=blackboard, engagement_slug=slug, agents=[])
        budget = Budget(request_max=max(1, int(request_budget)))
        return Planner(
            blackboard=blackboard, coordinator=coord, engagement_slug=slug,
            tree=tree, budget=budget,
            pruner=Pruner(), watchdog=Watchdog(engagement_slug=slug, tree=tree, budget=budget),
            scope_check=True,
            world=world, objectives=objectives or None, world_source=source,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ACT — drive a gated tool via invoke_tool; UPDATE — fold the observation
# ---------------------------------------------------------------------------


def _default_registry() -> Any:
    """The built-in gated-tool registry (carries the safe ``reverify_finding`` tool)."""
    from .agents.tools.builtin import default_registry
    return default_registry()


def _drive_reverify(finding: object, registry: Any, ctx: Any, sink: Any) -> Any:
    """Drive the SAFE built-in ``reverify_finding`` tool over ``finding`` through the FULL gated
    ``invoke_tool`` chain. The finding's own retained oracle certificate is re-executed by the
    veracity firewall (prove-by-re-execution); the ToolResult is a provenance-labelled observation
    (GROUNDED / not), never a new fact. A tripped kill-switch refuses it and it never runs."""
    from .agents.tools.invoker import invoke_tool

    finding_arg = {
        "bug_class": str(getattr(finding, "bug_class", "") or ""),
        "oracle_context": getattr(finding, "oracle_context", None),
    }
    return invoke_tool(registry, "reverify_finding", {"finding": finding_arg}, ctx, sink=sink)


def _fold_observation(world: "WorldModel | None", surface: str, verdict: str) -> str:
    """Fold the tool's observation back into the world-model: annotate the finding's node (resolved
    from its surface) with the live re-grounding verdict, in place (attrs is a mutable bag) so belief
    is not perturbed. Returns the node id folded onto, or "" when nothing matched. Best-effort."""
    if world is None or not surface or not verdict:
        return ""
    try:
        from .planner.goal_tree import surface_to_node_id
        nid = surface_to_node_id(world, surface)
        node = world.get_node(nid) if nid else None
        if node is not None:
            node.attrs["autonomy_reverify"] = verdict
            return nid or ""
    except Exception:
        return ""
    return ""


# ---------------------------------------------------------------------------
# the cycle
# ---------------------------------------------------------------------------


def run_autonomous_cycle(
    result: "EngagementResult",
    *,
    slug: str,
    max_cycles: int = 1,
    request_budget: int = 8,
    prompt_callback: Any = None,
    registry: Any = None,
    blackboard: Any = None,
    ctx: Any = None,
) -> AutonomyResult:
    """Run ONE bounded OODA cycle (``max_cycles`` default 1) over an authoritative
    :class:`engage.EngagementResult`. The scan report is NEVER mutated — the cycle only reads the
    confirmed findings + world-model, drives a gated tool, and folds its observation back.

    Localhost/authorized-only: the enclosing ``engage.run_engagement`` preflight already refused an
    out-of-scope / kill-switched engagement before this runs, and every tool call is re-gated by
    ``invoke_tool`` regardless. Deterministic and best-effort throughout."""
    from .agents.tools import ToolContext

    world = getattr(result, "world", None)
    findings = list(getattr(getattr(result, "report", None), "active_findings", []) or [])
    registry = registry if registry is not None else _default_registry()
    if ctx is None:
        ctx = ToolContext(slug=slug, world=world, prompt_callback=prompt_callback)

    out = AutonomyResult(engagement=result, slug=slug)
    out.world_nodes_before = world.node_count if world is not None else 0
    objectives = _objective_kinds()
    out.objectives = [getattr(k, "value", str(k)) for k in objectives]

    # OBSERVE — WS-B sensor fusion first, so the planner reasons over the enriched world.
    fused = _fuse_sensors(world, slug, ctx)
    out.fused_observations = len(fused)

    # ORIENT — goal tree over the confirmed findings + the planner over the run world-model.
    tree, leaf_to_finding = _build_goal_tree(findings)
    source = _foothold(world)
    out.planner_source = source
    planner = _construct_planner(world, slug, tree, objectives, source, request_budget, blackboard)
    out.planner_constructed = planner is not None

    sink = _spine_sink(blackboard, slug)

    # PRODUCER UNIFICATION (WS-B) — the fused SENSOR leads also reach the unified report, as
    # LEADS. A raw sensor observation carries no oracle_context, so the report grader renders it a
    # lead, never a fact (prove-don't-guess preserved). Spine-gated + opt-in autonomous path →
    # the default gate never reaches this, so it stays byte-identical. Best-effort.
    if sink is not None and fused:
        try:
            from .intel.project import observation_to_finding_payload
            for obs in fused:
                sink.finding_event(observation_to_finding_payload(obs))
        except Exception:
            pass

    if not findings:
        out.notes.append("no confirmed findings — nothing to drive this cycle")
        out.world_nodes_after = world.node_count if world is not None else 0
        # still exercise the WS-F reasoning hook so the seam is live even on an empty run
        out.reasoning_advice = _reason_step(world, findings, ctx)
        return out

    cycles = max(1, int(max_cycles))
    for c in range(1, cycles + 1):
        leaf = _select(tree, world, objectives, source)
        if leaf is None:
            out.notes.append(f"cycle {c}: no open action remaining")
            break
        step = AutonomyStep(cycle=c, picked_leaf_id=leaf.id, picked_label=leaf.label,
                            picked_surface=leaf.surface, picked_bug_class=leaf.bug_class)
        finding = leaf_to_finding.get(leaf.id)

        # ACT — drive the picked action as a GATED tool call.
        tree.mark_status(leaf.id, "claimed")
        res = _drive_reverify(finding, registry, ctx, sink) if finding is not None else None
        step.tool = "reverify_finding"
        step.gated = True
        if res is not None:
            step.refused = bool(getattr(res, "refused", False))
            step.gate = str(getattr(res, "gate", "") or "")
            step.tool_ok = bool(getattr(res, "ok", False))
            step.verdict = str((getattr(res, "output", {}) or {}).get("verdict", "")) or \
                str(getattr(res, "summary", "") or "")

        # UPDATE — fold the observation into the world-model + update the goal tree.
        if step.refused:
            # a fail-closed refusal is not a refutation of the finding — leave the leaf open, note it
            tree.mark_status(leaf.id, "open")
            out.notes.append(f"cycle {c}: tool refused at gate {step.gate!r} (fail-closed)")
        else:
            grounded = bool((getattr(res, "output", {}) or {}).get("is_fact", False)) if res else False
            step.folded_node = _fold_observation(
                world, leaf.surface, step.verdict or ("fact" if grounded else "not-grounded"))
            tree.mark_status(leaf.id, "succeeded" if grounded else "failed",
                             reason="" if grounded else "reverify did not re-ground")

        # RE-ORIENT — the WS-F reasoning hook, then re-select over the updated tree/world.
        out.reasoning_advice = _reason_step(world, findings, ctx)
        nxt = _select(tree, world, objectives, source)
        step.reoriented_to = nxt.label if nxt is not None else "(no more actions)"
        out.cycles.append(step)

    out.world_nodes_after = world.node_count if world is not None else 0
    return out


def _spine_sink(blackboard: Any, slug: str) -> Any:
    """A best-effort SpineSink over a caller-supplied blackboard (so gated tool_call/tool_result/
    refusal events land on the immutable stream), or None. Never raises."""
    if blackboard is None:
        return None
    try:
        from .agents.spine_sink import SpineSink
        return SpineSink(blackboard, slug)
    except Exception:
        return None


def render_summary(out: AutonomyResult) -> list[str]:
    """Human-readable one-liners for the CLI (kept out of ``run_autonomous_cycle`` so the cycle has
    no print side effects and stays a pure library call)."""
    lines: list[str] = []
    src = out.planner_source or "(none)"
    lines.append(
        f"  autonomous OODA   : planner over world-model "
        f"(constructed={out.planner_constructed}, source={src}, "
        f"objectives={','.join(out.objectives) or 'none'})")
    if out.fused_observations:
        lines.append(f"    fused sensors   : {out.fused_observations} observation(s) (WS-B)")
    for s in out.cycles:
        if s.refused:
            lines.append(f"    [cycle {s.cycle}] picked {s.picked_label} → {s.tool} "
                         f"REFUSED @ gate {s.gate} (fail-closed)")
        else:
            fold = f", folded→{s.folded_node}" if s.folded_node else ""
            lines.append(f"    [cycle {s.cycle}] picked {s.picked_label} → {s.tool} "
                         f"[{s.verdict}]{fold}; re-oriented → {s.reoriented_to}")
    for n in out.notes:
        lines.append(f"    note            : {n}")
    if out.reasoning_advice is not None:
        lines.append("    reasoning advice: present (WS-F)")
    return lines
