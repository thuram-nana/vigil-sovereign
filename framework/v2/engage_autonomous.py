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
    chained attack facts) and the oracle-confirmed findings, RE-OBSERVED at the top of EVERY cycle:
    the WS-B ``fuse_sensors`` hook runs each cycle and folds its (SAFE, offline) sensor observations
    into the SAME world-model the planner reasons over, so fresh observations enrich the next pick.
    (The first-slice allowlist stays the safe offline producers; extending it to the active sensors
    is a documented ``engage_fusion`` roadmap item, not this slice.)
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
  * RE-ORIENT— run the WS-F reasoning step and FEED ITS ADVICE BACK INTO SELECTION: the advice's
    focus/hypotheses re-weight the matching open leaves' priors (bounded, always recomputed from a
    fixed per-run baseline — no compounding), so the reasoning genuinely CHANGES which action the
    planner selects next. Then re-run the planner's selection over the now-updated tree/world; the
    pick changes, proving the loop closed. Advisory only — re-weighting orders effort, it NEVER
    promotes a finding, removes a leaf, or feeds an oracle/SCE/calibration input.

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
    the gated invoke, the reasoning-advice / meta-caution re-weight (recomputed from a fixed
    baseline), and the fold are pure functions of ``(result, world, tree, advice, ledger)`` — no
    wallclock, no rng. Running the cycle twice over the same inputs yields the same step sequence.
  * CAUTION-ONLY LEARNING. The learner-health meta-monitor (``calibration.meta_monitor``) may only
    ORDER effort (deprioritise borderline leaves when the calibrator/bands are untrustworthy); it
    never gates a surface, never promotes a finding, and never feeds the deterministic oracle/SCE/
    calibration inputs (coverage doctrine). Every open leaf stays selectable.
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


def _emit_fused_leads(sink: Any, observations: list, emitted_ids: set) -> None:
    """PRODUCER UNIFICATION (I-C) — the WS-B fused SENSOR observations also reach the unified report,
    as LEADS. A raw sensor observation carries no ``oracle_context``, so the report grader renders it
    a lead, never a fact (prove-don't-guess preserved). Fusion is idempotent across cycles (stable
    ``obs_id``), so ``emitted_ids`` dedups: each observation becomes at most one finding event.
    Spine-gated (no sink → no-op) + only reached on the opt-in ``--autonomous`` path, so the default
    gate never touches this. Best-effort, total: it can never sink the cycle."""
    if sink is None or not observations:
        return
    try:
        from .intel.project import observation_to_finding_payload
        for obs in observations:
            oid = getattr(obs, "obs_id", None)
            if oid is not None and oid in emitted_ids:
                continue
            sink.finding_event(observation_to_finding_payload(obs))
            if oid is not None:
                emitted_ids.add(oid)
    except Exception:
        pass


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
    advice_reweighted: int = 0    # open leaves the RE-ORIENT reasoning advice re-weighted this cycle
    fused_observations: int = 0   # WS-B sensor observations folded into the world THIS cycle (OBSERVE)
    coordinator_events: int = 0   # events the wired advisory agents posted when the Coordinator ticked
    learned: bool = False         # this cycle's confirm/refute outcome was written to the OutcomeLedger
    is_probe: bool = False        # W-C: this cycle DISCOVERED (drove probe_surface), not reverified
    discovered_findings: int = 0  # W-C: NEW oracle-confirmed findings this probe minted (0 = oracle silent)


@dataclass
class AutonomyResult:
    """The full outcome of the opt-in autonomous cycle: the underlying authoritative engagement
    (UNCHANGED) plus the OODA telemetry over it."""

    engagement: "EngagementResult"
    slug: str
    cycles: list[AutonomyStep] = field(default_factory=list)
    fused_observations: int = 0        # count returned by the WS-B fuse_sensors hook
    reasoning_advice: Any = None       # object returned by the WS-F reason_step hook (or None)
    advice_reweighted: int = 0         # total open leaves the WS-F advice re-weighted (all cycles)
    planner_constructed: bool = False  # a real Planner was constructed over the run world-model
    planner_driven: bool = False       # the Planner's Coordinator was TICKED in-loop (agents ran), not inert
    agents_wired: list[str] = field(default_factory=list)  # advisory agents on the Coordinator
    coordinator_events: int = 0        # total events the wired agents posted across all ticks
    critic_verdicts: int = 0           # critic_verdict events the multi-critic panel posted (advisory)
    reflections: int = 0               # reflection events the in-loop reflection posted (re-rank/defer)
    meta_recommend: str = ""           # learner-health recommend (ok / gather_evidence / trust_confidence_less)
    smt_deprioritised: int = 0         # open leaves whose parameter region is PROVABLY infeasible (advisory)
    planner_source: str | None = None  # the foothold node the planner reasons from
    objectives: list[str] = field(default_factory=list)
    lookahead_depth: int = 1           # 1 = one-step greedy; >= 2 = bounded multi-step lookahead (W2.2b)
    world_nodes_before: int = 0
    world_nodes_after: int = 0
    outcomes_credited: int = 0         # LEARN — confirm/refute outcomes written to the persistent OutcomeLedger
    learner_persisted: bool = False    # LEARN — the enriched ledger was saved to targets/<slug>/outcomes.json
    # W2.2d — the SECOND gated autonomous tool: a `declared_service` reachability re-check driven
    # through the FULL invoke_tool gate chain, folding a LEAD observation into the world-model.
    reachability_driven: bool = False  # the reachability re-check was attempted (opt-in)
    reachability_tool: str = ""        # the gated tool driven ("declared_service")
    reachability_host: str = ""        # the host the re-check acted on (scope-gated)
    reachability_refused: bool = False # a fail-closed gate declined it (kill-switch / out-of-scope)
    reachability_gate: str = ""        # which gate refused (when refused)
    reachability_applied: int = 0      # world-model observations the re-check folded as LEADS (never facts)
    # W-C — the DISCOVERING slice (opt-in): a gated `probe_surface` tool drives ONE existing scanner
    # check against LOW-prior probe-leaves seeded from world-model ENDPOINT nodes, and mints a NEW
    # oracle-confirmed finding (NOT in the seed set) ONLY when the wrapped check's oracle FIRES. This
    # is the first honest step from a re-verifying loop toward a DISCOVERING one. Default off →
    # byte-identical: no probe-leaves seeded, probe_surface never constructed, nothing minted.
    discover_enabled: bool = False     # discovery was requested AND a send was injected (probe I/O available)
    endpoints_promoted: int = 0        # Slice-0: in-scope recon/sensor assets promoted to url-bearing ENDPOINTs
    endpoints_expanded: int = 0        # Slice-2: param-bearing surfaces discovered by crawling promoted roots
    probe_posture: str = "auto-test"   # Slice-4: "auto-test" (probe now) | "discover-queue" (queue for human)
    candidates_queued: int = 0         # Slice-4: probe-leaves parked for operator approval (discover-queue, no traffic)
    queued_candidates: list = field(default_factory=list)  # the surfaces queued (discover-queue posture)
    probe_leaves_seeded: int = 0       # LOW-prior probe-leaves seeded from ENDPOINT nodes (opt-in)
    probes_driven: int = 0             # probe_surface tool calls that RAN through the gate chain (not refused)
    probes_refused: int = 0            # probe_surface calls a fail-closed gate declined (kill-switch / scope)
    discovered_findings: list = field(default_factory=list)  # serialised NEW AuditFindings (oracle_context kept)
    discovered_count: int = 0          # NEW oracle-confirmed findings discovery minted this run
    findings_folded: int = 0           # W-F3 — discovered findings SPLICED into the authoritative report
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


def _endpoint_probe_targets(world: "WorldModel | None", *, exclude: "set[str]") -> list[tuple[str, str]]:
    """The unexplored ENDPOINT leads to seed probe-leaves from: ``(node_id, url)`` for every world-
    model ENDPOINT node that carries a usable http(s) ``url`` NOT already covered by a confirmed
    finding's surface (``exclude``). Deterministic (id-sorted, first-match) and read-only; best-effort
    (any trouble → ``[]``). The scope gate — not this enumerator — is what authorizes probing a URL:
    an out-of-scope endpoint that slips in here is REFUSED fail-closed when its probe is driven."""
    if world is None:
        return []
    out: list[tuple[str, str]] = []
    try:
        from .worldmodel.models import NodeKind
        for n in sorted(world.nodes_of_kind(NodeKind.ENDPOINT), key=lambda n: n.id):
            url = n.attrs.get("url") if isinstance(getattr(n, "attrs", None), dict) else None
            if not isinstance(url, str):
                continue
            u = url.strip()
            if not (u.startswith("http://") or u.startswith("https://")):
                continue
            if u in exclude:
                continue
            out.append((n.id, u))
    except Exception:
        return []
    return out


def _build_goal_tree(
    findings: list,
    *,
    world: "WorldModel | None" = None,
    seed_probe_leaves: bool = False,
    probe_bug_class: str = "xss",
    probe_prior: float = 0.03,
) -> tuple[Any, dict[int, object]]:
    """Build a goal tree whose leaves are the confirmed findings — one leaf per finding, its prior
    seeded from the finding's confidence, tagged with the finding's bug_class + surface. Returns the
    tree and a ``leaf_id -> finding`` map so the ACT step can recover the finding to re-verify.

    W-C (opt-in, default OFF → byte-identical): when ``seed_probe_leaves`` and a ``world`` is given,
    the tree ALSO gets LOW-prior PROBE-leaves — one per world-model ENDPOINT node carrying an http(s)
    url NOT already covered by a confirmed finding (:func:`_endpoint_probe_targets`). A probe-leaf is
    an UNEXPLORED frontier the existing depth-2 lookahead can move toward; the ACT step recognises it
    as an open leaf absent from ``leaf_to_finding`` and drives the gated ``probe_surface`` tool on its
    ``surface`` (the endpoint url). Priors are kept LOW (``probe_prior``, default 0.03) so confirmed
    findings still DOMINATE ordering — discovery is what the loop does once the known leads are spent.
    Probe-leaves are deliberately NOT added to ``leaf_to_finding`` (they carry no finding yet), which
    is exactly how the cycle tells a discover leaf from a reverify leaf. Default args leave the return
    2-tuple and every seeded leaf byte-identical, so ``plan.py`` and the existing tests are unchanged."""
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
    if seed_probe_leaves and world is not None:
        bc = str(probe_bug_class or "xss")
        prior = min(max(float(probe_prior), 0.0), 1.0)
        covered: set[str] = set()
        for f in findings:
            covered.add(str(getattr(f, "endpoint", "") or ""))
            covered.add(_finding_surface(f))
        covered.discard("")
        # Slice-1: route the raw ENDPOINT probe-targets through the DiscoveryFrontier — it collapses
        # value-variants of one location to a single canonical key, orders by expected information gain,
        # and CAPS the count so a large recon/crawl graph cannot flood the goal tree. For a single
        # producer / a single endpoint this returns the same one leaf (the existing behaviour); its value
        # compounds once in-loop crawling (Slice 2) feeds many near-duplicate surfaces in.
        from .intel.frontier import frontier_from_targets
        targets = _endpoint_probe_targets(world, exclude=covered)
        fr = frontier_from_targets(targets, world=world, bug_class=bc, prior=prior)
        for item in fr.items():
            tree.add(
                parent_id=root, kind="leaf",
                label=f"probe {item.bug_class} @ {item.url}"[:120],
                prior=item.prior, value=1.0, bug_class=item.bug_class, surface=item.url,
                estimate=CostEstimate(requests=1),
            )
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


def _select(tree: Any, world: "WorldModel | None", objectives: list, source: str | None,
            *, lookahead_depth: int = 1, budget: int | None = None) -> Any:
    """Pick the next action.

    ``lookahead_depth <= 1`` (the default): the ONE-STEP world-aware greedy pick — the planner's
    ``best_open_leaf_pathaware`` (highest-value route to a crown jewel), degrading VERBATIM to
    greedy ``prior*value/cost`` when the world/objectives/foothold are absent or no crown jewel is
    reachable. Byte-identical to the pre-lookahead behaviour (so the existing autonomous tests and
    the greedy default are unchanged).

    ``lookahead_depth >= 2`` (opt-in, W2.2b): MULTI-STEP lookahead — ``best_open_leaf_lookahead``
    chooses the budget-feasible PLAN (a set of ``<= depth`` open leaves whose request cost fits
    ``budget``) whose value — the sum of the leaves' path-boosted scores PLUS a bonus for every
    crown-jewel route it COMPLETES — is greatest, then returns that plan's highest-value first step
    to execute now (receding horizon). Because the route bonus is earned only by a plan that
    includes ALL of a route's leaves, a tight budget makes lookahead DROP the single highest-scoring
    (off-path) leaf to finish an affordable route — a genuinely non-myopic pick. It degrades
    VERBATIM to the greedy pick above when there is no world / objective / reachable crown jewel /
    affordable plan, so ``lookahead_depth >= 2`` with none of those set is still the greedy pick.

    DETERMINISTIC: both selectors are pure functions of the (fixed-baseline) tree + world (no
    wallclock, no rng); ties break on ascending leaf id. Read-only on the world."""
    try:
        if lookahead_depth >= 2:
            return tree.best_open_leaf_lookahead(
                world=world, objective_kinds=objectives or None, source=source,
                depth=lookahead_depth, budget_requests=budget)
        return tree.best_open_leaf_pathaware(
            world=world, objective_kinds=objectives or None, source=source)
    except Exception:
        try:
            return tree.best_open_leaf()
        except Exception:
            return None


# ---------------------------------------------------------------------------
# RE-ORIENT — feed the WS-F reasoning advice back into leaf selection.
#
# The advice re-WEIGHTS matching open leaves' priors so the reasoning genuinely
# changes the next pick. It is ADVISORY ONLY: it orders effort (re-ranks), never
# removes a leaf (coverage doctrine), never promotes a finding, and never feeds
# an oracle / SCE / calibration input. Every re-weight is recomputed from a fixed
# per-run BASELINE, so it is idempotent and cannot compound across cycles —
# keeping the cycle deterministic (a pure function of advice + baseline).
# ---------------------------------------------------------------------------

_ADVICE_CAP = 0.99        # priors are lifted toward, but never to, certainty (search weight only)
_ADVICE_STRENGTH = 0.9    # rank-0 (focus) lift fraction toward the cap; decays as 1/(rank+1)
_PRIOR_FLOOR = 1e-6       # a re-weighted prior never reaches 0 → the leaf stays selectable (never gated)


def _duck(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a mapping OR an attribute of an object, defensively (advice may be a
    ``ReasoningAdvice``, a plain dict, or an unrelated object)."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _norm(s: Any) -> str:
    return str(s or "").strip().casefold()


def _surface_is_concrete(sf: str) -> bool:
    """A surface is concrete enough to match a specific leaf only when it is non-empty and not the
    kernel's DryRun placeholder. DryRun advice carries an ``(unspecified surface)`` — so under the
    deterministic DryRun backend the advice re-weight is a safe no-op (advice quality is bounded
    there, exactly as engage_reasoning documents); a live backend / concrete advice reorders."""
    n = _norm(sf)
    return bool(n) and "unspecified" not in n


def _advice_targets(advice: Any) -> list[tuple[str, str]]:
    """The advice's ordered (bug_class, surface) targets — its top focus first, then its ranked
    hypotheses — as normalised pairs. Duck-typed over ``ReasoningAdvice`` / dict / anything; a
    non-advice object (e.g. a plain telemetry dict with no focus/hypotheses) yields ``[]``, so the
    re-weight cleanly no-ops. ``pivots`` are lateral-move suggestions (not leaf-addressable), so
    they are carried as advice telemetry only, not used to re-weight in this slice."""
    raw: list[Any] = []
    focus = _duck(advice, "focus")
    if isinstance(focus, dict):
        raw.append(focus)
    hyps = _duck(advice, "hypotheses") or ()
    try:
        for h in hyps:
            if isinstance(h, dict):
                raw.append(h)
    except TypeError:
        pass
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for t in raw:
        bc = _norm(t.get("bug_class"))
        sf = str(t.get("surface", "") or "")
        if not bc:
            continue
        key = (bc, _norm(sf))
        if key in seen:
            continue
        seen.add(key)
        out.append((bc, sf))
    return out


def _leaf_baselines(tree: Any) -> dict[int, float]:
    """Snapshot each open leaf's ORIGINAL prior once, so every re-weight is recomputed from this
    fixed baseline (idempotent, non-compounding, deterministic)."""
    out: dict[int, float] = {}
    for leaf in tree.open_leaves():
        out[leaf.id] = float(leaf.prior_p_success)
    return out


def _advice_rank(node: Any, targets: list[tuple[str, str]]) -> int | None:
    """The rank of the first advice target that matches ``node``: a leaf matches a target when its
    bug_class matches AND the target names a CONCRETE surface equal to the leaf's. Returns None when
    no target matches (the leaf keeps its baseline prior)."""
    lbc = _norm(node.bug_class)
    lsf = _norm(node.surface)
    for rank, (bc, sf) in enumerate(targets):
        if bc == lbc and _surface_is_concrete(sf) and _norm(sf) == lsf:
            return rank
    return None


def _reprioritise(tree: Any, baselines: dict[int, float], *, advice: Any = None,
                  meta_caution: float = 0.0, smt_infeasible: "set[int] | None" = None) -> int:
    """Recompute each open leaf's prior FROM its baseline and apply the active advisory re-weighters,
    then return the count of leaves actually moved. In order:

      * SMT infeasibility (I-D.5) — a leaf whose bounded parameter region is PROVABLY infeasible is
        deprioritised to the floor (probing it can satisfy no constraint). Advisory: it degrades to
        a no-op when the region is unknown/absent, and the leaf stays selectable (never gated).
      * meta_monitor CAUTION (I-D.4) — when the learners are unhealthy, deprioritise the most
        BORDERLINE (nearest-coin-flip) leaves so effort orders toward more-decisive leads and
        abstains more on uncertain ones. Caution-only: it can only lower a prior toward the floor,
        never below it (the leaf stays selectable — no surface is gated).
      * reasoning ADVICE (I-D.1) — lift an advice-matched leaf toward the cap (rank-0 focus most,
        decaying by 1/(rank+1)).

    Bounded and idempotent (always recomputed from the fixed baseline → no compounding). Never
    touches a resolved/pruned leaf and never removes one — it only re-orders the OPEN frontier."""
    targets = _advice_targets(advice)
    caution = min(1.0, max(0.0, float(meta_caution)))
    infeasible = smt_infeasible or set()
    moved = 0
    for lid, base in baselines.items():
        node = tree.nodes.get(lid)
        if node is None or node.status not in ("open", "claimed"):
            continue
        # smt: a provably-infeasible parameter region starts at the floor (deprioritised).
        p = _PRIOR_FLOOR if lid in infeasible else base
        # meta caution: borderline = 1 at prior 0.5 (max uncertainty), 0 at prior in {0, 1}.
        if caution > 0.0:
            borderline = 1.0 - abs(2.0 * base - 1.0)
            p = p * (1.0 - caution * borderline)
        # reasoning advice: lift the matched leaf from its (possibly cautioned) prior toward the cap.
        rank = _advice_rank(node, targets) if targets else None
        if rank is not None:
            lift = _ADVICE_STRENGTH / (rank + 1)
            p = p + (_ADVICE_CAP - p) * lift
        p = min(_ADVICE_CAP, max(_PRIOR_FLOOR, p))
        if abs(p - float(node.prior_p_success)) > 1e-12:
            moved += 1
        node.prior_p_success = p
    return moved


# ---------------------------------------------------------------------------
# I-D.5 — SMT feasibility as a LEAD-PRUNING advisor (deprioritise dead regions).
#
# analysis.smt.is_feasible answers "does ANY integer assignment satisfy this bounded linear
# constraint system?" A leaf whose parameter region is PROVABLY infeasible cannot fire, so we
# deprioritise it before selection. Advisory only: an infeasible verdict never refutes/promotes a
# finding (only an oracle does), the leaf stays selectable (never gated), and the analyzer degrades
# to a clean no-op when z3 is absent and the domain is too large to enumerate (UNKNOWN, not a guess).
# ``smt_regions`` maps a leaf's bug_class OR surface -> {"variables": {name: (lo, hi)},
# "constraints": [LinearConstraint | {"coeffs", "op", "rhs"}]}.
# ---------------------------------------------------------------------------


def _coerce_bounds(variables: Any) -> "dict[str, tuple[int, int]] | None":
    if not isinstance(variables, dict) or not variables:
        return None
    out: dict[str, tuple[int, int]] = {}
    for name, b in variables.items():
        try:
            lo, hi = b
            out[str(name)] = (int(lo), int(hi))
        except Exception:
            return None
    return out


def _coerce_constraints(raw: Any, linear: Any) -> "list | None":
    cons: list = []
    for c in (raw or []):
        try:
            if isinstance(c, dict):
                cons.append(linear(c.get("coeffs", {}) or {}, str(c.get("op")), int(c.get("rhs", 0))))
            else:
                cons.append(c)   # already a LinearConstraint
        except Exception:
            return None
    return cons


def _region_infeasible(region: Any) -> bool:
    """True only when ``analysis.smt`` PROVES the region has no satisfying assignment. Anything else
    — feasible, UNKNOWN (domain too large + no z3), malformed, or an import error — returns False
    (no deprioritisation). Advisory + fail-open (never deprioritise on doubt)."""
    if not isinstance(region, dict):
        return False
    try:
        from .analysis.smt import is_feasible, linear
    except Exception:
        return False
    variables = _coerce_bounds(region.get("variables"))
    if variables is None:
        return False
    constraints = _coerce_constraints(region.get("constraints"), linear)
    if constraints is None:
        return False
    try:
        return bool(is_feasible(variables, constraints).is_infeasible)
    except Exception:
        return False


def _smt_region_for(leaf: Any, smt_regions: dict) -> Any:
    """The region declared for this leaf, keyed by its bug_class first, then its surface."""
    for key in (str(getattr(leaf, "bug_class", "") or ""), str(getattr(leaf, "surface", "") or "")):
        if key and key in smt_regions:
            return smt_regions[key]
    return None


def _smt_infeasible_leaves(tree: Any, smt_regions: Any) -> "set[int]":
    """The ids of OPEN leaves whose declared parameter region is provably infeasible. Empty when no
    regions are supplied or none is provably dead. Pure and read-only; best-effort."""
    if not isinstance(smt_regions, dict) or not smt_regions:
        return set()
    out: set[int] = set()
    for leaf in tree.open_leaves():
        region = _smt_region_for(leaf, smt_regions)
        if region is not None and _region_infeasible(region):
            out.add(leaf.id)
    return out


# ---------------------------------------------------------------------------
# I-D.4 — consult the learner-health meta-monitor to modulate effort (CAUTION-ONLY).
#
# assess_learner_health(ledger) diagnoses whether the learners (calibrator / conformal bands) are
# trustworthy. Its recommend can only make the loop MORE cautious — never more confident, never
# gate a surface, never promote. We map it to a caution STRENGTH fed into _reprioritise, which
# deprioritises borderline leaves (orders effort), leaving every surface selectable.
# ---------------------------------------------------------------------------

_META_CAUTION = {"ok": 0.0, "gather_evidence": 0.5, "trust_confidence_less": 0.7}


def _load_ledger(slug: str) -> Any:
    """Best-effort load of the operator's OutcomeLedger at ``targets/<slug>/outcomes.json`` — so a
    real engagement's accumulated labels modulate caution with zero wiring. Missing/malformed → None
    (no modulation). Never raises."""
    if not slug:
        return None
    try:
        from .calibration.ledger import OutcomeLedger
        from .common.paths import target_dir
        path = target_dir(slug) / "outcomes.json"
        if not path.is_file():
            return None
        return OutcomeLedger.load(path)
    except Exception:
        return None


def _meta_caution(slug: str, ledger: Any) -> tuple[str, float]:
    """Consult the meta-monitor over an OutcomeLedger and return ``(recommend, caution_strength)``.
    CAUTION-ONLY: the strength can only deprioritise borderline leaves (order effort), never gate a
    surface or promote a finding. No ledger / any error → ``("", 0.0)`` (no modulation). Pure."""
    if ledger is None:
        return ("", 0.0)
    try:
        from .calibration.meta_monitor import assess_learner_health
        sig = assess_learner_health(ledger)
        rec = str(getattr(sig, "recommend", "") or "")
        return (rec, _META_CAUTION.get(rec, 0.0))
    except Exception:
        return ("", 0.0)


# ---------------------------------------------------------------------------
# LEARN — feed the loop's confirm/refute outcomes into the persistent learner.
#
# This CLOSES the learning loop: historically the flagship/autonomous loop confirmed or refuted
# findings but fed NO persistent learner, so `_meta_caution` (above) always read a ledger that no run
# ever wrote. Now the autonomous OODA loop is the first real writer of the OutcomeLedger it already
# reads — so the learner improves from real runs, across runs.
#
# Honesty (prove-don't-guess): the reward bus's label is NON-CIRCULAR — `credit_outcome` resolves
# EXPLOITABLE only on >= 2 distinct corroborating oracle kinds, else DISPUTED (excluded from every
# calibrator fit). A single-oracle autonomous reverify therefore trains the learner as DISPUTED, never
# as a fact. Determinism: the id/feature-hash are pure functions of the finding (no wallclock/rng).
# Gate: `run_autonomous_cycle` runs ONLY under `--autonomous`, never on the byte-identical benchmark
# path, so every write here is off the gate. Best-effort/total throughout: a learner write can never
# sink the loop.
# ---------------------------------------------------------------------------

_LEARN_MODEL_VERSION = "autonomous-reverify-v1"   # attribution tag on the ledger Prediction


def _finding_ledger_id(finding: Any) -> str:
    """Stable ledger id for an AuditFinding — the SAME slug convention `engage._spine_finding_payload`
    uses (``bug_class:insertion_point``), so ledger keys line up with the spine's finding events. It is
    stable across runs, so the ledger's append-only guard dedups a re-credited finding (no double
    count) and `credit_outcome` swallows the resulting no-op cleanly."""
    bc = str(getattr(finding, "bug_class", "") or "")
    ip = str(getattr(finding, "insertion_point", "") or "")
    return (f"{bc}:{ip}"[:120]) or bc or "finding"


def _feature_hash(finding: Any) -> str:
    """A deterministic, attributable hash of the finding's identifying features (no wallclock/rng), so
    the Prediction is reproducible across runs."""
    import hashlib
    parts = [str(getattr(finding, a, "") or "")
             for a in ("check_id", "bug_class", "insertion_point", "param", "endpoint")]
    return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def _credit_finding_outcome(ledger: Any, finding: Any, leaf: Any, grounded: bool,
                            sink: Any, seq: int) -> bool:
    """Fan ONE autonomous confirm/refute outcome into the persistent OutcomeLedger (+ a spine reward
    event). Returns True iff the ledger recorded a NEW entry (so the caller knows to persist + count).
    A re-credited finding (same stable id) is refused by the ledger's append-only guard and swallowed
    by `credit_outcome` → returns False, never double-counts. Best-effort/total: never raises."""
    try:
        from .calibration.models import Prediction
        from .calibration.reward_bus import credit_outcome
    except Exception:
        return False
    try:
        conf = float(getattr(finding, "confidence", 0.0) or 0.0)
        conf = min(1.0, max(0.0, conf))
        pred = Prediction(
            finding_id=_finding_ledger_id(finding),
            raw_score=conf,
            feature_hash=_feature_hash(finding),
            model_version=_LEARN_MODEL_VERSION,
            oracle_confirmed=bool(grounded))
        sig = credit_outcome(
            oracle_fired=bool(grounded),
            distinct_confirming_kinds=_distinct_confirming_kinds(finding),
            seq=seq,
            ledger=ledger, prediction=pred,
            spine_sink=sink,
            arm=str(getattr(leaf, "bug_class", "") or getattr(finding, "bug_class", "") or ""),
            bug_class=str(getattr(finding, "bug_class", "") or ""))
        return "ledger" in sig.updated
    except Exception:
        return False


def _distinct_confirming_kinds(finding: Any) -> int:
    """How many DISTINCT oracle kinds independently confirmed this finding — the reward-bus
    corroboration signal (the non-circular bar for an autonomous EXPLOITABLE label is >= 2). Mirrors
    `engage._distinct_confirming_kinds`: a retained corroboration set when present, else 1 for a
    single-oracle confirmation, else 0. A single-oracle reverify is honestly ONE kind → DISPUTED."""
    for attr in ("corroborating_kinds", "confirmed_by_kinds", "confirmations"):
        kinds = getattr(finding, attr, None)
        if kinds:
            try:
                return max(1, len({str(k) for k in kinds}))
            except Exception:
                return 1
    return 1 if getattr(finding, "confirmed_by", None) else 0


def _persist_ledger(ledger: Any, slug: str) -> bool:
    """Best-effort persist of the OutcomeLedger to ``targets/<slug>/outcomes.json`` (owner-only via
    `OutcomeLedger.save`/`secure_write`). The NEXT autonomous run's `_load_ledger` reads it back → the
    learning loop closes ACROSS runs. Never raises."""
    if not slug or ledger is None:
        return False
    try:
        from .common.paths import target_dir
        ledger.save(target_dir(slug) / "outcomes.json")
        return True
    except Exception:
        return False


def _advisory_agents(blackboard: Any, slug: str) -> list:
    """The deterministic, ADVISORY nervous-system agents wired onto the Coordinator so they RUN
    inside the loop (not as post-hoc telemetry): the multi-critic panel (re-grounding / provenance
    / calibration lenses) and the in-loop reflection (dead-thread / stall re-orient). Both are
    deterministic (no LLM, no egress) and advisory — a critic can only endorse/object/abstain and
    reflection only re-ranks/defers; NEITHER promotes a finding or overrides an oracle (the type
    system enforces the critic side). Best-effort: an import failure yields fewer agents, never
    sinks construction. The LLM-backed ``CritiqueAgent`` is deliberately NOT wired here to keep the
    in-loop nervous system deterministic and network-free (a documented next slice)."""
    agents: list = []
    try:
        from .agents.critics import MultiCriticAgent
        agents.append(MultiCriticAgent(blackboard, slug))
    except Exception:
        pass
    try:
        from .agents.reflection import ReflectionAgent
        agents.append(ReflectionAgent(blackboard, slug))
    except Exception:
        pass
    return agents


def _construct_planner(world: "WorldModel | None", slug: str, tree: Any, objectives: list,
                       source: str | None, request_budget: int, blackboard: Any) -> Any:
    """Construct the real ``Planner`` over the run world-model AND give its Coordinator the real
    advisory agents (:func:`_advisory_agents`) — so the Coordinator, once TICKED in-loop, drives
    the nervous system LIVE instead of being constructed-inert with ``agents=[]``. Needs a
    blackboard (its event substrate); when none is available it is skipped (None) and the cycle
    still runs on the shared tree selection, which is byte-for-byte what the planner itself would
    select. Best-effort — never raises."""
    if blackboard is None:
        return None
    try:
        from .agents.coordinator import Coordinator
        from .planner import Budget, Planner, Pruner, Watchdog

        try:
            blackboard.engagement_id(slug)
        except Exception:
            pass
        coord = Coordinator(blackboard=blackboard, engagement_slug=slug,
                            agents=_advisory_agents(blackboard, slug))
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


def _discovery_registry(discover_send: Any, discover_check: Any, budget: int,
                        *, multi_probe: bool = False) -> Any:
    """A registry carrying ONLY the gated ``probe_surface`` discovery tool, wired with the injected
    ``discover_send`` (production: the gated executor's ``gated_fetch``; tests: a loopback send) and
    the scanner check(s) to wrap. Default: the ONE REFLECTED_XSS check (byte-identical). ``multi_probe``
    (Slice-3, opt-in) wraps the CURATED near-zero-FP multi-class set so one probe tests a discovered
    surface for several bug classes. Built on demand so the default autonomous path (discovery off)
    never imports the scanner tool stack."""
    from .agents.tools.builtin import curated_probe_checks, probe_surface_registry
    checks = curated_probe_checks() if multi_probe else None
    return probe_surface_registry(discover_send, check=discover_check, checks=checks,
                                  max_requests=max(1, int(budget)))


def _drive_probe(target: str, registry: Any, ctx: Any, sink: Any) -> Any:
    """Drive the gated ``probe_surface`` tool over ``target`` (an unexplored ENDPOINT url) through the
    FULL ``invoke_tool`` chain (kill-switch → entitlement → scope → destructive → egress). The tool
    runs ONE existing scanner check via the AuditEngine and returns a NEW oracle-confirmed finding
    ONLY if that check's deterministic oracle FIRES — the tool/planner never promotes on its own. A
    tripped kill-switch or an out-of-scope target REFUSES it and it probes nothing."""
    from .agents.tools.invoker import invoke_tool
    return invoke_tool(registry, "probe_surface", {"target": str(target or "")}, ctx, sink=sink)


def _record_discovered(out: "AutonomyResult", sink: Any, dumps: list, emitted: set) -> int:
    """Record probe-minted NEW findings on the AutonomyResult and mirror each to the spine as a
    finding event. A discovered finding carries its retained ``oracle_context`` (the oracle fired
    over evidence a real target produced), so the report grader renders it a FACT — honest, because a
    deterministic oracle DID confirm it. Deduped by (bug_class, insertion_point, endpoint) so a
    re-probed surface never double-counts. Best-effort/total. Returns the count newly recorded."""
    n = 0
    try:
        from .scanner.engine import AuditFinding
    except Exception:
        return 0
    for d in dumps or []:
        try:
            f = AuditFinding.model_validate(d)
        except Exception:
            continue
        key = (str(f.bug_class), str(f.insertion_point), str(f.endpoint))
        if key in emitted:
            continue
        emitted.add(key)
        out.discovered_findings.append(d)
        n += 1
        if sink is not None:
            try:
                sink.finding_event(_finding_payload(f))
            except Exception:
                pass
    return n


def _fold_discovered_into_report(engagement: Any, dumps: list) -> int:
    """W-F3 — FOLD the discovery cycle's NEW oracle-confirmed findings into the authoritative
    :class:`scanner.campaign.ScanReport`'s ``active_findings`` (the prove-don't-guess boundary WS-C
    deliberately left untouched). This is the honest "next slice" WS-C deferred.

    DETERMINISTIC + idempotent: each discovered dump is validated back into an ``AuditFinding``, the
    surviving set is SORTED by a stable key ``(bug_class, endpoint, insertion_point)``, and DEDUPED
    against BOTH the existing ``active_findings`` AND intra-set (same ``(bug_class, insertion_point,
    endpoint)`` identity ``_record_discovered`` uses) — so the same engagement replays to the same
    report and a re-fold never double-counts ``total_findings``/``by_severity()``.

    PROVE-DON'T-GUESS preserved: only a finding that carries a retained ``oracle_context`` (a
    deterministic oracle DID fire over evidence a real target produced) is spliced — no unconfirmed
    finding is ever added, so ``active_findings`` stays a prove-don't-guess set. Best-effort/total: any
    trouble folds nothing and returns what was folded so far. Returns the count folded.

    Reachability: called ONLY on the opt-in autonomous-discover path (``run_autonomous_cycle`` with a
    discovery send), which the byte-identical benchmark/gate NEVER runs — so the fold is structurally
    unreachable from the gate and the default ``engage`` path is unchanged."""
    n = 0
    try:
        report = getattr(engagement, "report", None)
        active = getattr(report, "active_findings", None) if report is not None else None
        if active is None:
            return 0
        from .scanner.engine import AuditFinding
        seen = {(str(f.bug_class), str(f.insertion_point), str(f.endpoint)) for f in active}
        validated: list = []
        for d in dumps or []:
            try:
                f = AuditFinding.model_validate(d)
            except Exception:
                continue
            if getattr(f, "oracle_context", None) is None:
                continue   # prove-don't-guess: never splice an UNCONFIRMED finding
            validated.append(f)
        # Stable order independent of planner/probe timing → replay-deterministic splice.
        validated.sort(key=lambda f: (str(f.bug_class), str(f.endpoint), str(f.insertion_point)))
        for f in validated:
            key = (str(f.bug_class), str(f.insertion_point), str(f.endpoint))
            if key in seen:
                continue        # already a seed finding (or an intra-set dup) — never double-count
            seen.add(key)
            active.append(f)
            n += 1
    except Exception:
        return n
    return n


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
# W2.2d — a SECOND gated autonomous tool: a `declared_service` reachability re-check.
#
# Beyond `reverify_finding`, the loop can drive a gated `declared_service` re-check of the
# engagement host derived from the confirmed findings. It runs through the SAME fail-closed chain
# (via sensors.pipeline.run_sensor -> agents.tools.invoke_tool: kill-switch -> entitlement -> scope
# -> destructive -> egress), so a tripped kill-switch OR an out-of-scope host REFUSES it and it
# mints nothing. When it runs it folds its output into the world-model as intel-tier OBSERVATIONS
# (GROUNDING_INTEL) — LEADS, never facts: a Sensor never writes a Finding, and only a deterministic
# oracle can later promote an observation. Deterministic: the (host, services) are derived from the
# findings in a fixed order and projected at a seq computed from the world's own clock (no rng).
# ---------------------------------------------------------------------------


def _reachability_registry() -> Any:
    """A registry carrying the SAFE Tier-1 no-egress ``declared_service`` sensor. Built on demand so
    the default autonomous path (reachability off) never imports the sensor stack."""
    from .agents.tools.base import ToolRegistry
    from .sensors.builtin import DeclaredServiceSensor
    reg = ToolRegistry()
    reg.register(DeclaredServiceSensor())
    return reg


def _reachability_target(findings: list) -> "tuple[str, list[dict]] | None":
    """Derive the (host, services) to re-check from the confirmed findings' endpoints, DETERMIN-
    ISTICALLY (findings scanned in a fixed sorted order; the first parseable host wins). The
    service is the endpoint's own scheme/port — the re-check asks 'is the host CRUCIBLE already
    reached still declared reachable on this service?'. None when no finding carries a host."""
    from urllib.parse import urlsplit
    for f in sorted(findings, key=lambda f: (str(getattr(f, "endpoint", "") or ""),
                                             str(getattr(f, "bug_class", "") or ""))):
        ep = str(getattr(f, "endpoint", "") or "")
        if not ep:
            continue
        parts = urlsplit(ep)
        host = parts.hostname
        if not host:
            continue
        scheme = (parts.scheme or "http").lower()
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            port = 443 if scheme == "https" else 80
        return host, [{"port": int(port), "protocol": "tcp", "service": scheme, "state": "open"}]
    return None


def _drive_reachability(world: "WorldModel | None", findings: list, ctx: Any, sink: Any,
                        slug: str, out: "AutonomyResult") -> None:
    """Drive the gated ``declared_service`` reachability re-check ONCE for the engagement host and
    fold its observations into the run world-model as LEADS. Records telemetry on ``out``. Fully
    gated + fail-closed via ``run_sensor``; best-effort/total — it never sinks the cycle and never
    mints a fact. A refusal (kill-switch / out-of-scope) folds nothing and is recorded as such."""
    out.reachability_driven = True
    out.reachability_tool = "declared_service"
    target = _reachability_target(findings)
    if target is None:
        out.notes.append("reachability: no finding carried a host to re-check (skipped)")
        return
    host, services = target
    out.reachability_host = host
    try:
        from .intel.ingest import IntelIngest
        from .sensors.pipeline import run_sensor
    except Exception:
        return
    try:
        ingest = IntelIngest(world if world is not None else _new_world(),
                             engagement_slug=slug)
        # a seq strictly above the world's clock so folding a lead never inverts monotonic time.
        seq = _world_seq(world)
        sr = run_sensor(_reachability_registry(), "declared_service",
                        {"host": host, "services": services}, ctx, ingest=ingest, seq=seq, sink=sink)
        res = getattr(sr, "result", None)
        out.reachability_refused = bool(getattr(res, "refused", False))
        out.reachability_gate = str(getattr(res, "gate", "") or "")
        out.reachability_applied = int(getattr(sr, "applied", 0) or 0)
        if out.reachability_refused:
            out.notes.append(f"reachability: re-check REFUSED at gate {out.reachability_gate!r} "
                             f"(fail-closed) — folded nothing")
        else:
            out.notes.append(f"reachability: re-check on {host} folded {out.reachability_applied} "
                             f"lead observation(s) (intel-tier; never a fact)")
    except Exception:
        pass


def _new_world() -> Any:
    from .worldmodel.graph import WorldModel
    return WorldModel()


def _world_seq(world: "WorldModel | None") -> int:
    """A monotonic seq strictly above the world's current clock (so a folded observation never
    inverts time). Deterministic — a pure function of the world's node clocks (no wallclock/rng)."""
    if world is None:
        return 1
    try:
        return max((int(getattr(n, "last_seen", 0) or 0) for n in world.all_nodes()), default=0) + 1
    except Exception:
        return 1


# ---------------------------------------------------------------------------
# DRIVE — tick the constructed Coordinator so the wired advisory agents RUN IN-LOOP.
#
# These mirror the loop's authoritative facts + its own reasoning trace onto the event spine and
# then TICK the Coordinator, so the multi-critic panel and the reflection agent run INSIDE each
# OODA cycle (the nervous system runs live, not as post-hoc telemetry). All ADVISORY: the critics
# only endorse/object/abstain and reflection only re-ranks/defers — none promotes a finding or
# touches an oracle verdict. Best-effort throughout; only reached when a blackboard is supplied.
# ---------------------------------------------------------------------------


def _finding_payload(f: object) -> dict:
    """A FindingPayload-shaped mirror of a confirmed AuditFinding — enough for the wired critic
    panel to review it in-loop. It mirrors an ALREADY oracle-confirmed fact (telemetry); it does
    NOT re-confirm one. Provenance is honest: ``verified_by_oracle`` tracks the presence of the
    retained ``oracle_context``, and ``critique_status`` stays ``pending`` (the critics advise; a
    verdict never promotes)."""
    bug_class = str(getattr(f, "bug_class", "") or "")
    surface = _finding_surface(f) or str(getattr(f, "param", "") or "") or "(surface)"
    oc = getattr(f, "oracle_context", None)
    conf = getattr(f, "confidence", None)
    try:
        conf = None if conf is None else min(1.0, max(0.0, float(conf)))
    except (TypeError, ValueError):
        conf = None
    return {
        "finding_slug": (f"{bug_class}:{getattr(f, 'insertion_point', '')}"[:120]) or bug_class or "finding",
        "title": (f"{bug_class} at {getattr(f, 'param', '')}".strip() or bug_class or "finding"),
        "severity": "High",
        "bug_class": bug_class or "unknown",
        "surface": str(surface),
        "summary": str(getattr(f, "rationale", "") or f"{bug_class} finding"),
        "critique_status": "pending",
        "oracle_context": oc,
        "verified_by_oracle": bool(oc),
        "confidence": conf,
        "oracle_kind": (str(getattr(f, "confirmed_by", "") or "") or None),
        "oracle_rationale": str(getattr(f, "rationale", "") or ""),
    }


def _mirror_findings_to_spine(sink: Any, findings: list) -> int:
    """Mirror the ALREADY oracle-confirmed findings onto the spine as ``finding`` events so the
    wired critic panel has material to review IN-LOOP. Telemetry over authoritative facts — it
    neither promotes nor demotes; the critics only advise over them. Best-effort. Returns count."""
    if sink is None:
        return 0
    n = 0
    for f in findings:
        try:
            if sink.finding_event(_finding_payload(f)) is not None:
                n += 1
        except Exception:
            pass
    return n


def _post_leaf_hypothesis(blackboard: Any, slug: str, leaf: Any, cycle: int, *, is_probe: bool = False) -> None:
    """Mirror THIS cycle's picked action onto the spine as a ``hypothesis`` event — the honest
    reasoning trace the reflection agent re-orients over. A probe-leaf (DISCOVER) carries a DIFFERENT,
    honest hypothesis than a reverify-leaf: it does not yet have a confirmed finding, so it does not
    claim one. Best-effort; never raises."""
    if blackboard is None:
        return
    if is_probe:
        payload = {
            "handle": f"AUTO-H{cycle:03d}",
            "surface": str(getattr(leaf, "surface", "") or "(surface)"),
            "bug_class": str(getattr(leaf, "bug_class", "") or "unknown"),
            "given": "an unexplored ENDPOINT lead sits on this surface (no confirmed finding yet)",
            "if_action": "probe it with one existing scanner check via the gated probe_surface tool",
            "then_observation": "the check's deterministic oracle either FIRES (a NEW finding) or does not",
            "because_model": "discovery-by-oracle — only a fired oracle mints a finding",
            "refute_on": "the probe oracle does not fire (no bug on this surface)",
            "cheap_test": "probe_surface (one existing check; gated; localhost/authorized only)",
            "confidence": min(1.0, max(0.0, float(getattr(leaf, "prior_p_success", 0.5) or 0.5))),
            "status": "open",
        }
    else:
        payload = {
            "handle": f"AUTO-H{cycle:03d}",
            "surface": str(getattr(leaf, "surface", "") or "(surface)"),
            "bug_class": str(getattr(leaf, "bug_class", "") or "unknown"),
            "given": "an oracle-confirmed finding sits on this surface",
            "if_action": "re-execute the finding's retained oracle certificate",
            "then_observation": "the oracle either re-fires (grounded) or does not",
            "because_model": "prove-by-re-execution over the retained proof",
            "refute_on": "the retained oracle certificate no longer re-grounds",
            "cheap_test": "reverify_finding (Tier-1, no egress)",
            "confidence": min(1.0, max(0.0, float(getattr(leaf, "prior_p_success", 0.5) or 0.5))),
            "status": "open",
        }
    try:
        blackboard.post(engagement=slug, kind="hypothesis", agent_name="autonomy", payload=payload)
    except Exception:
        pass


def _drive_coordinator(planner: Any, *, max_ticks: int = 4) -> int:
    """TICK the constructed Coordinator so its wired advisory agents RUN this cycle — this is what
    makes the planner DRIVEN (its nervous system runs in-loop) rather than constructed-inert.
    Returns the events the agents posted. Best-effort — a tick failure never sinks the cycle. The
    Coordinator, per FORGE §3.4, cannot suppress a critic objection; it only orders + budgets."""
    coord = getattr(planner, "coord", None)
    if coord is None:
        return 0
    try:
        report = coord.run_until_quiet(max_ticks=max(1, int(max_ticks)))
        return int(getattr(report, "total_events", 0) or 0)
    except Exception:
        return 0


def _count_kind(blackboard: Any, slug: str, kind: str) -> int:
    """Count spine events of ``kind`` for the engagement — best-effort (0 on any trouble)."""
    if blackboard is None:
        return 0
    try:
        return int(blackboard.count(engagement=slug, kind=kind))
    except Exception:
        return 0


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
    outcome_ledger: Any = None,
    smt_regions: Any = None,
    persist_learning: bool = False,
    lookahead_depth: int = 1,
    enable_reachability: bool = False,
    enable_discover: bool = False,
    discover_send: Any = None,
    discover_check: Any = None,
    discover_bug_class: str = "xss",
    enable_crawl_expand: bool = False,
    crawl_max_pages: int = 20,
    enable_multi_probe: bool = False,
    probe_posture: str = "auto-test",
) -> AutonomyResult:
    """Run ONE bounded OODA cycle (``max_cycles`` default 1) over an authoritative
    :class:`engage.EngagementResult`. The scan report is NEVER mutated — the cycle only reads the
    confirmed findings + world-model, drives a gated tool, and folds its observation back.

    ``lookahead_depth`` (default 1, W2.2b): 1 keeps the ONE-STEP greedy selection (byte-identical to
    the pre-lookahead behaviour, so the existing tests are unchanged); ``>= 2`` switches selection
    to bounded MULTI-STEP lookahead (see :func:`_select`) — the pick that begins the best plan
    (``<= depth`` leaves, cost fitting ``request_budget``) toward a crown jewel, still gated, still
    deterministic. Lookahead only re-ranks WHICH open leaf runs next; it never promotes a finding or
    changes the authoritative report.

    ``enable_discover`` (default off → byte-identical, W-C): the DISCOVERING slice. With a
    ``discover_send`` injected (production: the gated executor's ``gated_fetch``; tests: a loopback
    send), the goal tree ALSO gets LOW-prior probe-leaves seeded from world-model ENDPOINT nodes
    (:func:`_build_goal_tree`); when one is selected the loop drives the gated ``probe_surface`` tool
    over that unexplored endpoint, which runs ONE existing scanner check (``discover_check``, default
    REFLECTED_XSS) and mints a NEW oracle-confirmed finding — recorded on ``out.discovered_findings``
    — ONLY when that check's deterministic oracle FIRES. The oracle stays the sole authority: the
    tool/planner never promotes on their own.

    W-F3 — the discovered findings are then FOLDED into the authoritative ``ScanReport.active_findings``
    (the honest next slice WS-C deferred): :func:`_fold_discovered_into_report` sorts the discovered
    set by a stable key ``(bug_class, endpoint, insertion_point)`` and dedups against BOTH the existing
    active_findings AND intra-set, so the same engagement replays to the SAME report and a re-fold
    never double-counts. Every folded finding carries its retained ``oracle_context``, so
    active_findings stays a prove-don't-guess set — no unconfirmed finding is spliced. The fold runs
    ONLY on this opt-in discover path, so it is structurally unreachable from the byte-identical
    benchmark/gate. Off, no probe-leaf is seeded, ``probe_surface`` is never constructed, and the
    authoritative report is left byte-identical.

    Localhost/authorized-only: the enclosing ``engage.run_engagement`` preflight already refused an
    out-of-scope / kill-switched engagement before this runs, and every tool call is re-gated by
    ``invoke_tool`` regardless. Deterministic and best-effort throughout."""
    from .agents.tools import ToolContext

    lookahead_depth = max(1, int(lookahead_depth))

    world = getattr(result, "world", None)
    findings = list(getattr(getattr(result, "report", None), "active_findings", []) or [])
    registry = registry if registry is not None else _default_registry()
    if ctx is None:
        ctx = ToolContext(slug=slug, world=world, prompt_callback=prompt_callback)

    out = AutonomyResult(engagement=result, slug=slug)
    out.lookahead_depth = lookahead_depth
    out.world_nodes_before = world.node_count if world is not None else 0
    objectives = _objective_kinds()
    out.objectives = [getattr(k, "value", str(k)) for k in objectives]

    # DISCOVER (opt-in) — only when requested AND a send is injected AND a world exists to read
    # ENDPOINT leads from. Off → the tree seeds NO probe-leaves and probe_surface is never built,
    # so everything below is byte-identical to the pre-discovery loop.
    discover_active = bool(enable_discover) and discover_send is not None and world is not None
    out.discover_enabled = discover_active
    # Slice-4 posture: "discover-queue" (park probe-leaves for operator approval, zero probe traffic) is
    # the SAFE operator default; "auto-test" actively probes. Any unrecognised value falls back to the
    # active posture (the function's back-compat default) — the operator-facing safe default lives at the
    # engage CLI. Normalised once here.
    probe_posture = "discover-queue" if str(probe_posture) == "discover-queue" else "auto-test"
    out.probe_posture = probe_posture

    # DISCOVER — Slice-0 asset→endpoint promotion (the recon→test bridge). Before the goal tree is
    # built, promote each IN-SCOPE recon/sensor asset (DOMAIN/HOST/web-SERVICE) into a url-bearing
    # ENDPOINT node so the probe-leaf seeding below can SEE it. In-scope by construction (the charter
    # predicate the live gate uses); a LEAD (intel:promote provenance), never a fact; deterministic +
    # idempotent. Discover-path only → structurally unreachable from the byte-identical gate.
    if discover_active:
        try:
            from .intel.promote import promote_to_endpoints
            promoted = promote_to_endpoints(world, slug)
            out.endpoints_promoted = len(promoted)
            if promoted:
                out.notes.append(
                    f"discovery: promoted {len(promoted)} in-scope recon/sensor asset(s) "
                    "to testable endpoint(s)")
        except Exception:
            pass   # best-effort: promotion never breaks the cycle

        # DISCOVER — Slice-2 in-loop crawl/mine expansion (opt-in on top of discover; default OFF so the
        # existing discover tests stay byte-identical). Crawl each promoted ROOT endpoint — bounded,
        # scope-from-seed, over the SAME gated discover_send — and mint the discovered in-scope
        # param-bearing URLs as ENDPOINT nodes (provenance intel:expand). They flow through the frontier
        # into the goal tree, so a promoted host is not just reached but its real pages/params are tested.
        if enable_crawl_expand and promoted:
            try:
                from .intel.expand import expand_endpoint
                from .worldmodel.models import Node, NodeKind
                seq = max((n.last_seen for n in world.all_nodes()), default=0) + 1
                expanded = 0
                for _pid, root_url in promoted:
                    for durl in expand_endpoint(discover_send, root_url, max_pages=crawl_max_pages):
                        nid = f"endpoint:expand:{durl}"
                        if world.has_node(nid):
                            continue
                        world.add_node(Node(id=nid, kind=NodeKind.ENDPOINT,
                                            attrs={"url": durl, "expanded_from": root_url},
                                            provenance=f"intel:expand:{root_url}", confidence=0.5,
                                            first_seen=seq, last_seen=seq))
                        expanded += 1
                out.endpoints_expanded = expanded
                if expanded:
                    out.notes.append(
                        f"discovery: crawl-expanded {expanded} in-scope param-bearing surface(s)")
            except Exception:
                pass   # best-effort: expansion never breaks the cycle

    # ORIENT — goal tree over the confirmed findings (+ opt-in unexplored ENDPOINT probe-leaves) and
    # the planner over the run world-model.
    tree, leaf_to_finding = _build_goal_tree(
        findings, world=world, seed_probe_leaves=discover_active,
        probe_bug_class=str(discover_bug_class or "xss"))
    baselines = _leaf_baselines(tree)   # fixed per-run priors; every advice re-weight recomputes from these
    source = _foothold(world)
    out.planner_source = source
    planner = _construct_planner(world, slug, tree, objectives, source, request_budget, blackboard)
    out.planner_constructed = planner is not None
    if planner is not None:
        out.agents_wired = [getattr(a, "name", "agent") for a in getattr(planner.coord, "agents", [])]

    sink = _spine_sink(blackboard, slug)
    emitted_lead_ids: set = set()   # I-C dedup — a fused observation emits at most one lead event

    # A probe-leaf is exactly an open leaf the goal tree seeded that is NOT a confirmed finding (only
    # discovery adds such leaves). Build the discovery registry once, on demand, when there is at
    # least one to drive — so the default path never constructs the scanner tool stack.
    probe_leaf_ids: set = (
        {l.id for l in tree.open_leaves() if l.id not in leaf_to_finding} if discover_active else set())
    out.probe_leaves_seeded = len(probe_leaf_ids)
    discover_registry = (
        _discovery_registry(discover_send, discover_check, request_budget, multi_probe=enable_multi_probe)
        if (discover_active and probe_leaf_ids) else None)
    emitted_discovered: set = set()   # dedup NEW discovered findings by (bug_class, insertion_point, endpoint)
    if discover_active and probe_leaf_ids:
        out.notes.append(
            f"discovery: {len(probe_leaf_ids)} unexplored ENDPOINT probe-leaf/leaves seeded (low prior)")

    if not findings and not probe_leaf_ids:
        out.notes.append("no confirmed findings — nothing to drive this cycle")
        # still exercise the OBSERVE (WS-B) + reasoning (WS-F) seams so they are live on an empty run
        empty_obs = _fuse_sensors(world, slug, ctx)
        out.fused_observations += len(empty_obs)
        _emit_fused_leads(sink, empty_obs, emitted_lead_ids)   # I-C: fused leads reach the report
        out.world_nodes_after = world.node_count if world is not None else 0
        out.reasoning_advice = _reason_step(world, findings, ctx)
        return out

    # ORIENT (learner health) — consult the meta-monitor over the outcome ledger (explicit arg, else
    # the operator's targets/<slug>/outcomes.json). CAUTION-ONLY: it orders effort (deprioritises
    # borderline leaves), never gates a surface or promotes a finding. No ledger → no modulation.
    ledger = outcome_ledger if outcome_ledger is not None else _load_ledger(slug)
    out.meta_recommend, meta_caution = _meta_caution(slug, ledger)
    if meta_caution > 0.0:
        out.notes.append(f"meta-monitor: {out.meta_recommend} → caution ordering (no surface gated)")

    # LEARN (setup) — the loop will WRITE this run's confirm/refute outcomes into the ledger. A missing
    # ledger is CREATED (else the FIRST autonomous run could never bootstrap learning). We OWN
    # persistence only when we created/loaded it here (not a caller-passed ledger — the caller owns
    # that) AND `persist_learning`. We credit outcomes whenever they'll be durable somewhere (we
    # persist, or the caller does); otherwise we stay read-only (the pre-LEARN behaviour).
    learn_owned = persist_learning and outcome_ledger is None
    if ledger is None and learn_owned:
        from .calibration.ledger import OutcomeLedger
        ledger = OutcomeLedger()
    # Credit ONLY a ledger we own (created/loaded here under persist_learning). A caller-passed
    # `outcome_ledger` is READ-ONLY input to the meta-monitor — never mutated (some callers pass a
    # crafted ledger purely to drive caution ordering and must see it unchanged).
    learn_active = learn_owned and ledger is not None
    learn_credits = 0

    # ORIENT (SMT) — deprioritise leaves whose bounded parameter region is PROVABLY infeasible. The
    # region set is fixed for the run, so it is computed once. Advisory: it degrades to a no-op
    # without z3 on large domains and never gates a surface.
    smt_infeasible = _smt_infeasible_leaves(tree, smt_regions)
    out.smt_deprioritised = len(smt_infeasible)
    if smt_infeasible:
        out.notes.append(f"smt: {len(smt_infeasible)} provably-infeasible region(s) deprioritised (not gated)")

    # ORIENT (reasoning) — run the WS-F step ONCE up front and feed its advice into the FIRST
    # selection, so reasoning drives the opening pick, not only the re-orient.
    advice = _reason_step(world, findings, ctx)
    out.reasoning_advice = advice
    out.advice_reweighted += _reprioritise(tree, baselines, advice=advice, meta_caution=meta_caution,
                                           smt_infeasible=smt_infeasible)

    # DRIVE (setup) — mirror the ALREADY oracle-confirmed findings onto the spine so the wired
    # advisory critic panel has material to review when the Coordinator ticks in-loop. This is
    # telemetry over authoritative facts; it neither promotes nor demotes any finding.
    _mirror_findings_to_spine(sink, findings)

    cycles = max(1, int(max_cycles))
    for c in range(1, cycles + 1):
        # OBSERVE — re-run the WS-B sensor fusion EACH cycle, folding fresh observations into the
        # SAME world-model the planner reasons over BEFORE this cycle's selection. Idempotent: the
        # fusion's stable obs_ids mean re-fusing the same offline producers never inflates belief.
        cycle_obs = _fuse_sensors(world, slug, ctx)
        cycle_fused = len(cycle_obs)
        out.fused_observations += cycle_fused
        _emit_fused_leads(sink, cycle_obs, emitted_lead_ids)   # I-C: fused leads reach the report

        leaf = _select(tree, world, objectives, source,
                       lookahead_depth=lookahead_depth, budget=request_budget)
        if leaf is None:
            out.notes.append(f"cycle {c}: no open action remaining")
            break
        step = AutonomyStep(cycle=c, picked_leaf_id=leaf.id, picked_label=leaf.label,
                            picked_surface=leaf.surface, picked_bug_class=leaf.bug_class,
                            fused_observations=cycle_fused)
        finding = leaf_to_finding.get(leaf.id)
        # A probe-leaf (an unexplored ENDPOINT lead, not a confirmed finding) drives DISCOVERY;
        # every other open leaf is a confirmed finding and drives the existing RE-VERIFY path.
        is_probe = discover_registry is not None and leaf.id in probe_leaf_ids
        step.is_probe = is_probe

        # DRIVE — mirror THIS cycle's picked action onto the spine as a hypothesis (the honest
        # reasoning trace the in-loop reflection agent re-orients over).
        _post_leaf_hypothesis(blackboard, slug, leaf, c, is_probe=is_probe)

        # ACT — drive the picked action as a GATED tool call.
        tree.mark_status(leaf.id, "claimed")
        if is_probe and probe_posture == "discover-queue":
            # ACT (DISCOVER, discover-queue posture) — the SAFE default: enumerate/promote/crawl runs
            # autonomously, but a probe-leaf is PARKED for operator approval rather than actively
            # tested. Zero target probe traffic is issued here (the hypothesis lead was already emitted
            # to the spine above); the operator reviews the queued candidates and re-runs under
            # auto-test to actually probe an approved batch. Keeps a human on the ACT trigger.
            step.tool = "probe_surface"
            step.gated = True
            step.tool_ok = True
            step.verdict = f"queued for operator approval (discover-queue posture — no traffic): {leaf.surface}"
            out.candidates_queued += 1
            out.queued_candidates.append(str(leaf.surface))
            tree.mark_status(leaf.id, "deferred")
            out.notes.append(
                f"cycle {c}: QUEUED probe candidate {leaf.surface} (discover-queue — awaiting operator approval)")
        elif is_probe:
            # ACT (DISCOVER, auto-test posture) — drive the gated probe_surface tool over the unexplored
            # endpoint. It runs the curated check(s) and mints a NEW oracle-confirmed finding ONLY if a
            # check's deterministic oracle FIRES; the tool/planner never promote on their own.
            res = _drive_probe(leaf.surface, discover_registry, ctx, sink)
            step.tool = "probe_surface"
            step.gated = True
            step.refused = bool(getattr(res, "refused", False))
            step.gate = str(getattr(res, "gate", "") or "")
            step.tool_ok = bool(getattr(res, "ok", False))
            output = getattr(res, "output", {}) or {}
            step.verdict = str(getattr(res, "summary", "") or "")
            # UPDATE (DISCOVER) — fold the outcome into the world-model + goal tree.
            if step.refused:
                # a fail-closed refusal is not a clean surface — leave the leaf open, note it.
                tree.mark_status(leaf.id, "open")
                out.probes_refused += 1
                out.notes.append(f"cycle {c}: probe_surface refused at gate {step.gate!r} (fail-closed)")
            else:
                out.probes_driven += 1
                if bool(output.get("minted", False)):
                    recorded = _record_discovered(out, sink, output.get("findings", []), emitted_discovered)
                    step.discovered_findings = recorded
                    out.discovered_count += recorded
                    step.folded_node = _fold_observation(world, leaf.surface, "discovered")
                    tree.mark_status(leaf.id, "succeeded")
                    out.notes.append(
                        f"cycle {c}: DISCOVERED {recorded} NEW oracle-confirmed finding(s) at {leaf.surface}")
                else:
                    # the oracle stayed silent — no bug here; this is a refutation of the probe-leaf,
                    # never of any finding (there was none). The surface stays covered (marked done).
                    step.folded_node = _fold_observation(world, leaf.surface, "probed-clean")
                    tree.mark_status(leaf.id, "failed", reason="probe oracle did not fire")
        else:
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
                # LEARN — feed THIS confirm/refute back into the persistent OutcomeLedger. This is the loop
                # closure: the outcome the meta-monitor read at the START of this run is now written by the
                # run itself, so the NEXT run's `_meta_caution` reads richer ground truth. A fail-closed
                # refusal is excluded (handled in the `if step.refused` branch above — it is not a
                # refutation). Non-circular + off-gate + best-effort (see the LEARN helpers).
                if learn_active and finding is not None:
                    if _credit_finding_outcome(ledger, finding, leaf, grounded, sink, learn_credits):
                        learn_credits += 1
                        step.learned = True

        # RE-ORIENT — run the WS-F reasoning hook, FEED its advice back into the tree (re-weight the
        # matching open leaves' priors), THEN re-select. This is what closes the loop: the reasoning
        # advice changes which leaf the planner picks next.
        advice = _reason_step(world, findings, ctx)
        out.reasoning_advice = advice
        step.advice_reweighted = _reprioritise(tree, baselines, advice=advice, meta_caution=meta_caution,
                                               smt_infeasible=smt_infeasible)
        out.advice_reweighted += step.advice_reweighted
        nxt = _select(tree, world, objectives, source,
                      lookahead_depth=lookahead_depth, budget=request_budget)
        step.reoriented_to = nxt.label if nxt is not None else "(no more actions)"

        # DRIVE — tick the constructed Coordinator so its wired advisory agents (the multi-critic
        # panel + the reflection agent) RUN this cycle over the mirrored facts + reasoning trace.
        # This is what makes the planner DRIVEN (its nervous system runs in-loop) rather than
        # constructed-inert. Advisory only: a critic never confirms, reflection only re-ranks/defers;
        # the oracle stays the sole authority for any promotion.
        if planner is not None:
            step.coordinator_events = _drive_coordinator(planner)
            out.coordinator_events += step.coordinator_events
            out.planner_driven = True
        out.cycles.append(step)

    # W2.2d — the SECOND gated autonomous tool (opt-in). Drive a `declared_service` reachability
    # re-check of the engagement host through the FULL fail-closed gate chain and fold its output
    # into the world-model as intel-tier LEADS (never facts). Default off → byte-identical.
    if enable_reachability:
        _drive_reachability(world, findings, ctx, sink, slug, out)

    out.critic_verdicts = _count_kind(blackboard, slug, "critic_verdict")
    out.reflections = _count_kind(blackboard, slug, "reflection")
    out.world_nodes_after = world.node_count if world is not None else 0

    # LEARN (persist) — write the enriched ledger back so the NEXT run's meta-monitor reads it. Only
    # when WE own persistence (created/loaded here, not caller-passed) and we actually credited
    # something. A caller-passed ledger is left for the caller to persist. Best-effort.
    out.outcomes_credited = learn_credits
    if learn_owned and learn_credits > 0:
        out.learner_persisted = _persist_ledger(ledger, slug)
        if out.learner_persisted:
            out.notes.append(f"learned: {learn_credits} outcome(s) written to the outcome ledger")

    # W-F3 — FOLD the DISCOVERED findings into the authoritative report. Opt-in discover path ONLY
    # (`discover_active`), so structurally unreachable from the byte-identical benchmark/gate and the
    # default engage path. Deterministic + deduped (see `_fold_discovered_into_report`); every folded
    # finding carries its oracle_context, so active_findings stays a prove-don't-guess set.
    if discover_active and out.discovered_findings:
        out.findings_folded = _fold_discovered_into_report(result, out.discovered_findings)
        if out.findings_folded:
            out.notes.append(
                f"folded {out.findings_folded} discovered finding(s) into the authoritative report")
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
    sel = (f"lookahead depth-{out.lookahead_depth}" if out.lookahead_depth >= 2
           else "one-step greedy")
    lines.append(
        f"  autonomous OODA   : planner over world-model "
        f"(constructed={out.planner_constructed}, driven={out.planner_driven}, source={src}, "
        f"objectives={','.join(out.objectives) or 'none'}, select={sel})")
    if out.agents_wired:
        lines.append(
            f"    nervous system  : agents={','.join(out.agents_wired)}; "
            f"{out.coordinator_events} in-loop event(s) "
            f"({out.critic_verdicts} critic verdict(s), {out.reflections} reflection(s)) — advisory")
    if out.meta_recommend and out.meta_recommend != "ok":
        lines.append(f"    learner health  : {out.meta_recommend} → caution ordering (no surface gated)")
    if out.smt_deprioritised:
        lines.append(f"    smt pruning     : {out.smt_deprioritised} provably-infeasible region(s) "
                     f"deprioritised (advisory; not gated)")
    if out.fused_observations:
        lines.append(f"    fused sensors   : {out.fused_observations} observation(s) (WS-B)")
    if out.discover_enabled:
        lines.append(
            f"    discovery       : {out.probe_leaves_seeded} probe-leaf/leaves (unexplored ENDPOINTs); "
            f"{out.probes_driven} probed, {out.probes_refused} refused → {out.discovered_count} NEW "
            f"oracle-confirmed finding(s) minted ({out.findings_folded} folded into the report)")
    if out.reachability_driven:
        if out.reachability_refused:
            lines.append(f"    reachability    : {out.reachability_tool} on "
                         f"{out.reachability_host or '(no host)'} REFUSED @ gate "
                         f"{out.reachability_gate} (fail-closed)")
        else:
            lines.append(f"    reachability    : {out.reachability_tool} on "
                         f"{out.reachability_host or '(no host)'} → folded "
                         f"{out.reachability_applied} lead(s) (intel-tier; never a fact)")
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
        rw = (f", re-weighted {out.advice_reweighted} leaf/leaves into selection"
              if out.advice_reweighted else " (no leaf re-weighted this run)")
        lines.append(f"    reasoning advice: present (WS-F){rw}")
    return lines
