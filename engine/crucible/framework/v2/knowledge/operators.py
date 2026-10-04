"""
knowledge.operators — evaluate techniques against the world-model and assert
their effects.

This is the bridge from the technique catalog into world-model derivation. An
`Operator` *is* an interaction rule: its preconditions are checked against the
graph, and if they hold, its effects are asserted as new edges/attrs carrying
`provenance="operator:<id>"`. Chaining operators to a fixpoint is exactly what
lets the path engine reach a crown jewel it could not reach before — intel
turned into a move, a move turned into a new edge, a new edge turned into a
path.

Three public entry points:

    applicable(op, world, focus)         -> bool
    match(op, world, focus, seed=None)   -> Binding | None   (captures roles)
    apply(op, world, binding, seq)       -> list[Applied]     (mutates world)

plus `derive` (match+apply in one) and `saturate` (run a whole catalog to a
fixpoint). Everything is deterministic: no clock, no randomness. The caller
supplies the monotonic sequence int used as first_seen/last_seen on every
asserted fact, exactly as the world-model demands.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterable, Mapping

from ..common.errors import CrucibleError
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, Node, NodeKind
from .models import (
    AttrOp,
    Direction,
    Effect,
    EffectKind,
    Operator,
    Predicate,
    PredicateKind,
)

# A binding maps role names -> node ids. "focus" is always present.
Binding = dict[str, str]


class OperatorError(CrucibleError):
    """A knowledge-layer error — an effect references a role the binding
    cannot resolve, or asserts an edge to a node not in the graph. This is a
    modelling/wiring fault, not an authorization decision, so it is a plain
    CrucibleError, never an EthicsViolation."""


# ---------------------------------------------------------------------------
# Applied change (returned for inspection / audit)
# ---------------------------------------------------------------------------


class Applied:
    """A single fact an operator asserted, for the caller to inspect. Holds
    the stored Edge or Node (post-merge) and the operator id that produced it.
    Intentionally a light record, not a Pydantic model — it wraps objects the
    world-model already validated."""

    __slots__ = ("operator_id", "edge", "node")

    def __init__(self, operator_id: str, *, edge: Edge | None = None, node: Node | None = None):
        self.operator_id = operator_id
        self.edge = edge
        self.node = node

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        what = self.edge.key if self.edge is not None else (self.node.id if self.node else None)
        return f"Applied(op={self.operator_id!r}, {what})"


# ---------------------------------------------------------------------------
# Attr comparison
# ---------------------------------------------------------------------------


def _attr_ok(attrs: Mapping[str, object], attr: str, op: AttrOp, value: object) -> bool:
    present = attr in attrs
    observed = attrs.get(attr)
    if op is AttrOp.EXISTS:
        return present
    if op is AttrOp.ABSENT:
        return not present
    if op is AttrOp.FALSY:
        # a missing attr is as falsy as an explicit false — the honest reading
        return not present or not bool(observed)
    if op is AttrOp.TRUTHY:
        return present and bool(observed)
    if not present:
        # EQ/NE/IN over a missing attr: only NE is vacuously... no — an absent
        # attr matches nothing here; NE of a missing attr is False too (there
        # is no observed value to differ from). Fail closed.
        return False
    if op is AttrOp.EQ:
        return observed == value
    if op is AttrOp.NE:
        return observed != value
    if op is AttrOp.IN:
        return observed in value  # value validated as list/tuple in the model
    raise OperatorError(f"unhandled AttrOp {op!r}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------


def _incident_matches(
    world: WorldModel, focus_id: str, pred: Predicate
) -> list[str]:
    """Ids of far nodes reachable from `focus_id` by an edge satisfying an
    INCIDENT_EDGE predicate (kind + direction + optional far-node kind).
    Deterministic (sorted) order."""
    assert pred.edge_kind is not None
    far: list[str] = []
    directions = (
        (Direction.OUT, Direction.IN)
        if pred.direction is Direction.EITHER
        else (pred.direction,)
    )
    for d in directions:
        incoming = d is Direction.IN
        for edge in world.neighbors(focus_id, [pred.edge_kind], incoming=incoming):
            other_id = edge.src if incoming else edge.dst
            if pred.other_kind is not None:
                other = world.get_node(other_id)
                if other is None or other.kind is not pred.other_kind:
                    continue
            far.append(other_id)
    # de-dup while staying deterministic
    return sorted(dict.fromkeys(far))


def _graph_node_matches(world: WorldModel, pred: Predicate) -> list[str]:
    """Ids of nodes satisfying a GRAPH_HAS_NODE predicate (kind + optional
    attr constraint), id-sorted."""
    assert pred.node_kind is not None
    out: list[str] = []
    for node in world.nodes_of_kind(pred.node_kind):
        if pred.attr is not None:
            if not _attr_ok(node.attrs, pred.attr, pred.op, pred.value):
                continue
        out.append(node.id)
    return sorted(out)


def _predicate_ok(
    world: WorldModel, focus: Node, pred: Predicate, captures: dict[str, str]
) -> bool:
    """Evaluate one predicate against the focus node + graph. On success,
    record any `capture_as` binding into `captures` (first id-sorted match,
    for determinism)."""
    k = pred.kind
    if k is PredicateKind.NODE_KIND:
        return focus.kind is pred.node_kind
    if k is PredicateKind.NODE_ATTR:
        assert pred.attr is not None
        return _attr_ok(focus.attrs, pred.attr, pred.op, pred.value)
    if k is PredicateKind.INCIDENT_EDGE:
        far = _incident_matches(world, focus.id, pred)
        if not far:
            return False
        if pred.capture_as:
            captures[pred.capture_as] = far[0]
        return True
    if k is PredicateKind.GRAPH_HAS_NODE:
        hits = _graph_node_matches(world, pred)
        if not hits:
            return False
        if pred.capture_as:
            captures[pred.capture_as] = hits[0]
        return True
    raise OperatorError(f"unhandled PredicateKind {k!r}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def applicable(operator: Operator, world: WorldModel, focus: Node) -> bool:
    """True iff every precondition of `operator` holds for `focus` in
    `world`. Pure — reads the graph, mutates nothing."""
    captures: dict[str, str] = {}
    return all(_predicate_ok(world, focus, p, captures) for p in operator.preconditions)


def match(
    operator: Operator,
    world: WorldModel,
    focus: Node,
    seed: Mapping[str, str] | None = None,
) -> Binding | None:
    """If `operator` is applicable to `focus`, return a full `Binding`
    (role -> node id) comprising `focus`, every role the preconditions
    captured, and any caller-seeded roles (e.g. an `actor` principal the
    technique acts *as*). Otherwise return None.

    Seeded roles must reference nodes already in the graph — a binding that
    points an effect at a phantom node would fail loudly at apply time, so we
    reject it here where the cause is clear."""
    captures: dict[str, str] = {}
    for p in operator.preconditions:
        if not _predicate_ok(world, focus, p, captures):
            return None
    binding: Binding = {"focus": focus.id}
    binding.update(captures)
    if seed:
        for role, node_id in seed.items():
            if not world.has_node(node_id):
                raise OperatorError(
                    f"seeded role {role!r} -> {node_id!r} references a node "
                    f"not in the world-model"
                )
            binding[role] = node_id
    return binding


def _resolve(binding: Binding, role: str, operator_id: str) -> str:
    node_id = binding.get(role)
    if node_id is None:
        raise OperatorError(
            f"operator {operator_id!r} effect references unbound role {role!r}; "
            f"available roles: {sorted(binding)}"
        )
    return node_id


def apply(
    operator: Operator,
    world: WorldModel,
    binding: Binding,
    seq: int,
) -> list[Applied]:
    """Assert every effect of `operator` into `world`, resolving effect roles
    against `binding`. Each asserted fact carries
    `provenance="operator:<id>"`, `first_seen=last_seen=seq`, and the
    effect's confidence; asserted edges also record the technique refs and
    detection signals so a derived edge is self-explaining.

    Returns the list of `Applied` records (post-merge stored objects), in
    effect order. Mutates `world` via its idempotent upsert path, so
    re-applying the same operator refines rather than duplicates.

    Raises OperatorError if an effect references an unbound role or an edge
    endpoint absent from the graph."""
    if seq < 0:
        raise ValueError("seq must be >= 0")
    provenance = f"operator:{operator.id}"
    applied: list[Applied] = []
    for effect in operator.effects:
        if effect.kind is EffectKind.ASSERT_EDGE:
            assert effect.edge_kind is not None and effect.src_role and effect.dst_role
            src = _resolve(binding, effect.src_role, operator.id)
            dst = _resolve(binding, effect.dst_role, operator.id)
            attrs: dict[str, object] = dict(effect.edge_attrs)
            attrs.setdefault("technique", operator.id)
            attrs.setdefault("technique_ref", list(operator.technique_ref))
            if operator.detection_signals:
                attrs.setdefault("detection_signals", list(operator.detection_signals))
            if operator.oracle_kind is not None:
                attrs.setdefault("oracle_kind", operator.oracle_kind.value)
            if effect.note:
                attrs.setdefault("effect_note", effect.note)
            stored = world.add_edge(
                Edge(
                    src=src,
                    dst=dst,
                    kind=effect.edge_kind,
                    attrs=attrs,
                    provenance=provenance,
                    confidence=effect.confidence,
                    first_seen=seq,
                    last_seen=seq,
                )
            )
            applied.append(Applied(operator.id, edge=stored))
        else:  # SET_ATTR
            assert effect.attr is not None
            target_id = _resolve(binding, effect.target_role, operator.id)
            existing = world.get_node(target_id)
            if existing is None:
                raise OperatorError(
                    f"operator {operator.id!r} SET_ATTR targets unknown node "
                    f"{target_id!r}"
                )
            stored = world.add_node(
                Node(
                    id=target_id,
                    kind=existing.kind,
                    attrs={effect.attr: effect.value},
                    provenance=provenance,
                    confidence=effect.confidence,
                    first_seen=seq,
                    last_seen=seq,
                )
            )
            applied.append(Applied(operator.id, node=stored))
    return applied


def derive(
    operator: Operator,
    world: WorldModel,
    focus: Node,
    seq: int,
    seed: Mapping[str, str] | None = None,
) -> list[Applied] | None:
    """match + apply in one step. Returns the applied changes, or None if the
    operator is not applicable to `focus`."""
    binding = match(operator, world, focus, seed)
    if binding is None:
        return None
    return apply(operator, world, binding, seq)


def _narrow_focus_kind(op: Operator) -> NodeKind | None:
    """The single :class:`NodeKind` the focus node of every match of `op` MUST
    have, or ``None`` when that cannot be pinned statically (the operator has no
    ``NODE_KIND`` precondition, more than one naming different kinds, or one
    naming no kind at all).

    This drives the saturation loop's candidate narrowing, and it is
    behaviour-preserving BY CONSTRUCTION: a ``NODE_KIND`` precondition is checked
    inside :func:`match` as ``focus.kind is pred.node_kind`` (see
    :func:`_predicate_ok`), so a focus of any other kind fails it, ``match``
    returns ``None``, ``derive`` returns ``None``, and NOTHING is asserted — the
    graph, the sequence int and the ``seen`` set are all untouched. Visiting such
    a node is therefore indistinguishable from skipping it. When this returns a
    kind ``K``, the loop iterates ``world.nodes_of_kind(K)`` — which is exactly
    ``world.all_nodes()`` filtered to kind ``K``, in the SAME id-sorted order
    (the per-kind order index is maintained as that sorted subsequence; see
    ``worldmodel.graph`` and ``test_graph_order_identity``) — so the surviving
    matches fire in the identical order, at the identical seq, accumulating the
    identical belief. ``None`` means 'do not narrow': scan every node, exactly as
    the pre-index loop did, so an operator we cannot pin stays fully correct."""
    kinds = {
        p.node_kind
        for p in op.preconditions
        if p.kind is PredicateKind.NODE_KIND and p.node_kind is not None
    }
    return next(iter(kinds)) if len(kinds) == 1 else None


def _saturate_full(
    operators: Iterable[Operator],
    world: WorldModel,
    seq_start: int,
    *,
    seeds: Mapping[str, Mapping[str, str]] | None = None,
    max_rounds: int = 16,
) -> list[Applied]:
    """The FULL-RESCAN fixpoint — the pre-M2.1 ``saturate`` body, retained verbatim
    as the differential reference :func:`saturate` is proven byte-identical against.

    Every round tries EVERY operator against EVERY candidate node (narrowed by
    statically-pinned focus kind — the earlier #828 win) and ``derive``s it. A
    successful match re-fires its effects on EVERY round until the loop stops, which
    is how the model accumulates Beta belief (``alpha``/``beta``) and widens
    ``last_seen`` — that re-firing is part of the result, not noise.

    :func:`saturate` is the worklist rewrite (M2.1) that reaches the IDENTICAL
    saturated graph with strictly fewer ``derive`` calls. This function is the slow,
    obviously-correct truth it is diffed against over fixture AND random graphs (see
    ``knowledge/tests/test_operators.py``). Do NOT optimise it — its only job is to
    be unmistakably correct so the fast path can be checked."""
    seeds = seeds or {}
    ops = list(operators)
    all_applied: list[Applied] = []
    # Pre-seed with the graph's current facts so a re-run over an already
    # converged graph reports nothing new — the honest fixpoint contract.
    seen: set[tuple[str, ...]] = set()
    for e in world.all_edges():
        seen.add(("E", e.src, e.dst, e.kind.value))
    for n in world.all_nodes():
        seen.add(("N", n.id, ",".join(sorted(n.attrs))))
    # Each operator's statically-pinned focus kind (None => scan every node).
    narrowed = [_narrow_focus_kind(op) for op in ops]
    seq = seq_start
    for _ in range(max_rounds):
        round_new = 0
        # deterministic order: operator order, then node id order
        for op, kind in zip(ops, narrowed):
            seed = seeds.get(op.id)
            nodes = world.all_nodes() if kind is None else world.nodes_of_kind(kind)
            for node in nodes:
                changes = derive(op, world, node, seq, seed)
                if not changes:
                    continue
                for ch in changes:
                    sig = _signature(ch)
                    if sig in seen:
                        continue  # idempotent refine of a fact we already have
                    seen.add(sig)
                    all_applied.append(ch)
                    round_new += 1
                    seq += 1
        if round_new == 0:
            break
    return all_applied


def saturate(
    operators: Iterable[Operator],
    world: WorldModel,
    seq_start: int,
    *,
    seeds: Mapping[str, Mapping[str, str]] | None = None,
    max_rounds: int = 16,
) -> list[Applied]:
    """Run `operators` against the world to a fixpoint — the forward-chaining the
    planner uses to expand the reachable attack surface before querying for paths.

    `seeds` optionally maps an operator id to a role->node seed binding (for roles
    the preconditions cannot capture, e.g. an `actor` principal). The monotonic
    sequence int advances by one per asserted fact starting from `seq_start`, so
    every derived fact is uniquely and deterministically ordered. `max_rounds`
    bounds the loop; a well-formed catalog converges far sooner.

    WORKLIST / DELTA fixpoint (#828 M2.1). The full rescan (:func:`_saturate_full`,
    kept as the reference) re-``derive``s ``rounds x |ops| x |nodes|`` pairs, the
    bulk of which re-fail their preconditions every round and assert nothing. This
    rewrite instead re-``derive``s, after the first sweep, only the (operator, node)
    pairs whose match RESULT can have changed since it was last evaluated — those a
    graph mutation of the previous (or earlier-this-sweep) step could flip — plus the
    pairs that currently match (which MUST re-fire every sweep to reproduce the
    belief/`last_seen` accretion). It is **pure perf**: BYTE-IDENTICAL to
    :func:`_saturate_full` — same derived facts, same `seen` closure, same
    `first_seen`/`last_seen`, same Beta belief (`alpha`/`beta`), same provenance, and
    the same `all_applied` in the same order. ``test_operators`` diffs the two deeply
    over fixture and random graphs (+ the committed differential corpus and three
    minimal counterexamples); a synthetic case proves the derive-call count is
    strictly lower.

    SNAPSHOT SEMANTICS — the crux of byte-identity. :func:`_saturate_full` opens each
    operator's pass with ``nodes = world.all_nodes()`` / ``nodes_of_kind`` and iterates
    those captured OBJECTS. A SET_ATTR upsert REPLACES the stored object
    (``graph.add_node``), not the captured reference, so a focus visited later in the
    SAME pass is matched at its PRE-mutation attrs — the focus NODE_ATTR read is STALE
    within a pass. Every OTHER read in ``match`` goes through ``world`` live: the edges
    incident to the focus id (INCIDENT_EDGE) and the global nodes-of-a-kind and their
    attrs (GRAPH_HAS_NODE), as does ``apply``. The worklist reproduces this exactly:
    pairs pop in ``(operator-index, node-id)`` order, so each operator's pairs form one
    contiguous PASS; at a pass's first pop the worklist snapshots that operator's
    candidate objects (``seg_snap``) and matches the focus against that snapshot, while
    INCIDENT_EDGE / GRAPH_HAS_NODE / apply still read the live ``world``. (An earlier,
    rejected revision re-fetched the focus live via ``world.get_node`` and so saw an
    operator's own in-pass SET_ATTR — a verdict change, e.g. a lost derived edge and
    inflated Beta belief; this is the defect this function now fixes.)

    WHY IT STAYS SOUND (no under-saturation, no divergence). ``match`` reads only: the
    focus kind (never mutated) and attrs (NODE_ATTR, STALE per above); the edges
    incident to the focus and their far-node kinds (INCIDENT_EDGE, LIVE); and globally
    the nodes of a kind and their attrs (GRAPH_HAS_NODE, LIVE). ``apply`` writes only a
    new/re-fired edge (ASSERT_EDGE) and a node attr (SET_ATTR). So a mutation routes to
    its dependents by both WHAT it changes and WHICH read-kind consumes it:

      * NO precondition reads an edge's attrs/confidence/belief/seen, so an edge
        RE-FIRE (an existing (src,dst,kind) re-asserted) changes no match result and
        dirties nothing. A NEW edge changes the incident sets of its two endpoints, so
        it dirties every INCIDENT_EDGE operator whose focus candidate is one of them —
        a LIVE dependency.
      * A SET_ATTR changes a node's attrs (its value may change even when the sig —
        keyed on attr NAMES — does not). It flips the focus NODE_ATTR check wherever
        that node is the focus — a STALE dependency — and every attr-constrained
        GRAPH_HAS_NODE of that node's kind, for every focus of each reader — a LIVE
        dependency (a kind-only GRAPH_HAS_NODE is constant, so untracked).

    The dependency map is a sound OVER-approximation (it may re-derive a pair whose
    result did not change — a harmless no-op or identical re-fire), so it never MISSES
    a flip. A LIVE dependency dirtied not-yet-visited THIS sweep is pushed to fire this
    sweep (reproducing the full rescan's within-sweep chaining); one dirtying an
    already-passed pair defers to the next sweep. A STALE dependency is subtler: the
    acting operator cannot observe its own in-pass SET_ATTR through a focus NODE_ATTR
    (its pass snapshot predates the write) and an earlier operator's pass is finished,
    so only a LATER operator's pass — whose snapshot is captured after the write —
    fires it this sweep; the operator itself and earlier ones re-read it from next
    round's fresh snapshot. Skipped pairs are precisely those that would re-fail with
    no relevant mutation, so the surviving pairs see the IDENTICAL graph state and the
    IDENTICAL stale focus, in the identical order, at the identical seq — including the
    multi-hop / cyclic case where a round-k derivation depends on a node first touched
    in round k-2. Induction over sweeps gives byte-identity; ``round_new`` per sweep is
    therefore identical, so the loop stops on the same round."""
    seeds = seeds or {}
    ops = list(operators)
    all_applied: list[Applied] = []
    # Pre-seed with the graph's current facts so a re-run over an already converged
    # graph reports nothing new — the honest fixpoint contract (same as the full rescan).
    seen: set[tuple[str, ...]] = set()
    for e in world.all_edges():
        seen.add(("E", e.src, e.dst, e.kind.value))
    for n in world.all_nodes():
        seen.add(("N", n.id, ",".join(sorted(n.attrs))))

    # saturate never adds/removes a node and never changes a kind (effects only
    # ASSERT_EDGE between existing nodes or SET_ATTR on one), so the candidate node
    # set, its id-sorted order, and each node's kind are STABLE for the whole run.
    narrowed = [_narrow_focus_kind(op) for op in ops]
    all_nodes = world.all_nodes()                       # id-sorted, stable
    kind_of: dict[str, NodeKind] = {n.id: n.kind for n in all_nodes}
    all_ids = [n.id for n in all_nodes]
    cand_ids: list[list[str]] = [
        all_ids if narrowed[oi] is None else [n.id for n in world.nodes_of_kind(narrowed[oi])]
        for oi in range(len(ops))
    ]

    # --- dependency indexes: which operators' match result a mutation can flip -----
    # A precondition reads one of two input KINDS, and the two age DIFFERENTLY inside
    # _saturate_full's per-operator-pass snapshot, so a mutation must route to them
    # differently to stay byte-identical:
    #   * LIVE reads — INCIDENT_EDGE (world.neighbors on the focus id) and GRAPH_HAS_NODE
    #     (world.nodes_of_kind, read globally). _saturate_full evaluates these against the
    #     world AS IT IS at the derive call, so they observe every mutation made so far this
    #     sweep, the acting operator's own earlier-in-pass ones included.
    #   * STALE reads — NODE_ATTR on the FOCUS. _saturate_full reads the focus node OBJECT
    #     captured once, when the operator's pass began (``nodes = world.all_nodes()`` /
    #     ``nodes_of_kind`` above). A SET_ATTR upsert REPLACES the stored object
    #     (graph.add_node), leaving the captured one untouched, so a focus visited LATER in
    #     the SAME pass is read at its PRE-mutation attrs. An operator therefore never sees
    #     its own in-pass SET_ATTR through a focus NODE_ATTR; only the NEXT round's pass
    #     (fresh snapshot) does — and a LATER operator's pass THIS round does, because its
    #     snapshot is captured after this mutation.
    incident_ops = [oi for oi, op in enumerate(ops)
                    if any(p.kind is PredicateKind.INCIDENT_EDGE for p in op.preconditions)]
    node_attr_ops = [oi for oi, op in enumerate(ops)
                     if any(p.kind is PredicateKind.NODE_ATTR for p in op.preconditions)]
    # GRAPH_HAS_NODE is global; only an ATTR-constrained one is non-constant (the node
    # set of a kind never changes). Watched NodeKind -> operators reading it globally.
    graph_attr_ops: dict[NodeKind, list[int]] = {}
    for oi, op in enumerate(ops):
        for p in op.preconditions:
            if (p.kind is PredicateKind.GRAPH_HAS_NODE and p.attr is not None
                    and p.node_kind is not None):
                graph_attr_ops.setdefault(p.node_kind, []).append(oi)

    def _is_cand(oi: int, nid: str) -> bool:
        k = narrowed[oi]
        return k is None or kind_of.get(nid) is k

    def _incident_deps(src: str, dst: str) -> list[tuple[int, str]]:
        # LIVE: a NEW edge changes the incident set of BOTH endpoints.
        out: list[tuple[int, str]] = []
        for oi in incident_ops:
            if _is_cand(oi, src):
                out.append((oi, src))
            if _is_cand(oi, dst):
                out.append((oi, dst))
        return out

    def _node_attr_self_deps(nid: str) -> list[tuple[int, str]]:
        # STALE: a SET_ATTR on `nid` flips a NODE_ATTR check only where `nid` is the FOCUS.
        return [(oi, nid) for oi in node_attr_ops if _is_cand(oi, nid)]

    def _graph_attr_deps(nid: str) -> list[tuple[int, str]]:
        # LIVE: a SET_ATTR on `nid` flips an attr-constrained GRAPH_HAS_NODE of nid's kind
        # for EVERY focus of each operator reading it (the predicate is global, not per-focus).
        out: list[tuple[int, str]] = []
        for oi in graph_attr_ops.get(kind_of.get(nid), ()):  # type: ignore[arg-type]
            out.extend((oi, c) for c in cand_ids[oi])
        return out

    seq = seq_start
    live: set[tuple[int, str]] = set()
    # First sweep: evaluate every candidate pair, exactly as the full rescan's round 0.
    carry: set[tuple[int, str]] = {(oi, nid) for oi in range(len(ops)) for nid in cand_ids[oi]}

    for _ in range(max_rounds):
        round_new = 0
        heap: list[tuple[int, str]] = list(carry | live)
        heapq.heapify(heap)
        processed: set[tuple[int, str]] = set()
        carry = set()                                   # pairs dirtied FOR THE NEXT sweep
        # Pairs pop in (operator-index, node-id) order, so all of operator `oi`'s pairs form
        # one contiguous segment — its PASS. At the segment's first pop, every earlier
        # operator's pass this sweep is finished and `oi`'s own is not yet begun, so a
        # snapshot of `oi`'s candidate OBJECTS taken here is byte-for-byte _saturate_full's
        # captured-once ``nodes`` list for this pass: later-in-pass SET_ATTRs replace the
        # stored object, never this captured reference, giving the identical STALE focus
        # reads. INCIDENT_EDGE / GRAPH_HAS_NODE still read `world` (live) inside derive.
        seg_oi = -1
        seg_snap: dict[str, Node] = {}
        while heap:
            key = heapq.heappop(heap)
            if key in processed:
                continue                                # a pair is evaluated at most once per sweep
            processed.add(key)
            oi, nid = key
            if oi != seg_oi:                            # first pop of operator oi's pass
                seg_oi = oi
                seg_snap = {c: world.get_node(c) for c in cand_ids[oi]}
            op = ops[oi]
            node = seg_snap.get(nid)                    # pass-start object -> stale focus attrs
            if node is None:                            # pragma: no cover - no node removal
                live.discard(key)
                continue
            changes = derive(op, world, node, seq, seeds.get(op.id))
            if not changes:
                live.discard(key)                       # no longer matches -> stop re-firing it
                continue
            live.add(key)
            for ch in changes:
                sig = _signature(ch)
                is_new = sig not in seen
                # Route this mutation's dependents. A NEW edge flips INCIDENT_EDGE readers of
                # its endpoints (LIVE). Any SET_ATTR (new key OR value overwrite) flips the
                # focus NODE_ATTR readers of that node (STALE) and the attr-GRAPH_HAS_NODE
                # readers of its kind (LIVE). An edge RE-FIRE flips nothing (no precondition
                # reads edge metadata).
                live_deps: Iterable[tuple[int, str]]
                stale_deps: Iterable[tuple[int, str]]
                if ch.edge is not None:
                    live_deps = _incident_deps(ch.edge.src, ch.edge.dst) if is_new else ()
                    stale_deps = ()
                else:
                    cid = ch.node.id                    # type: ignore[union-attr]
                    stale_deps = _node_attr_self_deps(cid)
                    live_deps = _graph_attr_deps(cid)
                for dep in live_deps:
                    if dep > key:
                        heapq.heappush(heap, dep)       # not-yet-visited this sweep -> fire this sweep
                    else:
                        carry.add(dep)                  # already visited -> next sweep
                for dep in stale_deps:
                    # Stale focus read: operator oi cannot see its OWN in-pass SET_ATTR, and an
                    # earlier operator's pass is already finished. Only a LATER operator's pass
                    # (snapshot captured after this mutation) sees it this sweep; the operator
                    # itself and earlier ones re-read it from next round's fresh snapshot.
                    if dep[0] > oi:
                        heapq.heappush(heap, dep)
                    else:
                        carry.add(dep)
                if not is_new:
                    continue                            # idempotent refine of a fact we already have
                seen.add(sig)
                all_applied.append(ch)
                round_new += 1
                seq += 1
        if round_new == 0:
            break
    return all_applied


def _signature(applied: Applied) -> tuple[str, ...]:
    """A stable identity for an asserted fact, so saturate counts each new
    edge/attr once and stops when a round refines only known facts."""
    if applied.edge is not None:
        e = applied.edge
        return ("E", e.src, e.dst, e.kind.value)
    assert applied.node is not None
    n = applied.node
    return ("N", n.id, ",".join(sorted(n.attrs)))


def applicable_operators(
    world: WorldModel,
    operators: Iterable[Operator],
    *,
    seeds: Mapping[str, Mapping[str, str]] | None = None,
    focus_kinds: Iterable[NodeKind] | None = None,
) -> list[Operator]:
    """The operators whose preconditions are satisfied by the current world
    state — the "what can I do from here?" query the planner asks before it
    commits to a move.

    This is READ-ONLY: it evaluates preconditions and asserts nothing, so the
    world is unchanged (unlike ``derive`` / ``saturate``). An operator is
    included iff it :func:`match`es over at least one focus node — optionally
    restricted to ``focus_kinds`` to scope the scan (e.g. only ENDPOINTs).
    ``seeds`` is forwarded to ``match`` for operators whose preconditions
    reference a caller-supplied role.

    Deterministic: operators are returned in the given order, each tested
    against the graph's sorted node order, so the same world always yields the
    same applicable set — which is what makes a plan reproducible."""
    seeds = seeds or {}
    focus_set = set(focus_kinds) if focus_kinds is not None else None
    result: list[Operator] = []
    nodes = world.all_nodes()  # sorted -> deterministic
    for op in operators:
        seed = seeds.get(op.id)
        for node in nodes:
            if focus_set is not None and node.kind not in focus_set:
                continue
            if match(op, world, node, seed) is not None:
                result.append(op)
                break
    return result
