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

from collections.abc import Iterable, Mapping

from ..common.errors import CrucibleError
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, Node
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


def saturate(
    operators: Iterable[Operator],
    world: WorldModel,
    seq_start: int,
    *,
    seeds: Mapping[str, Mapping[str, str]] | None = None,
    max_rounds: int = 16,
) -> list[Applied]:
    """Run `operators` against every node to a fixpoint: repeatedly derive
    until a full round asserts nothing new. This is the forward-chaining the
    planner uses to expand the reachable attack surface before querying for
    paths.

    `seeds` optionally maps an operator id to a role->node seed binding (for
    roles the preconditions cannot capture, e.g. an `actor` principal). The
    monotonic sequence int advances by one per asserted fact starting from
    `seq_start`, so every derived fact is uniquely and deterministically
    ordered. `max_rounds` bounds the loop; a well-formed catalog converges
    far sooner (effects are monotonic — the graph only accretes)."""
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
    seq = seq_start
    for _ in range(max_rounds):
        round_new = 0
        # deterministic order: operator order, then node id order
        for op in ops:
            seed = seeds.get(op.id)
            for node in world.all_nodes():
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


def _signature(applied: Applied) -> tuple[str, ...]:
    """A stable identity for an asserted fact, so saturate counts each new
    edge/attr once and stops when a round refines only known facts."""
    if applied.edge is not None:
        e = applied.edge
        return ("E", e.src, e.dst, e.kind.value)
    assert applied.node is not None
    n = applied.node
    return ("N", n.id, ",".join(sorted(n.attrs)))
