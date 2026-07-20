"""
worldmodel.derivation — monotonic forward-chaining over the attack-graph.

Recon and intake write *observed* facts into the world-model. But most
of an attacker's reasoning is *inferred*: "this credential is valid on
that principal, and that principal is reachable from my foothold, so I
can assume it." Those inferences are edges too — they just aren't
observed, they're *derived*. This module derives them, deterministically,
to a fixpoint, so the path-search layer plans over the full transitive
consequence of what we know rather than only the raw observations.

The engine is a tiny Datalog-style forward chainer:

  * An :class:`InteractionRule` is a set of premise edge-patterns over
    *variables* plus one conclusion pattern. A premise matches an
    existing edge of its kind; shared variables force a join (the same
    variable in two premises must bind the same node). Optional
    per-variable :class:`NodeConstraint`s gate on node *kind* / *attrs*.

  * :func:`derive` evaluates every rule against the current graph, asserts
    each conclusion as a new edge with ``provenance='derived:<rule>'`` and
    ``confidence = product of the matched premises' confidence``, then
    repeats until no edge is added or strengthened (a fixpoint), bounded
    by ``max_iters``.

Three properties make this safe to run unattended:

  * **Monotone.** Derivation only *adds* edges and only ever *raises* a
    derived edge's confidence (via the graph's max-reconcile upsert). It
    never removes a fact and never touches an *observed* edge — the
    observation's provenance is preserved.

  * **Terminating.** The set of derivable edge keys is finite and a
    derived confidence is a product of factors each ``<= 1``, so it can
    never exceed the factors it is built from: the max-product fixpoint
    is reached in finitely many rounds. ``max_iters`` is a hard cap on
    top of that guarantee.

  * **Deterministic.** Premises are matched over the graph's sorted edge
    order and derived edges are stamped with a caller-supplied sequence
    int (``seq``), never a wallclock — same inputs, same bytes.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .graph import WorldModel
from .models import Edge, EdgeKind, NodeKind

_EPS = 1e-12


# ---------------------------------------------------------------------------
# Rule schema
# ---------------------------------------------------------------------------


class EdgePattern(BaseModel):
    """One premise (or the conclusion) of a rule. ``src`` and ``dst`` are
    *variable names*, not node ids — the same name appearing twice forces
    those positions to bind the same node (a join)."""

    model_config = ConfigDict(extra="forbid")

    src: str = Field(min_length=1, description="Variable name for the source node.")
    dst: str = Field(min_length=1, description="Variable name for the destination node.")
    kind: EdgeKind


class NodeConstraint(BaseModel):
    """An optional gate on the node a variable binds to: it must be of
    ``kind`` (when set) and every entry in ``attrs`` must match the node's
    attribute exactly. Lets a rule say 'this variable is a CREDENTIAL' or
    'this host has attrs.internet_facing == True'."""

    model_config = ConfigDict(extra="forbid")

    kind: NodeKind | None = None
    attrs: dict[str, object] = Field(default_factory=dict)


class InteractionRule(BaseModel):
    """A monotone inference: if every ``premise`` matches (jointly, honouring
    shared variables and ``where`` constraints), assert ``conclusion``.

    Every variable used in the conclusion must be bound by some premise —
    a rule may not invent a node out of nothing. ``allow_self_loop``
    (default False) suppresses conclusions whose src and dst bind the same
    node, which keeps transitive rules from cluttering the graph with
    reflexive edges."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, description="Stable rule name; used in provenance.")
    premises: list[EdgePattern] = Field(min_length=1)
    conclusion: EdgePattern
    where: dict[str, NodeConstraint] = Field(default_factory=dict)
    allow_self_loop: bool = False

    @model_validator(mode="after")
    def _check_bound(self) -> "InteractionRule":
        bound = {p.src for p in self.premises} | {p.dst for p in self.premises}
        for var in (self.conclusion.src, self.conclusion.dst):
            if var not in bound:
                raise ValueError(
                    f"rule {self.name!r}: conclusion variable {var!r} is not "
                    f"bound by any premise"
                )
        unknown = set(self.where) - bound
        if unknown:
            raise ValueError(
                f"rule {self.name!r}: where-constraint on unbound variable(s) "
                f"{sorted(unknown)!r}"
            )
        return self


class DerivationResult(BaseModel):
    """Outcome of a :func:`derive` run: the derived edges (final, merged
    form, in deterministic key order) and the number of fixpoint rounds
    performed. ``iterations`` includes the final round that made no
    change (the one that proves the fixpoint), so a run that derives
    nothing reports ``iterations == 1``."""

    model_config = ConfigDict(extra="forbid")

    derived: list[Edge]
    iterations: int = Field(ge=0)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _bind(binding: dict[str, str], var: str, node_id: str) -> bool:
    """Bind ``var`` to ``node_id``; if already bound, require equality."""
    cur = binding.get(var)
    if cur is None:
        binding[var] = node_id
        return True
    return cur == node_id


def _satisfies(
    world: WorldModel, binding: dict[str, str], var: str, where: dict[str, NodeConstraint]
) -> bool:
    """Check the (optional) node constraint for a freshly bound variable."""
    constraint = where.get(var)
    if constraint is None:
        return True
    node = world.get_node(binding[var])
    if node is None:  # pragma: no cover - edges guarantee endpoints exist
        return False
    if constraint.kind is not None and node.kind != constraint.kind:
        return False
    for key, expected in constraint.attrs.items():
        if node.attrs.get(key) != expected:
            return False
    return True


def _match(world: WorldModel, rule: InteractionRule) -> list[tuple[dict[str, str], list[Edge]]]:
    """All satisfying assignments of ``rule``'s premises over the current
    graph. Returns ``(binding, matched_edges)`` pairs in deterministic
    order (premises joined over the graph's sorted edge order)."""
    results: list[tuple[dict[str, str], list[Edge]]] = []
    premises = rule.premises

    def recurse(i: int, binding: dict[str, str], matched: list[Edge]) -> None:
        if i == len(premises):
            results.append((dict(binding), list(matched)))
            return
        pat = premises[i]
        for edge in world.edges_of_kind(pat.kind):  # sorted -> deterministic
            trial = dict(binding)
            if not _bind(trial, pat.src, edge.src):
                continue
            if not _bind(trial, pat.dst, edge.dst):
                continue
            if not _satisfies(world, trial, pat.src, rule.where):
                continue
            if not _satisfies(world, trial, pat.dst, rule.where):
                continue
            matched.append(edge)
            recurse(i + 1, trial, matched)
            matched.pop()

    recurse(0, {}, [])
    return results


# ---------------------------------------------------------------------------
# Fixpoint
# ---------------------------------------------------------------------------


def derive(
    world: WorldModel,
    rules: list[InteractionRule],
    seq: int,
    max_iters: int = 16,
) -> DerivationResult:
    """Forward-chain ``rules`` over ``world`` to a fixpoint, mutating the
    graph in place. Each derived edge carries ``provenance='derived:<rule>'``,
    ``confidence`` = the product of its supporting premises' confidence, and
    ``first_seen == last_seen == seq`` (the caller's monotonic sequence int).

    Semantics that make repeated runs safe:

      * an *observed* edge (any edge not asserted by this engine) is never
        overwritten — a derivation that would duplicate it is dropped;
      * a *derived* edge is asserted once and only re-asserted to *raise*
        its confidence (max-product), never to lower it;
      * ``allow_self_loop=False`` rules skip reflexive conclusions.

    Terminates when a full round adds and strengthens nothing, or after
    ``max_iters`` rounds — whichever comes first. Returns the derived
    edges and the round count."""
    if max_iters < 1:
        raise ValueError("max_iters must be >= 1")
    if seq < 0:
        raise ValueError("seq must be >= 0")

    derived_keys: set[tuple[str, str, str]] = set()
    iterations = 0

    for _ in range(max_iters):
        iterations += 1
        changed = False

        # Evaluate every rule against the current snapshot, collect
        # proposals, then assert — a clean naive round, order-stable.
        proposals: list[tuple[str, str, EdgeKind, float, str]] = []
        for rule in rules:
            for binding, matched in _match(world, rule):
                src = binding[rule.conclusion.src]
                dst = binding[rule.conclusion.dst]
                if src == dst and not rule.allow_self_loop:
                    continue
                confidence = 1.0
                for edge in matched:
                    confidence *= edge.confidence
                proposals.append((src, dst, rule.conclusion.kind, confidence, rule.name))

        for src, dst, kind, confidence, rule_name in proposals:
            key = (src, dst, kind.value)
            existing = world.get_edge(src, dst, kind)
            if existing is None:
                new = True
            elif key in derived_keys and confidence > existing.confidence + _EPS:
                new = True  # strengthen a previously-derived edge
            else:
                new = False  # observed edge, or no confidence gain
            if not new:
                continue
            world.add_edge(
                Edge(
                    src=src,
                    dst=dst,
                    kind=kind,
                    attrs={"rule": rule_name},
                    provenance=f"derived:{rule_name}",
                    confidence=confidence,
                    first_seen=seq,
                    last_seen=seq,
                )
            )
            derived_keys.add(key)
            changed = True

        if not changed:
            break

    derived = [
        world.get_edge(src, dst, EdgeKind(kv))  # type: ignore[misc]
        for (src, dst, kv) in sorted(derived_keys)
    ]
    return DerivationResult(derived=[e for e in derived if e is not None], iterations=iterations)


# ---------------------------------------------------------------------------
# Example rules
# ---------------------------------------------------------------------------


TRANSITIVE_REACHABILITY = InteractionRule(
    name="transitive_reachability",
    premises=[
        EdgePattern(src="X", dst="Y", kind=EdgeKind.REACHABLE_FROM),
        EdgePattern(src="Y", dst="Z", kind=EdgeKind.REACHABLE_FROM),
    ],
    conclusion=EdgePattern(src="X", dst="Z", kind=EdgeKind.REACHABLE_FROM),
)
"""If Y is reachable from X and Z is reachable from Y, then Z is reachable
from X. The transitive closure of network/call reach; self-loops suppressed."""


ASSUME_VIA_VALID_CREDENTIAL = InteractionRule(
    name="assume_via_valid_credential",
    premises=[
        EdgePattern(src="H", dst="P", kind=EdgeKind.REACHABLE_FROM),
        EdgePattern(src="C", dst="P", kind=EdgeKind.VALID_ON),
    ],
    conclusion=EdgePattern(src="H", dst="P", kind=EdgeKind.CAN_ASSUME),
    where={
        "P": NodeConstraint(kind=NodeKind.PRINCIPAL),
        "C": NodeConstraint(kind=NodeKind.CREDENTIAL),
    },
)
"""If a principal P is reachable from foothold H and some credential C is
valid on P, then from H one can assume P. Confidence is the product of the
reachability edge and the credential-validity edge — the path is only as
strong as its weaker half."""


DEFAULT_RULES: list[InteractionRule] = [
    TRANSITIVE_REACHABILITY,
    ASSUME_VIA_VALID_CREDENTIAL,
]
"""A ready-to-use starter set. Callers extend or replace this with rules
tuned to the engagement (cloud role-chaining, group membership, etc.)."""
