"""
knowledge.models — techniques as machine-checkable planning operators.

An operator is the join between *intel* (a technique: ATT&CK / CAPEC / CWE)
and *action* (a move the path engine can chain). Intel frameworks give an
operator loose prose — "adversary abuses a valid account" — which a machine
cannot check against a graph. This module turns that prose into a STRIPS-style
operator with:

  - **preconditions** — typed `Predicate`s over the world-model. Each is a
    condition the current attack-graph must satisfy for the technique to be
    applicable *here*. The vocabulary is deliberately the world-model's own
    (`NodeKind` / `EdgeKind` / node attrs), so an operator plugs straight into
    `worldmodel` derivation with no translation layer.
  - **effects** — typed `Effect`s that assert the capability the technique
    grants: a new edge (a boundary crossed / node made reachable) or a new
    attr (a fact learned). Effects carry `provenance="operator:<id>"` when
    applied, so every derived edge traces back to the technique that produced
    it — the same auditability the rest of the world-model demands.
  - **detection_signals** — the observable tells a defender/oracle would see,
    and an optional `oracle_kind` linking the operator to the deterministic
    verifier that would *confirm* it fired (`verify.OracleKind`). Knowledge
    proposes; the oracle layer disposes.

Nothing here evaluates a graph or asserts anything — these are pure, validated
data shapes. The evaluation/assertion logic lives in operators.py; the
hand-authored operator set lives in catalog.py.

No payloads live here. An `Operator` is an abstract planning move plus
detection metadata — it says *what becomes possible and how you'd know*,
never *how to weaponise it*.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..verify.models import OracleKind
from ..worldmodel.models import EdgeKind, NodeKind


# ---------------------------------------------------------------------------
# Predicate vocabulary — conditions over the world-model
# ---------------------------------------------------------------------------


class AttrOp(str, enum.Enum):
    """How a node-attr predicate compares the observed value.

    FALSY / TRUTHY treat a *missing* attr as falsy — an endpoint with no
    `auth` key is as unauthenticated as one with `auth=false`, which is the
    honest reading of an observation the recon layer never populated."""

    EQ = "eq"          # attr present and == value
    NE = "ne"          # attr present and != value
    EXISTS = "exists"  # attr key present (any value)
    ABSENT = "absent"  # attr key not present
    IN = "in"          # attr present and value in the (list) `value`
    TRUTHY = "truthy"  # attr present and truthy
    FALSY = "falsy"    # attr missing or falsy


class Direction(str, enum.Enum):
    """Which way an incident-edge predicate looks from the focus node."""

    OUT = "out"        # edge focus -> other
    IN = "in"          # edge other -> focus
    EITHER = "either"  # either orientation


class PredicateKind(str, enum.Enum):
    """The four shapes a precondition can take. Every shape is decidable
    against the world-model in bounded time — no free-text, no code."""

    NODE_KIND = "node_kind"          # focus node is of `node_kind`
    NODE_ATTR = "node_attr"          # focus node's `attr` satisfies `op`/`value`
    INCIDENT_EDGE = "incident_edge"  # focus has an edge (`direction`,`edge_kind`)
    #                                  to a node of `other_kind`
    GRAPH_HAS_NODE = "graph_has_node"  # some node of `node_kind` exists (global)


class Predicate(BaseModel):
    """One typed, machine-checkable condition over the world-model.

    A predicate is evaluated against a *focus* node (the candidate the
    operator is being tried on) plus the whole graph. `capture_as`, when set
    on an INCIDENT_EDGE or GRAPH_HAS_NODE predicate, binds the far / matched
    node id to a role name so an effect can reference it — this is how a
    precondition ("a CREDENTIAL VALID_ON this PRINCIPAL") feeds the endpoint
    of an effect edge."""

    model_config = ConfigDict(extra="forbid")

    kind: PredicateKind
    # NODE_KIND / GRAPH_HAS_NODE
    node_kind: NodeKind | None = None
    # NODE_ATTR (and optional attr constraint on GRAPH_HAS_NODE)
    attr: str | None = None
    op: AttrOp = AttrOp.EQ
    value: object | None = None
    # INCIDENT_EDGE
    edge_kind: EdgeKind | None = None
    direction: Direction = Direction.OUT
    other_kind: NodeKind | None = None
    # capture the far (INCIDENT_EDGE) / matched (GRAPH_HAS_NODE) node id
    capture_as: str | None = None
    note: str = Field(default="", description="Human note on why this gates the technique.")

    @model_validator(mode="after")
    def _check_shape(self) -> "Predicate":
        k = self.kind
        if k is PredicateKind.NODE_KIND and self.node_kind is None:
            raise ValueError("NODE_KIND predicate requires node_kind")
        if k is PredicateKind.NODE_ATTR and not self.attr:
            raise ValueError("NODE_ATTR predicate requires attr")
        if k is PredicateKind.INCIDENT_EDGE and self.edge_kind is None:
            raise ValueError("INCIDENT_EDGE predicate requires edge_kind")
        if k is PredicateKind.GRAPH_HAS_NODE and self.node_kind is None:
            raise ValueError("GRAPH_HAS_NODE predicate requires node_kind")
        if self.op is AttrOp.IN and not isinstance(self.value, (list, tuple)):
            raise ValueError("AttrOp.IN requires `value` to be a list/tuple")
        return self


# ---------------------------------------------------------------------------
# Effect vocabulary — what the technique asserts on success
# ---------------------------------------------------------------------------


class EffectKind(str, enum.Enum):
    ASSERT_EDGE = "assert_edge"  # a capability gained / boundary crossed
    SET_ATTR = "set_attr"        # a fact learned about a node


class Effect(BaseModel):
    """One assertion an operator makes when it fires.

    Effect endpoints/targets are named by *role*, not node id — `apply`
    resolves roles against a binding (the focus node plus whatever the
    preconditions captured plus any caller-seeded roles). The conventional
    role for the candidate node is `"focus"`. An ASSERT_EDGE effect names
    `src_role` and `dst_role`; a SET_ATTR effect names `target_role`
    (default `"focus"`), `attr`, and `value`."""

    model_config = ConfigDict(extra="forbid")

    kind: EffectKind
    # ASSERT_EDGE
    edge_kind: EdgeKind | None = None
    src_role: str | None = None
    dst_role: str | None = None
    edge_attrs: dict[str, object] = Field(default_factory=dict)
    # SET_ATTR
    target_role: str = "focus"
    attr: str | None = None
    value: object | None = None
    # shared
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    note: str = Field(default="", description="What capability this represents.")

    @model_validator(mode="after")
    def _check_shape(self) -> "Effect":
        if self.kind is EffectKind.ASSERT_EDGE:
            if self.edge_kind is None:
                raise ValueError("ASSERT_EDGE effect requires edge_kind")
            if not self.src_role or not self.dst_role:
                raise ValueError("ASSERT_EDGE effect requires src_role and dst_role")
        if self.kind is EffectKind.SET_ATTR and not self.attr:
            raise ValueError("SET_ATTR effect requires attr")
        return self


# ---------------------------------------------------------------------------
# Operator — a technique as a planning move
# ---------------------------------------------------------------------------


class Operator(BaseModel):
    """A technique reified as a STRIPS-style planning operator.

    `technique_ref` is the intel provenance — the ATT&CK / CAPEC / CWE ids
    this operator abstracts (strings, e.g. ["T1078", "CWE-522"]). The
    preconditions gate applicability against the world-model; the effects
    assert the capability gained. `detection_signals` and `oracle_kind`
    describe how the move is *observed* and *confirmed* — the bridge into the
    verify layer.

    An operator is abstract on purpose: it is a move in a plan, not an
    exploit. It states what must be true, what becomes true, and how a
    defender would see it — nothing about how to build a payload."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, description="Stable operator id (kebab-case).")
    name: str = Field(min_length=1)
    technique_ref: list[str] = Field(
        min_length=1,
        description="ATT&CK / CAPEC / CWE ids this operator abstracts (strings).",
    )
    tactic: str | None = Field(
        default=None,
        description="Optional ATT&CK tactic label, for planner grouping.",
    )
    description: str = ""
    preconditions: list[Predicate] = Field(min_length=1)
    effects: list[Effect] = Field(min_length=1)
    detection_signals: list[str] = Field(default_factory=list)
    oracle_kind: OracleKind | None = Field(
        default=None,
        description="The deterministic oracle (verify.OracleKind) that would "
        "confirm this technique actually fired.",
    )

    @property
    def effect_roles(self) -> set[str]:
        """Every binding role the effects reference — the roles `apply` must
        be able to resolve (focus is always available)."""
        roles: set[str] = set()
        for e in self.effects:
            if e.kind is EffectKind.ASSERT_EDGE:
                if e.src_role:
                    roles.add(e.src_role)
                if e.dst_role:
                    roles.add(e.dst_role)
            else:
                roles.add(e.target_role)
        return roles

    @property
    def captured_roles(self) -> set[str]:
        """Roles the preconditions capture — available to effects for free."""
        return {p.capture_as for p in self.preconditions if p.capture_as}
