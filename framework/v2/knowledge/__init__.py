"""
knowledge — the Technique Knowledge Graph: TTPs as planning operators.

This layer is the *join* that turns intel into action. ATT&CK / CAPEC / CWE
describe techniques in prose a human reads; the path engine needs techniques it
can *check* and *chain*. `knowledge` reifies each technique as a STRIPS-style
`Operator` whose preconditions and effects are typed conditions over the
`worldmodel` attack-graph — so a technique plugs straight into world-model
derivation: its preconditions are matched against the graph, and if they hold
its effects assert new edges/attrs carrying `provenance="operator:<id>"`. A new
edge unlocks a new path; a chain of operators is a chain of moves.

Public surface (import from here, not from submodules):

    from framework.v2.knowledge import (
        # models
        Operator, Predicate, Effect,
        PredicateKind, EffectKind, AttrOp, Direction,
        # evaluation / assertion
        applicable, match, apply, derive, saturate, Binding, OperatorError,
        # catalog
        CATALOG, by_id, by_technique,
    )

Design notes:
- The predicate/effect vocabulary is the world-model's own (`NodeKind`,
  `EdgeKind`, node attrs). No translation layer — an operator *is* an
  interaction rule with a technique label and detection metadata.
- Deterministic: evaluation reads the graph, assertion takes a caller-supplied
  monotonic sequence int (never a clock). Same inputs, same derived facts.
- Abstract, not armed: operators state what becomes possible and how a defender
  would see it (`detection_signals`, `oracle_kind` -> `verify.OracleKind`).
  There are no payloads here.
"""

from __future__ import annotations

from .catalog import CATALOG, by_id, by_technique
from .models import (
    AttrOp,
    Direction,
    Effect,
    EffectKind,
    Operator,
    Predicate,
    PredicateKind,
)
from .operators import (
    Applied,
    Binding,
    OperatorError,
    applicable,
    apply,
    derive,
    match,
    saturate,
)

__all__ = [
    # models
    "Operator",
    "Predicate",
    "Effect",
    "PredicateKind",
    "EffectKind",
    "AttrOp",
    "Direction",
    # evaluation / assertion
    "applicable",
    "match",
    "apply",
    "derive",
    "saturate",
    "Applied",
    "Binding",
    "OperatorError",
    # catalog
    "CATALOG",
    "by_id",
    "by_technique",
]
