"""Tests for knowledge.models — predicate/effect/operator validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ...verify.models import OracleKind
from ...worldmodel.models import EdgeKind, NodeKind
from ..models import (
    AttrOp,
    Direction,
    Effect,
    EffectKind,
    Operator,
    Predicate,
    PredicateKind,
)


def test_predicate_node_kind_requires_node_kind() -> None:
    with pytest.raises(ValidationError):
        Predicate(kind=PredicateKind.NODE_KIND)


def test_predicate_node_attr_requires_attr() -> None:
    with pytest.raises(ValidationError):
        Predicate(kind=PredicateKind.NODE_ATTR)


def test_predicate_incident_edge_requires_edge_kind() -> None:
    with pytest.raises(ValidationError):
        Predicate(kind=PredicateKind.INCIDENT_EDGE, other_kind=NodeKind.DATASTORE)


def test_predicate_in_op_requires_list_value() -> None:
    with pytest.raises(ValidationError):
        Predicate(kind=PredicateKind.NODE_ATTR, attr="x", op=AttrOp.IN, value="scalar")
    # list value is fine
    Predicate(kind=PredicateKind.NODE_ATTR, attr="x", op=AttrOp.IN, value=["a", "b"])


def test_effect_assert_edge_requires_endpoints() -> None:
    with pytest.raises(ValidationError):
        Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
               src_role="focus")  # missing dst_role
    with pytest.raises(ValidationError):
        Effect(kind=EffectKind.ASSERT_EDGE, src_role="focus", dst_role="db")  # no kind


def test_effect_set_attr_requires_attr() -> None:
    with pytest.raises(ValidationError):
        Effect(kind=EffectKind.SET_ATTR, value=True)


def test_operator_extra_forbidden() -> None:
    with pytest.raises(ValidationError):
        Operator(
            id="x", name="x", technique_ref=["T1"],
            preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.HOST)],
            effects=[Effect(kind=EffectKind.SET_ATTR, attr="a", value=1)],
            bogus="nope",
        )


def test_operator_roles_introspection() -> None:
    op = Operator(
        id="x", name="x", technique_ref=["T1"], oracle_kind=OracleKind.ACHIEVED_STATE,
        preconditions=[
            Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.CREDENTIAL),
            Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.VALID_ON,
                      direction=Direction.OUT, other_kind=NodeKind.PRINCIPAL,
                      capture_as="principal"),
        ],
        effects=[
            Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.CAN_ASSUME,
                   src_role="actor", dst_role="principal"),
        ],
    )
    assert op.captured_roles == {"principal"}
    assert op.effect_roles == {"actor", "principal"}
