"""Tests for analysis.smt — bounded constraint / path-condition feasibility (WS-G).

The DEFAULT path is an exact, deterministic pure-Python bounded search (no z3).
z3 only extends reach to domains too large to enumerate. Verdicts agree across
backends; witnesses are deterministic on the enum path.
"""

from __future__ import annotations

import pytest

from framework.v2.analysis import smt
from framework.v2.common import capabilities as cap


# --------------------------------------------------------------------------
# Default (pure-Python bounded enumeration) — always available, deterministic
# --------------------------------------------------------------------------


def test_feasible_single_param_witness_is_deterministic() -> None:
    r = smt.is_feasible({"id": (0, 100)}, [smt.linear({"id": 1}, "==", 42)])
    assert r.is_feasible and r.model == {"id": 42}
    assert r.backend == "bounded-enum" and r.exhaustive


def test_infeasible_is_exhaustive() -> None:
    r = smt.is_feasible(
        {"id": (0, 10)},
        [smt.linear({"id": 1}, ">", 5), smt.linear({"id": 1}, "<", 3)],
    )
    assert r.is_infeasible and r.exhaustive


def test_param_region_reachability_example() -> None:
    # validation allows 0..100; a business rule triggers only at victim_id.
    victim_in = smt.is_feasible(
        {"id": (0, 100)}, [smt.linear({"id": 1}, "==", 77)]
    )
    victim_out = smt.is_feasible(
        {"id": (0, 100)}, [smt.linear({"id": 1}, "==", 500)]
    )
    assert victim_in.is_feasible
    assert victim_out.is_infeasible  # provably unreachable in the validated region


def test_multivar_linear() -> None:
    # 2a + b == 10, with a in 0..5, b in 0..5  → e.g. a=... deterministic first hit
    r = smt.is_feasible(
        {"a": (0, 5), "b": (0, 5)},
        [smt.linear({"a": 2, "b": 1}, "==", 10)],
    )
    assert r.is_feasible
    a, b = r.model["a"], r.model["b"]
    assert 2 * a + b == 10
    # deterministic witness: sorted vars, ascending values → smallest a first
    assert (a, b) == (3, 4)


def test_witness_satisfies_all_constraints() -> None:
    r = smt.is_feasible(
        {"x": (0, 20), "y": (0, 20)},
        [
            smt.linear({"x": 1}, ">=", 5),
            smt.linear({"y": 1}, "<=", 10),
            smt.linear({"x": 1, "y": -1}, "==", 0),  # x == y
        ],
    )
    assert r.is_feasible
    assert r.model["x"] == r.model["y"] and r.model["x"] >= 5 and r.model["y"] <= 10


def test_constant_constraint_no_vars() -> None:
    assert smt.is_feasible({}, [smt.linear({}, "<=", 1)]).is_feasible
    assert smt.is_feasible({}, [smt.linear({}, ">", 1)]).is_infeasible


# --------------------------------------------------------------------------
# Honest refusal: too-large domain with no z3 → UNKNOWN (never a guess)
# --------------------------------------------------------------------------


def test_large_domain_without_z3_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(smt, "has_z3", lambda: False)
    r = smt.is_feasible(
        {"x": (0, 10**9)}, [smt.linear({"x": 1}, "==", 7)], max_enum=1000
    )
    assert r.is_unknown and not r.exhaustive
    assert "z3" in r.reason


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def test_unbounded_variable_raises() -> None:
    with pytest.raises(ValueError):
        smt.is_feasible({"a": (0, 5)}, [smt.linear({"b": 1}, "==", 1)])


def test_empty_domain_raises() -> None:
    with pytest.raises(ValueError):
        smt.is_feasible({"a": (5, 0)}, [])


def test_bad_op_raises() -> None:
    with pytest.raises(ValueError):
        smt.linear({"a": 1}, "≈", 3)


def test_bad_force_backend_raises() -> None:
    with pytest.raises(ValueError):
        smt.is_feasible({"a": (0, 1)}, [], force_backend="quantum")


def test_force_z3_without_z3_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(smt, "has_z3", lambda: False)
    with pytest.raises(RuntimeError):
        smt.is_feasible({"a": (0, 1)}, [], force_backend="z3")


# --------------------------------------------------------------------------
# z3 extension — exercised only when z3 is installed
# --------------------------------------------------------------------------


@pytest.mark.skipif(not cap.has_z3(), reason="z3 not installed — SMT extension unexercised")
def test_z3_agrees_with_enum_on_verdict() -> None:
    cases = [
        ({"id": (0, 100)}, [smt.linear({"id": 1}, "==", 42)]),
        ({"id": (0, 10)}, [smt.linear({"id": 1}, ">", 5), smt.linear({"id": 1}, "<", 3)]),
        ({"a": (0, 5), "b": (0, 5)}, [smt.linear({"a": 2, "b": 1}, "==", 10)]),
        ({"x": (0, 20), "y": (0, 20)}, [smt.linear({"x": 1, "y": -1}, "==", 0)]),
    ]
    for variables, constraints in cases:
        enum = smt.is_feasible(variables, constraints, force_backend="enum")
        z3r = smt.is_feasible(variables, constraints, force_backend="z3")
        assert enum.feasible == z3r.feasible, (variables, constraints)
        if z3r.is_feasible:
            # z3's witness, though possibly different from enum's, must satisfy.
            for c in constraints:
                assert smt._satisfies(c, z3r.model), (c, z3r.model)


@pytest.mark.skipif(not cap.has_z3(), reason="z3 not installed — SMT extension unexercised")
def test_z3_solves_large_domain_auto() -> None:
    r = smt.is_feasible(
        {"x": (0, 10**9)}, [smt.linear({"x": 1}, "==", 123456789)], max_enum=1000
    )
    assert r.is_feasible and r.backend == "z3" and r.model == {"x": 123456789}
