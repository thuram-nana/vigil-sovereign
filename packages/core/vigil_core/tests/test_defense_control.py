"""AEGIS AS-27b — the DEFENSE-CONTROL (``manage_defense``) evaluator: posture + stand-down preview.

The safe-direction mirror of AS-4b's release preview. Adversarial coverage:

  * ``enforcing`` is the fail-closed AND of every precondition (armed + BLOCK + proof_current + Respond + no
    override); a single missing input reads as "not enforcing", never "enforcing".
  * a stand-down is ``available`` iff there is live enforcement to stand down, and ``standdown_blockers``
    names, in a closed honest vocabulary, why it would be a no-op otherwise — fail-closed, deterministic.
  * READ-ONLY / safe direction — nothing here signs, mints, arms or stands anything down; the only control it
    describes (a stand-down) REDUCES authority and never widens scope.
  * ``customer_safe`` leaks only enum values, booleans and token lists; the model is frozen + extra-forbid; a
    bad host (IP literal, traversal) is refused.
  * the module is FATAL-2 clean — no ``framework`` / ``sigil`` import.
"""
from __future__ import annotations

import ast
import importlib
import inspect

import pytest
from pydantic import ValidationError

from vigil_core.defense_control import (
    STANDDOWN_ALREADY_STOOD_DOWN,
    STANDDOWN_NOT_ENFORCING,
    HostDefenseControl,
    defense_control_host,
)
from vigil_core.monitoring_authority import MonitoringMode


def _imported_roots(module_name: str) -> set[str]:
    mod = importlib.import_module(module_name)
    tree = ast.parse(inspect.getsource(mod))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


# --- FATAL-2 -------------------------------------------------------------------------------------------------
def test_module_is_fatal_2_clean():
    roots = _imported_roots("vigil_core.defense_control")
    assert "framework" not in roots and "sigil" not in roots, roots
    assert roots <= {"__future__", "typing", "pydantic"}, roots   # stdlib + pydantic + (relative) siblings only


# --- enforcing is the fail-closed AND of every precondition --------------------------------------------------
def _enforcing_inputs() -> dict:
    return dict(mode=MonitoringMode.BLOCK, armed=True, proof_current=True, respond_entitled=True)


def test_a_fully_armed_block_host_with_proof_and_respond_is_enforcing_and_standdown_applies():
    c = defense_control_host("a.example", **_enforcing_inputs())
    assert c.enforcing is True
    assert c.standdown_available is True
    assert c.standdown_blockers == ()


@pytest.mark.parametrize("missing", ["armed", "proof_current", "respond_entitled"])
def test_any_missing_precondition_means_not_enforcing_and_no_standdown(missing):
    inputs = _enforcing_inputs()
    inputs[missing] = False
    c = defense_control_host("a.example", **inputs)
    assert c.enforcing is False
    assert c.standdown_available is False
    assert c.standdown_blockers == (STANDDOWN_NOT_ENFORCING,)


def test_observe_mode_is_never_enforcing_even_fully_armed():
    c = defense_control_host("a.example", mode=MonitoringMode.OBSERVE, armed=True, proof_current=True,
                             respond_entitled=True)
    assert c.enforcing is False and c.standdown_available is False
    assert c.standdown_blockers == (STANDDOWN_NOT_ENFORCING,)


def test_an_active_override_already_stands_enforcement_down():
    # A downgrade-only override already in force: the host is NOT enforcing (the override reduced it), and a
    # fresh stand-down would be a no-op — the honest blocker is `already_stood_down`, not `not_enforcing`.
    c = defense_control_host("a.example", override_active=True, **_enforcing_inputs())
    assert c.enforcing is False
    assert c.standdown_available is False
    assert c.standdown_blockers == (STANDDOWN_ALREADY_STOOD_DOWN,)


def test_standdown_available_is_exactly_enforcing_across_the_grid():
    # The whole truth table: a stand-down is available iff the host is enforcing (no override). Exhaustive.
    for armed in (True, False):
        for proof in (True, False):
            for respond in (True, False):
                for mode in (MonitoringMode.OBSERVE, MonitoringMode.BLOCK):
                    for override in (True, False):
                        c = defense_control_host("h.example", mode=mode, armed=armed, proof_current=proof,
                                                 respond_entitled=respond, override_active=override)
                        expect_enforcing = armed and proof and respond and mode is MonitoringMode.BLOCK and not override
                        assert c.enforcing is expect_enforcing, (armed, proof, respond, mode, override)
                        # a stand-down only ever applies to live enforcement; never when already overridden
                        assert c.standdown_available is expect_enforcing
                        if override and not expect_enforcing:
                            assert c.standdown_blockers == (STANDDOWN_ALREADY_STOOD_DOWN,)
                        elif not expect_enforcing:
                            assert c.standdown_blockers == (STANDDOWN_NOT_ENFORCING,)


# --- read-only / determinism / honesty -----------------------------------------------------------------------
def test_it_is_deterministic_and_customer_safe():
    a = defense_control_host("a.example", **_enforcing_inputs())
    b = defense_control_host("a.example", **_enforcing_inputs())
    assert a == b                                   # frozen value objects, identical inputs -> identical output
    safe = a.customer_safe()
    assert safe == {
        "host": "a.example", "mode": "block", "armed": True, "proof_current": True, "respond_entitled": True,
        "enforcing": True, "override_active": False, "standdown_available": True, "standdown_blockers": [],
    }
    # only JSON-native primitives + token lists cross the hop — no model object, no secret, no internal id
    import json
    json.dumps(safe)


def test_blockers_are_sorted_and_deduplicated_tokens():
    c = defense_control_host("a.example", override_active=True, **_enforcing_inputs())
    assert list(c.standdown_blockers) == sorted(set(c.standdown_blockers))


def test_the_model_is_frozen_and_extra_forbid():
    c = defense_control_host("a.example", **_enforcing_inputs())
    with pytest.raises(ValidationError):
        HostDefenseControl(host="a.example", nonsense=True)          # extra field forbidden
    with pytest.raises((ValidationError, AttributeError, TypeError)):
        c.enforcing = False                                          # frozen


@pytest.mark.parametrize("bad", ["10.0.0.1", "not a host", "a.example/../b", "", "http://a.example"])
def test_a_bad_host_is_refused(bad):
    with pytest.raises((ValidationError, ValueError)):
        defense_control_host(bad, **_enforcing_inputs())
