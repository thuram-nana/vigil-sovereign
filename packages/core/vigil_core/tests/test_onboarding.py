"""AEGIS AS-6d — the customer tenant ONBOARDING-JOURNEY evaluator (connected host -> monitored).

The read-only evaluator that COMPOSES the already-built monitoring surfaces into a guided flow. Adversarial
coverage:

  * the journey is LINEAR and fail-closed — a step is ``done`` only when its grounded condition holds, the
    ``current`` step is the FIRST not-done step (every step after it ``todo``), and ``complete`` is reached
    only when a host is actually monitored; when complete no step is ``current`` and ``next_step`` is None.
  * a missing fact reads as "not done", never "done"; counts are clamped at 0.
  * READ-ONLY — nothing here signs, mints, arms or releases; it only records where the tenant already is.
  * ``customer_safe`` leaks only counts, booleans and closed tokens (no host name); the models are frozen +
    extra-forbid; it is deterministic (identical inputs -> identical output).
  * the module is FATAL-2 clean — no ``framework`` / ``sigil`` import.
"""
from __future__ import annotations

import ast
import importlib
import inspect

import pytest
from pydantic import ValidationError

from vigil_core.onboarding import (
    STATUS_CURRENT,
    STATUS_DONE,
    STATUS_TODO,
    STEP_PLAN,
    STEP_PROVE_HOST,
    STEP_TURN_ON,
    OnboardingJourney,
    OnboardingStep,
    onboarding_journey,
)


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


def _status(j: OnboardingJourney) -> dict[str, str]:
    return {s.key: s.status for s in j.steps}


# --- FATAL-2 -------------------------------------------------------------------------------------------------
def test_module_is_fatal_2_clean():
    roots = _imported_roots("vigil_core.onboarding")
    assert "framework" not in roots and "sigil" not in roots, roots
    assert roots <= {"__future__", "typing", "pydantic"}, roots   # stdlib + pydantic + (relative) siblings only


# --- the linear journey, step by step ------------------------------------------------------------------------
def test_an_empty_workspace_has_prove_host_current_and_the_rest_todo():
    j = onboarding_journey(proven_host_count=0, active_host_count=0, has_plan=False, respond_entitled=False)
    assert _status(j) == {STEP_PROVE_HOST: STATUS_CURRENT, STEP_PLAN: STATUS_TODO, STEP_TURN_ON: STATUS_TODO}
    assert j.complete is False and j.next_step == STEP_PROVE_HOST and j.explore_available is False


def test_a_proven_host_advances_the_current_step_to_plan():
    j = onboarding_journey(proven_host_count=1, active_host_count=0, has_plan=False, respond_entitled=False)
    assert _status(j) == {STEP_PROVE_HOST: STATUS_DONE, STEP_PLAN: STATUS_CURRENT, STEP_TURN_ON: STATUS_TODO}
    assert j.next_step == STEP_PLAN and j.complete is False


def test_a_proven_host_on_a_plan_makes_turn_on_the_current_step():
    j = onboarding_journey(proven_host_count=2, active_host_count=0, has_plan=True, respond_entitled=True)
    assert _status(j) == {STEP_PROVE_HOST: STATUS_DONE, STEP_PLAN: STATUS_DONE, STEP_TURN_ON: STATUS_CURRENT}
    assert j.next_step == STEP_TURN_ON and j.complete is False and j.explore_available is False


def test_a_monitored_host_completes_the_journey_with_no_current_step():
    j = onboarding_journey(proven_host_count=1, active_host_count=1, enforcing_host_count=0,
                           has_plan=True, respond_entitled=True)
    assert _status(j) == {STEP_PROVE_HOST: STATUS_DONE, STEP_PLAN: STATUS_DONE, STEP_TURN_ON: STATUS_DONE}
    assert j.complete is True and j.next_step is None and j.explore_available is True


def test_complete_is_reached_by_monitoring_even_if_a_later_fact_lapsed_and_names_no_current_step():
    # fail-closed + honest: a host is monitored (active) but its proof lapsed now (proven_host_count 0). The
    # journey is still complete (the destination was reached), prove_host reads not-done, and NO step is current.
    j = onboarding_journey(proven_host_count=0, active_host_count=1, has_plan=True, respond_entitled=False)
    assert j.complete is True and j.next_step is None
    assert _status(j)[STEP_PROVE_HOST] == STATUS_TODO and _status(j)[STEP_TURN_ON] == STATUS_DONE
    # no step is marked current once complete
    assert all(s.status != STATUS_CURRENT for s in j.steps)


def test_a_plan_without_a_proven_host_keeps_prove_host_current_honestly():
    j = onboarding_journey(proven_host_count=0, active_host_count=0, has_plan=True, respond_entitled=True)
    assert _status(j) == {STEP_PROVE_HOST: STATUS_CURRENT, STEP_PLAN: STATUS_DONE, STEP_TURN_ON: STATUS_TODO}
    assert j.next_step == STEP_PROVE_HOST


# --- read-only / determinism / honesty -----------------------------------------------------------------------
def test_it_is_deterministic_and_customer_safe():
    a = onboarding_journey(proven_host_count=1, active_host_count=1, enforcing_host_count=1,
                           has_plan=True, respond_entitled=True)
    b = onboarding_journey(proven_host_count=1, active_host_count=1, enforcing_host_count=1,
                           has_plan=True, respond_entitled=True)
    assert a == b                                   # frozen value objects, identical inputs -> identical output
    safe = a.customer_safe()
    assert safe == {
        "proven_host_count": 1, "active_host_count": 1, "enforcing_host_count": 1,
        "has_plan": True, "respond_entitled": True,
        "steps": [{"key": STEP_PROVE_HOST, "status": STATUS_DONE, "done": True},
                  {"key": STEP_PLAN, "status": STATUS_DONE, "done": True},
                  {"key": STEP_TURN_ON, "status": STATUS_DONE, "done": True}],
        "complete": True, "next_step": None, "explore_available": True,
    }
    # only JSON-native primitives cross the hop — no model object, no secret; the journey carries NO host name
    # at all (it is aggregate counts + closed tokens), so a renderer cannot leak one from this read.
    import json
    json.dumps(safe)
    assert "example" not in json.dumps(safe) and ".com" not in json.dumps(safe)


def test_negative_counts_are_clamped_to_zero():
    j = onboarding_journey(proven_host_count=-5, active_host_count=-1, enforcing_host_count=-3,
                           has_plan=False, respond_entitled=False)
    safe = j.customer_safe()
    assert safe["proven_host_count"] == 0 and safe["active_host_count"] == 0 and safe["enforcing_host_count"] == 0
    assert j.complete is False


def test_the_models_are_frozen_and_extra_forbid():
    j = onboarding_journey(proven_host_count=1, active_host_count=0, has_plan=True, respond_entitled=False)
    with pytest.raises(ValidationError):
        OnboardingJourney(nonsense=True)                             # extra field forbidden
    with pytest.raises(ValidationError):
        OnboardingStep(key="x", status="done", extra=1)              # extra field forbidden
    with pytest.raises((ValidationError, AttributeError, TypeError)):
        j.complete = True                                            # frozen
