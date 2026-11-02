"""K4-6 — the customer-launch production-execution flag HOLD (doctor refuse-to-start).

`vigil doctor` / the production START gate refuses to start when VIGIL_CUSTOMER_PROD_EXECUTION is flipped on
under a production posture, so production-target customer execution stays DISABLED until the full K4
acceptance matrix is green and the flip is a deliberate owner act (defence in depth over the launch gate +
worker runtime refusal, which already refuse a LIVE customer arm while the flag is off). This PR does NOT
flip the flag — it holds it. These pin: the flag state read; the hold is OPT-IN (inert unless the production
posture is armed); it fires ONLY when armed AND the flag is on; and the refusal documents the flip criteria.

FATAL-2: doctor is the offense/integration plane; the control reads only vigil_core.posture. PYTHONPATH=
integration (vigil_core installed).
"""
from __future__ import annotations

import vigil_integration.doctor as dmod


def test_flag_unset_is_disabled(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)
    state, detail = dmod._posture_customer_execution()
    assert state == "DISABLED" and "held off" in detail


def test_flag_set_is_enabled(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_PROD_EXECUTION", "1")
    state, _ = dmod._posture_customer_execution()
    assert state == "ENABLED"


def test_hold_is_inert_when_not_armed(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_PROD_EXECUTION", "1")      # flag ON...
    assert dmod._customer_execution_hold(armed=False) is None     # ...but NOT production posture → inert


def test_hold_is_inert_when_flag_held_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)
    assert dmod._customer_execution_hold(armed=True) is None      # production, but flag held off → no breach


def test_hold_refuses_when_armed_and_flag_on_and_documents_flip_criteria(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_PROD_EXECUTION", "1")
    msg = dmod._customer_execution_hold(armed=True)
    assert msg is not None
    assert "customer-execution is ENABLED" in msg and "acceptance matrix" in msg
    # the refusal documents the full flip criteria (every acceptance-matrix dimension named)
    for dimension in ("security", "tenant-isolation", "authz", "billing", "operational"):
        assert dimension in msg
    assert "deliberate owner act" in msg                         # the flip is gated + deliberate, never a default


def test_start_gate_enforces_the_hold_not_only_vigil_doctor(monkeypatch):
    # red-pen fold: the hold must refuse the ACTUAL `vigil up`/`engage` start path (_enforce_production_gate),
    # not only `vigil doctor`'s collect(). Make the REQUIRED_CONTROLS gate PASS + armed, so the customer-
    # execution hold is the SOLE refusal, and assert the start gate refuses (returns 2) when the flag is on.
    from vigil_integration import cli
    monkeypatch.setattr(dmod, "evaluate_production_gate",
                        lambda repo: {"ok": True, "armed": True, "posture": "production", "unmet": []})
    monkeypatch.setenv("VIGIL_CUSTOMER_PROD_EXECUTION", "1")
    assert cli._enforce_production_gate("up") == 2                # the START path refuses (the hold now enforces)
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)
    assert cli._enforce_production_gate("up") is None            # flag held off → start proceeds (hold inert)


def test_start_gate_hold_is_inert_when_posture_not_armed(monkeypatch):
    # not production posture → the hold is inert even with the flag on (the start gate proceeds on an otherwise-ok gate)
    from vigil_integration import cli
    monkeypatch.setattr(dmod, "evaluate_production_gate",
                        lambda repo: {"ok": True, "armed": False, "posture": None, "unmet": []})
    monkeypatch.setenv("VIGIL_CUSTOMER_PROD_EXECUTION", "1")
    assert cli._enforce_production_gate("up") is None            # not armed → inert → proceeds
