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
