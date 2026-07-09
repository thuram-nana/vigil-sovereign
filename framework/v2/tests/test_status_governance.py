"""
Speed X6 — `status` must surface the runtime GOVERNANCE state prominently (not just a log
line): the sovereignty tier + whether it is sealed, and whether capability entitlement is
ENFORCED or the deployment is running UNGOVERNED. An operator should see at a glance that
exploitation is (or is not) actually governed.
"""

from __future__ import annotations

from framework.v2.__main__ import _status


def test_status_prints_governance_section(capsys) -> None:
    rc = _status([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Governance" in out
    assert "sovereignty tier" in out
    # entitlement line is present either way; a dev checkout with no trust root is UNGOVERNED.
    assert "entitlement" in out


def test_status_flags_ungoverned_when_not_enforced(capsys, monkeypatch) -> None:
    # With no trust root provisioned and enforcement unset, the entitlement is UNGOVERNED — the
    # status must say so prominently rather than stay silent.
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False)
    from framework.v2.entitlement.policy import EntitlementPolicy

    if EntitlementPolicy.from_provisioned().enforced:
        import pytest
        pytest.skip("a trust root is provisioned in this environment; UNGOVERNED path not exercised")
    _status([])
    out = capsys.readouterr().out
    assert "UNGOVERNED" in out
