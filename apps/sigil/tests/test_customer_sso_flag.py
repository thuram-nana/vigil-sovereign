"""PR-H Area 7 — the flag-off golden: with VIGIL_CUSTOMER_SSO off, SSO/SCIM is absent and the ceiling holds.

Master flag ``VIGIL_CUSTOMER_SSO`` is OFF by default (mirrors ``VIGIL_REDPEN_ENABLED``). This pins that, off, the
flag reads False, and — independent of the flag — the SSO/SCIM ROLE CEILING can never reach a money/offense
permission: a build with SSO present is byte-identical in effective authority to one without it.
"""
from __future__ import annotations

import pytest

from sigil import config
from sigil.governor import scim as gscim
from sigil.governor import sso_config as sc
from vigil_core.rbac import PERMISSIONS, role_can


@pytest.fixture(autouse=True)
def _off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_SSO", raising=False)


def test_master_flag_off_by_default():
    assert config.customer_sso_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "enabled", "TRUE", "On"])
def test_affirmative_tokens_turn_it_on(monkeypatch, val):
    monkeypatch.setenv("VIGIL_CUSTOMER_SSO", val)
    assert config.customer_sso_enabled() is True


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off", "disabled", "  ", "nonsense"])
def test_non_affirmative_tokens_stay_off(monkeypatch, val):
    monkeypatch.setenv("VIGIL_CUSTOMER_SSO", val)
    assert config.customer_sso_enabled() is False


def test_the_ceiling_is_exactly_viewer_analyst_org_admin():
    assert sc.SSO_PROVISIONABLE_ROLES == frozenset({"viewer", "analyst", "org_admin"})
    assert gscim.SCIM_PROVISIONABLE_ROLES == sc.SSO_PROVISIONABLE_ROLES


def test_sso_ceiling_cannot_reach_any_money_or_offense_permission():
    # The whole point of PR-H: no SSO/SCIM-provisionable role can touch run_engagement / offense_authority /
    # manage_code / view_assessments or the owner-governance permissions. founder/operator/owner are excluded.
    dangerous = {"run_engagement", "manage_code", "offense_authority", "view_assessments", "promote", "secrets",
                 "kill_release", "manage_users", "manage_org", "approve_a2", "approve_a3"}
    for role in sc.SSO_PROVISIONABLE_ROLES:
        for perm in dangerous:
            assert not role_can(role, perm), f"SSO-provisionable {role!r} must not carry {perm!r}"
    # and the testing/offense roles are NOT provisionable
    assert sc.SSO_PROVISIONABLE_ROLES.isdisjoint({"founder", "operator", "owner"})


def test_run_engagement_and_offense_stay_owner_signed():
    # run_engagement exists only on founder/operator/owner; offense_authority only on owner — none provisionable.
    assert {r for r in PERMISSIONS if "run_engagement" in PERMISSIONS[r]}.isdisjoint(sc.SSO_PROVISIONABLE_ROLES)
    assert {r for r in PERMISSIONS if "offense_authority" in PERMISSIONS[r]}.isdisjoint(sc.SSO_PROVISIONABLE_ROLES)
