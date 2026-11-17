"""Red-Pen R2 — the per-org ``manage_code`` permission (decision O-4).

``manage_code`` (connect a repo, set its per-repo policy, click "Fix this") is TESTING-domain, so it rides with the
owner-granted ``operator`` and the ``founder`` and is DELIBERATELY NOT in ``org_admin`` (billing-authz != testing-authz).
A customer may still grant only viewer / analyst / org_admin — the grantable set is unchanged.
"""
from __future__ import annotations

from vigil_core.rbac import PERMISSIONS, role_can


def test_founder_and_operator_have_manage_code():
    assert role_can("founder", "manage_code")
    assert role_can("operator", "manage_code")
    assert role_can("owner", "manage_code")                     # cumulative: owner >= operator


def test_org_admin_analyst_and_viewer_do_not_have_manage_code():
    for role in ("org_admin", "analyst", "viewer"):
        assert not role_can(role, "manage_code"), role


def test_manage_code_is_disjoint_from_billing_admin():
    # the whole point of O-4: a billing tenant-admin (org_admin) never gains a testing-domain code capability
    assert "manage_code" not in PERMISSIONS["org_admin"]
    assert "manage_code" in PERMISSIONS["operator"] and "manage_code" in PERMISSIONS["founder"]


def test_the_customer_grantable_role_set_is_unchanged():
    from sigil.ui.provision import _CUSTOMER_GRANTABLE_ROLES
    assert _CUSTOMER_GRANTABLE_ROLES == frozenset({"viewer", "analyst", "org_admin"})
    # none of the customer-grantable roles carries manage_code (a customer cannot self-grant code management)
    for role in _CUSTOMER_GRANTABLE_ROLES:
        assert not role_can(role, "manage_code"), role
