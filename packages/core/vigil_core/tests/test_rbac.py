"""Unit tests for the shared role->permission vocabulary (`vigil_core.rbac`, Slice S1).

Pins the cumulative role ordering + `role_can` default-deny, and the offense-console route->permission map
(`OFFENSE_ACTION_PERM`) + its path resolver (`offense_perm_for` / `offense_route_key`) — including that the
DANGEROUS routes are owner-tier and everything ordinary is operator-tier, that an unmapped route is
default-deny, and that exact keys win over the wildcard patterns.
"""
from __future__ import annotations

import vigil_core
from vigil_core import rbac
from vigil_core.rbac import (
    OFFENSE_ACTION_PERM, PERMISSIONS, ROLES, offense_perm_for, offense_route_key, role_can, role_can_global,
)

# Every permission string the vocabulary defines, plus the default-deny probes.
_ALL_PERMS = sorted(frozenset().union(*PERMISSIONS.values()))
_PROBES = [*_ALL_PERMS, None, "", "no-such-permission"]


# --- role_can / cumulative ordering ------------------------------------------------------------
def test_roles_are_ordered_viewer_to_owner():
    assert ROLES == ("viewer", "analyst", "operator", "owner")


def test_permissions_are_cumulative():
    # owner ⊇ operator ⊇ analyst ⊇ viewer
    assert PERMISSIONS["viewer"] <= PERMISSIONS["analyst"]
    assert PERMISSIONS["analyst"] <= PERMISSIONS["operator"]
    assert PERMISSIONS["operator"] <= PERMISSIONS["owner"]


def test_role_can_basic_grants():
    assert role_can("viewer", "read") is True
    assert role_can("analyst", "queue_proposal") is True
    assert role_can("operator", "run_engagement") is True
    assert role_can("owner", "offense_authority") is True
    assert role_can("owner", "manage_users") is True


def test_role_can_default_deny():
    # an unmapped/blank permission refuses every role (the whole gate turns on this)
    assert role_can("owner", None) is False
    assert role_can("owner", "") is False
    # an unknown role has no permissions
    assert role_can("root", "read") is False
    assert role_can(None, "read") is False
    # a lower role never carries a higher role's permission
    assert role_can("operator", "offense_authority") is False
    assert role_can("analyst", "run_engagement") is False
    assert role_can("viewer", "run_engagement") is False


# --- OFFENSE_ACTION_PERM + resolution ----------------------------------------------------------
def test_every_mapped_permission_is_a_real_owner_permission():
    # a route can only require a permission the vocabulary actually defines (owner ⊇ all)
    owner = PERMISSIONS["owner"]
    for route, perm in OFFENSE_ACTION_PERM.items():
        assert perm in owner, f"{route} requires unknown permission {perm!r}"


def test_dangerous_routes_are_owner_tier():
    for path in ("/api/authority/provision", "/api/authority/ledger",
                 "/api/terminal/run",
                 "/api/remediate/run1/f1/apply", "/api/aegis/setup",
                 "/api/tools/install", "/api/services/up"):
        perm = offense_perm_for(path)
        assert perm == "offense_authority", f"{path} should be owner-tier, got {perm!r}"
        assert role_can("owner", perm) and not role_can("operator", perm)


def test_killswitch_trip_is_read_tier_protective():
    # tripping the kill-switch HALTS (never clears) — a protective emergency-stop must be the LOWEST tier
    # (mirrors sovereign `kill: read`), never owner. Regression guard against the privilege inversion.
    perm = offense_perm_for("/api/killswitch/s1/trip")
    assert perm == "read", f"killswitch trip must be read-tier (protective), got {perm!r}"
    # every role — down to viewer — may halt.
    assert role_can("viewer", perm) and role_can("operator", perm) and role_can("owner", perm)


def test_ordinary_routes_are_operator_tier():
    for path in ("/api/launch/preview", "/api/launch/assessment", "/api/launch/cloud", "/api/run/r1/cancel",
                 "/api/run/r1/retry", "/api/codebase/edit", "/api/codebase/apply",
                 "/api/session/create", "/api/chat/send", "/api/chat/stream",
                 "/api/chat/rename", "/api/chat/delete", "/api/reverify/r1",
                 "/api/dossier/r1/build", "/api/feed/s1/pull", "/api/aegis/stop",
                 "/api/terminal/dryrun", "/api/terminal/propose", "/api/label/run"):
        perm = offense_perm_for(path)
        assert perm == "run_engagement", f"{path} should be operator-tier, got {perm!r}"
        assert role_can("operator", perm) and not role_can("analyst", perm)


def test_offense_gated_api_routes_are_operator_tier():
    # W16-12: the loopback gated api's two POST routes are ordinary offense actions (invoke a SAFE tool /
    # import a third-party report) → operator-tier run_engagement, resolved out of the ONE shared map (not a
    # second model). A user lacking run_engagement (analyst/viewer) is refused BOTH; an operator+ is allowed.
    for path in ("/api/v1/tool/invoke", "/api/v1/import"):
        perm = offense_perm_for(path)
        assert perm == "run_engagement", f"{path} should be operator-tier, got {perm!r}"
        assert role_can("operator", perm) and role_can("owner", perm)
        assert not role_can("analyst", perm) and not role_can("viewer", perm)
    # they are EXACT keys (the api's /api/v1 prefix does not collide with any console wildcard pattern).
    assert offense_route_key("/api/v1/tool/invoke") == "/api/v1/tool/invoke"
    # and an unmapped /api/v1 route is still default-deny (fail-closed for a future api POST route).
    assert offense_perm_for("/api/v1/unmapped") is None


def test_launch_preview_matches_sibling_launch_rbac_and_gates_by_perm():
    # W17-9: the PRE-Send preflight /api/launch/preview must carry the SAME RBAC as its sibling launch
    # endpoints (operator-tier run_engagement), so a per-user proxied operator is neither silently allowed
    # nor silently denied on the new route. A principal LACKING run_engagement (analyst/viewer) is refused;
    # one WITH it (operator+) is allowed — mirroring /api/launch/assessment and /api/launch/cloud exactly.
    preview = offense_perm_for("/api/launch/preview")
    assert preview == "run_engagement", f"preview must be operator-tier, got {preview!r}"
    assert preview == offense_perm_for("/api/launch/assessment") == offense_perm_for("/api/launch/cloud")
    # a user lacking the perm is refused; one with it is allowed
    assert not role_can("analyst", preview) and not role_can("viewer", preview)
    assert role_can("operator", preview) and role_can("owner", preview)


def test_unmapped_route_is_default_deny():
    assert offense_perm_for("/api/totally/unknown") is None
    assert offense_route_key("/api/totally/unknown") is None
    # a GET-only route POSTed is not mapped either → default-deny
    assert offense_perm_for("/api/feed/status") is None
    assert offense_perm_for("/api/status") is None
    # and default-deny composes with role_can: no role clears an unmapped route
    for role in ROLES:
        assert role_can(role, offense_perm_for("/api/totally/unknown")) is False


def test_exact_key_wins_over_wildcard_pattern():
    # /api/knowledge/gitsync is an exact operator route; the /api/knowledge/*/deeplearn pattern must not
    # swallow it. /api/replay is exact and must not be captured by the /api/reverify/ prefix pattern.
    assert offense_route_key("/api/knowledge/gitsync") == "/api/knowledge/gitsync"
    assert offense_route_key("/api/knowledge/s1/deeplearn") == "/api/knowledge/*/deeplearn"
    assert offense_route_key("/api/replay") == "/api/replay"
    assert offense_route_key("/api/reverify/r9") == "/api/reverify/*"


# --- E0: the per-org tenant-admin role (billing != testing, structurally) ----------------------
def test_org_admin_is_tenant_billing_and_member_admin_never_testing():
    # Slice E0: `org_admin` is a PER-ORG role (never in the global linear chain), carrying billing +
    # membership administration but DELIBERATELY no run_engagement / offense_authority — so a paying
    # tenant-admin can manage their org's money + members yet can NEVER authorize a security assessment.
    assert "org_admin" not in ROLES                       # per-org only — never a global account role
    for granted in ("read", "view_billing", "view_usage", "view_invoices", "manage_billing", "manage_members"):
        assert role_can("org_admin", granted) is True, f"org_admin should carry {granted}"
    for forbidden in ("run_engagement", "offense_authority", "secrets", "manage_users", "manage_org",
                      "promote", "kill_release", "approve_a3"):
        assert role_can("org_admin", forbidden) is False, f"org_admin must NOT carry {forbidden}"
    assert PERMISSIONS["org_admin"] <= PERMISSIONS["owner"]   # owner remains the ceiling
    # the four cumulative roles are unchanged by the addition
    assert PERMISSIONS["operator"] <= PERMISSIONS["owner"] and PERMISSIONS["viewer"] <= PERMISSIONS["analyst"]


# --- role_can_global: the predicate for a GLOBAL account role ------------------------------------
def test_role_can_global_matches_role_can_for_every_global_role():
    # For the four global roles the two predicates agree on every permission (and on the default-deny
    # probes), so switching a global-role call site to role_can_global changes nothing for them.
    for role in ROLES:
        for perm in _PROBES:
            assert role_can_global(role, perm) == role_can(role, perm), (role, perm)


def test_role_can_global_refuses_every_per_org_and_unknown_role():
    per_org = [r for r in PERMISSIONS if r not in ROLES]
    assert "org_admin" in per_org
    for role in [*per_org, "root", "Owner", "", None]:
        for perm in _PROBES:
            assert role_can_global(role, perm) is False, (role, perm)
    # the per-org predicate still answers for a membership role (the org fold binds it to one org)
    assert role_can("org_admin", "read") is True and role_can("org_admin", "manage_billing") is True


def test_role_can_global_refuses_a_per_org_role_that_carries_the_permission(monkeypatch):
    # Even a per-org role whose permission set includes run_engagement carries nothing in a global position.
    monkeypatch.setitem(rbac.PERMISSIONS, "tenant_tester", frozenset({"read", "run_engagement"}))
    assert role_can("tenant_tester", "run_engagement") is True
    assert role_can_global("tenant_tester", "run_engagement") is False
    assert role_can_global("tenant_tester", "read") is False


def test_role_can_global_is_exported_by_the_package():
    assert vigil_core.role_can_global is rbac.role_can_global
    assert "role_can_global" in vigil_core.__all__


# --- the per-org founder role (owner-approved self-serve testing) ------------------------------------
def test_founder_is_exactly_org_admin_plus_the_testing_permissions():
    assert "founder" not in ROLES                         # per-org only — never a global account role
    assert PERMISSIONS["founder"] == frozenset({
        "read", "view_billing", "view_usage", "view_invoices", "manage_billing", "manage_members",
        "manage_monitoring", "run_engagement", "view_assessments", "manage_code",
        "manage_defense"})   # +manage_code (Red-Pen R2, O-4); +manage_defense (AEGIS AS-27b)
    assert PERMISSIONS["founder"] == PERMISSIONS["org_admin"] | {
        "run_engagement", "view_assessments", "manage_code", "manage_defense"}
    assert PERMISSIONS["founder"] <= PERMISSIONS["owner"]  # owner remains the ceiling


def test_founder_never_carries_authority_approval_config_or_secrets():
    for forbidden in ("offense_authority", "approve_a2", "approve_a3", "toggle_guard", "toggle_protected_guard",
                      "config_nonsecret", "queue_proposal", "manage_org", "manage_users", "secrets", "promote",
                      "kill_release"):
        assert role_can("founder", forbidden) is False, f"founder must NOT carry {forbidden}"


def test_founder_carries_nothing_in_a_global_position():
    for perm in _PROBES:
        assert role_can_global("founder", perm) is False, perm
    # inside its own org (the per-org predicate) it runs and reads its own assessments
    assert role_can("founder", "run_engagement") is True and role_can("founder", "view_assessments") is True
    # and the operator-tier offense routes are therefore never reachable by a founder stamp
    for path in ("/api/v1/tool/invoke", "/api/launch/preview", "/api/launch/assessment", "/api/killswitch/s/trip"):
        assert role_can_global("founder", offense_perm_for(path)) is False


# --- AEGIS AS-27b: the manage_defense capability (operate the live defensive response) ----------------
def test_manage_defense_is_a_founder_and_owner_capability_only():
    # The DEFENSE-CONTROL capability (the stand-down / override): the founder (the per-org security-responsible
    # role) and the owner carry it; NOBODY else does. In particular it rides with the testing-domain set, NOT
    # with the billing-only org_admin — defense-authz != billing-authz.
    assert role_can("founder", "manage_defense") is True
    assert role_can("owner", "manage_defense") is True
    assert role_can("org_admin", "manage_defense") is False      # billing-authz != defense-authz
    for role in ("viewer", "analyst", "operator"):
        assert role_can(role, "manage_defense") is False, role
    # owner remains the ceiling (founder ⊆ owner already asserted); no cumulative role below owner gained it
    assert "manage_defense" in PERMISSIONS["owner"] and "manage_defense" not in PERMISSIONS["operator"]


def test_manage_defense_is_disjoint_from_offense_and_carries_nothing_globally():
    # Defense is not offense: a defense manager never gains offense authority, and the permission carries
    # NOTHING in a global position (it is a per-org membership capability only, like run_engagement for a founder).
    assert role_can("founder", "offense_authority") is False
    assert role_can_global("founder", "manage_defense") is False
    assert role_can_global("owner", "manage_defense") is True     # owner IS a global role and carries it
    # it is also disjoint from manage_monitoring: a role may hold one without the other (org_admin holds
    # manage_monitoring but NOT manage_defense), so the two gates are genuinely distinct.
    assert role_can("org_admin", "manage_monitoring") is True and role_can("org_admin", "manage_defense") is False
