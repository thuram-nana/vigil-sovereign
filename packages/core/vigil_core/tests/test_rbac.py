"""Unit tests for the shared role->permission vocabulary (`vigil_core.rbac`, Slice S1).

Pins the cumulative role ordering + `role_can` default-deny, and the offense-console route->permission map
(`OFFENSE_ACTION_PERM`) + its path resolver (`offense_perm_for` / `offense_route_key`) — including that the
DANGEROUS routes are owner-tier and everything ordinary is operator-tier, that an unmapped route is
default-deny, and that exact keys win over the wildcard patterns.
"""
from __future__ import annotations

from vigil_core.rbac import (
    OFFENSE_ACTION_PERM, PERMISSIONS, ROLES, offense_perm_for, offense_route_key, role_can,
)


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
