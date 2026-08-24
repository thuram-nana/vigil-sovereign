"""VSCP route -> permission map, reusing the RBAC-of-record vocabulary (W13-7 / #500).

The permissions are the SAME strings the whole VIGIL monorepo shares
(:mod:`vigil_core.rbac`): ``viewer < analyst < operator < owner``, cumulative, with
``role_can`` the one predicate the gate turns on. VSCP does not invent a role vocabulary;
it maps its own routes onto the shared one, so a "reviewer" is exactly the read-only
``viewer`` role, everywhere.

The load-bearing property (acceptance (d)): REVIEWER ROLES ARE READ-ONLY, ASSERTED PER
ROUTE. Every mutating route (POST/PUT/PATCH/DELETE) requires a permission the reviewer
does not hold; every read route (GET) requires only ``read``, which the reviewer holds.
:func:`reviewer_readonly_report` proves this over the whole table, so a future route that
mapped a write to ``read`` (or left a mutation reviewer-reachable) fails the check.

DEFAULT-DENY: an unmapped ``(method, path)`` resolves to ``None`` -> ``role_can`` False ->
refused for every role, including owner.
"""
from __future__ import annotations

from dataclasses import dataclass

from vigil_core.rbac import role_can

__all__ = [
    "REVIEWER_ROLE",
    "READ",
    "WRITE",
    "MUTATING_METHODS",
    "ROUTE_PERMISSIONS",
    "route_required_permission",
    "role_can_route",
    "reviewer_can_route",
    "reviewer_readonly_report",
]

# The reviewer is the read-only role. Named once so the assertion below and any caller
# agree on which role "reviewer" means.
REVIEWER_ROLE = "viewer"

# Permission tiers used by VSCP routes, drawn from the shared vocabulary:
#   * READ  ("read")            — held by viewer+ (every authenticated principal).
#   * WRITE ("run_engagement")  — held by operator+; a reviewer/analyst does NOT hold it,
#                                 so every mutating control-plane action is above them.
READ = "read"
WRITE = "run_engagement"

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# (METHOD, path) -> required permission. Paths use ``*`` for a single path segment; the
# resolver matches segment-for-segment. Reviewer console routes are GET-only by
# construction (a reviewer reads deployments / authorities / authorizations / the review
# queue; a reviewer never mutates).
ROUTE_PERMISSIONS: dict[tuple[str, str], str] = {
    # ---- deployment registry --------------------------------------------------------
    ("GET", "/vscp/deployments"): READ,
    ("GET", "/vscp/deployments/*"): READ,
    ("POST", "/vscp/deployments"): WRITE,
    # ---- trust authorities ----------------------------------------------------------
    ("GET", "/vscp/trust-authorities"): READ,
    ("GET", "/vscp/trust-authorities/*"): READ,
    ("POST", "/vscp/trust-authorities"): WRITE,
    # ---- authorization issuance -----------------------------------------------------
    ("GET", "/vscp/authorizations"): READ,
    ("GET", "/vscp/authorizations/*"): READ,
    ("POST", "/vscp/authorizations"): WRITE,
    ("POST", "/vscp/authorizations/*/revoke"): WRITE,
    # ---- reviewer console (read-only) ----------------------------------------------
    ("GET", "/vscp/reviewer/queue"): READ,
    ("GET", "/vscp/reviewer/deployments"): READ,
}


def _match(pattern: str, path: str) -> bool:
    pp = pattern.strip("/").split("/")
    cp = path.strip("/").split("/")
    if len(pp) != len(cp):
        return False
    return all(a == "*" or a == b for a, b in zip(pp, cp, strict=True))


def route_required_permission(method: str, path: str) -> str | None:
    """The permission a ``(method, path)`` requires, or ``None`` (DEFAULT-DENY) if no route
    matches. Exact matches win over wildcard matches."""
    method = method.upper()
    if (method, path) in ROUTE_PERMISSIONS:
        return ROUTE_PERMISSIONS[(method, path)]
    for (m, pattern), perm in ROUTE_PERMISSIONS.items():
        if m == method and "*" in pattern and _match(pattern, path):
            return perm
    return None


def role_can_route(role: str | None, method: str, path: str) -> bool:
    """True iff ``role`` may call ``(method, path)``. Feeds the required permission straight
    into the shared :func:`vigil_core.rbac.role_can`, so VSCP adds no policy — an unmapped
    route (None permission) refuses every role."""
    return role_can(role, route_required_permission(method, path))


def reviewer_can_route(method: str, path: str) -> bool:
    """True iff the read-only reviewer role may call ``(method, path)``."""
    return role_can_route(REVIEWER_ROLE, method, path)


@dataclass(frozen=True)
class RouteAudit:
    method: str
    path: str
    permission: str | None
    reviewer_allowed: bool
    mutating: bool


def reviewer_readonly_report() -> list[str]:
    """Return a list of route errors that violate reviewer-read-only. Empty == compliant.

    Two rules over the whole table:
      1. A MUTATING route must NOT be reviewer-reachable (a write the reviewer can do is a
         read-only violation).
      2. A GET route must require exactly ``read`` and BE reviewer-reachable (a read route
         the reviewer cannot reach is a mis-mapping; a GET requiring a write permission is
         too).
    """
    errors: list[str] = []
    for (method, path), perm in ROUTE_PERMISSIONS.items():
        mutating = method.upper() in MUTATING_METHODS
        reviewer_ok = reviewer_can_route(method, path)
        if mutating and reviewer_ok:
            errors.append(
                f"{method} {path} is mutating but reachable by the reviewer "
                f"(perm={perm!r}) — reviewer must be read-only"
            )
        if not mutating:
            if perm != READ:
                errors.append(
                    f"{method} {path} is a read route but requires {perm!r}, not {READ!r}"
                )
            if not reviewer_ok:
                errors.append(
                    f"{method} {path} is a read route the reviewer cannot reach (perm={perm!r})"
                )
    return errors


def audit_routes() -> list[RouteAudit]:
    """A per-route audit table for reviewer/CLI display."""
    out: list[RouteAudit] = []
    for (method, path), perm in sorted(ROUTE_PERMISSIONS.items()):
        out.append(
            RouteAudit(
                method=method,
                path=path,
                permission=perm,
                reviewer_allowed=reviewer_can_route(method, path),
                mutating=method.upper() in MUTATING_METHODS,
            )
        )
    return out
