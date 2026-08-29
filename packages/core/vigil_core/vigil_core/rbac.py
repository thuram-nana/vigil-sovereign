"""vigil_core.rbac — the ONE role→permission vocabulary shared by both trust domains.

Claim 6 gave the sovereign plane (`apps/sigil/sigil/governor/accounts.py`) an enforced multi-user RBAC:
`viewer < analyst < operator < owner`, a cumulative permission set per role, and `role_can()`. That
vocabulary lived ONLY sovereign-side, so the offense console (`framework.v2.console.server`) could not
reuse it — the console is offense-side and MUST NEVER import `sigil.*` (FATAL-2 / sovereignty §12). This
module promotes the vocabulary into `vigil_core`, which BOTH domains may import (the offense console
already does `from vigil_core import TrustRoot`; the sovereign side reaches vigil_core through
`sigil/reuse`). The sovereign `accounts.py` now RE-EXPORTS `ROLES`/`PERMISSIONS`/`role_can` from here so
there is exactly one source of truth; it keeps its own `PERMISSION_BY_ACTION` for the sovereign action
surface, and this module adds `OFFENSE_ACTION_PERM` for the offense console's POST routes.

PURE STDLIB, namespace-pure: this module imports NOTHING (no crypto, no spine, no framework/strix/sigil).
It is a table plus one predicate — the load-bearing property is that it can be imported from either side
without dragging a dependency across the trust boundary.

DEFAULT-DENY is the whole posture: `role_can(role, None)` is False, an unknown role has no permissions,
and `offense_perm_for()` returns None (⇒ deny) for any route not explicitly mapped.
"""
from __future__ import annotations

from typing import Optional

# Roles, ordered by privilege rank (index = rank). "owner" is the trust-root key-holder / the direct
# console-token holder — it is the ceiling, never a grantable bearer role (single-owner doctrine). This
# ordering is IDENTICAL to the sovereign `accounts.ROLES`, which now imports it from here.
ROLES = ("viewer", "analyst", "operator", "owner")
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}

# The permission vocabulary. Cumulative: owner ⊇ operator ⊇ analyst ⊇ viewer. These frozensets are the
# canonical definition the sovereign side re-exports — the exact strings `accounts.PERMISSION_BY_ACTION`
# and this module's `OFFENSE_ACTION_PERM` map to. Keep them in lockstep with any sovereign action mapping.
_VIEWER = frozenset({"read"})
_ANALYST = _VIEWER | {"queue_proposal"}
_OPERATOR = _ANALYST | {"run_engagement", "approve_a2", "toggle_guard", "config_nonsecret"}
_OWNER = _OPERATOR | {"approve_a3", "kill_release", "promote", "secrets", "offense_authority",
                      "manage_users", "toggle_protected_guard"}
PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": _VIEWER, "analyst": _ANALYST, "operator": _OPERATOR, "owner": _OWNER,
}


def role_can(role: Optional[str], perm: Optional[str]) -> bool:
    """True iff `role` carries `perm`. DEFAULT-DENY: an unmapped permission (None/"") refuses, and an
    unknown role has no permissions. This is the one predicate the whole gate turns on — the sovereign
    admission gate and the offense console per-action gate both call THIS."""
    if not perm:
        return False
    return perm in PERMISSIONS.get(role or "", frozenset())


# ==================================================================================================
# OFFENSE per-action permission map (Slice S1 — console; W16-12 — the loopback gated api).
#
# Every state-changing POST route the offense HTTP surfaces dispatch is mapped to the permission a
# caller's role must carry. It covers BOTH offense backends behind the `vigil up` proxy:
#   * the offense CONSOLE (`framework.v2.console.server.do_POST`) — the read + SSE + run-control plane;
#   * the offense gated API (`framework.v2.api.server.do_POST`) — the `/api/v1/*` external action plane
#     (W16-12), whose two POST routes (`/api/v1/tool/invoke`, `/api/v1/import`) are added below.
# The two backends use disjoint path prefixes (console `/api/*`, api `/api/v1/*`), so ONE map with
# exact keys is unambiguous — and there is exactly one source of truth for "offense route → permission".
# TWO tiers:
#   * OPERATOR-tier (`run_engagement`) — ordinary launch / run-control / edit / session / chat / label /
#     read-recompute (replay/reverify/verify-cert/planner/intel/benchmark) routes. An operator+ may run
#     engagements; these are the everyday offense actions.
#   * OWNER-tier (`offense_authority`, an owner-only permission) — the DANGEROUS routes: minting a charter
#     authority + replaying its usage ledger, executing a local command, APPLYING an auto-patch, standing up
#     the AEGIS gateway, INSTALLING host packages, and CREATING docker services. Each of these either
#     executes on the host, changes durable governance/authority state, or provisions infrastructure — so it
#     is lifted above operator to the owner ceiling.
#   * PROTECTIVE (read-tier) — tripping the kill-switch only HALTS (never clears), so it is the LOWEST tier
#     (mirrors sovereign `kill: read`); an emergency-stop must never be gated above the operator watching a
#     live engagement.
#
# DEFAULT-DENY: a route absent from this map resolves (via `offense_perm_for`) to None ⇒ `role_can` False
# ⇒ 403. A future POST route refuses under a valid hop assertion until it is explicitly mapped here.
# ==================================================================================================
_READ = "read"                 # any authenticated principal (viewer+) — the LOWEST tier
_RUN = "run_engagement"        # operator+ (the coarse proxy floor uses the same permission)
_OWN = "offense_authority"     # owner-only

OFFENSE_ACTION_PERM: dict[str, str] = {
    # ---- operator-tier: ordinary run / edit / session / chat / launch / read-recompute --------------
    "/api/token-budgets": _RUN,
    "/api/run/*/cancel": _RUN,
    "/api/run/*/retry": _RUN,
    "/api/instruct": _RUN,
    "/api/codebase/edit": _RUN,
    "/api/codebase/apply": _RUN,
    "/api/codebase/test": _RUN,
    "/api/launch/preview": _RUN,
    "/api/launch/assessment": _RUN,
    "/api/launch/cloud": _RUN,
    "/api/brain/propose": _RUN,   # B3/H10 propose-only planning (spawns --plan-only; executes nothing)
    "/api/replay": _RUN,
    "/api/reverify/*": _RUN,
    "/api/proof/export": _RUN,
    "/api/dossier/*/build": _RUN,
    "/api/verify-cert": _RUN,
    "/api/verify": _RUN,                # Wave 2: run `vigil verify-integrity/verify-ledger/verify` (read-recompute)
    "/api/doctor": _RUN,                # Wave 2b: run `vigil doctor --json` (install/health preflight, read-only)
    "/api/daemons/status": _READ,       # Wave 4: read-only daemon/unit health strip (`vigil alerts --status`)
    "/api/emergency-stop": _READ,       # Wave 4: ENTER/STATUS restricted mode — halt is the safe direction (mirrors kill trip)
    "/api/emergency-stop/leave": _OWN,  # Wave 4: LIFT restricted mode — owner-only (restores full operation)
    # `panic` is MORE destructive than `down` (it masks the unit + kills cadence) yet sits at a LOWER tier
    # (read vs run_engagement) ON PURPOSE: both are halt-direction and neither enables offense or restores
    # operation, so the safe-to-HALT convention (== killswitch trip == read) governs, not the blast radius.
    # Clearing containment is always a deliberate owner CLI act (unmask + re-enable), never a UI tier.
    "/api/panic": _READ,                # Wave 4: emergency HARD-STOP — any principal may HALT; clearing is CLI-only
    "/api/down": _RUN,                  # Wave 4: contain the running console — operator+
    "/api/services/down": _OWN,         # Wave 4: gateway lifecycle down — owner (mirrors /api/services/up)
    "/api/services/render": _OWN,       # Wave 4: rewrite the gateway compose file — owner
    "/api/knowledge/gitsync": _RUN,
    "/api/evolve/*/tick": _RUN,
    "/api/knowledge/*/deeplearn": _RUN,
    "/api/feed/*/pull": _RUN,
    "/api/feed/*/start": _RUN,
    "/api/feed/*/stop": _RUN,
    "/api/benchmark/run": _RUN,
    "/api/planner/run": _RUN,
    "/api/intel/run": _RUN,
    "/api/label/engagement": _RUN,
    "/api/label/run": _RUN,
    "/api/session/create": _RUN,
    "/api/session/rename": _RUN,
    "/api/session/delete": _RUN,
    "/api/session/connect": _RUN,
    "/api/session/disconnect": _RUN,
    "/api/chat/stream": _RUN,
    "/api/chat/send": _RUN,
    "/api/chat/attach/begin": _RUN,
    "/api/chat/attach/chunk": _RUN,
    "/api/chat/attach/finish": _RUN,
    "/api/chat/attach/abort": _RUN,
    "/api/chat/attach/remove": _RUN,
    "/api/chat/rename": _RUN,
    "/api/chat/delete": _RUN,
    "/api/terminal/dryrun": _RUN,
    "/api/terminal/propose": _RUN,
    "/api/aegis/stop": _RUN,
    # ---- offense gated API (framework.v2.api.server) — the loopback /api/v1 external action plane
    #      (W16-12). Both POST routes are ordinary run-tier offense actions: invoking a tool through the
    #      fail-closed gate chain (the api exposes only the SAFE registry — reverify + import), and
    #      importing a third-party report as UNVERIFIED leads (a mutation of the intel store). Neither
    #      executes on the host, mints authority, or provisions infra, so both sit at operator-tier
    #      `run_engagement` — matching the coarse proxy floor (a viewer/analyst is refused BOTH here and
    #      at the proxy) and the console's sibling read-recompute / knowledge-sync routes.
    "/api/v1/tool/invoke": _RUN,
    "/api/v1/import": _RUN,
    # ---- protective: tripping the kill-switch HALTS an engagement (idempotent, never CLEARS). An
    #      emergency-stop must be broadly available, gated to the LOWEST privilege — mirroring the sovereign
    #      `kill: read` convention (accounts.PERMISSION_BY_ACTION). Any authenticated principal may halt;
    #      only `release`/un-halt is owner. (The proxy coarse floor still independently gates offense POSTs
    #      at operator+, so through `vigil up` the practical floor is operator; the map itself is read so the
    #      vocabulary stays in lockstep with sovereign and an operator is never denied the emergency stop.)
    "/api/killswitch/*/trip": _READ,
    # ---- owner-tier: host exec / infra provisioning / patch apply / authority ------------------------
    "/api/authority/provision": _OWN,
    "/api/authority/ledger": _OWN,
    "/api/terminal/run": _OWN,
    "/api/remediate/*/apply": _OWN,
    "/api/aegis/setup": _OWN,
    "/api/tools/install": _OWN,
    "/api/services/up": _OWN,
}

# The exact-match route keys (no wildcard). Membership test is O(1) and case-sensitive.
_EXACT_KEYS = frozenset(k for k in OFFENSE_ACTION_PERM if "*" not in k)

# The wildcard patterns, as (prefix, suffix, route_key). This ORDER + logic MIRRORS `do_POST`'s dispatch
# (prefix/suffix `startswith`/`endswith` branches), so the permission a path resolves to here is the
# permission for the branch that path will actually take. A suffix of "" means prefix-only.
_PATTERNS = (
    ("/api/run/", "/cancel", "/api/run/*/cancel"),
    ("/api/run/", "/retry", "/api/run/*/retry"),
    ("/api/remediate/", "/apply", "/api/remediate/*/apply"),
    ("/api/dossier/", "/build", "/api/dossier/*/build"),
    ("/api/evolve/", "/tick", "/api/evolve/*/tick"),
    ("/api/knowledge/", "/deeplearn", "/api/knowledge/*/deeplearn"),
    ("/api/feed/", "/pull", "/api/feed/*/pull"),
    ("/api/feed/", "/start", "/api/feed/*/start"),
    ("/api/feed/", "/stop", "/api/feed/*/stop"),
    ("/api/killswitch/", "/trip", "/api/killswitch/*/trip"),
    ("/api/reverify/", "", "/api/reverify/*"),          # prefix-only (registered after /api/replay)
)


def offense_route_key(path: str) -> Optional[str]:
    """Resolve a concrete console-side POST path (e.g. `/api/killswitch/s1/trip`) to its canonical route
    key in `OFFENSE_ACTION_PERM`, or None if the path matches no mapped route. Exact keys win over
    wildcard patterns (so `/api/knowledge/gitsync` is not swallowed by the `/api/knowledge/*/deeplearn`
    pattern), matching `do_POST`'s dispatch precedence."""
    if path in _EXACT_KEYS:
        return path
    for prefix, suffix, key in _PATTERNS:
        if path.startswith(prefix) and (path.endswith(suffix) if suffix else True):
            return key
    return None


def offense_perm_for(path: str) -> Optional[str]:
    """The permission a POST to `path` requires, or None ⇒ DEFAULT-DENY (an unmapped route). The console
    gate feeds this straight into `role_can`, so an unmapped route (None) refuses every role."""
    key = offense_route_key(path)
    if key is None:
        return None
    return OFFENSE_ACTION_PERM.get(key)
