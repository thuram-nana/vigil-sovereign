"""Shard routing resolver — the PURE control-plane map from a tenant to its shard's store/root (Front C S2b/S2c).

Given a tenant's owner-signed :class:`~sigil.governor.shard_assignment.ShardPlacement`, this resolves WHERE that
tenant's engine runs — its dedicated ``CRUCIBLE_ROOT`` and ``CRUCIBLE_TENANT`` on the owning shard — and WHICH
per-shard job queue drains its work. It is deliberately a PURE resolver (no store, no network): the control plane
reads the assignment once, then calls :func:`resolve` to direct the tenant's requests/jobs; the actual cross-HOST
dispatch + copy is the deploy layer.

COMPOSES WITH ``assert_tenant_fleet_isolated`` (``engine/crucible/framework/v2/common/tenant.py``, the merged D2
primitive). That offense-side guard FAILS CLOSED at a fleet worker's startup unless the worker is sharded
(``CRUCIBLE_TENANT`` set) AND its ``CRUCIBLE_ROOT`` is DEDICATED to that one tenant (one root per tenant). This
resolver produces exactly that env — ``crucible_root = <shard base>/<tenant_id>`` and ``crucible_tenant =
tenant_id`` — so a worker launched from a route PASSES the fleet guard by construction. FATAL-2 forbids importing
the offense ``tenant.py`` here, so :func:`assert_route_isolated_from` re-states the SOVEREIGN half of that invariant
(two tenants' roots are physically disjoint) and is mutation-tested, exactly as ``governor/orgs.py`` replicates the
engine's ``_TENANT_RE`` under a drift guard.

FLAG-GATED (``config.multi_shard_enabled`` / ``VIGIL_MULTI_SHARD``), DEFAULT-OFF + byte-identical:
  * OFF ⇒ :func:`resolve` returns the historical SINGLETON — the single shared ``CRUCIBLE_ROOT``, un-sharded
    (``CRUCIBLE_TENANT`` empty) — for EVERY tenant, REGARDLESS of any assignment (the assignment is never
    consulted); nothing is routed. This is the pre-S2 deployment, unchanged.
  * ON ⇒ an ASSIGNED tenant resolves to its shard's dedicated root; an UNASSIGNED tenant is REFUSED
    (:class:`UnassignedTenantError`), never guessed onto a default shard.

FATAL-2: SOVEREIGN-only (``assert_no_offense``); stdlib + sovereign siblings only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from .. import config  # noqa: E402
from .shard_assignment import ShardPlacement  # noqa: E402

_QUEUE_SUBDIR = "queue"   # the per-shard SecurityJobQueue root lives under the shard's base dir (S2c)


class RoutingError(ValueError):
    """Base class for a fail-closed routing refusal."""


class UnassignedTenantError(RoutingError):
    """The flag is ON and the tenant has no active shard assignment. Fail-closed: a request for an unassigned
    tenant is REFUSED, never defaulted onto a shard (which would commingle it with that shard's tenants)."""


class ShardTopologyError(RoutingError):
    """An active assignment names a ``shard_id`` the deploy topology does not know a base directory for. Fail-closed:
    the control plane refuses rather than invent a path."""


class StaleRouteError(RoutingError):
    """A route minted at an older epoch/shard than the tenant's current active placement. Fail-closed: a consumer
    holding this route must re-resolve (the placement has moved — a live migration bumped the epoch)."""


@dataclass(frozen=True)
class ShardTopology:
    """The deploy map ``shard_id -> base directory`` (where that shard/host stores its tenants' roots). Pure data;
    at deploy it comes from config, and offline tests pass two in-process directories (two 'shards')."""
    bases: Mapping[str, Path]

    def base_for(self, shard_id: str) -> Optional[Path]:
        b = self.bases.get(shard_id)
        return None if b is None else Path(b)


@dataclass(frozen=True)
class ShardRoute:
    """Where a tenant's engine runs and which queue drains it.

      * ``singleton`` True ⇒ the historical un-sharded default (flag OFF): ``crucible_tenant`` is empty and
        ``crucible_root`` is the single shared root; nothing was routed.
      * ``singleton`` False ⇒ a routed tenant: ``crucible_root = shard_base/<tenant_id>`` (dedicated per tenant, so
        it satisfies ``assert_tenant_fleet_isolated``) and ``crucible_tenant = tenant_id``.
    """
    tenant_id: str
    shard_id: str
    epoch: int
    shard_base: Path
    crucible_root: Path
    crucible_tenant: str
    singleton: bool

    @property
    def queue_root(self) -> Path:
        """The per-shard job-queue root (a ``SecurityJobQueue`` is built here). A shard drains ONLY this root, and a
        tenant's job is enqueued to its OWN shard's root — so a shard only ever drains its own tenants' jobs."""
        return self.shard_base / _QUEUE_SUBDIR


def _singleton(tenant_id: str, default_root: Path) -> ShardRoute:
    """The flag-OFF historical route: the single shared root, un-sharded. The assignment is NEVER consulted, so an
    assigned and an unassigned tenant resolve identically — the byte-identical pre-S2 behaviour."""
    root = Path(default_root)
    return ShardRoute(tenant_id=tenant_id, shard_id="", epoch=0, shard_base=root, crucible_root=root,
                      crucible_tenant="", singleton=True)


def resolve(tenant_id: str, *, placement: Optional[ShardPlacement], topology: ShardTopology, default_root: Path,
            multi_shard: Optional[bool] = None) -> ShardRoute:
    """Resolve ``tenant_id`` to its :class:`ShardRoute`. ``placement`` is the tenant's current active assignment
    (``None`` if unassigned); ``multi_shard`` overrides the flag for a caller that already read it (else the
    ``VIGIL_MULTI_SHARD`` env is read). Pure.

    OFF ⇒ the :func:`_singleton` default, regardless of ``placement`` (byte-identical). ON ⇒ the assigned shard's
    dedicated root, or fail-closed (:class:`UnassignedTenantError` / :class:`ShardTopologyError`)."""
    enabled = config.multi_shard_enabled() if multi_shard is None else bool(multi_shard)
    if not enabled:
        return _singleton(tenant_id, default_root)
    if placement is None:
        raise UnassignedTenantError(
            f"tenant {tenant_id!r} has no active shard assignment — refusing to route it (fail-closed; a request "
            f"for an unassigned tenant is never defaulted onto a shard)")
    base = topology.base_for(placement.shard_id)
    if base is None:
        raise ShardTopologyError(
            f"tenant {tenant_id!r} is assigned to shard {placement.shard_id!r} but the deploy topology has no base "
            f"directory for it — refusing to route (fail-closed)")
    return ShardRoute(tenant_id=placement.tenant_id, shard_id=placement.shard_id, epoch=int(placement.epoch),
                      shard_base=base, crucible_root=base / placement.tenant_id,
                      crucible_tenant=placement.tenant_id, singleton=False)


def resolve_for(registry, tenant_id: str, *, topology: ShardTopology, default_root: Path,
                multi_shard: Optional[bool] = None) -> ShardRoute:
    """Convenience: read the tenant's placement from a :class:`~sigil.governor.shard_assignment.ShardAssignmentRegistry`
    (when routing is on) and :func:`resolve`. OFF ⇒ the registry is NEVER read (byte-identical singleton)."""
    enabled = config.multi_shard_enabled() if multi_shard is None else bool(multi_shard)
    placement = registry.placement(tenant_id) if enabled else None
    return resolve(tenant_id, placement=placement, topology=topology, default_root=default_root,
                   multi_shard=enabled)


def crucible_env(route: ShardRoute) -> "dict[str, str]":
    """The environment a fleet launcher sets before exec'ing the tenant's offense worker: ``CRUCIBLE_ROOT`` and
    (for a routed tenant) ``CRUCIBLE_TENANT``. The worker's ``assert_tenant_fleet_isolated`` then enforces the
    one-root-per-tenant claim at startup. For the singleton default, ``CRUCIBLE_TENANT`` is omitted (un-sharded)."""
    env = {"CRUCIBLE_ROOT": str(route.crucible_root)}
    if route.crucible_tenant:
        env["CRUCIBLE_TENANT"] = route.crucible_tenant
    return env


def _resolved(p: Path) -> Path:
    """Resolve a path for disjointness comparison without requiring it to exist (``strict=False``)."""
    try:
        return p.resolve()
    except OSError:
        return Path(os.path.normpath(str(p)))


def _nested(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def assert_route_isolated_from(a: ShardRoute, b: ShardRoute) -> None:
    """Raise ``AssertionError`` unless routes ``a`` and ``b`` have PHYSICALLY DISJOINT ``crucible_root``s — not
    equal, and neither nested inside the other. This is the SOVEREIGN half of the offense-side
    ``assert_tenant_fleet_isolated`` (one ``CRUCIBLE_ROOT`` per tenant): because each routed tenant's root is
    ``shard_base/<tenant_id>`` and a tenant id is one path component, two distinct tenants are disjoint by
    construction — this guard makes that checkable offline (FATAL-2 forbids importing the offense guard)."""
    ra, rb = _resolved(a.crucible_root), _resolved(b.crucible_root)
    if ra == rb or _nested(ra, rb) or _nested(rb, ra):
        raise AssertionError(
            f"shard-route isolation violated: tenant {a.tenant_id!r}'s root {ra} is not disjoint from tenant "
            f"{b.tenant_id!r}'s root {rb} (one CRUCIBLE_ROOT per tenant — assert_tenant_fleet_isolated would fail)")


def route_is_current(route: ShardRoute, placement: Optional[ShardPlacement]) -> bool:
    """True iff ``route`` still matches the tenant's current active ``placement`` (same shard AND epoch). A route to
    a different shard, or at a lower epoch, is STALE — a live migration bumped the placement past it."""
    if placement is None:
        return False
    return route.shard_id == placement.shard_id and route.epoch == int(placement.epoch)


def assert_route_current(route: ShardRoute, placement: Optional[ShardPlacement]) -> None:
    """Fail-closed consumer guard: raise :class:`StaleRouteError` unless ``route`` is the current placement. A
    consumer that cached a route before a migration must re-resolve rather than dispatch to the old shard."""
    if not route_is_current(route, placement):
        raise StaleRouteError(
            f"route for tenant {route.tenant_id!r} (shard {route.shard_id!r}, epoch {route.epoch}) is stale — the "
            f"current placement is {placement!r}; re-resolve before dispatching (the epoch bump moved it)")


def shard_owns_tenant(route: ShardRoute, shard_id: str) -> bool:
    """True iff ``route``'s tenant belongs to ``shard_id`` — the per-shard drain check: a shard processes a job only
    for a tenant its own assignment places on it (mirrors ``jobs/authorize._reconcile_tenant`` — isolation only
    gets stronger)."""
    return (not route.singleton) and route.shard_id == shard_id


def assert_job_targets_shard(route: ShardRoute, draining_shard_id: str) -> None:
    """Fail-closed: raise :class:`RoutingError` unless ``route``'s tenant is placed on ``draining_shard_id``. A job
    for a tenant another shard owns is refused — a shard drains only its own tenants' jobs."""
    if not shard_owns_tenant(route, draining_shard_id):
        raise RoutingError(
            f"shard {draining_shard_id!r} must not drain a job for tenant {route.tenant_id!r} (placed on shard "
            f"{route.shard_id!r}) — refusing (fail-closed, per-shard tenant isolation)")
