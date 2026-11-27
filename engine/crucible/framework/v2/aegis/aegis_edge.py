"""
aegis.aegis_edge — AS-6c: the AEGIS EDGE automation layer — a declarative EDGE reconciler over AS-6a.

The INFRA-chain piece (26 -> 6c -> 34) that AUTOMATES the per-(org,host) gateway EDGE: the CloudFront ->
VPC-origin/ALB-target-group -> gateway-unit path AS-26 declares in ``infra/aws/aegis-staging`` and the
per-(org,host) edge secret the AS-26 relay guard verifies (``aegis_relay_guard.assert_cloudfront_not_bypassed``).
Where AS-6a (``aegis_fleet``) places and rolls the WORKERS, AS-6c converges the EDGE that fronts them: it
reads the AS-6a ``FleetState`` and, for each desired (org, host) edge, provisions/rotates the per-(org,host)
edge secret and binds the distribution's origin at the gateway unit AS-6a has proven HEALTHY — with NO
operator step, idempotently, fail-closed.

DOCTRINE (non-negotiable, enforced here and tested):
  * DEFENSIVE + CONTROL-PLANE ONLY. This automates the operator's OWN managed edge; it never attacks and
    never reaches a tenant's traffic. It lives in the ENGINE plane beside ``aegis_fleet`` (FATAL-2: it
    imports only ``aegis_fleet`` (same plane), ``vigil_core`` + stdlib + ``..common`` — never ``sigil``).
  * NEVER BIND AN UNPROVEN ORIGIN. An edge is bound to a gateway unit ONLY when that unit is HEALTHY in the
    AS-6a ``FleetState`` (fail closed). An absent / STARTING / DRAINING / RETIRED backing unit REFUSES the
    bind, so the edge never cuts traffic over to a unit AS-6a has not proven healthy; during a unit rollout
    the edge keeps serving its current, proven origin until the replacement is HEALTHY.
  * NEVER OPEN THE ORIGIN WITHOUT A PROVISIONED EDGE SECRET. The per-(org,host) edge secret (the
    ``X-Vigil-Edge-Secret`` CloudFront injects and the origin verifies) must be provisioned at the desired
    epoch BEFORE the origin is bound; a missing / refused provisioning REFUSES the bind — the control-plane
    mirror of the AS-26 guard's "a blank expected secret refuses everything" (misconfiguration must not open
    the origin).
  * ONLY SIGIL TT ORIGINS BEFORE AS-2g. Reusing the AS-6a guard rail, the edge admits ONLY the internal
    SIGIL test-tenant origins and REFUSES any other tenant's edge (fail closed).
  * DETERMINISM. No wall-clock, no RNG. ``now`` is injected; origin ids, secret ids and action ids are
    content hashes of canonical fields. The same desired + fleet + actual + now yields a byte-identical result.
  * IDEMPOTENT. A converged edge takes NO action: the edge secret is not re-provisioned and the origin is
    not re-bound on a steady reconcile tick (the AS-6a "converged => no action" contract, carried to the edge).
  * DEFAULT-OFF. The whole reconciler is gated behind ``VIGIL_AEGIS_EDGE`` (strict, fail-closed, DEFAULT
    OFF — the ``aegis_fleet`` flag pattern). With the flag off the reconciler is INERT: it binds and retires
    nothing and returns a fixed ``disabled`` result (flag-off golden byte-identical).
  * LIVE EDGE OPS ARE OWNER-PROVIDED. The real AWS edge control plane (the CloudFront distribution/origin
    update, the ALB target-group register/deregister with connection draining) and the real edge-secret
    store (AWS Secrets Manager / SSM) are owner-provided and deploy-gated (VIGIL-LIMIT:LIMIT-aegis-edge-automation-deploy-gated);
    offline BOTH are injected in-memory doubles through :class:`EdgeControlPlane` / :class:`EdgeSecretStore`,
    so the reconcile LOGIC is exercised deterministically without an AWS call (the AS-6a ``SnapshotSink`` /
    ``SsmCredentialChannel`` seam pattern).

Nothing under ``aegis/__init__`` or ``framework.v2.__main__`` imports this module (it is off the gate path,
like ``aegis_fleet`` and ``tt_rig``), so ``make gate`` stays byte-identical. Its tests import it directly.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping, Optional, Protocol, runtime_checkable

from ..common.logging import get_logger

# aegis_fleet is the AS-6a control-plane peer in the SAME engine plane (FATAL-2 safe: it imports only
# vigil_core + stdlib + ..common). The edge reconciler CONSUMES its fleet types and guard rails, never
# re-codes them.
from .aegis_fleet import (
    SIGIL_TT_TENANTS,
    FleetError,
    FleetState,
    RoutedWorker,
    WorkerHealth,
    WorkerKind,
    worker_kind_spec,
)

_log = get_logger("aegis.edge")

__all__ = [
    "EDGE_ENV", "edge_enabled",
    "EdgeError", "EdgeReconcileError",
    "EdgeHealth", "DesiredEdge",
    "EdgeSecretStore", "EdgeControlPlane",
    "BoundEdge", "EdgeState",
    "EdgeAction", "EdgeRefusal", "EdgeReconcileResult",
    "EdgeReconciler",
    "desired_edges_for_fleet",
]


# ==================================================================================================
# Default-OFF flag (the aegis_fleet flag pattern — strict, fail-closed, DEFAULT OFF).
# ==================================================================================================
EDGE_ENV = "VIGIL_AEGIS_EDGE"


def edge_enabled() -> bool:
    """The AS-6c edge reconciler flag — strict, fail-closed, DEFAULT OFF. Only an explicit affirmative
    token turns the reconciler on; anything else (unset, typo, empty) keeps it INERT (the managed edge is
    not bound/retired by this process)."""
    return (os.environ.get(EDGE_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


# ==================================================================================================
# Exceptions — every one is fail-closed (REFUSE), never a silent pass.
# ==================================================================================================
class EdgeError(Exception):
    """An edge-automation contract was violated and the operation was REFUSED (fail-closed)."""


class EdgeReconcileError(EdgeError):
    """The reconciler was constructed or called with a malformed dependency/argument (fail-closed)."""


# ==================================================================================================
# Health + the desired/actual edge records + the edge state.
# ==================================================================================================
class EdgeHealth(str, Enum):
    """The per-edge health state this slice tracks (the edge-lifecycle mirror of AS-6a's WorkerHealth)."""

    BINDING = "binding"    # the origin bind was attempted but not yet confirmed (retry next pass)
    BOUND = "bound"        # the origin is bound to a HEALTHY unit and the edge secret is provisioned
    DRAINING = "draining"  # the origin is being drained (rollout cutover or teardown) — not yet torn down
    RETIRED = "retired"    # drained, origin released, edge secret scheduled for destruction


@dataclass(frozen=True)
class DesiredEdge:
    """One desired (org, host) gateway edge the control plane wants converged. ``desired_state`` is
    ``present`` (bind the edge to the org/host's HEALTHY gateway unit) or ``absent`` (drain + retire it).
    The backing unit is the AS-6a ``units`` worker for the same (org, host, replica); ``secret_epoch`` is
    the per-(org,host) edge-secret epoch the edge must carry (a bump rotates the secret)."""

    org: str
    host: str
    distribution_id: str
    desired_state: str = "present"
    secret_epoch: int = 1
    backing_kind: WorkerKind = WorkerKind.UNITS
    replica_index: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.org, str) or not self.org:
            raise EdgeError("org must be a non-empty str")
        if not isinstance(self.host, str) or not self.host:
            raise EdgeError("host must be a non-empty str")
        if not isinstance(self.distribution_id, str) or not self.distribution_id:
            raise EdgeError("distribution_id must be a non-empty str")
        if self.desired_state not in ("present", "absent"):
            raise EdgeError(f"desired_state must be 'present' or 'absent', got {self.desired_state!r}")
        if not isinstance(self.secret_epoch, int) or isinstance(self.secret_epoch, bool) or self.secret_epoch < 1:
            raise EdgeError("secret_epoch must be a positive int")
        if not isinstance(self.backing_kind, WorkerKind):
            raise EdgeError("backing_kind must be a WorkerKind")
        if not isinstance(self.replica_index, int) or isinstance(self.replica_index, bool) or self.replica_index < 0:
            raise EdgeError("replica_index must be a non-negative int")

    @property
    def key(self) -> str:
        """The stable deterministic edge key (org, host)."""
        return f"edge|{self.org}|{self.host}"

    @property
    def backing_key(self) -> str:
        """The AS-6a fleet key of the gateway unit this edge fronts (``units|org|host|replica``)."""
        return f"{self.backing_kind.value}|{self.org}|{self.host}|{self.replica_index}"


@dataclass(frozen=True)
class BoundEdge:
    """The actual state of one edge. Immutable; the reconciler produces a NEW one on every transition.
    ``origin_id`` is a content hash of the backing unit identity (key, epoch, image digest) the edge points
    at — so a unit ROLLOUT (AS-6a bumps the unit epoch) changes it and drives an edge cutover."""

    key: str
    org: str
    host: str
    distribution_id: str
    origin_id: str
    backing_key: str
    secret_epoch: int
    secret_status: str        # "provisioned" (bound/binding) | "none" (retired/tombstone)
    health: EdgeHealth
    bound_at: float


@dataclass(frozen=True)
class EdgeState:
    """The declarative edge state: key -> BoundEdge, ordered by key. Immutable; the reconciler returns a
    NEW state each pass (the AS-6a ``FleetState`` mirror)."""

    edges: tuple[BoundEdge, ...] = ()

    def by_key(self) -> dict[str, BoundEdge]:
        return {e.key: e for e in self.edges}

    def get(self, key: str) -> Optional[BoundEdge]:
        return self.by_key().get(key)

    def active(self) -> tuple[BoundEdge, ...]:
        """Edges that are not retired, in key order."""
        return tuple(sorted((e for e in self.edges if e.health != EdgeHealth.RETIRED), key=lambda e: e.key))

    @staticmethod
    def from_edges(edges: "Iterable[BoundEdge]") -> "EdgeState":
        return EdgeState(edges=tuple(sorted(edges, key=lambda e: e.key)))


# ==================================================================================================
# Injected ports — the live AWS edge plane is owner-provided; offline these are in-memory doubles.
# ==================================================================================================
@runtime_checkable
class EdgeSecretStore(Protocol):
    """The per-(org,host) edge-secret store the reconciler provisions/destroys an epoch's secret through.
    ``provision`` returns True iff the secret for ``(org, host, epoch)`` is durably stored; ``destroy``
    returns True iff it is removed. The REAL store (AWS Secrets Manager / SSM, matching the AS-26
    ``aegis-staging/edge/<tenant>`` secrets) is owner-provided; offline it is an injected in-memory double,
    so the provisioning PATH is exercised deterministically without an AWS call."""

    def provision(self, org: str, host: str, epoch: int) -> bool: ...

    def destroy(self, org: str, host: str, epoch: int) -> bool: ...


@runtime_checkable
class EdgeControlPlane(Protocol):
    """The edge control plane the reconciler binds/drains a distribution's origin through. ``bind_origin``
    points the distribution's origin at ``origin_id`` (register the HEALTHY gateway unit as the active ALB
    target) and returns True iff confirmed; ``drain_origin`` deregisters an origin with CONNECTION DRAINING
    and returns True iff confirmed. The REAL plane (CloudFront distribution/origin update + ALB
    target-group register/deregister) is owner-provided; offline it is an injected in-memory double, so the
    bind / rollout / drain ORDER is exercised deterministically without an AWS call."""

    def bind_origin(self, distribution_id: str, origin_id: str) -> bool: ...

    def drain_origin(self, distribution_id: str, origin_id: str) -> bool: ...


def _content_id(*parts: object) -> str:
    """A deterministic sha256 content id over canonical JSON of ``parts``. No RNG, no wall-clock (any time
    component is the injected ``now``), so the same inputs hash to the same id."""
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _origin_id(unit: RoutedWorker) -> str:
    """The content-addressed origin identity the edge points at: the backing unit's (key, epoch, image
    digest). A unit rollout (epoch/image bump) changes this, which is exactly what drives an edge cutover."""
    return _content_id("origin", unit.key, unit.epoch, unit.image_digest)


# ==================================================================================================
# Reconcile actions / refusals / result.
# ==================================================================================================
@dataclass(frozen=True)
class EdgeAction:
    """One deterministic action the reconciler took. ``action_id`` is a content hash so the same desired +
    fleet + actual + now produces byte-identical actions."""

    verb: str                 # "bind" | "rollout" | "drain" | "retire" | "provision_secret" | "rotate_secret" | "destroy_secret"
    edge_key: str
    detail: str
    at: float
    action_id: str


@dataclass(frozen=True)
class EdgeRefusal:
    """A desired edge the reconciler REFUSED to bind/retire, with a stable machine code (fail closed)."""

    edge_key: str
    code: str                 # "origin_not_sigil_tt" | "unknown_backing_kind" | "backing_unit_not_healthy"
    #                           | "edge_secret_unavailable" | "edge_secret_refused" | "origin_bind_failed"
    #                           | "drain_failed"
    reason: str


@dataclass(frozen=True)
class EdgeReconcileResult:
    """The outcome of one reconcile pass: the new state, the ordered actions and the refusals. ``disabled``
    is True when the DEFAULT-OFF flag is off (the inert result)."""

    disabled: bool
    state: EdgeState
    actions: tuple[EdgeAction, ...] = ()
    refusals: tuple[EdgeRefusal, ...] = ()

    def bound_keys(self) -> tuple[str, ...]:
        return tuple(e.key for e in self.state.active() if e.health == EdgeHealth.BOUND)

    def retired_keys(self) -> tuple[str, ...]:
        return tuple(sorted(e.key for e in self.state.edges if e.health == EdgeHealth.RETIRED))

    def golden(self) -> dict:
        """A deterministic, JSON-safe projection used by the flag-off byte-identity test and by auditors.
        Pure function of the result — no wall-clock, no RNG."""
        return {
            "disabled": self.disabled,
            "bound": list(self.bound_keys()),
            "retired": list(self.retired_keys()),
            "actions": [[a.verb, a.edge_key, a.action_id] for a in self.actions],
            "refusals": [[r.edge_key, r.code] for r in self.refusals],
        }


# ==================================================================================================
# The reconciler.
# ==================================================================================================
class EdgeReconciler:
    """The declarative AEGIS edge reconciler: converge the ACTUAL per-(org,host) edge toward the DESIRED
    edge over the AS-6a ``FleetState``, with NO operator step. Construct ONCE with the injected ports
    (deterministic); call :meth:`reconcile` with the desired edges + the AS-6a fleet state + the current
    edge state + the injected ``now``.

    Guard rails, enforced here:
      * NEVER BIND AN UNPROVEN ORIGIN — a desired edge whose backing unit is absent or not HEALTHY in the
        fleet is REFUSED (``backing_unit_not_healthy``); the edge keeps its current proven origin.
      * NEVER OPEN WITHOUT A SECRET — a desired edge whose secret epoch cannot be provisioned is REFUSED
        (``edge_secret_refused``) BEFORE the origin is bound.
      * ONLY SIGIL TT ORIGINS — an org not in ``sigil_tt_tenants`` is REFUSED (``origin_not_sigil_tt``).
      * SAFE ROLLOUT ORDER — on a unit rollout the NEW origin is bound FIRST; only once it is confirmed is
        the OLD origin drained (never a gap with no proven origin).
      * DRAIN-FIRST RETIRE — an edge going absent is DRAINED before it is torn down; a failed drain leaves
        it DRAINING and REFUSES the teardown (never release an edge while its origin may still serve)."""

    def __init__(self, *, control_plane: EdgeControlPlane,
                 secret_store: Optional[EdgeSecretStore] = None,
                 sigil_tt_tenants: frozenset[str] = SIGIL_TT_TENANTS) -> None:
        if not isinstance(control_plane, EdgeControlPlane):
            raise EdgeReconcileError("EdgeReconciler requires an EdgeControlPlane")
        if secret_store is not None and not isinstance(secret_store, EdgeSecretStore):
            raise EdgeReconcileError("secret_store, when given, must be an EdgeSecretStore")
        self._cp = control_plane
        self._store = secret_store
        self._sigil_tt_tenants = frozenset(sigil_tt_tenants)

    # -- the one public entrypoint -----------------------------------------------------------------
    def reconcile(self, desired: "list[DesiredEdge]", fleet: FleetState, state: EdgeState, *,
                  now: float) -> EdgeReconcileResult:
        """Converge ``state`` toward ``desired`` over the AS-6a ``fleet`` at the injected ``now``.
        DEFAULT-OFF: with the flag off this is INERT — it returns a fixed ``disabled`` result and changes
        nothing (flag-off golden byte-identical). Deterministic: the result is a pure function of (desired,
        fleet, state, now, the injected ports)."""
        if not edge_enabled():
            return EdgeReconcileResult(disabled=True, state=state)

        current = state.by_key()
        desired_by_key = {e.key: e for e in sorted(desired, key=lambda e: e.key)}
        new_edges: dict[str, BoundEdge] = dict(current)
        actions: list[EdgeAction] = []
        refusals: list[EdgeRefusal] = []

        # 1) Drive every desired edge toward its desired state.
        for key in sorted(desired_by_key):
            e = desired_by_key[key]
            # Guard rail: only SIGIL TT origins before AS-2g.
            if e.org not in self._sigil_tt_tenants:
                refusals.append(EdgeRefusal(edge_key=key, code="origin_not_sigil_tt",
                                            reason=f"org {e.org!r} is not a SIGIL TT origin; before AS-2g "
                                                   "no tenant origin is fronted"))
                continue
            try:
                worker_kind_spec(e.backing_kind)
            except FleetError as exc:
                refusals.append(EdgeRefusal(edge_key=key, code="unknown_backing_kind", reason=str(exc)))
                continue

            if e.desired_state == "absent":
                self._retire(e, new_edges.get(key), now, actions, refusals, new_edges, reason="desired absent")
                continue

            # desired_state == "present": prove the backing unit, provision the secret, bind the origin.
            unit = fleet.get(e.backing_key)
            if unit is None or unit.health != WorkerHealth.HEALTHY:
                have = "absent" if unit is None else unit.health.value
                refusals.append(EdgeRefusal(edge_key=key, code="backing_unit_not_healthy",
                                            reason=f"backing unit {e.backing_key!r} is {have}; refusing to bind the "
                                                   "edge to an unproven origin (fail closed)"))
                continue

            origin_id = _origin_id(unit)
            prior = new_edges.get(key)
            # Decide convergence BEFORE any side effect. A re-provision (secret store write) and a re-bind
            # (control-plane call) are real side effects + audit actions, so they must NOT run on an already-
            # converged BOUND edge. Otherwise a steady BOUND edge would re-push its secret and re-bind its
            # origin on EVERY tick — breaking idempotency + determinism. A BOUND edge's secret is provisioned
            # by construction (we never bind without it), so health==BOUND + origin + epoch IS convergence.
            if (prior is not None and prior.health == EdgeHealth.BOUND
                    and prior.origin_id == origin_id and prior.secret_epoch == e.secret_epoch):
                continue  # already converged incl. the edge secret — NO action (idempotent, no operator step)

            secret_status = self._provision_secret(e, prior, actions, now)
            if secret_status != "provisioned":
                # Fail closed: NEVER open the origin without a provisioned edge secret. "unavailable" = no
                # edge-secret store wired (owner-gated); "refused" = a wired store declined/failed the write.
                code = "edge_secret_unavailable" if secret_status == "unavailable" else "edge_secret_refused"
                detail = ("no edge-secret store wired (owner-gated)" if secret_status == "unavailable"
                          else "the edge-secret store declined/failed the write")
                refusals.append(EdgeRefusal(edge_key=key, code=code,
                                            reason=f"edge secret epoch {e.secret_epoch} is not provisioned "
                                                   f"({detail}); refusing to open the origin without it (fail closed)"))
                continue

            self._bind(e, prior, unit, origin_id, secret_status, now, actions, refusals, new_edges)

        # 2) Declarative convergence: any ACTIVE edge not in the desired set is absent -> retire it.
        for key in sorted(current):
            if key in desired_by_key:
                continue
            cur = current[key]
            if cur.health == EdgeHealth.RETIRED:
                continue
            self._retire_existing(cur, now, actions, refusals, new_edges, reason="absent from desired")

        return EdgeReconcileResult(
            disabled=False, state=EdgeState.from_edges(new_edges.values()),
            actions=tuple(actions), refusals=tuple(refusals))

    # -- edge-secret provisioning (idempotent across unit rollouts) --------------------------------
    def _provision_secret(self, e: DesiredEdge, prior: Optional[BoundEdge], actions: list[EdgeAction],
                          now: float) -> str:
        """Provision the desired secret epoch, idempotently. A unit ROLLOUT (origin change) at the SAME
        secret epoch re-provisions NOTHING — the already-provisioned secret is kept (no action). An epoch
        BUMP rotates: provision the new epoch and schedule the old one's destruction. No store wired =>
        'unavailable' (owner-gated); a store write failure => 'refused'. The caller refuses the bind on
        anything but 'provisioned' (never open the origin without a provisioned edge secret)."""
        # Idempotent: the secret for this epoch is already provisioned (e.g. a unit rollout at the same
        # epoch) — keep it, take NO action.
        if prior is not None and prior.secret_epoch == e.secret_epoch and prior.secret_status == "provisioned":
            return "provisioned"
        if self._store is None:
            return "unavailable"  # no edge-secret store wired (owner-gated); the origin stays closed
        rotating = prior is not None and prior.secret_status == "provisioned" and prior.secret_epoch != e.secret_epoch
        try:
            ok = bool(self._store.provision(e.org, e.host, e.secret_epoch))
        except Exception as exc:  # noqa: BLE001 — a store error is a REFUSED provisioning, never a crash
            _log.warning("edge secret store raised for %s e%d: %s", e.key, e.secret_epoch, exc)
            return "refused"
        if not ok:
            return "refused"
        verb = "rotate_secret" if rotating else "provision_secret"
        actions.append(self._action(verb, e.key, f"edge secret epoch {e.secret_epoch} provisioned", now))
        if rotating and prior is not None:
            # Schedule the OVERLAP epoch's destruction (the rotation keeps new; the old is retired). A store
            # that declines the delete is tolerated — the stale epoch is harmless and retried next bump.
            try:
                self._store.destroy(e.org, e.host, prior.secret_epoch)
            except Exception as exc:  # noqa: BLE001 — a failed overlap-destroy never blocks the rotation
                _log.warning("edge secret overlap-destroy raised for %s e%d: %s", e.key, prior.secret_epoch, exc)
            actions.append(self._action("destroy_secret", e.key,
                                        f"edge secret epoch {prior.secret_epoch} scheduled for destruction", now))
        return "provisioned"

    # -- origin bind (safe rollout order: bind NEW first, then drain OLD) ---------------------------
    def _bind(self, e: DesiredEdge, prior: Optional[BoundEdge], unit: RoutedWorker, origin_id: str,
              secret_status: str, now: float, actions: list[EdgeAction], refusals: list[EdgeRefusal],
              new_edges: dict[str, BoundEdge]) -> None:
        # Secret-only change: the origin is ALREADY bound to this exact unit (a pure edge-secret rotation).
        # Re-asserting the origin would be a wasteful control-plane call + a spurious action, so update only
        # the secret fields — NO bind_origin call.
        if prior is not None and prior.health == EdgeHealth.BOUND and prior.origin_id == origin_id:
            new_edges[e.key] = BoundEdge(
                key=e.key, org=e.org, host=e.host, distribution_id=e.distribution_id, origin_id=origin_id,
                backing_key=e.backing_key, secret_epoch=e.secret_epoch, secret_status=secret_status,
                health=EdgeHealth.BOUND, bound_at=prior.bound_at)
            return
        rollout = (prior is not None and prior.health in (EdgeHealth.BOUND, EdgeHealth.DRAINING)
                   and prior.origin_id != origin_id)
        try:
            bound = bool(self._cp.bind_origin(e.distribution_id, origin_id))
        except Exception as exc:  # noqa: BLE001 — a control-plane error is a REFUSED bind, never a crash
            _log.warning("edge bind_origin raised for %s: %s", e.key, exc)
            bound = False
        if not bound:
            # Fail closed: do NOT mark BOUND. On a rollout the OLD origin is still proven + serving, so keep
            # it (never drain an un-replaced origin); a first bind stays BINDING and retries next pass.
            refusals.append(EdgeRefusal(edge_key=e.key, code="origin_bind_failed",
                                        reason=f"control plane declined to bind origin {origin_id} for "
                                               f"distribution {e.distribution_id!r}; keeping the proven origin"))
            if prior is not None and prior.health != EdgeHealth.RETIRED:
                return  # keep the prior BoundEdge untouched (still serving its proven origin)
            new_edges[e.key] = BoundEdge(
                key=e.key, org=e.org, host=e.host, distribution_id=e.distribution_id, origin_id=origin_id,
                backing_key=e.backing_key, secret_epoch=e.secret_epoch, secret_status=secret_status,
                health=EdgeHealth.BINDING, bound_at=now)
            return
        if rollout and prior is not None:
            # The NEW origin is confirmed — NOW drain the OLD one (connection draining). A failed drain is
            # tolerated (the old target simply ages out); the cutover already points at the proven new unit.
            try:
                self._cp.drain_origin(e.distribution_id, prior.origin_id)
            except Exception as exc:  # noqa: BLE001 — a failed overlap-drain never un-does a confirmed cutover
                _log.warning("edge rollout drain raised for %s: %s", e.key, exc)
            actions.append(self._action("rollout", e.key,
                                        f"cut origin {prior.origin_id[:12]} -> {origin_id[:12]} (unit epoch "
                                        f"{unit.epoch})", now))
        verb = "rollout" if rollout else "bind"
        new_edges[e.key] = BoundEdge(
            key=e.key, org=e.org, host=e.host, distribution_id=e.distribution_id, origin_id=origin_id,
            backing_key=e.backing_key, secret_epoch=e.secret_epoch, secret_status=secret_status,
            health=EdgeHealth.BOUND, bound_at=now)
        if verb == "bind":
            actions.append(self._action("bind", e.key,
                                        f"bound edge origin to {e.backing_key} (unit epoch {unit.epoch})", now))

    # -- retire (drain-first) ----------------------------------------------------------------------
    def _retire(self, e: DesiredEdge, prior: Optional[BoundEdge], now: float, actions: list[EdgeAction],
                refusals: list[EdgeRefusal], new_edges: dict[str, BoundEdge], *, reason: str) -> None:
        if prior is None or prior.health == EdgeHealth.RETIRED:
            # Never bound (or already retired): record an absent tombstone, nothing to drain.
            new_edges[e.key] = BoundEdge(
                key=e.key, org=e.org, host=e.host, distribution_id=e.distribution_id, origin_id="",
                backing_key=e.backing_key, secret_epoch=e.secret_epoch, secret_status="none",
                health=EdgeHealth.RETIRED, bound_at=now)
            return
        self._retire_existing(prior, now, actions, refusals, new_edges, reason=reason)

    def _retire_existing(self, prior: BoundEdge, now: float, actions: list[EdgeAction],
                         refusals: list[EdgeRefusal], new_edges: dict[str, BoundEdge], *, reason: str) -> None:
        """Retire a bound edge DRAIN-FIRST: drain the origin (connection draining) -> release -> schedule
        edge-secret destruction -> RETIRED. If the drain cannot be confirmed the teardown is REFUSED and the
        edge is left DRAINING (never released while its origin may still serve); the next pass retries."""
        try:
            drained = bool(self._cp.drain_origin(prior.distribution_id, prior.origin_id))
        except Exception as exc:  # noqa: BLE001 — a drain error is a REFUSED teardown, never a crash/release
            _log.warning("edge retire drain raised for %s: %s", prior.key, exc)
            drained = False
        if not drained:
            refusals.append(EdgeRefusal(edge_key=prior.key, code="drain_failed",
                                        reason="origin drain could not be confirmed; teardown refused "
                                               "(drain-first is inviolable)"))
            new_edges[prior.key] = BoundEdge(
                key=prior.key, org=prior.org, host=prior.host, distribution_id=prior.distribution_id,
                origin_id=prior.origin_id, backing_key=prior.backing_key, secret_epoch=prior.secret_epoch,
                secret_status=prior.secret_status, health=EdgeHealth.DRAINING, bound_at=prior.bound_at)
            return
        actions.append(self._action("drain", prior.key, f"drained origin {prior.origin_id[:12]} ({reason})", now))
        # release the origin + schedule edge-secret destruction (the real store delete is owner-provided).
        if prior.secret_status == "provisioned" and self._store is not None:
            try:
                self._store.destroy(prior.org, prior.host, prior.secret_epoch)
            except Exception as exc:  # noqa: BLE001 — a failed destroy never blocks the teardown
                _log.warning("edge retire secret-destroy raised for %s: %s", prior.key, exc)
            actions.append(self._action("destroy_secret", prior.key,
                                        f"edge secret epoch {prior.secret_epoch} scheduled for destruction", now))
        actions.append(self._action("retire", prior.key, f"retired after drain ({reason})", now))
        new_edges[prior.key] = BoundEdge(
            key=prior.key, org=prior.org, host=prior.host, distribution_id=prior.distribution_id,
            origin_id=prior.origin_id, backing_key=prior.backing_key, secret_epoch=prior.secret_epoch,
            secret_status="none", health=EdgeHealth.RETIRED, bound_at=prior.bound_at)

    # -- deterministic action id -------------------------------------------------------------------
    def _action(self, verb: str, edge_key: str, detail: str, now: float) -> EdgeAction:
        return EdgeAction(verb=verb, edge_key=edge_key, detail=detail, at=now,
                          action_id=_content_id("edge-action", verb, edge_key, detail, now))


# ==================================================================================================
# Adapter — derive the desired edges from the AS-6a fleet state (shows the automation wiring).
# ==================================================================================================
def desired_edges_for_fleet(fleet: FleetState, *, distribution_ids: Mapping[str, str],
                            secret_epoch_by_host: Optional[Mapping[str, int]] = None,
                            backing_kind: WorkerKind = WorkerKind.UNITS) -> list[DesiredEdge]:
    """Derive a :class:`DesiredEdge` for every HEALTHY gateway unit in the AS-6a ``fleet`` — the automation
    wiring that makes AS-6c "edge automation built on AS-6a": the desired edges TRACK the placed gateway
    units. ``distribution_ids`` maps a host to its CloudFront distribution id (owner-provided, from the
    AS-26 ``20-edge-cloudfront`` stack outputs); a host with no mapped distribution is skipped (the edge
    cannot be fronted without one). ``secret_epoch_by_host`` overrides the per-host edge-secret epoch
    (default 1). Deterministic: a pure, sorted function of the fleet state + the mappings."""
    epochs = dict(secret_epoch_by_host or {})
    out: list[DesiredEdge] = []
    for w in fleet.active():
        if w.kind != backing_kind or w.health != WorkerHealth.HEALTHY:
            continue
        dist = distribution_ids.get(w.host)
        if not dist:
            continue
        out.append(DesiredEdge(
            org=w.tenant, host=w.host, distribution_id=dist, desired_state="present",
            secret_epoch=int(epochs.get(w.host, 1)), backing_kind=backing_kind,
            replica_index=w.replica_index))
    return sorted(out, key=lambda e: e.key)
