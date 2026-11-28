"""
aegis.aegis_fleet_rolling — AS-6e: ROLLING (staged, health-gated) fleet reconcile over AS-6a.

The FLEET-chain piece (6a -> 29 -> 6e -> 27b) that turns AS-6a's **big-bang** rollout into a **rolling**
one. AS-6a (``aegis_fleet``) converges the ENTIRE fleet in a single pass: every worker whose placement
changed (an epoch / image bump — a ``rollout``, the "6e seam" named in ``FleetReconciler.reconcile``) is
drained-and-replaced at once. That is correct but blunt: a bad epoch takes the whole fleet over at once.
AS-6e converges the SAME desired state GRADUALLY — in deterministic, health-gated batches — so at most a
bounded ``max_surge`` of the tenant's hosts are mid-rollout at any tick, and the next batch is admitted
only once the prior batch has landed HEALTHY. Continuously reconciled: each tick advances the rollout by
one batch, and a converged fleet takes NO action (idempotent).

Scope inference (no §9.3 plan spec in the repo; inferred from the docs + the FLEET chain + the code's own
seam, NOT invented). "rolling" has no written spec, so it is grounded in:
  * the FORGE domain map (Domain 4): the FLEET chain is ``6a -> 29 -> 6e -> 27b`` and the reconciler
    "renders placement ... and renders enforcement only after a release";
  * AS-6a's own code: ``FleetReconciler.reconcile`` tags its placement-change branch "(6e seam)" and sets a
    rolled worker to ``STARTING`` (not ``HEALTHY``) — an explicit, un-advanced hook this slice completes;
  * AS-6c (``aegis_edge``), the sibling reconciler, whose doctrine already says "during a unit rollout the
    edge keeps serving its current, proven origin until the replacement is HEALTHY" — the edge assumes a
    STAGED, health-gated unit rollout, which is exactly what this slice supplies.
So AS-6e's minimal REAL increment is a rolling POLICY over AS-6a: a per-tick surge budget + a health gate
that advances the rollout batch by batch. Confidence: medium-high that "rolling" = staged/health-gated
fleet rollout (the name + chain + the literal "(6e seam)" converge on it); the exact knob names are a
reasoned choice, not a spec.

DOCTRINE (non-negotiable, enforced here and tested):
  * DEFENSIVE + CONTROL-PLANE ONLY. This only STAGES how fast AS-6a's own placements roll; it never attacks,
    never reaches a tenant's traffic, and adds NO capability of its own. It lives in the ENGINE plane beside
    ``aegis_fleet`` (FATAL-2: it imports only ``aegis_fleet`` (same plane), stdlib and ``..common`` — never
    ``sigil`` / ``apps`` / a ``governor`` module).
  * NEVER RENDER ENFORCEMENT. Enforcement rendering stays entirely in AS-6a (release-gated, observe-only
    until AS-29's release source is wired); this slice only orders WHEN AS-6a's placements are applied. It
    sets no enforce env, mints no authority, opens no route, and adds NO ``OracleKind`` / ``WorkerKind``.
  * HEALTH-GATED ADVANCE. A batch is admitted only when in-flight (``STARTING``) workers are at/under the
    surge budget; a rolled worker advances ``STARTING -> HEALTHY`` only when the injected
    :class:`RolloutHealth` reports it SETTLED. The richer health state machine (CRASH_LOOP / EXPIRING /
    REVOCATION_PENDING) remains AS-3d; this slice uses only the ``STARTING -> HEALTHY`` advance AS-6a left
    open, and gates it on an injected signal.
  * DETERMINISM. No wall-clock, no RNG. ``now`` is injected; the batch is chosen in sorted key order; every
    action id is a content hash. The same desired + state + now + injected health yields a byte-identical
    result.
  * IDEMPOTENT. A fully converged fleet (nothing in-flight, nothing deferred) takes NO action on a steady
    tick — the AS-6a "converged => no action" contract, carried to the rolling layer.
  * DEFAULT-OFF. Gated behind ``VIGIL_AEGIS_FLEET_ROLLING`` (strict, fail-closed, DEFAULT OFF — the
    ``aegis_fleet`` flag pattern). With the flag off (or with the underlying ``VIGIL_AEGIS_FLEET`` off) the
    reconciler is INERT: it advances and admits nothing and returns a fixed ``disabled`` result (flag-off
    golden byte-identical). With the rolling flag off, callers use the plain AS-6a ``FleetReconciler`` and
    AS-6a stays byte-identical — AS-6e adds nothing until its own flag is on.
  * LIVE HEALTH IS OWNER-PROVIDED. The real per-worker health signal (the AS-6a ``health_probe`` readyz /
    ping socket check) is owner-provided and deploy-gated; offline it is an injected
    :class:`RolloutHealth` double, so the rolling LOGIC is exercised deterministically without a probe —
    the AS-6a ``SnapshotSink`` / ``SsmCredentialChannel`` seam pattern. The default
    :class:`ElapsedTickHealth` advances a worker one reconcile tick after it was placed (``routed_at <
    now``), a deterministic cadence with no external dependency.

Nothing under ``aegis/__init__`` or ``framework.v2.__main__`` imports this module (it is off the gate path,
like ``aegis_fleet`` / ``aegis_edge`` / ``tt_rig``), so ``make gate`` stays byte-identical. Its tests import
it directly.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from typing import Optional, Protocol, runtime_checkable

from ..common.logging import get_logger

# aegis_fleet is the AS-6a control-plane peer in the SAME engine plane (FATAL-2 safe: it imports only
# vigil_core + stdlib + ..common). The rolling reconciler CONSUMES its reconciler + types and guard rails,
# never re-codes them. It adds NO new WorkerKind / OracleKind.
from .aegis_fleet import (
    DesiredWorker,
    FleetAction,
    FleetError,
    FleetReconciler,
    FleetState,
    ReconcileResult,
    RoutedWorker,
    WorkerHealth,
    fleet_enabled,
)

_log = get_logger("aegis.fleet.rolling")

__all__ = [
    "ROLLING_ENV", "rolling_enabled",
    "RolloutHealth", "ElapsedTickHealth",
    "RollingPolicy",
    "RollingReconcileResult",
    "RollingFleetReconciler",
]


# ==================================================================================================
# Default-OFF flag (the aegis_fleet flag pattern — strict, fail-closed, DEFAULT OFF).
# ==================================================================================================
ROLLING_ENV = "VIGIL_AEGIS_FLEET_ROLLING"


def rolling_enabled() -> bool:
    """The AS-6e rolling-reconcile flag — strict, fail-closed, DEFAULT OFF. Only an explicit affirmative
    token turns rolling on; anything else (unset, typo, empty) keeps it INERT, and callers fall back to the
    plain AS-6a big-bang ``FleetReconciler`` (so AS-6a stays byte-identical)."""
    return (os.environ.get(ROLLING_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _content_id(*parts: object) -> str:
    """A deterministic sha256 content id over canonical JSON of ``parts`` (mirrors ``aegis_fleet``). No RNG,
    no wall-clock — the only time input is the injected ``now`` a caller passes through ``parts``."""
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ==================================================================================================
# The health gate — when has a rolled (STARTING) worker landed HEALTHY, so the rollout may advance?
# ==================================================================================================
@runtime_checkable
class RolloutHealth(Protocol):
    """The injected signal that reports whether a just-rolled worker has SETTLED (become healthy), so the
    rolling reconciler may advance it ``STARTING -> HEALTHY`` and free surge budget for the next batch. The
    REAL signal is the AS-6a ``health_probe`` (a readyz / ping over the worker's socket), owner-provided and
    deploy-gated; offline it is an injected double, so advancement is exercised deterministically without a
    probe. Pure + deterministic: a function of the worker + the injected ``now``, never wall-clock/RNG."""

    def settled(self, worker: RoutedWorker, *, now: float) -> bool: ...


@dataclass(frozen=True)
class ElapsedTickHealth:
    """The DEFAULT health gate: a rolled worker is SETTLED one reconcile tick after it was placed — i.e.
    once a later ``now`` observes it (``routed_at < now``). Deterministic, no external dependency: it makes
    the rollout advance exactly one batch per tick. A real deployment injects a probe-backed
    :class:`RolloutHealth` instead (which may legitimately keep a worker ``STARTING`` until it is truly
    healthy, correctly stalling the rollout)."""

    def settled(self, worker: RoutedWorker, *, now: float) -> bool:
        return worker.health == WorkerHealth.STARTING and float(worker.routed_at) < float(now)


# ==================================================================================================
# The rolling policy — the surge budget (how many hosts may be mid-rollout at once).
# ==================================================================================================
@dataclass(frozen=True)
class RollingPolicy:
    """The rolling knob: ``max_surge`` is the most workers that may be mid-rollout (``STARTING``) at any one
    tick. ``max_surge == 1`` is a strict one-at-a-time rollout; a larger value rolls wider batches. It
    bounds ONLY the ``rollout`` / new-placement ("apply") direction — retires proceed as in AS-6a
    (snapshot-first, which already makes them safe), matching "apply enforcement to the fleet gradually"."""

    max_surge: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.max_surge, int) or isinstance(self.max_surge, bool) or self.max_surge < 1:
            raise FleetError("RollingPolicy.max_surge must be a positive int")


# ==================================================================================================
# The rolling result.
# ==================================================================================================
_INERT_GOLDEN = {
    "disabled": True, "promoted": [], "admitted": [], "deferred": [],
    "actions": [], "routed": [], "retired": [], "converged": False,
}


@dataclass(frozen=True)
class RollingReconcileResult:
    """The outcome of one rolling reconcile tick. ``result`` is the underlying AS-6a pass (its new state,
    actions, refusals, snapshots). ``promotions`` are the ``STARTING -> HEALTHY`` advances this tick;
    ``promoted`` / ``admitted`` / ``deferred`` are the worker keys advanced / rolled this tick / held back
    for budget. ``converged`` is True when nothing is in-flight and nothing is deferred. ``disabled`` is
    True when the DEFAULT-OFF flag (or the underlying fleet flag) is off (the inert result)."""

    disabled: bool
    result: ReconcileResult
    promotions: tuple[FleetAction, ...] = ()
    promoted: tuple[str, ...] = ()
    admitted: tuple[str, ...] = ()
    deferred: tuple[str, ...] = ()
    converged: bool = False

    @property
    def state(self) -> FleetState:
        """The new fleet state after this tick (the underlying AS-6a state, with this tick's promotions)."""
        return self.result.state

    def actions(self) -> tuple[FleetAction, ...]:
        """The full, ordered action stream of this tick: the health-advance ``rolled_in`` promotions FIRST
        (they gate the batch), then the underlying AS-6a actions."""
        return self.promotions + self.result.actions

    def golden(self) -> dict:
        """A deterministic, JSON-safe projection used by the flag-off byte-identity test and by auditors.
        Pure function of the result — no wall-clock, no RNG."""
        if self.disabled:
            return dict(_INERT_GOLDEN)
        return {
            "disabled": False,
            "promoted": list(self.promoted),
            "admitted": list(self.admitted),
            "deferred": list(self.deferred),
            "actions": [[a.verb, a.worker_key, a.action_id] for a in self.actions()],
            "routed": list(self.result.routed_keys()),
            "retired": list(self.result.retired_keys()),
            "converged": self.converged,
        }


# ==================================================================================================
# The rolling reconciler.
# ==================================================================================================
class RollingFleetReconciler:
    """A staged, health-gated rolling reconcile over an AS-6a :class:`FleetReconciler`. Construct ONCE with
    the inner reconciler, a :class:`RollingPolicy` and a :class:`RolloutHealth` (deterministic); call
    :meth:`reconcile` each tick with the desired workers + current state + the injected ``now``.

    Each tick, in order:
      1. ADVANCE: promote every in-flight (``STARTING``) worker the health gate reports SETTLED to
         ``HEALTHY`` (a ``rolled_in`` action), freeing surge budget — the AS-6a hook this slice completes.
      2. BUDGET: ``budget = max_surge - (workers still IN-FLIGHT after the advance)``, where in-flight is
         every worker still holding a surge slot — ``STARTING`` (not yet proven healthy) OR ``DRAINING`` (a
         teardown whose snapshot-first retirement has not landed). Both count, so the cap holds across ticks.
      3. ADMIT: in deterministic key order, admit up to ``budget`` workers whose placement would change (a
         ``rollout`` of a live worker, or a brand-new placement); DEFER the rest.
      4. DELEGATE: run the inner AS-6a reconcile over the admitted + stable + retiring desired workers, with
         the deferred ones HELD (``hold_keys``) so AS-6a neither rolls nor retires them this tick.

    It renders NOTHING itself and holds NO release source: enforcement stays release-gated inside AS-6a. It
    only orders WHEN AS-6a's own placements are applied."""

    def __init__(self, inner: FleetReconciler, *, policy: RollingPolicy = RollingPolicy(),
                 health: Optional[RolloutHealth] = None) -> None:
        if not isinstance(inner, FleetReconciler):
            raise FleetError("RollingFleetReconciler requires an AS-6a FleetReconciler")
        if not isinstance(policy, RollingPolicy):
            raise FleetError("RollingFleetReconciler requires a RollingPolicy")
        health = health if health is not None else ElapsedTickHealth()
        if not isinstance(health, RolloutHealth):
            raise FleetError("RollingFleetReconciler requires a RolloutHealth")
        self._inner = inner
        self._policy = policy
        self._health = health

    # -- the one public entrypoint -----------------------------------------------------------------
    def reconcile(self, desired: "list[DesiredWorker]", state: FleetState, *,
                  now: float) -> RollingReconcileResult:
        """Advance the rolling reconcile one tick. DEFAULT-OFF: with the rolling flag off (or the underlying
        fleet flag off) this is INERT — it returns a fixed ``disabled`` result and changes nothing (flag-off
        golden byte-identical). Deterministic: a pure function of (desired, state, now, the injected deps)."""
        if not rolling_enabled() or not fleet_enabled():
            return RollingReconcileResult(disabled=True, result=ReconcileResult(disabled=True, state=state))

        # 1) ADVANCE — promote settled in-flight workers STARTING -> HEALTHY (the health gate).
        promoted_workers: dict[str, RoutedWorker] = {w.key: w for w in state.workers}
        promotions: list[FleetAction] = []
        promoted_keys: list[str] = []
        for key in sorted(promoted_workers):
            w = promoted_workers[key]
            if w.health == WorkerHealth.STARTING and self._health.settled(w, now=now):
                promoted_workers[key] = replace(w, health=WorkerHealth.HEALTHY, routed_at=now)
                promotions.append(FleetAction(
                    verb="rolled_in", worker_key=key, detail="rollout landed HEALTHY (health-gated advance)",
                    at=now, action_id=_content_id("rolled_in", key, now)))
                promoted_keys.append(key)
        promoted_state = FleetState.from_workers(promoted_workers.values())
        current = promoted_state.by_key()

        # 2) BUDGET — how many more workers may enter rollout this tick. IN-FLIGHT is every worker still
        #    occupying a surge slot: a STARTING worker (new/rolled, not yet proven HEALTHY) AND a DRAINING
        #    worker (mid-teardown — its snapshot-first retirement has not landed, so the old unit is still up).
        #    Both count against max_surge. Counting only STARTING leaked the cap: a worker left DRAINING by a
        #    prior tick (e.g. a refused-snapshot retirement) was re-rolled OUTSIDE the budget, so new STARTING
        #    admits + the leftover DRAINING could put MORE than max_surge hosts in-flight at once.
        in_flight = sum(1 for w in promoted_state.workers
                        if w.health in (WorkerHealth.STARTING, WorkerHealth.DRAINING))
        budget = max(0, self._policy.max_surge - in_flight)

        # 3) ADMIT — classify each desired worker; admit disruptive "apply" transitions up to budget.
        desired_by_key = {w.key: w for w in sorted(desired, key=lambda w: w.key)}
        disruptive: list[str] = []  # keys needing a rollout / new placement (sorted)
        for key in sorted(desired_by_key):
            dw = desired_by_key[key]
            if dw.desired_mode == "off":
                continue  # a retire is not surge-governed (snapshot-first already makes it safe) — see policy.
            cur = current.get(key)
            if cur is None or cur.health == WorkerHealth.RETIRED:
                disruptive.append(key)  # brand-new placement
            elif cur.health in (WorkerHealth.HEALTHY, WorkerHealth.STARTING) and (
                    cur.epoch != dw.epoch or cur.image_digest != dw.image_digest):
                disruptive.append(key)  # a rollout of a live worker (epoch / image bump)
            # else: already converged / a no-op — passed through as-is below.
        admitted = disruptive[:budget]
        deferred = disruptive[budget:]
        held = frozenset(deferred)

        # 4) DELEGATE — run AS-6a over everything EXCEPT the deferred keys, holding those untouched.
        projected = [w for k, w in desired_by_key.items() if k not in held]
        res = self._inner.reconcile(projected, promoted_state, now=now, hold_keys=held)

        # Converged iff nothing is in-flight (no STARTING AND no DRAINING — a stuck-draining worker is work
        # still outstanding) and nothing was deferred this tick.
        in_flight_after = any(w.health in (WorkerHealth.STARTING, WorkerHealth.DRAINING) for w in res.state.workers)
        converged = (not in_flight_after) and not deferred
        return RollingReconcileResult(
            disabled=False, result=res, promotions=tuple(promotions),
            promoted=tuple(promoted_keys), admitted=tuple(admitted), deferred=tuple(deferred),
            converged=converged)
