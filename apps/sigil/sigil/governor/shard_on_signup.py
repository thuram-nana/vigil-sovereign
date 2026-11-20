"""Shard placement ON SIGN-UP — the OWNER-side policy that rides the owner-signed ShardAssignment (consumer PR-F).

A tenant NEVER chooses its shard. On sign-up the shard is computed HERE from the owner's topology
(``config.shard_ids``) + the current cross-tenant load, and minted by the owner-key-holding Provisioner through
:meth:`~sigil.governor.shard_assignment.ShardAssignmentRegistry.assign` (owner-signed). The sign-up request
carries NO shard field — placement is server-decided + owner-signed, exactly as a launch AMOUNT is server-decided
and never taken from the customer. The ``epoch`` + ``issued_at`` anti-replay live inside those signed bytes, so a
captured assignment can neither self-assign a tenant nor resurrect a migrated-off placement.

WIRED: ``ui.provision.build_provisioner`` injects the owner-keyed registry, and ``Provisioner._place_on_signup``
calls :func:`assign_on_signup` on every sign-up path (email token, email code, Google) when
``VIGIL_CUSTOMER_FAIR_QUEUE`` + ``VIGIL_MULTI_SHARD`` are on AND the owner named a topology (``VIGIL_SHARD_IDS``).

IDEMPOTENT by construction, to fit the idempotent-forward sign-up transaction (``provision._signup_commit``): a
tenant already placed is a no-op (the existing placement is returned), so a sign-up RETRY after a crash re-drives
to exactly one placement and never a second. With no owner topology the policy places NOTHING (fail-safe: a tenant
is never guessed onto a shard; routing then fails closed for it until the owner assigns one).

COST: one signature-verifying spine fold decides both "already placed?" and the per-shard load, and the
registry's own ``assign`` re-checks under the caller's sign-up lock (its single TOCTOU guard) — two folds per
placement, under the sign-up lock.

Owner deploy work, deploy-gated and outside this module: the elastic we-host fleet these shard ids name — standing
it up, scaling it, and the cross-HOST dispatch/copy (``LIMIT-frontc-shard-cross-host-deploy``).

Operational limit of turning placement on (``LIMIT-consumer-shard-on-signup-ops``): carrying shard rows into the
spine snapshot seed is not yet built, so ``spine.prune`` refuses a hard prune past any active placement until the
owner re-signs it above the prune point — with a placement per sign-up, the oldest placed sign-up pins hard prune.
Tenants created before placement was switched on are placed by ``sigil shard backfill`` (:func:`backfill_placements`).

FATAL-2: SOVEREIGN-only (``assert_no_offense`` at import); imports only sovereign siblings + the shared vigil_core
(via ``shard_assignment``). Pure policy + one owner-signed append through the injected registry.
"""
from __future__ import annotations

from typing import Callable, ContextManager, Mapping, Optional, Sequence

from ..reuse import assert_no_offense

assert_no_offense()

from .shard_assignment import ShardAssignmentRegistry, ShardPlacement  # noqa: E402


def choose_shard(shard_ids: "Sequence[str]", loads: "Mapping[str, int]") -> Optional[str]:
    """Deterministic LEAST-LOADED placement: the owner-named shard carrying the FEWEST active tenants, tie-broken
    by ``shard_id`` (lexicographic) so the choice is reproducible. ``None`` when no shards are named (fail-safe:
    never guess a tenant onto an unknown shard). A shard absent from ``loads`` counts as load 0 — a fresh/empty
    shard is preferred, which spreads a cold fleet evenly. Pure."""
    ids = [s for s in shard_ids if s]
    if not ids:
        return None
    return min(ids, key=lambda s: (int(loads.get(s, 0)), s))


def loads_of(placements: "Sequence[ShardPlacement]") -> "dict[str, int]":
    """The active-placement count per shard in ``placements`` — the load view :func:`choose_shard` balances. Pure."""
    loads: "dict[str, int]" = {}
    for p in placements:
        loads[p.shard_id] = loads.get(p.shard_id, 0) + 1
    return loads


def current_loads(registry: ShardAssignmentRegistry) -> "dict[str, int]":
    """The active-placement count per shard across ALL tenants (one registry fold). OWNER-side: it reads every
    tenant's placement, which a per-tenant caller never needs."""
    return loads_of(registry.placements())


def assign_on_signup(registry: ShardAssignmentRegistry, org_id: str, *, shard_ids: "Sequence[str]",
                     issued_at: float) -> Optional[ShardPlacement]:
    """IDEMPOTENTLY place a newly-signed-up tenant on an owner-named shard, OWNER-SIGNED via ``registry.assign``.

      * ALREADY PLACED  -> return the existing :class:`ShardPlacement` (no-op; safe under the sign-up retry — the
        tenant keeps the shard it was first placed on, never bounced to another by a re-drive);
      * NO ``shard_ids`` -> ``None`` (fail-safe: the owner named no topology, so nothing is placed; the tenant
        stays unassigned and the routing resolver fails closed for it until the owner assigns one);
      * ELSE            -> choose the least-loaded owner-named shard, OWNER-SIGN the assignment, and return the
        placement it just signed (built from the signed record, not re-read: no third fold).

    ONE fold answers both "already placed?" and the loads; ``registry.assign`` keeps its own already-placed check
    (it refuses a second placement), so the caller's sign-up lock plus that check is the whole TOCTOU story.

    A tenant can NEVER reach this with a self-chosen shard: ``shard_ids`` is OWNER config (``config.shard_ids``),
    never request input, and the mint goes through the owner-key-holding registry — so "a tenant self-assigns a
    shard" is impossible by construction, not by a check. The caller gates the whole call on the PR-F flag +
    ``multi_shard_enabled`` + an owner topology (see ``provision.Provisioner._place_on_signup``)."""
    return _place(registry, org_id, shard_ids=shard_ids, issued_at=issued_at)[0]


def _place(registry: ShardAssignmentRegistry, org_id: str, *, shard_ids: "Sequence[str]",
           issued_at: float) -> "tuple[Optional[ShardPlacement], bool]":
    """``(placement, placed_now)`` — :func:`assign_on_signup` 's body, also telling whether THIS call signed it."""
    active = registry.placements()                         # the ONE fold
    for p in active:
        if p.tenant_id == org_id:
            return p, False
    shard = choose_shard(list(shard_ids), loads_of(active))
    if shard is None:
        return None, False
    doc = registry.assign(org_id, shard, issued_at=issued_at)
    return ShardPlacement(tenant_id=doc.tenant_id, shard_id=doc.shard_id, epoch=int(doc.epoch),
                          issued_at=float(doc.issued_at)), True


_PLACEMENT_LOCK_WAIT_S = 10.0


def placement_lock(store, *, wait_s: "Optional[float]" = None):
    """THE cross-process critical section for owner shard placement on ``store`` 's spine: an ``flock`` on
    ``<spine dir>/<stem>.shards.lock`` (a ``*.lock`` transient the backups skip), taken with the hardened
    ``seam_lock.locked_file``. Both placement writers hold it around their fold + owner-signed assign — the sign-up
    path (``Provisioner._place_on_signup``, in the cockpit process) and the owner backfill (``sigil shard
    backfill``, its own process) — so two processes can never both see a tenant unplaced and place it twice. Lock
    order: ``spine_lock`` (in-process) -> this -> the spine's append lock. A bounded wait, then ``LockBusy`` (an
    ``OSError``) with nothing written: a sign-up then fails closed and its token stays valid for the retry."""
    from pathlib import Path

    from vigil_integration.live.seam_lock import locked_file
    raw = getattr(store, "path", None)
    if not raw:
        raise ValueError("shard placement needs a spine store with a path")
    sp = Path(raw)
    path = sp.parent / f"{sp.stem or sp.name}.shards.lock"
    wait = _PLACEMENT_LOCK_WAIT_S if wait_s is None else float(wait_s)
    return locked_file(path, wait_s=wait, create=False, chown_like=path.parent)


def backfill_placements(registry: ShardAssignmentRegistry, org_ids: "Sequence[str]", *, shard_ids: "Sequence[str]",
                        issued_at: float, lock: "Callable[[], ContextManager[object]]") -> "dict[str, int]":
    """Owner-sign a placement for every org in ``org_ids`` that has none — the catch-up for tenants created before
    placement-on-sign-up was switched on. One fold finds who is already placed (they cost nothing more); each of the
    rest is placed under ``lock()`` (a fresh :func:`placement_lock` per tenant, so sign-ups interleave with a long
    backfill instead of waiting it out) by the same least-loaded, owner-signed step a sign-up uses, which re-reads
    the placements under the lock — a tenant a concurrent sign-up placed meanwhile is counted ``already``, never
    placed twice. Idempotent: a second run places nothing. An org that cannot be placed (the registry refuses it, or
    the lock stays busy) is counted ``failed`` and the sweep goes on. No ``shard_ids`` ⇒ nothing is placed
    (fail-safe). Returns ``{"placed", "already", "failed"}``."""
    out = {"placed": 0, "already": 0, "failed": 0}
    if not [s for s in shard_ids if s]:
        return out
    placed = {p.tenant_id for p in registry.placements()}
    for org_id in sorted(set(org_ids)):
        if org_id in placed:
            out["already"] += 1
            continue
        try:
            with lock():
                _p, now = _place(registry, org_id, shard_ids=shard_ids, issued_at=issued_at)
        except (ValueError, OSError):
            out["failed"] += 1
            continue
        out["placed" if now else "already"] += 1
    return out
