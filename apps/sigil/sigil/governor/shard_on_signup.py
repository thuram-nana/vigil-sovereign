"""Shard placement ON SIGN-UP — the OWNER-side policy that rides the owner-signed ShardAssignment (PR-F).

A tenant NEVER chooses its shard. On sign-up the shard is computed HERE from the owner's topology
(``config.shard_ids``) + the current cross-tenant load, and minted by the owner-key-holding Provisioner through
:meth:`~sigil.governor.shard_assignment.ShardAssignmentRegistry.assign` (owner-signed). The sign-up request
carries NO shard field — placement is server-decided + owner-signed, exactly as a launch AMOUNT is server-decided
and never taken from the customer. The ``epoch`` + ``issued_at`` anti-replay live inside those signed bytes, so a
captured assignment can neither self-assign a tenant nor resurrect a migrated-off placement.

IDEMPOTENT by construction, to fit the idempotent-forward sign-up transaction (``provision._signup_commit``): a
tenant already placed is a no-op (the existing placement is returned), so a sign-up RETRY after a crash re-drives
to exactly one placement and never a second. With no owner topology the policy places NOTHING (fail-safe: a tenant
is never guessed onto a shard; routing then fails closed for it until the owner assigns one).

OUT OF SCOPE — the elastic we-host k8s/Firecracker fleet these shard ids name is OWNER-GATED infra. This module
only decides WHICH owner-named shard a new tenant is placed on and records the owner-signed assignment; standing up
or auto-scaling the fleet, and the cross-HOST dispatch/copy, are the owner's deploy work.

FATAL-2: SOVEREIGN-only (``assert_no_offense`` at import); imports only sovereign siblings + the shared vigil_core
(via ``shard_assignment``). Pure policy + one owner-signed append through the injected registry.
"""
from __future__ import annotations

from typing import Mapping, Optional, Sequence

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


def current_loads(registry: ShardAssignmentRegistry) -> "dict[str, int]":
    """The active-placement count per shard across ALL tenants — the owner-side load view :func:`choose_shard`
    balances over. O(active placements). (Reads every tenant's placement, so it is OWNER-side; a per-tenant caller
    never needs it.)"""
    loads: "dict[str, int]" = {}
    for p in registry.placements():
        loads[p.shard_id] = loads.get(p.shard_id, 0) + 1
    return loads


def assign_on_signup(registry: ShardAssignmentRegistry, org_id: str, *, shard_ids: "Sequence[str]",
                     issued_at: float) -> Optional[ShardPlacement]:
    """IDEMPOTENTLY place a newly-signed-up tenant on an owner-named shard, OWNER-SIGNED via ``registry.assign``.

      * ALREADY PLACED  -> return the existing :class:`ShardPlacement` (no-op; safe under the sign-up retry — the
        tenant keeps the shard it was first placed on, never bounced to another by a re-drive);
      * NO ``shard_ids`` -> ``None`` (fail-safe: the owner named no topology, so nothing is placed; the tenant
        stays unassigned and the routing resolver fails closed for it until the owner assigns one);
      * ELSE            -> choose the least-loaded owner-named shard and OWNER-SIGN the assignment, then return the
        resulting placement.

    A tenant can NEVER reach this with a self-chosen shard: ``shard_ids`` is OWNER config (``config.shard_ids``),
    never request input, and the mint goes through the owner-key-holding registry — so "a tenant self-assigns a
    shard" is impossible by construction, not by a check. The caller gates the whole call on the PR-F flag +
    ``multi_shard_enabled`` (see ``provision.Provisioner._place_on_signup``)."""
    existing = registry.placement(org_id)
    if existing is not None:
        return existing
    shard = choose_shard(list(shard_ids), current_loads(registry))
    if shard is None:
        return None
    registry.assign(org_id, shard, issued_at=issued_at)
    return registry.placement(org_id)
