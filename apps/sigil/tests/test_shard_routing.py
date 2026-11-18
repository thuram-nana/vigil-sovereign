"""Front C S2b/S2c — the pure shard routing resolver (tenant -> shard root/store + per-shard queue).

Invariants pinned here:
  * flag OFF -> the historical SINGLETON for EVERY tenant, regardless of assignment (byte-identical: an assigned
    and an unassigned tenant resolve identically; the assignment is never consulted);
  * flag ON -> an assigned tenant resolves to its shard's DEDICATED root (crucible_root = shard_base/<tenant>,
    crucible_tenant = tenant), and an UNASSIGNED tenant is REFUSED (fail-closed, never defaulted);
  * two tenants' roots are physically DISJOINT (the sovereign half of assert_tenant_fleet_isolated: one root per
    tenant) — so a worker launched from a route passes the offense fleet guard by construction;
  * the per-shard job-queue root isolates a shard to its own tenants' jobs;
  * a route is STALE after an epoch bump and the consumer fails closed.
"""
from __future__ import annotations

import itertools
import tempfile
from pathlib import Path

import pytest

from sigil.governor import shard_routing as sr
from sigil.governor.shard_assignment import ShardAssignmentRegistry, ShardPlacement
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_c = itertools.count(1)


def _t() -> float:
    return float(next(_c))


def _topo(tmp_path):
    return sr.ShardTopology({"shardA": tmp_path / "A", "shardB": tmp_path / "B"})


def _default_root(tmp_path):
    return tmp_path / "single"


def _place(tenant, shard, epoch=1):
    return ShardPlacement(tenant_id=tenant, shard_id=shard, epoch=epoch, issued_at=float(epoch))


# -- flag OFF: byte-identical singleton ----------------------------------------------------------------
def test_flag_off_resolves_the_singleton_default(tmp_path):
    r = sr.resolve("acme", placement=_place("acme", "shardA"), topology=_topo(tmp_path),
                   default_root=_default_root(tmp_path), multi_shard=False)
    assert r.singleton and r.crucible_tenant == "" and r.crucible_root == _default_root(tmp_path)


def test_flag_off_is_byte_identical_whether_or_not_the_tenant_is_assigned(tmp_path):
    # THE byte-identical proof: with the flag off, an assigned and an unassigned tenant resolve to the IDENTICAL
    # route (the assignment is never consulted) — the pre-S2 single-root behaviour, unchanged.
    args = dict(topology=_topo(tmp_path), default_root=_default_root(tmp_path), multi_shard=False)
    assigned = sr.resolve("acme", placement=_place("acme", "shardA", epoch=4), **args)
    unassigned = sr.resolve("acme", placement=None, **args)
    assert assigned == unassigned


def test_flag_off_resolve_for_never_reads_the_registry(tmp_path):
    class _Boom:
        def placement(self, _tid):
            raise AssertionError("resolve_for must NOT read the registry when the flag is off")
    r = sr.resolve_for(_Boom(), "acme", topology=_topo(tmp_path), default_root=_default_root(tmp_path),
                       multi_shard=False)
    assert r.singleton


# -- flag ON: routed ------------------------------------------------------------------------------------
def test_flag_on_resolves_an_assigned_tenant_to_its_shard_root(tmp_path):
    r = sr.resolve("acme", placement=_place("acme", "shardA", epoch=3), topology=_topo(tmp_path),
                   default_root=_default_root(tmp_path), multi_shard=True)
    assert not r.singleton and r.shard_id == "shardA" and r.epoch == 3
    assert r.crucible_root == tmp_path / "A" / "acme" and r.crucible_tenant == "acme"


def test_flag_on_refuses_an_unassigned_tenant(tmp_path):
    with pytest.raises(sr.UnassignedTenantError):
        sr.resolve("acme", placement=None, topology=_topo(tmp_path),
                   default_root=_default_root(tmp_path), multi_shard=True)


def test_flag_on_refuses_an_assignment_to_an_unknown_shard(tmp_path):
    with pytest.raises(sr.ShardTopologyError):
        sr.resolve("acme", placement=_place("acme", "shardZ"), topology=_topo(tmp_path),
                   default_root=_default_root(tmp_path), multi_shard=True)


def test_flag_on_resolve_for_reads_the_registry(tmp_path):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    reg = ShardAssignmentRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    reg.assign("acme", "shardB", issued_at=_t())
    r = sr.resolve_for(reg, "acme", topology=_topo(tmp_path), default_root=_default_root(tmp_path), multi_shard=True)
    assert r.shard_id == "shardB" and r.crucible_root == tmp_path / "B" / "acme"


# -- isolation (composing with assert_tenant_fleet_isolated) -------------------------------------------
def test_two_tenants_resolve_to_disjoint_roots(tmp_path):
    args = dict(topology=_topo(tmp_path), default_root=_default_root(tmp_path), multi_shard=True)
    a = sr.resolve("acme", placement=_place("acme", "shardA"), **args)
    b = sr.resolve("globex", placement=_place("globex", "shardA"), **args)   # SAME shard, different tenants
    sr.assert_route_isolated_from(a, b)                                      # must not raise: disjoint roots
    assert a.crucible_root != b.crucible_root


def test_isolation_guard_fires_on_a_shared_root(tmp_path):
    args = dict(topology=_topo(tmp_path), default_root=_default_root(tmp_path), multi_shard=True)
    a = sr.resolve("acme", placement=_place("acme", "shardA"), **args)
    with pytest.raises(AssertionError, match="isolation violated"):
        sr.assert_route_isolated_from(a, a)                                 # identical root -> not disjoint


def test_crucible_env_carries_root_and_tenant_when_routed(tmp_path):
    r = sr.resolve("acme", placement=_place("acme", "shardA"), topology=_topo(tmp_path),
                   default_root=_default_root(tmp_path), multi_shard=True)
    assert sr.crucible_env(r) == {"CRUCIBLE_ROOT": str(tmp_path / "A" / "acme"), "CRUCIBLE_TENANT": "acme"}


def test_crucible_env_omits_tenant_for_the_singleton(tmp_path):
    r = sr.resolve("acme", placement=None, topology=_topo(tmp_path),
                   default_root=_default_root(tmp_path), multi_shard=False)
    assert sr.crucible_env(r) == {"CRUCIBLE_ROOT": str(_default_root(tmp_path))}   # no CRUCIBLE_TENANT


# -- per-shard job queue --------------------------------------------------------------------------------
def test_per_shard_queue_root_isolates_a_shard_to_its_own_tenants(tmp_path):
    args = dict(topology=_topo(tmp_path), default_root=_default_root(tmp_path), multi_shard=True)
    a = sr.resolve("acme", placement=_place("acme", "shardA"), **args)
    b = sr.resolve("globex", placement=_place("globex", "shardA"), **args)      # same shard
    z = sr.resolve("zeta", placement=_place("zeta", "shardB"), **args)          # other shard
    assert a.queue_root == b.queue_root == tmp_path / "A" / "queue"             # one queue per shard
    assert z.queue_root == tmp_path / "B" / "queue"
    assert a.queue_root != z.queue_root                                         # a shard never drains another's


def test_a_shard_refuses_to_drain_another_shards_tenant(tmp_path):
    r = sr.resolve("acme", placement=_place("acme", "shardA"), topology=_topo(tmp_path),
                   default_root=_default_root(tmp_path), multi_shard=True)
    sr.assert_job_targets_shard(r, "shardA")                                   # own tenant: ok
    with pytest.raises(sr.RoutingError):
        sr.assert_job_targets_shard(r, "shardB")                               # foreign shard: refused


# -- stale route after an epoch bump --------------------------------------------------------------------
def test_a_route_is_stale_after_an_epoch_bump(tmp_path):
    args = dict(topology=_topo(tmp_path), default_root=_default_root(tmp_path), multi_shard=True)
    route = sr.resolve("acme", placement=_place("acme", "shardA", epoch=1), **args)
    assert sr.route_is_current(route, _place("acme", "shardA", epoch=1))
    # after a migration bumps the placement to (shardB, epoch 2) the old route is stale -> consumer fails closed.
    new_placement = _place("acme", "shardB", epoch=2)
    assert not sr.route_is_current(route, new_placement)
    with pytest.raises(sr.StaleRouteError):
        sr.assert_route_current(route, new_placement)


def test_a_route_to_an_unassigned_tenant_is_not_current(tmp_path):
    route = sr.resolve("acme", placement=_place("acme", "shardA"), topology=_topo(tmp_path),
                       default_root=_default_root(tmp_path), multi_shard=True)
    assert not sr.route_is_current(route, None)


# -- the env flag path ----------------------------------------------------------------------------------
def test_the_env_flag_drives_resolve_when_not_passed_explicitly(tmp_path, monkeypatch):
    args = dict(topology=_topo(tmp_path), default_root=_default_root(tmp_path))
    monkeypatch.delenv("VIGIL_MULTI_SHARD", raising=False)
    assert sr.resolve("acme", placement=_place("acme", "shardA"), **args).singleton      # off by default
    monkeypatch.setenv("VIGIL_MULTI_SHARD", "1")
    assert not sr.resolve("acme", placement=_place("acme", "shardA"), **args).singleton   # on -> routed
