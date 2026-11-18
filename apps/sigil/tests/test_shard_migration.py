"""Front C S3 — the live tenant-migration orchestrator (pause -> drain -> copy+verify -> epoch -> resume).

Invariants pinned here:
  * the full sequence moves a tenant between two in-process 'shards' (two roots): the data is copied + VERIFIED, the
    epoch is bumped, the pause is cleared;
  * it is IDEMPOTENT (re-running is a no-op) and CRASH-SAFE: a crash at ANY step leaves a recoverable state —
    fully OLD (before the epoch bump) or fully NEW (after it), NEVER a split placement;
  * the copy is HASH-VERIFIED: a corrupt copy fails closed (MigrationVerifyError) and the placement stays on the
    intact source shard;
  * the epoch bump makes a stale route fail closed;
  * drain is fail-closed (a mid-flight job refuses the copy);
  * cross-tenant isolation holds across the migration (the moved tenant's new root is disjoint from others');
  * the flag OFF refuses to run (byte-identical singleton default).
"""
from __future__ import annotations

import itertools
import tempfile
from pathlib import Path

import pytest

from sigil.governor import shard_migration as sm
from sigil.governor import shard_routing as srt
from sigil.governor.shard_assignment import ShardAssignmentRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_c = itertools.count(1)


def _t() -> float:
    return float(next(_c))


@pytest.fixture(autouse=True)
def _multi_shard_on(monkeypatch):
    monkeypatch.setenv("VIGIL_MULTI_SHARD", "1")


def _seed_root(base: Path, tenant: str, marker: str) -> Path:
    root = base / tenant
    root.mkdir(parents=True)
    (root / "spine.jsonl").write_text(f"spine-{marker}", encoding="utf-8")
    (root / "fold").mkdir()
    (root / "fold" / "cache.bin").write_text(f"fold-{marker}", encoding="utf-8")
    return root


def _fixture(tmp_path, *, inflight=0, tenant="acme"):
    """A registry with ``tenant`` assigned to shardA (seeded on disk), an orchestrator over two shard bases."""
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    reg = ShardAssignmentRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    reg.assign(tenant, "shardA", issued_at=_t())
    baseA, baseB = tmp_path / "A", tmp_path / "B"
    topo = srt.ShardTopology({"shardA": baseA, "shardB": baseB})
    _seed_root(baseA, tenant, "A")
    orch = sm.ShardMigrationOrchestrator(reg, topology=topo, workdir=tmp_path / "ctrl",
                                         inflight=lambda _tid: inflight, clock=_t)
    plan = sm.MigrationPlan(tenant, "shardA", "shardB", reg.placement(tenant).epoch, f"mig-{tenant}")
    return reg, orch, plan, baseA, baseB


def test_full_migration_moves_the_tenant_and_copies_verified_data(tmp_path):
    reg, orch, plan, baseA, baseB = _fixture(tmp_path)
    assert orch.run(plan) == sm.DONE
    p = reg.placement("acme")
    assert p.shard_id == "shardB" and p.epoch == 2                      # authoritative switch committed
    assert (baseB / "acme" / "spine.jsonl").read_text() == "spine-A"    # data copied...
    assert (baseB / "acme" / "fold" / "cache.bin").read_text() == "fold-A"
    assert sm.tree_digest(baseB / "acme") == sm.tree_digest(baseA / "acme")   # ...and verified equal
    assert not sm.is_tenant_paused(tmp_path / "ctrl", "acme")           # resumed


def test_migration_is_idempotent(tmp_path):
    reg, orch, plan, _a, _b = _fixture(tmp_path)
    assert orch.run(plan) == sm.DONE
    records_before = len(list(reg.store.iter_records()))
    assert orch.run(plan) == sm.DONE                                    # re-run: no-op
    assert len(list(reg.store.iter_records())) == records_before        # no second epoch bump


def test_flag_off_refuses_to_run(tmp_path, monkeypatch):
    reg, orch, plan, _a, _b = _fixture(tmp_path)
    monkeypatch.delenv("VIGIL_MULTI_SHARD", raising=False)
    with pytest.raises(sm.MigrationDisabled):
        orch.run(plan)
    assert reg.placement("acme").shard_id == "shardA"                   # nothing moved


def test_drain_is_fail_closed_on_a_mid_flight_job(tmp_path):
    reg, orch, plan, _a, baseB = _fixture(tmp_path, inflight=2)
    with pytest.raises(sm.MigrationNotDrained):
        orch.run(plan)
    assert reg.placement("acme").shard_id == "shardA"                   # not migrated
    assert not (baseB / "acme").exists()                               # not copied
    assert orch.status(plan) == sm.PAUSED                               # journal stopped before drain


def test_a_corrupt_copy_fails_closed_and_keeps_the_old_placement(tmp_path, monkeypatch):
    reg, orch, plan, baseA, baseB = _fixture(tmp_path)

    def _corrupt_copy(src, dst):
        import shutil
        shutil.copytree(src, dst)
        (Path(dst) / "spine.jsonl").write_text("CORRUPTED", encoding="utf-8")   # a lossy/corrupt transport

    monkeypatch.setattr(sm, "_copy_tree", _corrupt_copy)
    with pytest.raises(sm.MigrationVerifyError):
        orch.run(plan)
    assert reg.placement("acme").shard_id == "shardA" and reg.placement("acme").epoch == 1   # epoch NOT bumped
    assert not (baseB / "acme").exists()                               # the corrupt temp was never published
    assert orch.status(plan) == sm.DRAINED                             # stopped at the copy step


def test_copy_and_verify_detects_a_byte_difference(tmp_path):
    src = _seed_root(tmp_path, "src", "x")
    good = sm.copy_and_verify(src, tmp_path / "good")
    assert sm.tree_digest(tmp_path / "good") == good
    # a destination that differs by one byte must not hash-equal the source
    (tmp_path / "good" / "spine.jsonl").write_text("spine-x-tampered", encoding="utf-8")
    assert sm.tree_digest(tmp_path / "good") != good


def test_copy_and_verify_is_idempotent_when_dst_already_matches(tmp_path):
    src = _seed_root(tmp_path, "src", "x")
    first = sm.copy_and_verify(src, tmp_path / "dst")
    second = sm.copy_and_verify(src, tmp_path / "dst")                  # dst already matches -> no re-copy, same digest
    assert first == second == sm.tree_digest(src)


@pytest.mark.parametrize("crash_step", [sm.PAUSED, sm.DRAINED, sm.COPIED, sm.COMMITTED])
def test_a_crash_at_each_step_is_recoverable_with_no_split_brain(tmp_path, crash_step):
    reg, orch, plan, baseA, baseB = _fixture(tmp_path)
    # Simulate a crash immediately after `crash_step`.
    assert orch.run(plan, stop_after=crash_step) == crash_step
    p = reg.placement("acme")
    # THE no-split-brain invariant: the authoritative placement is EITHER fully old OR fully new, never ambiguous.
    before_commit = sm._STEP_INDEX[crash_step] < sm._STEP_INDEX[sm.COMMITTED]
    if before_commit:
        assert (p.shard_id, p.epoch) == ("shardA", 1)                  # still fully OLD (routes to the intact source)
    else:
        assert (p.shard_id, p.epoch) == ("shardB", 2)                  # already fully NEW (data copied + verified)
    assert sm.is_tenant_paused(tmp_path / "ctrl", "acme")              # paused until the final resume (fail-closed)
    # A FRESH orchestrator recovers the interrupted migration to DONE.
    orch2 = sm.ShardMigrationOrchestrator(reg, topology=orch.topology, workdir=tmp_path / "ctrl",
                                          inflight=lambda _tid: 0, clock=_t)
    assert orch2.run(plan) == sm.DONE
    p2 = reg.placement("acme")
    assert (p2.shard_id, p2.epoch) == ("shardB", 2)
    assert sm.tree_digest(baseB / "acme") == sm.tree_digest(baseA / "acme")
    assert not sm.is_tenant_paused(tmp_path / "ctrl", "acme")


def test_a_crash_after_the_commit_effect_before_its_journal_write_is_recoverable(tmp_path):
    # The HARDER crash case: the epoch-bump effect lands on the spine but the journal write is lost in the gap.
    # Re-driving must NOT double-bump (exactly-once) — the registry's idempotent reassign guarantees it.
    reg, orch, plan, baseA, baseB = _fixture(tmp_path)
    orch.run(plan, stop_after=sm.COPIED)                   # journal at COPIED
    orch._do_commit(plan)                                  # the commit EFFECT happens (epoch bumped)...
    assert reg.placement("acme").epoch == 2
    assert orch.status(plan) == sm.COPIED                  # ...but the journal write was 'lost' (still COPIED)
    records_after_effect = len(list(reg.store.iter_records()))
    orch2 = sm.ShardMigrationOrchestrator(reg, topology=orch.topology, workdir=tmp_path / "ctrl",
                                          inflight=lambda _tid: 0, clock=_t)
    assert orch2.run(plan) == sm.DONE
    assert reg.placement("acme").epoch == 2                # still 2, not 3 — no second bump (exactly-once)
    assert len(list(reg.store.iter_records())) == records_after_effect   # no duplicate assignment record


def test_the_epoch_bump_makes_a_pre_migration_route_stale(tmp_path):
    reg, orch, plan, baseA, baseB = _fixture(tmp_path)
    topo = orch.topology
    route_before = srt.resolve_for(reg, "acme", topology=topo, default_root=tmp_path / "single", multi_shard=True)
    assert srt.route_is_current(route_before, reg.placement("acme"))
    orch.run(plan)
    # the cached pre-migration route (shardA, epoch 1) is now stale against the committed placement (shardB, epoch 2)
    with pytest.raises(srt.StaleRouteError):
        srt.assert_route_current(route_before, reg.placement("acme"))
    route_after = srt.resolve_for(reg, "acme", topology=topo, default_root=tmp_path / "single", multi_shard=True)
    assert route_after.shard_id == "shardB" and route_after.epoch == 2


def test_cross_tenant_isolation_holds_across_a_migration(tmp_path):
    reg, orch, plan, baseA, baseB = _fixture(tmp_path)
    # a second tenant stays put on shardA while acme migrates to shardB
    reg.assign("globex", "shardA", issued_at=_t())
    _seed_root(baseA, "globex", "G")
    orch.run(plan)
    topo = orch.topology
    r_acme = srt.resolve_for(reg, "acme", topology=topo, default_root=tmp_path / "single", multi_shard=True)
    r_globex = srt.resolve_for(reg, "globex", topology=topo, default_root=tmp_path / "single", multi_shard=True)
    srt.assert_route_isolated_from(r_acme, r_globex)                    # disjoint roots across shards
    assert r_acme.shard_id == "shardB" and r_globex.shard_id == "shardA"


def test_a_journal_for_a_different_plan_is_refused(tmp_path):
    reg, orch, plan, _a, _b = _fixture(tmp_path)
    orch.run(plan, stop_after=sm.PAUSED)
    # a DIFFERENT plan (different source shard) reusing the same migration id must be refused (fail-closed)
    other = sm.MigrationPlan("acme", "shardX", "shardB", 1, plan.migration_id)
    with pytest.raises(sm.MigrationPlanConflict):
        orch.run(other)


def test_is_tenant_paused_is_fail_closed_on_presence(tmp_path):
    workdir = tmp_path / "ctrl"
    assert not sm.is_tenant_paused(workdir, "acme")                    # no marker -> not paused (default-off)
    sm._set_pause(workdir, "acme", "mig-1")
    assert sm.is_tenant_paused(workdir, "acme")                        # present -> paused (even if unreadable)
    sm._clear_pause(workdir, "acme")
    assert not sm.is_tenant_paused(workdir, "acme")
