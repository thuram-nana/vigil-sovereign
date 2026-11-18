"""Front C (in-repo) — offense-worker TENANT ISOLATION holds across a FLEET at scale.

The D2 contract (`common/tenant.py`): ONE ``CRUCIBLE_ROOT`` per tenant, ``CRUCIBLE_TENANT`` pins each worker's
spine/memory shard, and every fleet worker calls ``assert_tenant_fleet_isolated`` at startup (fail-closed).
`agents/tests/test_blackboard_sharding.py` proves it for two tenants and one shared root. This file proves it
holds for a FLEET — the owner's target is 10,000 concurrent engagements (HANDOFF §13.1), i.e. 10,000 workers,
one root each — and that nothing in it grows with the fleet:

  * F1 DISJOINT AT SCALE — M tenants (default 10,000) resolve 2M pairwise-disjoint store paths. For EVERY
    tenant the env-driven path a worker actually opens equals the explicit computation and has the shape
    base/<store>/tenants/<id>/store.sqlite with a validated single-component id; distinct ids are therefore
    distinct sibling dirs, so no path equals or nests inside another (and all 2M are checked distinct).
    ``assert_isolated_from`` holds on boundary + sampled pairs, and fires on a same-tenant positive control.
  * F2 FAIL-CLOSED AT SCALE — R dedicated roots (default 1,000) are each claimed by their own tenant (TOFU,
    idempotent re-attach); a foreign tenant starting in a claimed root is REFUSED for boundary + sampled pairs
    and never steals the claim; an unsharded worker is refused.
  * F3 A FAULT STAYS IN ITS ROOT — a malformed claim, or a foreign tenant's shard, in ONE root of the fleet
    fails closed for every tenant there, while every other root's worker still starts.
  * F4 O(1) PER WORKER — after all R workers open their stores, each root holds exactly its own tenant's
    shard, so the startup guard's scan (``_other_tenant_shards``: two directory listings of its OWN root) is
    two entries for every worker, whatever R is.
  * F5 SIMULTANEOUS FLEET START — several roots, each raced by several real processes released at once (an
    autoscale burst): EXACTLY ONE winner per root, every other contender fails closed, and each root's
    recorded owner is its winner.

Scale knobs (no silent cap; the values are in the test ids): ``VIGIL_SCALE_FLEET_M`` (F1),
``VIGIL_SCALE_FLEET_ROOTS`` (F2-F4), ``VIGIL_SCALE_FLEET_RACE`` (F5, ``<roots>x<contenders>``).
What this does NOT prove (owner deploy work, out of the repo): that a real orchestrator gives every worker
its own root and tenant pin — the guard makes a mis-deploy a hard startup error, which is what is in-repo.

The sovereign twin (fold cache + per-org admission at 100k / 1M): apps/sigil/tests/test_front_c_scale.py.
"""
from __future__ import annotations

import multiprocessing
import os
import random

import pytest

from framework.v2.common import paths, tenant
from framework.v2.common.tenant import TenantIsolationError

_FLEET_M = int(os.environ.get("VIGIL_SCALE_FLEET_M", "10000"))
_ROOTS_R = int(os.environ.get("VIGIL_SCALE_FLEET_ROOTS", "1000"))
_RACE_ROOTS, _RACE_K = (int(x) for x in os.environ.get("VIGIL_SCALE_FLEET_RACE", "6x4").split("x"))
if _FLEET_M < 3 or _ROOTS_R < 3 or _RACE_ROOTS < 1 or _RACE_K < 2:   # loud, never a silently smaller test
    raise ValueError(f"fleet scale knobs too small to test isolation: M={_FLEET_M} R={_ROOTS_R} "
                     f"race={_RACE_ROOTS}x{_RACE_K} (need M, R >= 3 and a race of at least 1x2)")


def _tid(i: int) -> str:
    """Fleet member i's tenant id — the sovereign side's org id format (org == tenant_id)."""
    return f"org_scale_{i:09d}"


def _pairs(n: int, k: int, seed: int) -> "list[tuple[int, int]]":
    """Boundary pairs (first/last both ways, adjacent) + `k` deterministic random pairs, i != j."""
    rng = random.Random(seed)
    out = [(0, n - 1), (n - 1, 0), (0, 1), (1, 0), (n - 2, n - 1), (n - 1, n - 2)]
    out += [(rng.randrange(n), rng.randrange(n)) for _ in range(k)]
    return [(i, j) for i, j in out if i != j]


@pytest.fixture
def fleet_root(monkeypatch):
    """Point ``paths.v2_root`` at a switchable root (a worker's dedicated CRUCIBLE_ROOT)."""
    current: dict = {"root": None}
    monkeypatch.setattr(paths, "v2_root", lambda: current["root"])
    return current


# ============ F1 — M tenants, 2M pairwise-disjoint stores ==============================================
@pytest.mark.parametrize("m", [pytest.param(_FLEET_M, id=f"M={_FLEET_M}")])
def test_f1_every_tenant_of_the_fleet_resolves_disjoint_stores(m, tmp_path, monkeypatch, fleet_root):
    base = tmp_path / "root"
    fleet_root["root"] = base
    seen: set = set()
    for i in range(m):
        t = _tid(i)
        monkeypatch.setenv("CRUCIBLE_TENANT", t)
        mine = tenant.store_paths()                            # the env-driven paths a worker opens
        assert mine == tenant.store_paths(t), f"tenant {i}: env-driven != explicit store paths"
        for kind, store_dir in (("blackboard", ".blackboard"), ("memory", ".memory")):
            p = mine[kind]
            assert p.name == "store.sqlite" and p.parent.name == t, (i, kind, p)
            assert p.parent.parent == base / store_dir / paths._TENANT_SUBDIR, (i, kind, p)
            seen.add(p)
    assert len(seen) == 2 * m, f"{2 * m - len(seen)} store paths collide across a fleet of {m}"
    for i, j in _pairs(m, 500, seed=m):
        monkeypatch.setenv("CRUCIBLE_TENANT", _tid(i))
        tenant.assert_isolated_from(_tid(j))                   # disjoint => no raise
    monkeypatch.setenv("CRUCIBLE_TENANT", _tid(m // 2))
    with pytest.raises(AssertionError, match="not disjoint"):  # positive control: the guard is not vacuous
        tenant.assert_isolated_from(_tid(m // 2))


# ============ F2 — every root claims itself; every foreign start is refused ============================
def _claim_fleet(tmp_path, monkeypatch, fleet_root, r: int) -> list:
    roots = [tmp_path / f"r{i:07d}" for i in range(r)]
    for i, root in enumerate(roots):
        fleet_root["root"] = root
        monkeypatch.setenv("CRUCIBLE_TENANT", _tid(i))
        tenant.assert_tenant_fleet_isolated()                  # TOFU claim of its own root
    return roots


@pytest.mark.parametrize("r", [pytest.param(_ROOTS_R, id=f"R={_ROOTS_R}")])
def test_f2_each_root_admits_only_its_own_tenant_across_the_fleet(r, tmp_path, monkeypatch, fleet_root):
    roots = _claim_fleet(tmp_path, monkeypatch, fleet_root, r)
    for i, root in enumerate(roots):
        fleet_root["root"] = root
        monkeypatch.setenv("CRUCIBLE_TENANT", _tid(i))
        tenant.assert_tenant_fleet_isolated()                  # idempotent re-attach
        assert tenant.root_owner() == _tid(i)
    for i, j in _pairs(r, 2000, seed=r):
        fleet_root["root"] = roots[i]
        monkeypatch.setenv("CRUCIBLE_TENANT", _tid(j))
        with pytest.raises(TenantIsolationError, match="owned by tenant"):
            tenant.assert_tenant_fleet_isolated()
        assert tenant.root_owner() == _tid(i), f"tenant {j}'s refused start changed root {i}'s owner"
    fleet_root["root"] = roots[0]
    monkeypatch.delenv("CRUCIBLE_TENANT", raising=False)
    with pytest.raises(TenantIsolationError, match="not sharded"):
        tenant.assert_tenant_fleet_isolated()


# ============ F3 — a fault in one root fails closed THERE and nowhere else =============================
@pytest.mark.parametrize("r", [pytest.param(_ROOTS_R, id=f"R={_ROOTS_R}")])
def test_f3_a_poisoned_root_fails_closed_without_touching_the_fleet(r, tmp_path, monkeypatch, fleet_root):
    roots = _claim_fleet(tmp_path, monkeypatch, fleet_root, r)
    bad_claim, bad_shard = r // 3, (2 * r) // 3
    (roots[bad_claim] / ".tenant-owner").write_text("not a tenant/../id\n")         # malformed claim
    (roots[bad_shard] / ".blackboard" / paths._TENANT_SUBDIR / _tid(r + 1)).mkdir(parents=True)  # foreign shard
    for who in (bad_claim, (bad_claim + 1) % r):
        fleet_root["root"] = roots[bad_claim]
        monkeypatch.setenv("CRUCIBLE_TENANT", _tid(who))
        with pytest.raises(TenantIsolationError, match="malformed"):
            tenant.assert_tenant_fleet_isolated()
    fleet_root["root"] = roots[bad_shard]
    monkeypatch.setenv("CRUCIBLE_TENANT", _tid(bad_shard))
    with pytest.raises(TenantIsolationError, match="shared"):
        tenant.assert_tenant_fleet_isolated()
    for i, root in enumerate(roots):
        if i in (bad_claim, bad_shard):
            continue
        fleet_root["root"] = root
        monkeypatch.setenv("CRUCIBLE_TENANT", _tid(i))
        tenant.assert_tenant_fleet_isolated()                  # the rest of the fleet is unaffected


# ============ F4 — the startup guard's scan is O(1) per worker, whatever the fleet size ================
@pytest.mark.parametrize("r", [pytest.param(_ROOTS_R, id=f"R={_ROOTS_R}")])
def test_f4_each_workers_guard_scans_only_its_own_shard(r, tmp_path, monkeypatch, fleet_root):
    roots = _claim_fleet(tmp_path, monkeypatch, fleet_root, r)
    for i, root in enumerate(roots):                           # every worker opens its stores
        fleet_root["root"] = root
        monkeypatch.setenv("CRUCIBLE_TENANT", _tid(i))
        for p in tenant.store_paths().values():
            p.parent.mkdir(parents=True, exist_ok=True)
    for i, root in enumerate(roots):
        for store_dir in (".blackboard", ".memory"):
            listed = sorted(os.listdir(root / store_dir / paths._TENANT_SUBDIR))
            assert listed == [_tid(i)], f"root {i}'s {store_dir} lists {listed[:3]}… (expected only its own)"
        fleet_root["root"] = root
        monkeypatch.setenv("CRUCIBLE_TENANT", _tid(i))
        assert tenant._other_tenant_shards(_tid(i)) == []
        tenant.assert_tenant_fleet_isolated()


# ============ F5 — a simultaneous fleet start: exactly one winner per root =============================
def _fleet_burst_worker(tenant_name: str, root_str: str, go_path: str, q) -> None:
    """A real separate process (module-level so a fork-context Process can target it): waits on the shared
    'go' file, then runs the fleet guard against its root and reports (root, tenant, outcome)."""
    import os as _os
    import time as _time
    from pathlib import Path as _Path
    from framework.v2.common import paths as _paths, tenant as _t

    _paths.v2_root = lambda: _Path(root_str)
    _os.environ["CRUCIBLE_TENANT"] = tenant_name
    while not _os.path.exists(go_path):
        _time.sleep(0.001)
    try:
        _t.assert_tenant_fleet_isolated()
        q.put((root_str, tenant_name, "PASS"))
    except _t.TenantIsolationError:
        q.put((root_str, tenant_name, "FAILCLOSED"))
    except BaseException as e:  # noqa: BLE001 — any other shape is a test failure
        q.put((root_str, tenant_name, "ERROR:" + repr(e)))


@pytest.mark.parametrize("shape", [pytest.param((_RACE_ROOTS, _RACE_K), id=f"burst={_RACE_ROOTS}x{_RACE_K}")])
def test_f5_a_simultaneous_fleet_start_has_exactly_one_winner_per_root(shape, tmp_path):
    n_roots, k = shape
    ctx = multiprocessing.get_context("fork")
    go = tmp_path / "GO"
    q = ctx.Queue()
    roots = [tmp_path / f"burst{r}" for r in range(n_roots)]
    procs = []
    for r, root in enumerate(roots):
        root.mkdir()
        procs += [ctx.Process(target=_fleet_burst_worker, args=(_tid(r * k + c), str(root), str(go), q))
                  for c in range(k)]
    for p in procs:
        p.start()
    go.write_text("go")                                        # release the whole fleet at once
    results = [q.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(timeout=60)
    assert not [x for x in results if x[2].startswith("ERROR")], results
    for root in roots:
        mine = [x for x in results if x[0] == str(root)]
        winners = [x[1] for x in mine if x[2] == "PASS"]
        assert len(mine) == k and len(winners) == 1, (str(root), mine)
        assert sum(1 for x in mine if x[2] == "FAILCLOSED") == k - 1, mine
        assert (root / ".tenant-owner").read_text().strip() == winners[0]
