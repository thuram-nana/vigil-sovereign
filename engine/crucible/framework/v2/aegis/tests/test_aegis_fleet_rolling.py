"""AS-6e — the AEGIS ROLLING (staged, health-gated) fleet reconcile over AS-6a.

Deterministic, OFFLINE tests. They prove the rolling increment the FLEET chain (6a -> 29 -> 6e -> 27b)
names —

  * e2e: a multi-host epoch rollout converges GRADUALLY, at most ``max_surge`` hosts mid-rollout at any
    tick (where AS-6a would roll the whole fleet at once), and reaches a converged no-op;
  * negative control: a health gate that never settles STALLS the rollout after the first batch (it never
    tears the fleet over on an unproven replacement);
  * the DEFAULT-OFF flag (inert + flag-off golden byte-identical; AS-6a stays big-bang when rolling is off);
  * determinism (same desired+state+now+health => byte-identical result; content-hash action ids);
  * FATAL-2 (no cross-plane import) + gate-invariance (off the __init__/__main__ path; oracle count stays
    15; adds no WorkerKind);
  * the AS-6a guard rails carried THROUGH (tampered image / non-TT origin still refuse; enforcement never
    rendered — observe-only).

No wall-clock, no RNG, no network: ``now`` is injected and every id is a content hash.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from framework.v2.aegis import aegis_fleet as F
from framework.v2.aegis import aegis_fleet_rolling as R
from vigil_core.authority_v2 import MonitoringCapability

NOW = 1_000_000.0
_LOCKED = F.locked_image_digest()  # the real AS-28 committed digest


# --------------------------------------------------------------------------------------------------
# Test doubles (in-memory, deterministic).
# --------------------------------------------------------------------------------------------------
class MemSnapshotSink:
    def __init__(self) -> None:
        self.stored: list[F.Snapshot] = []

    def store(self, snapshot: F.Snapshot) -> bool:
        self.stored.append(snapshot)
        return True


class NeverSettles:
    """A probe-backed health that reports NO worker healthy — the rollout must stall (fail-closed)."""

    def settled(self, worker: F.RoutedWorker, *, now: float) -> bool:
        return False


class AlwaysSettles:
    def settled(self, worker: F.RoutedWorker, *, now: float) -> bool:
        return worker.health == F.WorkerHealth.STARTING


@pytest.fixture
def fleet_and_rolling_on(monkeypatch):
    monkeypatch.setenv(F.FLEET_ENV, "1")
    monkeypatch.setenv(R.ROLLING_ENV, "1")


def _worker(host, *, tenant="tt-a", epoch=1, digest=_LOCKED, caps=(MonitoringCapability.OBSERVE,)):
    return F.DesiredWorker(kind=F.WorkerKind.UNITS, tenant=tenant, host=host, desired_mode="observe",
                           capabilities=caps, image_digest=digest, epoch=epoch)


def _plain(sink=None):
    return F.FleetReconciler(snapshot_sink=sink or MemSnapshotSink())


def _rolling(*, max_surge=1, health=None, sink=None):
    return R.RollingFleetReconciler(_plain(sink), policy=R.RollingPolicy(max_surge=max_surge), health=health)


def _place_healthy(workers, *, sink=None):
    """Big-bang place a set of observe workers HEALTHY at epoch 1 via the plain AS-6a reconciler (the
    starting fleet the rollout then rolls)."""
    res = _plain(sink=sink).reconcile(list(workers), F.FleetState(), now=NOW)
    assert all(w.health == F.WorkerHealth.HEALTHY for w in res.state.workers)
    return res.state


def _starting_count(state: F.FleetState) -> int:
    return sum(1 for w in state.workers if w.health == F.WorkerHealth.STARTING)


# ==================================================================================================
# e2e — a multi-host epoch rollout converges GRADUALLY, at most max_surge mid-rollout per tick.
# ==================================================================================================
def test_e2e_rolling_epoch_bump_converges_one_at_a_time(fleet_and_rolling_on):
    hosts = ["app-a.tt-a.example", "app-b.tt-a.example", "app-c.tt-a.example"]
    start = _place_healthy([_worker(h, epoch=1) for h in hosts])
    rr = _rolling(max_surge=1)  # strict one-at-a-time, default ElapsedTickHealth
    desired = [_worker(h, epoch=2) for h in hosts]

    state = start
    max_in_flight = 0
    converged_tick = None
    for i in range(1, 9):  # plenty of ticks; it must converge well before this bound
        res = rr.reconcile(desired, state, now=NOW + 10 * i)
        assert not res.disabled
        state = res.state
        max_in_flight = max(max_in_flight, _starting_count(state))
        if res.converged:
            converged_tick = i
            break

    # The rolling invariant: never more than max_surge host mid-rollout at any tick.
    assert max_in_flight <= 1
    # It DID converge, and every host ended HEALTHY at the new epoch.
    assert converged_tick is not None
    assert all(w.health == F.WorkerHealth.HEALTHY and w.epoch == 2 for w in state.workers)
    # A 3-host, surge-1 rollout needs several ticks (NOT a single big-bang pass).
    assert converged_tick >= 3


def test_e2e_rolling_surge_two_rolls_two_at_once(fleet_and_rolling_on):
    hosts = [f"app-{i}.tt-a.example" for i in range(4)]
    start = _place_healthy([_worker(h, epoch=1) for h in hosts])
    rr = _rolling(max_surge=2)
    desired = [_worker(h, epoch=2) for h in hosts]
    # First tick: two hosts admitted into rollout, two deferred.
    res1 = rr.reconcile(desired, start, now=NOW + 10)
    assert len(res1.admitted) == 2 and len(res1.deferred) == 2
    assert _starting_count(res1.state) == 2
    # Converge the rest.
    state = res1.state
    for i in range(2, 8):
        res = rr.reconcile(desired, state, now=NOW + 10 * i)
        state = res.state
        assert _starting_count(state) <= 2  # never exceeds the surge budget
        if res.converged:
            break
    assert all(w.epoch == 2 and w.health == F.WorkerHealth.HEALTHY for w in state.workers)


def test_single_tick_admits_then_promotes_next_tick(fleet_and_rolling_on):
    a, b = "app-a.tt-a.example", "app-b.tt-a.example"
    start = _place_healthy([_worker(a, epoch=1), _worker(b, epoch=1)])
    rr = _rolling(max_surge=1)
    desired = [_worker(a, epoch=2), _worker(b, epoch=2)]

    t1 = rr.reconcile(desired, start, now=NOW + 10)
    # Admitted exactly the lowest-key host (deterministic order), the other deferred.
    assert len(t1.admitted) == 1 and len(t1.deferred) == 1
    rolled_key = t1.admitted[0]
    assert t1.state.get(rolled_key).health == F.WorkerHealth.STARTING and t1.state.get(rolled_key).epoch == 2
    assert not t1.converged

    t2 = rr.reconcile(desired, t1.state, now=NOW + 20)
    # The first host is PROMOTED (rolled_in) and the second admitted.
    assert rolled_key in t2.promoted
    assert any(a.verb == "rolled_in" and a.worker_key == rolled_key for a in t2.actions())
    assert t2.state.get(rolled_key).health == F.WorkerHealth.HEALTHY and t2.state.get(rolled_key).epoch == 2


# ==================================================================================================
# Negative control — a health gate that never settles STALLS the rollout (never over-rolls).
# ==================================================================================================
def test_health_gate_never_settles_stalls_rollout(fleet_and_rolling_on):
    hosts = ["app-a.tt-a.example", "app-b.tt-a.example", "app-c.tt-a.example"]
    start = _place_healthy([_worker(h, epoch=1) for h in hosts])
    rr = _rolling(max_surge=1, health=NeverSettles())
    desired = [_worker(h, epoch=2) for h in hosts]

    state = start
    for i in range(1, 6):
        res = rr.reconcile(desired, state, now=NOW + 10 * i)
        state = res.state
        assert _starting_count(state) == 1       # exactly one in-flight, forever — never advances
        assert res.promoted == ()                 # health never settles => no promotion
        assert not res.converged                  # and never converges
    # Two hosts remain on the OLD epoch (never torn over onto an unproven replacement).
    assert sum(1 for w in state.workers if w.epoch == 1 and w.health == F.WorkerHealth.HEALTHY) == 2


# ==================================================================================================
# Retire is NOT surge-governed — it proceeds even at zero budget (snapshot-first).
# ==================================================================================================
def test_retire_proceeds_even_at_zero_budget(fleet_and_rolling_on):
    sink = MemSnapshotSink()
    a, b = "app-a.tt-a.example", "app-b.tt-a.example"
    start = _place_healthy([_worker(a, epoch=1), _worker(b, epoch=1)], sink=sink)
    rr = _rolling(max_surge=1, health=NeverSettles(), sink=sink)
    # a: roll to epoch 2 (will occupy the only surge slot and stall); b: turn OFF (retire).
    off_b = F.DesiredWorker(kind=F.WorkerKind.UNITS, tenant="tt-a", host=b, desired_mode="off",
                            image_digest=_LOCKED, epoch=1)
    res = rr.reconcile([_worker(a, epoch=2), off_b], start, now=NOW + 10)
    # a is in-flight (surge slot taken); b is retired despite zero remaining budget.
    assert res.state.get(_worker(a).key).health == F.WorkerHealth.STARTING
    assert res.state.get(_worker(b).key).health == F.WorkerHealth.RETIRED
    assert len(res.result.snapshots) == 1  # snapshot FIRST, carried from AS-6a


# ==================================================================================================
# Idempotent — a converged fleet is a true no-op.
# ==================================================================================================
def test_converged_fleet_is_a_noop(fleet_and_rolling_on):
    hosts = ["app-a.tt-a.example", "app-b.tt-a.example"]
    start = _place_healthy([_worker(h, epoch=1) for h in hosts])
    rr = _rolling(max_surge=2)
    desired = [_worker(h, epoch=1) for h in hosts]  # already at the desired epoch
    res = rr.reconcile(desired, start, now=NOW + 10)
    assert res.converged
    assert res.admitted == () and res.deferred == () and res.promoted == ()
    assert res.actions() == ()
    # And a second identical pass is byte-identical.
    res2 = rr.reconcile(desired, res.state, now=NOW + 20)
    assert res2.golden() == res.golden()


# ==================================================================================================
# DEFAULT-OFF flag — inert + flag-off golden byte-identical; AS-6a stays big-bang.
# ==================================================================================================
def test_rolling_flag_off_is_inert(monkeypatch):
    monkeypatch.setenv(F.FLEET_ENV, "1")
    monkeypatch.delenv(R.ROLLING_ENV, raising=False)
    assert R.rolling_enabled() is False
    start = _place_healthy([_worker("app-a.tt-a.example", epoch=1)])
    rr = _rolling(max_surge=1)
    res = rr.reconcile([_worker("app-a.tt-a.example", epoch=2)], start, now=NOW + 10)
    assert res.disabled is True
    assert res.actions() == () and res.admitted == () and res.deferred == () and res.promoted == ()
    assert res.state == start  # nothing changed


def test_fleet_flag_off_makes_rolling_inert(monkeypatch):
    # Rolling on but the underlying fleet flag off => the whole fleet is inert, so rolling is inert too.
    monkeypatch.delenv(F.FLEET_ENV, raising=False)
    monkeypatch.setenv(R.ROLLING_ENV, "1")
    rr = _rolling(max_surge=1)
    res = rr.reconcile([_worker("app-a.tt-a.example", epoch=2)], F.FleetState(), now=NOW)
    assert res.disabled is True
    assert res.golden() == R._INERT_GOLDEN


def test_flag_off_golden_is_byte_identical_regardless_of_desired(monkeypatch):
    monkeypatch.delenv(R.ROLLING_ENV, raising=False)
    monkeypatch.setenv(F.FLEET_ENV, "1")
    rr = _rolling(max_surge=1)
    g1 = rr.reconcile([_worker("app-a.tt-a.example", epoch=2)], F.FleetState(), now=NOW).golden()
    g2 = rr.reconcile([_worker("app-z.tt-b.example", epoch=9)], F.FleetState(), now=NOW + 999).golden()
    assert g1 == g2 == R._INERT_GOLDEN


def test_as6a_stays_big_bang_when_rolling_off(monkeypatch):
    # With rolling OFF, the plain AS-6a reconciler still converges the WHOLE fleet in ONE pass (big-bang).
    monkeypatch.setenv(F.FLEET_ENV, "1")
    monkeypatch.delenv(R.ROLLING_ENV, raising=False)
    hosts = [f"app-{i}.tt-a.example" for i in range(3)]
    start = _place_healthy([_worker(h, epoch=1) for h in hosts])
    res = _plain().reconcile([_worker(h, epoch=2) for h in hosts], start, now=NOW + 10)
    # All three roll at once — the behaviour AS-6e stages, proven present when rolling is off.
    assert len({a.worker_key for a in res.actions if a.verb == "rollout"}) == 3


@pytest.mark.parametrize("token,expected", [("1", True), ("true", True), ("YES", True), ("on", True),
                                            ("0", False), ("", False), ("nope", False)])
def test_flag_token_parsing(monkeypatch, token, expected):
    monkeypatch.setenv(R.ROLLING_ENV, token)
    assert R.rolling_enabled() is expected


# ==================================================================================================
# Determinism — same (desired, state, now, health) => byte-identical result.
# ==================================================================================================
def test_determinism_rolling_tick(fleet_and_rolling_on):
    hosts = ["app-a.tt-a.example", "app-b.tt-a.example", "app-c.tt-a.example"]
    start = _place_healthy([_worker(h, epoch=1) for h in hosts])
    desired = [_worker(h, epoch=2) for h in hosts]
    g1 = _rolling(max_surge=1).reconcile(desired, start, now=NOW + 10).golden()
    g2 = _rolling(max_surge=1).reconcile(desired, start, now=NOW + 10).golden()
    assert g1 == g2
    assert g1["admitted"] and g1["actions"]  # non-empty, with content-hash action ids
    assert all(len(a[2]) == 64 for a in g1["actions"])  # sha256 hex


# ==================================================================================================
# AS-6a guard rails carried THROUGH the rolling layer.
# ==================================================================================================
def test_tampered_image_still_refuses_through_rolling(fleet_and_rolling_on):
    rr = _rolling(max_surge=1)
    bad = _worker("app-a.tt-a.example", epoch=1, digest="sha256:" + "0" * 64)
    res = rr.reconcile([bad], F.FleetState(), now=NOW)
    assert res.result.routed_keys() == ()
    assert [rf.code for rf in res.result.refusals] == ["tampered_image"]


def test_non_tt_origin_still_refuses_through_rolling(fleet_and_rolling_on):
    rr = _rolling(max_surge=1)
    real = _worker("app.acme.example", tenant="acme", epoch=1)
    res = rr.reconcile([real], F.FleetState(), now=NOW)
    assert res.result.routed_keys() == ()
    assert [rf.code for rf in res.result.refusals] == ["origin_not_sigil_tt"]


def test_no_enforcement_rendered_through_rolling(fleet_and_rolling_on):
    # Even with BLOCK in the grant, the rolled worker stays observe-only (no release source in AS-6a).
    rr = _rolling(max_surge=1)
    w = _worker("app-a.tt-a.example", epoch=1,
                caps=(MonitoringCapability.OBSERVE, MonitoringCapability.BLOCK))
    res = rr.reconcile([w], F.FleetState(), now=NOW)
    assert res.state.get(w.key).mode == "observe"


# ==================================================================================================
# The hold_keys seam on AS-6a (additive, default-empty => AS-6a byte-identical).
# ==================================================================================================
def test_hold_keys_pauses_a_worker_neither_converged_nor_retired(monkeypatch):
    monkeypatch.setenv(F.FLEET_ENV, "1")
    a, b = "app-a.tt-a.example", "app-b.tt-a.example"
    start = _place_healthy([_worker(a, epoch=1), _worker(b, epoch=1)])
    r = _plain()
    # Desired: bump BOTH to epoch 2, but HOLD b. b must be neither rolled nor retired.
    res = r.reconcile([_worker(a, epoch=2), _worker(b, epoch=2)], start, now=NOW + 10,
                      hold_keys=frozenset({_worker(b).key}))
    assert res.state.get(_worker(a).key).epoch == 2                 # a rolled
    held = res.state.get(_worker(b).key)
    assert held.epoch == 1 and held.health == F.WorkerHealth.HEALTHY  # b untouched (held)


def test_hold_keys_default_empty_is_as6a_identical(monkeypatch):
    monkeypatch.setenv(F.FLEET_ENV, "1")
    w = _worker("app-a.tt-a.example", epoch=1)
    g_default = _plain().reconcile([w], F.FleetState(), now=NOW).golden()
    g_explicit = _plain().reconcile([w], F.FleetState(), now=NOW, hold_keys=frozenset()).golden()
    assert g_default == g_explicit


# ==================================================================================================
# Policy / constructor validation (fail closed).
# ==================================================================================================
def test_rolling_policy_rejects_nonpositive_surge():
    for bad in (0, -1, True):
        with pytest.raises(F.FleetError):
            R.RollingPolicy(max_surge=bad)


def test_reconciler_rejects_bad_dependencies():
    with pytest.raises(F.FleetError):
        R.RollingFleetReconciler(object())                                  # not a FleetReconciler
    with pytest.raises(F.FleetError):
        R.RollingFleetReconciler(_plain(), policy=object())                 # not a RollingPolicy
    with pytest.raises(F.FleetError):
        R.RollingFleetReconciler(_plain(), health=object())                 # not a RolloutHealth


def test_default_health_is_elapsed_tick():
    rr = R.RollingFleetReconciler(_plain())
    assert isinstance(rr._health, R.ElapsedTickHealth)


# ==================================================================================================
# FATAL-2 — the rolling module imports NO cross-plane (sigil / apps / governor) module.
# ==================================================================================================
def test_fatal2_no_cross_plane_import():
    src = Path(R.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [n.name for n in node.names]
        elif isinstance(node, ast.ImportFrom):
            # a relative import (level>0) stays inside framework.v2; an absolute one names its root.
            if node.level == 0 and node.module:
                imported.append(node.module)
    forbidden = [m for m in imported if m.split(".")[0] in {"sigil", "apps"} or "governor" in m]
    assert forbidden == [], f"aegis_fleet_rolling made a cross-plane import (FATAL-2): {forbidden}"
    roots = {m.split(".")[0] for m in imported}
    assert roots <= {"__future__", "hashlib", "json", "os", "dataclasses", "typing"}, roots


# ==================================================================================================
# Gate-invariance — off the __init__/__main__ path; adds no OracleKind / WorkerKind.
# ==================================================================================================
def test_off_the_gate_path_not_imported_by_package_init():
    init_src = (Path(R.__file__).parent / "__init__.py").read_text(encoding="utf-8")
    assert "aegis_fleet_rolling" not in init_src


def test_importing_rolling_adds_no_oracle_and_no_worker_kind():
    import framework.v2.aegis.aegis_fleet_rolling  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15
    # AS-6e adds NO fleet worker kind — it only orders AS-6a's placements.
    assert {k.value for k in F.WorkerKind} == {
        "units", "broker", "prover", "receiver", "jobs", "suricata", "executor", "judge"}
