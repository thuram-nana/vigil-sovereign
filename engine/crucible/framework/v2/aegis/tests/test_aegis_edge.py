"""AS-6c — the AEGIS edge automation layer: a declarative EDGE reconciler over the AS-6a fleet.

Deterministic, OFFLINE tests. They prove the edge-automation acceptance cases built on AS-6a —

  * present => BOUND with NO operator step (the reconciler provisions the per-(org,host) edge secret and
    binds the distribution's origin at the HEALTHY gateway unit in one pass, no manual step);
  * a unit ROLLOUT (AS-6a bumps the backing unit's epoch) drives an edge cutover, NEW origin bound FIRST,
    OLD origin drained AFTER (never a gap with no proven origin);
  * absent => DRAINED then retired (drain-first);

— plus the fail-closed guard rails (never bind an unproven/unhealthy origin; never open the origin without
a provisioned edge secret; only SIGIL TT origins), the DEFAULT-OFF flag (inert + flag-off golden
byte-identical), determinism, FATAL-2 (no cross-plane import), and the AS-6a-fleet adapter.

No wall-clock, no RNG, no network: ``now`` is injected, every id is a content hash, and the AWS edge plane
is replaced by injected in-memory doubles.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from framework.v2.aegis import aegis_edge as E
from framework.v2.aegis import aegis_fleet as F

NOW = 1_000_000.0
_LOCKED = F.locked_image_digest()  # the real AS-28 committed digest


# --------------------------------------------------------------------------------------------------
# Test doubles (in-memory, deterministic). Each records its calls IN ORDER so the bind/drain ORDER is
# assertable (the safe-rollout-order property).
# --------------------------------------------------------------------------------------------------
class MemControlPlane:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []  # (verb, distribution_id, origin_id)

    def bind_origin(self, distribution_id: str, origin_id: str) -> bool:
        self.calls.append(("bind", distribution_id, origin_id))
        return True

    def drain_origin(self, distribution_id: str, origin_id: str) -> bool:
        self.calls.append(("drain", distribution_id, origin_id))
        return True

    def binds(self) -> list[str]:
        return [o for v, _d, o in self.calls if v == "bind"]

    def drains(self) -> list[str]:
        return [o for v, _d, o in self.calls if v == "drain"]


class FailBindControlPlane(MemControlPlane):
    def bind_origin(self, distribution_id: str, origin_id: str) -> bool:
        self.calls.append(("bind", distribution_id, origin_id))
        return False


class FailDrainControlPlane(MemControlPlane):
    def drain_origin(self, distribution_id: str, origin_id: str) -> bool:
        self.calls.append(("drain", distribution_id, origin_id))
        return False


class MemSecretStore:
    def __init__(self) -> None:
        self.provisioned: list[tuple[str, str, int]] = []
        self.destroyed: list[tuple[str, str, int]] = []

    def provision(self, org: str, host: str, epoch: int) -> bool:
        self.provisioned.append((org, host, epoch))
        return True

    def destroy(self, org: str, host: str, epoch: int) -> bool:
        self.destroyed.append((org, host, epoch))
        return True


class FailSecretStore(MemSecretStore):
    def provision(self, org: str, host: str, epoch: int) -> bool:
        self.provisioned.append((org, host, epoch))
        return False


@pytest.fixture
def edge_on(monkeypatch):
    monkeypatch.setenv(E.EDGE_ENV, "1")


# --------------------------------------------------------------------------------------------------
# Helpers.
# --------------------------------------------------------------------------------------------------
def _unit(tenant="tt-a", host=None, *, epoch=1, health=F.WorkerHealth.HEALTHY, digest=_LOCKED,
          kind=F.WorkerKind.UNITS, replica=0) -> F.RoutedWorker:
    host = host or f"app.{tenant}.example"
    return F.RoutedWorker(key=f"{kind.value}|{tenant}|{host}|{replica}", kind=kind, tenant=tenant,
                          host=host, replica_index=replica, mode="observe", health=health, epoch=epoch,
                          image_digest=digest, credential_status="delivered", routed_at=NOW)


def _fleet(*units) -> F.FleetState:
    return F.FleetState.from_workers(units)


def _edge(tenant="tt-a", host=None, *, dist="E-tt-a", state="present", secret_epoch=1) -> E.DesiredEdge:
    return E.DesiredEdge(org=tenant, host=host or f"app.{tenant}.example", distribution_id=dist,
                         desired_state=state, secret_epoch=secret_epoch)


def _reconciler(cp=None, store=None) -> E.EdgeReconciler:
    return E.EdgeReconciler(control_plane=cp or MemControlPlane(), secret_store=store)


# ==================================================================================================
# Acceptance 1 — present => BOUND with NO operator step.
# ==================================================================================================
def test_acceptance_present_binds_with_no_operator_step(edge_on):
    cp, store = MemControlPlane(), MemSecretStore()
    r = _reconciler(cp, store)
    d = _edge()
    res = r.reconcile([d], _fleet(_unit()), E.EdgeState(), now=NOW)
    assert not res.disabled
    assert res.bound_keys() == (d.key,)
    bound = res.state.get(d.key)
    assert bound is not None and bound.health == E.EdgeHealth.BOUND and bound.secret_status == "provisioned"
    # The edge secret was provisioned BEFORE the origin was bound; exactly one of each; no refusal.
    assert [a.verb for a in res.actions] == ["provision_secret", "bind"]
    assert store.provisioned == [("tt-a", "app.tt-a.example", 1)]
    assert len(cp.binds()) == 1 and cp.drains() == []
    assert res.refusals == ()


def test_reconcile_is_idempotent_second_pass_is_a_noop(edge_on):
    cp, store = MemControlPlane(), MemSecretStore()
    r = _reconciler(cp, store)
    d, fleet = _edge(), _fleet(_unit())
    first = r.reconcile([d], fleet, E.EdgeState(), now=NOW)
    second = r.reconcile([d], fleet, first.state, now=NOW + 10)
    assert second.bound_keys() == (d.key,)
    assert second.actions == ()                  # already converged — no action
    assert store.provisioned == [("tt-a", "app.tt-a.example", 1)]   # NOT re-provisioned
    assert len(cp.binds()) == 1                  # NOT re-bound


# ==================================================================================================
# Acceptance 2 — a unit ROLLOUT drives an edge cutover: bind NEW first, drain OLD after.
# ==================================================================================================
def test_rollout_binds_new_then_drains_old(edge_on):
    cp, store = MemControlPlane(), MemSecretStore()
    r = _reconciler(cp, store)
    d = _edge()
    first = r.reconcile([d], _fleet(_unit(epoch=1)), E.EdgeState(), now=NOW)
    old_origin = first.state.get(d.key).origin_id
    # AS-6a rolls the backing unit to epoch 2 (new origin identity).
    res = r.reconcile([d], _fleet(_unit(epoch=2)), first.state, now=NOW + 100)
    new_origin = res.state.get(d.key).origin_id
    assert new_origin != old_origin
    assert [a.verb for a in res.actions] == ["rollout"]
    # The NEW origin was bound BEFORE the OLD one was drained (safe cutover order).
    assert cp.calls[-2] == ("bind", d.distribution_id, new_origin)
    assert cp.calls[-1] == ("drain", d.distribution_id, old_origin)
    # A unit rollout at the SAME edge-secret epoch does NOT re-provision the secret.
    assert store.provisioned == [("tt-a", "app.tt-a.example", 1)]


def test_first_bind_failure_is_binding_and_retries(edge_on):
    """A FIRST bind that the control plane refuses leaves the edge BINDING (never BOUND) with an
    origin_bind_failed refusal; once the control plane recovers the next pass binds it (fail-closed, then
    self-heal). The edge secret provisioned on the failed pass is NOT re-provisioned on the retry."""
    store = MemSecretStore()
    fail_cp = FailBindControlPlane()
    r_fail = E.EdgeReconciler(control_plane=fail_cp, secret_store=store)
    d, fleet = _edge(), _fleet(_unit())
    first = r_fail.reconcile([d], fleet, E.EdgeState(), now=NOW)
    assert [rf.code for rf in first.refusals] == ["origin_bind_failed"]
    assert first.state.get(d.key).health == E.EdgeHealth.BINDING
    assert first.bound_keys() == ()
    # Recover: a healthy control plane, SAME secret store (the secret is already provisioned).
    ok_cp = MemControlPlane()
    r_ok = E.EdgeReconciler(control_plane=ok_cp, secret_store=store)
    second = r_ok.reconcile([d], fleet, first.state, now=NOW + 10)
    assert second.refusals == () and second.bound_keys() == (d.key,)
    assert store.provisioned == [("tt-a", "app.tt-a.example", 1)]      # NOT re-provisioned on the retry
    assert len(ok_cp.binds()) == 1


def test_rollout_bind_failure_keeps_the_proven_old_origin(edge_on):
    store = MemSecretStore()
    ok_cp = MemControlPlane()
    r1 = E.EdgeReconciler(control_plane=ok_cp, secret_store=store)
    d = _edge()
    first = r1.reconcile([d], _fleet(_unit(epoch=1)), E.EdgeState(), now=NOW)
    old_origin = first.state.get(d.key).origin_id
    # New reconciler whose control plane REFUSES the new bind during the rollout.
    fail_cp = FailBindControlPlane()
    r2 = E.EdgeReconciler(control_plane=fail_cp, secret_store=store)
    res = r2.reconcile([d], _fleet(_unit(epoch=2)), first.state, now=NOW + 100)
    assert [(rf.edge_key, rf.code) for rf in res.refusals] == [(d.key, "origin_bind_failed")]
    # The edge is UNTOUCHED — still BOUND to the proven OLD origin; the OLD origin was NEVER drained.
    kept = res.state.get(d.key)
    assert kept.health == E.EdgeHealth.BOUND and kept.origin_id == old_origin
    assert fail_cp.drains() == []


# ==================================================================================================
# Guard rail — never bind an unproven / unhealthy origin.
# ==================================================================================================
def test_absent_backing_unit_refuses(edge_on):
    cp, store = MemControlPlane(), MemSecretStore()
    r = _reconciler(cp, store)
    d = _edge()
    res = r.reconcile([d], F.FleetState(), E.EdgeState(), now=NOW)       # empty fleet — no backing unit
    assert [(rf.edge_key, rf.code) for rf in res.refusals] == [(d.key, "backing_unit_not_healthy")]
    assert res.bound_keys() == () and cp.binds() == [] and store.provisioned == []


@pytest.mark.parametrize("health", [F.WorkerHealth.STARTING, F.WorkerHealth.DRAINING, F.WorkerHealth.RETIRED])
def test_non_healthy_backing_unit_refuses(edge_on, health):
    cp = MemControlPlane()
    r = _reconciler(cp, MemSecretStore())
    d = _edge()
    res = r.reconcile([d], _fleet(_unit(health=health)), E.EdgeState(), now=NOW)
    assert [rf.code for rf in res.refusals] == ["backing_unit_not_healthy"]
    assert cp.binds() == []


def test_starting_unit_during_rollout_keeps_old_origin(edge_on):
    """While AS-6a rolls the unit (it is STARTING, not yet HEALTHY), the edge keeps its proven origin —
    it does NOT cut traffic over to a unit the fleet has not proven healthy."""
    cp, store = MemControlPlane(), MemSecretStore()
    r = _reconciler(cp, store)
    d = _edge()
    first = r.reconcile([d], _fleet(_unit(epoch=1)), E.EdgeState(), now=NOW)
    old_origin = first.state.get(d.key).origin_id
    # The replacement unit is STARTING (mid-rollout) — refuse the cutover.
    res = r.reconcile([d], _fleet(_unit(epoch=2, health=F.WorkerHealth.STARTING)), first.state, now=NOW + 50)
    assert [rf.code for rf in res.refusals] == ["backing_unit_not_healthy"]
    assert res.state.get(d.key).origin_id == old_origin         # still serving the proven origin


# ==================================================================================================
# Guard rail — never open the origin without a provisioned edge secret.
# ==================================================================================================
def test_edge_secret_refused_blocks_the_bind(edge_on):
    cp = MemControlPlane()
    r = _reconciler(cp, FailSecretStore())
    d = _edge()
    res = r.reconcile([d], _fleet(_unit()), E.EdgeState(), now=NOW)
    assert [(rf.edge_key, rf.code) for rf in res.refusals] == [(d.key, "edge_secret_refused")]
    # The origin was NEVER bound — a secret that cannot be provisioned fails closed BEFORE the bind.
    assert cp.binds() == [] and res.bound_keys() == ()


def test_edge_secret_store_raise_is_a_refusal_not_a_crash(edge_on):
    class RaisingStore(MemSecretStore):
        def provision(self, org, host, epoch):
            raise RuntimeError("secrets manager unavailable")

    cp = MemControlPlane()
    r = _reconciler(cp, RaisingStore())
    res = r.reconcile([_edge()], _fleet(_unit()), E.EdgeState(), now=NOW)
    assert [rf.code for rf in res.refusals] == ["edge_secret_refused"]
    assert cp.binds() == []


def test_no_secret_store_refuses_the_bind_fail_closed(edge_on):
    """With no edge-secret store wired (owner-gated), the origin is NEVER opened: the bind is refused
    (edge_secret_unavailable) and the reconciler binds nothing, fail-closed — never route traffic to an
    origin with no provisioned bypass secret."""
    cp = MemControlPlane()
    r = _reconciler(cp, store=None)
    d = _edge()
    res = r.reconcile([d], _fleet(_unit()), E.EdgeState(), now=NOW)
    assert [(rf.edge_key, rf.code) for rf in res.refusals] == [(d.key, "edge_secret_unavailable")]
    assert cp.binds() == [] and res.bound_keys() == ()


def test_refused_secret_is_retried_next_pass(edge_on):
    """A refused edge-secret provisioning is NOT terminal: once the store recovers, the next pass provisions
    and binds (fail-closed, then self-heal)."""
    class Flaky(MemSecretStore):
        def __init__(self):
            super().__init__()
            self.ok = False

        def provision(self, org, host, epoch):
            super().provision(org, host, epoch)
            return self.ok

    store = Flaky()
    cp = MemControlPlane()
    r = E.EdgeReconciler(control_plane=cp, secret_store=store)
    d, fleet = _edge(), _fleet(_unit())
    first = r.reconcile([d], fleet, E.EdgeState(), now=NOW)
    assert [rf.code for rf in first.refusals] == ["edge_secret_refused"]
    store.ok = True
    second = r.reconcile([d], fleet, first.state, now=NOW + 10)
    assert second.refusals == () and second.bound_keys() == (d.key,)


# ==================================================================================================
# Edge-secret rotation (epoch bump) — origin is NOT re-bound (secret-only change).
# ==================================================================================================
def test_secret_rotation_on_epoch_bump(edge_on):
    cp, store = MemControlPlane(), MemSecretStore()
    r = _reconciler(cp, store)
    fleet = _fleet(_unit())
    first = r.reconcile([_edge(secret_epoch=1)], fleet, E.EdgeState(), now=NOW)
    assert len(cp.binds()) == 1
    # Bump the edge-secret epoch; the backing unit is unchanged (origin identical).
    res = r.reconcile([_edge(secret_epoch=2)], fleet, first.state, now=NOW + 100)
    verbs = [a.verb for a in res.actions]
    assert "rotate_secret" in verbs and "destroy_secret" in verbs
    assert store.provisioned == [("tt-a", "app.tt-a.example", 1), ("tt-a", "app.tt-a.example", 2)]
    assert store.destroyed == [("tt-a", "app.tt-a.example", 1)]       # the overlap epoch is retired
    assert len(cp.binds()) == 1                                       # origin NOT re-bound (secret-only)
    assert res.state.get(_edge().key).secret_epoch == 2
    # Converged after the rotation.
    third = r.reconcile([_edge(secret_epoch=2)], fleet, res.state, now=NOW + 200)
    assert third.actions == ()


# ==================================================================================================
# Guard rail — only SIGIL TT origins before AS-2g.
# ==================================================================================================
def test_only_sigil_tt_origins(edge_on):
    cp = MemControlPlane()
    r = _reconciler(cp, MemSecretStore())
    real = _edge(tenant="acme-corp", dist="E-acme")
    # A HEALTHY unit exists for the real tenant, but the edge is refused on the origin guard rail FIRST.
    res = r.reconcile([real], _fleet(_unit(tenant="acme-corp")), E.EdgeState(), now=NOW)
    assert [(rf.edge_key, rf.code) for rf in res.refusals] == [(real.key, "origin_not_sigil_tt")]
    assert cp.binds() == []


def test_both_sigil_tt_tenants_admitted(edge_on):
    r = _reconciler(MemControlPlane(), MemSecretStore())
    da, db = _edge("tt-a", dist="E-a"), _edge("tt-b", dist="E-b")
    res = r.reconcile([da, db], _fleet(_unit("tt-a"), _unit("tt-b")), E.EdgeState(), now=NOW)
    assert set(res.bound_keys()) == {da.key, db.key} and res.refusals == ()


# ==================================================================================================
# Acceptance 3 — absent => DRAINED then retired (drain-first).
# ==================================================================================================
def test_absent_retires_drain_first(edge_on):
    cp, store = MemControlPlane(), MemSecretStore()
    r = _reconciler(cp, store)
    d, fleet = _edge(), _fleet(_unit())
    bound = r.reconcile([d], fleet, E.EdgeState(), now=NOW)
    gone = E.DesiredEdge(org=d.org, host=d.host, distribution_id=d.distribution_id, desired_state="absent")
    res = r.reconcile([gone], fleet, bound.state, now=NOW + 100)
    retired = res.state.get(d.key)
    assert retired is not None and retired.health == E.EdgeHealth.RETIRED
    assert res.retired_keys() == (d.key,)
    verbs = [(a.verb, a.edge_key) for a in res.actions]
    # drain happened BEFORE retire (drain-first), and the edge secret was scheduled for destruction.
    assert verbs.index(("drain", d.key)) < verbs.index(("retire", d.key))
    assert store.destroyed == [("tt-a", "app.tt-a.example", 1)]


def test_absent_from_desired_is_retired_declaratively(edge_on):
    cp = MemControlPlane()
    r = _reconciler(cp, MemSecretStore())
    d, fleet = _edge(), _fleet(_unit())
    bound = r.reconcile([d], fleet, E.EdgeState(), now=NOW)
    # The edge is simply dropped from the desired set — declarative convergence retires it.
    res = r.reconcile([], fleet, bound.state, now=NOW + 100)
    assert res.retired_keys() == (d.key,)
    assert "drain" in [a.verb for a in res.actions]


def test_retire_refused_when_drain_cannot_be_confirmed(edge_on):
    store = MemSecretStore()
    ok_cp = MemControlPlane()
    r1 = E.EdgeReconciler(control_plane=ok_cp, secret_store=store)
    d, fleet = _edge(), _fleet(_unit())
    bound = r1.reconcile([d], fleet, E.EdgeState(), now=NOW)
    # A control plane whose drain FAILS: the teardown is refused, the edge is left DRAINING (never released).
    fail_cp = FailDrainControlPlane()
    r2 = E.EdgeReconciler(control_plane=fail_cp, secret_store=store)
    res = r2.reconcile([], fleet, bound.state, now=NOW + 100)
    assert [(rf.edge_key, rf.code) for rf in res.refusals] == [(d.key, "drain_failed")]
    left = res.state.get(d.key)
    assert left.health == E.EdgeHealth.DRAINING and d.key not in res.retired_keys()
    assert store.destroyed == []        # the secret is NOT destroyed while the edge may still serve


def test_absent_never_bound_is_a_tombstone(edge_on):
    cp = MemControlPlane()
    r = _reconciler(cp, MemSecretStore())
    gone = _edge(state="absent")
    res = r.reconcile([gone], _fleet(_unit()), E.EdgeState(), now=NOW)
    assert res.state.get(gone.key).health == E.EdgeHealth.RETIRED
    assert cp.calls == [] and res.actions == ()     # nothing placed => nothing to drain


# ==================================================================================================
# DEFAULT-OFF flag — inert + flag-off golden byte-identical.
# ==================================================================================================
def test_default_off_flag_is_inert(monkeypatch):
    monkeypatch.delenv(E.EDGE_ENV, raising=False)
    cp, store = MemControlPlane(), MemSecretStore()
    r = _reconciler(cp, store)
    res = r.reconcile([_edge()], _fleet(_unit()), E.EdgeState(), now=NOW)
    assert res.disabled is True and res.state == E.EdgeState()
    assert res.actions == () and res.refusals == ()
    assert cp.calls == [] and store.provisioned == []       # NO side effects when off


def test_flag_off_golden_is_byte_identical_regardless_of_desired(monkeypatch):
    monkeypatch.delenv(E.EDGE_ENV, raising=False)
    r = _reconciler(MemControlPlane(), MemSecretStore())
    g_empty = r.reconcile([], F.FleetState(), E.EdgeState(), now=NOW).golden()
    g_full = r.reconcile([_edge(), _edge("tt-b", dist="E-b")], _fleet(_unit(), _unit("tt-b")),
                         E.EdgeState(), now=NOW + 5).golden()
    assert g_empty == g_full == {"disabled": True, "bound": [], "retired": [],
                                 "actions": [], "refusals": []}


@pytest.mark.parametrize("token,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True), (" On ", True),
    ("0", False), ("false", False), ("", False), ("nope", False),
])
def test_flag_token_parsing(monkeypatch, token, expected):
    monkeypatch.setenv(E.EDGE_ENV, token)
    assert E.edge_enabled() is expected


# ==================================================================================================
# Determinism — byte-identical result for the same inputs; stable content ids.
# ==================================================================================================
def test_determinism_golden_is_stable(edge_on):
    d, fleet = _edge(), _fleet(_unit())
    a = _reconciler(MemControlPlane(), MemSecretStore()).reconcile([d], fleet, E.EdgeState(), now=NOW)
    b = _reconciler(MemControlPlane(), MemSecretStore()).reconcile([d], fleet, E.EdgeState(), now=NOW)
    assert a.golden() == b.golden()
    assert [x.action_id for x in a.actions] == [x.action_id for x in b.actions]
    assert a.state.get(d.key).origin_id == b.state.get(d.key).origin_id


def test_origin_id_tracks_unit_identity(edge_on):
    # Same unit identity => same origin id; a different epoch/digest => a different origin id.
    assert E._origin_id(_unit(epoch=1)) == E._origin_id(_unit(epoch=1))
    assert E._origin_id(_unit(epoch=1)) != E._origin_id(_unit(epoch=2))


# ==================================================================================================
# FATAL-2 — the edge module imports NO cross-plane (sigil / governor) module.
# ==================================================================================================
def test_fatal2_no_cross_plane_import():
    src = Path(E.__file__).read_text(encoding="utf-8")
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
    assert forbidden == [], f"aegis_edge made a cross-plane import (FATAL-2): {forbidden}"
    # Only the allowed roots appear among absolute imports (stdlib + vigil_core; the plane-neutral set).
    roots = {m.split(".")[0] for m in imported}
    assert roots <= {"__future__", "hashlib", "json", "os", "dataclasses", "enum", "typing", "vigil_core"}, roots


def test_off_the_gate_path_not_imported_by_package_init():
    """The reconciler is off the gate path: aegis/__init__ does not import it (so `make gate` byte-identity
    is untouched), mirroring aegis_fleet / tt_rig."""
    init_src = (Path(E.__file__).parent / "__init__.py").read_text(encoding="utf-8")
    assert "aegis_edge" not in init_src


# ==================================================================================================
# The AS-6a-fleet adapter — the edge-automation wiring.
# ==================================================================================================
def test_desired_edges_for_fleet_tracks_healthy_units(edge_on):
    fleet = _fleet(
        _unit("tt-a"),                                          # healthy units -> an edge
        _unit("tt-b"),                                          # healthy units -> an edge
        _unit("tt-a", host="other.tt-a.example"),              # healthy but NO mapped distribution -> skipped
        _unit("tt-a", kind=F.WorkerKind.BROKER, host="broker.tt-a"),   # not a gateway unit -> skipped
        _unit("tt-b", epoch=2, health=F.WorkerHealth.STARTING, host="rolling.tt-b"),  # not healthy -> skipped
    )
    dists = {"app.tt-a.example": "E-a", "app.tt-b.example": "E-b"}
    edges = E.desired_edges_for_fleet(fleet, distribution_ids=dists, secret_epoch_by_host={"app.tt-b.example": 3})
    assert [(e.org, e.host, e.distribution_id, e.secret_epoch) for e in edges] == [
        ("tt-a", "app.tt-a.example", "E-a", 1),
        ("tt-b", "app.tt-b.example", "E-b", 3),
    ]
    # The derived edges reconcile cleanly against the same fleet (automation end to end).
    r = _reconciler(MemControlPlane(), MemSecretStore())
    res = r.reconcile(edges, fleet, E.EdgeState(), now=NOW)
    assert set(res.bound_keys()) == {"edge|tt-a|app.tt-a.example", "edge|tt-b|app.tt-b.example"}


def test_desired_edges_for_fleet_skips_retired_unit():
    # A retired units worker is not active, so it yields no desired edge (the edge is then reconciled away).
    retired = _unit("tt-a", health=F.WorkerHealth.RETIRED)
    edges = E.desired_edges_for_fleet(_fleet(retired), distribution_ids={"app.tt-a.example": "E-a"})
    assert edges == []


# ==================================================================================================
# Input validation.
# ==================================================================================================
def test_desired_edge_validates_inputs():
    with pytest.raises(E.EdgeError):
        E.DesiredEdge(org="", host="h", distribution_id="d")
    with pytest.raises(E.EdgeError):
        E.DesiredEdge(org="o", host="", distribution_id="d")
    with pytest.raises(E.EdgeError):
        E.DesiredEdge(org="o", host="h", distribution_id="")
    with pytest.raises(E.EdgeError):
        E.DesiredEdge(org="o", host="h", distribution_id="d", desired_state="maybe")
    with pytest.raises(E.EdgeError):
        E.DesiredEdge(org="o", host="h", distribution_id="d", secret_epoch=0)
    with pytest.raises(E.EdgeError):
        E.DesiredEdge(org="o", host="h", distribution_id="d", replica_index=-1)


def test_reconciler_requires_a_control_plane():
    with pytest.raises(E.EdgeReconcileError):
        E.EdgeReconciler(control_plane=object())            # not an EdgeControlPlane
    with pytest.raises(E.EdgeReconcileError):
        E.EdgeReconciler(control_plane=MemControlPlane(), secret_store=object())
