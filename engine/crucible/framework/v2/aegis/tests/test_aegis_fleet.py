"""AS-6a — the AEGIS fleet placement engine + declarative reconciler.

Deterministic, OFFLINE tests. They prove the three acceptance cases the plan row names —

  * Observe => routed with NO operator step (the reconciler converges a desired observe worker to ROUTED
    in one pass, no manual placement);
  * Off => retired (with the mandatory pre-retirement SNAPSHOT taken FIRST);
  * a tampered image REFUSES (an attested digest != the AS-28 lock fails closed);

— plus the two guard rails (never render enforcement before AS-29; only SIGIL TT origins before AS-2g),
the DEFAULT-OFF flag (inert + flag-off golden byte-identical), determinism, the worker-kind registry, and
the AS-2h sealing-delivery seam made real (SSM-only ``SsmSecretDelivery``).

No wall-clock, no RNG, no network: ``now`` is injected and every id is a content hash.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from framework.v2.aegis import aegis_fleet as F
from vigil_core.aegis_sealing import (
    SEALING_DELIVER_ENV, SecretKind, SecretRing, build_bundle, deliver_bundle, delivery_enabled,
)
from vigil_core.authority_v2 import (
    AuthoritySubject, EnforceRelease, MonitoringAuthorityV2, MonitoringCapability, MonitoringLease,
    SubjectKind,
)

NOW = 1_000_000.0
_KEK = bytes(range(32))
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


class FailSnapshotSink:
    def store(self, snapshot: F.Snapshot) -> bool:
        return False


class MemSsmChannel:
    def __init__(self) -> None:
        self.params: dict[str, bytes] = {}

    def put_parameter(self, name: str, sealed_blob: bytes) -> bool:
        self.params[name] = sealed_blob
        return True


class FailSsmChannel:
    def put_parameter(self, name: str, sealed_blob: bytes) -> bool:
        return False


@pytest.fixture
def fleet_on(monkeypatch):
    monkeypatch.setenv(F.FLEET_ENV, "1")


def _observe_worker(tenant="tt-a", *, digest=_LOCKED, kind=F.WorkerKind.UNITS, epoch=1,
                    caps=(MonitoringCapability.OBSERVE,), bundles=()):
    return F.DesiredWorker(kind=kind, tenant=tenant, host=f"app.{tenant}.example",
                           desired_mode="observe", capabilities=caps, image_digest=digest,
                           epoch=epoch, credential_bundles=bundles)


def _bundle(org="tt-a", scope="app.tt-a.example"):
    ring = SecretRing(SecretKind.REPORT, org, scope)
    ring.activate(1, b"report-secret-0001")
    return build_bundle(ring, _KEK)


def _reconciler(sink=None, channel=None):
    return F.FleetReconciler(snapshot_sink=sink or MemSnapshotSink(), ssm_channel=channel)


# ==================================================================================================
# Acceptance 1 — Observe => routed with NO operator step.
# ==================================================================================================
def test_acceptance_observe_routes_with_no_operator_step(fleet_on):
    r = _reconciler()
    w = _observe_worker()
    res = r.reconcile([w], F.FleetState(), now=NOW)
    assert not res.disabled
    assert res.routed_keys() == (w.key,)
    routed = res.state.get(w.key)
    assert routed is not None and routed.health == F.WorkerHealth.HEALTHY and routed.mode == "observe"
    # Exactly one automatic "route" action; no refusal, no manual placement step.
    assert [a.verb for a in res.actions] == ["route"]
    assert res.refusals == ()


def test_reconcile_is_idempotent_second_pass_is_a_noop(fleet_on):
    r = _reconciler()
    w = _observe_worker()
    first = r.reconcile([w], F.FleetState(), now=NOW)
    second = r.reconcile([w], first.state, now=NOW + 10)
    assert second.routed_keys() == (w.key,)
    assert second.actions == ()  # already converged — the reconciler takes no action


# ==================================================================================================
# Acceptance 2 — Off => retired, SNAPSHOT FIRST.
# ==================================================================================================
def test_acceptance_off_retires_snapshot_first(fleet_on):
    sink = MemSnapshotSink()
    r = _reconciler(sink=sink)
    w = _observe_worker()
    placed = r.reconcile([w], F.FleetState(), now=NOW)
    off = F.DesiredWorker(kind=w.kind, tenant=w.tenant, host=w.host, desired_mode="off",
                          image_digest=_LOCKED, epoch=w.epoch)
    res = r.reconcile([off], placed.state, now=NOW + 100)
    retired = res.state.get(w.key)
    assert retired is not None and retired.health == F.WorkerHealth.RETIRED
    assert res.retired_keys() == (w.key,)
    # A snapshot was taken AND durably stored...
    assert len(res.snapshots) == 1 and sink.stored == list(res.snapshots)
    assert retired.snapshot_id == res.snapshots[0].snapshot_id
    # ...and the snapshot action happened BEFORE the retire action (snapshot FIRST).
    verbs = [(a.verb, a.worker_key) for a in res.actions]
    assert verbs.index(("snapshot", w.key)) < verbs.index(("retire", w.key))


def test_absent_from_desired_is_retired_declaratively(fleet_on):
    sink = MemSnapshotSink()
    r = _reconciler(sink=sink)
    w = _observe_worker()
    placed = r.reconcile([w], F.FleetState(), now=NOW)
    # The worker vanishes from the desired set entirely => declarative convergence retires it (snapshot first).
    res = r.reconcile([], placed.state, now=NOW + 100)
    assert res.retired_keys() == (w.key,)
    assert len(res.snapshots) == 1


def test_retire_refused_when_snapshot_cannot_be_stored(fleet_on):
    placed = _reconciler().reconcile([_observe_worker()], F.FleetState(), now=NOW)
    r = F.FleetReconciler(snapshot_sink=FailSnapshotSink())
    w = _observe_worker()
    off = F.DesiredWorker(kind=w.kind, tenant=w.tenant, host=w.host, desired_mode="off",
                          image_digest=_LOCKED, epoch=w.epoch)
    res = r.reconcile([off], placed.state, now=NOW + 100)
    # Snapshot FIRST is inviolable: a failed snapshot REFUSES the retirement; the worker is NOT retired.
    assert res.snapshots == ()
    assert [rf.code for rf in res.refusals] == ["snapshot_failed"]
    assert res.state.get(w.key).health == F.WorkerHealth.DRAINING


# ==================================================================================================
# Acceptance 3 — a tampered image REFUSES.
# ==================================================================================================
def test_acceptance_tampered_image_refuses(fleet_on):
    r = _reconciler()
    bad = _observe_worker(digest="sha256:" + "0" * 64)
    res = r.reconcile([bad], F.FleetState(), now=NOW)
    assert res.routed_keys() == ()
    assert [rf.code for rf in res.refusals] == ["tampered_image"]


def test_verify_image_digest_matches_and_rejects():
    assert F.verify_image_digest(_LOCKED) == _LOCKED
    for bad in ("sha256:" + "0" * 64, "", "not-a-digest", _LOCKED.upper()):
        with pytest.raises(F.TamperedImageError):
            F.verify_image_digest(bad)


def test_locked_digest_cross_checks_dockerfile(tmp_path):
    # An internally inconsistent lock (closure json digest != Dockerfile FROM pin) fails closed.
    good = _LOCKED
    other = "sha256:" + "1" * 64
    (tmp_path / "saas-closure.json").write_text(
        '{"dockerfile": {"base_image_digest": "%s"}}' % good, encoding="utf-8")
    (tmp_path / "Dockerfile.saas").write_text("FROM python:3.13-slim@%s\n" % other, encoding="utf-8")
    with pytest.raises(F.TamperedImageError):
        F.locked_image_digest(closure_lock=tmp_path / "saas-closure.json",
                              dockerfile=tmp_path / "Dockerfile.saas")


# ==================================================================================================
# Guard rail — NEVER render enforcement before AS-29.
# ==================================================================================================
def test_guardrail_no_enforcement_rendered_even_with_block_capability(fleet_on):
    r = _reconciler()
    w = _observe_worker(caps=(MonitoringCapability.OBSERVE, MonitoringCapability.BLOCK))
    res = r.reconcile([w], F.FleetState(), now=NOW)
    routed = res.state.get(w.key)
    assert routed is not None and routed.mode == "observe"  # routed, but observe-only
    # The render carries NO enforce env (the fleet has no release source — AS-29 unbuilt).
    rendered = F.render_worker(w, release=None, now=NOW)
    assert rendered.mode == "observe"
    assert F._ENFORCE_ENV not in rendered.env_dict() and F._RESPOND_ENV not in rendered.env_dict()


def test_render_release_gate_is_real_not_hardcoded():
    """The observe-only outcome above is the ABSENCE of a release, not a constant: given a release that
    covers BLOCK at ``now``, the SAME render flips to enforce. This is the AS-29 seam, proven live."""
    w = _observe_worker(caps=(MonitoringCapability.OBSERVE, MonitoringCapability.BLOCK))
    subject = AuthoritySubject(kind=SubjectKind.HOST, org_id="tt-a", host="app.tt-a.example")
    release = EnforceRelease(
        subject=subject, released_capabilities=[MonitoringCapability.BLOCK], epoch=1,
        not_before=datetime.fromtimestamp(0, tz=timezone.utc),
        not_after=datetime.fromtimestamp(2_000_000, tz=timezone.utc))
    rendered = F.render_worker(w, release=release, now=NOW)
    assert rendered.mode == "enforce"
    assert rendered.env_dict()[F._ENFORCE_ENV] == "1"
    # A release whose window does NOT cover now stays observe (the gate honours the window).
    stale = EnforceRelease(
        subject=subject, released_capabilities=[MonitoringCapability.BLOCK], epoch=1,
        not_before=datetime.fromtimestamp(0, tz=timezone.utc),
        not_after=datetime.fromtimestamp(10, tz=timezone.utc))
    assert F.render_worker(w, release=stale, now=NOW).mode == "observe"


def test_reconciler_has_no_release_source(fleet_on):
    # Structural guard: the fleet wires NO release source in this slice.
    assert _reconciler()._release_source is None


# ==================================================================================================
# Guard rail — only SIGIL TT origins before AS-2g.
# ==================================================================================================
def test_guardrail_only_sigil_tt_origins(fleet_on):
    r = _reconciler()
    tt = _observe_worker(tenant="tt-a")
    real = _observe_worker(tenant="acme")
    res = r.reconcile([tt, real], F.FleetState(), now=NOW)
    assert res.routed_keys() == (tt.key,)  # only the SIGIL TT worker routed
    assert [(rf.worker_key, rf.code) for rf in res.refusals] == [(real.key, "origin_not_sigil_tt")]


def test_both_sigil_tt_tenants_admitted(fleet_on):
    r = _reconciler()
    a, b = _observe_worker("tt-a"), _observe_worker("tt-b")
    res = r.reconcile([a, b], F.FleetState(), now=NOW)
    assert set(res.routed_keys()) == {a.key, b.key}


# ==================================================================================================
# DEFAULT-OFF flag — inert + flag-off golden byte-identical.
# ==================================================================================================
def test_default_off_flag_is_inert(monkeypatch):
    monkeypatch.delenv(F.FLEET_ENV, raising=False)
    assert F.fleet_enabled() is False
    r = _reconciler()
    res = r.reconcile([_observe_worker()], F.FleetState(), now=NOW)
    assert res.disabled is True
    assert res.actions == () and res.refusals == () and res.snapshots == ()
    assert res.state == F.FleetState()  # nothing placed


def test_flag_off_golden_is_byte_identical_regardless_of_desired(monkeypatch):
    monkeypatch.delenv(F.FLEET_ENV, raising=False)
    r = _reconciler()
    g1 = r.reconcile([_observe_worker("tt-a")], F.FleetState(), now=NOW).golden()
    g2 = r.reconcile([_observe_worker("tt-b", epoch=7),
                      _observe_worker("acme")], F.FleetState(), now=NOW + 999).golden()
    assert g1 == g2 == {"disabled": True, "routed": [], "retired": [], "actions": [],
                        "refusals": [], "snapshots": []}


@pytest.mark.parametrize("token,expected", [("1", True), ("true", True), ("YES", True), ("on", True),
                                            ("0", False), ("", False), ("nope", False)])
def test_flag_token_parsing(monkeypatch, token, expected):
    monkeypatch.setenv(F.FLEET_ENV, token)
    assert F.fleet_enabled() is expected


# ==================================================================================================
# Determinism — same (desired, state, now) => byte-identical result.
# ==================================================================================================
def test_determinism_route(fleet_on):
    w = _observe_worker()
    g1 = _reconciler().reconcile([w], F.FleetState(), now=NOW).golden()
    g2 = _reconciler().reconcile([w], F.FleetState(), now=NOW).golden()
    assert g1 == g2
    assert g1["actions"] and g1["actions"][0][2]  # a non-empty content-hash action id


def test_determinism_retire_snapshot_ids(fleet_on):
    w = _observe_worker()
    placed = _reconciler().reconcile([w], F.FleetState(), now=NOW)
    off = F.DesiredWorker(kind=w.kind, tenant=w.tenant, host=w.host, desired_mode="off",
                          image_digest=_LOCKED, epoch=w.epoch)
    s1 = _reconciler().reconcile([off], placed.state, now=NOW + 100).snapshots[0].snapshot_id
    s2 = _reconciler().reconcile([off], placed.state, now=NOW + 100).snapshots[0].snapshot_id
    assert s1 == s2  # content-addressed, not RNG


# ==================================================================================================
# Worker-kind registry.
# ==================================================================================================
def test_worker_kind_registry_covers_all_eight_kinds():
    expected = {"units", "broker", "prover", "receiver", "jobs", "suricata", "executor", "judge"}
    assert {k.value for k in F.WorkerKind} == expected
    assert set(F.WORKER_KIND_REGISTRY) == set(F.WorkerKind)
    for kind, spec in F.WORKER_KIND_REGISTRY.items():
        assert spec.kind == kind
        assert spec.systemd_template and spec.credential_names and spec.health_probe
        assert F.worker_kind_spec(kind) is spec
    # The units kind mirrors the shipped aegis-saas-gateway@.service LoadCredential names.
    assert F.WORKER_KIND_REGISTRY[F.WorkerKind.UNITS].credential_names == ("report-secret", "gw-secret")


# ==================================================================================================
# Credentials — LoadCredential-style, SSM ONLY (the AS-2h SecretDelivery seam made real).
# ==================================================================================================
def test_ssm_secret_delivery_writes_via_ssm_only():
    channel = MemSsmChannel()
    receipt = F.SsmSecretDelivery(channel).deliver(_bundle())
    assert receipt.delivered is True and receipt.status == "delivered"
    assert channel.params  # the sealed secret landed in SSM
    name = next(iter(channel.params))
    assert name.startswith("/aegis-saas/tt-a/")


def test_ssm_secret_delivery_refuses_on_failed_write():
    receipt = F.SsmSecretDelivery(FailSsmChannel()).deliver(_bundle())
    assert receipt.delivered is False and receipt.status == "refused"


def test_as2h_deliver_bundle_is_real_with_ssm_seam(monkeypatch):
    bundle = _bundle()
    channel = MemSsmChannel()
    seam = F.SsmSecretDelivery(channel)
    # Flag OFF (default): deliver_bundle falls back to the DEFAULT-OFF DeferredDelivery.
    monkeypatch.delenv(SEALING_DELIVER_ENV, raising=False)
    assert delivery_enabled() is False
    assert deliver_bundle(bundle, seam).delivered is False
    # Flag ON + the real AS-6a seam injected: delivery is REAL.
    monkeypatch.setenv(SEALING_DELIVER_ENV, "1")
    r = deliver_bundle(bundle, seam)
    assert r.delivered is True and r.status == "delivered"
    assert channel.params


def test_reconcile_delivers_credentials_when_channel_wired(fleet_on):
    channel = MemSsmChannel()
    r = _reconciler(channel=channel)
    w = _observe_worker(bundles=(_bundle(),))
    res = r.reconcile([w], F.FleetState(), now=NOW)
    assert res.state.get(w.key).credential_status == "delivered"
    assert channel.params
    assert any(a.verb == "deliver_credentials" for a in res.actions)


def test_reconcile_credentials_deferred_without_channel(fleet_on):
    r = _reconciler()  # no SSM channel wired
    w = _observe_worker(bundles=(_bundle(),))
    res = r.reconcile([w], F.FleetState(), now=NOW)
    assert res.state.get(w.key).credential_status == "deferred"


# ==================================================================================================
# Rollout — a placement change on a live worker is a target-group swap with drain.
# ==================================================================================================
def test_rollout_on_epoch_bump(fleet_on):
    r = _reconciler()
    w1 = _observe_worker(epoch=1)
    placed = r.reconcile([w1], F.FleetState(), now=NOW)
    w2 = _observe_worker(epoch=2)
    res = r.reconcile([w2], placed.state, now=NOW + 50)
    assert any(a.verb == "rollout" for a in res.actions)
    assert res.state.get(w2.key).epoch == 2


# ==================================================================================================
# AS-2a contract wiring — derive a DesiredWorker from a MonitoringAuthorityV2 grant.
# ==================================================================================================
def _grant(*, caps, live=True):
    subject = AuthoritySubject(kind=SubjectKind.HOST, org_id="tt-a", host="app.tt-a.example")
    nb = datetime.fromtimestamp(0, tz=timezone.utc)
    na = datetime.fromtimestamp(2_000_000, tz=timezone.utc)
    if live:
        lnb = datetime.fromtimestamp(NOW - 1000, tz=timezone.utc)
        lna = datetime.fromtimestamp(NOW + 1000, tz=timezone.utc)
    else:
        lnb = datetime.fromtimestamp(10, tz=timezone.utc)
        lna = datetime.fromtimestamp(20, tz=timezone.utc)
    return MonitoringAuthorityV2(subject=subject, capabilities=caps, epoch=3, not_before=nb, not_after=na,
                                 lease=MonitoringLease(not_before=lnb, not_after=lna), instance_id="i-1")


def test_desired_from_grant_observe_when_lease_live(fleet_on):
    grant = _grant(caps=[MonitoringCapability.OBSERVE, MonitoringCapability.BLOCK])
    w = F.desired_from_grant(grant, kind=F.WorkerKind.UNITS, image_digest=_LOCKED, now=NOW)
    assert w.desired_mode == "observe" and w.tenant == "tt-a" and w.epoch == 3
    # Even with BLOCK in the grant, the routed worker stays observe-only (no release before AS-29).
    res = _reconciler().reconcile([w], F.FleetState(), now=NOW)
    assert res.state.get(w.key).mode == "observe"


def test_desired_from_grant_off_when_lease_lapsed():
    grant = _grant(caps=[MonitoringCapability.OBSERVE], live=False)
    w = F.desired_from_grant(grant, kind=F.WorkerKind.UNITS, image_digest=_LOCKED, now=NOW)
    assert w.desired_mode == "off"


# ==================================================================================================
# Input validation (fail closed).
# ==================================================================================================
def test_desired_worker_validates_inputs():
    for kwargs in ({"desired_mode": "enforce"}, {"tenant": ""}, {"epoch": 0}, {"replica_index": -1}):
        base = dict(kind=F.WorkerKind.UNITS, tenant="tt-a", host="app.tt-a.example")
        base.update(kwargs)
        with pytest.raises(F.FleetError):
            F.DesiredWorker(**base)
