"""
Tests for Wave 2.1 — the Universal Sensor framework.

A sensor is a gated tool + a normalizer: run_sensor gates it (kill-switch/entitlement/scope/
destructive/egress), then normalizes its output into Observations that project into the ONE
world-model as provenance-labelled facts (GROUNDING_INTEL) — never oracle-proof. The reference
DeclaredServiceSensor is the first producer of the HOST/SERVICE/HOSTS structure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolRegistry
from framework.v2.intel.ingest import IntelIngest
from framework.v2.sensors import DeclaredServiceSensor, default_registry, run_sensor
from framework.v2.sensors.base import service_observations
from framework.v2.intel.models import Credibility, IntelSourceKind, Reliability, SourceReliability
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind


# A signed charter that lists the test host in scope — the sensor's host is charter-scope-gated
# (invoke_tool derives the scope target from args['host']), so a minting run needs a real charter.
_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `10.0.0.5` | Declared host | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    td = tmp_path / "alpha"
    td.mkdir(parents=True, exist_ok=True)
    (td / "charter.md").write_text(_CHARTER.format(slug="alpha"), encoding="utf-8")


_ARGS = {"host": "10.0.0.5", "services": [
    {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.18.0"},
    {"port": 22, "protocol": "tcp", "state": "closed"},   # closed -> not minted
]}

_DECL = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)


def _run(world: WorldModel, *, seq: int = 1, args: dict | None = None):
    reg = default_registry()
    ingest = IntelIngest(world, engagement_slug="alpha")
    return run_sensor(reg, "declared_service", args or _ARGS, ToolContext(slug="alpha"),
                      ingest=ingest, seq=seq)


def test_default_registry_ships_the_declared_sensor() -> None:
    assert "declared_service" in default_registry()


def test_declared_sensor_mints_host_service_hosts_into_the_world() -> None:
    world = WorldModel()
    res = _run(world)
    assert res.ok and res.applied > 0
    # HOST + SERVICE nodes, the HOSTS edge, and SERVICE--RUNS-->application (product known)
    assert world.has_node("host:10.0.0.5")
    assert world.has_node("service:10.0.0.5:443/tcp")
    assert world.get_edge("host:10.0.0.5", "service:10.0.0.5:443/tcp", EdgeKind.HOSTS) is not None
    assert world.has_node("application:nginx")
    assert world.get_edge("service:10.0.0.5:443/tcp", "application:nginx", EdgeKind.RUNS) is not None
    # the CLOSED port did not mint a service
    assert not world.has_node("service:10.0.0.5:22/tcp")


def test_sensor_output_is_grounding_intel_not_a_fact() -> None:
    world = WorldModel()
    _run(world)
    svc = world.get_node("service:10.0.0.5:443/tcp")
    assert svc is not None
    # a sensor mints an OBSERVATION: provenance is the intel/grounding tier, never oracle-proof
    assert svc.provenance.startswith("intel:")


def test_service_descriptor_lands_on_the_service_node_not_the_host() -> None:
    # Review fix: the port/protocol/product descriptor belongs on the SERVICE node's own claim, not
    # on the HOSTS edge (which would smear it onto the HOST, order-dependently). The HOST stays a
    # clean machine node.
    world = WorldModel()
    _run(world)
    svc = world.get_node("service:10.0.0.5:443/tcp")
    assert svc is not None
    assert svc.attrs.get("port") == 443 and svc.attrs.get("product") == "nginx"
    host = world.get_node("host:10.0.0.5")
    assert host is not None
    assert "port" not in host.attrs and "product" not in host.attrs   # host is not polluted


def test_hostname_declared_host_mints_no_wrong_tier_domain_hosts_edge() -> None:
    # Review fix: host_ref maps a hostname to a DOMAIN, and HOSTS is a host/netblock->service edge.
    # A DOMAIN-declared host must NOT emit a DOMAIN--HOSTS-->SERVICE edge, but still records the
    # SERVICE and its RUNS->application (both tier-valid).
    obs = service_observations(
        "web.example.com", [{"port": 443, "protocol": "tcp", "product": "nginx"}],
        seq=1, source="declared", source_kind=IntelSourceKind.OPERATOR_INGEST, reliability=_DECL)
    rels = [o.relation for o in obs]
    assert EdgeKind.HOSTS not in rels          # no wrong-tier domain-hosts-service edge
    assert EdgeKind.RUNS in rels               # service->application is still recorded
    assert any(o.subject.node_id == "service:web.example.com:443/tcp" and o.relation is None
               for o in obs)                    # the SERVICE node itself is still minted


def test_obs_ids_are_claim_keyed_so_reorder_and_duplicates_collapse() -> None:
    # Review fix: obs_id carries no positional index, so it is a pure function of the claim. The
    # SAME service set in a different order yields the SAME obs_id set, and an intra-batch duplicate
    # collapses — belief cannot inflate from input ordering or duplication.
    a = {"port": 443, "protocol": "tcp", "product": "nginx"}
    b = {"port": 22, "protocol": "tcp"}
    fwd = service_observations("10.0.0.5", [a, b], seq=1, source="declared",
                               source_kind=IntelSourceKind.OPERATOR_INGEST, reliability=_DECL)
    rev = service_observations("10.0.0.5", [b, a], seq=1, source="declared",
                               source_kind=IntelSourceKind.OPERATOR_INGEST, reliability=_DECL)
    assert {o.obs_id for o in fwd} == {o.obs_id for o in rev}
    dup = service_observations("10.0.0.5", [a, a], seq=1, source="declared",
                               source_kind=IntelSourceKind.OPERATOR_INGEST, reliability=_DECL)
    single = service_observations("10.0.0.5", [a], seq=1, source="declared",
                                  source_kind=IntelSourceKind.OPERATOR_INGEST, reliability=_DECL)
    assert {o.obs_id for o in dup} == {o.obs_id for o in single}


def test_reingest_in_a_different_order_is_idempotent_no_belief_inflation() -> None:
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    ctx = ToolContext(slug="alpha")
    a1 = {"host": "10.0.0.5", "services": [
        {"port": 443, "protocol": "tcp", "product": "nginx"}, {"port": 80, "protocol": "tcp"}]}
    a2 = {"host": "10.0.0.5", "services": [
        {"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp", "product": "nginx"}]}
    reg = default_registry()
    run_sensor(reg, "declared_service", a1, ctx, ingest=ingest, seq=1)
    svc = world.get_node("service:10.0.0.5:443/tcp")
    mean_before = svc.belief_mean
    # re-declaring the SAME inventory in a different order at the same seq must not re-project
    r2 = run_sensor(reg, "declared_service", a2, ctx, ingest=ingest, seq=1)
    assert r2.applied == 0
    assert world.get_node("service:10.0.0.5:443/tcp").belief_mean == mean_before


def test_out_of_scope_host_is_refused_and_mints_nothing() -> None:
    # Review fix: a sensor acts on args['host'], so the charter-scope gate now applies to it. A host
    # NOT in the charter is refused BEFORE any minting.
    world = WorldModel()
    res = _run(world, args={"host": "8.8.8.8", "services": [{"port": 53, "protocol": "udp"}]})
    assert res.result.refused and res.result.gate == "scope"
    assert res.observations == [] and res.applied == 0
    assert not world.has_node("host:8.8.8.8")


def test_kill_switch_refuses_the_sensor_and_mints_nothing() -> None:
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("test halt")
    world = WorldModel()
    res = _run(world)
    assert res.result.refused and res.result.gate == "kill-switch"
    assert res.observations == [] and res.applied == 0
    assert not world.has_node("host:10.0.0.5")   # the gate ran BEFORE any minting


def test_sensor_ingest_is_deterministic_and_idempotent() -> None:
    world = WorldModel()
    reg = default_registry()
    ingest = IntelIngest(world, engagement_slug="alpha")
    ctx = ToolContext(slug="alpha")

    r1 = run_sensor(reg, "declared_service", _ARGS, ctx, ingest=ingest, seq=1)
    ids1 = [o.obs_id for o in r1.observations]
    n_nodes = len(world.all_nodes())
    # re-running the SAME observations at the SAME seq is idempotent: identical obs_ids, no
    # re-projection (applied 0), world unchanged (no false corroboration).
    r2 = run_sensor(reg, "declared_service", _ARGS, ctx, ingest=ingest, seq=1)
    assert [o.obs_id for o in r2.observations] == ids1     # deterministic obs_ids
    assert r2.applied == 0 and len(world.all_nodes()) == n_nodes


def test_normalizer_handles_a_bare_host_and_a_missing_host() -> None:
    s = DeclaredServiceSensor()
    ctx = ToolContext(slug="alpha")
    # an IP host with no services -> just the HOST observation (host_ref maps an IP -> HOST,
    # a hostname -> DOMAIN, per the intel convention)
    ok = s.run({"host": "192.0.2.9", "services": []}, ctx)
    assert ok.ok and [o.claim_key for o in s.normalize(ok, ctx, seq=1)] == [("host:192.0.2.9", "", "")]
    # a missing host -> failed result, no observations
    bad = s.run({"services": []}, ctx)
    assert not bad.ok and s.normalize(bad, ctx, seq=1) == []
