"""
Tests for the service-mesh posture sensor (Istio/Linkerd config offline ingest).

A mesh config file/dir is ingested (offline) as a gated sensor → mesh-resource CONTROL LEADS
(``GROUNDING_INTEL``), never facts. The sensor STOPS at leads; the mesh-posture oracle
(``verify.mesh_posture``) re-verifies a lead to a FACT only for a concrete insecure achieved state —
wired through ``engage_fusion`` (``test_engage_fusion.py``). A STRICT/scoped/deny config stays a lead.
Mirrors ``test_cicd_sensor``.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.v2.agents.tools import ToolContext
from framework.v2.sensors import MeshConfigSensor, mesh_control_observations, parse_mesh
from framework.v2.sensors.builtin import register_builtin_sensors
from framework.v2.agents.tools.base import ToolRegistry

_PERMISSIVE = json.dumps([
    {"kind": "PeerAuthentication", "metadata": {"name": "default", "namespace": "istio-system"},
     "spec": {"mtls": {"mode": "PERMISSIVE"}}},
    {"kind": "AuthorizationPolicy", "metadata": {"name": "allow-all", "namespace": "prod"},
     "spec": {"action": "ALLOW", "rules": [{}]}},
])
_STRICT = json.dumps([
    {"kind": "PeerAuthentication", "metadata": {"name": "default", "namespace": "istio-system"},
     "spec": {"mtls": {"mode": "STRICT"}}},
])


def test_parse_tags_each_control_with_a_stable_source_namespaced_check_id(tmp_path: Path) -> None:
    p = tmp_path / "istio.json"
    p.write_text(_PERMISSIVE, encoding="utf-8")
    controls = parse_mesh(str(p))
    assert len(controls) == 2
    cids = sorted(c["check_id"] for c in controls)
    assert cids == ["istio.json:istio:AuthorizationPolicy:prod/allow-all",
                    "istio.json:istio:PeerAuthentication:istio-system/default"]
    assert len(set(cids)) == len(cids)


def test_same_identity_resources_across_files_do_not_collide(tmp_path: Path) -> None:
    # review fix: a merged/multi-cluster dir where two files carry the SAME provider:kind:ns/name resource
    # (one STRICT, one PERMISSIVE) must yield TWO distinct controls, not one collapsed node.
    d = tmp_path / "clusters"
    d.mkdir()
    same = {"kind": "PeerAuthentication", "metadata": {"name": "default", "namespace": "istio-system"}}
    (d / "cluster-a.json").write_text(json.dumps([{**same, "spec": {"mtls": {"mode": "STRICT"}}}]), encoding="utf-8")
    (d / "cluster-b.json").write_text(json.dumps([{**same, "spec": {"mtls": {"mode": "PERMISSIVE"}}}]), encoding="utf-8")
    controls = parse_mesh(str(d))
    cids = {c["check_id"] for c in controls}
    assert len(controls) == 2 and len(cids) == 2                     # both survive, distinct keys
    assert cids == {"cluster-a.json:istio:PeerAuthentication:istio-system/default",
                    "cluster-b.json:istio:PeerAuthentication:istio-system/default"}


def test_parse_of_a_directory_reads_all_manifests(tmp_path: Path) -> None:
    d = tmp_path / "mesh"
    d.mkdir()
    (d / "a.json").write_text(_PERMISSIVE, encoding="utf-8")
    (d / "b.json").write_text(_STRICT, encoding="utf-8")
    (d / "notes.txt").write_text("ignored", encoding="utf-8")   # non-manifest extension skipped
    assert len(parse_mesh(str(d))) == 3


def test_parse_is_total_on_garbage(tmp_path: Path) -> None:
    p = tmp_path / "junk.json"
    for junk in ("not json or yaml : :", "null", "123", "{}", '{"kind":"Service"}'):
        p.write_text(junk, encoding="utf-8")
        assert parse_mesh(str(p)) == []          # unrecognised kinds are skipped
    assert parse_mesh(str(tmp_path / "nope.json")) == []


def test_observations_are_leads_not_facts(tmp_path: Path) -> None:
    p = tmp_path / "istio.json"
    p.write_text(_PERMISSIVE, encoding="utf-8")
    obs = mesh_control_observations(parse_mesh(str(p)), seq=1)
    assert len(obs) == 2
    for o in obs:
        assert o.source == "mesh_config"
        assert o.source_kind.value == "operator_ingest"
        assert 0.0 < o.confidence < 1.0
        assert o.relation is None and o.object is None
        assert o.subject.node_id.startswith("control:mesh:")
        assert o.attrs.get("lead") is True and o.attrs.get("unverified") is True


def test_obs_ids_are_claim_keyed_and_reingest_is_idempotent(tmp_path: Path) -> None:
    p = tmp_path / "istio.json"
    p.write_text(_PERMISSIVE, encoding="utf-8")
    controls = parse_mesh(str(p))
    ids1 = [o.obs_id for o in mesh_control_observations(controls, seq=1)]
    ids2 = [o.obs_id for o in mesh_control_observations(controls, seq=1)]
    assert ids1 == ids2
    dup = mesh_control_observations(controls + controls, seq=1)
    assert [o.obs_id for o in dup] == ids1                  # intra-batch duplicate collapses


def test_sensor_ingests_config_and_mints_control_leads(tmp_path: Path) -> None:
    p = tmp_path / "istio.json"
    p.write_text(_PERMISSIVE, encoding="utf-8")
    s = MeshConfigSensor()
    ctx = ToolContext(slug="alpha")
    res = s.run({"config": str(p)}, ctx)
    assert res.ok and res.summary == "mesh: 2 mesh resource(s)"
    obs = s.normalize(res, ctx, seq=1)
    assert obs and all(o.subject.node_id.startswith("control:mesh:") for o in obs)


def test_sensor_missing_and_absent_config_degrade_cleanly(tmp_path: Path) -> None:
    ctx = ToolContext(slug="alpha")
    assert not MeshConfigSensor().run({}, ctx).ok
    assert not MeshConfigSensor().run({"config": "/no/such/dir"}, ctx).ok
    p = tmp_path / "junk.json"
    p.write_text('{"kind":"Service"}', encoding="utf-8")   # a non-mesh kind → runs, mints nothing
    res = MeshConfigSensor().run({"config": str(p)}, ctx)
    assert res.ok and MeshConfigSensor().normalize(res, ctx, seq=1) == []


def test_registered_in_default_registry() -> None:
    assert "mesh_config" in register_builtin_sensors(ToolRegistry())
