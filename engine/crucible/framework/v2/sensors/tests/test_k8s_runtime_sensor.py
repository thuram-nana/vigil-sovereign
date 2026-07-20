"""
Tests for Workstream C — the Kubernetes-runtime posture sensor (kube-bench offline ingest).

A kube-bench ``--json`` report is ingested (offline) as a gated sensor → CIS-control-failure LEADS
(``GROUNDING_INTEL``), never facts. This slice STOPS at leads — there is NO oracle; a FUTURE k8s-posture
oracle would re-verify a lead to a FACT (see ``docs/coverage-mobile-k8s-roadmap.md``), exactly as the
version-range oracle promotes SBOM leads. The sensor never mints a confirmed weakness.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import IntelSourceKind
from framework.v2.sensors import (
    KubeBenchSensor,
    default_registry,
    kube_bench_observations,
    parse_kube_bench,
)
from framework.v2.worldmodel.graph import WorldModel


# Shape 1: the top-level OBJECT (one target). FAIL + WARN are leads; PASS is skipped.
_KB_OBJECT = """
{"Controls": [
  {"id": "1", "text": "Master Node Security Configuration", "tests": [
    {"section": "1.2", "desc": "API Server", "results": [
      {"test_number": "1.2.1", "test_desc": "Ensure that the --anonymous-auth argument is set to false",
       "status": "FAIL", "remediation": "Edit the API server pod spec and set --anonymous-auth=false"},
      {"test_number": "1.2.2", "test_desc": "Ensure that the --basic-auth-file argument is not set",
       "status": "PASS"},
      {"test_number": "1.2.6", "test_desc": "Ensure that the --kubelet-certificate-authority argument is set",
       "status": "WARN", "remediation": "Follow the Kubernetes documentation and setup the TLS connection"}
    ]}
  ]}
]}
"""

# Shape 2: the newer top-level LIST (master/node/etcd/policies concatenated). FAIL is a lead; INFO skipped.
_KB_LIST = """
[
  {"Controls": [
    {"id": "4", "text": "Worker Node Security Configuration", "tests": [
      {"section": "4.2", "desc": "Kubelet", "results": [
        {"test_number": "4.2.1", "test_desc": "Ensure that the --anonymous-auth argument is set to false",
         "status": "FAIL", "remediation": "Set --anonymous-auth=false in the kubelet config"}
      ]}
    ]}
  ]},
  {"Controls": [
    {"id": "5", "text": "Kubernetes Policies", "tests": [
      {"section": "5.1", "desc": "RBAC and Service Accounts", "results": [
        {"test_number": "5.1.1", "test_desc": "Ensure that the cluster-admin role is only used where required",
         "status": "INFO"}
      ]}
    ]}
  ]}
]
"""


def test_parse_object_and_list_shapes() -> None:
    o = parse_kube_bench(_KB_OBJECT)
    # only FAIL + WARN survive; PASS (1.2.2) is dropped
    assert [c["check_id"] for c in o] == ["1.2.1", "1.2.6"]
    assert o[0]["status"] == "FAIL" and o[1]["status"] == "WARN"
    assert o[0]["section"] == "1.2" and o[0]["remediation"].startswith("Edit the API server")

    lst = parse_kube_bench(_KB_LIST)
    # only the FAIL survives; INFO (5.1.1) is dropped — even across the concatenated list documents
    assert [c["check_id"] for c in lst] == ["4.2.1"]
    assert lst[0]["status"] == "FAIL" and lst[0]["section"] == "4.2"


def test_parse_is_total_on_garbage() -> None:
    for junk in ["", "not json", "null", "123", '{"weird": 1}', '{"Controls": "nope"}', "[{}]", "[1, 2]"]:
        assert parse_kube_bench(junk) == []


def test_observations_are_leads_not_facts() -> None:
    controls = parse_kube_bench(_KB_OBJECT)
    obs = kube_bench_observations(controls, seq=1)
    assert len(obs) == 2
    for o in obs:
        # a sensor mints a LEAD: a posture source_kind, sub-1.0 confidence, never a confirmed fact
        assert o.source == "kube_bench"
        assert o.source_kind is IntelSourceKind.CLOUD_POSTURE
        assert 0.0 < o.confidence < 1.0
        assert o.relation is None and o.object is None      # a bare node-claim, no asserted edge
        assert o.subject.node_id.startswith("control:cis-k8s:")
    # the FAIL lead is weighted above the WARN lead (deterministic, status-derived)
    by_id = {o.subject.key: o.confidence for o in obs}
    assert by_id["cis-k8s:1.2.1"] > by_id["cis-k8s:1.2.6"]


def test_obs_ids_are_claim_keyed_and_reingest_is_idempotent() -> None:
    controls = parse_kube_bench(_KB_OBJECT)
    ids1 = [o.obs_id for o in kube_bench_observations(controls, seq=1)]
    ids2 = [o.obs_id for o in kube_bench_observations(controls, seq=1)]
    assert ids1 == ids2                                     # deterministic (no clock/rng)
    # an intra-batch duplicate check_id collapses to one observation (belief cannot inflate)
    dup = kube_bench_observations(controls + controls, seq=1)
    assert [o.obs_id for o in dup] == ids1


def test_sensor_ingests_report_and_mints_control_leads(tmp_path: Path) -> None:
    report = tmp_path / "kube-bench.json"
    report.write_text(_KB_OBJECT, encoding="utf-8")
    s = KubeBenchSensor()
    ctx = ToolContext(slug="alpha")
    res = s.run({"report": str(report)}, ctx)
    assert res.ok and res.summary == "kube-bench: 2 failed/warned control(s)"

    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    obs = s.normalize(res, ctx, seq=1)
    ingest.ingest(obs, seq=1)
    # the failed control is a CONTROL node carried as a GROUNDING_INTEL lead, never oracle-proof
    assert world.has_node("control:cis-k8s:1.2.1")
    node = world.get_node("control:cis-k8s:1.2.1")
    assert node.provenance.startswith("intel:")
    assert node.attrs.get("status") == "FAIL" and node.attrs.get("benchmark") == "cis-kubernetes"

    # re-ingesting the SAME report at the SAME seq is idempotent — no new nodes, no belief inflation
    n_nodes = len(world.all_nodes())
    r2 = ingest.ingest(s.normalize(res, ctx, seq=1), seq=1)
    assert r2.applied == 0 and len(world.all_nodes()) == n_nodes


def test_sensor_missing_and_absent_report_degrade_cleanly() -> None:
    ctx = ToolContext(slug="alpha")
    assert not KubeBenchSensor().run({}, ctx).ok
    assert not KubeBenchSensor().run({"report": "/no/such/kube-bench.json"}, ctx).ok
    # a malformed report still runs (parse is total) but mints nothing
    assert KubeBenchSensor().normalize(
        KubeBenchSensor().run({}, ctx), ctx, seq=1) == []


def test_registered_in_default_registry() -> None:
    assert "kube_bench" in default_registry()
