"""
Tests for the CI/CD posture sensor (GitHub-Actions workflow offline ingest).

A workflow file/dir is ingested (offline) as a gated sensor → CI/CD-control LEADS (``GROUNDING_INTEL``),
never facts. The sensor STOPS at leads; the CI/CD-posture oracle (``verify.cicd_posture``) re-verifies a
lead to a FACT only when it re-derives a concrete dangerous construct — wired through ``engage_fusion``
(``test_engage_fusion.py``), exactly as the k8s-posture oracle promotes kube-bench leads. The sensor
itself never mints a confirmed weakness. Mirrors ``test_k8s_runtime_sensor``.
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.agents.tools import ToolContext
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import IntelSourceKind
from framework.v2.sensors import (
    WorkflowScanSensor,
    cicd_control_observations,
    default_registry,
    parse_workflows,
)
from framework.v2.worldmodel.graph import WorldModel

# Dangerous: pull_request_target + a PR-head checkout (pwn_request), an unpinned third-party action, and
# a run interpolating an untrusted title (script_injection). The first-party checkout@v4 is a lead too.
_WF_VULN = """
name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: evil-org/evil-action@main
      - run: echo "PR ${{ github.event.pull_request.title }}"
"""

_WF_BENIGN = """
name: ci
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abcabcabcabcabcabcabcabcabcabcabcabcabca
      - run: make build
"""


def test_parse_tags_each_control_with_a_stable_check_id(tmp_path: Path) -> None:
    p = tmp_path / "ci.yml"
    p.write_text(_WF_VULN, encoding="utf-8")
    controls = parse_workflows(str(p))
    rules = sorted(c["rule"] for c in controls)
    assert rules == ["pwn_request", "script_injection", "unpinned_action", "unpinned_action"]
    # every control carries a stable, workflow-namespaced check_id so lead + later FACT share a node
    cids = [c["check_id"] for c in controls]
    assert all(c.startswith("ci.yml:build:") for c in cids)
    assert len(set(cids)) == len(cids)                       # unique per construct


def test_parse_of_a_directory_reads_all_workflows(tmp_path: Path) -> None:
    d = tmp_path / "workflows"
    d.mkdir()
    (d / "a.yml").write_text(_WF_VULN, encoding="utf-8")
    (d / "b.yaml").write_text(_WF_BENIGN, encoding="utf-8")
    (d / "notes.txt").write_text("ignored", encoding="utf-8")   # non-workflow files are skipped
    controls = parse_workflows(str(d))
    wfs = {c["workflow"] for c in controls}
    assert wfs == {"a.yml", "b.yaml"}


def test_parse_is_total_on_garbage(tmp_path: Path) -> None:
    for junk in ["", "not: : yaml", "null", "123", "{}", "jobs: nope"]:
        p = tmp_path / "j.yml"
        p.write_text(junk, encoding="utf-8")
        assert parse_workflows(str(p)) == []
    assert parse_workflows(str(tmp_path / "does-not-exist.yml")) == []


def test_observations_are_leads_not_facts(tmp_path: Path) -> None:
    p = tmp_path / "ci.yml"
    p.write_text(_WF_VULN, encoding="utf-8")
    obs = cicd_control_observations(parse_workflows(str(p)), seq=1)
    assert len(obs) == 4
    for o in obs:
        assert o.source == "cicd_workflows"
        assert o.source_kind is IntelSourceKind.OPERATOR_INGEST
        assert 0.0 < o.confidence < 1.0
        assert o.relation is None and o.object is None      # a bare node-claim, no asserted edge
        assert o.subject.node_id.startswith("control:cicd:")
        assert o.attrs.get("lead") is True and o.attrs.get("unverified") is True


def test_obs_ids_are_claim_keyed_and_reingest_is_idempotent(tmp_path: Path) -> None:
    p = tmp_path / "ci.yml"
    p.write_text(_WF_VULN, encoding="utf-8")
    controls = parse_workflows(str(p))
    ids1 = [o.obs_id for o in cicd_control_observations(controls, seq=1)]
    ids2 = [o.obs_id for o in cicd_control_observations(controls, seq=1)]
    assert ids1 == ids2                                     # deterministic (no clock/rng)
    dup = cicd_control_observations(controls + controls, seq=1)
    assert [o.obs_id for o in dup] == ids1                  # intra-batch duplicate collapses


def test_sensor_ingests_workflow_and_mints_control_leads(tmp_path: Path) -> None:
    p = tmp_path / "ci.yml"
    p.write_text(_WF_VULN, encoding="utf-8")
    s = WorkflowScanSensor()
    ctx = ToolContext(slug="alpha")
    res = s.run({"workflow": str(p)}, ctx)
    assert res.ok and res.summary == "cicd: 4 workflow control(s)"

    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    obs = s.normalize(res, ctx, seq=1)
    ingest.ingest(obs, seq=1)
    node_ids = [o.subject.node_id for o in obs]
    for nid in node_ids:
        assert world.has_node(nid)
        assert world.get_node(nid).provenance.startswith("intel:")   # a lead, never oracle-proof

    # re-ingesting the SAME workflow at the SAME seq is idempotent — no new nodes
    n_nodes = len(world.all_nodes())
    r2 = ingest.ingest(s.normalize(res, ctx, seq=1), seq=1)
    assert r2.applied == 0 and len(world.all_nodes()) == n_nodes


def test_sensor_missing_and_absent_report_degrade_cleanly(tmp_path: Path) -> None:
    ctx = ToolContext(slug="alpha")
    assert not WorkflowScanSensor().run({}, ctx).ok
    assert not WorkflowScanSensor().run({"workflow": "/no/such/dir"}, ctx).ok
    # a malformed workflow still runs (parse is total) but mints nothing
    p = tmp_path / "bad.yml"
    p.write_text("jobs: nope", encoding="utf-8")
    res = WorkflowScanSensor().run({"workflow": str(p)}, ctx)
    assert res.ok and WorkflowScanSensor().normalize(res, ctx, seq=1) == []


def test_registered_in_default_registry() -> None:
    assert "cicd_workflows" in default_registry()
