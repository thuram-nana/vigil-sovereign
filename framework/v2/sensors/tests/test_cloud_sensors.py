"""
Tests for Wave 5a — the Cloud / IAM / CSPM posture sensors.

These upgrade ``intel.from_cloud`` file-ingest into the Wave-2 sensor framework: an offline export
(native / ScoutSuite / Prowler) is normalised into IAM TOPOLOGY observations + posture LEADS
(``GROUNDING_INTEL``), never facts. The normalize path is PURE (offline fixtures); ``cloud_import`` is
Tier-1 (kill-switch gated, no network), ``cloud_pull`` is Tier-2 (ACTIVE_RECON + egress-allowlisted,
opt-in); both degrade cleanly when the export/collector is absent. The LEAD->FACT bridge
(``confirm_cloud_privilege_path``) is proven to promote only over a REAL IAM grant path (the policy-path
oracle re-derives it over the retained graph) and proven NOT to confirm a benign config.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolResult
from framework.v2.agents.tools.base import ToolRegistry
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import IntelSourceKind
from framework.v2.sensors import (
    CloudInventoryPullSensor,
    CloudPostureImportSensor,
    cloud_observations,
    cloud_posture_leads,
    confirm_cloud_privilege_path,
    default_registry,
    normalize_cloud_export,
    run_sensor,
)
from framework.v2.sensors.cloud import (
    _CLOUD_POSTURE_LEAD_RELIABILITY,
    _CLOUD_TOPOLOGY_RELIABILITY,
)
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind, NodeKind

# ---- fixtures: representative offline exports -------------------------------

_NATIVE = {
    "provider": "aws",
    "principals": [
        {"id": "role/dev", "kind": "role", "can_assume": ["role/admin"], "member_of": ["group/eng"]},
        {"id": "role/admin", "kind": "role"},
    ],
    "resources": [
        {"id": "s3/customer-data", "kind": "datastore", "sensitive": True,
         "grants": [{"principal": "role/admin", "access": "read"}]},
        {"id": "s3/public-logs", "kind": "datastore", "public": True},
        {"id": "db/pii", "kind": "database", "sensitive": True, "encrypted": False,
         "grants": [{"principal": "role/admin", "access": "admin"}]},
    ],
}

_SCOUTSUITE = {
    "provider": "aws",
    "services": {
        "iam": {
            "roles": {"AIDA1": {"id": "role/admin", "grants": [{"resource": "s3/secret", "access": "admin"}]}},
            "users": {"u1": {"id": "user/alice", "can_assume": ["role/admin"]}},
            "groups": {"g1": {"id": "group/eng"}},
        },
        "s3": {"buckets": {"b1": {"id": "s3/open", "public": True, "encryption_enabled": False}}},
    },
}

_PROWLER = {
    "provider": "aws",
    "findings": [
        {"check_id": "s3_bucket_public_access", "status": "FAIL", "resource_id": "s3/leaky"},
        {"check_id": "rds_storage_encrypted", "status": "FAIL", "resource_id": "rds/db1"},
        {"check_id": "iam_password_policy", "status": "PASS", "resource_id": "iam/acct"},   # a pass mints no lead
    ],
}


# ---- isolation + charter helpers (mirror the web-scanner sensor tests) ------


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _write_charter(tmp_path: Path, slug: str, host: str) -> None:
    (tmp_path / slug).mkdir(parents=True, exist_ok=True)
    (tmp_path / slug / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        "Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        "| Host / Surface | Notes | Auth |\n|---|---|---|\n"
        f"| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _ctx(slug: str = "alpha") -> ToolContext:
    return ToolContext(slug=slug)


def _ingest() -> tuple[WorldModel, IntelIngest]:
    world = WorldModel()
    return world, IntelIngest(world, engagement_slug="alpha")


# ===========================================================================
# normalize — offline, pure, real-format fixtures
# ===========================================================================


def test_native_normalize_mints_iam_topology_and_leads() -> None:
    world, ingest = _ingest()
    obs = CloudPostureImportSensor().normalize(
        ToolResult(ok=True, output={"export": json.dumps(_NATIVE), "format": "native"}), _ctx(), seq=1)
    ingest.ingest(obs, seq=1)
    # IAM topology the knowledge operators chain over
    assert world.get_edge("principal:role/dev", "principal:role/admin", EdgeKind.CAN_ASSUME) is not None
    assert world.get_edge("principal:role/dev", "principal:group/eng", EdgeKind.MEMBER_OF) is not None
    assert world.get_edge("principal:role/admin", "datastore:s3/customer-data", EdgeKind.HAS_GRANT) is not None
    # posture leads on the resource nodes
    classes = {o.attrs.get("lead_class") for o in obs if o.attrs.get("cloud_lead")}
    assert {"public_exposure", "excessive_privilege", "misconfiguration"} <= classes


def test_scoutsuite_normalize_extracts_iam_and_public_bucket() -> None:
    obs = CloudPostureImportSensor().normalize(
        ToolResult(ok=True, output={"export": json.dumps(_SCOUTSUITE), "format": "scoutsuite"}), _ctx(), seq=1)
    ids = {o.subject.node_id for o in obs}
    edges = {(o.subject.node_id, o.relation, o.object.node_id) for o in obs if o.relation}
    assert "principal:user/alice" in ids and "principal:role/admin" in ids
    assert ("principal:user/alice", EdgeKind.CAN_ASSUME, "principal:role/admin") in edges
    assert ("principal:role/admin", EdgeKind.HAS_GRANT, "cloud_resource:s3/secret") in edges
    assert any(o.attrs.get("lead_class") == "public_exposure" and "s3/open" in o.subject.node_id for o in obs)


def test_prowler_normalize_maps_failed_checks_to_leads() -> None:
    obs = CloudPostureImportSensor().normalize(
        ToolResult(ok=True, output={"export": json.dumps(_PROWLER), "format": "prowler"}), _ctx(), seq=1)
    leads = {(o.subject.node_id, o.attrs.get("lead_class")) for o in obs if o.attrs.get("cloud_lead")}
    assert ("cloud_resource:s3/leaky", "public_exposure") in leads
    assert ("cloud_resource:rds/db1", "misconfiguration") in leads
    assert not any("iam/acct" in nid for nid, _ in leads)   # the PASSing check mints no lead


def test_format_auto_detection() -> None:
    for doc, has in ((_NATIVE, "principal:role/dev"), (_SCOUTSUITE, "principal:user/alice")):
        obs = CloudPostureImportSensor().normalize(
            ToolResult(ok=True, output={"export": json.dumps(doc), "format": "auto"}), _ctx(), seq=1)
        assert any(has == o.subject.node_id for o in obs)


def test_source_kind_is_cloud_posture_and_reliabilities_are_split() -> None:
    obs = cloud_observations(_NATIVE, seq=1)
    assert obs and all(o.source_kind is IntelSourceKind.CLOUD_POSTURE for o in obs)
    topo = [o for o in obs if not o.attrs.get("cloud_lead")]
    leads = [o for o in obs if o.attrs.get("cloud_lead")]
    assert all(o.source_reliability == _CLOUD_TOPOLOGY_RELIABILITY for o in topo)   # policy topology: A2
    assert all(o.source_reliability == _CLOUD_POSTURE_LEAD_RELIABILITY for o in leads)   # judgement: moderate
    assert _CLOUD_POSTURE_LEAD_RELIABILITY.weight() < _CLOUD_TOPOLOGY_RELIABILITY.weight()


def test_leads_project_as_grounding_intel_never_a_fact() -> None:
    world, ingest = _ingest()
    ingest.ingest(cloud_observations(_NATIVE, seq=1), seq=1)
    node = world.get_node("datastore:s3/public-logs")
    assert node.grounding == "intel" and node.provenance.startswith("intel:")
    assert not any(n.kind is NodeKind.FINDING for n in world.all_nodes())   # a sensor never mints a FACT


def test_misconfiguration_lead_is_honestly_not_oracle_provable() -> None:
    leads = cloud_posture_leads(_NATIVE, seq=1)
    mis = [l for l in leads if l.attrs.get("lead_class") == "misconfiguration"]
    pub = [l for l in leads if l.attrs.get("lead_class") == "public_exposure"]
    assert mis and mis[0].attrs.get("oracle_provable") is False   # no reachability oracle proves "unencrypted"
    assert pub and pub[0].attrs.get("oracle_provable") is True    # a public grant path IS provable


# ===========================================================================
# determinism / idempotency
# ===========================================================================


def test_normalize_is_deterministic() -> None:
    a = cloud_observations(_NATIVE, seq=7)
    b = cloud_observations(_NATIVE, seq=7)
    assert [o.obs_id for o in a] == [o.obs_id for o in b]


def test_reingest_is_idempotent_no_node_inflation() -> None:
    world, ingest = _ingest()
    obs = cloud_observations(_NATIVE, seq=1)
    ingest.ingest(obs, seq=1)
    n1 = len(world.all_nodes())
    ingest.ingest(obs, seq=1)
    assert len(world.all_nodes()) == n1


def test_reordering_resources_yields_same_lead_ids() -> None:
    fwd = {o.obs_id for o in cloud_posture_leads(_NATIVE, seq=1)}
    shuffled = {**_NATIVE, "resources": list(reversed(_NATIVE["resources"]))}
    rev = {o.obs_id for o in cloud_posture_leads(shuffled, seq=1)}
    assert fwd == rev


# ===========================================================================
# malformed / graceful degradation
# ===========================================================================


@pytest.mark.parametrize("bad", ["", "not json at all", "42", "[]", "{}"])
def test_malformed_export_yields_no_or_empty_observations(bad: str) -> None:
    obs = CloudPostureImportSensor().normalize(
        ToolResult(ok=True, output={"export": bad, "format": "auto"}), _ctx(), seq=1)
    assert obs == []


def test_normalize_with_missing_output_yields_nothing() -> None:
    s = CloudPostureImportSensor()
    assert s.normalize(ToolResult(ok=True, output=None), _ctx(), seq=1) == []
    assert s.normalize(ToolResult(ok=True, output={"format": "auto"}), _ctx(), seq=1) == []


def test_normalize_cloud_export_total_on_garbage() -> None:
    for junk in (None, 42, "x", [], {"weird": 1}):
        out = normalize_cloud_export(junk)
        assert isinstance(out, dict) and "resources" in out


def test_normalize_is_pure_and_does_not_mutate_its_input() -> None:
    import copy
    original = copy.deepcopy(_NATIVE)
    normalize_cloud_export(_NATIVE)                        # synthesises the public->anon grant on a COPY
    confirm_cloud_privilege_path(_NATIVE, "*", "s3/public-logs")  # also normalises internally
    assert _NATIVE == original                            # the shared fixture is untouched


# ===========================================================================
# run() — graceful absence + arg validation (no network)
# ===========================================================================


def test_cloud_import_reads_an_export_file(tmp_path: Path) -> None:
    f = tmp_path / "export.json"
    f.write_text(json.dumps(_NATIVE), encoding="utf-8")
    res = CloudPostureImportSensor().run({"inventory_file": str(f)}, _ctx())
    assert res.ok and res.output["format"] == "auto"
    obs = CloudPostureImportSensor().normalize(res, _ctx(), seq=1)
    assert any(o.subject.node_id == "principal:role/dev" for o in obs)


def test_cloud_import_missing_file_degrades_cleanly(tmp_path: Path) -> None:
    res = CloudPostureImportSensor().run({"inventory_file": str(tmp_path / "nope.json")}, _ctx())
    assert not res.ok and "not found" in (res.note or "")


def test_cloud_import_missing_arg_is_a_failed_result_not_a_crash() -> None:
    res = CloudPostureImportSensor().run({}, _ctx())
    assert not res.ok and "inventory_file" in (res.note or "")


def test_cloud_pull_no_url_degrades_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CRUCIBLE_CLOUD_INVENTORY_URL", raising=False)
    res = CloudInventoryPullSensor(api_url="").run({}, _ctx())
    assert not res.ok and "no collector URL" in (res.note or "")


# ===========================================================================
# gating through run_sensor (the fail-closed chain)
# ===========================================================================


def test_cloud_sensors_registered_in_default_registry() -> None:
    reg = default_registry()
    assert "cloud_import" in reg and "cloud_pull" in reg


def test_cloud_import_is_tier1_but_kill_switch_gated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # No entitlement needed (Tier-1), but a tripped kill-switch refuses before anything is minted.
    from framework.v2.authority import KillSwitch
    _write_charter(tmp_path, "alpha", "127.0.0.1")
    f = tmp_path / "export.json"
    f.write_text(json.dumps(_NATIVE), encoding="utf-8")
    KillSwitch("alpha").trip("halt")
    world, ingest = _ingest()
    res = run_sensor(default_registry(), "cloud_import", {"inventory_file": str(f)}, _ctx(), ingest=ingest, seq=1)
    assert res.result.refused and res.result.gate == "kill-switch"
    assert res.observations == [] and len(world.all_nodes()) == 0


def test_cloud_import_runs_through_the_gate_and_ingests(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _write_charter(tmp_path, "alpha", "127.0.0.1")
    f = tmp_path / "export.json"
    f.write_text(json.dumps(_NATIVE), encoding="utf-8")
    world, ingest = _ingest()
    res = run_sensor(default_registry(), "cloud_import", {"inventory_file": str(f)}, _ctx(), ingest=ingest, seq=1)
    assert res.result.ok and not res.result.refused and res.applied > 0
    assert world.get_node("principal:role/admin") is not None


def test_cloud_pull_is_egress_gated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _grant_active_recon(monkeypatch)                        # entitlement passes; egress must still refuse
    _write_charter(tmp_path, "alpha", "127.0.0.1")          # the collector host is NOT in charter
    reg = ToolRegistry()
    reg.register(CloudInventoryPullSensor(api_url="http://collector.internal:8080"))
    world, ingest = _ingest()
    res = run_sensor(reg, "cloud_pull", {}, _ctx(), ingest=ingest, seq=1)
    assert res.result.refused and res.result.gate == "egress"
    assert res.observations == []


def test_cloud_pull_refused_without_entitlement(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from framework.v2 import entitlement

    def _deny(cap):
        raise RuntimeError(f"not entitled to {cap}")

    monkeypatch.setattr(entitlement, "require_capability", _deny)
    _write_charter(tmp_path, "alpha", "127.0.0.1")
    reg = ToolRegistry()
    reg.register(CloudInventoryPullSensor(api_url="http://collector.internal:8080"))
    world, ingest = _ingest()
    res = run_sensor(reg, "cloud_pull", {}, _ctx(), ingest=ingest, seq=1)
    assert res.result.refused and res.result.gate == "entitlement"


# ===========================================================================
# the LEAD -> FACT bridge (the policy-path oracle re-derives; the tool is never trusted)
# ===========================================================================


def test_confirm_cloud_privilege_path_promotes_a_real_assume_chain() -> None:
    # dev -> (assume) admin -> (grant) customer-data: a REAL IAM path -> CONFIRMED by the oracle.
    res = confirm_cloud_privilege_path(_NATIVE, "role/dev", "s3/customer-data")
    assert res.confirmed and res.confirming_signals[0].kind.value == "policy_path"


def test_confirm_cloud_privilege_path_none_against_a_benign_query() -> None:
    # a principal with no grant path never confirms — prove-don't-guess.
    assert not confirm_cloud_privilege_path(_NATIVE, "role/nobody", "s3/customer-data").confirmed


def test_public_exposure_lead_is_confirmed_via_the_anonymous_grant() -> None:
    # public-logs is public -> normalisation synthesises the anonymous grant -> the oracle proves the
    # anonymous principal's grant path (which is exactly what "public" means).
    assert confirm_cloud_privilege_path(_NATIVE, "*", "s3/public-logs").confirmed


def test_over_privileged_admin_grant_is_confirmed_at_write_tier() -> None:
    # role/admin holds ADMIN over the sensitive db/pii — a write/admin request confirms.
    assert confirm_cloud_privilege_path(_NATIVE, "role/admin", "db/pii", "write").confirmed


def test_bridge_does_not_confirm_a_wrong_access_tier() -> None:
    # customer-data grants only READ to admin; a WRITE request over the dev->admin path must NOT confirm.
    assert not confirm_cloud_privilege_path(_NATIVE, "role/dev", "s3/customer-data", "write").confirmed
