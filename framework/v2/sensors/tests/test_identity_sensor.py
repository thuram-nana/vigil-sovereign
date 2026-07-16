"""FORGE Domain 7 — the identity sensor (Tier-1, offline IdP-export ingest) tests."""

from __future__ import annotations

import json

from framework.v2.sensors.identity import (
    IdentitySensor,
    identity_observations,
    parse_identity_export,
)
from framework.v2.sensors.builtin import default_registry


def test_sensor_is_tier1_offline_and_non_egressing():
    s = IdentitySensor()
    assert s.name == "identity" and s.tier == "T1"
    assert s.capability is None and s.destructive is False and s.egress_hosts == ()


def test_registered_in_default_registry():
    reg = default_registry()
    getter = getattr(reg, "get", None)
    assert getter is not None and getter("identity") is not None


def test_parse_tags_a_stable_check_id_per_subject_and_rule():
    controls = parse_identity_export(json.dumps({"identities": [
        {"subject": "admin@x", "privileged": True, "mfa_enrolled": False},
        {"subject": "k1", "age_days": 400, "max_age_days": 90},
    ]}))
    assert {c["check_id"] for c in controls} == {"admin@x:privileged_without_mfa", "k1:stale_credential"}


def test_parse_is_total_on_garbage():
    assert parse_identity_export("{ not json") == []
    assert parse_identity_export(json.dumps({"identities": "nope"})) == []
    assert parse_identity_export(json.dumps([1, 2, 3])) == []


def test_leads_are_minted_on_the_control_node_the_oracle_promotes():
    controls = parse_identity_export(json.dumps({"identities": [
        {"subject": "Admin@Corp", "privileged": True, "mfa_enrolled": False}]}))
    obs = identity_observations(controls, seq=7)
    # the lead lands on the lowercased identity:<check_id> node — the exact node a promoted FACT will key on
    assert [o.subject.node_id for o in obs] == ["control:identity:admin@corp:privileged_without_mfa"]
    assert all(o.attrs.get("lead") is True and o.attrs.get("unverified") is True for o in obs)


def test_run_reads_a_local_export_file(tmp_path):
    p = tmp_path / "identity.json"
    p.write_text(json.dumps({"identities": [
        {"subject": "svc", "age_days": 500, "max_age_days": 90}]}), encoding="utf-8")

    class _Ctx:  # a minimal ToolContext stand-in
        dry_run = False
    res = IdentitySensor().run({"export": str(p)}, _Ctx())
    assert res.ok and res.output["controls"][0]["rule"] == "stale_credential"


def test_run_refuses_a_missing_export_arg():
    class _Ctx:
        dry_run = False
    assert not IdentitySensor().run({}, _Ctx()).ok
    assert not IdentitySensor().run({"export": "/no/such/file.json"}, _Ctx()).ok
