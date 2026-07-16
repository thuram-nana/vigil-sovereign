"""sensors.mobile — the MobSF static-report mobile posture sensor (leads-only first slice).

Pins that it mints APPLICATION + CONTROL + ENDPOINT LEADS (never facts), reuses existing node kinds (no
new enum), skips secure checks, is idempotent + malformed-safe, and is a gated Tier-1 sensor.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.v2.sensors.mobile import MobsfSensor, mobsf_observations, parse_mobsf
from framework.v2.worldmodel.models import NodeKind

_REPORT = {
    "app_name": "DemoApp", "package_name": "com.demo.app", "version_name": "1.2",
    "manifest_analysis": {"manifest_findings": [
        {"title": "Activity is exported", "severity": "high", "rule": "exported_activity",
         "description": "com.demo.X is exported without a permission"},
        {"title": "App uses cleartext traffic", "severity": "warning", "rule": "clear_text",
         "description": "android:usesCleartextTraffic=true"},
        {"title": "A secure setting", "severity": "secure", "rule": "ok_check"}]},
    "network_security": {"network_findings": [
        {"title": "Base config permits cleartext", "severity": "high", "rule": "nsc_cleartext"}]},
    "urls": [{"url": ["http://api.demo.app/v1", "https://cdn.demo.app/x"]}, "not-a-url"],
    "possible_secrets": ["AKIAIOSFODNN7EXAMPLE"],
}


def _kinds(obs):
    from collections import Counter
    return Counter(o.subject.kind for o in obs)


def test_parse_extracts_app_controls_urls():
    p = parse_mobsf(json.dumps(_REPORT))
    assert p["app"]["package"] == "com.demo.app"
    # 2 manifest + 1 network + 1 secret = 4 controls; the "secure" finding is skipped
    assert len(p["controls"]) == 4
    assert not any("ok_check" in c["check_id"] for c in p["controls"])
    assert p["urls"] == ["http://api.demo.app/v1", "https://cdn.demo.app/x"]


def test_mints_leads_not_facts():
    obs = mobsf_observations(parse_mobsf(json.dumps(_REPORT)), seq=1)
    kinds = _kinds(obs)
    assert kinds[NodeKind.APPLICATION] == 1
    assert kinds[NodeKind.CONTROL] == 4
    assert kinds[NodeKind.ENDPOINT] == 2
    # EVERY observation is an operator-ingest LEAD, never a fact
    for o in obs:
        assert o.source_kind.value == "operator_ingest"
        assert o.confidence < 1.0
        if o.subject.kind in (NodeKind.CONTROL, NodeKind.ENDPOINT):
            assert o.attrs.get("unverified") is True
    # control keys are namespaced mobile:<check_id>
    assert any(o.subject.key.startswith("mobile:") for o in obs if o.subject.kind is NodeKind.CONTROL)
    # embedded URLs carry a `url` attr (so the discoverer can test them, scope-gated)
    assert all(o.attrs.get("url") for o in obs if o.subject.kind is NodeKind.ENDPOINT)


def test_observations_are_idempotent():
    p = parse_mobsf(json.dumps(_REPORT))
    a = [o.obs_id for o in mobsf_observations(p, seq=1)]
    b = [o.obs_id for o in mobsf_observations(p, seq=1)]
    assert a == b and len(a) == len(set(a))   # deterministic + no duplicate obs_ids


def test_malformed_and_empty_are_safe():
    assert parse_mobsf("{bad json") == {}
    assert parse_mobsf(json.dumps([1, 2, 3])) == {}
    assert mobsf_observations({}, seq=1) == []
    assert mobsf_observations({"app": {}}, seq=1) == []   # no app identity -> nothing


def test_run_over_a_file(tmp_path: Path):
    f = tmp_path / "mobsf.json"
    f.write_text(json.dumps(_REPORT), encoding="utf-8")
    s = MobsfSensor()
    res = s.run({"report": str(f)}, ctx=None)
    assert res.ok
    obs = s.normalize(res, ctx=None, seq=3)
    assert _kinds(obs)[NodeKind.CONTROL] == 4
    # a missing file / bad args fail cleanly (no raise)
    assert not s.run({}, ctx=None).ok
    assert not s.run({"report": str(tmp_path / "nope.json")}, ctx=None).ok


def test_parse_retains_embedded_private_key_pem_as_structured_control():
    import pytest
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import rsa
    pem = rsa.generate_private_key(65537, 2048).private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode()
    # MobSF often escapes newlines when the secret is a JSON string value
    for shape in (pem, pem.replace("\n", "\\n")):
        p = parse_mobsf(json.dumps({"package_name": "com.x", "possible_secrets": [shape]}))
        pk = [c for c in p["controls"] if c.get("rule") == "private_key_material"]
        assert len(pk) == 1
        # the FULL PEM is retained verbatim (not truncated to 200) so the oracle can re-load it
        assert "BEGIN PRIVATE KEY" in pk[0]["pem"] and "END PRIVATE KEY" in pk[0]["pem"]
        assert pk[0]["severity"] == "high"


def test_parse_reconstructs_a_list_of_lines_secret():
    # review defect [LOW]: MobSF sometimes splits a secret into per-line pieces; joining with newlines
    # (not str(list), which inserts ', ' separators) keeps the PEM re-loadable by the oracle.
    import pytest
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import rsa
    from framework.v2.verify.mobile_posture import confirm_mobile_controls
    pem = rsa.generate_private_key(65537, 2048).private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode()
    p = parse_mobsf(json.dumps({"package_name": "com.x", "secrets": [pem.split("\n")]}))
    assert confirm_mobile_controls(p["controls"])  # reconstructed → the oracle confirms it


def test_parse_non_key_secret_stays_a_plain_lead():
    # a normal flagged secret gets NO private_key_material rule (so the oracle never promotes it)
    p = parse_mobsf(json.dumps({"package_name": "com.x", "possible_secrets": ["AKIAIOSFODNN7EXAMPLE"]}))
    assert p["controls"] and all(c.get("rule") != "private_key_material" for c in p["controls"])


def test_control_lead_carries_check_id_and_rule_in_attrs():
    obs = mobsf_observations(parse_mobsf(json.dumps(_REPORT)), seq=1)
    controls = [o for o in obs if o.subject.kind is NodeKind.CONTROL]
    assert controls and all(o.attrs.get("check_id") for o in controls)  # parity with k8s/cicd


def test_sensor_is_gated_tier1_and_registered():
    s = MobsfSensor()
    assert s.tier == "T1" and s.capability is None and s.egress_hosts == () and s.destructive is False
    from framework.v2.sensors.builtin import register_builtin_sensors
    from framework.v2.agents.tools import ToolRegistry
    reg = register_builtin_sensors(ToolRegistry())
    assert "mobsf_static" in reg
