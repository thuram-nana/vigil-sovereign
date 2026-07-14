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


def test_sensor_is_gated_tier1_and_registered():
    s = MobsfSensor()
    assert s.tier == "T1" and s.capability is None and s.egress_hosts == () and s.destructive is False
    from framework.v2.sensors.builtin import register_builtin_sensors
    from framework.v2.agents.tools import ToolRegistry
    reg = register_builtin_sensors(ToolRegistry())
    assert "mobsf_static" in reg
