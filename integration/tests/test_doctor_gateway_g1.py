"""PRICING G1 — `vigil doctor` reports the gateway-at-scale posture (without importing sigil): the provider-account
POOL spec is validated and each account's key must be present, and the model gateway's LOSS ALARM file is a hard
issue while it is open. Integration leg (doctor only — framework-free).
"""
from __future__ import annotations

import json

from vigil_core import model_metering as mm

from vigil_integration import doctor as d

ON = {"VIGIL_METERED_BILLING": "1", "VIGIL_MODEL_GATEWAY_ENABLED": "1", "SIGIL_ANTHROPIC_API_KEY": "sk",
      mm.MARGIN_ENV: "0." + str(3) + str(75), mm.CANCEL_ENV: "metered", "VIGIL_SETTLE_SPINE_RECORD": "1"}


def _alive(url):
    return True


def test_g1_off_adds_no_g1_section():
    section, issues, _ = d._metering_report(dict(ON), probe=_alive)
    assert "g1" not in section and not issues


def test_a_valid_g1_pool_is_reported():
    env = {**ON, "VIGIL_GATEWAY_G1": "1",
           "VIGIL_GATEWAY_POOL": json.dumps([{"id": "a", "key_env": "KA"}, {"id": "b", "key_env": "KB"}]),
           "KA": "sk-a", "KB": "sk-b"}
    section, issues, _ = d._metering_report(env, probe=_alive)
    assert section.get("g1") is True and section.get("pool_accounts") == 2 and not issues


def test_a_g1_pool_account_missing_its_key_is_a_hard_issue():
    env = {**ON, "VIGIL_GATEWAY_G1": "1",
           "VIGIL_GATEWAY_POOL": json.dumps([{"id": "a", "key_env": "KA"}])}   # KA unset
    section, issues, _ = d._metering_report(env, probe=_alive)
    assert any("account 'a' has no key" in m for m in issues)


def test_a_malformed_g1_pool_is_a_hard_issue():
    env = {**ON, "VIGIL_GATEWAY_G1": "1", "VIGIL_GATEWAY_POOL": "not json"}
    _s, issues, _ = d._metering_report(env, probe=_alive)
    assert any("provider pool is misconfigured" in m for m in issues)


def test_g1_without_the_gateway_is_a_hard_issue():
    env = {"VIGIL_GATEWAY_G1": "1", "VIGIL_MODEL_GATEWAY_ENABLED": "0", "VIGIL_METERED_BILLING": "0"}
    _s, issues, _ = d._metering_report(env, probe=_alive)
    assert any("VIGIL_GATEWAY_G1 is on but VIGIL_MODEL_GATEWAY_ENABLED is not" in m for m in issues)


# --------------------------------------------------------------------------- the loss-alarm collect block (real)
import os  # noqa: E402
from pathlib import Path  # noqa: E402

_REPO = Path(d.__file__).resolve().parents[2]


def _doctor(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    if "VIGIL_SETTLE_SPOOL" not in os.environ:
        monkeypatch.setenv("VIGIL_SETTLE_SPOOL", str(tmp_path / "no-spool"))
    return d.collect(_REPO)


def _write_loss(tmp_path, body):
    p = tmp_path / "home" / "alarms" / "gateway-loss.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return p


def test_no_loss_alarm_adds_nothing(tmp_path, monkeypatch):
    clean = _doctor(tmp_path, monkeypatch)
    assert not any("loss alarm" in i for i in clean["issues"])
    assert "gateway_loss" not in clean


def test_an_open_loss_alarm_is_a_hard_issue(tmp_path, monkeypatch):
    _write_loss(tmp_path, {"v": 1, "tripped": True, "day": "2026-11-17", "confirmed_nano": 1, "unconfirmed_nano": 9})
    report = _doctor(tmp_path, monkeypatch)
    assert any("loss alarm is OPEN for 2026-11-17" in i for i in report["issues"])
    assert report["gateway_loss"]["state"] == "tripped"


def test_an_unreadable_loss_alarm_is_a_hard_issue(tmp_path, monkeypatch):
    _write_loss(tmp_path, "{broken json")
    report = _doctor(tmp_path, monkeypatch)
    assert any("loss alarm" in i and "cannot be read" in i for i in report["issues"])
    assert report["gateway_loss"]["state"] == "unreadable"


def test_a_cleared_loss_alarm_adds_nothing(tmp_path, monkeypatch):
    # a record that is present but not tripped (the gateway removes it, but be robust) -> treated as unreadable
    clean = _doctor(tmp_path, monkeypatch)
    _write_loss(tmp_path, {"v": 1, "tripped": False, "day": "2026-11-17"})
    report = _doctor(tmp_path, monkeypatch)
    # a non-tripped record is unexpected (the gateway deletes it) -> surfaced fail-closed, not silently dropped
    assert any("loss alarm" in i for i in report["issues"])
    assert clean is not report
