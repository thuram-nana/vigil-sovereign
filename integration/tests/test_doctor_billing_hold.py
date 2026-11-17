"""``vigil doctor`` reports customer orgs on a BILLING HOLD (W5) as a HARD issue.

A chargeback or refund takes credits back that were already spent, so the org owes them (arrears) and can start no
billable work until a top-up repays them. The sovereign reversal ledger names each held org in
``$SIGIL_HOME/alarms/billing-hold.json``. Doctor reads that file (no sovereign import, FATAL-2) and raises a HARD issue
naming the held orgs with the credits each owes (``billing_holds``); an unreadable record is a HARD issue too; no
record (or one naming none) adds nothing, so the default report is unchanged. Framework-free (integration leg).

Mutation-verify targets (each neuter reds a NAMED test here):
  * the probe dropped / reported as a note        -> test_doctor_reports_held_orgs
  * an unreadable record passed as "nothing held" -> test_doctor_reports_an_unreadable_hold_record
  * an empty record reported                      -> test_doctor_adds_nothing_without_a_billing_hold
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from vigil_integration import doctor as _doc

_REPO = Path(_doc.__file__).resolve().parents[2]
_HIT = "on a billing hold"


def _doctor(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    if "VIGIL_SETTLE_SPOOL" not in os.environ:
        monkeypatch.setenv("VIGIL_SETTLE_SPOOL", str(tmp_path / "no-spool"))
    return _doc.collect(_REPO)


def _write(tmp_path, body) -> Path:
    p = tmp_path / "home" / "alarms" / "billing-hold.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return p


def test_doctor_adds_nothing_without_a_billing_hold(tmp_path, monkeypatch):
    clean = _doctor(tmp_path, monkeypatch)
    assert not any(_HIT in i for i in clean["issues"]) and "billing_holds" not in clean
    _write(tmp_path, {"v": 1, "held": []})
    report = _doctor(tmp_path, monkeypatch)
    assert report["issues"] == clean["issues"] and "billing_holds" not in report


def test_doctor_reports_held_orgs(tmp_path, monkeypatch):
    clean = _doctor(tmp_path, monkeypatch)
    _write(tmp_path, {"v": 1, "held": [{"org_id": "org_a", "owed": 300, "since": 1.0},
                                       {"org_id": "org_b", "owed": 50, "since": 2.0}]})
    report = _doctor(tmp_path, monkeypatch)
    hit = [i for i in report["issues"] if _HIT in i]
    assert len(hit) == 1 and "org_a (300 credits)" in hit[0] and "org_b (50 credits)" in hit[0]
    assert report["ok"] is False and report["billing_holds"] == [{"org_id": "org_a", "owed": 300},
                                                                 {"org_id": "org_b", "owed": 50}]
    assert len(report["issues"]) == len(clean["issues"]) + 1


def test_doctor_reports_an_unreadable_hold_record(tmp_path, monkeypatch):
    _write(tmp_path, "{not json")
    report = _doctor(tmp_path, monkeypatch)
    assert report["ok"] is False and report["billing_holds"] == ["(unreadable)"]
    assert any("cannot be read" in i and "billing hold" in i for i in report["issues"])


def test_a_symlink_hold_record_is_unreadable(tmp_path, monkeypatch):
    real = tmp_path / "evil.json"
    real.write_text(json.dumps({"v": 1, "held": [{"org_id": "org_a", "owed": 9}]}), encoding="utf-8")
    p = tmp_path / "home" / "alarms" / "billing-hold.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.symlink_to(real)
    report = _doctor(tmp_path, monkeypatch)
    assert report["billing_holds"] == ["(unreadable)"] and report["ok"] is False


def test_a_malformed_entry_is_unreadable(tmp_path, monkeypatch):
    _write(tmp_path, {"v": 1, "held": [{"org_id": "org_a"}]})      # missing owed
    report = _doctor(tmp_path, monkeypatch)
    assert report["billing_holds"] == ["(unreadable)"]
