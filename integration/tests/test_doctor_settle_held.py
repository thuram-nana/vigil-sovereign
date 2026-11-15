"""``vigil doctor`` reports customer launch settles HELD for the owner as a HARD issue.

A launch settle that cannot tell how much of a reservation to return to each credit bucket moves nothing; the
sovereign gate names the launch in ``$SIGIL_HOME/alarms/launch-settle-held.json``, whichever path refused it. Doctor
reads that file (no sovereign import, FATAL-2) and raises a HARD issue naming the held launches by slug only (never a
nonce), ``launch_settlements["held"]``; an unreadable record is a HARD issue too; no record (or one naming none) adds
nothing, so the default report is unchanged. Framework-free (integration leg).

Mutation-verify targets (each neuter reds a NAMED test here):
  * the probe dropped / reported as a note           -> test_doctor_reports_held_settles_by_slug
  * a nonce printed                                  -> test_doctor_reports_held_settles_by_slug
  * an unreadable record passed as "nothing held"    -> test_doctor_reports_an_unreadable_record
  * an empty record reported                         -> test_doctor_adds_nothing_without_a_held_settle
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from vigil_integration import doctor as _doc

_REPO = Path(_doc.__file__).resolve().parents[2]
_HIT = "held for the owner"


def _doctor(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    if "VIGIL_SETTLE_SPOOL" not in os.environ:               # never the real ~/.sigil spool of the machine
        monkeypatch.setenv("VIGIL_SETTLE_SPOOL", str(tmp_path / "no-spool"))
    return _doc.collect(_REPO)


def _write(tmp_path, body) -> Path:
    p = tmp_path / "home" / "alarms" / "launch-settle-held.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return p


def _entry(slug, nonce):
    return {"org_id": "org_a", "slug": slug, "nonce": nonce, "reason": "plan_debit_pruned", "since": 1.0}


def test_doctor_adds_nothing_without_a_held_settle(tmp_path, monkeypatch):
    clean = _doctor(tmp_path, monkeypatch)
    assert not any(_HIT in i for i in clean["issues"])
    assert "held" not in clean.get("launch_settlements", {})
    _write(tmp_path, {"v": 1, "held": []})
    report = _doctor(tmp_path, monkeypatch)
    assert report["issues"] == clean["issues"] and "held" not in report.get("launch_settlements", {})


def test_doctor_reports_held_settles_by_slug(tmp_path, monkeypatch):
    clean = _doctor(tmp_path, monkeypatch)
    entries = [_entry(f"cust_{i:02d}", f"nonce-secret-{i:02d}") for i in range(12)]
    entries.append(_entry("cust_00", "nonce-secret-again"))           # two launches of one target: one slug
    _write(tmp_path, {"v": 1, "held": entries})
    report = _doctor(tmp_path, monkeypatch)
    new = [i for i in report["issues"] if i not in clean["issues"]]
    assert len(new) == 1 and _HIT in new[0], new
    assert new[0].startswith("12 customer launch settle(s)") and "and 2 more" in new[0], new[0]
    assert "cust_00" in new[0] and "cust_10" not in new[0]
    assert "nonce-secret" not in new[0] and "nonce-secret" not in json.dumps(report["launch_settlements"])
    assert report["launch_settlements"]["held"] == [f"cust_{i:02d}" for i in range(12)]
    assert report["ok"] is False


@pytest.mark.parametrize("body", ["{not json", {"held": "x"}, {"held": [{"nonce": "n"}]}, ["x"]],
                         ids=["json", "not_a_list", "no_slug", "not_a_record"])
def test_doctor_reports_an_unreadable_record(tmp_path, monkeypatch, body):
    clean = _doctor(tmp_path, monkeypatch)
    _write(tmp_path, body)
    report = _doctor(tmp_path, monkeypatch)
    new = [i for i in report["issues"] if i not in clean["issues"]]
    assert len(new) == 1 and "cannot be read" in new[0] and "held for the owner" in new[0], new
    assert report["launch_settlements"]["held"] == ["(unreadable)"]
