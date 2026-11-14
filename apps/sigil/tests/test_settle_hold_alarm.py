"""The held-settle alarm record (``governor.settle_hold``): what `vigil doctor` reads to report customer launch
settles held for the owner.

Pinned here: a launch is named once (its first entry, and so the time it has been held since, is kept); a release
drops only that launch and removes the file once it names none; a record that cannot be read is never overwritten
or released into (so no held launch it names is ever dropped by a later write) and reads as None; the record is
0600. The settle paths that write it are pinned in test_lease_plan_split_prune.py.
"""
from __future__ import annotations

import json
import os
import stat

import pytest

from sigil.governor import settle_hold


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    yield tmp_path / "home"


def test_a_launch_is_named_once_and_keeps_its_first_entry():
    assert settle_hold.read_held() == []
    assert settle_hold.record_held("org_a", "cust_1", "n1", "plan_debit_pruned") is True
    first = settle_hold.read_held()
    assert [(h["org_id"], h["slug"], h["nonce"], h["reason"]) for h in first] == [
        ("org_a", "cust_1", "n1", "plan_debit_pruned")]
    assert settle_hold.record_held("org_a", "cust_1", "n1", "plan_debit_pruned") is True
    assert settle_hold.read_held() == first
    assert stat.S_IMODE(os.stat(settle_hold.held_alarm_path()).st_mode) == 0o600


def test_a_release_drops_only_that_launch_and_the_file_goes_when_none_is_left():
    settle_hold.record_held("org_a", "cust_1", "n1", "plan_debit_pruned")
    settle_hold.record_held("org_a", "cust_1", "n2", "plan_debit_pruned")   # another launch of the same target
    settle_hold.record_held("org_b", "cust_2", "n3", "plan_debit_pruned")
    assert settle_hold.release_held("cust_1", "n1") is True
    assert sorted((h["slug"], h["nonce"]) for h in settle_hold.read_held()) == [("cust_1", "n2"), ("cust_2", "n3")]
    settle_hold.release_held("cust_1", "n2")
    settle_hold.release_held("cust_2", "n3")
    assert not settle_hold.held_alarm_path().exists()
    assert settle_hold.release_held("cust_9", "n9") is True                   # no record: a no-op
    assert not settle_hold.held_alarm_path().exists()


@pytest.mark.parametrize("body", ["{not json", json.dumps({"held": "x"}), json.dumps({"held": ["x"]}),
                                  json.dumps(["x"])], ids=["json", "not_a_list", "not_an_entry", "not_a_record"])
def test_an_unreadable_record_is_never_overwritten_or_released_into(body):
    p = settle_hold.held_alarm_path()
    p.parent.mkdir(parents=True)
    p.write_text(body, encoding="utf-8")
    assert settle_hold.read_held() is None
    assert settle_hold.record_held("org_a", "cust_1", "n1", "plan_debit_pruned") is False
    assert settle_hold.release_held("cust_1", "n1") is False
    assert p.read_text(encoding="utf-8") == body


def test_a_symlinked_record_is_unreadable(tmp_path):
    p = settle_hold.held_alarm_path()
    p.parent.mkdir(parents=True)
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"held": []}), encoding="utf-8")
    os.symlink(target, p)
    assert settle_hold.read_held() is None
    assert settle_hold.record_held("org_a", "cust_1", "n1", "plan_debit_pruned") is False
    assert json.loads(target.read_text(encoding="utf-8")) == {"held": []}


def test_the_record_names_the_file_vigil_doctor_reads():
    import pathlib

    from vigil_integration import doctor as _doc
    src = pathlib.Path(_doc.__file__).read_text(encoding="utf-8")
    assert f'home / "alarms" / "{settle_hold.HELD_ALARM_NAME}"' in src
    assert settle_hold.held_alarm_path().parent.name == "alarms"
