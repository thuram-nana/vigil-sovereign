"""DEP-3 (#73) — the on-box upgrade/rollback drill (``sigil.spine.upgrade_drill``).

It must (a) PASS on a healthy real spine (legacy or already-migrated) — upgrade under this build, detect a
corrupted deployment, roll back intact; (b) NEVER modify the real spine directory (proven by a content digest,
and a drill that DID change it must FAIL); (c) FAIL honestly when any step does not hold (source does not
verify, negative control does not bite, rollback not intact); (d) report NOT-RUN (exit 3), never green, when
there is no data to drill.
"""
from __future__ import annotations

import json

import pytest

from sigil.spine import upgrade_drill as ud
from sigil.spine.store import SpineStore
from sigil.spine.upgrade import upgrade


def _real_spine(tmp_path, n=8, migrate=False):
    path = tmp_path / "home" / "spine" / "spine.jsonl"
    s = SpineStore(str(path))
    for i in range(n):
        s.append(kind="event", source="drill-test", actor="op", payload={"i": i, "note": f"entry {i}"})
    if migrate:
        upgrade(SpineStore(str(path)), backup_dir=tmp_path / "pre-backups")
    return path


@pytest.mark.parametrize("migrate", [False, True])
def test_healthy_real_spine_passes_and_the_source_is_untouched(tmp_path, migrate):
    path = _real_spine(tmp_path, migrate=migrate)
    before = ud._tree_digest(path.parent)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.PASS and v["ok"] is True, v
    assert v["source_untouched"] is True and ud._tree_digest(path.parent) == before
    steps = {s["step"]: s for s in v["steps"]}
    assert steps["negative_control"]["detected"] is True
    assert steps["rollback"]["ok"] is True and steps["rollback"]["intact"] is True
    assert v["count"] == 8


def test_no_data_is_not_run_never_green(tmp_path):
    v = ud.run_upgrade_drill(tmp_path / "empty" / "spine.jsonl", tmp_path / "work")
    assert v["status"] == ud.NOT_RUN and v["ok"] is False


def test_a_source_that_does_not_verify_fails(tmp_path):
    path = _real_spine(tmp_path)
    assert ud.corrupt_one_record(path.parent)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and v["detail"].startswith("the real spine (copied) does not verify")
    assert not any(st["step"] == "upgrade" for st in v["steps"])   # never even attempts to upgrade it


def test_an_upgrade_that_changes_the_record_set_fails(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)
    real_upgrade = ud.upgrade

    def lossy_upgrade(store, **kw):
        rep = real_upgrade(store, **kw)
        SpineStore(str(store.path)).append(kind="event", source="rogue", actor="x", payload={"extra": 1})
        return rep                                                           # "ok" — but not the same data
    monkeypatch.setattr(ud, "upgrade", lossy_upgrade)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "upgraded copy is not intact" in v["detail"]


def test_a_negative_control_that_does_not_bite_fails(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)
    monkeypatch.setattr(ud, "corrupt_one_record", lambda d: False)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "negative control" in v["detail"]


def test_a_rollback_that_does_not_restore_fails(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)
    monkeypatch.setattr(ud, "restore_from_backup", lambda d, b: None)       # rollback is a no-op
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "rollback" in v["detail"]


def test_a_drill_that_touches_the_real_spine_fails(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)
    real_upgrade = ud.upgrade

    def leaky_upgrade(store, **kw):
        (path.parent / "stray.jsonl").write_text("{}\n")                    # a write into the REAL home
        return real_upgrade(store, **kw)
    monkeypatch.setattr(ud, "upgrade", leaky_upgrade)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and v["source_untouched"] is False


def test_an_unexpected_error_is_a_failed_drill_not_a_crash(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("disk vanished")
    monkeypatch.setattr(ud, "upgrade", boom)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "RuntimeError" in v["detail"] and v["source_untouched"] is True


def test_corrupt_one_record_reaches_sealed_gz_segments(tmp_path):
    path = _real_spine(tmp_path, migrate=True)                               # migrated + compacted ⇒ gz
    for p in path.parent.rglob("*.jsonl"):
        if p.stat().st_size:                                                 # only sealed segments hold data
            pytest.skip("layout kept an open plaintext segment; gz path covered by the healthy test")
    assert ud.corrupt_one_record(path.parent) is True
    assert SpineStore(str(path)).verify()[0] is False


@pytest.mark.parametrize("make,rc,status", [("healthy", 0, "PASS"), ("empty", 3, "NOT-RUN"), ("bad", 1, "FAIL")])
def test_main_exit_codes(tmp_path, capsys, make, rc, status):
    if make == "empty":
        spine = tmp_path / "none" / "spine.jsonl"
    else:
        spine = _real_spine(tmp_path)
        if make == "bad":
            ud.corrupt_one_record(spine.parent)
    assert ud.main(["--spine", str(spine), "--work-dir", str(tmp_path), "--json"]) == rc
    assert json.loads(capsys.readouterr().out)["status"] == status
