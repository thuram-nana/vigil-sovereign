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
    assert v["source_unchanged"] is True and ud._tree_digest(path.parent) == before
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
    monkeypatch.setattr(ud, "corrupt_one_record", lambda d, verify=None: False)
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
    assert v["status"] == ud.INCONCLUSIVE and v["ok"] is False and v["source_unchanged"] is False   # never green


def test_an_unexpected_error_is_a_failed_drill_not_a_crash(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("disk vanished")
    monkeypatch.setattr(ud, "upgrade", boom)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "RuntimeError" in v["detail"] and v["source_unchanged"] is True


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


# --- red-pen folds --------------------------------------------------------------------------------------

def _archive_a_segment(path):
    """Put a plaintext record file under spine/archive/segments/ (where prune's cold-archive lives, sorting
    BEFORE the live segment dir) — live verification never reads it."""
    arch = path.parent / "archive" / "segments"
    arch.mkdir(parents=True)
    line = next(ln for ln in path.read_text().splitlines() if ln.strip()) if path.exists() else \
        json.dumps({"seq": 0, "payload": {"x": 1}, "cert_digest": "00"})
    (arch / "seg-000000.jsonl").write_text(line + "\n")
    return arch


def test_an_archive_dir_is_neither_copied_nor_the_corruption_target(tmp_path):
    path = _real_spine(tmp_path)
    arch = _archive_a_segment(path)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.PASS, v                     # the negative control still bites the LIVE data
    assert not (tmp_path / "work" / "spine" / "archive").exists()       # pruned history is never copied
    assert (arch / "seg-000000.jsonl").exists()                         # and the real archive is untouched


def test_corruption_reverts_a_candidate_that_verification_does_not_read(tmp_path):
    path = _real_spine(tmp_path)
    decoy = path.parent / "aaa-decoy.jsonl"              # sorts first; not on the live verify path
    decoy.write_text(json.dumps({"seq": 0, "payload": {"d": 1}}) + "\n")
    before = decoy.read_bytes()
    assert ud.corrupt_one_record(path.parent, verify=lambda: SpineStore(str(path)).verify()) is True
    assert decoy.read_bytes() == before                   # reverted, then the real data was corrupted
    assert SpineStore(str(path)).verify()[0] is False


@pytest.mark.parametrize("where", ["inside", "around", "same"])
def test_a_work_dir_overlapping_the_real_spine_is_refused(tmp_path, where):
    path = _real_spine(tmp_path)
    before = ud._tree_digest(path.parent)
    work = {"inside": path.parent / "w", "around": tmp_path / "home", "same": path.parent}[where]
    v = ud.run_upgrade_drill(path, work)
    assert v["status"] == ud.FAIL and "overlaps the real spine" in v["detail"]
    assert ud._tree_digest(path.parent) == before and not (path.parent / "w").exists()


def test_a_copy_error_is_a_failed_verdict_not_a_traceback(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)

    def boom(*a, **k):
        raise OSError("a writer's tmp file vanished mid-copy")
    monkeypatch.setattr(ud.shutil, "copytree", boom)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "OSError" in v["detail"]


def test_an_inconsistent_snapshot_is_inconclusive_not_a_fail(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)
    digests = iter(str(i) for i in range(100))            # every digest differs ⇒ a writer never lets it settle
    monkeypatch.setattr(ud, "_tree_digest", lambda root: next(digests))
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.INCONCLUSIVE and "consistent snapshot" in v["detail"]


def test_the_snapshot_holds_a_shared_lock_on_the_writer_lockfile(tmp_path, monkeypatch):
    import fcntl
    path = _real_spine(tmp_path)
    lock = path.parent / "spine.lock"
    assert lock.exists()
    seen = []
    real = fcntl.flock

    def spy(fd, op):
        seen.append(op)
        return real(fd, op)
    monkeypatch.setattr(fcntl, "flock", spy)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.PASS and fcntl.LOCK_SH in seen


def test_a_concurrent_writer_never_yields_a_false_accusation(tmp_path):
    import threading
    path = _real_spine(tmp_path, n=40)
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            SpineStore(str(path)).append(kind="event", source="live", actor="w", payload={"live": i})
            i += 1
    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        v = ud.run_upgrade_drill(path, tmp_path / "work")
    finally:
        stop.set()
        t.join(5)
    assert v["status"] in (ud.PASS, ud.INCONCLUSIVE), v      # never FAIL-blames the drill for a live writer
    assert "investigate immediately" not in v["detail"]


def test_pass_message_is_honest_about_an_already_migrated_spine(tmp_path):
    v = ud.run_upgrade_drill(_real_spine(tmp_path, migrate=True), tmp_path / "work")
    assert v["status"] == ud.PASS and "already migrated" in v["detail"]
    v2 = ud.run_upgrade_drill(_real_spine(tmp_path / "b"), tmp_path / "work2")
    assert v2["status"] == ud.PASS and "migrated to the segment layout" in v2["detail"]


def test_main_exit_code_for_inconclusive(tmp_path, monkeypatch, capsys):
    path = _real_spine(tmp_path)
    monkeypatch.setattr(ud, "run_upgrade_drill", lambda s, w: {"status": ud.INCONCLUSIVE, "detail": "x", "steps": []})
    assert ud.main(["--spine", str(path), "--work-dir", str(tmp_path)]) == 4
