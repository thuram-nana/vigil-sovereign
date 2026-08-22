"""SIGIL spine — the `sigil upgrade` / `vigil upgrade` data-migration orchestrator (W5-5, #449).

verify(before) -> backup -> verify(backup) -> migrate -> verify(after) -> report, ROLLING BACK to the
verified backup on ANY failure, plus the fail-closed startup gate that refuses to run on an un-migrated
store.

FAILS WITHOUT THE FIX: `sigil.spine.upgrade` does not exist on a pre-W5-5 tree, so this whole module
fails to import there (collection error). Beyond that, each behavioural test pins a property the pre-fix
tree lacks: there was no automated migrate path, no rollback, and no startup refusal.

Run: PYTHONPATH=apps/sigil python -m pytest apps/sigil/tests/test_spine_upgrade.py -q
(In CI it is auto-included by the required `SIGIL governor gates (P7 …)` job, which runs the whole
apps/sigil/tests/ directory.)
"""
import os
import signal
import tempfile
from pathlib import Path

import pytest

from sigil.spine.manifest import SpineLayout, read_manifest, segment_filename
from sigil.spine.store import SpineError, SpineStore
from sigil.spine.upgrade import (
    MigrationRequired,
    UpgradeFailed,
    assert_operable,
    migration_needed,
    restore_from_backup,
    upgrade,
    verify_backup,
)


def _legacy_store(tmp_path: Path, records: int, *, seg_max_records: int = 20) -> tuple[Path, Path]:
    """A legacy single-file spine at tmp_path/spine/spine.jsonl with `records` records. Returns
    (data_path, spine_dir). spine_dir.parent == tmp_path, so a default backup lands at tmp_path/backups
    (OUTSIDE the spine dir)."""
    spine_dir = tmp_path / "spine"
    spine_dir.mkdir(parents=True, exist_ok=True)
    p = spine_dir / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=seg_max_records)
    for i in range(records):
        s.append(kind="event", source="t", actor="a",
                 payload={"n": i, "text": "some compressible text " * 4})
    assert read_manifest(s._layout) is None, "precondition: a legacy (un-migrated) store"
    return p, spine_dir


# ----------------------------------------------------------------------------------------------------
# happy path
# ----------------------------------------------------------------------------------------------------
def test_upgrade_happy_path_migrates_verifies_and_preserves_every_record(tmp_path):
    p, spine_dir = _legacy_store(tmp_path, 90)
    before = SpineStore(p).count()

    # migration is needed BEFORE and not needed AFTER (round-trip on the same detector the gate uses)
    needed, reason = migration_needed(SpineStore(p))
    assert needed and "legacy" in reason.lower()

    rep = upgrade(SpineStore(p, seg_max_bytes=0, seg_max_records=20),
                  backup_dir=tmp_path / "backups")

    assert rep["ok"] is True and rep["rolled_back"] is False
    assert rep["migrated"] is True and rep["sealed"] is True and rep["compacted"] >= 1
    assert rep["verify_before"]["ok"] and rep["verify_after"]["ok"]
    assert rep["verify_backup"]["ok"] and rep["verify_backup"]["count"] == before
    assert rep["count_after"] == before, "retain-all: every record preserved"

    backup = Path(rep["backup"])
    assert backup.exists() and backup.suffix == ".gz"
    assert spine_dir.resolve() not in backup.resolve().parents, "backup must live OUTSIDE the spine dir"

    fresh = SpineStore(p)
    ok, why = fresh.verify()
    assert ok, why
    assert read_manifest(fresh._layout) is not None, "the store is now migrated (segment layout)"
    assert [r.seq for r in fresh.iter_records()] == list(range(before))
    assert migration_needed(SpineStore(p))[0] is False


def test_upgrade_is_idempotent(tmp_path):
    p, _ = _legacy_store(tmp_path, 40)
    r1 = upgrade(SpineStore(p, seg_max_bytes=0, seg_max_records=20), backup_dir=tmp_path / "backups")
    r2 = upgrade(SpineStore(p, seg_max_bytes=0, seg_max_records=20), backup_dir=tmp_path / "backups")
    assert r1["migrated"] is True and r2["migrated"] is False   # already migrated on the re-run
    assert r2["ok"] and r2["count_after"] == r1["count_after"]


# ----------------------------------------------------------------------------------------------------
# ROLLBACK on a mid-migration failure (the core new safety property)
# ----------------------------------------------------------------------------------------------------
def test_upgrade_rolls_back_to_the_verified_backup_on_a_midmigration_failure(tmp_path, monkeypatch):
    p, spine_dir = _legacy_store(tmp_path, 60)
    before = SpineStore(p).count()

    # Inject a failure AFTER migrate + seal have completed (the hardest case: the store is ALREADY in the
    # segment layout, and the rollback must undo a COMPLETED migration back to the verified legacy backup).
    def _boom(self):
        raise RuntimeError("simulated crash during compaction")
    monkeypatch.setattr(SpineStore, "compact", _boom)

    with pytest.raises(UpgradeFailed) as ei:
        upgrade(SpineStore(p, seg_max_bytes=0, seg_max_records=20), backup_dir=tmp_path / "backups")

    rep = ei.value.report
    assert rep["rolled_back"] is True
    assert rep["rollback_verified"] is True, rep
    assert rep["ok"] is False

    # the store is RESTORED: verifies, every record preserved, and BACK to the legacy layout (the
    # completed migration was undone — never a half-migrated store).
    restored = SpineStore(p)
    ok, why = restored.verify()
    assert ok, why
    assert restored.count() == before
    assert read_manifest(restored._layout) is None, "rolled back to the pre-migration (legacy) layout"
    assert [r.seq for r in restored.iter_records()] == list(range(before))


def test_upgrade_rolls_back_on_a_record_count_change(tmp_path, monkeypatch):
    # A migration that LOSES a record (retain-all violation) must roll back, not commit.
    p, _ = _legacy_store(tmp_path, 30)
    before = SpineStore(p).count()

    real_count = SpineStore.count

    def _short_count(self):
        # make the FINAL post-compact count read one short, so the retain-all guard trips
        n = real_count(self)
        return n - 1 if read_manifest(self._layout) is not None else n
    monkeypatch.setattr(SpineStore, "count", _short_count)

    with pytest.raises(UpgradeFailed):
        upgrade(SpineStore(p, seg_max_bytes=0, seg_max_records=20), backup_dir=tmp_path / "backups")

    monkeypatch.undo()
    restored = SpineStore(p)
    ok, why = restored.verify()
    assert ok and restored.count() == before
    assert read_manifest(restored._layout) is None


# ----------------------------------------------------------------------------------------------------
# KILL-DURING-MIGRATE — a real SIGKILL at the migrate crash window leaves a RESTORABLE state
# ----------------------------------------------------------------------------------------------------
def test_kill_during_migrate_leaves_a_restorable_state(tmp_path):
    """Negative control for acceptance criterion 3: an upgrade interrupted MID-migration leaves a
    restorable state. We take + verify the backup (as the orchestrator does), then a forked child performs
    the DURABLE half of migrate() (rename spine.jsonl -> seg-0) and is SIGKILL'd BEFORE the manifest is
    written — the exact real crash window. We then assert the state is restorable BOTH ways:
    (a) the verified backup restores cleanly, and (b) a fresh SpineStore auto-reconciles the orphan."""
    p, spine_dir = _legacy_store(tmp_path, 25)
    before = SpineStore(p).count()

    # the orchestrator's frame: a taken + VERIFIED backup exists before the crash.
    from sigil.spine.upgrade import _backup_spine_dir
    backup = _backup_spine_dir(spine_dir, tmp_path / "backups")
    bok, breason, bcount = verify_backup(backup, "spine.jsonl", expect_count=before)
    assert bok and bcount == before, breason

    pid = os.fork()
    if pid == 0:  # child: crash mid-migrate
        try:
            layout = SpineLayout.for_path(str(p))
            layout.segments_dir.mkdir(parents=True, exist_ok=True)
            seg0 = layout.segments_dir / segment_filename(0)
            os.replace(str(layout.data_path), str(seg0))   # the durable half of migrate()
            # crash HERE — before write_manifest: seg-0 present, spine.jsonl gone, NO manifest
            os.kill(os.getpid(), signal.SIGKILL)
        except BaseException:
            os._exit(1)
        os._exit(2)  # unreachable if the SIGKILL landed
    _, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL, \
        "the child must have been killed mid-migrate (before the manifest write)"

    # the on-disk state is the mid-migrate crash: seg-0 present, spine.jsonl gone, no manifest.
    assert (spine_dir / "spine.segments" / segment_filename(0)).exists()
    assert not p.exists()
    assert not (spine_dir / "spine.manifest.json").exists()

    # (b) a fresh SpineStore auto-reconciles the orphaned migration and reads every record.
    reconciled = SpineStore(p)
    ok, why = reconciled.verify()
    assert ok, why
    assert reconciled.count() == before
    assert [r.seq for r in reconciled.iter_records()] == list(range(before))

    # (a) the verified backup restores cleanly over whatever state is on disk.
    restore_from_backup(spine_dir, backup)
    restored = SpineStore(p)
    ok, why = restored.verify()
    assert ok, why
    assert restored.count() == before
    assert [r.seq for r in restored.iter_records()] == list(range(before))


def test_restore_never_leaves_no_spine_dir_when_the_backup_is_bad(tmp_path):
    # rollback robustness: if the extract fails, the original dir is put back (never NO spine dir).
    p, spine_dir = _legacy_store(tmp_path, 10)
    bad = tmp_path / "not-a-real.tar.gz"
    bad.write_bytes(b"garbage, not a gzip tar")
    with pytest.raises(Exception):
        restore_from_backup(spine_dir, bad)
    assert spine_dir.exists() and p.exists(), "the original spine dir must survive a failed restore"
    ok, _ = SpineStore(p).verify()
    assert ok


# ----------------------------------------------------------------------------------------------------
# fail-closed refusals (negative controls: a bad state is REJECTED before any mutation)
# ----------------------------------------------------------------------------------------------------
def test_upgrade_refuses_a_non_verifying_spine_without_mutating(tmp_path):
    p, spine_dir = _legacy_store(tmp_path, 10)
    # corrupt a record's payload (same length -> valid JSON, but no longer hashes to its cert_digest)
    lines = p.read_bytes().splitlines(keepends=True)
    assert b"compressible" in lines[3]
    lines[3] = lines[3].replace(b"compressible", b"CORRUPTED123", 1)
    p.write_bytes(b"".join(lines))

    with pytest.raises(SpineError) as ei:
        upgrade(SpineStore(p), backup_dir=tmp_path / "backups")
    assert "does not verify" in str(ei.value)
    # nothing mutated: still legacy, no segment layout produced
    assert read_manifest(SpineStore(p)._layout) is None
    assert not (spine_dir / "spine.segments").exists()


def test_upgrade_refuses_when_the_backup_is_not_restorable(tmp_path, monkeypatch):
    p, spine_dir = _legacy_store(tmp_path, 10)
    import sigil.spine.upgrade as up
    monkeypatch.setattr(up, "verify_backup", lambda *a, **k: (False, "simulated unrestorable backup", -1))

    with pytest.raises(SpineError) as ei:
        upgrade(SpineStore(p), backup_dir=tmp_path / "backups")
    assert "not restorable" in str(ei.value)
    # refused BEFORE any migration: still legacy
    assert read_manifest(SpineStore(p)._layout) is None
    assert not (spine_dir / "spine.segments").exists()


def test_verify_backup_rejects_a_count_mismatch(tmp_path):
    # negative control on the backup verifier itself: a wrong expected count fails closed.
    p, spine_dir = _legacy_store(tmp_path, 12)
    from sigil.spine.upgrade import _backup_spine_dir
    backup = _backup_spine_dir(spine_dir, tmp_path / "backups")
    ok, reason, count = verify_backup(backup, "spine.jsonl", expect_count=999)
    assert ok is False and "count" in reason and count == 12


# ----------------------------------------------------------------------------------------------------
# startup gate — refuse to run degraded, name the fix command
# ----------------------------------------------------------------------------------------------------
def test_migration_needed_detects_legacy_with_data_only(tmp_path):
    # legacy with data -> needed
    p, _ = _legacy_store(tmp_path, 5)
    assert migration_needed(SpineStore(p))[0] is True
    # migrated -> NOT needed (negative control: the gate is not a constant-True no-op)
    upgrade(SpineStore(p), backup_dir=tmp_path / "backups")
    assert migration_needed(SpineStore(p))[0] is False
    # a fresh/empty legacy store (never written) -> NOT needed
    fresh = tmp_path / "fresh" / "spine.jsonl"
    assert migration_needed(SpineStore(fresh))[0] is False


def test_assert_operable_raises_and_names_the_command_on_a_legacy_store(tmp_path):
    p, _ = _legacy_store(tmp_path, 3)
    with pytest.raises(MigrationRequired) as ei:
        assert_operable(SpineStore(p))
    msg = str(ei.value)
    assert "vigil upgrade" in msg and "sigil upgrade" in msg
    # negative control: a migrated store is operable (no raise)
    upgrade(SpineStore(p), backup_dir=tmp_path / "backups")
    assert_operable(SpineStore(p))  # must not raise


def test_cli_startup_gate_refuses_non_exempt_and_allows_exempt(monkeypatch):
    """The `sigil` CLI startup gate (`_assert_store_operable_or_exit`) refuses a normal command when a
    migration is needed (exit 3, names the command) and EXEMPTS the recovery commands so the fix is
    always reachable. Wiring is tested with a stubbed detector, so it touches no real default store."""
    from sigil import cli
    import sigil.spine.upgrade as up

    def _needs(_store=None):
        raise up.MigrationRequired("the spine is in the LEGACY layout — run `vigil upgrade`")
    monkeypatch.setattr(up, "assert_operable", _needs)

    # a normal command refuses with exit 3
    with pytest.raises(SystemExit) as ei:
        cli._assert_store_operable_or_exit("search")
    assert ei.value.code == 3

    # the recovery commands are exempt (do not even consult the detector)
    for exempt in ("upgrade", "spine", "doctor", "restore", "backup"):
        cli._assert_store_operable_or_exit(exempt)   # must not raise


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
