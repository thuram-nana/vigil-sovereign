"""SUB-PART 2 — staged / atomic restore for the OFFENSE plane (no stale-state overlay).

``restore_offense_backup`` builds + re-verifies the restored state in a sibling temp dir and only then swaps
it into place, refusing to overwrite existing state unless ``force=True``:
  * base_dir is a WHOLE-tree capture → a non-empty base is refused without force; with force it whole-replaces;
  * crucible_root is a strict SUBSET capture → the force-gate fires only when a captured proof unit already
    exists, and restore replaces ONLY those units (proof-db + runs), NEVER deleting un-captured data there (the
    CRUCIBLE code) — even under ``--force`` (the red-pen BLOCK-1 fix, exercised by
    ``test_force_crucible_restore_preserves_uncaptured_code``);
  * a simulated mid-restore failure (re-verify raises) → the destination is UNTOUCHED (old state intact),
    never left half-written, and no staging litter survives.

Run in the offense leg:
    PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core .venv-offense/bin/python \
        -m pytest integration/tests/test_backup_staged_restore.py -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.cli")

import vigil_integration.backup as bk
from vigil_integration.backup import (
    OffenseBackupError,
    create_offense_backup,
    restore_offense_backup,
)
from vigil_integration.live.spine_identity import DEFAULT_SPINE_KEY_FILE

from test_backup_roundtrip import PW, SLUG, _seed_offense_home  # type: ignore


def _make_backup(tmp_path: Path) -> Path:
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    dest = tmp_path / "o.vglbk"
    create_offense_backup(dest, PW, base_dir=str(base))
    return dest


def test_restore_into_nonempty_base_is_refused_without_force(tmp_path):
    dest = _make_backup(tmp_path)
    new_base = tmp_path / "nb"
    new_base.mkdir()
    (new_base / "pre-existing.txt").write_text("do not overlay me")
    with pytest.raises(OffenseBackupError, match="NON-EMPTY base dir"):
        restore_offense_backup(dest, str(new_base), PW)
    # the guard fired BEFORE anything was written — the pre-existing file is untouched, no spine landed.
    assert (new_base / "pre-existing.txt").read_text() == "do not overlay me"
    assert not (new_base / f"{SLUG}.spine").exists()


def _make_crucible_backup(tmp_path):
    """A backup carrying BOTH crucible units: the proof-db (``.blackboard/store.sqlite``) and a runs file
    (``.console/runs/r1/report.json``). Returns (dest, base)."""
    base = tmp_path / "src-base"
    croot = tmp_path / "src-crucible"
    _seed_offense_home(base)
    (croot / ".blackboard").mkdir(parents=True)
    (croot / ".blackboard" / "store.sqlite").write_bytes(b"SQLite format 3\x00NEW-DB")
    (croot / ".console" / "runs" / "r1").mkdir(parents=True)
    (croot / ".console" / "runs" / "r1" / "report.json").write_text('{"run":"NEW"}')
    dest = tmp_path / "o.vglbk"
    create_offense_backup(dest, PW, base_dir=str(base), crucible_root=str(croot))
    return dest, base


def test_restore_refused_when_a_captured_crucible_unit_exists_without_force(tmp_path):
    """The crucible force-gate is UNIT-SCOPED: a restore is refused (without force) ONLY when a CAPTURED proof
    unit already exists at the destination — not merely because the crucible root is non-empty."""
    dest, _base = _make_crucible_backup(tmp_path)
    new_base = tmp_path / "nb"
    new_croot = tmp_path / "nc"
    (new_croot / ".blackboard").mkdir(parents=True)
    (new_croot / ".blackboard" / "store.sqlite").write_bytes(b"SQLite format 3\x00OLD-DB")   # a captured unit
    with pytest.raises(OffenseBackupError, match="live CRUCIBLE proof state"):
        restore_offense_backup(dest, str(new_base), PW, crucible_root=str(new_croot))
    assert (new_croot / ".blackboard" / "store.sqlite").read_bytes().endswith(b"OLD-DB")   # untouched
    assert not (new_base / f"{SLUG}.spine").exists()      # base never written


def test_force_crucible_restore_preserves_uncaptured_code(tmp_path):
    """THE make-or-break negative control (red-pen BLOCK-1): the crucible capture is a strict SUBSET, so a
    --force restore must replace ONLY the captured units (proof-db + runs) and NEVER delete live, un-captured
    data under the crucible root — in a dev checkout that root is the CRUCIBLE codebase itself."""
    dest, _base = _make_crucible_backup(tmp_path)
    new_base = tmp_path / "nb"
    new_croot = tmp_path / "nc"
    # the destination crucible root holds LIVE, never-backed-up data (framework code + config) alongside OLD
    # captured units that SHOULD be replaced.
    (new_croot / ".blackboard").mkdir(parents=True)
    (new_croot / ".blackboard" / "store.sqlite").write_bytes(b"SQLite format 3\x00OLD-DB")
    (new_croot / ".blackboard" / "store.sqlite-wal").write_bytes(b"stale-wal-of-old-db")   # orphaned sidecar
    (new_croot / ".console").mkdir(parents=True)
    (new_croot / ".console" / "config.json").write_text('{"live":"config"}')               # un-captured
    (new_croot / ".console" / "runs" / "oldrun").mkdir(parents=True)
    (new_croot / ".console" / "runs" / "oldrun" / "x").write_text("old run")
    (new_croot / "framework_code.py").write_text("# the CRUCIBLE engine — must NOT be deleted")
    (new_croot / "pkg").mkdir()
    (new_croot / "pkg" / "keep.txt").write_text("live source tree")

    res = restore_offense_backup(dest, str(new_base), PW, crucible_root=str(new_croot), force=True)
    assert res["verified"] is True
    # captured units REPLACED with the backed-up versions:
    assert (new_croot / ".blackboard" / "store.sqlite").read_bytes().endswith(b"NEW-DB")
    assert (new_croot / ".console" / "runs" / "r1" / "report.json").read_text() == '{"run":"NEW"}'
    assert not (new_croot / ".console" / "runs" / "oldrun").exists()   # runs subtree wholly replaced (DR snapshot)
    assert not (new_croot / ".blackboard" / "store.sqlite-wal").exists()   # orphaned sidecar of the old db dropped
    # un-captured LIVE data SURVIVES — the whole point of the fix:
    assert (new_croot / "framework_code.py").read_text().startswith("# the CRUCIBLE engine")
    assert (new_croot / "pkg" / "keep.txt").read_text() == "live source tree"
    assert (new_croot / ".console" / "config.json").read_text() == '{"live":"config"}'
    assert _staging_litter(tmp_path) == []


def _staging_litter(parent: Path) -> list[Path]:
    return [p for p in parent.iterdir() if p.name.startswith((".restore-staging-", ".restore-old-"))]


def test_mid_restore_failure_leaves_the_target_not_half_written(tmp_path, monkeypatch):
    """Inject a failure at the LAST step before the swap (re-verify raises). Because the tree is built +
    verified in staging and only swapped at the end, the existing destination is left as its complete OLD
    state — never a half-written mix — and no staging dir litters the parent."""
    dest = _make_backup(tmp_path)
    new_base = tmp_path / "nb"
    new_base.mkdir()
    (new_base / "OLD-STATE").write_text("the whole old home")

    def _boom(*a, **k):
        raise OffenseBackupError("simulated mid-restore failure (post-stage, pre-swap)")

    monkeypatch.setattr(bk, "_reverify_restored", _boom)
    with pytest.raises(OffenseBackupError, match="simulated mid-restore failure"):
        restore_offense_backup(dest, str(new_base), PW, force=True)     # force: dest is non-empty

    # the destination still holds ONLY the old state — nothing new leaked in, nothing was half-written.
    assert (new_base / "OLD-STATE").read_text() == "the whole old home"
    assert not (new_base / f"{SLUG}.spine").exists()
    assert _staging_litter(tmp_path) == [], "a failed restore must not leave staging/aside dirs behind"


def test_force_replaces_an_existing_tree_cleanly(tmp_path):
    """--force does a clean REPLACE, not an overlay: a stale file that lived in the destination is gone after
    the restore, and the restored spine is present. Proves the fix for the 'overlay stale state' bug."""
    dest = _make_backup(tmp_path)
    new_base = tmp_path / "nb"
    (new_base / "sub").mkdir(parents=True)
    (new_base / "sub" / "STALE.txt").write_text("should not survive a clean restore")

    res = restore_offense_backup(dest, str(new_base), PW, force=True)
    assert res["verified"] is True
    assert not (new_base / "sub" / "STALE.txt").exists(), "stale files must not survive a --force restore"
    assert (new_base / f"{SLUG}.spine").is_file()
    assert (new_base / DEFAULT_SPINE_KEY_FILE).is_file()
    assert _staging_litter(tmp_path) == [], "a successful restore must clean up its staging/aside dirs"
