"""SUB-PART 2 — staged / atomic restore for the OFFENSE plane (no stale-state overlay).

``restore_offense_backup`` now builds + re-verifies the whole restored tree in a sibling temp dir and only
then ATOMICALLY swaps it into place, and REFUSES a non-empty destination unless ``force=True``:
  * restore into a NON-EMPTY base dir (or crucible root) → refused without force;
  * a simulated mid-restore failure (re-verify raises) → the destination is UNTOUCHED (old state intact),
    never left half-written, and no staging litter survives;
  * ``force=True`` cleanly REPLACES an existing tree — stale files do NOT survive the restore.

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

from tests.test_backup_roundtrip import PW, SLUG, _seed_offense_home  # type: ignore


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


def test_restore_into_nonempty_crucible_root_is_refused_without_force(tmp_path):
    base = tmp_path / "src-base"
    croot = tmp_path / "src-crucible"
    _seed_offense_home(base)
    (croot / ".blackboard").mkdir(parents=True)
    (croot / ".blackboard" / "store.sqlite").write_bytes(b"SQLite format 3\x00stub")
    dest = tmp_path / "o.vglbk"
    create_offense_backup(dest, PW, base_dir=str(base), crucible_root=str(croot))

    new_base = tmp_path / "nb"
    new_croot = tmp_path / "nc"
    new_croot.mkdir()
    (new_croot / "stale").write_text("x")
    with pytest.raises(OffenseBackupError, match="NON-EMPTY crucible root"):
        restore_offense_backup(dest, str(new_base), PW, crucible_root=str(new_croot))
    assert (new_croot / "stale").read_text() == "x"      # untouched
    assert not (new_base / f"{SLUG}.spine").exists()     # base never written


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
