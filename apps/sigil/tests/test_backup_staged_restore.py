"""SUB-PART 2 — staged / atomic restore for the SOVEREIGN plane (no stale-state overlay).

``restore_backup`` now builds + re-verifies the whole restored home in a sibling temp dir and only then
ATOMICALLY swaps it into place, and REFUSES a non-empty destination unless ``force=True``:
  * restore into a NON-EMPTY home → refused without force;
  * a simulated mid-restore failure (the staged spine fails re-verification) → the destination is UNTOUCHED
    (old state intact), never left half-written, and no staging litter survives;
  * ``force=True`` cleanly REPLACES an existing home — stale files do NOT survive the restore.

Run in the sovereign leg:
    PYTHONPATH=apps/sigil:packages/core/vigil_core .venv-sovereign/bin/python \
        -m pytest apps/sigil/tests/test_backup_staged_restore.py -q
"""
from __future__ import annotations

import pytest

from sigil import backup
from sigil.backup import BackupError, create_backup, restore_backup
from vigil_core.vault import Vault

from tests.test_backup import PW, _make_source, make_fake_tpm  # type: ignore


def _make_backup(tmp_path):
    src, v, owner = _make_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    return dest


def _staging_litter(parent):
    return [p for p in parent.iterdir() if p.name.startswith((".restore-staging-", ".restore-old-"))]


def test_restore_into_nonempty_home_is_refused_without_force(tmp_path):
    dest = _make_backup(tmp_path)
    new = tmp_path / "restored"
    new.mkdir()
    (new / "pre-existing.txt").write_text("do not overlay me")
    rv = Vault(tmp_path / "rv", make_fake_tpm())
    with pytest.raises(BackupError, match="NON-EMPTY home"):
        restore_backup(dest, new, PW, vault=rv)
    assert (new / "pre-existing.txt").read_text() == "do not overlay me"   # untouched
    assert not (new / "spine").exists()                                    # nothing written


def test_mid_restore_failure_leaves_the_target_not_half_written(tmp_path, monkeypatch):
    """Force the staged spine's re-verification to fail (a real code path). Because the home is built +
    verified in staging and only swapped at the very end, the existing destination keeps its complete OLD
    state — never a half-written mix — and no staging dir litters the parent."""
    dest = _make_backup(tmp_path)
    new = tmp_path / "restored"
    new.mkdir()
    (new / "OLD-STATE").write_text("the whole old home")

    import sigil.spine.store as store_mod
    monkeypatch.setattr(store_mod.SpineStore, "verify", lambda self: (False, "injected failure"))

    rv = Vault(tmp_path / "rv", make_fake_tpm())
    with pytest.raises(BackupError, match="failed verification"):
        restore_backup(dest, new, PW, vault=rv, force=True)              # force: dest is non-empty

    assert (new / "OLD-STATE").read_text() == "the whole old home"       # only the old state remains
    assert not (new / "spine").exists()                                  # nothing new leaked in
    assert _staging_litter(tmp_path) == [], "a failed restore must not leave staging/aside dirs behind"


def test_force_replaces_an_existing_home_cleanly(tmp_path):
    """--force does a clean REPLACE, not an overlay: a stale file that lived in the destination is gone after
    the restore, and the restored spine reads back the exact records."""
    dest = _make_backup(tmp_path)
    new = tmp_path / "restored"
    (new / "sub").mkdir(parents=True)
    (new / "sub" / "STALE.txt").write_text("should not survive a clean restore")
    rv = Vault(tmp_path / "rv", make_fake_tpm())

    out = restore_backup(dest, new, PW, vault=rv, force=True)
    assert out["verified"] is True
    assert not (new / "sub" / "STALE.txt").exists(), "stale files must not survive a --force restore"
    from sigil.spine.store import SpineStore
    recs = list(SpineStore(str(new / "spine" / "spine.jsonl")).iter_records())
    assert [r.payload["text"] for r in recs] == ["memory one", "memory two"]
    assert rv.read_text_secret(new / "spine" / "keys" / "owner.priv",
                               context=backup._OWNER_PRIV_CONTEXT) is not None
    assert _staging_litter(tmp_path) == [], "a successful restore must clean up its staging/aside dirs"
