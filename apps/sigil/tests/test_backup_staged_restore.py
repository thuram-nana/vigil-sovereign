"""SUB-PART 2 — staged / atomic restore for the SOVEREIGN plane (no stale-state overlay).

``restore_backup`` builds + re-verifies the restored state in a sibling temp dir and only then swaps it into
place. The home is a strict SUBSET capture (spine/floor/security-manifest/warden), so restore is UNIT-SCOPED:
  * the force-gate fires only when a CAPTURED unit already exists — un-captured content neither blocks it nor
    requires force (``test_restore_proceeds_over_uncaptured_content_without_force``);
  * with force it replaces ONLY the captured units and PRESERVES un-captured home content (vector/config
    caches), while a stale file INSIDE a captured unit is gone
    (``test_force_replaces_captured_units_but_preserves_uncaptured``);
  * a simulated mid-restore failure (the staged spine fails re-verification) → the destination is UNTOUCHED
    (old state intact), never left half-written, and no staging litter survives.

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


def test_restore_refused_when_a_captured_unit_exists_without_force(tmp_path):
    """The force-gate is UNIT-SCOPED: a restore is refused (without force) ONLY when a CAPTURED unit (here
    ``spine``) already exists at the destination — not merely because the home is non-empty."""
    dest = _make_backup(tmp_path)
    new = tmp_path / "restored"
    (new / "spine").mkdir(parents=True)                       # a captured unit already present
    (new / "spine" / "old.jsonl").write_text("old")
    rv = Vault(tmp_path / "rv", make_fake_tpm())
    with pytest.raises(BackupError, match="existing SIGIL state"):
        restore_backup(dest, new, PW, vault=rv)
    assert (new / "spine" / "old.jsonl").read_text() == "old"   # untouched
    assert not (new / "spine" / "head.json").exists()           # nothing written


def test_restore_proceeds_over_uncaptured_content_without_force(tmp_path):
    """Un-captured home content (vector/config caches) must NEITHER block a restore NOR require --force: only a
    pre-existing CAPTURED unit forces the flag. The un-captured content survives the restore."""
    dest = _make_backup(tmp_path)
    new = tmp_path / "restored"
    (new / "vectors").mkdir(parents=True)
    (new / "vectors" / "embeddings.db").write_text("expensive cache")   # un-captured, no captured unit present
    rv = Vault(tmp_path / "rv", make_fake_tpm())
    out = restore_backup(dest, new, PW, vault=rv)               # NO force needed — no captured unit present
    assert out["verified"] is True
    assert (new / "spine" / "head.json").is_file()                       # spine restored
    assert (new / "vectors" / "embeddings.db").read_text() == "expensive cache"   # un-captured survives


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


def test_force_replaces_captured_units_but_preserves_uncaptured(tmp_path):
    """--force does a UNIT-SCOPED replace: a stale file INSIDE a captured unit (``spine/``) is gone (the unit is
    wholly replaced) and the restored spine reads back the exact records — but un-captured home content
    (vector/config caches) SURVIVES. This is the subset-capture fix: --force must not destroy live data the
    backup never captured."""
    dest = _make_backup(tmp_path)
    new = tmp_path / "restored"
    (new / "spine").mkdir(parents=True)
    (new / "spine" / "STALE.txt").write_text("inside a captured unit — must not survive")   # captured unit
    (new / "vectors").mkdir(parents=True)
    (new / "vectors" / "embeddings.db").write_text("expensive cache")                        # un-captured
    (new / "config.json").write_text('{"live":"config"}')                                    # un-captured
    rv = Vault(tmp_path / "rv", make_fake_tpm())

    out = restore_backup(dest, new, PW, vault=rv, force=True)
    assert out["verified"] is True
    # the captured unit was wholly replaced — its stale contents are gone, its records read back:
    assert not (new / "spine" / "STALE.txt").exists(), "a stale file inside a captured unit must not survive"
    from sigil.spine.store import SpineStore
    recs = list(SpineStore(str(new / "spine" / "spine.jsonl")).iter_records())
    assert [r.payload["text"] for r in recs] == ["memory one", "memory two"]
    assert rv.read_text_secret(new / "spine" / "keys" / "owner.priv",
                               context=backup._OWNER_PRIV_CONTEXT) is not None
    # un-captured home content SURVIVES the --force restore:
    assert (new / "vectors" / "embeddings.db").read_text() == "expensive cache"
    assert (new / "config.json").read_text() == '{"live":"config"}'
    assert _staging_litter(tmp_path) == [], "a successful restore must clean up its staging/aside dirs"
