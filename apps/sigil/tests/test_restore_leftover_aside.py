"""The journaled restore's handling of an entry left at a unit's aside (``.restore-old-<name>``), unit by unit:

* a resumed swap whose destination is proven to still hold the old unit (``_old_unit_in_place``) removes the entry at
  the aside — no attempt moved the old unit, so it is a leftover, never its only old copy — and leaves the
  destination as it is (``_clear_the_way``);
* the destination NOT proven to be the old unit: the aside may hold the only old copy, so it is kept and the swap is
  refused with nothing moved (an empty dir recreated at the destination is removed instead);
* before a new journal is written, a leftover from an earlier restore at any destination's aside is removed
  (``_drop_leftover_asides``); a destination with no aside is left alone.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sigil import backup as b


def _unit(dst: Path) -> dict:
    return {"name": dst.name, "dst": str(dst), "started": True, "done": False, "old": b._entry_identity(dst)}


def test_a_proven_old_unit_in_place_has_its_leftover_aside_removed(tmp_path):
    dst = tmp_path / "floor.json"
    dst.write_text("old floor", encoding="utf-8")
    u = _unit(dst)
    aside = b._aside_of(dst)
    aside.mkdir()
    (aside / "stale").write_text("a leftover of an earlier restore", encoding="utf-8")
    b._clear_the_way(tmp_path, {"units": [u]}, u)
    assert not aside.exists()                                      # the leftover is gone ...
    assert dst.read_text(encoding="utf-8") == "old floor"          # ... and the old unit untouched


def test_an_unproven_destination_keeps_the_aside_and_refuses(tmp_path):
    dst = tmp_path / "floor.json"
    dst.write_text("old floor", encoding="utf-8")
    u = _unit(dst)
    dst.unlink()
    dst.write_text("made after the interruption", encoding="utf-8")   # not what the restore found there
    aside = b._aside_of(dst)
    aside.write_text("the only old copy", encoding="utf-8")
    with pytest.raises(b.BackupError, match="nothing was moved"):
        b._clear_the_way(tmp_path, {"units": [u]}, u)
    assert aside.read_text(encoding="utf-8") == "the only old copy"
    assert dst.read_text(encoding="utf-8") == "made after the interruption"


def test_an_empty_dir_recreated_at_the_destination_is_cleared_and_the_aside_kept(tmp_path):
    dst = tmp_path / "graph"
    dst.mkdir()
    (dst / "x").write_text("old", encoding="utf-8")
    u = _unit(dst)
    aside = b._aside_of(dst)
    dst.rename(aside)                                              # an earlier attempt moved the old unit aside
    dst.mkdir()                                                    # and an empty dir appeared after it
    b._clear_the_way(tmp_path, {"units": [u]}, u)
    assert not dst.exists() and (aside / "x").read_text(encoding="utf-8") == "old"


def test_leftover_asides_of_an_earlier_restore_are_removed_before_the_journal(tmp_path):
    a, c = tmp_path / "budgets.json", tmp_path / "qdrant"
    a.write_text("{}", encoding="utf-8")
    c.mkdir()
    b._aside_of(a).write_text("stale", encoding="utf-8")
    journal = {"units": [{"name": a.name, "dst": str(a)}, {"name": c.name, "dst": str(c)}]}
    b._drop_leftover_asides(journal)
    assert not b._aside_of(a).exists() and not b._aside_of(c).exists()
    assert a.read_text(encoding="utf-8") == "{}" and c.is_dir()
