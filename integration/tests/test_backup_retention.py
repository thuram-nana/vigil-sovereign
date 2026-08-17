"""A-S3 — backup retention safety (tools.backup.retention.prune).

A retention bug deletes exactly the disaster-recovery artifact you most need, so every invariant is a
negative control: never delete the newest or the sole remaining backup, only ever touch timestamp-glob dirs
(never a sibling file/dir/symlink), and no-op without an explicit policy. Pure stdlib — runs in the sovereign
leg (no framework).

Run: PYTHONPATH=integration:gateway python -m pytest integration/tests/test_backup_retention.py -q
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# tools/ is a standalone helper package at the repo root — put it on the path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.backup.retention import prune, timestamp_name   # noqa: E402


def _mk(root: Path, name: str, *, is_file: bool = False) -> Path:
    p = root / name
    if is_file:
        p.write_text("x")
    else:
        p.mkdir(parents=True)
        (p / "MANIFEST.json").write_text("{}")
    return p


def _names(paths):
    return sorted(p.name for p in paths)


def test_single_backup_is_never_pruned(tmp_path):
    _mk(tmp_path, "20260101-000000")
    assert prune(tmp_path, keep_last=1) == []
    assert prune(tmp_path, keep_days=0, keep_last=0) == []       # even an aggressive policy keeps the sole one
    assert (tmp_path / "20260101-000000").is_dir()


def test_keep_last_keeps_the_n_most_recent_and_never_zero(tmp_path):
    for d in ("20260101-000000", "20260102-000000", "20260103-000000", "20260104-000000"):
        _mk(tmp_path, d)
    deleted = prune(tmp_path, keep_last=2)
    assert _names(deleted) == ["20260101-000000", "20260102-000000"]
    assert _names(p for p in tmp_path.iterdir() if p.is_dir()) == ["20260103-000000", "20260104-000000"]


def test_keep_last_zero_still_keeps_the_newest(tmp_path):
    for d in ("20260101-000000", "20260102-000000"):
        _mk(tmp_path, d)
    deleted = prune(tmp_path, keep_last=0)
    assert _names(deleted) == ["20260101-000000"]                # the older one goes
    assert (tmp_path / "20260102-000000").is_dir()               # the NEWEST always survives


def test_keep_days_keeps_recent_and_deletes_old(tmp_path):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    recent = (now - timedelta(days=2)).strftime("%Y%m%d-%H%M%S")
    old = (now - timedelta(days=40)).strftime("%Y%m%d-%H%M%S")
    older = (now - timedelta(days=90)).strftime("%Y%m%d-%H%M%S")
    for d in (older, old, recent):
        _mk(tmp_path, d)
    deleted = prune(tmp_path, keep_days=30, now=now)
    assert _names(deleted) == sorted([older, old])
    assert (tmp_path / recent).is_dir()


def test_no_policy_is_a_noop(tmp_path):
    for d in ("20260101-000000", "20260102-000000", "20260103-000000"):
        _mk(tmp_path, d)
    assert prune(tmp_path) == []                                 # neither keep_days nor keep_last → prune nothing
    assert len([p for p in tmp_path.iterdir() if p.is_dir()]) == 3


def test_only_timestamp_dirs_are_ever_candidates(tmp_path):
    for d in ("20260101-000000", "20260102-000000", "20260103-000000"):
        _mk(tmp_path, d)
    # non-timestamp siblings that must NEVER be deleted, whatever the policy:
    _mk(tmp_path, "latest")                       # a plain dir
    _mk(tmp_path, "20260103-000000-note")         # timestamp-LIKE but not the exact glob
    _mk(tmp_path, "MANIFEST.json", is_file=True)  # a file
    _mk(tmp_path, "README", is_file=True)
    deleted = prune(tmp_path, keep_last=1)
    assert _names(deleted) == ["20260101-000000", "20260102-000000"]   # only real timestamp dirs
    for survivor in ("latest", "20260103-000000-note", "MANIFEST.json", "README", "20260103-000000"):
        assert (tmp_path / survivor).exists()


def test_dry_run_deletes_nothing(tmp_path):
    for d in ("20260101-000000", "20260102-000000", "20260103-000000"):
        _mk(tmp_path, d)
    would = prune(tmp_path, keep_last=1, dry_run=True)
    assert _names(would) == ["20260101-000000", "20260102-000000"]
    assert len([p for p in tmp_path.iterdir() if p.is_dir()]) == 3      # nothing actually removed


def test_symlinked_timestamp_dir_is_never_deleted_or_traversed(tmp_path):
    root = tmp_path / "backups"
    root.mkdir()
    for d in ("20260101-000000", "20260102-000000", "20260103-000000"):
        _mk(root, d)
    external = tmp_path / "external-data"           # a real dir OUTSIDE the backup root
    external.mkdir()
    (external / "keep").write_text("x")
    link = root / "20260100-000000"                 # a timestamp-NAMED symlink to that external dir (sorts oldest)
    link.symlink_to(external, target_is_directory=True)
    deleted = prune(root, keep_last=1)
    # the symlink is never a candidate, and its external target is never traversed/deleted through it.
    assert link.is_symlink()
    assert external.is_dir() and (external / "keep").exists()
    assert "20260100-000000" not in _names(deleted)
    assert _names(deleted) == ["20260101-000000", "20260102-000000"]


def test_timestamp_name_is_recognised_by_prune(tmp_path):
    # the name the backup CLI writes IS the name prune recognises (no format drift between writer + reaper).
    name = timestamp_name(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    assert name == "20260102-030405"
    _mk(tmp_path, name)
    _mk(tmp_path, timestamp_name(datetime(2026, 1, 3, 3, 4, 5, tzinfo=timezone.utc)))
    assert _names(prune(tmp_path, keep_last=1)) == ["20260102-030405"]
