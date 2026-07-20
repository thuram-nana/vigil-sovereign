"""SIGIL spine — the safe operator conversion runner (backup -> migrate -> verify -> compact -> verify).
Run: ~/.sigil/venv/bin/python -m pytest tests/test_spine_migrate_runner.py -q
"""
import tempfile
from pathlib import Path

import pytest

from sigil.spine.migrate_runner import backup_migrate_compact
from sigil.spine.store import SpineError, SpineStore


def _legacy_spine(records: int, seg_max_records: int = 20) -> tuple[Path, SpineStore]:
    d = Path(tempfile.mkdtemp(prefix="sigil-conv-"))
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=seg_max_records)
    for i in range(records):
        s.append(kind="event", source="t", actor="a", payload={"n": i, "text": "some compressible text " * 4})
    return p, s


def test_convert_preserves_every_record_and_reclaims(monkeypatch, tmp_path):
    # keep the backup inside the test's temp home
    import sigil.spine.migrate_runner as runner
    monkeypatch.setattr(runner, "SIGIL_HOME", tmp_path)
    p, s = _legacy_spine(90)
    before = SpineStore(p).count()

    rep = backup_migrate_compact(SpineStore(p, seg_max_bytes=0, seg_max_records=20))

    assert rep["ok"] and rep["migrated"] is True and rep["sealed"] is True and rep["compacted"] >= 1
    assert rep["verify_before"]["ok"] and rep["verify_after_compact"]["ok"]
    assert rep["count_after"] == before, "retain-all: every record preserved"
    assert Path(rep["backup"]).exists() and Path(rep["backup"]).suffix == ".gz"
    # the converted spine verifies + is fully readable as one contiguous chain
    fresh = SpineStore(p)
    ok, reason = fresh.verify()
    assert ok, reason
    assert [r.seq for r in fresh.iter_records()] == list(range(before))


def test_convert_is_idempotent(monkeypatch, tmp_path):
    import sigil.spine.migrate_runner as runner
    monkeypatch.setattr(runner, "SIGIL_HOME", tmp_path)
    p, _ = _legacy_spine(50)
    r1 = backup_migrate_compact(SpineStore(p, seg_max_bytes=0, seg_max_records=20))
    r2 = backup_migrate_compact(SpineStore(p, seg_max_bytes=0, seg_max_records=20))
    assert r1["migrated"] is True and r2["migrated"] is False   # already migrated
    assert r2["ok"] and r2["count_after"] == r1["count_after"]


def test_convert_refuses_a_corrupt_spine(monkeypatch, tmp_path):
    import sigil.spine.migrate_runner as runner
    monkeypatch.setattr(runner, "SIGIL_HOME", tmp_path)
    p, _ = _legacy_spine(10)
    # corrupt a record's payload text (same length -> still valid JSON, but the content no longer hashes to
    # the stored cert_digest) so verify() fails the binding check
    lines = p.read_bytes().splitlines(keepends=True)
    assert b"compressible" in lines[3]
    lines[3] = lines[3].replace(b"compressible", b"CORRUPTED123", 1)
    p.write_bytes(b"".join(lines))
    with pytest.raises(SpineError):
        backup_migrate_compact(SpineStore(p))                  # refuses to convert a non-verifying spine
