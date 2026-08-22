"""Regression for #552 — a manifest-ABSENT segmented spine must fail CLOSED, never read a short chain.

The defect (pre-existing, fail-OPEN): a segmented spine whose `spine.manifest.json` is removed used to be
read as if it were a legacy (pre-migrate) single-file spine. The resolver's first attempt saw "no manifest"
and fell back to the legacy single file (and the orphan-migration reconciler auto-published a seg-0-only
manifest), so a genesis-rooted survivor segment was read as the WHOLE log — a SILENT SHORT CHAIN that even
`verify()` could not catch (invariant 15 forbids exactly this: a reader must RAISE on genuine loss, never
report a healthy shorter log).

The fix is READ-PATH ONLY and DETECTS the ambiguous/lossy state from ON-DISK EVIDENCE: a genuine legacy
single-file spine has NO segment artifacts, whereas a manifest-removed segmented spine HAS `seg-*` files but
NO manifest. Every read entry point that could return a short chain routes through the same resolver guard,
so all of verify()/count()/entries()/tail()/iter_records()/get() fail closed.

Run:
  SIGIL_HOME=$(mktemp -d) PYTHONPATH=packages/core/vigil_core:apps/sigil:integration \
    /home/kali/vigil/.venv-sovereign/bin/python -m pytest -q \
    apps/sigil/tests/test_spine_manifest_absent_guard.py
"""
import json
import tempfile
from pathlib import Path

import pytest

from sigil.reuse.chain import _GENESIS_PREV
from sigil.spine.manifest import Manifest, Segment, SpineLayout, write_manifest
from sigil.spine.store import SpineError, SpineStore


def _fresh_dir(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def _append_n(store: SpineStore, n: int) -> None:
    for i in range(n):
        store.append(kind="event", source="t", actor="u", payload={"n": i})


def _make_segmented(d: Path, seg_counts: list[int]) -> SpineLayout:
    """Build a real single chain of sum(seg_counts) records, then physically lay it out as
    len(seg_counts) segments (the last is the ACTIVE) with a valid manifest — the exact shape rotation
    produces. Every seam is contiguous because the records were ONE chain before the split."""
    p = d / "spine.jsonl"
    s = SpineStore(p)
    _append_n(s, sum(seg_counts))
    lay = SpineLayout.for_path(p)
    lines = [ln for ln in p.read_bytes().splitlines(keepends=True) if ln.strip()]
    recs = [json.loads(ln) for ln in lines]
    assert len(recs) == sum(seg_counts)
    lay.segments_dir.mkdir(parents=True, exist_ok=True)
    segments, idx, prev_boundary, prev_seq = [], 0, _GENESIS_PREV, -1
    for seg_id, cnt in enumerate(seg_counts):
        seg_lines, seg_recs = lines[idx:idx + cnt], recs[idx:idx + cnt]
        (lay.segments_dir / f"seg-{seg_id:08d}.jsonl").write_bytes(b"".join(seg_lines))
        is_last = seg_id == len(seg_counts) - 1
        first_seq = seg_recs[0]["seq"] if seg_recs else prev_seq + 1
        segments.append(Segment(
            id=seg_id, file=f"{lay.segments_dir.name}/seg-{seg_id:08d}.jsonl", codec="none",
            sealed=not is_last, first_seq=first_seq,
            last_seq=None if is_last else seg_recs[-1]["seq"],
            count=None if is_last else cnt,
            first_prev_hash=prev_boundary,
            boundary_hash=None if is_last else seg_recs[-1]["entry_hash"],
        ))
        if seg_recs:
            prev_boundary, prev_seq = seg_recs[-1]["entry_hash"], seg_recs[-1]["seq"]
        idx += cnt
    p.unlink()                                             # the legacy file is now split into segments
    write_manifest(lay, Manifest(generation=1, scope="", segments=segments))
    return lay


def _assert_all_reads_raise(s: SpineStore) -> None:
    """Every read entry point that could return a short chain MUST fail closed (SpineError), not silently
    return the surviving-segment prefix."""
    with pytest.raises(SpineError):
        s.verify()
    with pytest.raises(SpineError):
        s.count()
    with pytest.raises(SpineError):
        s.entries()
    with pytest.raises(SpineError):
        s.tail(3)
    with pytest.raises(SpineError):
        list(s.iter_records())                             # generator — consume it to trigger resolution
    with pytest.raises(SpineError):
        s.get(0)                                           # even a point read of a surviving seq fails closed


def test_manifest_absent_segmented_raises_on_every_read():
    """(1) A segmented spine with its manifest REMOVED raises on verify/count/entries/tail/iter_records/get
    — a silent short read is refused. On a tree WITHOUT the fix this FAILS: the orphan reconciler
    auto-publishes a seg-0-only manifest and every read silently returns just the 3 seg-0 records."""
    d = _fresh_dir("sigil-mabsent-")
    lay = _make_segmented(d, [3, 4, 2])                    # seg-0(0-2) seg-1(3-6) sealed; seg-2(7-8) active
    assert lay.manifest_path.exists()
    lay.manifest_path.unlink()                             # attacker/corruption removes ONLY the manifest
    # segment artifacts survive on disk — this is the manifest-REMOVED segmented state, NOT legacy.
    assert len([p for p in lay.segments_dir.iterdir() if p.name.startswith("seg-")]) == 3

    s = SpineStore(d / "spine.jsonl")                      # construction must not resurrect a short manifest
    assert not lay.manifest_path.exists(), "read-path fix must NOT auto-repair/recreate the manifest"
    _assert_all_reads_raise(s)
    # And it stayed read-only: no manifest, no spine.jsonl resurrected, all 3 segment files intact.
    assert not lay.manifest_path.exists()
    assert not (d / "spine.jsonl").exists()
    assert len([p for p in lay.segments_dir.iterdir() if p.name.startswith("seg-")]) == 3


def test_legacy_single_file_still_reads_clean():
    """(2a) NEGATIVE CONTROL: a genuine legacy (pre-migrate) single-file spine — no segments dir, no
    manifest — must still read and verify cleanly (no false raise)."""
    d = _fresh_dir("sigil-legacy-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    _append_n(s, 5)
    lay = SpineLayout.for_path(p)
    assert not lay.manifest_path.exists()                  # never migrated
    assert not lay.segments_dir.exists()                   # no segment artifacts at all

    s2 = SpineStore(p)                                     # fresh reader
    ok, reason = s2.verify()
    assert ok, reason
    assert s2.count() == 5
    assert [r.seq for r in s2.iter_records()] == [0, 1, 2, 3, 4]
    assert s2.get(2) is not None and s2.get(2).seq == 2
    assert [r.seq for r in s2.tail(3)] == [2, 3, 4]
    assert len(s2.entries()) == 5


def test_manifest_present_segmented_reads_full_chain():
    """(2b) NEGATIVE CONTROL: a normal manifest-PRESENT segmented spine reads the FULL chain across all
    segments (the guard must not touch the healthy case)."""
    d = _fresh_dir("sigil-present-")
    _make_segmented(d, [3, 4, 2])                          # 9 records across 3 segments
    s = SpineStore(d / "spine.jsonl")
    ok, reason = s.verify()
    assert ok, reason
    assert s.count() == 9
    assert [r.seq for r in s.iter_records()] == list(range(9))
    assert [r.seq for r in s.tail(9)] == list(range(9))
    assert s.get(8) is not None and s.get(8).seq == 8
    assert len(s.entries()) == 9


def test_manifest_absent_single_segment_orphan_migration_completes():
    """A genuine INTERRUPTED single-file migration (exactly seg-0, spine.jsonl gone, no manifest) is still
    reconciled at construction and reads cleanly — the guard fires ONLY when segment files beyond seg-0
    exist, so this legitimate crash-recovery path is unaffected."""
    d = _fresh_dir("sigil-orphan-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    _append_n(s, 4)
    lay = SpineLayout.for_path(p)
    # Simulate the migrate() crash window: rename spine.jsonl -> seg-0, NO manifest published yet.
    lay.segments_dir.mkdir(parents=True, exist_ok=True)
    (lay.segments_dir / "seg-00000000.jsonl").write_bytes(p.read_bytes())
    p.unlink()
    assert not lay.manifest_path.exists()

    s2 = SpineStore(p)                                     # reconciler completes the interrupted migration
    assert lay.manifest_path.exists()                      # exactly-seg-0 orphan IS legitimately completed
    ok, reason = s2.verify()
    assert ok, reason
    assert s2.count() == 4
