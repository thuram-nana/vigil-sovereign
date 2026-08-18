"""SIGIL spine segment rotation — Slice 0: manifest + path-stable lockfile + split-brain-safe migration.

Slice 0 introduces the layout (manifest.json, spine.lock, segments/) and an EXPLICIT `migrate()`, but
keeps behavior byte-identical until then: with no manifest the store reads/writes the legacy single file
in place. These tests pin the Slice-0 invariants:
  - a legacy store is byte-identical (no manifest / segments dir created; data stays in spine.jsonl);
  - the in-process RLock is keyed on the STABLE store.path and survives a migration (invariant 14 — the
    lock `envelope.consume` shares with `append` is the same object across a rotation);
  - migrate() renames spine.jsonl → segments/seg-00000000.jsonl (O(1)) + publishes a manifest, preserving
    the chain, next_seq, and verify();
  - a STALE appender constructed before a concurrent migrate() re-resolves the active segment under the
    lock and never resurrects spine.jsonl (the split-brain the two-step migration guards against).
Run: ~/.sigil/venv/bin/python -m pytest tests/test_spine_rotation.py -q
"""
import gzip
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path

from sigil.reuse.chain import _GENESIS_PREV
from sigil.spine.manifest import Manifest, Segment, read_manifest, write_manifest, SpineLayout
from sigil.spine.store import SpineError, SpineStore, spine_lock


def _fresh_dir(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def _append_n(store: SpineStore, n: int, start: int = 0) -> None:
    for i in range(start, start + n):
        store.append(kind="event", source="t", actor="u", payload={"n": i})


def _make_segmented(d: Path, seg_counts: list[int]) -> SpineLayout:
    """Build a real chain of sum(seg_counts) records, then physically lay it out as len(seg_counts)
    segments (the last is the ACTIVE) with a valid manifest — a genuine multi-segment spine of exactly the
    shape Slice 3's rotation will produce. The chain spans every seam (each segment's first record's
    prev_hash == the prior segment's last entry_hash), because the records were ONE chain before the split."""
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
        first_seq = seg_recs[0]["seq"] if seg_recs else prev_seq + 1   # empty active -> next seq after boundary
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


def test_reads_span_multiple_segments():
    d = _fresh_dir("sigil-span-")
    _make_segmented(d, [3, 4, 2])                          # seg-0(seq0-2) seg-1(seq3-6) sealed; seg-2(seq7-8) active
    p = d / "spine.jsonl"
    s = SpineStore(p)

    ok, reason = s.verify()
    assert ok, reason                                      # verify_chain spans all 3 segments from genesis
    assert s.count() == 9
    assert [r.seq for r in s.iter_records()] == list(range(9))
    for seq in range(9):                                   # get() resolves a seq in EVERY segment
        assert s.get(seq) is not None and s.get(seq).payload["n"] == seq
    assert [r.seq for r in s.iter_records(since_seq=2)] == [3, 4, 5, 6, 7, 8]   # seeks past seg-0
    assert [r.seq for r in s.iter_records(since_seq=6)] == [7, 8]               # into the active
    assert [r.seq for r in s.tail(5)] == [4, 5, 6, 7, 8]   # tail() spans the seg-1→seg-2 seam (B3)
    assert s.next_seq == 9                                 # tip from the active segment

    s.append(kind="event", source="t", actor="u", payload={"n": 9})   # append continues across the last seam
    fresh = SpineStore(p)
    ok, reason = fresh.verify()
    assert ok, reason
    assert [r.seq for r in fresh.iter_records()] == list(range(10))


def test_missing_referenced_segment_raises():
    import pytest
    d = _fresh_dir("sigil-missing-")
    lay = _make_segmented(d, [3, 2])
    (lay.segments_dir / "seg-00000000.jsonl").unlink()     # a sealed segment vanishes → fail closed
    s = SpineStore(d / "spine.jsonl")
    with pytest.raises(SpineError):
        list(s.iter_records())
    with pytest.raises(SpineError):
        s.verify()


def test_empty_active_seam_no_seq0_fork():
    """A rotated (non-genesis) active segment that is EMPTY must seed its first append from the prior
    sealed segment's boundary — NOT build_chain from genesis (which would fork the chain at seq 0)."""
    d = _fresh_dir("sigil-seam-")
    lay = _make_segmented(d, [4, 0])                       # seg-0 sealed (seq0-3); seg-1 active but EMPTY
    p = d / "spine.jsonl"
    s = SpineStore(p)
    assert s.next_seq == 4, "tip resolves across the empty active to the sealed boundary"
    s.append(kind="event", source="t", actor="u", payload={"n": 4})   # must become seq 4, prev=seg-0 boundary
    ok, reason = SpineStore(p).verify()
    assert ok, reason
    assert [r.seq for r in SpineStore(p).iter_records()] == [0, 1, 2, 3, 4], "no seq-0 fork across the seam"


def test_end_to_end_migrate_rotate_compact_transparency():
    """Acceptance: the whole pipeline (migrate -> auto-rotate -> compact) preserves integrity and keeps a
    security-critical full-scan consumer transparent — a kill-switch engage buried in an early, now
    GZIP-COMPRESSED segment is still reconstructed as engaged, and verify()/count()/the contiguous chain
    all hold across the mixed gz+plaintext segment set. Retain-all: entry count == records appended."""
    from sigil.governor.killswitch import KillSwitch

    d = _fresh_dir("sigil-e2e-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=10)
    s.migrate()
    _append_n(s, 5)
    KillSwitch(s).engage(by="owner", reason="e2e")     # seq 5 — buried in seg-0
    _append_n(s, 44, start=6)                           # seq 6..49 — rotates several times
    assert len(s.segment_info()) >= 4, "the spine rotated into several segments"
    assert s.compact() >= 3                             # gzip the sealed segments (incl. the engage's)

    fresh = SpineStore(p)
    ok, reason = fresh.verify()
    assert ok, reason                                   # verify_chain spans gz + plaintext from genesis
    assert fresh.count() == 50
    assert [r.seq for r in fresh.iter_records()] == list(range(50))
    assert KillSwitch(SpineStore(p)).is_engaged() is True, "engage in a gz segment reconstructs across compaction"

    # rotation + compaction keep working after, and the chain stays contiguous
    more = SpineStore(p, seg_max_bytes=0, seg_max_records=10)
    _append_n(more, 20, start=50)
    more.compact()
    ok, reason = SpineStore(p).verify()
    assert ok, reason
    assert SpineStore(p).count() == 70 and SpineStore(p).next_seq == 70


def test_legacy_store_is_byte_identical():
    """No manifest ⇒ active target IS the legacy single file; no manifest/segments artifacts appear."""
    d = _fresh_dir("sigil-legacy-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    _append_n(s, 4)
    lay = SpineLayout.for_path(p)
    assert s._active == p, "legacy store must append/read in place at spine.jsonl"
    assert p.exists()
    assert not lay.manifest_path.exists(), "no manifest is written until an explicit migrate()"
    assert not lay.segments_dir.exists(), "segments/ is not created for a legacy/fresh store"
    ok, reason = s.verify()
    assert ok, reason
    assert [r.seq for r in s.iter_records()] == [0, 1, 2, 3]


def test_rlock_keyed_on_stable_path_and_survives_migration():
    """Invariant 14: the RLock is keyed on the stable store.path, so the object `append` and
    `envelope.consume` both take via spine_lock(store.path) is identical — and stays identical across a
    migration (store.path never changes, even though spine.jsonl is renamed away)."""
    d = _fresh_dir("sigil-rlock-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    _append_n(s, 2)
    lock_before = spine_lock(s.path)
    assert spine_lock(s.path) is lock_before, "same path ⇒ same RLock object"
    assert s.migrate() is True
    assert s.path == p, "store.path (the lock/identity token) is unchanged by migration"
    assert spine_lock(s.path) is lock_before, "the RLock survives the migration unchanged"


def test_migrate_preserves_chain_and_moves_to_segment():
    d = _fresh_dir("sigil-mig-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    _append_n(s, 5)
    before = [(r.seq, r.entry_hash, r.payload["n"]) for r in s.iter_records()]

    lay = SpineLayout.for_path(p)
    assert s.migrate() is True
    assert not p.exists(), "spine.jsonl is renamed away and never a data file again"
    assert (lay.segments_dir / "seg-00000000.jsonl").exists()
    assert lay.manifest_path.exists()

    # reads identical, chain intact, tip preserved
    assert [(r.seq, r.entry_hash, r.payload["n"]) for r in s.iter_records()] == before
    ok, reason = s.verify()
    assert ok, reason
    assert s.next_seq == 5

    # a FRESH instance resolves the active segment via the manifest and reads the same chain
    fresh = SpineStore(p)
    assert [r.seq for r in fresh.iter_records()] == [0, 1, 2, 3, 4]
    assert fresh.get(2) is not None and fresh.get(2).payload["n"] == 2

    # appends continue cleanly with no seq reuse
    s.append(kind="event", source="t", actor="u", payload={"n": 5})
    ok, reason = SpineStore(p).verify()
    assert ok, reason
    assert [r.seq for r in SpineStore(p).iter_records()] == [0, 1, 2, 3, 4, 5]


def test_migrate_is_idempotent():
    d = _fresh_dir("sigil-idem-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    _append_n(s, 3)
    assert s.migrate() is True
    gen1 = read_manifest(SpineLayout.for_path(p)).generation
    assert s.migrate() is False, "a second migrate is a no-op"
    assert read_manifest(SpineLayout.for_path(p)).generation == gen1


def test_migrate_fresh_creates_empty_active():
    """A fresh (never-appended) store migrates by creating an empty active segment; appends then work."""
    d = _fresh_dir("sigil-freshmig-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    assert s.migrate() is True
    assert not p.exists()
    seg0 = SpineLayout.for_path(p).segments_dir / "seg-00000000.jsonl"
    assert seg0.exists() and seg0.stat().st_size == 0
    assert s.next_seq == 0
    _append_n(s, 2)
    ok, reason = SpineStore(p).verify()
    assert ok, reason
    assert [r.seq for r in SpineStore(p).iter_records()] == [0, 1]


def test_orphan_migration_is_reconciled():
    """The judge-flagged migration crash window: a crash AFTER the atomic rename but BEFORE the manifest
    write leaves seg-0 present, spine.jsonl gone, no manifest. The store MUST reconcile (finish the
    migration) and recover the records — never read the spine as empty and hide all history."""
    d = _fresh_dir("sigil-orphan-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    _append_n(s, 4)
    before = [r.seq for r in s.iter_records()]
    lay = SpineLayout.for_path(p)

    # simulate the crash: rename done, manifest NOT written
    lay.segments_dir.mkdir()
    os.replace(p, lay.segments_dir / "seg-00000000.jsonl")
    assert not p.exists() and (lay.segments_dir / "seg-00000000.jsonl").exists()
    assert not lay.manifest_path.exists()

    s2 = SpineStore(p)                                     # __init__ must reconcile
    assert lay.manifest_path.exists(), "reconciler publishes the manifest to complete the migration"
    assert [r.seq for r in s2.iter_records()] == before, "records recovered, NOT hidden as an empty spine"
    ok, reason = s2.verify()
    assert ok, reason


def test_live_appender_completes_orphan_migration_no_resurrect():
    """The CRITICAL review finding: a long-lived appender (e.g. the bridge) that never re-constructed its
    store, appending AFTER another process crashed mid-migrate(), must COMPLETE the orphan under the lock
    and write to the migrated segment — never re-create spine.jsonl and fork the log."""
    d = _fresh_dir("sigil-orphanlive-")
    p = d / "spine.jsonl"
    lay = SpineLayout.for_path(p)
    a = SpineStore(p)                                      # long-lived appender, legacy _active == spine.jsonl
    _append_n(a, 3)
    assert a._active == p

    # simulate a crash mid-migrate() in ANOTHER process: rename done, manifest NOT written
    lay.segments_dir.mkdir()
    os.replace(p, lay.segments_dir / "seg-00000000.jsonl")
    assert not p.exists()

    a.append(kind="event", source="t", actor="u", payload={"n": 3})   # A never saw the migration
    assert not p.exists(), "the live appender must NOT resurrect spine.jsonl (fork)"
    assert lay.manifest_path.exists(), "the live appender completed the interrupted migration under the lock"
    recs = [r.payload["n"] for r in SpineStore(p).iter_records()]
    assert recs == [0, 1, 2, 3], f"no fork — all records in the migrated segment: {recs}"
    ok, reason = SpineStore(p).verify()
    assert ok, reason


def test_reader_sees_data_during_pre_manifest_migrate_window():
    """F3 completeness (re-check finding): a lock-free reader with a stale active (constructed before the
    migration) must NOT see a false-empty spine during the migrate() window where spine.jsonl is already
    renamed to seg-0 but the manifest is not yet published — else the kill-switch scan and nonce highwater
    regress (the un-halting / replay direction)."""
    d = _fresh_dir("sigil-premanifest-")
    p = d / "spine.jsonl"
    lay = SpineLayout.for_path(p)
    a = SpineStore(p)                                      # stale reader; _active == spine.jsonl
    _append_n(a, 4)

    # reproduce the IN-migrate window: rename done, manifest NOT yet written
    lay.segments_dir.mkdir()
    os.replace(p, lay.segments_dir / "seg-00000000.jsonl")
    assert not p.exists() and not lay.manifest_path.exists()

    assert [r.seq for r in a.iter_records()] == [0, 1, 2, 3], "reader must not see a false-empty spine mid-migrate"
    assert a.count() == 4
    assert a.get(2) is not None and a.get(2).payload["n"] == 2          # indexed read path must not crash


def test_change_token_reflects_append_and_migration():
    """change_token() (the unified A4 epoch) must move on every append, on migration, and on a post-
    migration append — so a bare file-size check that would freeze once spine.jsonl is renamed away is
    replaced by a token that keeps changing."""
    d = _fresh_dir("sigil-tok-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    t0 = s.change_token()
    s.append(kind="event", source="t", actor="u", payload={"n": 0})
    t1 = s.change_token()
    assert t1 != t0, "append changes the token"
    s.migrate()
    t2 = s.change_token()
    assert t2 != t1, "migration changes the token (generation + active path)"
    s.append(kind="event", source="t", actor="u", payload={"n": 1})
    assert s.change_token() != t2, "append after migration changes the token"


def test_gesture_killswitch_panic_observed_after_migration():
    """BLOCK-2 end-to-end: a kill-switch PANIC engaged AFTER a migration must be observed by a running
    gesture session. The old size-token froze on OSError once spine.jsonl was renamed away — stranding a
    device-armed session un-halted. The change token keeps the panic observable."""
    from sigil.gesture.session import SessionGate

    class _NullBackend:
        def move(self, *a, **k): pass
        def click(self, *a, **k): pass
        def type_text(self, *a, **k): pass
        def launch(self, *a, **k): pass

    d = _fresh_dir("sigil-kssess-")
    p = d / "spine.jsonl"
    s = SpineStore(p)
    g = SessionGate(s, _NullBackend())
    assert g._killswitch_engaged(now=1.0) is False
    s.migrate()                                            # spine.jsonl renamed away
    from sigil.governor.killswitch import KillSwitch
    KillSwitch(s).engage(by="owner", reason="post-migration panic")
    assert g._killswitch_engaged(now=100.0) is True, \
        "a panic after migration must be observed (a frozen size token would strand the session un-halted)"


def test_manifest_rejects_path_escaping_segment_file():
    """MEDIUM-1: a doctored manifest whose segment `file` escapes the spine dir (absolute or `..`) is
    rejected at the model boundary, because get()/iter/tail open segment files without running verify()."""
    import pytest
    from pydantic import ValidationError

    from sigil.spine.manifest import Segment

    for bad in ("/etc/hostname", "../../etc/hostname", "../secret.jsonl"):
        with pytest.raises(ValidationError):
            Segment(id=0, file=bad, first_seq=0)
    Segment(id=0, file="spine.segments/seg-00000000.jsonl", first_seq=0)   # a contained relative path is fine


def test_reset_clears_all_segment_artifacts():
    """reset() must clear the legacy file, manifest, ALL segments, trash, and lockfile — not just
    spine.jsonl (the old --reset left rotated segments + the manifest behind, resurrecting stale data)."""
    d = _fresh_dir("sigil-reset-")
    lay = _make_segmented(d, [3, 2])                       # a migrated, multi-segment spine + manifest
    p = d / "spine.jsonl"
    # touch a lockfile + trash to prove they are cleared too
    _append_n(SpineStore(p), 0)                            # (constructs; no-op append count)
    lay.trash_dir.mkdir(parents=True, exist_ok=True)
    (lay.trash_dir / "old.jsonl").write_text("x")
    assert lay.manifest_path.exists() and lay.segments_dir.exists()

    SpineStore(p).reset()
    assert not lay.manifest_path.exists(), "manifest cleared"
    assert not lay.segments_dir.exists(), "segments dir cleared"
    assert not lay.trash_dir.exists(), "trash cleared"
    assert not p.exists(), "legacy file cleared"
    # a fresh store reads empty and can be rebuilt
    s = SpineStore(p)
    assert s.count() == 0 and s.next_seq == 0
    _append_n(s, 2)
    ok, reason = SpineStore(p).verify()
    assert ok, reason


def test_cli_spine_migrate_and_status(capsys):
    """The `sigil spine migrate|status` wrappers operate on the DEFAULT store (isolated under the test
    SIGIL_HOME). Bracketed with reset() so it neither inherits nor leaks default-spine state."""
    from sigil.cli import cmd_spine

    def _ns(**kw):
        return type("A", (), kw)()

    SpineStore().reset()                                   # clean legacy start on the default path
    try:
        _append_n(SpineStore(), 3)
        cmd_spine(_ns(action="status"))
        assert "LEGACY single file" in capsys.readouterr().out
        cmd_spine(_ns(action="migrate"))
        assert "migrated" in capsys.readouterr().out
        cmd_spine(_ns(action="migrate"))                   # idempotent
        assert "already migrated" in capsys.readouterr().out
        cmd_spine(_ns(action="status"))
        out = capsys.readouterr().out
        assert "1 segment(s)" in out and "generation 0" in out and "3 records" in out
    finally:
        SpineStore().reset()                               # don't leak a migrated default spine to other tests


def test_rotation_seals_into_contiguous_segments():
    d = _fresh_dir("sigil-rot-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=4)   # seal every 4 records
    s.migrate()
    _append_n(s, 18)
    info = s.segment_info()
    assert len(info) >= 4, f"expected several sealed segments, got {len(info)}"
    assert sum(1 for x in info if not x["sealed"]) == 1, "exactly one active segment"
    ok, reason = SpineStore(p).verify()
    assert ok, reason                                       # chain spans every seam from genesis
    assert [r.seq for r in SpineStore(p).iter_records()] == list(range(18))
    assert SpineStore(p).count() == 18 and SpineStore(p).next_seq == 18
    for seq in (0, 5, 11, 17):                              # get() across sealed + active segments
        assert SpineStore(p).get(seq).payload["n"] == seq


def test_legacy_store_never_auto_rotates():
    d = _fresh_dir("sigil-norot-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=2)   # tiny threshold, but NOT migrated
    _append_n(s, 20)
    assert s.segment_info() == [], "a legacy (un-migrated) spine never rotates"
    assert s._active == p and p.exists()
    ok, reason = s.verify()
    assert ok, reason


def test_rotation_disabled_when_thresholds_zero():
    d = _fresh_dir("sigil-rotoff-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=0)   # both bounds off => never rotate
    s.migrate()
    _append_n(s, 30)
    assert len(s.segment_info()) == 1, "rotation disabled: one (growing) active segment"
    ok, reason = SpineStore(p).verify()
    assert ok, reason


def test_manual_rotate():
    d = _fresh_dir("sigil-manrot-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=0)   # no auto-rotation
    s.migrate()
    _append_n(s, 5)
    assert s.rotate() is True                               # force a seal
    assert len(s.segment_info()) == 2
    _append_n(s, 3, start=5)
    ok, reason = SpineStore(p).verify()
    assert ok, reason
    assert [r.seq for r in SpineStore(p).iter_records()] == list(range(8))


def test_ambient_crash_env_is_inert_in_production(monkeypatch):
    """Review fix: the fault-injection hook must NOT be armable by an ambient env var — production ships
    _crash_hook=None, so setting SIGIL_SPINE_CRASH_AT does nothing (no os._exit crash-loop of every writer)."""
    import sigil.spine.store as store
    assert store._crash_hook is None, "production must ship no crash hook"
    monkeypatch.setenv("SIGIL_SPINE_CRASH_AT", "append_after_fsync")
    d = _fresh_dir("sigil-nohook-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_records=2)
    s.migrate()
    assert s.append(kind="event", source="t", actor="u", payload={"n": 0}) == 0   # must NOT os._exit


def test_negative_threshold_clamps_to_disabled():
    """Review fix: a negative threshold clamps to 0 (disabled), not `size >= -1` == always-over (which
    would seal on every append — a self-DoS)."""
    d = _fresh_dir("sigil-negthr-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=-1, seg_max_records=-1)
    assert s._seg_max_bytes == 0 and s._seg_max_records == 0
    s.migrate()
    _append_n(s, 10)
    assert len(s.segment_info()) == 1, "clamped to disabled — one segment, not one-per-record"


def test_panic_append_durable_when_it_triggers_rotation():
    """D1 / write-then-rotate: a kill-switch PANIC append that itself trips the rotation threshold is
    written + fsync'd BEFORE the seal, so it is durable and honored even though it triggered a rotation."""
    from sigil.governor.killswitch import KillSwitch

    d = _fresh_dir("sigil-panicrot-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=3)
    s.migrate()
    _append_n(s, 2)                                         # records 0,1 in the active
    KillSwitch(s).engage(by="owner", reason="panic")        # record 2 -> trips the seal (write-then-rotate)
    assert KillSwitch(SpineStore(p)).is_engaged() is True, "panic honored across the rotation it triggered"
    assert len(SpineStore(p).segment_info()) >= 2, "the seal happened"
    ok, reason = SpineStore(p).verify()
    assert ok, reason


def test_compact_gzips_sealed_and_reads_transparently():
    d = _fresh_dir("sigil-compact-")
    p = d / "spine.jsonl"
    lay = SpineLayout.for_path(p)
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=40)
    s.migrate()
    for i in range(180):
        s.append(kind="event", source="t", actor="a", payload={"n": i, "text": "lorem ipsum dolor sit amet " * 3})
    before_total = sum(f.stat().st_size for f in lay.segments_dir.iterdir() if f.is_file())
    n = s.compact()
    assert n >= 3, f"expected several sealed segments compressed, got {n}"
    after_total = sum(f.stat().st_size for f in lay.segments_dir.iterdir() if f.is_file())
    assert after_total < before_total, f"compact must reclaim disk IMMEDIATELY: {after_total} !< {before_total}"
    assert len(list(lay.segments_dir.glob("*.jsonl"))) == 1, "only the ACTIVE stays plaintext (no lingering copy)"
    codecs = {x["id"]: x["codec"] for x in s.segment_info()}
    assert all(codecs[i] == "gzip" for i in codecs if i != max(codecs)), "all sealed segments gzip"
    assert codecs[max(codecs)] == "none", "active segment stays plaintext"

    # every read is transparent across gz + plaintext
    fresh = SpineStore(p)
    ok, reason = fresh.verify()
    assert ok, reason
    assert [r.seq for r in fresh.iter_records()] == list(range(180))
    assert fresh.count() == 180 and fresh.next_seq == 180
    for seq in (0, 41, 179):                                # get() from a gz segment and the active
        assert fresh.get(seq).payload["n"] == seq
    assert [r.seq for r in fresh.tail(3)] == [177, 178, 179]
    assert s.compact() == 0, "idempotent — nothing left to compact"
    # a post-compact append still verifies and rotation still works over gz segments
    s.append(kind="event", source="t", actor="a", payload={"n": 180})
    ok, reason = SpineStore(p).verify()
    assert ok, reason


def test_reader_grace_during_concurrent_compact():
    """D2: lock-free readers iterating while a compactor gzips sealed segments (moving superseded plaintext
    to trash) must NEVER ENOENT or see a short/forked chain — the manifest-reread retry + open-fd grace
    keep every read a contiguous chain from genesis."""
    d = _fresh_dir("sigil-d2-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=15)
    s.migrate()
    _append_n(s, 60)

    errors: list[str] = []
    stop = threading.Event()

    def reader():
        r = SpineStore(p)
        while not stop.is_set():
            try:
                seqs = [rec.seq for rec in r.iter_records()]
            except Exception as e:                          # noqa: BLE001 — any read exception is a failure
                errors.append(f"reader raised {e!r}")
                return
            if seqs != list(range(len(seqs))):
                errors.append(f"reader saw a non-contiguous chain: {seqs[:3]}..{seqs[-3:]}")
                return

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for k in range(4):                                      # interleave: more sealed plaintext, then compact
        _append_n(s, 15, start=60 + k * 15)
        s.compact()
        time.sleep(0.005)
    stop.set()
    for t in threads:
        t.join(timeout=10)
    assert not errors, errors[:3]


def test_tail_contiguous_during_concurrent_compact():
    """Review BLOCK-1: tail() must stay a contiguous window under a concurrent compaction that unlinks a
    plaintext (its feeds the device-arm replay-dedup gate). The read-path retry must re-resolve, never
    silently drop a segment and hole the window."""
    d = _fresh_dir("sigil-tailrace-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=15)
    s.migrate()
    _append_n(s, 120)
    errors: list[str] = []
    stop = threading.Event()

    def tailer():
        r = SpineStore(p)
        while not stop.is_set():
            try:
                got = [rec.seq for rec in r.tail(40)]
            except Exception as e:                          # noqa: BLE001
                errors.append(f"tail raised {e!r}")
                return
            if got != list(range(got[0], got[0] + len(got))) or (len(got) >= 40 and got[-1] - got[0] != 39):
                errors.append(f"tail window non-contiguous: {got}")
                return

    threads = [threading.Thread(target=tailer) for _ in range(4)]
    for t in threads:
        t.start()
    for _ in range(30):
        s.compact()
        time.sleep(0.003)
    stop.set()
    for t in threads:
        t.join(timeout=10)
    assert not errors, errors[:3]


# --- C-1: the reader/compaction TOCTOU, driven DETERMINISTICALLY -------------------------------------
#
# The two tests above are timing stress: they hit the race only when the scheduler cooperates (it did in
# CI on PR #391 — `SpineError('spine manifest (generation 13) references a missing segment: …seg-6.jsonl')`
# — and did not on #390 from the same base). The tests below DRIVE the exact interleaving instead of
# racing for it: a reader takes its manifest snapshot at generation G, a full compaction then commits
# G+1 and unlinks every superseded plaintext, and only THEN does the reader stat/open the files its
# snapshot named. Each fails deterministically without the fix. Their negative controls pin the other
# half of the contract: a segment missing at an UNCHANGED generation is real corruption and must RAISE.


def _compact_inside_the_resolve_window(monkeypatch, p: Path, *, skip: int = 0) -> dict:
    """Run a COMPLETE compaction immediately after the read path takes its manifest snapshot, so the caller
    is left holding a stale (generation G) view while the on-disk truth is G+1 with the superseded
    plaintext segments unlinked — the exact C-1 interleaving, with no reliance on timing.

    `skip` manifest reads pass through untouched first: get() reads the manifest once for its change-token
    before it resolves segments, so skip=1 lands the compaction in ITS resolve window. The store under test
    must be constructed BEFORE arming this (a constructor read would otherwise burn the shot)."""
    from sigil.spine import store as store_mod
    real_read = store_mod.read_manifest
    state = {"reads": 0, "fired": 0}

    def racing_read(layout):
        m = real_read(layout)                              # the reader's snapshot, taken BEFORE the compact
        state["reads"] += 1
        if (state["fired"] == 0 and state["reads"] > skip and m is not None
                and any(sg.sealed and sg.codec == "none" for sg in m.segments)):
            state["fired"] = 1                             # set first: compact()'s own reads must not re-fire
            SpineStore(p).compact()                        # commits gen+1, THEN unlinks the superseded files
        return m

    monkeypatch.setattr(store_mod, "read_manifest", racing_read)
    return state


def _segmented_store(prefix: str, n: int = 22) -> tuple[Path, SpineStore]:
    d = _fresh_dir(prefix)
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=5)
    s.migrate()
    _append_n(s, n)                                        # 4 sealed plaintext segments + an active
    return p, s


def test_iter_records_reresolves_when_compaction_supersedes_the_snapshot(monkeypatch):
    """C-1: iter_records() resolved the segment list from manifest generation G; a compaction committed
    G+1 and unlinked the plaintext G still named. The reader must RE-READ the manifest and complete the
    scan, not raise 'references a missing segment'. Without the fix this raises deterministically."""
    p, _s = _segmented_store("sigil-c1-iter-")
    r = SpineStore(p)                                      # construct BEFORE arming (see the helper's note)
    state = _compact_inside_the_resolve_window(monkeypatch, p)
    seqs = [rec.seq for rec in r.iter_records()]
    assert state["fired"] == 1, "the interleaving never fired — the test would be vacuous"
    assert seqs == list(range(22)), f"the scan must stay a contiguous chain from genesis: {seqs}"


def test_tail_reresolves_when_compaction_supersedes_the_snapshot(monkeypatch):
    """C-1 for the bounded-window read: tail() must survive the same interleaving with a contiguous
    window (the device-arm replay-dedup gate depends on it), not raise."""
    p, _s = _segmented_store("sigil-c1-tail-")
    r = SpineStore(p)
    state = _compact_inside_the_resolve_window(monkeypatch, p)
    got = [rec.seq for rec in r.tail(12)]
    assert state["fired"] == 1
    assert got == list(range(10, 22)), f"tail window must be contiguous and complete: {got}"


def test_get_reresolves_when_compaction_supersedes_the_snapshot(monkeypatch):
    """C-1 for the point read: get() indexes through the same resolver (_ensure_index), so it must
    re-resolve too rather than fail closed on a segment that was merely superseded."""
    p, _s = _segmented_store("sigil-c1-get-")
    r = SpineStore(p)
    state = _compact_inside_the_resolve_window(monkeypatch, p, skip=1)   # skip get()'s change-token read
    rec = r.get(7)
    assert state["fired"] == 1
    assert rec is not None and rec.seq == 7


def test_missing_segment_at_unchanged_generation_still_raises():
    """NEGATIVE CONTROL (the half that must NOT be tolerated): a segment that is genuinely gone while the
    manifest generation is UNCHANGED is real corruption, and every read path must still fail CLOSED and
    loudly (invariant 15) — naming the missing segment, not blaming 'churn'."""
    import pytest
    d = _fresh_dir("sigil-c1-neg-")
    lay = _make_segmented(d, [3, 3, 3])                    # generation 1; seg-0/seg-1 sealed, seg-2 active
    p = d / "spine.jsonl"
    assert read_manifest(lay).generation == 1
    (lay.segments_dir / "seg-00000001.jsonl").unlink()      # vanishes; the manifest still names it at gen 1

    for label, call in (("iter_records", lambda: list(SpineStore(p).iter_records())),
                        ("tail", lambda: SpineStore(p).tail(4)),
                        ("count", lambda: SpineStore(p).count()),
                        ("verify", lambda: SpineStore(p).verify())):
        with pytest.raises(SpineError) as ei:
            call()
        msg = str(ei.value)
        assert "references a missing segment" in msg and "seg-00000001.jsonl" in msg, f"{label}: {msg}"
        assert "generation 1" in msg, f"{label} must name the generation it fails at: {msg}"
    assert read_manifest(lay).generation == 1, "a failed read must not mutate the manifest"


def test_segment_vanishing_at_open_time_at_unchanged_generation_still_raises(monkeypatch):
    """NEGATIVE CONTROL for the OPEN-time half of the rule. The resolve succeeds (the file is there), then
    the file is unlinked WITHOUT any manifest swap, so the open raises FileNotFoundError. Because the
    generation did not move, that is genuine loss — the read-path retry must NOT absorb it as compaction
    churn; it must re-raise as a loud missing-segment SpineError."""
    import pytest
    p, _s = _segmented_store("sigil-c1-openneg-")
    r = SpineStore(p)
    real_open, fired = SpineStore._open_segment, {"n": 0}

    def vanishing_open(self, path):
        if fired["n"] == 0:
            fired["n"] = 1
            path.unlink()                              # NO manifest swap: the generation is UNCHANGED
        return real_open(self, path)                   # -> FileNotFoundError, straight into the retry arm

    monkeypatch.setattr(SpineStore, "_open_segment", vanishing_open)
    with pytest.raises(SpineError) as ei:
        list(r.iter_records())
    assert fired["n"] == 1
    assert "references a missing segment" in str(ei.value), str(ei.value)
    assert "kept moving" not in str(ei.value), "real loss must not be reported as compaction churn"


def test_perpetual_manifest_churn_fails_loudly_and_does_not_hang(monkeypatch):
    """The retry is BOUNDED. Under a pathological writer that never stops swapping the manifest, a reader
    must surface a loud SpineError after a finite number of re-resolves — never spin forever, and never
    fall back to a short chain."""
    import pytest
    d = _fresh_dir("sigil-c1-churn-")
    lay = _make_segmented(d, [3, 3])
    p = d / "spine.jsonl"
    (lay.segments_dir / "seg-00000000.jsonl").unlink()
    ticks = iter(range(1_000, 11_000))                 # always != the real generation, and never repeats
    monkeypatch.setattr(SpineStore, "_manifest_generation", lambda self: next(ticks))
    with pytest.raises(SpineError) as ei:
        list(SpineStore(p).iter_records())
    assert "kept changing" in str(ei.value), str(ei.value)


def test_missing_segment_with_manifest_vanishing_in_resolve_window_still_raises(monkeypatch):
    """C-1 / BLOCK-1 (fail-closed -> fail-OPEN regression). Interior segments are genuinely DELETED and the
    manifest itself is removed INSIDE the resolver's retry window (generation -> -1, which is NOT a strictly-
    forward move — the same shape reset()/an in-flight migrate produces). Every full read path must still
    RAISE: the manifest vanishing must NOT be mistaken for a benign compaction supersession and absorbed into
    a SILENT SHORT CHAIN (invariant 15). Before the `> gen` fix this returned count()==3 / tail(9)==[6,7,8].
    The store is constructed BEFORE arming so the raise is attributable to the resolver, not the ctor read."""
    import pytest
    from sigil.spine import store as store_mod
    real_read = store_mod.read_manifest                    # the genuine reader, captured once (never chained)
    for label, call in (("iter_records", lambda s: list(s.iter_records())),
                        ("count", lambda s: s.count()),
                        ("entries", lambda s: s.entries()),
                        ("verify", lambda s: s.verify()),
                        ("tail", lambda s: s.tail(9))):
        d = _fresh_dir("sigil-c1-mvanish-")
        lay = _make_segmented(d, [3, 3, 3])                # generation 1, seqs 0..8
        p = d / "spine.jsonl"
        (lay.segments_dir / "seg-00000001.jsonl").unlink()  # REAL LOSS: seqs 3,4,5 gone from disk
        s = SpineStore(p)                                  # construct BEFORE arming
        state = {"n": 0}

        def racing_read(layout, _lay=lay, _st=state):
            m = real_read(layout)                          # the resolver's snapshot: gen 1, 3 segments
            _st["n"] += 1
            if _st["n"] == 1:                              # remove the manifest strictly inside the resolve
                _lay.manifest_path.unlink()
            return m

        monkeypatch.setattr(store_mod, "read_manifest", racing_read)
        with pytest.raises(SpineError) as ei:
            call(s)
        assert "references a missing segment" in str(ei.value), f"{label}: {ei.value}"
        assert state["n"] >= 1, f"{label}: the interleaving never fired — the test would be vacuous"


def test_manifest_vanishing_on_a_retry_raises_not_legacy_fallback(monkeypatch):
    """C-1 / BLOCK-1 point (2): the no-manifest legacy fallback is FIRST-ATTEMPT-ONLY. If the resolver
    already held a manifest (gen >= 0), took a snapshot that looked SUPERSEDED (generation appears to have
    moved strictly forward, so it retries), and on the RE-RESOLVE finds the manifest GONE (gen -> -1, not a
    forward move), it must RAISE 'manifest disappeared' — never silently fall back to the single active file
    (a short chain)."""
    import pytest
    from sigil.spine import store as store_mod
    d = _fresh_dir("sigil-c1-retryvanish-")
    lay = _make_segmented(d, [3, 3, 3])                    # generation 1
    p = d / "spine.jsonl"
    (lay.segments_dir / "seg-00000001.jsonl").unlink()      # a segment the snapshot names is missing
    s = SpineStore(p)                                      # construct BEFORE arming
    monkeypatch.setattr(SpineStore, "_manifest_generation", lambda self: 999)   # forward -> attempt 0 retries
    real_read, state = store_mod.read_manifest, {"n": 0}

    def racing_read(layout):
        state["n"] += 1
        if state["n"] == 1:
            return real_read(layout)                       # attempt 0: the real manifest (gen 1)
        return None                                        # the retry finds the manifest gone

    monkeypatch.setattr(store_mod, "read_manifest", racing_read)
    with pytest.raises(SpineError) as ei:
        list(s.iter_records())
    assert "manifest disappeared" in str(ei.value), str(ei.value)
    assert state["n"] >= 2, "the retry never happened — the point-(2) branch was not exercised"


def test_get_survives_compaction_during_index_scan(monkeypatch):
    """C-1 / BLOCK-2 (the race is NOT closed on get()/_ensure_index). get() builds its index via
    _ensure_index -> _scan_segment, which OPENS each segment. A compaction that commits gen+1 and unlinks the
    superseded plaintext AFTER the resolve but DURING the scan must be re-resolved (the manifest now names the
    .gz), never surface as a bare FileNotFoundError. The C-1 fix left this open() outside any retry."""
    p, _s = _segmented_store("sigil-c1-getscan-")
    r = SpineStore(p)                                      # a cold reader: get() will build the index now
    real_ls, fired = SpineStore._load_sidecar, {"n": 0}

    def racing_load_sidecar(self, ps, pth):
        if fired["n"] == 0:
            fired["n"] = 1
            SpineStore(p).compact()                        # commits gen+1, THEN unlinks the plaintext, mid-scan
        return real_ls(self, ps, pth)

    monkeypatch.setattr(SpineStore, "_load_sidecar", racing_load_sidecar)
    rec = r.get(7)
    assert fired["n"] == 1, "the interleaving never fired — the test would be vacuous"
    assert rec is not None and rec.seq == 7


def test_iter_records_survives_compaction_during_start_locus_index_scan(monkeypatch):
    """C-1 / BLOCK-2 for the indexed iter_records path: _start_locus -> _ensure_index -> _scan_segment opens
    segments too, and the C-1 fix left _start_locus OUTSIDE the retry try. A compaction unlinking a plaintext
    during that index build must be re-resolved, not escape as a bare FileNotFoundError."""
    p, _s = _segmented_store("sigil-c1-iterscan-")
    r = SpineStore(p)
    real_ls, fired = SpineStore._load_sidecar, {"n": 0}

    def racing_load_sidecar(self, ps, pth):
        if fired["n"] == 0:
            fired["n"] = 1
            SpineStore(p).compact()
        return real_ls(self, ps, pth)

    monkeypatch.setattr(SpineStore, "_load_sidecar", racing_load_sidecar)
    got = [x.seq for x in r.iter_records(since_seq=3)]
    assert fired["n"] == 1
    assert got == list(range(4, 22)), got


def test_get_index_scan_open_at_unchanged_generation_still_raises(monkeypatch):
    """C-1 / BLOCK-2 NEGATIVE control: if a plaintext is unlinked during get()'s index scan WITHOUT any
    manifest swap (generation UNCHANGED), that is genuine loss — the get() retry must NOT absorb it; the next
    re-resolve RAISES a loud missing-segment SpineError, never a silent value read from surviving segments."""
    import pytest
    p, _s = _segmented_store("sigil-c1-getscan-neg-")
    r = SpineStore(p)
    lay = SpineLayout.for_path(p)
    victim = [sg for sg in read_manifest(lay).segments if sg.sealed][1]
    real_ls, fired = SpineStore._load_sidecar, {"n": 0}

    def racing_load_sidecar(self, ps, pth):
        if fired["n"] == 0:
            fired["n"] = 1
            lay.seg_path(victim).unlink()                  # NO manifest swap -> generation is UNCHANGED
        return real_ls(self, ps, pth)

    monkeypatch.setattr(SpineStore, "_load_sidecar", racing_load_sidecar)
    with pytest.raises(SpineError) as ei:
        r.get(7)
    assert fired["n"] == 1
    assert "references a missing segment" in str(ei.value), str(ei.value)
    assert "kept moving" not in str(ei.value) and "kept changing" not in str(ei.value), \
        "real loss at an unchanged generation must not be reported as compaction churn"


def test_compaction_publishes_the_new_manifest_before_unlinking(monkeypatch):
    """The WRITE-side half of the C-1 contract, pinned so a future refactor cannot invert it: compaction
    must COMMIT the new-generation manifest (segment flipped to gzip) BEFORE unlinking the plaintext it
    supersedes. If the unlink ever came first, no reader-side generation check could tell a superseded
    file from a lost one, and the race would be unfixable rather than merely retryable."""
    p, s = _segmented_store("sigil-c1-order-")
    lay = SpineLayout.for_path(p)
    violations: list[str] = []
    real_unlink = Path.unlink

    def checked_unlink(self, *a, **kw):
        if self.parent == lay.segments_dir and self.name.endswith(".jsonl"):
            m = read_manifest(lay)
            if m is not None and any(lay.seg_path(sg) == self for sg in m.segments):
                violations.append(f"unlinked {self.name} while the manifest (generation "
                                  f"{m.generation}) still referenced it")
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", checked_unlink)
    assert s.compact() > 0, "the fixture must have sealed plaintext to compact"
    assert not violations, violations
    assert [r.seq for r in SpineStore(p).iter_records()] == list(range(22))


def test_two_concurrent_compactors_no_crash():
    """Review BLOCK-2: two compactors on the same spine must not clobber a shared temp and crash — each
    uses a unique temp; both complete (or no-op), and the spine verifies."""
    d = _fresh_dir("sigil-2compact-")
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=8)
    s.migrate()
    _append_n(s, 120)
    errors: list[str] = []

    def compactor():
        try:
            SpineStore(p).compact()
        except Exception as e:                              # noqa: BLE001
            errors.append(repr(e))

    threads = [threading.Thread(target=compactor) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not errors, errors
    ok, reason = SpineStore(p).verify()
    assert ok, reason
    assert [r.seq for r in SpineStore(p).iter_records()] == list(range(120))


def test_compact_recovers_from_crash_before_codec_flip():
    """Crash after building the .gz but before the manifest flip: an orphan .gz, manifest still plaintext.
    Reads use the plaintext; re-running compact overwrites the orphan and completes."""
    d = _fresh_dir("sigil-ccrash1-")
    p = d / "spine.jsonl"
    lay = SpineLayout.for_path(p)
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=5)
    s.migrate()
    _append_n(s, 12)
    plain0 = lay.segments_dir / "seg-00000000.jsonl"
    with plain0.open("rb") as fin, gzip.open(lay.segments_dir / "seg-00000000.jsonl.gz", "wb") as fout:
        shutil.copyfileobj(fin, fout)                       # simulate the orphan .gz (crashed before flip)
    ok, reason = SpineStore(p).verify()
    assert ok, reason                                       # manifest still plaintext -> reads use it
    s.compact()
    assert s.segment_info()[0]["codec"] == "gzip"
    ok, reason = SpineStore(p).verify()
    assert ok, reason


def test_compact_removes_orphan_plaintext_after_flip():
    """Crash after the codec flip but before the plaintext unlink: an orphan plaintext beside the gz. The
    next compact()'s sweep removes it (immediate reclaim)."""
    d = _fresh_dir("sigil-ccrash2-")
    p = d / "spine.jsonl"
    lay = SpineLayout.for_path(p)
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=5)
    s.migrate()
    _append_n(s, 12)
    s.compact()                                            # seg-0 -> gzip, plaintext unlinked
    (lay.segments_dir / "seg-00000000.jsonl").write_bytes(b'{"stale":true}\n')   # crash-stranded plaintext
    s.compact()                                            # sweep must remove it
    assert not (lay.segments_dir / "seg-00000000.jsonl").exists(), "orphan plaintext removed"
    ok, reason = SpineStore(p).verify()
    assert ok, reason


def test_reset_keeps_lockfile_so_it_still_excludes(monkeypatch):
    """Review F1: reset() must NOT unlink the lockfile it holds (flock binds to the inode, not the path),
    or a concurrent appender opens a new inode and slips the lock during the destructive rmtree. Assert the
    lockfile survives reset so its flock keeps excluding appenders for the whole critical section."""
    d = _fresh_dir("sigil-resetlock-")
    _make_segmented(d, [3, 2])
    p = d / "spine.jsonl"
    lay = SpineLayout.for_path(p)
    SpineStore(p).append(kind="event", source="t", actor="u", payload={"n": 99})   # ensure the lockfile exists
    assert lay.lockfile_path.exists()
    SpineStore(p).reset()
    assert lay.lockfile_path.exists(), "reset() must keep the path-stable lockfile (it holds its flock)"
    assert not lay.manifest_path.exists() and not lay.segments_dir.exists()


def test_get_fails_closed_on_missing_segment():
    """Review F2a: get() of a seq in a SURVIVING segment must NOT fail open while the chain is truncated —
    it fails closed (raises) exactly like the scans, not returns a value from stale index state."""
    import pytest
    d = _fresh_dir("sigil-getclosed-")
    lay = _make_segmented(d, [3, 3])                       # seg-0 seq0-2 sealed; seg-1 seq3-5 active
    s = SpineStore(d / "spine.jsonl")
    assert s.get(4) is not None                            # warm the index while whole
    (lay.segments_dir / "seg-00000000.jsonl").unlink()     # a DIFFERENT segment vanishes
    with pytest.raises(SpineError):
        s.get(4)                                           # must fail closed, not return seq 4 from seg-1


def test_append_fails_closed_not_fork_when_seam_unreadable():
    """Review F3: append into an empty non-genesis active whose seam boundary is unreadable must FAIL
    CLOSED (refuse) — never build_chain from genesis and write a seq-0 fork into a first_seq>0 segment."""
    import pytest
    d = _fresh_dir("sigil-seamclosed-")
    lay = _make_segmented(d, [4, 0])                       # seg-0 sealed seq0-3; seg-1 active EMPTY first_seq=4
    (lay.segments_dir / "seg-00000000.jsonl").unlink()     # the seam boundary vanishes
    s = SpineStore(d / "spine.jsonl")
    with pytest.raises(SpineError):
        s.append(kind="event", source="t", actor="u", payload={"n": 4})   # must refuse, not fork at seq 0


def test_stale_appender_reresolves_no_split_brain():
    """The core split-brain test. Instance A appends in legacy mode; instance B migrates; A appends
    again. A MUST re-resolve the active segment under the lock and write to the migrated segment — never
    resurrect spine.jsonl and fork the chain."""
    d = _fresh_dir("sigil-sb-")
    p = d / "spine.jsonl"
    a = SpineStore(p)
    a.append(kind="event", source="t", actor="u", payload={"n": 0})
    assert a._active == p                                   # A cached the legacy path

    b = SpineStore(p)                                       # "another process"
    assert b.migrate() is True                              # p is renamed → seg-0; A's cached _active is now stale

    a.append(kind="event", source="t", actor="u", payload={"n": 1})   # A must re-resolve under the lock
    assert not p.exists(), "a stale appender must not resurrect spine.jsonl (split-brain / fork)"

    recs = [r.payload["n"] for r in SpineStore(p).iter_records()]
    assert recs == [0, 1], f"both records land in the migrated segment, no fork: {recs}"
    ok, reason = SpineStore(p).verify()
    assert ok, reason
    seqs = [r.seq for r in SpineStore(p).iter_records()]
    assert seqs == [0, 1], f"no seq reuse across the migration seam: {seqs}"
