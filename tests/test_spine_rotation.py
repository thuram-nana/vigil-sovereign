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
import json
import os
import tempfile
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
