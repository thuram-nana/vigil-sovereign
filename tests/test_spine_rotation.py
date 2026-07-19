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
import os
import tempfile
from pathlib import Path

from sigil.spine.manifest import read_manifest, SpineLayout
from sigil.spine.store import SpineStore, spine_lock


def _fresh_dir(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def _append_n(store: SpineStore, n: int, start: int = 0) -> None:
    for i in range(start, start + n):
        store.append(kind="event", source="t", actor="u", payload={"n": i})


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
