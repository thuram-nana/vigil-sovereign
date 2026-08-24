"""Cold-archive hard-prune Slice E — the crash-safe cutover that DELETES the pruned prefix (issue #530).

Happy-path + the three owner gates + the roll-forward reconciler. The kill-9-during-cutover fuzz lives in
test_spine_prune_crashfuzz.py. Slice E is the ONLY code that drops a live record; these pin that it does so
soundly: below-K is GONE from the live spine but preserved + owner-anchored in the archive, ≥K is retained,
and both verify()/verify_checkpoint hold over the re-based window.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_spine_prune_cutover.py -q
"""
import pytest

import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
from sigil.spine import prune
from sigil.spine.store import SpineStore


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    import sigil.config as cfg
    keys, head = tmp_path / "keys", tmp_path / "head.json"
    monkeypatch.setattr(_cp, "HEAD_PATH", head)
    monkeypatch.setattr(_snap, "HEAD_PATH", head)
    monkeypatch.setattr(cfg, "HEAD_PATH", head, raising=False)
    monkeypatch.setattr(_cp, "KEYS_DIR", keys)
    monkeypatch.setattr(_cp, "_PRIV", keys / "owner.priv")
    monkeypatch.setattr(_cp, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(_fl, "FLOOR_PATH", tmp_path / "floor.json")
    return head


def _segmented_store(tmp_path, n_segments=4, per=5):
    s = SpineStore(tmp_path / "spine.jsonl")
    s.migrate()
    seq = 0
    for _seg in range(n_segments):
        for _i in range(per):
            s.append(kind="event", source="t", actor="u", payload={"i": seq}); seq += 1
        s.rotate()
    for _i in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": seq}); seq += 1
    return s


def _seqs(s):
    return [r.seq for r in s.iter_records()]


def test_commit_prune_deletes_and_stays_verifiable(tmp_path, isolated):
    def _data_segments():
        return sorted(p.name for p in s._layout.segments_dir.glob("seg-*") if not p.name.endswith(".idx"))

    s = _segmented_store(tmp_path)
    _cp.checkpoint(s)                                      # a valid owner-signed baseline (gate 1)
    assert _seqs(s) == list(range(23))
    seg_files_before = _data_segments()

    rep = prune.commit_prune(s, 10, confirm=True, )
    assert rep["base_seq"] == 10 and rep["files_deleted"] >= 1

    # a FRESH handle (no in-memory state) must see the pruned, still-verifiable spine.
    s2 = SpineStore(tmp_path / "spine.jsonl")
    live = _seqs(s2)
    assert live[0] == 10, "records below K must be GONE from the live spine"
    assert live == list(range(10, 24)), "retained window [10..T] + the snapshot record, contiguous"
    ok, why = s2.verify()
    assert ok, why                                        # prune-aware verify() re-roots from base_prev_hash
    hok, hmsg = _cp.verify_checkpoint(s2)
    assert hok, hmsg                                      # owner-signed pruned head verifies the live window

    # the pruned prefix is DELETED on disk but preserved + owner-anchored in the archive.
    seg_files_after = _data_segments()
    assert "seg-00000000.jsonl" in seg_files_before and "seg-00000000.jsonl" not in seg_files_after
    assert "seg-00000001.jsonl" not in seg_files_after, "below-K segment files were unlinked"
    aok, amsg = prune.verify_with_archive(s2)
    assert aok, amsg                                      # [archive‖live] re-attaches to the owner-signed head


def test_drop_primitives_refuse_without_a_committed_prune(tmp_path, isolated):
    """Red-pen LOW-1 (defence-in-depth): the destructive primitives `_rebase_manifest_below` /
    `_delete_orphan_segment_files_below` refuse to drop live records unless the OWNER-SIGNED head has
    committed a prune reaching that far. A direct caller that bypasses `commit_prune`'s three gates cannot
    delete owner-signed records."""
    from sigil.spine.store import SpineError
    s = _segmented_store(tmp_path)
    _cp.checkpoint(s)                                       # a valid signed head, but base_seq=0 (no prune)
    with pytest.raises(SpineError) as e1:
        s._rebase_manifest_below(10)
    assert "committed-prune context" in str(e1.value)
    with pytest.raises(SpineError):
        s._delete_orphan_segment_files_below(10)
    assert _seqs(s) == list(range(23)), "a guarded primitive dropped nothing"
    # fail-closed with NO head at all, too.
    isolated.unlink()
    with pytest.raises(SpineError):
        s._rebase_manifest_below(10)


def test_commit_prune_requires_confirm(tmp_path, isolated):
    s = _segmented_store(tmp_path)
    _cp.checkpoint(s)
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.commit_prune(s, 10)                          # confirm defaults False (gate 2)
    assert "confirmation" in str(e.value)
    assert _seqs(s) == list(range(23)), "a refused prune drops nothing"


def test_commit_prune_requires_signed_head(tmp_path, isolated):
    s = _segmented_store(tmp_path)                          # NO checkpoint() — unsigned spine (gate 1)
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.commit_prune(s, 10, confirm=True)
    assert "signed head" in str(e.value)
    assert _seqs(s) == list(range(23))


def test_commit_prune_refuses_unsafe_boundary(tmp_path, isolated):
    s = _segmented_store(tmp_path)
    _cp.checkpoint(s)
    with pytest.raises(prune.PruneUnsafe):                  # K=7 is mid-segment (gate 3)
        prune.commit_prune(s, 7, confirm=True)
    assert _seqs(s) == list(range(23)), "an unsafe prune drops nothing"


def test_finish_prune_rolls_forward_after_head_commit(tmp_path, isolated):
    """Crash-recovery unit: the head has committed (base_seq=10) but the manifest/file GC has NOT run yet.
    `finish_prune()` must idempotently complete it — and a no-op the second time."""
    s = _segmented_store(tmp_path)
    _cp.checkpoint(s)
    # drive the cutover up to the commit, then STOP before rebase/GC (simulate a crash there).
    archived = prune.check_prune_safe(s, 10)
    snap_payload = prune.snapshot_payload(s, 10)
    prune.archive_copy(s, 10, snap_payload)
    snap_seq = prune._append_snapshot_idempotent(s, snap_payload)
    _cp.sign_pruned_head(s, base_seq=10, base_prev_hash=snap_payload["base_prev_hash"],
                         cumulative_merkle_root=snap_payload["cumulative_merkle_root"], snapshot_seq=snap_seq)
    # at this point the head says base_seq=10 but the manifest still holds [0..T]; verify still passes.
    assert _cp.verify_checkpoint(SpineStore(tmp_path / "spine.jsonl"))[0]

    s2 = SpineStore(tmp_path / "spine.jsonl")
    assert s2.finish_prune() is True                       # rolls the manifest forward + GCs the files
    assert s2.finish_prune() is False                      # idempotent — nothing left to do
    s3 = SpineStore(tmp_path / "spine.jsonl")
    assert _seqs(s3)[0] == 10 and s3.verify()[0] and _cp.verify_checkpoint(s3)[0]
    assert len(archived) >= 1
