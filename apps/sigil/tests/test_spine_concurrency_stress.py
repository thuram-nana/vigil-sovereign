"""W11-5 (#486) — concurrency stress + race detection for the ONE spine two engagements share.

The spine (``apps/sigil/sigil/spine/store.py``) is a single append-only hash chain. In production more
than one *engagement* (a logical actor/session — the bridge server, the gesture daemon, a governed
``engage`` run) can be live at once against the SAME ``SIGIL_HOME`` spine: they append concurrently and
read concurrently, and rotation/compaction rewrites segments underneath both. This file is the
concurrency harness the W11-5 acceptance criteria call for:

  1. A **concurrent-engagement** test drives TWO engagements against ONE spine and asserts correctness:
     one contiguous chain 0..N-1 (no fork / gap / duplicate), ``verify()`` green, and every record
     correctly ATTRIBUTED to the engagement that wrote it (no cross-log — the #532 concern, checked on
     the plaintext ``actor``/``source`` metadata so it needs no vault/DEK).

  2. A **deterministic C-1 (#392) interleaving**: an engagement reading the spine while another
     engagement's compaction commits the next manifest generation and unlinks the plaintext it
     superseded. Pre-fix (the PARENT of the #392 fix, commit a00bac4e) this raises
     ``SpineError('… references a missing segment …')`` — the harness CATCHES the race. Post-fix the
     generation-aware resolver (``SpineStore._resolve_segments``) turns the supersession into a bounded
     retry and the scan completes. See RED-PEN-BRIEF.md for the exact parent-commit repro command.

  3. A **negative control** in the same run: a segment that is genuinely gone at an UNCHANGED manifest
     generation still fails CLOSED and loudly (invariant 15). This proves the harness's compaction
     tolerance is not a blanket "swallow every read error" no-op — it still detects real loss.

Repeat/stress: the threaded test loops ``SIGIL_STRESS_ITERS`` times (default 3 — deterministic and fast
for the required ``sigil-governor`` job; the scheduled heavy job cranks it up). The CI also repeats the
whole file via a shell loop (pytest-xdist/pytest-repeat are not in the pinned hash-lock, so repetition is
driven WITHOUT a plugin — see .github/workflows/ci.yml sigil-governor and .github/workflows/concurrency-race.yml).

Run locally:  PYTHONPATH=apps/sigil python -m pytest apps/sigil/tests/test_spine_concurrency_stress.py -q
"""
from __future__ import annotations

import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

from sigil.spine.store import SpineError, SpineStore

STRESS_ITERS = int(os.environ.get("SIGIL_STRESS_ITERS", "3"))
# per-engagement records; small enough to be fast, large enough (with seg_max_records below) to force
# several seals + compactions and thus a live rotation window for readers to race.
_PER_ENGAGEMENT = int(os.environ.get("SIGIL_STRESS_PER", "60"))
_SEG_RECORDS = 5


def _fresh_dir(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def _migrated_store(d: Path) -> tuple[Path, SpineStore]:
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=_SEG_RECORDS)
    s.migrate()                                            # segmented from record 0
    return p, s


# --------------------------------------------------------------------------------------------------
# (1) TWO engagements, ONE spine — concurrent writers + readers + compaction, asserted correct.
# --------------------------------------------------------------------------------------------------
def _drive_two_engagements(p: Path, per: int) -> list[str]:
    """Two writer engagements (A, B), a compactor engagement (C), and two readers — all on ONE spine.
    Each engagement uses its OWN SpineStore instance on the shared path (the realistic multi-instance
    case: the in-process RLock is path-keyed and the flock is cross-process, so both must serialise the
    write-tip). Returns a list of observed correctness violations (empty == clean)."""
    errors: list[str] = []
    stop = threading.Event()

    def writer(tag: str) -> None:
        w = SpineStore(p, seg_max_bytes=0, seg_max_records=_SEG_RECORDS)
        for i in range(per):
            try:
                w.append(kind="event", source=f"eng-{tag}", actor=f"actor-{tag}",
                         payload={"eng": tag, "i": i})   # "eng"/"i" are NOT content fields -> no DEK/vault
            except Exception as e:                        # noqa: BLE001 — any append failure is a violation
                errors.append(f"writer {tag}: {e!r}")
                return

    def compactor() -> None:
        c = SpineStore(p, seg_max_bytes=0, seg_max_records=_SEG_RECORDS)
        while not stop.is_set():
            try:
                c.compact()
            except Exception as e:                        # noqa: BLE001
                errors.append(f"compactor: {e!r}")
                return
            time.sleep(0.002)

    def reader() -> None:
        r = SpineStore(p)
        while not stop.is_set():
            try:
                seqs = [rec.seq for rec in r.iter_records()]
            except Exception as e:                        # noqa: BLE001 — ENOENT / SpineError under a
                errors.append(f"reader: {e!r}")           # benign compaction is exactly the C-1 race
                return
            if seqs != list(range(len(seqs))):
                errors.append(f"reader saw a non-contiguous chain: {seqs[:3]}..{seqs[-3:]}")
                return

    threads = [
        threading.Thread(target=writer, args=("A",)),
        threading.Thread(target=writer, args=("B",)),
        threading.Thread(target=compactor),
        threading.Thread(target=reader),
        threading.Thread(target=reader),
    ]
    for t in threads:
        t.start()
    # let the writers finish, then stop the endless reader/compactor loops
    threads[0].join(timeout=30)
    threads[1].join(timeout=30)
    stop.set()
    for t in threads[2:]:
        t.join(timeout=30)
    if any(t.is_alive() for t in threads):
        errors.append("a thread did not finish within the timeout (possible deadlock/livelock)")
    return errors


def test_two_engagements_one_spine_stay_contiguous_and_attributed():
    """CONCURRENT-ENGAGEMENT correctness (AC-1). Two engagements append to one spine while a third
    compacts and readers scan; afterwards the chain is one contiguous verified sequence and EVERY record
    is attributed to the engagement that wrote it — no fork, no gap, no duplicate, no cross-log (#532)."""
    for it in range(STRESS_ITERS):
        d = _fresh_dir(f"sigil-2eng-{it}-")
        p, _s = _migrated_store(d)
        errors = _drive_two_engagements(p, _PER_ENGAGEMENT)
        assert not errors, f"iter {it}: concurrency violations: {errors[:3]}"

        final = SpineStore(p)
        ok, reason = final.verify()
        assert ok, f"iter {it}: verify() failed after concurrent engagements: {reason}"

        recs = list(final.iter_records())
        seqs = [r.seq for r in recs]
        assert seqs == list(range(2 * _PER_ENGAGEMENT)), (
            f"iter {it}: chain not contiguous 0..{2 * _PER_ENGAGEMENT - 1}: "
            f"len={len(seqs)} head={seqs[:3]} tail={seqs[-3:]}")
        assert len(seqs) == len(set(seqs)), f"iter {it}: duplicate seq (a forked chain): {seqs}"

        # No cross-log (#532): each record's PLAINTEXT actor/source is exactly the writer's, and each
        # engagement contributed EXACTLY its number of records — nothing lost, nothing mislabelled.
        by_actor: dict[str, int] = {}
        for r in recs:
            assert r.actor in ("actor-A", "actor-B"), f"iter {it}: cross-log — stray actor {r.actor!r}"
            assert r.source == ("eng-A" if r.actor == "actor-A" else "eng-B"), (
                f"iter {it}: cross-log — actor {r.actor!r} carries source {r.source!r}")
            by_actor[r.actor] = by_actor.get(r.actor, 0) + 1
        assert by_actor == {"actor-A": _PER_ENGAGEMENT, "actor-B": _PER_ENGAGEMENT}, (
            f"iter {it}: per-engagement record counts wrong (loss or cross-log): {by_actor}")


# --------------------------------------------------------------------------------------------------
# (2) The C-1 (#392) reader/compaction TOCTOU — driven DETERMINISTICALLY (fails on the PARENT commit).
# --------------------------------------------------------------------------------------------------
def _compact_inside_the_resolve_window(monkeypatch, p: Path, *, skip: int = 0) -> dict:
    """Force the exact C-1 interleaving with no reliance on the scheduler: immediately after the read
    path takes its manifest snapshot (the first ``read_manifest`` past ``skip``), run a COMPLETE
    compaction — which commits generation G+1 and then unlinks every superseded plaintext — so the reader
    is left holding a stale generation-G view whose files are gone. The store under test must be built
    BEFORE arming this (a constructor read would otherwise burn the shot). Mirrors the deterministic
    driver in test_spine_rotation.py so this harness has proven C-1 sensitivity."""
    from sigil.spine import store as store_mod
    real_read = store_mod.read_manifest
    state = {"reads": 0, "fired": 0}

    def racing_read(layout):
        m = real_read(layout)                              # the reader engagement's snapshot (BEFORE compact)
        state["reads"] += 1
        if (state["fired"] == 0 and state["reads"] > skip and m is not None
                and any(sg.sealed and sg.codec == "none" for sg in m.segments)):
            state["fired"] = 1                             # set first: compact()'s own reads must not re-fire
            SpineStore(p).compact()                        # engagement C: commits gen+1, THEN unlinks
        return m

    monkeypatch.setattr(store_mod, "read_manifest", racing_read)
    return state


def _segmented_two_engagement_spine(prefix: str, per: int = 11) -> Path:
    """Engagement A writes 2*per records to a fresh spine, sealing 4 plaintext segments + an active."""
    d = _fresh_dir(prefix)
    p, a = _migrated_store(d)
    for i in range(per):
        a.append(kind="event", source="eng-A", actor="actor-A", payload={"eng": "A", "i": i})
    for i in range(per):
        a.append(kind="event", source="eng-B", actor="actor-B", payload={"eng": "B", "i": i})
    return p


@pytest.mark.parametrize("read_call", ["iter", "tail", "get"])
def test_concurrent_engagement_read_survives_compaction_supersession(monkeypatch, read_call):
    """FAIL-WITHOUT-FIX + C-1 SENSITIVITY (AC-3). Engagement R reads the spine at generation G; engagement
    C's compaction commits G+1 and unlinks the plaintext G named, inside R's resolve window. R must
    RE-RESOLVE and return the full contiguous chain — it must NOT raise 'references a missing segment'.
    On the PARENT of the #392 fix this raises deterministically for every read path; post-fix it passes."""
    p = _segmented_two_engagement_spine(f"sigil-c1-2eng-{read_call}-")
    r = SpineStore(p)                                      # construct BEFORE arming (see helper note)
    skip = 1 if read_call == "get" else 0                 # get() reads the manifest once for its change-token
    state = _compact_inside_the_resolve_window(monkeypatch, p, skip=skip)

    if read_call == "iter":
        got = [rec.seq for rec in r.iter_records()]
        assert got == list(range(22)), f"iter_records must stay a contiguous chain from genesis: {got}"
    elif read_call == "tail":
        got = [rec.seq for rec in r.tail(12)]
        assert got == list(range(10, 22)), f"tail window must be contiguous and complete: {got}"
    else:  # get
        rec = r.get(7)
        assert rec is not None and rec.seq == 7, f"get(7) must resolve past the supersession: {rec}"

    assert state["fired"] == 1, "the C-1 interleaving never fired — the test would be VACUOUS"


# --------------------------------------------------------------------------------------------------
# (3) NEGATIVE CONTROL — the harness still detects GENUINE loss (it is not a swallow-everything no-op).
# --------------------------------------------------------------------------------------------------
def test_genuine_segment_loss_still_raises_under_concurrent_engagements():
    """NEGATIVE CONTROL (AC-3, the half that must NOT be tolerated). If a sealed segment is genuinely gone
    while the manifest generation is UNCHANGED, that is real corruption — every read path an engagement
    might use must STILL fail closed and loudly (invariant 15), naming the missing segment, not silently
    yielding a short chain and not blaming 'churn'. This proves the compaction-tolerance above cannot mask
    real loss."""
    p = _segmented_two_engagement_spine("sigil-c1-2eng-neg-")
    gen_before = SpineStore(p).generation()

    # unlink a SEALED segment (seg-00000001.jsonl) with NO manifest swap: the live manifest still names it.
    seg = p.parent / "spine.segments" / "seg-00000001.jsonl"
    assert seg.exists(), f"expected sealed plaintext segment to exist: {seg}"
    seg.unlink()

    for label, call in (("iter_records", lambda: list(SpineStore(p).iter_records())),
                        ("tail", lambda: SpineStore(p).tail(6)),
                        ("count", lambda: SpineStore(p).count()),
                        ("verify", lambda: SpineStore(p).verify())):
        with pytest.raises(SpineError) as ei:
            call()
        msg = str(ei.value)
        assert "references a missing segment" in msg and "seg-00000001.jsonl" in msg, f"{label}: {msg}"
        assert "kept moving" not in msg and "kept changing" not in msg, (
            f"{label}: genuine loss must NOT be reported as compaction churn: {msg}")
    assert SpineStore(p).generation() == gen_before, "a failed read must not mutate the manifest generation"
