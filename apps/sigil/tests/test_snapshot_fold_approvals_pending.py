"""Equivalence test for the hard-prune fold rewrite of `sigil.agents.approvals.pending`.

The consumer was rewired to seed empty and window the LIVE records `[base_seq..T]` from a folded
`SnapshotState` prefix (Slice C ships the EMPTY identity, so it is a full genesis scan today). This test
proves the rewrite is EXACTLY the old full scan:

  (A) IDENTITY — the current behavior (load -> empty): a crafted store returns the known-correct open
      queue; plus the referential-floor ASSERT (`open_queued_below_base` non-empty -> fail closed).
  (B) SPLIT   — the real proof: build a synthetic snapshot of the prefix `[0..K)` and monkeypatch
      `SnapshotState.load` to return it, so the consumer seeds that prefix + folds only the live
      `[K..T]` from the SAME store. `split == full` proves fold([0..K)) + fold([K..T]) == scan([0..T]).

Note on approvals specifically: the RESOLVED set is query-pubkey-dependent, so the snapshot carries NO
resolved/queued seed — only the (empty, under a valid prune) floor assert. The equivalence therefore
holds precisely when the referential-floor invariant holds (no OPEN queued item below K); the split
places an OPEN queued item at EXACTLY seq==base_seq so an off-by-one in the window (since_seq=base_seq
instead of base_seq-1) would drop it and break split==full — real teeth for the boundary.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_approvals_pending.py -q
"""
from __future__ import annotations

import os
import tempfile

import pytest

from sigil.agents.approvals import ApprovalError, ApprovalQueue, pending
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build as build_snapshot
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64

_QUEUED = {"decision": "queued", "status": "awaiting-approval"}


def _store() -> SpineStore:
    return SpineStore(tempfile.mktemp(suffix=".jsonl", dir=os.environ.get("SIGIL_HOME") or None))


def _queue(store: SpineStore, subject: str) -> int:
    """Append a genuine queued A2/A3 proposal record (mirrors agents.base's QUEUE write)."""
    return store.append(kind="draft", source="agents", actor="TESTER",
                        payload={**_QUEUED, "kind": "draft", "tier": "A2", "subject": subject})


def _approve(store: SpineStore, seq: int) -> int:
    """A genuine OWNER-signed approval that VERIFIES against OWNER_PUB (resolves the queued `seq`)."""
    return ApprovalQueue(store, owner_key=OWNER, trusted_pubkey_b64=OWNER_PUB).approve(seq)


# ---- shared fixture: a store whose queue spans a prune boundary ------------------------------------
def _spanning_store():
    """q1,q2 queued THEN resolved (all in the prefix); q3 queued at the eventual floor (base_seq) and q4
    above it, both left OPEN. Returns (store, K, open_seqs). The prefix carries real state that matters
    (two resolved queued pairs); the floor invariant holds (no OPEN queued below K)."""
    s = _store()
    s1 = _queue(s, "q1")
    s2 = _queue(s, "q2")
    _approve(s, s1)          # resolves q1  (prefix)
    _approve(s, s2)          # resolves q2  (prefix)
    s5 = _queue(s, "q3")     # OPEN — will sit at EXACTLY base_seq (the floor)
    s6 = _queue(s, "q4")     # OPEN — above the floor
    return s, s5, [s5, s6]


# ==================================================================================================
# (A) IDENTITY — current behavior under the empty snapshot (load -> empty identity)
# ==================================================================================================
def test_identity_returns_known_open_queue():
    s, _K, open_seqs = _spanning_store()
    got = [r.seq for r in pending(s, OWNER_PUB)]
    assert got == sorted(open_seqs), "pending must return exactly the OPEN queued items, oldest first"


def test_identity_forged_approval_does_not_resolve():
    s = _store()
    q = _queue(s, "q1")
    # an UNSIGNED/forged approval must NOT drop the item (fail-closed resolution).
    s.append(kind="event", source="agents", actor="attacker",
             payload={"signal": "governor.approval", "approval": "approved", "target_seq": q,
                      "approver": "attacker", "decision": "auto"})  # no valid sig/pubkey
    assert [r.seq for r in pending(s, OWNER_PUB)] == [q], "forged approval leaves the item pending"


def test_referential_floor_assert_fails_closed(monkeypatch):
    """If a committed snapshot ever carries OPEN queued item(s) below base_seq, pending() must fail
    closed rather than serve a truncated window. Directly exercises the new assert branch."""
    s, _K, _open = _spanning_store()
    violating = SnapshotState(base_seq=3, snapshot_seq=2, trusted_pubkey=OWNER_PUB,
                              open_queued_below_base=[{"seq": 1, "note": "still-open"}])
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: violating))
    with pytest.raises(ApprovalError):
        pending(s, OWNER_PUB)


# ==================================================================================================
# (B) SPLIT — the associativity proof: build(prefix) + consumer(live) == full scan
# ==================================================================================================
def test_split_prefix_fold_equals_full_scan(monkeypatch):
    s, K, _open = _spanning_store()

    full = pending(s, OWNER_PUB)                                  # real empty load -> scans [0..T]

    prefix = [r for r in s.iter_records() if r.seq < K]
    synthetic = build_snapshot(prefix, trusted_pubkey=OWNER_PUB, base_seq=K, snapshot_seq=K - 1)

    # --- the prefix must be NON-EMPTY and carry state that MATTERS (queued+approval records below K) ---
    assert K > 0, "base_seq must be > 0 or the split is a trivial full scan"
    assert prefix, "prefix must be non-empty"
    assert any(r.payload.get("decision") == "queued" for r in prefix), \
        "prefix must contain queued records the fold had to summarize"
    assert any(r.payload.get("signal") == "governor.approval" for r in prefix), \
        "prefix must contain resolving approvals (the state the fold associatively collapses)"
    # floor holds: build() does not populate the floor, and this construction leaves NO open queued
    # item below K (q1,q2 were resolved in the prefix), so the empty floor is CORRECT here.
    assert synthetic.open_queued_below_base == [], "no open queued item below the floor in this store"
    # boundary teeth: an OPEN queued item sits at EXACTLY base_seq, so it lives in the live window only
    # via since_seq==base_seq-1; an off-by-one would drop it.
    assert any(r.seq == K and r.payload.get("decision") == "queued" for r in s.iter_records()), \
        "an OPEN queued item must sit at exactly seq==base_seq to test the window boundary"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    split = pending(s, OWNER_PUB)                                 # seeds synthetic prefix + folds [K..T]

    assert [r.seq for r in split] == [r.seq for r in full], \
        "fold([0..K)) (via build) + fold([K..T]) (via consumer) must equal scan([0..T])"
    # the collapsed prefix items (resolved) must NOT resurface, and every surviving item is in the window
    assert all(r.seq >= K for r in split), "no sub-floor item may survive (they were resolved in prefix)"
