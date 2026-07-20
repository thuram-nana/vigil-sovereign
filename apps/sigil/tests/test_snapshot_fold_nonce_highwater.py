"""Hard-prune fold equivalence for `device_nonce_highwater` (bridge/envelope.py).

Proves the rewired consumer — which SEEDS from `SnapshotState.load(store).nonce_highwater` and then folds
only the LIVE window `iter_records(since_seq=base_seq-1)` — is EXACTLY equal to the old genesis full scan,
for any prune point. `nonce_highwater` is a device-keyed MAX (a join-semilattice), so
`fold(fold(empty,[0..K)),[K..T]) == fold(empty,[0..T])`.

  (A) IDENTITY — real (empty Slice-C) load: the rewired consumer returns the KNOWN-CORRECT high-water.
  (B) SPLIT — build a synthetic prefix snapshot at a middle K, monkeypatch load to return it, and assert
      seed([0..K)) + fold([K..T]) == scan([0..T]) for every device. K is chosen so the prefix carries the
      MAX for one device (seed load-bearing) AND the live window carries the MAX for another (live fold
      load-bearing) — neither side is trivially droppable.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_nonce_highwater.py -q
"""
import tempfile

from sigil.bridge import RECEIPT_SIGNAL, device_nonce_highwater
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
TP = OWNER.public_key_b64                                   # the trusted_pubkey build() is folded under

DEV_A = generate_keypair().public_key_b64                  # MAX lands in the PREFIX (seed load-bearing)
DEV_B = generate_keypair().public_key_b64                  # MAX lands in the LIVE window (live-fold load-bearing)
DEV_C = generate_keypair().public_key_b64                  # appears ONLY in the live window (seed default -1)
DEV_D = generate_keypair().public_key_b64                  # appears ONLY in the prefix (returns the seed)
DEV_Z = generate_keypair().public_key_b64                  # never receipted (highwater -1)

# K splits the log after seq 5. Prefix [0..5] carries A:{1,5}->5, B:{2,1}->2, D:{4}->4; live [6..11]
# carries A:{3,None,"nan"}, B:{9}, C:{0,2}. Full maxes: A=5, B=9, C=2, D=4, Z=-1.
SPLIT_K = 6
EXPECTED = {DEV_A: 5, DEV_B: 9, DEV_C: 2, DEV_D: 4, DEV_Z: -1}


def _receipt(store: SpineStore, device: str, nonce) -> int:
    """Append a genuine consumption receipt (the RECEIPT_SIGNAL record device_nonce_highwater folds)."""
    return store.append(kind="event", source="mesh", actor="DEVICE",
                        payload={"signal": RECEIPT_SIGNAL, "device": device, "nonce": nonce,
                                 "action": "panic", "ts": 1700000000, "tier": "A0", "decision": "auto"})


def _populated_store() -> SpineStore:
    """A store whose receipts exercise: max-over-out-of-order nonces, a None-nonce skip, a non-int-nonce
    skip, a non-receipt record the filter ignores, and four devices spanning the split boundary."""
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _receipt(s, DEV_A, 1)                                  # seq 0
    _receipt(s, DEV_D, 4)                                  # seq 1  (D: prefix-only)
    _receipt(s, DEV_B, 2)                                  # seq 2
    s.append(kind="event", source="mesh", actor="DEVICE",  # seq 3  non-receipt NOISE (ignored by the filter)
             payload={"signal": "mesh.other", "device": DEV_A, "nonce": 999})
    _receipt(s, DEV_A, 5)                                  # seq 4  A's MAX (in the PREFIX)
    _receipt(s, DEV_B, 1)                                  # seq 5  lower than B=2 -> max stays 2
    # ---- SPLIT_K = 6 : prefix is seq [0..5], live is seq [6..T] ----
    _receipt(s, DEV_A, 3)                                  # seq 6  live, < seed 5 -> A stays 5
    _receipt(s, DEV_B, 9)                                  # seq 7  B's MAX (in the LIVE window)
    _receipt(s, DEV_C, 0)                                  # seq 8  C live-only, first nonce 0
    _receipt(s, DEV_A, None)                               # seq 9  None nonce -> skipped
    _receipt(s, DEV_A, "not-an-int")                       # seq 10 non-int nonce -> skipped (ValueError)
    _receipt(s, DEV_C, 2)                                  # seq 11 C live, max -> 2
    return s


# ---- (A) IDENTITY: real empty Slice-C load -> full genesis scan yields the known-correct high-water ----
def test_identity_known_correct_highwater():
    s = _populated_store()
    for dev, want in EXPECTED.items():
        assert device_nonce_highwater(s, dev) == want, f"device {dev[:8]} high-water must be {want}"


# ---- (B) SPLIT: build(prefix) [via SnapshotState.build] + fold(live) [via the consumer] == full scan ----
def test_split_fold_equals_full_scan(monkeypatch):
    s = _populated_store()

    # full = the real (empty-load) genesis scan over [0..T].
    full = {dev: device_nonce_highwater(s, dev) for dev in EXPECTED}
    assert full == EXPECTED, "the full scan must match the known-correct values"

    # Synthesize the pruned-prefix snapshot by folding ONLY [0..K) with the real build() folder.
    prefix = [r for r in s.iter_records() if r.seq < SPLIT_K]
    synthetic = build(prefix, trusted_pubkey=TP, base_seq=SPLIT_K, snapshot_seq=SPLIT_K - 1)

    # Sanity: the prefix is NON-EMPTY and carries state that MATTERS (not a trivially-passing K).
    assert len(prefix) == SPLIT_K, "prefix must be the non-empty [0..K) window"
    assert synthetic.base_seq == SPLIT_K
    assert synthetic.nonce_highwater == {DEV_A: 5, DEV_B: 2, DEV_D: 4}, \
        "the prefix snapshot must carry A's MAX (5), B's partial (2) and D-only (4)"
    # A's overall MAX (5) lives in the prefix while A's LIVE-only max is only 3 -> the seed is LOAD-BEARING:
    # a seedless (live-only) fold would return 3, not 5.
    assert synthetic.nonce_highwater[DEV_A] == 5 and full[DEV_A] == 5

    # Rewire load() to return the synthetic prefix; the consumer now seeds it + folds only live [K..T].
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    split = {dev: device_nonce_highwater(s, dev) for dev in EXPECTED}

    assert split == full, "fold([0..K) via build) + fold([K..T] via consumer) must equal the full scan"


# ---- anti-green-wash guard: the prefix seed genuinely changes the answer (dropping it would fail) ----
def test_seed_is_load_bearing(monkeypatch):
    """If the consumer ignored the snapshot seed and folded only the live window, DEV_A would read 3 (its
    live-only max), not 5. This test pins that the seed is what makes the split correct."""
    s = _populated_store()
    prefix = [r for r in s.iter_records() if r.seq < SPLIT_K]
    synthetic = build(prefix, trusted_pubkey=TP, base_seq=SPLIT_K, snapshot_seq=SPLIT_K - 1)

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    a_with_seed = device_nonce_highwater(s, DEV_A)

    # Fold the SAME live window with an EMPTY seed (base_seq=K, empty nonce_highwater) -> the seedless answer.
    empty_prefix_state = SnapshotState(base_seq=SPLIT_K, snapshot_seq=SPLIT_K - 1, trusted_pubkey=TP)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: empty_prefix_state))
    a_seedless = device_nonce_highwater(s, DEV_A)

    assert a_with_seed == 5 and a_seedless == 3, \
        "the seed must lift DEV_A from its live-only max (3) to its true max (5) — the seed is load-bearing"


if __name__ == "__main__":                                 # allow direct execution too
    import sys

    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
