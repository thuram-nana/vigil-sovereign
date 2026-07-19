"""Equivalence proof for the hard-prune fold rewrite of `cmd_warden_anchor_get` (sigil/cli.py).

The consumer prints the highest WARDEN head ever anchored FOR A GIVEN pubkey as JSON {count, head_hash}.
Its state is a max-count / LWW-head_hash-on-tie (>=) semilattice keyed by the WARDEN pubkey. The rewrite
seeds that high-water from the folded pruned-prefix snapshot `[0..base_seq)` (`SnapshotState.warden_best_of`)
and then folds ONLY the live window `[base_seq..T]`.

Two tests, per the fold-rewrite doctrine:
  (A) IDENTITY — with the REAL (empty Slice-C) load, the rewired consumer returns the known-correct value
      over a crafted record set (multiple pubkeys, a lower-count, a tie, a non-warden record, an unknown
      pubkey). This pins the *current* behavior.
  (B) SPLIT — the real proof. With the SAME store, `full = consumer(store)` (real empty load, scans all).
      Fold the prefix `[0..K)` via `build()` into a synthetic snapshot, monkeypatch `SnapshotState.load`
      to return it, and `split = consumer(store)` (seeds the synthetic prefix + folds only live `[K..T]`).
      `assert split == full` proves fold([0..K)) + fold([K..T]) == scan([0..T]). K is chosen so the prefix
      carries the WINNING max for one key (never re-established in the live window — the seed is load-bearing,
      not green-washed), a prefix-ONLY key, and a cross-boundary TIE that exercises the `>=` LWW head_hash.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_warden_anchor_cli.py -q
"""
import json
from types import SimpleNamespace

import pytest

from sigil.config import FLOOR_PATH, HEAD_PATH
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

PK_A = "a" * 64          # max lives in the prefix, live window is strictly lower -> seed is REQUIRED
PK_B = "b" * 64          # anchored only in the prefix -> prefix-only state must survive
PK_C = "c" * 64          # tie across the split boundary -> exercises the `>=` LWW head_hash
PK_UNKNOWN = "d" * 64    # never anchored -> identity (0, "")

# Split point: prefix = seqs [0..K), live = seqs [K..T].
K = 6


def _anchor(store: SpineStore, count: int, head_hash: str, pubkey: str) -> None:
    # Mirrors cmd_warden_anchor_set's spine record exactly (minus the signature check, which the GET path
    # does not re-check — it trusts the chain+signed-head integrity gates it runs first).
    store.append(kind="warden_checkpoint", source="warden", actor="warden",
                 payload={"count": count, "head_hash": head_hash, "pubkey": pubkey})


def _populate(store: SpineStore) -> None:
    """A crafted record set exercising every fold branch. Seqs are assigned 0.. in append order."""
    _anchor(store, 5, "A5", PK_A)          # seq0
    _anchor(store, 100, "B100", PK_B)      # seq1  (prefix-only key)
    _anchor(store, 8, "C8-pre", PK_C)      # seq2  (tie candidate, prefix side)
    _anchor(store, 3, "A3", PK_A)          # seq3  (3 >= 5 is False -> ignored)
    _anchor(store, 8, "A8", PK_A)          # seq4  (A's WINNING max, in the prefix)
    store.append(kind="event", source="t", actor="u", payload={"note": "x"})  # seq5 (non-warden -> filtered)
    # --- split boundary at K=6: everything below is the LIVE window ---
    _anchor(store, 4, "A4-live", PK_A)     # seq6  (4 >= 8 False -> ignored; live re-max would be wrong)
    _anchor(store, 8, "C8-live", PK_C)     # seq7  (8 >= 8 True -> LWW tie wins over C8-pre)
    _anchor(store, 7, "A7-live", PK_A)     # seq8  (7 >= 8 False -> ignored)
    store.append(kind="event", source="t", actor="u", payload={"note": "y"})  # seq9 (non-warden -> filtered)


def _run(capsys, pubkey: str) -> dict:
    """Invoke the real consumer (it builds its own SpineStore() from SIGIL_HOME) and parse its JSON line."""
    from sigil.cli import cmd_warden_anchor_get
    cmd_warden_anchor_get(SimpleNamespace(pubkey=pubkey))
    out = capsys.readouterr().out.strip().splitlines()
    return json.loads(out[-1])


@pytest.fixture(autouse=True)
def _clean_home():
    """Isolate each test: the whole session shares one SIGIL_HOME, so start from an empty spine + no head
    (a stale head from a prior test could make verify_checkpoint report TAMPER and abort the consumer)."""
    SpineStore().reset()
    for p in (HEAD_PATH, FLOOR_PATH):
        p.unlink(missing_ok=True)
    yield
    SpineStore().reset()
    for p in (HEAD_PATH, FLOOR_PATH):
        p.unlink(missing_ok=True)


def test_identity_known_correct(capsys):
    """(A) With the REAL empty load, the rewired consumer returns the known-correct high-water per key."""
    store = SpineStore()
    _populate(store)

    assert _run(capsys, PK_A) == {"count": 8, "head_hash": "A8"}          # max in-log, ties/lowers handled
    assert _run(capsys, PK_B) == {"count": 100, "head_hash": "B100"}      # isolated per-key lineage
    assert _run(capsys, PK_C) == {"count": 8, "head_hash": "C8-live"}     # >= tie -> last writer wins
    assert _run(capsys, PK_UNKNOWN) == {"count": 0, "head_hash": ""}      # never anchored -> identity


def test_split_equals_scan(capsys, monkeypatch):
    """(B) The real proof: fold(prefix via build) + fold(live via consumer) == full genesis scan."""
    store = SpineStore()
    _populate(store)

    # full = the real empty-load consumer scanning ALL records [0..T].
    full_a = _run(capsys, PK_A)
    full_b = _run(capsys, PK_B)
    full_c = _run(capsys, PK_C)
    full_u = _run(capsys, PK_UNKNOWN)

    # Fold the prefix [0..K) into a synthetic snapshot, exactly as a real prune would have committed it.
    prefix = [r for r in store.iter_records() if r.seq < K]
    assert len(prefix) == K and prefix[-1].seq == K - 1        # sanity: prefix is NON-EMPTY and is [0..K)
    synthetic = build(prefix, trusted_pubkey="", base_seq=K, snapshot_seq=K - 1)

    # Sanity: the prefix carries state that MATTERS (not a trivially-passing split):
    #  - A's WINNING max (8/"A8") is entirely inside the prefix; the live window is strictly lower, so a
    #    seed-less (green-washed) scan of the live window alone would return 7, NOT 8.
    assert synthetic.warden_best_of(PK_A) == (8, "A8", 4)
    assert synthetic.warden_best_of(PK_B) == (100, "B100", 1)   # prefix-only key must live in the snapshot
    assert synthetic.warden_best_of(PK_C) == (8, "C8-pre", 2)   # tie seed the live [K..T] record ties against
    live_only_a = max((int(r.payload["count"]) for r in store.iter_records(since_seq=K - 1)
                       if r.kind == "warden_checkpoint" and r.payload.get("pubkey") == PK_A), default=0)
    assert live_only_a == 7 and full_a["count"] == 8            # seed is LOAD-BEARING: live-only != full

    # Redirect the consumer's load() to the synthetic prefix; it now seeds it and folds ONLY live [K..T].
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: synthetic))

    assert _run(capsys, PK_A) == full_a       # prefix max survives; live (4,7) correctly ignored
    assert _run(capsys, PK_B) == full_b       # prefix-only state survives with no live record
    assert _run(capsys, PK_C) == full_c       # cross-boundary `>=` tie: live C8-live wins, as in full scan
    assert _run(capsys, PK_UNKNOWN) == full_u  # identity seed + no live == full identity
