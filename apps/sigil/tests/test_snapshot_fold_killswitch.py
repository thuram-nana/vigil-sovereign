"""Equivalence proof for the hard-prune fold of the kill-switch latch consumer
(`KillSwitch._scan_engaged`, sigil/governor/killswitch.py).

The consumer used to full-scan the spine from genesis, folding an ASSOCIATIVE last-write latch
(engage=any halts; a release un-halts ONLY if owner-signed and it verifies). It now seeds that latch
from the folded snapshot prefix `[0..base_seq)` (`SnapshotState.load`) and folds only the LIVE window
`[base_seq..T]`. This test proves the rewired consumer is byte-identical to the old genesis scan:

  (A) IDENTITY — under the real (empty, Slice-C) load, the consumer returns the KNOWN-CORRECT verdict
      for a crafted engage/forged-release/signed-release/tie sequence.
  (B) SPLIT — the real proof: with the SAME store, full = consumer(load->empty scans [0..T]). Monkeypatch
      load to a SYNTHETIC prefix snapshot `build([0..K))` and assert consumer (now seeds prefix + folds
      only [K..T]) == full. i.e. fold([0..K)) [build] ∘ fold([K..T]) [consumer] == scan([0..T]).
  (C) PUBKEY-DEPENDENCE — a snapshot folded under a DIFFERENT trusted pubkey is BYPASSED (genesis rescan),
      because a release's honoring is pubkey-dependent and the folded latch is invalid under another anchor.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_killswitch.py -q
"""
import tempfile

from sigil.governor.killswitch import SIGNAL, KillSwitch
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _ks(store):
    """The reader/consumer under the established owner trust anchor."""
    return KillSwitch(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def _noise(store, text):
    return store.append(kind="message", source="t", actor="u", payload={"text": text})


def _forged_release(store):
    """An UNSIGNED release — must NEVER un-halt (fail-closed)."""
    return store.append(kind="event", source="governor", actor="WARDEN",
                        payload={"signal": SIGNAL, "state": "released"})


# ---------------------------------------------------------------------------------------------------
# (A) IDENTITY — the rewired consumer returns the known-correct verdict (current empty-load behavior).
# ---------------------------------------------------------------------------------------------------
def test_identity_known_correct_verdict():
    s = _store()
    writer = _ks(s)
    _noise(s, "seed")                    # seq0 non-killswitch noise
    writer.engage(reason="drill")        # seq1 engaged -> True
    writer.release(reason="all clear")   # seq2 owner-signed release -> False
    _forged_release(s)                   # seq3 forged release -> IGNORED (stays False)
    writer.engage(reason="drill2")       # seq4 engaged -> True
    _forged_release(s)                   # seq5 forged release -> IGNORED (stays True, fail-closed)
    _noise(s, "tail")                    # seq6 noise
    # last real state-change is the seq4 engage; the seq5 forged release cannot un-halt.
    assert _ks(s)._scan_engaged() is True, "engage stands; a forged release can never revive the mesh"

    # a subsequent OWNER-SIGNED release does un-halt.
    writer.release(reason="stand down")  # seq7 signed release -> False
    assert _ks(s)._scan_engaged() is False, "an owner-signed release un-halts (fail-closed honored)"

    # is_engaged() (the change-token cache wrapper) agrees with the underlying scan.
    assert _ks(s).is_engaged() is False


# ---------------------------------------------------------------------------------------------------
# (B) SPLIT — fold(prefix) ∘ fold(live) == full genesis scan, for a split whose prefix state MATTERS.
# ---------------------------------------------------------------------------------------------------
def _seed_store():
    """A store whose FINAL verdict is decided by a record in the prefix and NOT re-decided in the live
    window at the load-bearing split — so dropping the seed would flip the answer (no green-wash)."""
    s = _store()
    writer = _ks(s)
    _noise(s, "seed")                    # seq0 noise
    writer.engage(reason="a")            # seq1 engaged -> True
    writer.release(reason="b")           # seq2 signed release -> False
    writer.engage(reason="c")            # seq3 engaged -> True   <-- LAST real state-change
    _noise(s, "d")                       # seq4 noise
    _forged_release(s)                   # seq5 forged release -> IGNORED
    _noise(s, "e")                       # seq6 noise
    return s


def _prefix(store, K):
    return [r for r in store.iter_records() if r.seq < K]


def _synthetic(store, K, *, trusted_pubkey=OWNER_PUB):
    return build(_prefix(store, K), trusted_pubkey=trusted_pubkey,
                 base_seq=K, snapshot_seq=K - 1)


def test_split_prefix_seed_is_load_bearing(monkeypatch):
    s = _seed_store()
    full = _ks(s)._scan_engaged()        # real empty load -> scans [0..T]
    assert full is True, "the seq3 engage is the last real state-change -> engaged"

    K = 4                                 # prefix [0..3] fixes engaged=True; live [4..6] = noise + forged only
    synthetic = _synthetic(s, K)
    # prove the split is meaningful: prefix non-empty, its folded latch is the non-trivial True state, and
    # the LIVE window carries NO engage — so an empty seed would (wrongly) yield False. The seed is load-bearing.
    assert len(_prefix(s, K)) == K, "prefix is non-empty"
    assert synthetic.killswitch_engaged is True, "the folded prefix latch is a NON-TRIVIAL True"
    live = [r for r in s.iter_records(since_seq=K - 1)]
    assert all(r.payload.get("state") != "engaged" for r in live), \
        "live window has no engage -> without the seed the fold would yield False (proves seed matters)"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    split = _ks(s)._scan_engaged()        # seeds synthetic prefix + folds only live [K..T]
    assert split == full, "fold(prefix) ∘ fold(live) must equal the full genesis scan"
    assert split is True


def test_split_live_window_overrides_seed(monkeypatch):
    """The complementary direction: a split whose LIVE window re-decides the latch (a signed release then a
    re-engage) must override the seed. Proves the live fold does real work, not just carries the seed."""
    s = _seed_store()
    full = _ks(s)._scan_engaged()
    assert full is True

    K = 2                                 # prefix [0..1] fixes engaged=True; live [2..6] flips False then True
    synthetic = _synthetic(s, K)
    assert synthetic.killswitch_engaged is True, "prefix seeds True..."
    live = [r for r in s.iter_records(since_seq=K - 1)]
    assert any(r.payload.get("signal") == SIGNAL and r.payload.get("state") == "released" for r in live), \
        "...but the live window contains a (signed) release that flips it before the seq3 re-engage"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    split = _ks(s)._scan_engaged()
    assert split == full, "the live fold overrides the seed and still equals the full scan"


# ---------------------------------------------------------------------------------------------------
# (C) PUBKEY-DEPENDENCE — a snapshot folded under a foreign anchor is BYPASSED (genesis rescan).
# ---------------------------------------------------------------------------------------------------
def test_foreign_pubkey_snapshot_is_bypassed(monkeypatch):
    """The latch is pubkey-dependent (a release un-halts only under the anchor it verifies against). A
    snapshot folded under a DIFFERENT owner pubkey MUST NOT be trusted: bypass -> full genesis rescan."""
    s = _store()
    writer = _ks(s)
    writer.engage(reason="halt")         # seq0 engaged -> True (genesis truth: engaged)
    full = _ks(s)._scan_engaged()
    assert full is True

    # a hostile/rotated-anchor snapshot claims engaged=False under a FOREIGN pubkey.
    other = generate_keypair().public_key_b64
    poisoned = SnapshotState(base_seq=99, killswitch_engaged=False, trusted_pubkey=other)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: poisoned))
    # reader anchor (OWNER_PUB) != poisoned.trusted_pubkey -> BYPASS -> genesis rescan -> real verdict.
    assert _ks(s)._scan_engaged() is True, \
        "a snapshot under a foreign anchor is bypassed; the folded (False) latch cannot un-halt the mesh"
