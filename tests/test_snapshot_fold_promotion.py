"""Equivalence proof for the SnapshotState-folded `PromotionPolicy.is_promoted` (hard-prune Slice C).

Proves fold == scan for the promotion bearer (LWW keep-revoked, pubkey-dependent):
  (A) IDENTITY — under the real empty load (no prune) the rewired consumer returns the known-correct
      value == the current genesis scan.
  (B) SPLIT — with the SAME store, split the records at K; build a synthetic prefix snapshot for [0..K)
      and monkeypatch it into load(); the consumer then seeds the prefix + folds only the live [K..T].
      assert split == full for every query  ⇒  fold([0..K)) + fold([K..T]) == scan([0..T]).

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_promotion.py -q
"""
import tempfile

from sigil.governor.promotion import PromotionPolicy
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64

# Queries and their KNOWN-CORRECT promotion state (the current genesis-scan semantics).
EXPECTED = {
    ("SCHOLAR", "draft"): True,    # granted in prefix, never touched  -> prefix state is LOAD-BEARING
    ("SCHOLAR", "report"): False,  # SCHOLAR granted only for "draft", no wildcard
    ("ARTIFICER", "wire"): False,  # granted then REVOKED (LWW keep-revoked, live overrides prefix)
    ("TESTER", "code"): True,      # revoked in prefix then RE-GRANTED live (live overrides prefix)
    ("BASTION", "anything"): True, # wildcard "*" grant -> promoted for any scope via (agent,"*")
    ("EVIL", "draft"): False,      # forged/unsigned grant -> fail-closed, grants nothing
    ("NOONE", "x"): False,         # never mentioned
    ("ENVOY", "*"): False,         # structural NO_PROMOTION early-return
}


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _populate(store):
    """Append the crafted record set. Returns the split seq K such that the prefix (seq < K) is
    NON-EMPTY and carries promotion state that MATTERS (a live-untouched grant, a soon-revoked grant,
    a soon-regranted revoke). Live window (seq >= K) then overrides/extends it."""
    pol = PromotionPolicy(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    # ---- prefix [0..K): three signed governance events that all matter downstream ----
    pol.grant("SCHOLAR", "draft")     # never touched again -> discriminator: only a seeded prefix yields True
    pol.grant("ARTIFICER", "wire")    # revoked below the split
    pol.revoke("TESTER", "code")      # re-granted below the split
    k = store.append(kind="event", source="governor", actor="WARDEN",   # marks the split boundary K
                     payload={"signal": "marker"})                        # inert (no promotion signal)
    # ---- live [K..T): overrides + extensions + a forged grant that must be ignored ----
    pol.revoke("ARTIFICER", "wire")   # LWW: overrides the prefix grant
    pol.grant("TESTER", "code")       # LWW: overrides the prefix revoke
    pol.grant("BASTION", "*")         # wildcard grant
    store.append(kind="event", source="governor", actor="WARDEN",        # forged, unsigned -> ignored
                 payload={"signal": "governor.promotion", "state": "granted",
                          "agent": "EVIL", "scope": "draft"})
    return k


def _consumer(store):
    return PromotionPolicy(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


# ---- (A) IDENTITY: rewired consumer under the real empty load == known-correct genesis scan --------
def test_identity_empty_load_matches_known_correct():
    store = _store()
    _populate(store)
    # sanity: with no prune, load() is the empty identity (a genuine full scan, not a truncated window)
    assert SnapshotState.load(store).base_seq == 0
    pol = _consumer(store)
    for (agent, scope), want in EXPECTED.items():
        assert pol.is_promoted(agent, scope) is want, f"{agent}/{scope} expected {want}"


# ---- (B) SPLIT: build(prefix) + consumer(live) == scan(all) ----------------------------------------
def test_split_fold_equals_full_scan(monkeypatch):
    store = _store()
    k = _populate(store)

    # full = the real (empty-load) genesis scan over the WHOLE store
    full = {q: _consumer(store).is_promoted(*q) for q in EXPECTED}

    # prefix = records strictly below K; fold them with build() into a synthetic prefix snapshot
    prefix = [r for r in store.iter_records() if r.seq < k]
    assert len(prefix) >= 3, "prefix must be non-empty and carry real state"
    synthetic = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)

    # the prefix snapshot must be NON-TRIVIAL: it carries the load-bearing grants/revokes
    pm = synthetic.promotion_map()
    assert synthetic.base_seq == k
    assert pm.get(("SCHOLAR", "draft")) == "granted"    # the discriminator lives ONLY in the prefix
    assert pm.get(("ARTIFICER", "wire")) == "granted"   # (overridden live)
    assert pm.get(("TESTER", "code")) == "revoked"      # (overridden live)
    assert synthetic.trusted_pubkey == OWNER_PUB        # so the consumer takes the fold (non-bypass) path

    # seed the synthetic prefix + fold ONLY the live window [K..T] from the SAME store
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: synthetic))
    split = {q: _consumer(store).is_promoted(*q) for q in EXPECTED}

    assert split == full, f"fold != scan\n full={full}\n split={split}"
    # and both equal the independently-known-correct table (no green-wash: SCHOLAR/draft True proves
    # the seed was actually consumed — dropping the seed would make it False here while full stays True)
    assert full == {q: v for q, v in EXPECTED.items()}
