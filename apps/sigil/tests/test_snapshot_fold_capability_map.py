"""Equivalence proof for the hard-prune rewiring of `capability_map` (sigil/mesh/registry.py).

The consumer used to full-scan the spine from genesis to compute the latest owner-VERIFIED capability
per host_id (right-biased last-write-wins). It now seeds from `SnapshotState.load(store).capability_map`
(the folded summary of the pruned prefix `[0..base_seq)`) and folds only the LIVE records `[base_seq..T]`.

`capability_map` is persisted as a LIST-of-rows (`[[host_id, cap], ...]`) — NOT a dict — precisely so a
non-str host_id key that an owner-signed-but-malformed record can carry (`host_id=None`/int) round-trips
VERBATIM: the live scan keys on `p.get("host_id")` with no type guard, so a snapshot that silently dropped
such a key would make `build() != scan`. `dict(st.capability_map)` reconstructs the map (incl. any non-str key).

This test proves the rewrite is behaviour-preserving, two ways:
  (A) IDENTITY — under the real (empty, Slice-C) snapshot the rewired consumer returns the known-correct
      value: base_seq==0 => since_seq==-1 (a full genesis scan) + empty seed => byte-identical to the old scan.
  (B) SPLIT — the real proof of associativity. With the SAME store, split the record stream at K:
      build a synthetic prefix snapshot over `[0..K)` via `SnapshotState.build`, monkeypatch `load` to
      return it, and assert `consumer(store)` (which now seeds the synthetic prefix and folds live `[K..T]`)
      equals the full genesis scan. K is chosen so the prefix carries state that MATTERS:
        - `desk` is advertised ONLY in the prefix (never re-advertised live) — its final value can come
          ONLY from the snapshot seed, so a broken seed would drop it.
        - a `None` host_id is advertised (owner-signed) ONLY in the prefix — a NON-STRING key whose final
          value can come ONLY from the seed. This is the case the list-of-rows persisted form exists for:
          it proves build() keeps a non-str key exactly as the type-guardless scan does (build()==scan).
        - `laptop` is advertised in the prefix (has_camera=False) AND re-advertised live (has_camera=True)
          — the LWW must overwrite ACROSS the fold seam, proving the seam is right-biased.
  Plus the pubkey-BYPASS rule (registry rewrite rule 4): a query under a DIFFERENT trust anchor than the
  one the snapshot was folded with must IGNORE the snapshot and re-scan from genesis.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_capability_map.py -q
"""
import tempfile

from sigil.governor.authn import signed_payload
from sigil.mesh.registry import CAP_SIGNAL, advertise_capability, capability_map
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
AP = ATTACKER.public_key_b64

K = 4   # split point: prefix = seq [0,1,2,3], live = seq [4,5,6]


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _advertise(store, host_id, *, os_, camera):
    """An owner-SIGNED capability advertisement (verifies under OP). host_id passes through VERBATIM —
    `advertise_capability` does not coerce it, so a non-str host_id (None/int) is signed and kept as-is."""
    return advertise_capability(store, {"host_id": host_id, "os": os_, "has_screen": True,
                                        "has_camera": camera, "has_gpu_vlm": True, "always_on": True,
                                        "has_hid_inject": False, "has_camera_stream": False}, OWNER)


def _forged(store, host_id):
    """A capability advertisement signed by the ATTACKER (never verifies under OP; verifies under AP).
    Core carries the full _CAP_CORE key set so it re-verifies under the attacker's own key too."""
    core = {"signal": CAP_SIGNAL, "host_id": host_id, "os": "?", "has_screen": True, "has_camera": True,
            "has_gpu_vlm": True, "always_on": True, "has_hid_inject": False, "has_camera_stream": False}
    payload = {**signed_payload(core, ATTACKER), "tier": "A0", "decision": "auto"}
    return store.append(kind="event", source="mesh", actor="OWNER", payload=payload)


def _seed(store):
    """Craft the record stream. Returns the store. Layout (seq):
        0 desk    (owner, camera=T)      -> prefix; NEVER re-advertised live (value must come from the seed)
        1 None    (owner, camera=T)      -> prefix; NON-STR host key, owner-signed; NEVER re-advertised live
                                            (value must come from the seed -> proves build() keeps a non-str key)
        2 laptop  (owner, camera=F)      -> prefix; PRE-seam value of a host updated across the split
        3 rogue   (attacker)             -> prefix; forged, must be dropped
      --- K=4 ---
        4 laptop  (owner, camera=T)      -> live;   POST-seam LWW update of `laptop`
        5 server  (owner, camera=F)      -> live;   fresh host only in the live window
        6 rogue2  (attacker)             -> live;   forged, must be dropped
    """
    assert _advertise(store, "desk", os_="linux", camera=True) == 0
    assert _advertise(store, None, os_="linux", camera=True) == 1
    assert _advertise(store, "laptop", os_="linux", camera=False) == 2
    assert _forged(store, "rogue") == 3
    assert _advertise(store, "laptop", os_="linux", camera=True) == 4
    assert _advertise(store, "server", os_="darwin", camera=False) == 5
    assert _forged(store, "rogue2") == 6
    return store


# ---- (A) IDENTITY: rewired consumer == known-correct value under the empty (Slice-C) snapshot ---------
def test_identity_known_correct_under_empty_snapshot():
    s = _seed(_store())
    m = capability_map(s, OP)
    # only owner-signed hosts; laptop is the LWW winner (camera=True, seq 4); forged rogues dropped.
    # the owner-signed None host is kept VERBATIM — the scan keys on p.get("host_id") with no type guard.
    assert set(m) == {"desk", None, "laptop", "server"}, "forged advertisements ignored; all signed hosts kept, incl. the None key"
    assert m["laptop"]["has_camera"] is True, "latest owner-signed advertisement wins (LWW)"
    assert m["desk"]["has_camera"] is True and m["server"]["os"] == "darwin"
    assert None in m and m[None]["has_camera"] is True, "an owner-signed non-str (None) host_id is a real key"
    assert "rogue" not in m and "rogue2" not in m, "attacker-signed advertisements never verify under OP"


# ---- (B) SPLIT: fold(build([0..K))) + fold([K..T]) == scan([0..T]) ------------------------------------
def test_split_fold_equals_full_scan(monkeypatch):
    s = _seed(_store())

    # The reference values, computed by the REAL (empty) load -> a full genesis scan.
    full = capability_map(s, OP)
    bypass_full = capability_map(s, AP)   # under the attacker anchor: only the forged hosts verify

    # Fold the prefix [0..K) into a synthetic snapshot, exactly as a Slice-D/E prune would at prune time.
    prefix = [r for r in s.iter_records() if r.seq < K]
    synthetic = build(prefix, trusted_pubkey=OP, base_seq=K, snapshot_seq=K - 1)
    syn_cap = dict(synthetic.capability_map)   # persisted as list-of-rows; dict() reconstructs (keys verbatim)

    # --- sanity: the prefix is non-empty and carries state that MATTERS (not a trivially-green split) ---
    assert [r.seq for r in prefix] == [0, 1, 2, 3], "prefix must be non-empty and end just below the split"
    assert set(syn_cap) == {"desk", None, "laptop"}, "prefix fold keeps signed hosts (incl. None), drops the forged one"
    assert "rogue" not in syn_cap, "build() drops the attacker-signed prefix record"
    # THE previously-missed case: build() must preserve a non-str (None) owner-signed host key EXACTLY, or
    # it would diverge from the type-guardless live scan (build() != scan). This is why capability_map is a
    # list-of-rows and not a dict-with-str-keys.
    assert None in syn_cap, "build() preserves the owner-signed non-str (None) host key in the fold seed"
    assert syn_cap[None]["has_camera"] is True, "the non-str key carries its verbatim capability value"
    assert syn_cap["laptop"]["has_camera"] is False, \
        "the PRE-seam laptop value that the live fold must overwrite"
    live_hosts = {r.payload.get("host_id") for r in s.iter_records() if r.seq >= K}
    assert "desk" not in live_hosts, "desk is NOT re-advertised live -> its final value can only come from the seed"
    assert None not in live_hosts, "the None host is NOT re-advertised live -> its final value can only come from the seed"

    # Rewire load() -> the synthetic prefix snapshot. The consumer now seeds it and folds only live [K..T].
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))

    split = capability_map(s, OP)
    assert split == full, "fold(prefix) + fold(live) == the full genesis scan"
    # pin WHY it is non-trivial: desk + the None key survived only via the seed; laptop was LWW-overwritten.
    assert split["desk"] == syn_cap["desk"], "desk carried through the snapshot seed"
    assert None in split and split[None] == syn_cap[None], \
        "the non-str None host key carried through the snapshot seed (build()==scan for non-str keys)"
    assert split["laptop"]["has_camera"] is True, "the live fold overwrote the seeded (pre-seam) laptop value"

    # --- pubkey BYPASS (rewrite rule 4): a mismatched anchor ignores the snapshot, re-scans from genesis ---
    bypass_split = capability_map(s, AP)   # AP != synthetic.trusted_pubkey(OP) -> bypass, seed {}, since=-1
    assert bypass_split == bypass_full, "a mismatched trust anchor bypasses the snapshot -> same as a full scan"
    assert set(bypass_split) == {"rogue", "rogue2"}, "under the attacker anchor only the attacker-signed hosts verify"
    assert "desk" not in bypass_split and None not in bypass_split, \
        "the OP-folded snapshot seed (incl. its None key) is NOT leaked into an attacker-anchor query"
