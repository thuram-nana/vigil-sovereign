"""Snapshot-fold equivalence for the gesture device-ARM replay bearer (hard-prune Slice C wiring).

Two wired sites in sigil/gesture/session.py both seed the set-union arm-replay ledger from
`SnapshotState.load(store).arm_set()` (the folded pruned prefix `[0..base_seq)`) and then fold ONLY the
live records `[base_seq..T]`:
  Site A  pending_device_arms()        — seeds `armed`, folds live SESSION_ARMED markers + ARM_REQUEST cands.
  Site B  SessionGate.arm_by_device()  — replay check: refuse if (pub,nonce) already in the prefix arm_set
                                          OR appears in a live SESSION_ARMED device marker.

Each test proves fold==scan two ways:
  (A) IDENTITY — real empty load (Slice-C universal path): the rewired consumer returns the KNOWN-CORRECT
      value by scanning the whole store.
  (B) SPLIT — the real proof: with the SAME full store, full = consumer(store) (empty load -> scans all).
      Pick a split seq K in the MIDDLE, build the prefix snapshot with build([0..K)),
      monkeypatch load -> that synthetic, split = consumer(store) (seeds the synthetic prefix + folds live
      [K..T]).  assert split == full.  K is chosen so the prefix carries state that MATTERS (a consumed arm
      nonce that filters/refuses a live record); an empty seed would give a DIFFERENT answer -> not green-wash.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_gesture_arm.py -q
"""
import tempfile
import time

from sigil.gesture.session import (ARM_REQUEST, SESSION_ARMED, SessionGate,
                                    pending_device_arms, sign_arm_request)
from sigil.mesh import authorize_device
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build  # build() is the module-level prefix folder
from sigil.spine.store import SpineStore

# --- Site A fixtures: pubkeys are opaque strings (pending_device_arms does NO crypto) --------------
P1, P2, P3 = "pk_dev_one", "pk_dev_two", "pk_dev_three"


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _arm_marker(store, device_pubkey, nonce):
    """A device-armed SESSION_ARMED record (what arm_by_device writes) — the set-union arm ledger entry."""
    return store.append(kind="event", source="gesture", actor="DEVICE",
                        payload={"signal": SESSION_ARMED, "armed_by": "device",
                                 "device_pubkey": device_pubkey, "nonce": nonce,
                                 "session_id": "sid", "tier": "A0", "decision": "auto"})


def _cand(store, pubkey, nonce):
    """A recorded ARM_REQUEST candidate (what the bridge's submit_arm_request writes)."""
    return store.append(kind="event", source="mesh", actor="DEVICE",
                        payload={"signal": ARM_REQUEST, "decision": "auto", "sig": "s", "pubkey": pubkey,
                                 "nonce": nonce, "device_id": "phone", "ts": 0.0, "ttl_seconds": 120.0})


def _keys(cands):
    return [(c.get("pubkey"), c.get("nonce")) for c in cands]


def _build_site_a_store():
    """Layout (seq -> record). Exercises BOTH a prefix-seeded arm marker and a live-folded one, plus a
    nonce-TYPE-fidelity case (int marker must NOT filter a str-nonce candidate).
        0: MARKER (P1, 1 int)     -> filters the live candidate at seq 2   (prefix state that MATTERS)
        1: MARKER (P3, 1 int)     -> type-fidelity anchor for the str "1" candidate at seq 7
        2: CAND   (P1, 1 int)     -> DROPPED  (armed by seq 0)
        3: CAND   (P1, 2 int)     -> KEPT
        4: MARKER (P2, 5 int)     -> live-folded marker, filters seq 5
        5: CAND   (P2, 5 int)     -> DROPPED  (armed by seq 4)
        6: CAND   (P2, 6 int)     -> KEPT
        7: CAND   (P3, "1" str)   -> KEPT  (str "1" != int 1 -> NOT stringified/collapsed)"""
    s = _store()
    _arm_marker(s, P1, 1)
    _arm_marker(s, P3, 1)
    _cand(s, P1, 1)
    _cand(s, P1, 2)
    _arm_marker(s, P2, 5)
    _cand(s, P2, 5)
    _cand(s, P2, 6)
    _cand(s, P3, "1")
    return s


# EXPECTED under a whole-store scan: (P1,1)&(P2,5) filtered by their markers; (P3,"1") kept (type-distinct).
_EXPECTED_A = [(P1, 2), (P2, 6), (P3, "1")]


def test_site_a_identity_full_scan_is_known_correct():
    """(A) IDENTITY: real empty load (base_seq=0 => full genesis scan) returns the KNOWN-CORRECT value."""
    s = _build_site_a_store()
    result = pending_device_arms(s, trusted_pubkey=None)
    assert _keys(result) == _EXPECTED_A, _keys(result)
    # nonce type is preserved VERBATIM — the surviving (P3,*) candidate carries the STRING "1", not int 1.
    p3 = next(c for c in result if c["pubkey"] == P3)
    assert p3["nonce"] == "1" and isinstance(p3["nonce"], str), "str nonce must not be stringify-collapsed onto int"


def test_site_a_split_equals_full(monkeypatch):
    """(B) SPLIT: fold([0..K) via build) + fold([K..T] via consumer) == scan([0..T])."""
    s = _build_site_a_store()
    full = pending_device_arms(s, trusted_pubkey=None)           # real empty load -> scans all
    assert _keys(full) == _EXPECTED_A

    K = 2                                                        # prefix = the two seed markers (P1,1)+(P3,1)
    prefix = [r for r in s.iter_records() if r.seq < K]
    assert prefix, "prefix must be non-empty"
    synthetic = build(prefix, trusted_pubkey="", base_seq=K, snapshot_seq=K - 1)
    # the prefix carries state that MATTERS: the consumed (P1,1) marker (filters the live seq-2 candidate)
    # AND the (P3,1 int) anchor for the type-fidelity live candidate. A trivial/empty seed => WRONG answer.
    assert synthetic.arm_set() == {(P1, 1), (P3, 1)}, synthetic.arm_set()

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    split = pending_device_arms(s, trusted_pubkey=None)          # seeds synthetic prefix + folds live [K..T]
    assert split == full, "fold(prefix)+fold(live) must equal the full genesis scan (byte-for-byte cands)"
    assert _keys(split) == _EXPECTED_A

    # PROVE the seed did the work: the (P1,1) marker is BELOW base_seq, so only the snapshot seed can filter
    # the live (P1,1) candidate. Without the seed the live scan would KEEP it -> a different (wrong) result.
    assert not any(r.payload.get("signal") == SESSION_ARMED and r.payload.get("device_pubkey") == P1
                   for r in s.iter_records(since_seq=K - 1)), "the P1 arm marker lives only in the pruned prefix"


# ==================================================================================================
# Site B — arm_by_device replay refusal, driven end-to-end (real crypto: only an owner-authorized,
# fresh, signed request reaches the replay gate). Proves the arm_set SEED refuses a nonce whose arm
# marker is below base_seq (invisible to the live scan).
# ==================================================================================================
OWNER = generate_keypair()
OP = OWNER.public_key_b64
DEV = generate_keypair()


class _FakeCls:
    def classify(self, tool):
        from sigil.agents.base import Tier
        return Tier.A1


def _gate(store):
    from sigil.gesture.components import RecordingInputBackend
    return SessionGate(store, RecordingInputBackend(), classifier=_FakeCls(), trusted_pubkey=OP)


def test_site_b_replay_split_equals_full(monkeypatch):
    s = _store()
    authorize_device(s, "phone1", DEV.public_key_b64, OWNER)     # seq 0: owner-signed DEV authz
    now = time.time()
    req = sign_arm_request(DEV, device_id="phone1", nonce=77, ts=now, ttl_seconds=120.0)

    # arm once (empty load) -> writes the SESSION_ARMED device marker; then disarm.
    assert _gate(s).arm_by_device(req, now=now) is not None, "first arm with nonce 77 succeeds (empty snapshot)"

    # (A) IDENTITY / FULL: empty load -> the full live scan sees the marker -> re-use of nonce 77 is refused.
    full = _gate(s).arm_by_device(req, now=now)
    assert full is None, "full-scan replay detection refuses the re-used (device,nonce)"

    # locate the arm marker and SPLIT above it so the marker lives in the pruned prefix.
    marker_seq = next(r.seq for r in s.iter_records()
                      if r.payload.get("signal") == SESSION_ARMED and r.payload.get("armed_by") == "device")
    K = marker_seq + 1
    prefix = [r for r in s.iter_records() if r.seq < K]
    assert prefix, "prefix must be non-empty"
    # build() folds the prefix under OP: it carries BOTH the consumed arm nonce (my bearer) AND the device
    # authz (so the auth gate upstream of the replay check still passes when seeded from the same snapshot).
    synthetic = build(prefix, trusted_pubkey=OP, base_seq=K, snapshot_seq=K - 1)
    assert (DEV.public_key_b64, 77) in synthetic.arm_set(), "prefix carries the consumed arm nonce (state that MATTERS)"
    assert dict(synthetic.mesh_dev_state).get(DEV.public_key_b64) == "authorized", "prefix carries device authz"
    # PROVE the seed is load-bearing: no arm marker survives in the LIVE window [K..T] -> only the snapshot
    # seed can catch this replay. Without it, arm_by_device would arm again (wrong).
    assert not any(r.payload.get("signal") == SESSION_ARMED and r.payload.get("armed_by") == "device"
                   for r in s.iter_records(since_seq=K - 1)), "the arm marker is below base_seq"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    split = _gate(s).arm_by_device(req, now=now)                 # seeds synthetic prefix + folds live [K..T]
    assert split is None, "seed(prefix arm_set) + live-fold refuses the replay just like the full scan"
    assert split == full, "fold(prefix)+fold(live) == full genesis scan (both refuse -> None)"

    # not green-washed: refused SPECIFICALLY as a replay (not an auth/freshness refusal).
    reasons = [r.payload.get("reason") for r in s.iter_records()
               if r.payload.get("signal") == ARM_REQUEST and r.payload.get("decision") == "refused"]
    assert reasons and reasons[-1] == "replayed arm nonce", f"refused as replay, got {reasons}"


def test_site_b_nonce_type_is_not_stringified(monkeypatch):
    """A prefix that consumed INT nonce 77 must NOT refuse a distinct STR nonce "77" (no stringify)."""
    s = _store()
    authorize_device(s, "phone1", DEV.public_key_b64, OWNER)
    now = time.time()
    assert _gate(s).arm_by_device(
        sign_arm_request(DEV, device_id="phone1", nonce=77, ts=now, ttl_seconds=120.0), now=now) is not None
    _gate(s).disarm()

    prefix = list(s.iter_records())                              # whole store into the prefix
    K = prefix[-1].seq + 1
    synthetic = build(prefix, trusted_pubkey=OP, base_seq=K, snapshot_seq=K - 1)
    assert (DEV.public_key_b64, 77) in synthetic.arm_set()       # INT 77 consumed
    assert (DEV.public_key_b64, "77") not in synthetic.arm_set(), "str '77' is a DISTINCT key from int 77"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    # a NEW request with the STRING nonce "77" must arm (int 77 in the ledger does not shadow str "77").
    got = _gate(s).arm_by_device(
        sign_arm_request(DEV, device_id="phone1", nonce="77", ts=now, ttl_seconds=120.0), now=now)
    assert got is not None, "str nonce '77' is not collapsed onto the consumed int 77 -> it arms"
