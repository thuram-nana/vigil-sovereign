"""Prune-survival proof for the SnapshotState-seeded `AssetOwnershipRegistry._fold_proofs` (Slice G0 close-out).

The asset-ownership PROOF fold used to be a GENESIS scan with NO snapshot seed, so a hard prune below the
first `governor.asset_ownership_proof` grant would SILENTLY vanish an active proof (`proof()` /
`has_current_proof` -> None/False) AND reset the per-(org_id, host) anti-replay high-water — re-opening the
LWW replay-RESURRECTION the G0 red-pen flagged (a captured owner-signed `active` proof for a REVOKED/expired
engagement-authorization basis becomes replayable again). This slice seeds the fold from `SnapshotState` (v3
grew `ownership_proof_*` rows) exactly as `orgs._fold_memberships` does, and `spine.prune` refuses any prune
that would strand an active proof the seed does not carry.

PHYSICAL-PRUNE HARNESS (identical to tests/test_snapshot_fold_orgs.py): a `PrunedView` physically hides every
record with `seq < K` from `iter_records` regardless of `since_seq`, so only the SEED can carry the pruned
state. Each test also carries an inline NEUTERED control (`SnapshotState.load` -> the empty identity) that
reproduces the pre-fix genesis-scan behaviour from inside the test, proving the seed is load-bearing.
"""
import itertools
import tempfile

import pytest

from sigil.governor.asset_ownership import (
    METHOD_DNS_TXT,
    PROOF_SIGNAL,
    AssetOwnershipRegistry,
)
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64

_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return AssetOwnershipRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def _record_proof(store, org, host, *, now, ttl=1e12):
    """Prove ownership of (org, host) via the real challenge+verdict path; proof issued_at = verified_at = now."""
    reg = _reg(store)
    ch = reg.issue_challenge(org, host, issued_at=now)
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=ttl)


class PrunedView:
    """A REAL hard prune: physically hide every record with `seq < K` from `iter_records`."""
    def __init__(self, inner, K):
        self._inner = inner
        self._K = K

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self._K:
                yield r

    def get(self, seq):
        return self._inner.get(seq)

    def append(self, **kw):
        return self._inner.append(**kw)


# ---- (a) an active PROOF whose only grant is PHYSICALLY PRUNED survives via the seed ----------------
def test_active_proof_survives_a_hard_prune(monkeypatch):
    store = _store()
    _record_proof(store, "acme", "apme.cm", now=5.0)                 # challenge seq0, proof seq1 (active, 5.0)
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.ownership_proof_state_map().get(("acme", "apme.cm")) == "active"
    assert snap.ownership_proof_issued_map().get(("acme", "apme.cm")) == 5.0
    assert any(row[0] == "acme" and row[1] == "apme.cm" for row in snap.ownership_proof_row)

    pruned = PrunedView(store, k)                                    # [0..k) GONE — the proof grant is unreadable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = AssetOwnershipRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2.proof("acme", "apme.cm") is not None, "a pruned active proof must survive via the seed"
    assert reg2.has_current_proof("acme", "apme.cm", now=100.0)
    assert reg2.proven_hosts("acme", now=100.0) == ["apme.cm"]

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = AssetOwnershipRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.proof("acme", "apme.cm") is None, "no seed over a physically-pruned store ⇒ vanished"


# ---- (b) the per-(org,host) high-water SURVIVES the prune (no replay resurrection) ------------------
def test_proof_high_water_survives_the_prune_no_replay_resurrection(monkeypatch):
    store = _store()
    _record_proof(store, "acme", "apme.cm", now=5.0)                 # challenge seq0, proof seq1 (active, 5.0)
    captured = next(r.payload for r in store.iter_records()
                    if isinstance(r.payload, dict) and r.payload.get("signal") == PROOF_SIGNAL
                    and r.payload.get("state") == "active")
    _reg(store).revoke_proof("acme", "apme.cm")                      # revoked
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.ownership_proof_state_map().get(("acme", "apme.cm")) == "revoked"
    assert snap.ownership_proof_issued_map().get(("acme", "apme.cm")) == 5.0   # high-water preserved though revoked

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay the active grant
    pruned = PrunedView(store, k)                                    # create + revoke are both pruned away
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = AssetOwnershipRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2.proof("acme", "apme.cm") is None, "replayed grant must NOT resurrect the proof (seed high-water)"
    assert reg2.has_current_proof("acme", "apme.cm", now=100.0) is False

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = AssetOwnershipRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.proof("acme", "apme.cm") is not None, "no seed ⇒ high-water lost ⇒ replay resurrects"


# ---- (c) empty-identity load == genesis scan (byte-identity of the no-prune path) ------------------
def test_proof_empty_load_matches_genesis():
    store = _store()
    _record_proof(store, "acme", "apme.cm", now=_iss())
    _record_proof(store, "acme", "other.example", now=_iss())
    _reg(store).revoke_proof("acme", "other.example")               # revoked live
    assert SnapshotState.load(store).base_seq == 0                  # no prune -> empty identity (genesis scan)
    reg = _reg(store)
    assert reg.proof("acme", "apme.cm") is not None
    assert reg.proof("acme", "other.example") is None               # revoked
    assert reg.proven_hosts("acme", now=100.0) == ["apme.cm"]        # within the proof's validity window


# ---- (d) check_prune_safe referential floor --------------------------------------------------------
def _proof_segmented_store(tmp_path):
    """A migrated store: an owner-signed active ownership proof sits in segment 0 [0..5), which a prune at
    K=5 archives+deletes; the seed must carry it or the floor refuses."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _record_proof(s, "acme", "apme.cm", now=1.0)                     # challenge seq0, proof seq1
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})         # seq 2..4
    s.rotate()                                                                       # seal segment 0 [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})        # seq 5..9
    s.rotate()                                                                       # seal segment 1 [5..10)
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})        # a live tail
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_check_prune_safe_allows_a_carried_active_proof(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _proof_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)                          # must NOT raise: the proof IS carried
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_ownership_proofs(s, archived, 5) == []   # detector empty on a complete seed


def test_referential_floor_detects_a_seed_that_omits_an_active_proof(tmp_path, monkeypatch):
    """Positive control: if build()/the seed ever DROPPED an active proof whose only grant is below K, the
    floor must DETECT it (non-empty) and refuse — not silently prune the proof away."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _proof_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "ownership_proof_state": [r for r in seed.ownership_proof_state if (r[0], r[1]) != ("acme", "apme.cm")],
            "ownership_proof_issued": [r for r in seed.ownership_proof_issued if (r[0], r[1]) != ("acme", "apme.cm")],
            "ownership_proof_row": [r for r in seed.ownership_proof_row if (r[0], r[1]) != ("acme", "apme.cm")],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    stranded = prune.stranded_active_ownership_proofs(s, _archived_below(s, 5), 5)
    assert stranded == ["apme.cm@acme"]                             # real diff: active minus carried={}
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "apme.cm@acme" in msg and "ownership proof" in msg


def test_check_prune_safe_reraises_a_nonempty_proof_floor_wiring_only(tmp_path, monkeypatch):
    """Pure wiring check: check_prune_safe re-raises PruneUnsafe when the proof detector reports non-empty."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _proof_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_ownership_proofs", lambda store, archived, K: ["ghost@org"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost@org" in str(e.value)
