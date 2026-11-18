"""Front C S2a — the sovereign ShardAssignmentRegistry (owner-signed tenant→shard placements).

Invariants pinned here:
  * assign/reassign are the DANGEROUS direction (owner-signed, fresh), carrying the shard + epoch inside the signed
    bytes; unassign is the SAFE direction (honored unsigned);
  * a record signed by a NON-owner is inert (refused), a tampered field is refused;
  * cross-tenant isolation: one tenant can never read / overwrite / redirect another's placement;
  * anti-replay: a captured/replayed assignment cannot resurrect a migrated-off placement (per-tenant high-water);
  * epoch is registry-managed + monotonic; reassign is idempotent + exactly-once (a wrong source is refused);
  * HARD-PRUNE durability: the prune tripwire refuses a prune that would strand an active assignment, and allows
    one re-asserted live.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.shard_assignment import (
    SIGNAL, ShardAssignmentConflict, ShardAssignmentRegistry, _owner_root,
)
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.store import SpineStore
from vigil_core import ShardAssignmentRecord, sign_shard_assignment_record, verify_shard_assignment_record

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)


def _t() -> float:
    return float(next(_c))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, key=OWNER, pub=OP):
    return ShardAssignmentRegistry(store, owner_key=key, trusted_pubkey=pub)


def _append_signed(store, doc: ShardAssignmentRecord, signer):
    """Append a hostile/alternate signed assignment directly (bypassing the registry's mint checks) to probe the
    fold's verify — e.g. a non-owner signer, or a tampered document under a valid-but-wrong signature."""
    signed = sign_shard_assignment_record(doc, {"owner": signer.private_key_b64})
    store.append(kind="event", source="governor", actor="WARDEN",
                 payload={"signal": SIGNAL, "record": signed.model_dump(mode="json"), "by": "owner",
                          "requested_by": "owner", "tier": "A0", "decision": "auto", "reason": "raw"})


def test_assign_records_an_owner_signed_placement():
    s = _store()
    _reg(s).assign("acme", "shard01", issued_at=_t())
    p = _reg(s).placement("acme")
    assert p is not None and p.shard_id == "shard01" and p.epoch == 1


def test_assign_requires_the_owner_signing_key():
    with pytest.raises(ValueError, match="owner signing key"):
        ShardAssignmentRegistry(_store(), owner_key=None, trusted_pubkey=OP)._append_assignment("acme", "s1", 1, 1.0)


def test_a_record_signed_by_a_non_owner_is_inert():
    s = _store()
    _append_signed(s, ShardAssignmentRecord(tenant_id="acme", shard_id="s1", epoch=1, issued_at=_t()), ATTACKER)
    assert _reg(s).placement("acme") is None


def test_a_tampered_record_is_refused():
    s = _store()
    # A document signed under one shard, then re-pointed at another with the ORIGINAL signature: verify breaks.
    doc = ShardAssignmentRecord(tenant_id="acme", shard_id="s1", epoch=1, issued_at=_t())
    signed = sign_shard_assignment_record(doc, {"owner": OWNER.private_key_b64})
    tampered = signed.model_copy(update={"document": doc.model_copy(update={"shard_id": "s2"})})
    assert not verify_shard_assignment_record(tampered, _owner_root(OP))[0]
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={"signal": SIGNAL, "record": tampered.model_dump(mode="json"), "by": "owner",
                      "requested_by": "owner", "tier": "A0", "decision": "auto", "reason": "raw"})
    assert _reg(s).placement("acme") is None


def test_cross_tenant_isolation():
    s = _store()
    r = _reg(s)
    r.assign("acme", "shardA", issued_at=_t())
    r.assign("globex", "shardB", issued_at=_t())
    assert r.placement("acme").shard_id == "shardA"
    assert r.placement("globex").shard_id == "shardB"
    # globex's assignment never redirected acme and vice-versa.
    assert {p.tenant_id: p.shard_id for p in r.placements()} == {"acme": "shardA", "globex": "shardB"}


def test_assign_refuses_an_already_assigned_tenant():
    s = _store()
    _reg(s).assign("acme", "shardA", issued_at=_t())
    with pytest.raises(ValueError, match="already has an active placement"):
        _reg(s).assign("acme", "shardB", issued_at=_t())


def test_reassign_bumps_the_epoch_to_the_new_shard():
    s = _store()
    _reg(s).assign("acme", "shardA", issued_at=_t())
    _reg(s).reassign("acme", "shardB", expected_from_shard="shardA", expected_from_epoch=1, issued_at=_t())
    p = _reg(s).placement("acme")
    assert p.shard_id == "shardB" and p.epoch == 2


def test_reassign_is_idempotent_when_already_committed():
    s = _store()
    _reg(s).assign("acme", "shardA", issued_at=_t())
    _reg(s).reassign("acme", "shardB", expected_from_shard="shardA", expected_from_epoch=1, issued_at=_t())
    before = len(list(s.iter_records()))
    # Re-driving the SAME commit is a no-op (no second bump, no duplicate record).
    _reg(s).reassign("acme", "shardB", expected_from_shard="shardA", expected_from_epoch=1, issued_at=_t())
    assert len(list(s.iter_records())) == before
    assert _reg(s).placement("acme").epoch == 2


def test_reassign_refuses_a_wrong_source_placement():
    s = _store()
    _reg(s).assign("acme", "shardA", issued_at=_t())
    with pytest.raises(ShardAssignmentConflict):
        _reg(s).reassign("acme", "shardC", expected_from_shard="shardB", expected_from_epoch=1, issued_at=_t())


def test_a_replayed_old_assignment_cannot_resurrect_a_migrated_off_placement():
    s = _store()
    r = _reg(s)
    r.assign("acme", "shardA", issued_at=1.0)                       # epoch 1, issued_at 1.0
    r.reassign("acme", "shardB", expected_from_shard="shardA", expected_from_epoch=1, issued_at=3.0)   # epoch 2
    # A captured OLD assignment (shardA, issued_at 1.0) re-appended after the migration: below the high-water -> inert.
    _append_signed(s, ShardAssignmentRecord(tenant_id="acme", shard_id="shardA", epoch=1, issued_at=1.0), OWNER)
    p = r.placement("acme")
    assert p.shard_id == "shardB" and p.epoch == 2


def test_unassign_is_the_safe_direction_and_removes_the_tenant():
    s = _store()
    _reg(s).assign("acme", "shardA", issued_at=_t())
    _reg(s).unassign("acme")
    assert _reg(s).placement("acme") is None
    # And the SAFE direction is honored even from a key-less registry (no owner key).
    s2 = _store()
    _reg(s2).assign("beta", "shardA", issued_at=_t())
    ShardAssignmentRegistry(s2, owner_key=None, trusted_pubkey=OP).unassign("beta")
    assert _reg(s2).placement("beta") is None


# -- HARD-PRUNE durability (mirror the connected_repos tripwire test's segment math) --------------------
def _segmented(tmp_path, monkeypatch):
    """A rotated spine with acme's assign (seq 0) inside the FIRST sealed segment [0..4], then two more sealed
    segments — so a prune to K=5 archives the assign record. Mirrors ``_segmented`` in the connected-repos test."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _reg(s).assign("acme", "shardA", issued_at=2.0)                     # seq 0
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})   # seq 1..4
    s.rotate()                                                          # seal [0..4]
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})  # seq 5..9
    s.rotate()                                                          # seal [5..9]
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})  # seq 10..12
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_prune_tripwire_refuses_stranding_an_active_assignment(tmp_path, monkeypatch):
    s = _segmented(tmp_path, monkeypatch)
    assert prune.stranded_active_shard_assignments(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "acme" in str(e.value) and "shard assignment" in str(e.value)


def test_prune_tripwire_allows_an_assignment_re_asserted_live(tmp_path, monkeypatch):
    s = _segmented(tmp_path, monkeypatch)
    # Re-assert acme LIVE (seq >= 5) at a higher high-water via a reassign — the tripwire is then clear for acme.
    _reg(s).reassign("acme", "shardB", expected_from_shard="shardA", expected_from_epoch=1, issued_at=99.0)
    assert prune.stranded_active_shard_assignments(s, _archived_below(s, 5), 5) == []


def test_check_prune_safe_wires_the_shard_assignment_tripwire(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path, monkeypatch)
    monkeypatch.setattr(prune, "stranded_active_shard_assignments", lambda st, a, K: ["ghost"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "ghost" in str(e.value)
