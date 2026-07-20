"""SnapshotState.load() must VERIFY the owner signature before trusting a declared prune boundary
(Slice-C review HIGH). The genesis scan this slice replaces verified EVERY governance record per-signature,
so a forged snapshot must NOT be able to inject governance state (release a kill-switch, authorize a rogue
device) without the owner key. Also: a present-but-corrupt head fails CLOSED, never masquerading as
no-prune (which would scan a truncated post-prune window with empty seeds). Under a legit Slice-C spine
(no prune, snapshot_seq == -1) load() returns the empty identity and NEVER triggers verification (hot path
unaffected).
Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_load_verify.py -q
"""
import pytest

import sigil.spine.checkpoint as cp
import sigil.spine.floor as fl
import sigil.spine.snapshot as snap
from sigil.reuse.models import SignedChainHead
from sigil.spine.snapshot import SnapshotError, SnapshotState
from sigil.spine.store import SpineStore


def _setup(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    head = tmp_path / "head.json"
    monkeypatch.setattr(snap, "HEAD_PATH", head)
    monkeypatch.setattr(cp, "HEAD_PATH", head)
    monkeypatch.setattr(cp, "KEYS_DIR", keys)
    monkeypatch.setattr(cp, "_PRIV", keys / "owner.priv")
    monkeypatch.setattr(cp, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(fl, "FLOOR_PATH", tmp_path / "floor.json")
    store = SpineStore(tmp_path / "spine.jsonl")
    for i in range(6):
        store.append(kind="event", source="t", actor="u", payload={"i": i})
    return store, head


def test_no_head_and_signed_no_prune_head_return_empty(tmp_path, monkeypatch):
    store, _head = _setup(tmp_path, monkeypatch)
    assert SnapshotState.load(store).snapshot_seq == -1        # no head -> empty identity
    cp.checkpoint(store)                                        # a legit sign (snapshot_seq == -1)
    st = SnapshotState.load(store)
    assert st.snapshot_seq == -1 and st.base_seq == 0          # parsed no-prune head -> empty, verify NOT tripped


def test_forged_unsigned_prune_head_is_rejected(tmp_path, monkeypatch):
    """An FS-write attacker (no owner key) writes a head declaring a prune (snapshot_seq >= 0). load() must
    verify the head and FAIL CLOSED — never returning a boundary that would seed forged governance state."""
    store, head = _setup(tmp_path, monkeypatch)
    forged = SignedChainHead(schema_version=2, engagement_slug="sigil", last_seq=5, entry_count=6,
                             head_hash="ff" * 32, base_seq=3, base_count=3, snapshot_seq=5)  # UNSIGNED
    head.write_text(forged.model_dump_json())
    with pytest.raises(SnapshotError):
        SnapshotState.load(store)


def test_signed_head_retargeted_to_a_prune_is_rejected(tmp_path, monkeypatch):
    """Even a VALID owner signature over a no-prune head cannot be replayed as a prune: flipping
    snapshot_seq/base_seq on a signed head breaks the signature (the fields are in the signed payload)."""
    store, head = _setup(tmp_path, monkeypatch)
    signed = cp.checkpoint(store)                               # valid signature over a no-prune head
    tampered = signed.model_copy(update={"snapshot_seq": 5, "base_seq": 3, "base_count": 3})
    head.write_text(tampered.model_dump_json())
    with pytest.raises(SnapshotError):
        SnapshotState.load(store)


def test_corrupt_head_fails_closed(tmp_path, monkeypatch):
    store, head = _setup(tmp_path, monkeypatch)
    head.write_text("{ not valid json --")
    with pytest.raises(SnapshotError):                          # present-but-corrupt -> never treated as no-prune
        SnapshotState.load(store)
