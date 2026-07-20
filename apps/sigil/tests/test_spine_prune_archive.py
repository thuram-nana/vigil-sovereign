"""Cold-archive hard-prune Slice D — the NON-DESTRUCTIVE machinery: Merkle accumulator, snapshot payload,
archive COPY (no live drop), §7 referential guards, and the `--with-archive` re-attach verifier.
Pins: a multi-segment spine archives whole sealed segments below K; the re-attach verifier links [archive‖
live] from genesis + re-derives every Merkle root; at-rest tamper (a flipped archived byte) is caught;
the referential floor refuses a K that would prune an open workflow; K must be segment-aligned; a two-prune
fold-of-fold snapshot == the single-scan fold. NO live record is deleted here.
Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_spine_prune_archive.py -q
"""
import json

import pytest

import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
from sigil.spine import prune
from sigil.spine.merkle import chain_cumulative, merkle_root
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Isolate the owner head + keys + floor to per-test paths (the config globals are process-shared, so
    without this a prior test's floor/head would contaminate verify_checkpoint here)."""
    import sigil.config as cfg
    keys = tmp_path / "keys"
    head = tmp_path / "head.json"
    monkeypatch.setattr(_cp, "HEAD_PATH", head)
    monkeypatch.setattr(_snap, "HEAD_PATH", head)
    monkeypatch.setattr(cfg, "HEAD_PATH", head, raising=False)
    monkeypatch.setattr(_cp, "KEYS_DIR", keys)
    monkeypatch.setattr(_cp, "_PRIV", keys / "owner.priv")
    monkeypatch.setattr(_cp, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(_fl, "FLOOR_PATH", tmp_path / "floor.json")
    return head


def _segmented_store(tmp_path, n_segments=4, per=5):
    """A migrated store rotated into `n_segments` sealed segments (each `per` records) + a live tail."""
    s = SpineStore(tmp_path / "spine.jsonl")
    s.migrate()
    seq = 0
    for _seg in range(n_segments):
        for _i in range(per):
            s.append(kind="event", source="t", actor="u", payload={"i": seq})
            seq += 1
        s.rotate()                                          # seal the active, start a fresh one
    for _i in range(3):                                     # a live (unsealed) tail
        s.append(kind="event", source="t", actor="u", payload={"i": seq})
        seq += 1
    return s


def test_merkle_root_properties():
    assert merkle_root([]) == ""
    assert merkle_root(["a"]) != ""
    # count-sensitive (dup-last-on-odd + committed count): 2 leaves != 3 leaves
    assert merkle_root(["a", "b"]) != merkle_root(["a", "b", "c"])
    # order-sensitive
    assert merkle_root(["a", "b", "c"]) != merkle_root(["c", "b", "a"])
    # cumulative chains + is distinct from a bare delta
    d0 = merkle_root(["a", "b"])
    c0 = chain_cumulative("", d0)
    assert c0 != d0 and chain_cumulative(c0, merkle_root(["c"])) != c0


def test_archive_copy_and_reattach_verify(tmp_path, isolated):
    s = _segmented_store(tmp_path)
    _cp.checkpoint(s)                                       # owner-sign the live spine (the verifier's anchor)
    K = 10                                                  # a sealed-segment boundary (segments start 0,5,10,15)
    payload = prune.snapshot_payload(s, K)
    assert payload["base_seq"] == 10 and payload["base_count"] == 10
    rep = prune.archive_copy(s, K, payload, adir=tmp_path / "arch")
    assert rep["verified"] and rep["copied"] == 2          # segments [0..5) and [5..10)
    # NO live drop: the store still holds every record.
    assert s.count() == 23 and s.verify()[0]
    ok, msg = prune.verify_with_archive(s, adir=tmp_path / "arch")
    assert ok, msg
    # the OWNER anchor is load-bearing: an UNSIGNED spine cannot certify the archive.
    (tmp_path / "head.json").unlink()
    ok2, msg2 = prune.verify_with_archive(s, adir=tmp_path / "arch")
    assert not ok2 and "does not verify" in msg2


def test_reattach_detects_at_rest_tamper(tmp_path):
    s = _segmented_store(tmp_path)
    payload = prune.snapshot_payload(s, 10)
    prune.archive_copy(s, 10, payload, adir=tmp_path / "arch")
    # flip a byte in an archived segment file -> sha256 mismatch caught.
    seg0 = next((tmp_path / "arch" / "segments").glob("seg-*"))
    raw = seg0.read_bytes()
    seg0.write_bytes(raw[:-2] + b"X\n")
    ok, msg = prune.verify_with_archive(s, adir=tmp_path / "arch")
    assert not ok and "sha256" in msg.lower()


def test_payload_forged_archive_is_rejected(tmp_path, isolated):
    """Review HIGH (binding) + BLOCK (anchor): rewriting a pruned record's PAYLOAD while keeping the chain
    fields must be caught — by the per-record content binding and/or the cross-check against the owner-signed
    live spine. A self-consistent sha256 in the manifest does NOT save it."""
    import hashlib

    s = _segmented_store(tmp_path)
    _cp.checkpoint(s)
    payload = prune.snapshot_payload(s, 10)
    prune.archive_copy(s, 10, payload, adir=tmp_path / "arch")
    assert prune.verify_with_archive(s, adir=tmp_path / "arch")[0]

    seg = sorted((tmp_path / "arch" / "segments").glob("seg-*"))[0]
    seg.write_text(seg.read_text().replace('"i": 0', '"i": 999'))   # forge a payload; cert_digest now stale
    mp = tmp_path / "arch" / "archive.manifest.json"
    am = json.loads(mp.read_text())
    for row in am["segments"]:                                       # make sha256 self-consistent with the forgery
        am_p = tmp_path / "arch" / row["file"]
        row["sha256"] = hashlib.sha256(am_p.read_bytes()).hexdigest()
    mp.write_text(json.dumps(am))
    ok, msg = prune.verify_with_archive(s, adir=tmp_path / "arch")
    assert not ok, "a payload-forged archive with a self-consistent sha256 must be rejected"


def test_open_workflow_floor_counts_unexecuted_operator_plan(tmp_path):
    """Review HIGH: an un-executed operator.plan is an open loop — the floor must sit at (or below) it, so a
    prune can't delete the plan + its preview."""
    s = _segmented_store(tmp_path)
    plan_seq = s.append(kind="operation", source="operator", actor="OPERATOR",
                        payload={"signal": "operator.plan", "subject": "x", "decision": "queued"})
    assert prune.open_workflow_floor(s) <= plan_seq
    # once executed, it no longer floors the prune.
    s.append(kind="operation", source="operator", actor="OPERATOR",
             payload={"signal": "operator.execute", "target_seq": plan_seq, "status": "APPLIED"})
    assert prune.open_workflow_floor(s) > plan_seq


def test_referential_floor_blocks_open_workflow(tmp_path, monkeypatch):
    s = _segmented_store(tmp_path)
    # force an open-workflow floor at seq 3 (inside the first segment) -> a prune at K=10 must be refused.
    monkeypatch.setattr(prune, "open_workflow_floor", lambda store: 3)
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 10)
    assert "referential floor" in str(e.value)


def test_k_must_be_segment_aligned(tmp_path):
    s = _segmented_store(tmp_path)
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 7)                        # 7 is mid-segment, not a boundary
    assert "boundary" in str(e.value)


def test_two_prune_fold_of_fold_equals_single_scan(tmp_path):
    """Multi-prune: build(prior_folded, delta[K1..K2)) == build(empty, [0..K2)). The snapshot's folded_state
    accumulator is exact across successive prunes."""
    s = _segmented_store(tmp_path)
    all_recs = list(s.iter_records())
    # prune #1 at K1=5, prune #2 at K2=10 seeded from #1.
    p1 = prune.snapshot_payload(s, 5)
    p2 = prune.snapshot_payload(s, 10, prior=p1)
    folded_2 = SnapshotState.model_validate(p2["folded_state"])
    single = build([r for r in all_recs if r.seq < 10], trusted_pubkey=p2["trusted_pubkey"],
                   base_seq=10, snapshot_seq=-1)
    assert folded_2.model_dump() == single.model_dump()    # fold-of-fold == single scan
    # and the cumulative Merkle chains the two deltas
    assert p2["cumulative_merkle_root"] == chain_cumulative(p1["cumulative_merkle_root"], p2["delta_merkle_root"])


def test_snapshot_payload_is_json_and_kind_registered(tmp_path):
    from sigil.spine.models import KINDS
    assert "snapshot" in KINDS
    s = _segmented_store(tmp_path)
    payload = prune.snapshot_payload(s, 10)
    json.dumps(payload)                                     # fully JSON-serializable
    # appending it is a normal retain-all append (inert until a head commits snapshot_seq — Slice E)
    seq = s.append(kind="snapshot", source="spine", actor="OWNER", payload=payload)
    assert s.get(seq).kind == "snapshot" and s.verify()[0]
