"""Equivalence proof for the device-approval dedup fold (BridgeDaemon.submit_device_approval, daemon.py).

The dedup scan was rewired from a raw genesis scan to a SnapshotState fold: seed
`dict(st.approval_dedup_map())`, then min-seq-fold the LIVE records `[base_seq..T]` and look up the
incoming `(pubkey, sig)`. This test proves fold == scan two ways:

  (A) IDENTITY — under the real (empty Slice-C) load, a replay of an already-recorded approval returns
      the MIN (earliest) seq among duplicate records, NOT the last-write seq, and does NOT append.
  (B) SPLIT — SnapshotState.build([0..K)) [the prefix fold] + the consumer's live fold of [K..T] over the
      SAME store == the full genesis scan. K is chosen so the EARLIEST duplicate of the submitted body is
      in the prefix and a LATER duplicate is in the suffix; without seeding the snapshot the consumer would
      return the later seq (or append), so the equality is load-bearing, not green-washed.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_device_approval_dedup.py -q
"""
import tempfile

from sigil.agents.approvals import _approval_message
from sigil.bridge import BridgeDaemon
from sigil.mesh import authorize_device
from sigil.reuse import generate_keypair, sha256_hex, sign
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _approval(dev, target_seq):
    """A genuine device-signed approval body (passes the daemon guards + verify_approval)."""
    msg = _approval_message(target_seq, "approved", "device")
    return {"signal": "governor.approval", "approval": "approved", "target_seq": target_seq,
            "approver": "device", "pubkey": dev.public_key_b64, "sig": sign(dev.private_key_b64, msg),
            "msg_digest": sha256_hex(msg), "device": True}


def _record_approval(store, body):
    """Append a raw governor.approval record (bypassing the daemon dedup) so the SAME (pubkey,sig) can be
    forced to appear at MULTIPLE distinct seqs — the min-seq case the consumer must resolve to the earliest."""
    return store.append(kind="event", source="mesh", actor="DEVICE",
                        payload={**body, "tier": "A0", "decision": "auto"})


def _build_store():
    """A store whose earliest duplicate of `appr` sits well before a later duplicate, plus an unrelated
    approval key. Returns (store, daemon, owner, dev, appr, earliest_seq, later_seq)."""
    s = _store()
    owner, dev, dev2 = generate_keypair(), generate_keypair(), generate_keypair()
    authorize_device(s, "d", dev.public_key_b64, owner)       # dev is authorized (owner-signed)
    d = BridgeDaemon(s, trusted_pubkey=owner.public_key_b64)

    appr = _approval(dev, target_seq=100)                     # the body we will re-submit (a replay)
    other = _approval(dev2, target_seq=777)                   # an UNRELATED approval key (different pubkey+sig)

    earliest_seq = _record_approval(s, appr)                  # first copy of appr — the MIN seq
    _record_approval(s, other)                                # unrelated key between the duplicates
    _record_approval(s, other)                                # a duplicate of the unrelated key
    later_seq = _record_approval(s, appr)                     # a LATER copy of appr — higher seq
    _record_approval(s, other)                                # more unrelated records after
    assert later_seq > earliest_seq
    return s, d, owner, dev, appr, earliest_seq, later_seq


def test_identity_dedup_returns_min_seq_not_last_write():
    """(A) Under the real empty load, a replay resolves to the EARLIEST matching record and does not append."""
    s, d, owner, dev, appr, earliest_seq, later_seq = _build_store()
    tip_before = s.tail(1)[0].seq

    got = d.submit_device_approval(appr)                      # a replay of an already-recorded approval
    assert got == earliest_seq, "dedup must return the MIN (earliest) matching seq, not the last-write seq"
    assert got != later_seq, "returning the later duplicate would be last-write, not min-seq"
    assert s.tail(1)[0].seq == tip_before, "a dedup hit must NOT append a new record"


def test_split_prefix_fold_plus_live_fold_equals_full_scan(monkeypatch):
    """(B) build([0..K)) + consumer-fold([K..T]) == the full genesis scan, with a non-trivial prefix."""
    s, d, owner, dev, appr, earliest_seq, later_seq = _build_store()
    tp = d.trusted_pubkey

    full = d.submit_device_approval(appr)                     # real empty load -> full scan; earliest match
    assert full == earliest_seq

    # Split BETWEEN the two duplicates of appr: the earliest is in the prefix, the later is in the suffix.
    K = later_seq                                            # prefix = [.. earliest .. other ..], suffix = [later ..]
    prefix = [r for r in s.iter_records() if r.seq < K]
    assert prefix, "prefix must be non-empty"
    assert any(r.payload.get("signal") == "governor.approval"
               and r.payload.get("pubkey") == dev.public_key_b64
               and r.payload.get("sig") == appr["sig"]
               and r.seq == earliest_seq for r in prefix), "the earliest duplicate must live in the prefix"
    assert any(r.seq == later_seq for r in s.iter_records() if r.seq >= K), "a later duplicate must live in the suffix"

    synthetic = build(prefix, trusted_pubkey=tp, base_seq=K, snapshot_seq=K - 1)
    # The prefix carries the state that MATTERS: the min-seq for our key, folded from [0..K).
    dedup_map = synthetic.approval_dedup_map()
    assert dedup_map.get((dev.public_key_b64, appr["sig"])) == earliest_seq, \
        "synthetic snapshot must carry the earliest seq for the submitted key (non-trivial prefix state)"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    split = d.submit_device_approval(appr)                    # seeds synthetic prefix + folds only live [K..T]
    assert split == full, "prefix-fold + live-fold must equal the full genesis scan (byte-identical)"

    # Load-bearing check: had the consumer NOT seeded the snapshot, folding only the suffix [K..T] would
    # have found the LATER duplicate first -> returned later_seq (!= full). Seeding is what makes it correct.
    assert later_seq != earliest_seq and split != later_seq, "seeding the prefix min-seq is load-bearing"


if __name__ == "__main__":
    test_identity_dedup_returns_min_seq_not_last_write()
    print("OK identity")
