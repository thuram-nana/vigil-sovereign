"""SIGIL Phase 7 P0 — shared primitives: KernelClassifier bridge (the fail-closed Rust tiering
oracle) + SpineTailer / verify_record (the integrity-verifying live tail).
Run: ~/.sigil/venv/bin/python tests/test_shared_primitives.py"""
import json
import tempfile
from pathlib import Path

from sigil.agents.base import Tier
from sigil.agents.kernel_classify import KernelClassifier
from sigil.reuse import (AuthorizerKey, TrustRoot, digest_payload, generate_keypair, sign_head)
from sigil.reuse.chain import _GENESIS_PREV, _entry_hash
from sigil.spine.store import SpineStore
from sigil.spine.tail import Broadcaster, SpineTailer
from sigil.spine.verify import verify_record

_KERNEL = Path("/home/kali/sigil/kernel/target/release/sigil-kernel")


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _append(s, n, kind="event"):
    return [s.append(kind=kind, source="agent", actor="TESTER", payload={"summary": f"e{i}"}) for i in range(n)]


# ---- P0.1 KernelClassifier -----------------------------------------------------------------------
def test_kernel_classifier_fail_closed_on_bad_binary():
    kc = KernelClassifier(kernel_bin="/nonexistent/sigil-kernel", timeout=5)
    assert kc.classify("fs.read") == Tier.A3, "a missing kernel must fail-closed to A3"
    assert kc.classify("git.push") == Tier.A3


def test_kernel_classifier_empty_tool_is_a3():
    kc = KernelClassifier(kernel_bin=str(_KERNEL) if _KERNEL.exists() else "/nonexistent")
    assert kc.classify("") == Tier.A3 and kc.classify("   ") == Tier.A3


def test_kernel_classifier_real_oracle():
    if not _KERNEL.exists():
        print("    (skip real oracle — kernel not built)")
        return
    kc = KernelClassifier(kernel_bin=str(_KERNEL))
    expect = {"fs.read": Tier.A0, "memory.search": Tier.A0, "fs.write": Tier.A1,
              "vision.frontier.upload": Tier.A2, "shell.exec.rm": Tier.A3, "git.push": Tier.A3,
              "config.overwrite": Tier.A3, "totally.unknown.tool": Tier.A3}
    for tool, tier in expect.items():
        assert kc.classify(tool) == tier, f"{tool} should classify {tier.label()} (fail-closed oracle)"


# ---- P0.2 verify_record --------------------------------------------------------------------------
def test_verify_record_accepts_clean_and_rejects_tamper():
    s = _store()
    seq = s.append(kind="event", source="agent", actor="X", payload={"summary": "hello"})
    rec = s.get(seq)
    ok, _ = verify_record(rec)
    assert ok, "a freshly-written record must verify"
    # binding break: mutate the payload but keep the stored cert_digest
    import dataclasses
    tampered = dataclasses.replace(rec, payload={"summary": "HELLO-TAMPERED"})
    ok2, reason2 = verify_record(tampered)
    assert not ok2 and "binding" in reason2, "a payload edit must break the binding"
    # derivation break: mutate entry_hash
    tampered2 = dataclasses.replace(rec, entry_hash="deadbeef")
    ok3, reason3 = verify_record(tampered2)
    assert not ok3 and "entry_hash" in reason3


# ---- P0.2 SpineTailer ----------------------------------------------------------------------------
def test_tailer_emits_new_records_verified_in_order():
    s = _store()
    _append(s, 3)
    t = SpineTailer(s, since_seq=-1)
    ev = t.poll()
    assert [e["seq"] for e in ev] == [0, 1, 2] and all(e["integrity_ok"] for e in ev)
    assert all(e.get("entry_hash") for e in ev), "each event carries provenance"
    _append(s, 2)
    ev2 = t.poll()
    assert [e["seq"] for e in ev2] == [3, 4], "second poll yields ONLY the new records"
    assert t.poll() == [], "no new records → empty poll"


def test_tailer_live_only_cursor_skips_backlog():
    s = _store()
    _append(s, 3)
    t = SpineTailer(s, since_seq=s.next_seq - 1)   # start at head → live-only
    assert t.poll() == [], "starting at head sees no backlog"
    _append(s, 1)
    assert [e["seq"] for e in t.poll()] == [3]


def _rewrite_line(path, seq, mutate):
    lines = Path(path).read_text().splitlines()
    for i, ln in enumerate(lines):
        d = json.loads(ln)
        if d["seq"] == seq:
            lines[i] = json.dumps(mutate(d), ensure_ascii=False)
    Path(path).write_text("\n".join(lines) + "\n")


def test_tailer_flags_a_tampered_payload_not_dropped():
    s = _store()
    _append(s, 3)
    _rewrite_line(s.path, 1, lambda d: {**d, "payload": {"summary": "TAMPERED"}})  # keep cert_digest
    ev = SpineTailer(SpineStore(s.path), since_seq=-1).poll()
    assert [e["seq"] for e in ev] == [0, 1, 2], "the tampered record is EMITTED, not silently dropped"
    bad = [e for e in ev if not e["integrity_ok"]]
    assert [e["seq"] for e in bad] == [1] and "binding" in bad[0]["integrity_reason"]


def test_tailer_flags_a_linkage_break():
    s = _store()
    _append(s, 3)
    _rewrite_line(s.path, 2, lambda d: {**d, "prev_hash": "00" * 32})  # break the chain link at seq 2
    ev = SpineTailer(SpineStore(s.path), since_seq=-1).poll()
    bad = [e for e in ev if not e["integrity_ok"]]
    assert 2 in [e["seq"] for e in bad] and any("linkage" in e["integrity_reason"] for e in bad)


# ---- P0.2 SpineTailer — KEYED anchor (the red-pen negative controls) -----------------------------
def _sign_prefix(store, n):
    """Owner-sign the first n records → (SignedChainHead, TrustRoot). Real Ed25519."""
    kp = generate_keypair()
    head = sign_head(store.entries()[:n], engagement_slug="sigil", signers=[("owner", kp.private_key_b64)])
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return head, tr


def _content(d):
    return {"scope": d["scope"], "kind": d["kind"], "source": d["source"], "actor": d["actor"],
            "payload": d["payload"], "parent_id": d.get("parent_id"), "supersedes_id": d.get("supersedes_id")}


def _fork_cascade(path, from_seq, new_payload):
    """Recompute-tamper seq `from_seq`'s payload and forward-cascade cert_digest/prev/entry_hash so
    the chain stays INTERNALLY CONSISTENT (store.verify passes) — the exact attack unkeyed checks miss."""
    rows = sorted((json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()),
                  key=lambda d: d["seq"])
    prev = rows[from_seq - 1]["entry_hash"] if from_seq > 0 else _GENESIS_PREV
    for d in rows[from_seq:]:
        if d["seq"] == from_seq:
            d["payload"] = new_payload
        d["cert_digest"] = digest_payload(_content(d))
        d["prev_hash"] = prev
        d["entry_hash"] = _entry_hash(d["seq"], prev, d["cert_digest"])
        prev = d["entry_hash"]
    Path(path).write_text("\n".join(json.dumps(d, ensure_ascii=False) for d in rows) + "\n")


def test_keyed_anchor_detects_fork_below_signed_head():
    s = _store(); _append(s, 4)
    head, tr = _sign_prefix(s, 3)                        # notarize [0..2]
    t = SpineTailer(SpineStore(s.path), since_seq=-1, signed_head=head, tr=tr)
    a = t.check_anchor()
    assert a["anchor_ok"] and a["signed_last_seq"] == 2
    ev = t.poll()
    assert all(e["anchored"] for e in ev if e["seq"] <= 2), "notarized prefix is anchored"
    assert not any(e["anchored"] for e in ev if e["seq"] > 2), "records past the signed head are un-notarized"
    # recompute-fork a record BELOW the signed head + cascade → store.verify still passes, but the
    # OWNER-SIGNED head no longer matches → keyed detection fires.
    _fork_cascade(s.path, 1, {"summary": "REWROTE-HISTORY"})
    assert SpineStore(s.path).verify()[0], "the fork is internally consistent (unkeyed check is fooled)"
    a2 = SpineTailer(SpineStore(s.path), since_seq=-1, signed_head=head, tr=tr).check_anchor()
    assert not a2["anchor_ok"] and "TAMPER" in a2["reason"].upper(), "the signed head catches the recompute-fork"


def test_keyed_anchor_detects_truncation():
    s = _store(); _append(s, 4)
    head, tr = _sign_prefix(s, 4)                        # notarize all 4
    rows = Path(s.path).read_text().splitlines()
    Path(s.path).write_text("\n".join(rows[:3]) + "\n")  # truncate below the signed head
    a = SpineTailer(SpineStore(s.path), since_seq=-1, signed_head=head, tr=tr).check_anchor()
    assert not a["anchor_ok"] and ("TAMPER" in a["reason"].upper() or "truncat" in a["reason"].lower())


def test_high_water_flags_tail_rollback():
    s = _store(); _append(s, 5)
    t = SpineTailer(s, since_seq=-1); t.poll()           # high-water established at seq 4
    rows = Path(s.path).read_text().splitlines()
    Path(s.path).write_text("\n".join(rows[:3]) + "\n")  # rewind the (un-notarized) tail
    a = t.check_anchor()
    assert a["rollback"] and "ROLLBACK" in a["rollback"], "a monotonic rollback of even the tail is flagged"


def test_recompute_tip_tamper_is_labeled_unanchored_not_truth():
    # THE red-pen BLOCK-2A case: a recompute-tamper of the freshest (un-notarized) tip is well-formed
    # (integrity_ok=True) but MUST be labelled anchored=False — never served as tamper-proof truth.
    s = _store(); _append(s, 4)
    head, tr = _sign_prefix(s, 2)                        # notarize [0..1]; seq 2,3 = un-notarized tail
    _fork_cascade(s.path, 3, {"summary": "TIP-TAMPER approved wire $1,000,000"})
    ev = SpineTailer(SpineStore(s.path), since_seq=-1, signed_head=head, tr=tr).poll()
    tip = next(e for e in ev if e["seq"] == 3)
    assert tip["integrity_ok"] is True, "a recompute-tip is internally well-formed (unkeyed can't tell)"
    assert tip["anchored"] is False, "but it is HONESTLY labelled un-notarized, never proven truth"
    assert all(e["anchored"] for e in ev if e["seq"] <= 1), "the owner-signed prefix stays anchored"


# ---- FIX 1: the index-seeked iter_records SpineTailer.poll relies on matches a full scan ----------
def test_iter_records_index_seek_matches_full_scan():
    """SpineTailer.poll() reads via iter_records(since_seq=cursor). The seq→offset index seek (O(records
    returned)) must return EXACTLY what a from-scratch full scan would, for every cursor boundary — and
    a live tailer polling across an append must see exactly the new records."""
    s = _store()
    _append(s, 6)                                      # seq 0..5
    truth = [r.seq for r in SpineStore(s.path).iter_records()]   # full scan, fresh instance (no index)
    assert truth == list(range(6))
    for since in range(-1, 7):
        got = [r.seq for r in s.iter_records(since_seq=since)]   # index-seeked path on the built index
        assert got == [x for x in truth if x > since], f"index seek at since={since} must match the scan"
    t = SpineTailer(s, since_seq=-1)
    assert [e["seq"] for e in t.poll()] == list(range(6)), "first poll (full) emits all"
    _append(s, 3)                                      # seq 6..8
    assert [e["seq"] for e in t.poll()] == [6, 7, 8], "poll seeks from the cursor and matches exactly"
    assert t.poll() == [], "no new records → empty poll"


def test_broadcaster_fans_out_and_flags_lag():
    b = Broadcaster(maxlen=3)
    a = b.subscribe()
    c = b.subscribe()
    b.publish([{"seq": i} for i in range(2)])
    evs, lagged = b.drain(a)
    assert [e["seq"] for e in evs] == [0, 1] and not lagged
    b.publish([{"seq": i} for i in range(5)])          # 5 > maxlen 3 → oldest dropped, lagged
    evs2, lagged2 = b.drain(a)
    assert lagged2 and len(evs2) == 3, "overflow drops oldest and flags lag (consumer resyncs)"
    # a second subscriber that never drained also sees its own bounded queue independently
    evs3, _ = b.drain(c)
    assert len(evs3) == 3


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-7 P0 (shared primitives) guarantees hold")
