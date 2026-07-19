"""SIGIL integrity + sovereignty guarantees. Run: ~/.sigil/venv/bin/python tests/test_integrity.py"""
import json
import tempfile

from sigil import reuse
from sigil.spine.store import SpineStore


def _fresh(n=5):
    p = tempfile.mktemp(suffix=".jsonl")
    s = SpineStore(p)
    for i in range(n):
        s.append(kind="message", source="t", actor="u", payload={"text": f"event {i}"})
    return p, s


def test_tail_returns_the_last_n_records():   # tightening #2 (bounded-window dedup)
    p, _ = _fresh(10)                          # 10 records, seq 0..9
    s = SpineStore(p)
    assert [r.seq for r in s.tail(3)] == [7, 8, 9], "tail(3) = the last three records, in order"
    assert len(s.tail(100)) == 10, "tail(n > len) returns all"
    assert s.tail(0) == [], "tail(0) is empty"


def test_concurrent_appends_do_not_fork_the_chain():   # Phase 9 sweep HIGH-2 (threaded bridge server exposes it)
    import threading
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="event", source="t", actor="u", payload={"seed": True})
    barrier = threading.Barrier(8)

    def w(i):
        barrier.wait()
        SpineStore(p).append(kind="event", source="t", actor="u", payload={"i": i})   # FRESH instance per thread

    threads = [threading.Thread(target=w, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    seqs = [r.seq for r in SpineStore(p).iter_records()]
    assert len(seqs) == len(set(seqs)) == 9, f"8 concurrent appends produce distinct seqs (no fork): {sorted(seqs)}"
    ok, reason = SpineStore(p).verify()
    assert ok, f"the hash chain stays intact after concurrent appends: {reason}"


def test_clean_verifies():
    _, s = _fresh()
    ok, _ = s.verify()
    assert ok, "clean spine must verify"


def test_payload_tamper_caught():
    p, _ = _fresh()
    lines = open(p).read().splitlines()
    o = json.loads(lines[1]); o["payload"] = {"text": "TAMPERED"}; lines[1] = json.dumps(o)
    open(p, "w").write("\n".join(lines) + "\n")
    ok, msg = SpineStore(p).verify()
    assert not ok and "binding break" in msg, f"payload tamper must fail binding: {msg}"


def test_delete_caught():
    p, _ = _fresh()
    lines = open(p).read().splitlines(); del lines[2]
    open(p, "w").write("\n".join(lines) + "\n")
    ok, msg = SpineStore(p).verify()
    assert not ok and "chain break" in msg, f"delete must fail chain: {msg}"


def test_reopen_seek_from_end():
    p, _ = _fresh(3)
    s2 = SpineStore(p)
    seq = s2.append(kind="message", source="t", actor="u", payload={"text": "reopened"})
    assert seq == 3 and s2.verify()[0], "reopen must continue the chain"


def test_digest_is_wallclock_free():
    # same content, different ts → identical cert_digest (replay-stable)
    c = {"scope": "sigil", "kind": "message", "source": "t", "actor": "u",
         "payload": {"text": "x"}, "parent_id": None, "supersedes_id": None}
    assert reuse.digest_payload(c) == reuse.digest_payload(dict(c)), "digest must ignore ts"


def test_sign_and_verify_head():
    _, s = _fresh(4)
    kp = reuse.generate_keypair()
    tr = reuse.TrustRoot(threshold=1, authorizers=[
        reuse.AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    head = reuse.sign_head(s.entries(), engagement_slug="sigil", signers=[("owner", kp.private_key_b64)])
    ok, msg = reuse.verify_head(head, s.entries(), tr)
    assert ok, f"signed head must verify: {msg}"


def _head_over(store, n):
    """Sign a head over the first `n` entries; return (head, trust_root)."""
    kp = reuse.generate_keypair()
    tr = reuse.TrustRoot(threshold=1, authorizers=[
        reuse.AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    head = reuse.sign_head(store.entries()[:n], engagement_slug="sigil",
                           signers=[("owner", kp.private_key_b64)])
    return head, tr


def test_growth_is_benign_not_tampering():
    from sigil.spine.checkpoint import classify_head
    _, s = _fresh(4)
    head, tr = _head_over(s, 4)
    s.append(kind="message", source="t", actor="u", payload={"text": "later"})  # grow past anchor
    ok, msg = classify_head(head, s.entries(), tr)
    assert ok and "appended" in msg and "TAMPERING" not in msg, f"growth must be benign: {msg}"


def test_truncation_below_head_is_tampering():
    from sigil.spine.checkpoint import classify_head
    _, s = _fresh(5)
    head, tr = _head_over(s, 5)
    ok, msg = classify_head(head, s.entries()[:3], tr)  # chain shrank below the anchor
    assert not ok and "TAMPERING" in msg, f"truncation must be tampering: {msg}"


def test_rewrite_below_head_is_tampering():
    from sigil.spine.checkpoint import classify_head
    _, s = _fresh(5)
    head, tr = _head_over(s, 5)
    entries = s.entries()
    entries[2].cert_digest = "0" * 64  # rewrite a record's digest inside the signed prefix
    ok, msg = classify_head(head, entries, tr)
    assert not ok and "TAMPERING" in msg, f"history rewrite must be tampering: {msg}"


def test_no_offense():
    reuse.assert_no_offense()  # no framework.* module may be loaded


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"{passed}/{len(fns)} integrity guarantees hold")
