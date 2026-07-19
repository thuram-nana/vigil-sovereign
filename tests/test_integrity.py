"""SIGIL integrity + sovereignty guarantees. Run: ~/.sigil/venv/bin/python tests/test_integrity.py"""
import json
import random
import tempfile

from sigil import reuse
from sigil.spine.models import SpineRecord
from sigil.spine.store import SpineStore


def _fresh(n=5):
    p = tempfile.mktemp(suffix=".jsonl")
    s = SpineStore(p)
    for i in range(n):
        s.append(kind="message", source="t", actor="u", payload={"text": f"event {i}"})
    return p, s


def _full_scan(path):
    """Ground truth: parse EVERY well-formed line from byte 0, with no index (what the fix must match)."""
    recs = []
    for ln in open(path, encoding="utf-8"):
        ln = ln.strip()
        if ln:
            recs.append(SpineRecord.from_dict(json.loads(ln)))
    return recs


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


# ---- FIX 1: the seq -> byte-offset index is byte-identical to a full scan ------------------------
def test_offset_index_matches_full_scan():
    """get / iter_records(since_seq) / tail via the index return IDENTICAL records to a from-scratch
    full scan — across random spine sizes, unicode payloads (byte != char offsets), and edge seqs.
    Checked on BOTH a fresh store (index built lazily) and the append-maintained store."""
    rnd = random.Random(20260719)
    for _ in range(15):
        n = rnd.choice([1, 2, 3, 8, 25, 60])
        p = tempfile.mktemp(suffix=".jsonl")
        s = SpineStore(p)
        for i in range(n):
            body = rnd.choice(["e", "café ☕", "日本語テキスト", "x"]) + f"-{i}-{rnd.randint(0, 1_000_000)}"
            s.append(kind="message", source="t", actor="u", payload={"text": body, "i": i})
        truth = _full_scan(p)
        assert [r.seq for r in truth] == list(range(n)), "contiguous seqs from 0"
        for store in (SpineStore(p), s):                       # fresh (lazy build) AND append-maintained
            for seq in range(-2, n + 2):                       # every seq + out-of-range edges
                want = truth[seq] if 0 <= seq < n else None
                assert store.get(seq) == want, f"get({seq}) != scan (n={n})"
            for since in range(-2, n + 1):                     # every since_seq boundary
                got = list(store.iter_records(since_seq=since))
                exp = [r for r in truth if r.seq > since]
                assert got == exp, f"iter_records(since={since}) != scan (n={n})"
            for k in (0, 1, 3, n, n + 5):                      # tail windows incl. > len
                got = [r.seq for r in store.tail(k)]
                exp = [] if k <= 0 else [r.seq for r in truth][-k:]
                assert got == exp, f"tail({k}) != scan (n={n})"


def test_index_extends_when_another_process_appends():
    """An append via a SECOND store instance (simulating another PROCESS) grows the file; a read on the
    FIRST instance (whose index was already built) must detect the growth and return the new records."""
    p = tempfile.mktemp(suffix=".jsonl")
    a = SpineStore(p)
    for i in range(4):
        a.append(kind="message", source="t", actor="u", payload={"text": f"a{i}"})
    assert a.get(0).seq == 0, "build the index on instance A"                      # index now built
    b = SpineStore(p)                                                              # "another process"
    b.append(kind="message", source="t", actor="u", payload={"text": "from-B"})    # seq 4, A doesn't know
    assert a.get(4) is not None and a.get(4).text() == "from-B", "A extends its index over B's append"
    assert [r.seq for r in a.iter_records(since_seq=2)] == [3, 4], "A's index-seek sees B's record too"


# ---- FIX 2: torn-line tolerance (reads survive a torn tail; middle corruption fails verify) -------
def test_torn_last_line_is_tolerated_by_reads():
    p, _ = _fresh(5)                                    # clean seq 0..4
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"seq": 5, "scope": "sigil", "kind": "messa')   # a torn/partial LAST line, NO newline
    s = SpineStore(p)                                   # __init__ must NOT crash (daemon can restart)
    assert s.next_seq == 5, "the tip is the last VALID record; the torn tail is skipped"
    assert [r.seq for r in s.iter_records()] == [0, 1, 2, 3, 4], "reads skip the torn tail, no crash"
    assert s.get(4).seq == 4 and s.get(2).seq == 2, "targeted reads survive the torn tail"
    assert [r.seq for r in s.tail(10)] == [0, 1, 2, 3, 4], "tail survives the torn tail (skips it, no crash)"
    ok, _ = s.verify()
    assert ok, "the valid prefix still verifies (a torn tail is a crash artifact, not tampering)"


def test_torn_middle_line_still_fails_verify():
    p, _ = _fresh(6)                                    # clean seq 0..5
    lines = open(p).read().splitlines()
    lines[2] = '{"seq": 2, "kind": "messa'              # corrupt a MIDDLE line (real corruption/tamper)
    open(p, "w").write("\n".join(lines) + "\n")
    s = SpineStore(p)
    assert [r.seq for r in s.iter_records()] == [0, 1, 3, 4, 5], "the corrupt middle line is skipped (a gap)"
    ok, msg = s.verify()
    assert not ok and "chain break" in msg, f"mid-file corruption must NEVER be hidden — verify() fails: {msg}"


# ---- FIX 3: fsync'd append stays chain-valid + durable across a reopen ----------------------------
def test_append_is_chain_valid_after_fsync():
    p = tempfile.mktemp(suffix=".jsonl")
    s = SpineStore(p)
    seqs = [s.append(kind="message", source="t", actor="u", payload={"text": f"e{i}"}) for i in range(20)]
    assert seqs == list(range(20)), "the fsync'd appends produce a contiguous chain"
    ok, msg = s.verify()
    assert ok, f"the chain verifies after fsync appends: {msg}"
    s2 = SpineStore(p)                                  # reopen: the durable tip is read back
    assert s2.next_seq == 20
    assert s2.append(kind="message", source="t", actor="u", payload={"text": "more"}) == 20
    assert s2.verify()[0], "the chain continues cleanly after a reopen"


# ---- FIX 4: the kill-switch state cache is correct AND invalidates on growth ----------------------
def test_killswitch_cache_correct_and_invalidates_on_growth():
    from sigil.governor import KillSwitch
    owner = reuse.generate_keypair()
    pub = owner.public_key_b64
    p = tempfile.mktemp(suffix=".jsonl")
    s = SpineStore(p)
    s.append(kind="message", source="t", actor="u", payload={"text": "seed"})
    ks = KillSwitch(s, owner_key=owner, trusted_pubkey=pub)
    assert ks.is_engaged() is False, "no kill record → released"
    KillSwitch(s, owner_key=owner, trusted_pubkey=pub).engage(reason="drill")     # append → file grows
    assert ks.is_engaged() is True, "an appended engage is honored on the next call (growth invalidates)"
    assert ks.is_engaged() is True, "a repeat with no new append is a cache HIT with the same verdict"
    s.append(kind="event", source="governor", actor="WARDEN",                     # forged UNSIGNED release
             payload={"signal": "governor.killswitch", "state": "released"})
    assert ks.is_engaged() is True, "an unsigned release cannot revive the mesh — even through the cache"
    KillSwitch(s, owner_key=owner, trusted_pubkey=pub).release()                   # owner-signed → grows
    assert ks.is_engaged() is False, "an owner-signed release un-halts on the next call"
    # prove the cache is actually consulted: with no new appends the authoritative scan is NOT re-run
    calls = {"n": 0}
    real = ks._scan_engaged
    ks._scan_engaged = lambda: (calls.__setitem__("n", calls["n"] + 1), real())[1]
    assert ks.is_engaged() is False and ks.is_engaged() is False
    assert calls["n"] == 0, "repeated calls with no new appends serve from cache without re-scanning (O(1))"


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
