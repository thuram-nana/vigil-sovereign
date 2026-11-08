"""SCALE-C1b — concurrent-append COALESCING (leader/follower group commit) on SpineStore.

C1a shipped ``append_many([...])`` (one fsync for a batch a SINGLE caller holds). C1b adds a thin
commit-coalescing front-end (default-OFF) that gathers INDEPENDENT concurrent ``append()`` calls (different
threads) into one group and delegates the actual write to the EXISTING ``append_many`` on a LEADER thread —
one fsync per group instead of one per caller (the 1M-scale concurrent-append throughput wall).

These pin both the CORRECTNESS (chain contiguity, verify(), per-caller attribution, the re-entrant
``envelope.consume`` TOCTOU replay gate, poison-payload isolation, leader-exception fan-out + safe retry) and
the OPTIMISATION (fsync amortized across a group, durable-before-ack, a single leader). Every threaded case
joins with a TIMEOUT so a deadlock/livelock FAILS LOUDLY instead of hanging the suite.

The flag is driven ON per-store via ``store._group_commit_coalesce = True`` (what the store reads at
construction from ``config.SPINE_GROUP_COMMIT_COALESCE``); default-OFF stores exercise the byte-identical
legacy path. Sovereign leg: PYTHONPATH=apps/sigil:packages/core/vigil_core, SIGIL_HOME=$(mktemp -d).
"""
from __future__ import annotations

import tempfile
import threading
import time

import pytest

from sigil.bridge import build_core, consume, sign_envelope
from sigil.mesh import authorize_device, authorized_devices
from sigil.reuse import generate_keypair
from sigil.spine import store as store_mod
from sigil.spine.models import KINDS
from sigil.spine.store import SpineStore, spine_lock

_KIND = sorted(KINDS)[0]
_JOIN_TIMEOUT = 20.0                                         # watchdog: a deadlock must FAIL, never hang the suite
_OWNER = generate_keypair()


def _store():
    """A fresh store with the coalescing flag at its DEFAULT (OFF)."""
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _store_on():
    """A fresh store with commit-coalescing turned ON (what the config flag does, set on the instance)."""
    s = _store()
    s._group_commit_coalesce = True
    return s


def _thr(*args, **kwargs):
    """A DAEMON thread (always). If a mutation makes a test deadlock, the watchdog assertion fails on the
    wall-clock deadline AND the leaked thread — being a daemon — never blocks interpreter shutdown, so the
    suite fails fast instead of hanging at process exit."""
    kwargs["daemon"] = True
    return threading.Thread(*args, **kwargs)


def _join_all(threads, *, timeout: float = _JOIN_TIMEOUT) -> None:
    """Join every thread against ONE wall-clock deadline (NOT per-thread, so a deadlock fails in ~timeout
    seconds regardless of thread count) and assert NONE is still alive — a coalescing deadlock/livelock
    surfaces as a loud, BOUNDED test failure, never a hung suite."""
    deadline = time.monotonic() + timeout
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))
    alive = [t.name for t in threads if t.is_alive()]
    assert not alive, f"thread(s) did not finish within {timeout}s — deadlock/livelock under coalescing: {alive}"


def _run_barrier_appends(s: SpineStore, n: int) -> dict:
    """Release ``n`` threads SIMULTANEOUSLY (a threading.Barrier), each doing exactly ONE ``append()`` with a
    DISTINCT actor/source/payload. Returns {i: assigned_seq}. Joins with the watchdog."""
    bar = threading.Barrier(n)
    got: dict = {}

    def worker(i: int) -> None:
        bar.wait()
        got[i] = s.append(kind=_KIND, source=f"src-{i}", actor=f"actor-{i}", payload={"i": i})

    ts = [_thr(target=worker, args=(i,), name=f"app-{i}") for i in range(n)]
    for t in ts:
        t.start()
    _join_all(ts)
    assert len(got) == n, f"only {len(got)}/{n} appends completed"
    return got


# --------------------------------------------------------------------------------------------------
# (1) CORRECTNESS — N concurrent appends coalesce into ONE contiguous, verified, correctly-attributed chain.
# --------------------------------------------------------------------------------------------------
def test_concurrent_appends_coalesce_into_one_contiguous_attributed_chain():
    s = _store_on()
    n = 24
    got = _run_barrier_appends(s, n)
    # union of the returned seqs is EXACTLY {0..N-1}: no duplicate (a fork) and no gap (a lost append)
    assert sorted(got.values()) == list(range(n)), f"returned seqs must be the full set 0..{n - 1}: {sorted(got.values())}"
    assert len(set(got.values())) == n, "duplicate seq → a forked chain"
    recs = list(s.iter_records())
    assert [r.seq for r in recs] == list(range(n)), "iter_records must be ONE contiguous 0..N-1 chain"
    # per-caller attribution: each record carries ITS OWN caller's actor/source (no cross-attribution)
    for r in recs:
        i = r.payload["i"]
        assert r.actor == f"actor-{i}" and r.source == f"src-{i}", (
            f"cross-attribution at seq {r.seq}: actor={r.actor!r} source={r.source!r} for payload i={i}")
    ok, why = s.verify()
    assert ok, f"verify() must be green after coalesced concurrent appends: {why}"


# --------------------------------------------------------------------------------------------------
# (2) FSYNC AMORTIZATION — coalescing cuts fsyncs far below K; flag OFF pays one fsync per append.
# --------------------------------------------------------------------------------------------------
def test_fsync_is_amortized_under_coalescing_and_one_per_append_without(monkeypatch):
    k = 32
    calls = {"n": 0}
    real = store_mod.os.fsync

    def counting(fd):
        calls["n"] += 1
        time.sleep(0.003)                                   # widen the leader's write window → reliable coalescing
        return real(fd)

    monkeypatch.setattr(store_mod.os, "fsync", counting)

    # flag ON → one fsync per GROUP → substantially fewer than K
    s = _store_on()
    got = _run_barrier_appends(s, k)
    on = calls["n"]
    assert sorted(got.values()) == list(range(k))           # still perfectly correct
    assert 1 <= on <= k // 2, f"coalescing must amortize fsync substantially below K={k}, got {on}"

    # flag OFF → one fsync PER append == K (byte-identical to today)
    calls["n"] = 0
    t = _store()
    got2 = _run_barrier_appends(t, k)
    off = calls["n"]
    assert sorted(got2.values()) == list(range(k))
    assert off == k, f"flag OFF must fsync exactly once per append: {off} != {k}"


# --------------------------------------------------------------------------------------------------
# (3a) RE-ENTRANT NO-DEADLOCK — an append wrapped in spine_lock (envelope.consume-style) completes.
# --------------------------------------------------------------------------------------------------
def test_reentrant_append_under_spine_lock_completes_under_coalescing():
    s = _store_on()
    out: dict = {}

    def go() -> None:
        with spine_lock(s.path):                            # an OUTER check-then-append txn holds the lock
            out["seq"] = s.append(kind=_KIND, source="re", actor="re", payload={"x": 1})

    t = _thr(target=go, name="reentrant")
    t.start()
    _join_all([t], timeout=5.0)
    assert out.get("seq") == 0, f"a re-entrant append must take the DIRECT path and return seq 0: {out}"
    assert [r.seq for r in s.iter_records()] == [0]
    assert s.verify()[0]


# --------------------------------------------------------------------------------------------------
# (3b) RE-ENTRANT NO-DEADLOCK — the deterministic deadlock guard for the _is_owned() routing itself.
# --------------------------------------------------------------------------------------------------
def test_reentrant_holder_is_routed_direct_not_queued_behind_a_leader(monkeypatch):
    """The DETERMINISTIC guard that re-entrant spine_lock holders MUST route DIRECT. We force the exact
    interleaving the routing prevents: a LEADER L enters append_many() and BLOCKS acquiring spine_lock
    because thread R already holds it; R, still holding spine_lock, then appends. With the _is_owned()
    routing intact, R goes DIRECT and both finish; WITHOUT it (the mutation) R is queued as a FOLLOWER
    behind L and the two DEADLOCK — the watchdog join times out and this FAILS."""
    s = _store_on()
    r_holds = threading.Event()
    leader_in_append_many = threading.Event()

    real_am = s.append_many

    def wrapped_am(specs):
        leader_in_append_many.set()                         # L is leading and about to block on spine_lock (R holds it)
        return real_am(specs)

    monkeypatch.setattr(s, "append_many", wrapped_am)

    results: dict = {}

    def thread_r() -> None:
        with spine_lock(s.path):
            r_holds.set()
            assert leader_in_append_many.wait(timeout=5), "the leader never entered append_many"
            results["R"] = s.append(kind=_KIND, source="R", actor="R", payload={"who": "R"})

    def thread_l() -> None:
        assert r_holds.wait(timeout=5), "R never took spine_lock"
        results["L"] = s.append(kind=_KIND, source="L", actor="L", payload={"who": "L"})

    tr = _thr(target=thread_r, name="R-holds-lock")
    tl = _thr(target=thread_l, name="L-leader")
    tr.start()
    tl.start()
    _join_all([tr, tl], timeout=10.0)                        # DEADLOCK under the mutation → fails here
    assert sorted(results.values()) == [0, 1], f"both appends must land exactly once: {results}"
    assert [r.seq for r in s.iter_records()] == [0, 1]
    assert s.verify()[0]


# --------------------------------------------------------------------------------------------------
# (3c) RE-ENTRANT — two concurrent envelope.consume of ONE captured nonce still REFUSE the replay (TOCTOU).
# --------------------------------------------------------------------------------------------------
def _authorized_device(s: SpineStore):
    device = generate_keypair()
    authorize_device(s, "phone-1", device.public_key_b64, _OWNER, issued_at=1.0)
    return device, authorized_devices(s, _OWNER.public_key_b64)


def test_concurrent_consume_of_one_nonce_still_refuses_replay_under_coalescing():
    """The envelope.consume TOCTOU replay gate stays intact with coalescing ON. consume holds the re-entrant
    spine_lock across the nonce high-water read AND the receipt append, and that inner append is routed DIRECT
    (the lock is held on this thread), so two concurrent replays of ONE captured envelope can't both pass."""
    s = _store_on()
    device, authorized = _authorized_device(s)
    env = sign_envelope(device, build_core(device.public_key_b64, "panic", {}, 1, 1700000001))
    bar = threading.Barrier(2)
    results: list = []
    lk = threading.Lock()

    def go() -> None:
        bar.wait()
        try:
            core = consume(s, env, authorized, effectful=True)
            with lk:
                results.append(("ok", core["nonce"]))
        except ValueError as e:
            with lk:
                results.append(("refused", str(e)))

    ts = [_thr(target=go, name=f"consume-{i}") for i in range(2)]
    for t in ts:
        t.start()
    _join_all(ts, timeout=10.0)
    oks = [r for r in results if r[0] == "ok"]
    refused = [r for r in results if r[0] == "refused"]
    assert len(oks) == 1, f"EXACTLY one concurrent consume of one nonce may succeed: {results}"
    assert len(refused) == 1 and "replay" in refused[0][1], f"the other must be a replay refusal: {results}"
    assert s.verify()[0]


# --------------------------------------------------------------------------------------------------
# (4) POISON-PAYLOAD ISOLATION — a non-serializable payload fails ONLY its owner, never its co-batch.
# --------------------------------------------------------------------------------------------------
def test_poison_payload_fails_only_its_owner_not_the_coalesced_batch(monkeypatch):
    """A payload only ``json.dumps`` finds non-serializable must fail ONLY its own caller (pre-flighted before
    enqueue), so the all-serializable batch the leader hands to append_many commits. We deterministically put
    a good append and a poison append into the SAME second group (behind a primer leader held mid-write):
    the good one must SUCCEED and the poison one must RAISE, with the chain contiguous over the good records."""
    s = _store_on()
    primer_leading = threading.Event()
    let_primer_go = threading.Event()
    calls = {"n": 0}
    real_am = s.append_many

    def wrapped(specs):
        calls["n"] += 1
        if calls["n"] == 1:                                 # hold the FIRST leader so good+poison queue behind it
            primer_leading.set()
            assert let_primer_go.wait(timeout=5)
        return real_am(specs)

    monkeypatch.setattr(s, "append_many", wrapped)
    results: dict = {}

    def primer() -> None:
        results["primer"] = s.append(kind=_KIND, source="primer", actor="primer", payload={"p": 1})

    def good() -> None:
        assert primer_leading.wait(timeout=5)
        try:
            results["good"] = ("ok", s.append(kind=_KIND, source="g", actor="g", payload={"i": 1}))
        except Exception as e:                              # noqa: BLE001 — must NOT happen (isolation)
            results["good"] = ("err", type(e).__name__)

    def poison() -> None:
        assert primer_leading.wait(timeout=5)
        try:
            s.append(kind=_KIND, source="p", actor="p", payload={"bad": object()})
            results["poison"] = ("ok", None)
        except Exception as e:                              # noqa: BLE001 — EXPECTED (fails only its owner)
            results["poison"] = ("err", type(e).__name__)

    tp = _thr(target=primer, name="primer")
    tg = _thr(target=good, name="good")
    tx = _thr(target=poison, name="poison")
    tp.start()
    assert primer_leading.wait(timeout=5), "primer never became the leader"
    tg.start()
    tx.start()
    time.sleep(0.2)                                         # let good + poison enqueue (or poison pre-raise) behind primer
    let_primer_go.set()
    _join_all([tp, tg, tx], timeout=10.0)
    assert results["poison"][0] == "err", f"the poison caller MUST raise: {results.get('poison')}"
    assert results["good"][0] == "ok", f"the innocent co-batched append MUST succeed (poison isolated): {results.get('good')}"
    assert [r.seq for r in s.iter_records()] == [0, 1], "chain is contiguous over the good records; poison never landed"
    assert s.verify()[0]


# --------------------------------------------------------------------------------------------------
# (5) LEADER-EXCEPTION FAN-OUT — append_many raising fails EVERY batch waiter; a retry has no duplicate.
# --------------------------------------------------------------------------------------------------
def test_leader_exception_fans_out_to_every_waiter_and_retry_has_no_duplicate(monkeypatch):
    """When the leader's append_many RAISES (and rolls back atomically — NOTHING acked), EVERY waiter in that
    batch must raise, so each may safely retry. We coalesce two followers into one batch (behind a primer),
    make THAT batch's append_many raise once, and assert both followers raise AND their retries land with NO
    duplicate (at-least-once over the contiguous chain)."""
    s = _store_on()
    primer_leading = threading.Event()
    let_go = threading.Event()
    calls = {"n": 0}
    real_am = s.append_many
    boom = RuntimeError("append_many boom")

    def wrapped(specs):
        calls["n"] += 1
        if calls["n"] == 1:                                 # primer: hold leadership so the two followers coalesce
            primer_leading.set()
            assert let_go.wait(timeout=5)
            return real_am(specs)
        if calls["n"] == 2:                                 # the coalesced follower batch fails as a UNIT
            raise boom
        return real_am(specs)                               # a later retry succeeds

    monkeypatch.setattr(s, "append_many", wrapped)
    first_err: dict = {}
    retry_seq: dict = {}

    def primer() -> None:
        s.append(kind=_KIND, source="primer", actor="primer", payload={"p": 1})

    def follower(tag: str) -> None:
        assert primer_leading.wait(timeout=5)
        try:
            s.append(kind=_KIND, source=tag, actor=tag, payload={"t": tag})
            first_err[tag] = None                           # MUST NOT reach here — the batch failed as a unit
        except Exception as e:                              # noqa: BLE001 — EXPECTED fan-out
            first_err[tag] = type(e).__name__
        # retry: the failed batch rolled back (nothing acked), so this writes a FRESH seq with no duplicate
        retry_seq[tag] = s.append(kind=_KIND, source=tag, actor=tag, payload={"t": tag, "retry": True})

    tp = _thr(target=primer, name="primer")
    ta = _thr(target=follower, args=("A",), name="A")
    tb = _thr(target=follower, args=("B",), name="B")
    tp.start()
    assert primer_leading.wait(timeout=5)
    ta.start()
    tb.start()
    time.sleep(0.2)                                         # let A and B BOTH enqueue into the one (to-fail) batch
    let_go.set()
    _join_all([tp, ta, tb], timeout=10.0)
    assert first_err.get("A") == "RuntimeError" and first_err.get("B") == "RuntimeError", (
        f"EVERY waiter in the failed batch must raise (fan-out), got {first_err}")
    assert sorted(retry_seq.values()) == [1, 2], f"retries land with NO duplicate on the contiguous chain: {retry_seq}"
    assert [r.seq for r in s.iter_records()] == [0, 1, 2], "primer(0) + the two retries(1,2); the failed batch left nothing"
    assert s.verify()[0]


# --------------------------------------------------------------------------------------------------
# (6) DURABLE-BEFORE-ACK — a coalesced caller is signaled ONLY after the group's single fsync.
# --------------------------------------------------------------------------------------------------
def test_coalesced_callers_are_signaled_only_after_the_fsync(monkeypatch):
    """Every coalesced ack must be durable-before-ack: a caller returns ONLY after the ONE append_many that
    makes ITS record durable (append_many writes + fsyncs, then returns). We track the durable high-water
    ``durable_upto`` = the highest seq whose group's append_many has fully RETURNED (post-fsync), and record
    what each caller observes at the instant its append() returns. The invariant is ``seq <= durable_upto``:
    a caller acked before its OWN group's fsync completes sees a high-water BELOW its seq (a prior group's
    fsync cannot mask this — the check is per-record, not a global count)."""
    k = 16
    s = _store_on()
    durable = {"upto": -1}
    real_am = s.append_many

    def wrapped(specs):
        time.sleep(0.02)                                    # widen the window so ack-before-fsync is caught deterministically
        seqs = real_am(specs)                               # real: writes + ONE fsync; RETURNS only once the batch is durable
        if seqs:
            durable["upto"] = max(durable["upto"], max(seqs))
        return seqs

    monkeypatch.setattr(s, "append_many", wrapped)
    bar = threading.Barrier(k)
    observed: dict = {}

    def worker(i: int) -> None:
        bar.wait()
        seq = s.append(kind=_KIND, source=f"src-{i}", actor=f"actor-{i}", payload={"i": i})
        observed[i] = (seq, durable["upto"])                # the durable high-water at the instant our ack returned

    ts = [_thr(target=worker, args=(i,), name=f"dba-{i}") for i in range(k)]
    for t in ts:
        t.start()
    _join_all(ts)
    for i, (seq, upto) in observed.items():
        assert isinstance(seq, int), f"caller {i} got a non-int seq {seq!r} (acked before the write assigned one?)"
        assert seq <= upto, (
            f"caller {i} (seq {seq}) was acked BEFORE its record's group fsync completed "
            f"(durable high-water {upto}) — durable-before-ack violated")
    assert sorted(seq for seq, _ in observed.values()) == list(range(k))
    assert s.verify()[0]


# --------------------------------------------------------------------------------------------------
# (7) SINGLE LEADER — no two append_many run concurrently (the _leader_inflight gate).
# --------------------------------------------------------------------------------------------------
def test_only_one_leader_runs_append_many_at_a_time(monkeypatch):
    """The single-leader gate (``_leader_inflight``) must ensure only ONE group-commit leader is in append_many
    at a time — otherwise concurrent leaders each lead a tiny batch and the amortization collapses. We wrap
    append_many to track its max concurrency; it must never exceed 1."""
    k = 24
    s = _store_on()
    conc = {"cur": 0, "max": 0}
    lk = threading.Lock()
    real_am = s.append_many

    def probe(specs):
        with lk:
            conc["cur"] += 1
            conc["max"] = max(conc["max"], conc["cur"])
        try:
            time.sleep(0.003)                               # widen the window so a second leader WOULD overlap
            return real_am(specs)
        finally:
            with lk:
                conc["cur"] -= 1

    monkeypatch.setattr(s, "append_many", probe)
    got = _run_barrier_appends(s, k)
    assert sorted(got.values()) == list(range(k)), "the capped-batch chain is still contiguous"
    assert conc["max"] == 1, f"a SECOND leader ran append_many concurrently (single-leader gate broken): max={conc['max']}"
    assert s.verify()[0]


# --------------------------------------------------------------------------------------------------
# (8) FLAG OFF equivalence — byte-identical to today: one fsync per append, the queue is never touched.
# --------------------------------------------------------------------------------------------------
def test_flag_off_is_byte_identical_and_never_touches_the_queue(monkeypatch):
    calls = {"n": 0}
    real = store_mod.os.fsync

    def counting(fd):
        calls["n"] += 1
        return real(fd)

    monkeypatch.setattr(store_mod.os, "fsync", counting)
    s = _store()                                            # flag at its DEFAULT (OFF)
    assert s._group_commit_coalesce is False
    for i in range(5):
        assert s.append(kind=_KIND, source=f"s{i}", actor=f"a{i}", payload={"i": i}) == i
    assert calls["n"] == 5, f"flag OFF must fsync exactly once per append: {calls['n']}"
    assert s._commit_queue == [], "flag OFF must NEVER touch the coalescing queue"
    assert s._leader_inflight is False
    assert [r.seq for r in s.iter_records()] == [0, 1, 2, 3, 4]
    assert s.verify()[0]
