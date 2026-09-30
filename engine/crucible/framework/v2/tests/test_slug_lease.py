"""D1 — the per-slug engagement lease: atomic, cross-process, crash-safe.

Proves the three invariants the launch guard depends on:
  * ATOMIC single winner — of many racers for one slug (threads AND real processes) exactly one acquires it.
  * CRASH-SAFE reclaim — a holder that exits without releasing (a dead pid, a real SIGKILL'd process, a
    torn/empty marker) does not wedge the slug: the next acquirer reclaims it. A LIVE holder is never evicted.
  * RELEASE — a holder frees the slug for the next engagement, and only its OWN generation (a wrong/stale
    token is a no-op, so a lease reclaimed after a crash is never yanked from its new owner).
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import signal
import threading
import time

from framework.v2.slug_lease import SlugLease


# --- atomic single-winner: threads ----------------------------------------------------------------
def test_many_threads_racing_one_slug_yield_exactly_one_winner(tmp_path):
    lease = SlugLease(tmp_path / "leases")
    start = threading.Barrier(24)
    wins: list[bool] = []
    lock = threading.Lock()

    def _race():
        start.wait()                                  # all threads fire acquire together
        res = lease.acquire("alpha")
        with lock:
            wins.append(res.ok)

    ts = [threading.Thread(target=_race) for _ in range(24)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sum(1 for w in wins if w) == 1, f"exactly one winner expected, got {sum(wins)}"
    assert lease.is_held("alpha") is True             # the winner still holds it (this live process)


# --- atomic single-winner: real processes ---------------------------------------------------------
def _proc_worker(dirpath: str, slug: str, barrier, q) -> None:
    lease = SlugLease(dirpath)
    barrier.wait()                                     # synchronise the race across processes
    res = lease.acquire(slug)
    q.put(1 if res.ok else 0)
    time.sleep(1.0)                                    # a winner stays ALIVE so losers see a live holder


def test_two_processes_racing_one_slug_exactly_one_wins(tmp_path):
    ctx = mp.get_context("fork")
    n = 6
    barrier = ctx.Barrier(n)
    q: mp.Queue = ctx.Queue()
    procs = [ctx.Process(target=_proc_worker, args=(str(tmp_path / "leases"), "beta", barrier, q))
             for _ in range(n)]
    for p in procs:
        p.start()
    got = [q.get(timeout=15) for _ in range(n)]
    for p in procs:
        p.join(timeout=15)
    assert sum(got) == 1, f"exactly one cross-process winner expected, got {sum(got)} of {n}"


# --- crash reclaim: a dead-pid holder is reclaimable ----------------------------------------------
def test_a_dead_holder_is_reclaimable(tmp_path):
    d = tmp_path / "leases"
    lease = SlugLease(d)
    # a holder that crashed without releasing: a marker naming a pid that cannot exist.
    d.mkdir(parents=True, exist_ok=True)
    marker = lease._marker("gamma")
    marker.write_text(json.dumps({"epoch": "deadbeef", "slug": "gamma", "pid": 2_147_483_600,
                                  "boot_id": "some-old-boot", "ts": time.time()}), encoding="utf-8")
    assert lease.is_held("gamma") is False            # a dead holder does NOT read as held
    res = lease.acquire("gamma")
    assert res.ok is True                             # ...and the slug is reclaimable, not wedged
    assert lease.holder("gamma")["pid"] == os.getpid()


def test_a_live_holder_is_never_evicted(tmp_path):
    lease = SlugLease(tmp_path / "leases")
    first = lease.acquire("delta")
    assert first.ok is True
    second = lease.acquire("delta")                   # same live process holds it → the second is refused
    assert second.ok is False and "live" in second.reason
    assert lease.holder("delta")["epoch"] == first.token   # the original generation is intact


def test_a_torn_marker_is_reclaimed_only_after_the_birth_grace(tmp_path, monkeypatch):
    d = tmp_path / "leases"
    lease = SlugLease(d)
    d.mkdir(parents=True, exist_ok=True)
    marker = lease._marker("eps")
    marker.write_text("", encoding="utf-8")           # empty file: a crash between create and write
    # fresh mtime → treated as a writer mid-create (alive) → not reclaimable yet
    assert lease.is_held("eps") is True
    # age it past the birth grace → a crashed write → reclaimable
    old = time.time() - 3600
    os.utime(marker, (old, old))
    assert lease.is_held("eps") is False
    assert lease.acquire("eps").ok is True


# --- crash reclaim across REAL processes: SIGKILL a holder, the survivor reclaims ------------------
def _hold_forever(dirpath: str, slug: str, ready) -> None:
    lease = SlugLease(dirpath)
    res = lease.acquire(slug)
    ready.put(1 if res.ok else 0)
    time.sleep(120)                                    # hold until the parent kills us (a crash, no release)


def test_a_sigkilled_holder_is_reclaimed_by_the_survivor(tmp_path):
    ctx = mp.get_context("fork")
    ready: mp.Queue = ctx.Queue()
    child = ctx.Process(target=_hold_forever, args=(str(tmp_path / "leases"), "zeta", ready))
    child.start()
    assert ready.get(timeout=15) == 1                  # the child won the lease
    lease = SlugLease(tmp_path / "leases")
    assert lease.is_held("zeta") is True               # a live holder holds it
    os.kill(child.pid, signal.SIGKILL)                 # the holder crashes without releasing
    child.join(timeout=15)                             # reap it so its pid is definitively gone
    assert lease.is_held("zeta") is False              # the crashed holder no longer reads as held
    assert lease.acquire("zeta").ok is True            # ...and the slug is reclaimable — never wedged


# --- release semantics ----------------------------------------------------------------------------
def test_release_frees_the_slug_for_the_next_engagement(tmp_path):
    lease = SlugLease(tmp_path / "leases")
    a = lease.acquire("eta")
    assert a.ok is True
    assert lease.acquire("eta").ok is False            # held
    assert lease.release("eta", a.token) is True
    assert lease.is_held("eta") is False
    b = lease.acquire("eta")                            # the next engagement acquires cleanly
    assert b.ok is True and b.token != a.token


def test_release_with_a_wrong_token_never_yanks_a_live_lease(tmp_path):
    lease = SlugLease(tmp_path / "leases")
    a = lease.acquire("theta")
    assert a.ok is True
    assert lease.release("theta", "not-the-token") is False   # a stale/wrong token is a no-op
    assert lease.is_held("theta") is True                      # the live lease is untouched
    assert lease.release("theta", a.token) is True


# --- concurrent reclaimers of ONE dead marker → exactly one winner (the BLOCK regression guard) ----
def test_a_lagging_reclaimer_never_clobbers_a_freshly_reclaimed_live_lease(tmp_path):
    # Deterministic white-box model of the concurrent-reclaim clobber (no timing): acquirer A proves the
    # seeded marker dead and captures that generation; a peer B then fully reclaims it and installs a FRESH
    # LIVE lease; the LAGGING A resumes _reclaim. A must NOT unlink B's live lease — the unlink is gated on the
    # PROVEN-DEAD generation A captured, which no longer matches the marker. (On the pre-fix code A recomputed
    # the target from a fresh read and unlinked B → two live holders.)
    lease = SlugLease(tmp_path / "leases")
    lease.dir.mkdir(parents=True, exist_ok=True)
    marker = lease._marker("slug")
    marker.write_text(json.dumps({"epoch": "E_dead", "slug": "slug", "pid": 2_147_483_600,
                                  "boot_id": "old-boot", "ts": 0.0}), encoding="utf-8")
    holder_a = lease._read(marker)
    assert lease._alive(holder_a, marker) is False               # A's precondition: a dead holder
    dead_gen_a = str(holder_a["epoch"])                          # the generation A proves dead (as acquire does)
    # --- context switch to B --- B fully acquires: reclaims E_dead and installs a FRESH LIVE lease
    res_b = lease.acquire("slug")
    assert res_b.ok is True and lease.is_held("slug") is True
    e_new = lease.holder("slug")["epoch"]
    assert e_new != "E_dead"
    # --- back to A --- the lagging reclaimer runs with the generation it PROVED dead
    lease._reclaim("slug", marker, dead_gen_a)
    assert lease.is_held("slug") is True                         # B's live lease SURVIVES — no clobber
    assert lease.holder("slug")["epoch"] == e_new
    assert lease.acquire("slug").ok is False                     # A is cleanly refused by B's live holder


def _reclaim_race_worker(dirpath: str, slug: str, barrier, q) -> None:
    lease = SlugLease(dirpath)
    barrier.wait()                                               # every racer fires acquire together
    res = lease.acquire(slug)
    q.put((os.getpid(), res.token) if res.ok else None)
    time.sleep(0.5)                                              # a live winner stays alive so overlap shows


def test_concurrent_reclaimers_of_a_seeded_dead_marker_yield_exactly_one_winner(tmp_path):
    # The natural (no injected timing) proof, modelled on the red-pen's clobber_natural.py: many processes
    # race the PUBLIC acquire() over a SEEDED DEAD marker (so every racer takes the reclaim path). Exactly one
    # LIVE winner per trial — distinct pids/tokens for >1 would be the spine-forking false-negative.
    ctx = mp.get_context("fork")
    n_procs, trials = 40, 10
    for trial in range(trials):
        d = tmp_path / f"t{trial}"
        d.mkdir(parents=True, exist_ok=True)
        seed = SlugLease(d)
        seed.dir.mkdir(parents=True, exist_ok=True)
        seed._marker("beta").write_text(json.dumps({"epoch": "E_dead", "slug": "beta", "pid": 2_147_483_600,
                                                     "boot_id": "old-boot", "ts": 0.0}), encoding="utf-8")
        barrier = ctx.Barrier(n_procs)
        q: mp.Queue = ctx.Queue()
        procs = [ctx.Process(target=_reclaim_race_worker, args=(str(d), "beta", barrier, q))
                 for _ in range(n_procs)]
        for p in procs:
            p.start()
        got = [q.get(timeout=40) for _ in range(n_procs)]
        for p in procs:
            p.join(timeout=40)
        winners = [g for g in got if g]
        assert len(winners) == 1, f"trial {trial}: expected exactly one live winner, got {winners}"


def test_rebind_repoints_liveness_at_the_child_and_only_our_generation(tmp_path):
    lease = SlugLease(tmp_path / "leases")
    a = lease.acquire("iota")                          # holder pid = this (launcher) process
    assert a.ok is True
    # rebinding to a DEAD child pid makes the lease stale (the engagement process is what matters now)
    assert lease.rebind("iota", a.token, 2_147_483_600) is True
    assert lease.holder("iota")["pid"] == 2_147_483_600
    assert lease.is_held("iota") is False              # dead child → reclaimable, not wedged
    # a rebind with the wrong token never touches a live lease
    b = lease.acquire("iota")                          # reclaims the stale one, fresh generation
    assert b.ok is True
    assert lease.rebind("iota", "not-the-token", os.getpid()) is False
    assert lease.holder("iota")["epoch"] == b.token    # untouched


def test_empty_slug_is_refused(tmp_path):
    lease = SlugLease(tmp_path / "leases")
    assert lease.acquire("").ok is False
    assert lease.acquire("   ").ok is False
    assert lease.is_held("") is False
