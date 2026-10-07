"""
Lane O / O1 — the fleet concurrency controls are CROSS-PROCESS, not just cross-thread.

The engagement scheduler is a MULTI-PROCESS queue, so the serial-proof-per-target invariant (and the
per-host rate cap / per-tenant budget) must hold across PROCESSES. The in-process ``threading.Lock``
versions proven in ``test_fleet_concurrency`` / ``test_serial_proof_invariant`` do NOT — this file proves
the cross-process backing does, with REAL ``multiprocessing`` child processes (not threads) coordinating
only through the on-disk ``flock`` + counter files under a tmp dir.

Proven here:
  1. Two PROCESSES requesting a PROOF slot for the SAME host SERIALIZE — the second blocks until the first
     releases (its enter is not before the first's exit).
  2. Two PROCESSES proving DIFFERENT hosts run CONCURRENTLY (their hold intervals overlap).
  3. SEARCH through the governor runs CONCURRENTLY across processes against one host (never serialized).
  4. The per-host rate cap is shared across processes (N processes see ONE window).
  5. The per-tenant budget is shared across processes (N processes see ONE budget).
  6. ``default_fleet_governor`` wires the cross-process backing and does not refuse by default.
"""

from __future__ import annotations

import multiprocessing as mp
import time

from ..fleet import (
    FleetConcurrencyGovernor,
    HostRateLimiter,
    ProofSerializer,
    TenantBudget,
    WorkKind,
    default_fleet_governor,
)

_CTX = mp.get_context("fork")   # Linux worker model the scheduler uses; children inherit imports


# --------------------------------------------------------------------------------------------------
# module-level workers (picklable for any start method; coordinate only via the on-disk lock/counter)
# --------------------------------------------------------------------------------------------------
def _proof_hold(xdir: str, host: str, label: str, hold_s: float, q, go) -> None:
    ps = ProofSerializer(xproc_dir=xdir)
    go.wait(10.0)
    q.put((label, "request", time.time()))
    with ps.proof(host):
        q.put((label, "enter", time.time()))
        time.sleep(hold_s)
        q.put((label, "exit", time.time()))


def _search_hold(xdir: str, host: str, label: str, hold_s: float, q, barrier) -> None:
    gov = FleetConcurrencyGovernor(
        host_rate_limiter=HostRateLimiter(max_per_window=10**9, window_seconds=1.0, xproc_dir=xdir),
        tenant_budget=TenantBudget({}, default=10**9, xproc_dir=xdir),
        proof_serializer=ProofSerializer(xproc_dir=xdir),
    )
    with gov.engage(target=host, tenant="acme", kind=WorkKind.SEARCH):
        q.put((label, "enter", time.time()))
        # If SEARCH were serialized, a barrier of N would deadlock and the test times out.
        try:
            barrier.wait(timeout=10.0)
        except Exception:
            q.put((label, "barrier_broke", time.time()))
        q.put((label, "exit", time.time()))


def _rate_try(xdir: str, host: str, label: str, q) -> None:
    rl = HostRateLimiter(max_per_window=3, window_seconds=10_000.0, xproc_dir=xdir)
    q.put((label, rl.try_acquire(host, now=0.0)))   # fixed now ⇒ window never slides, deterministic


def _budget_charge(xdir: str, tenant: str, label: str, q) -> None:
    b = TenantBudget({"acme": 3}, default=0, xproc_dir=xdir)
    q.put((label, b.charge(tenant)))


def _events(q, n_expected: int, timeout: float = 20.0) -> list:
    out: list = []
    deadline = time.time() + timeout
    while len(out) < n_expected and time.time() < deadline:
        try:
            out.append(q.get(timeout=max(0.01, deadline - time.time())))
        except Exception:
            break
    return out


# --------------------------------------------------------------------------------------------------
# 1. same-host PROOF serializes across PROCESSES
# --------------------------------------------------------------------------------------------------
def test_proof_serializes_across_processes_same_host(tmp_path) -> None:
    xdir = str(tmp_path)
    host = "https://app.example.com/x"
    q = _CTX.Queue()
    go_a = _CTX.Event()
    go_b = _CTX.Event()

    a = _CTX.Process(target=_proof_hold, args=(xdir, host, "A", 0.6, q, go_a))
    b = _CTX.Process(target=_proof_hold, args=(xdir, host, "B", 0.1, q, go_b))
    a.start()
    b.start()

    # Release A first and wait until it has ENTERED the proof (holds the cross-process lock).
    go_a.set()
    ev: dict = {}
    seen: list = []
    deadline = time.time() + 10.0
    while ("A", "enter") not in {(l, e) for (l, e, *_rest) in seen} and time.time() < deadline:
        item = q.get(timeout=10.0)
        seen.append(item)
    # Now release B; it must BLOCK on the same host's cross-process proof lock until A exits.
    go_b.set()

    a.join(20.0)
    b.join(20.0)
    assert not a.is_alive() and not b.is_alive()

    seen.extend(_events(q, n_expected=100, timeout=2.0))
    for (label, event, ts) in seen:
        ev[(label, event)] = ts

    assert {"A", "B"} <= {l for (l, _e) in ev}, ev
    a_exit = ev[("A", "exit")]
    b_enter = ev[("B", "enter")]
    b_request = ev[("B", "request")]
    # B asked for the slot WHILE A still held it (it genuinely contended, not merely ran after A finished)...
    assert b_request <= a_exit + 0.05, ev
    # ...and could not ENTER until A RELEASED — the serialization: B's enter is at/after A's exit.
    assert b_enter >= a_exit - 0.01, f"B entered before A released (not serialized): {ev}"


# --------------------------------------------------------------------------------------------------
# 2. different-host PROOF runs concurrently across PROCESSES
# --------------------------------------------------------------------------------------------------
def test_proof_different_hosts_run_concurrently_across_processes(tmp_path) -> None:
    xdir = str(tmp_path)
    q = _CTX.Queue()
    go = _CTX.Event()
    a = _CTX.Process(target=_proof_hold, args=(xdir, "https://a.example.com/", "A", 0.6, q, go))
    b = _CTX.Process(target=_proof_hold, args=(xdir, "https://b.example.com/", "B", 0.6, q, go))
    a.start()
    b.start()
    go.set()
    a.join(20.0)
    b.join(20.0)
    assert not a.is_alive() and not b.is_alive()

    ev = {(l, e): ts for (l, e, ts) in _events(q, n_expected=6, timeout=5.0)}
    # Different hosts ⇒ independent locks ⇒ the two hold intervals OVERLAP.
    assert ev[("A", "enter")] <= ev[("B", "exit")] and ev[("B", "enter")] <= ev[("A", "exit")], ev
    # Specifically, one entered before the other exited (concurrency, not back-to-back).
    assert ev[("B", "enter")] < ev[("A", "exit")] or ev[("A", "enter")] < ev[("B", "exit")], ev


# --------------------------------------------------------------------------------------------------
# 3. SEARCH runs concurrently across PROCESSES through the governor
# --------------------------------------------------------------------------------------------------
def test_search_runs_concurrently_across_processes(tmp_path) -> None:
    xdir = str(tmp_path)
    host = "https://app.example.com/x"
    n = 4
    q = _CTX.Queue()
    barrier = _CTX.Barrier(n)   # only all-cross-at-once if the n SEARCHes run concurrently
    procs = [
        _CTX.Process(target=_search_hold, args=(xdir, host, f"S{i}", 0.2, q, barrier))
        for i in range(n)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(20.0)
    assert all(not p.is_alive() for p in procs)
    events = _events(q, n_expected=n * 2, timeout=5.0)
    labels_broken = [l for (l, e, *_r) in events if e == "barrier_broke"]
    assert not labels_broken, f"SEARCH was serialized — barrier broke for {labels_broken}"
    enters = [ts for (l, e, ts) in events if e == "enter"]
    assert len(enters) == n, events


# --------------------------------------------------------------------------------------------------
# 4. rate cap shared across PROCESSES
# --------------------------------------------------------------------------------------------------
def test_rate_limiter_shared_across_processes(tmp_path) -> None:
    xdir = str(tmp_path)
    host = "app.example.com"
    n = 8
    q = _CTX.Queue()
    procs = [_CTX.Process(target=_rate_try, args=(xdir, host, f"R{i}", q)) for i in range(n)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(20.0)
    grants = [g for (_l, g) in _events(q, n_expected=n, timeout=5.0)]
    assert grants.count(True) == 3, grants   # ONE window of 3 shared by all 8 processes


# --------------------------------------------------------------------------------------------------
# 5. budget shared across PROCESSES
# --------------------------------------------------------------------------------------------------
def test_budget_shared_across_processes(tmp_path) -> None:
    xdir = str(tmp_path)
    n = 8
    q = _CTX.Queue()
    procs = [_CTX.Process(target=_budget_charge, args=(xdir, "acme", f"B{i}", q)) for i in range(n)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(20.0)
    oks = [ok for (_l, ok) in _events(q, n_expected=n, timeout=5.0)]
    assert oks.count(True) == 3, oks   # ONE budget of 3 shared by all 8 processes
    assert TenantBudget({"acme": 3}, default=0, xproc_dir=xdir).spent("acme") == 3


# --------------------------------------------------------------------------------------------------
# 6. the default governor is cross-process wired and non-refusing by default
# --------------------------------------------------------------------------------------------------
def test_default_fleet_governor_is_cross_process_and_non_refusing(tmp_path) -> None:
    gov = default_fleet_governor(str(tmp_path))
    # Backed cross-process (not threading-only).
    assert gov.proof_serializer._xproc_dir is not None
    assert gov.host_rate._xproc_dir is not None
    assert gov.budget._xproc_dir is not None
    # It does not newly refuse: many SEARCH and PROOF engagements against one host all admit.
    host = "https://app.example.com/x"
    for _ in range(50):
        with gov.engage(target=host, tenant="whoever", kind=WorkKind.SEARCH):
            pass
    with gov.engage(target=host, tenant="whoever", kind=WorkKind.PROOF):
        pass
