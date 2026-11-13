"""W6-3 #454 — the SOVEREIGN plane (glass-cockpit UI) exposes OpenMetrics on /metrics.

The route is UNAUTHENTICATED and Host-ungated — the SAME probe posture as /healthz+/readyz (this cockpit
binds loopback / a private WG address only). The exposition carries the RED series (the server's own
requests), the process metrics, and the four domain counters. A scrape after some traffic reflects the
request in the RED counter (the negative-control that the RED wiring is not a no-op).

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=packages/core/vigil_core:apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest -q apps/sigil/tests/test_metrics_endpoint.py
"""
from __future__ import annotations

import re
import tempfile
import threading
import time
import urllib.request

from sigil.spine.store import SpineStore
from sigil.ui.server import build_server as build_ui

TOKEN = "owner-shared-token-metrics-1"


def _spine() -> str:
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _serve():
    srv = build_ui(token=TOKEN, port=0, spine_path=_spine())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _get(port: int, path: str, *, host: str | None = None):
    h = {"Host": host} if host is not None else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
        return r.status, r.headers.get("Content-Type", ""), r.read().decode()


def _series_present(text: str, name: str) -> bool:
    return any(re.match(rf"^{re.escape(name)}(\{{[^}}]*\}})?\s+\S+$", ln) for ln in text.splitlines())


def _series_value(text: str, name: str) -> float:
    """Sum every sample of the family `name` (ignoring labels) parsed out of the exposition text."""
    total = 0.0
    for ln in text.splitlines():
        m = re.match(rf"^{re.escape(name)}(\{{[^}}]*\}})?\s+(\S+)$", ln)
        if m:
            total += float(m.group(2))
    return total


def test_metrics_is_unauthenticated_openmetrics_with_red_process_and_domain():
    srv, port = _serve()
    try:
        # a probe presents no token and a probe Host (not the anti-rebind allowlist) — still served.
        _get(port, "/healthz", host="kube-probe/1.0")  # warm up the RED counter with one completed request
        status, ctype, body = _get(port, "/metrics", host="kube-probe/1.0")
        assert status == 200
        assert ctype.startswith("application/openmetrics-text")
        assert body.rstrip().endswith("# EOF")
        assert 'plane="sovereign"' in body
        # the four domain counters
        for fam in ("vigil_facts_total", "vigil_leads_total", "vigil_refusals_total",
                    "vigil_gate_denials_total"):
            assert fam in body, f"missing domain series {fam}"
        # RED
        assert _series_present(body, "vigil_requests_total"), "no RED request sample after traffic"
        assert "# TYPE vigil_request_duration_seconds histogram" in body
        # process
        assert "vigil_process_resident_memory_bytes" in body
        assert "vigil_process_uptime_seconds" in body
    finally:
        srv.shutdown()


def test_metrics_body_carries_no_token():
    srv, port = _serve()
    try:
        _, _, body = _get(port, "/metrics")
        assert TOKEN not in body
    finally:
        srv.shutdown()


def test_refusals_total_is_monotonic_across_scrapes_despite_the_windowed_dashboard():
    """W6-3 #454 regression: `vigil_refusals_total` is a *_total COUNTER and MUST be monotonic. It was fed
    from `dashboard.snapshot()['recent_decisions']`, a SLIDING `lookback`-windowed view, so once a DENY
    aged out of the window the counter DROPPED — an illegal counter reset. The fix feeds it from the
    CUMULATIVE `refusals_total` spine projection instead. This asserts: (a) a recorded DENY shows up, (b)
    after enough later records push it out of the window the counter does NOT drop (the bug), and (c) a
    fresh DENY still increases it."""
    from sigil.dashboard import snapshot as _snapshot
    from sigil.spine.store import SpineStore

    path = tempfile.mktemp(suffix=".jsonl")
    store = SpineStore(path)
    store.append(kind="refusal", source="agent", actor="operator",
                 payload={"decision": "denied", "governor": "kill-switch"})

    srv = build_ui(token=TOKEN, port=0, spine_path=path)
    srv.metrics_projection_ttl_s = 0.0      # re-fold on every scrape: this pins the FEED, not the rate bound
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    port = srv.server_address[1]
    try:
        _, _, body1 = _get(port, "/metrics")
        r1 = _series_value(body1, "vigil_refusals_total")
        assert r1 == 1.0, f"the recorded DENY must be counted, got {r1}"

        # Push the DENY out of the dashboard's sliding lookback window with later non-deny agent records.
        for _ in range(305):
            store.append(kind="message", source="agent", actor="operator",
                         payload={"decision": "auto", "text": "OBSIDIAN-TEST filler"})
        # Sanity: the WINDOWED view has indeed dropped the denial (this is exactly the non-monotonic source).
        snap = _snapshot(store)
        assert snap["recent_decisions"].get("denied", 0) == 0, "window should have slid past the DENY"
        assert snap["refusals_total"] == 1, "the cumulative projection must still hold the DENY"

        _, _, body2 = _get(port, "/metrics")
        r2 = _series_value(body2, "vigil_refusals_total")
        assert r2 >= r1, f"counter went DOWN ({r1} -> {r2}) — non-monotonic *_total"
        assert r2 == 1.0, f"cumulative refusals should be unchanged at 1, got {r2}"

        # A new DENY still moves the counter up.
        store.append(kind="refusal", source="agent", actor="operator",
                     payload={"decision": "refused", "requested": "OBSIDIAN-TEST"})
        _, _, body3 = _get(port, "/metrics")
        r3 = _series_value(body3, "vigil_refusals_total")
        assert r3 == 2.0, f"a fresh DENY must increment the counter, got {r3}"
    finally:
        srv.shutdown()


# --- the domain projection is rate-bounded: an anonymous scraper cannot make the server re-fold the spine ---
# `/metrics` is unauthenticated, and the refusals counter is a fold over the WHOLE spine (dashboard.snapshot).
# The fold runs at most once per `metrics_projection_ttl_s`, counted from the END of the previous fold, never
# two at once; a scrape in between serves the last value. These pin each half of that bound.


class _Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _deny(store) -> None:
    store.append(kind="refusal", source="agent", actor="operator",
                 payload={"decision": "denied", "governor": "kill-switch"})


def _counting_server(monkeypatch, *, ttl: "float | None" = None, fold=None):
    """A served cockpit over a spine holding one DENY, with a fake clock and a counted `dashboard.snapshot`
    (`fold(store)` replaces it when given; the real fold otherwise). `ttl=None` keeps the shipped interval."""
    import sigil.dashboard as dash

    path = tempfile.mktemp(suffix=".jsonl")
    store = SpineStore(path)
    _deny(store)
    calls: list = []
    real = dash.snapshot

    def counted(st, *a, **k):
        calls.append(1)
        return (fold or real)(st, *a, **k)

    monkeypatch.setattr(dash, "snapshot", counted)
    srv = build_ui(token=TOKEN, port=0, spine_path=path)
    if ttl is not None:
        srv.metrics_projection_ttl_s = ttl
    clock = _Clock()
    srv.metrics_clock = clock
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1], store, calls, clock


def test_a_burst_of_anonymous_scrapes_folds_the_spine_once(monkeypatch):
    """With the SHIPPED interval: 25 scrapes inside it fold once — and every other series stays live (only the
    spine-folded refusals counter is rate-bounded, never the whole exposition)."""
    srv, port, _store, calls, _clock = _counting_server(monkeypatch)
    try:
        seen_requests, seen_denials = [], []
        for i in range(25):
            if i == 12:
                srv.metrics.inc_gate_denial()
            status, _, body = _get(port, "/metrics", host="kube-probe/1.0")
            assert status == 200 and body.rstrip().endswith("# EOF")
            assert _series_value(body, "vigil_refusals_total") == 1.0
            seen_requests.append(_series_value(body, "vigil_requests_total"))
            seen_denials.append(_series_value(body, "vigil_gate_denials_total"))
        assert len(calls) == 1, f"{len(calls)} spine folds for 25 scrapes inside one TTL"
        assert all(b > a for a, b in zip(seen_requests, seen_requests[1:])), "RED was served from a cache"
        assert seen_denials[12] == seen_denials[11] + 1, "the gate-denial counter was served from a cache"
    finally:
        srv.shutdown()


def test_a_new_deny_shows_once_the_ttl_has_elapsed_and_not_before(monkeypatch):
    srv, port, store, calls, clock = _counting_server(monkeypatch, ttl=15.0)
    try:
        assert _series_value(_get(port, "/metrics")[2], "vigil_refusals_total") == 1.0
        _deny(store)
        clock.t += 14.999
        assert _series_value(_get(port, "/metrics")[2], "vigil_refusals_total") == 1.0   # still the last value
        assert len(calls) == 1
        clock.t += 0.001                                       # exactly one TTL after the last fold ended
        assert _series_value(_get(port, "/metrics")[2], "vigil_refusals_total") == 2.0
        assert len(calls) == 2
        _deny(store)
        clock.t += 15.0                                        # and the bound keeps applying after that
        assert _series_value(_get(port, "/metrics")[2], "vigil_refusals_total") == 3.0
        assert len(calls) == 3
    finally:
        srv.shutdown()


def test_the_ttl_is_counted_from_the_end_of_a_slow_fold(monkeypatch):
    """A fold that takes longer than the TTL must not be re-run by the very next scrape (back-to-back folds
    would keep the server folding the spine for as long as someone scrapes)."""
    import sigil.dashboard as dash
    real = dash.snapshot
    holder: dict = {}

    def slow(st, *a, **k):
        holder["clock"].t += 100.0                             # the fold takes 100 s on the fake clock
        return real(st, *a, **k)

    srv, port, _store, calls, clock = _counting_server(monkeypatch, ttl=15.0, fold=slow)
    holder["clock"] = clock
    try:
        _get(port, "/metrics")
        clock.t += 1.0                                         # 101 s after the fold STARTED, 1 s after it ended
        _get(port, "/metrics")
        assert len(calls) == 1, "the TTL was counted from the start of the fold"
    finally:
        srv.shutdown()


def test_a_failing_fold_keeps_the_last_projected_value(monkeypatch):
    """A fold that fails after a good one leaves the counter where it was: never a reset to 0 (a scraper would read
    a counter reset and the shipped rate()/alert rules would misfire)."""
    state = {"fail": False}
    import sigil.dashboard as dash
    real = dash.snapshot

    def flaky(st, *a, **k):
        if state["fail"]:
            raise RuntimeError("unreadable spine")
        return real(st, *a, **k)

    srv, port, store, calls, clock = _counting_server(monkeypatch, ttl=15.0, fold=flaky)
    try:
        assert _series_value(_get(port, "/metrics")[2], "vigil_refusals_total") == 1.0
        _deny(store)
        state["fail"] = True
        clock.t += 15.0
        assert _series_value(_get(port, "/metrics")[2], "vigil_refusals_total") == 1.0
        assert len(calls) == 2
    finally:
        srv.shutdown()


def test_a_failing_fold_is_not_retried_per_request(monkeypatch):
    def broken(st, *a, **k):
        raise RuntimeError("unreadable spine")

    srv, port, _store, calls, clock = _counting_server(monkeypatch, fold=broken)
    try:
        for _ in range(10):
            status, _, body = _get(port, "/metrics")
            assert status == 200 and "vigil_requests_total" in body   # RED/process still render
        assert len(calls) == 1, f"a failing fold was retried {len(calls)} times inside one TTL"
        clock.t += 15.0
        _get(port, "/metrics")
        assert len(calls) == 2, "a failed fold must still be retried once the TTL has elapsed"
    finally:
        srv.shutdown()


def _gated_fold():
    import sigil.dashboard as dash
    real = dash.snapshot
    gate = {"on": False}
    entered, release = threading.Event(), threading.Event()

    def fold(st, *a, **k):
        if gate["on"]:
            entered.set()
            assert release.wait(10), "test fold never released"
        return real(st, *a, **k)

    return fold, gate, entered, release


def test_a_scrape_during_a_running_fold_neither_waits_nor_starts_a_second(monkeypatch):
    fold, gate, entered, release = _gated_fold()
    srv, port, store, calls, clock = _counting_server(monkeypatch, ttl=0.0, fold=fold)
    first: dict = {}
    t = threading.Thread(target=lambda: first.setdefault("r", _get(port, "/metrics")), daemon=True)
    try:
        assert _series_value(_get(port, "/metrics")[2], "vigil_refusals_total") == 1.0   # the first fold
        _deny(store)
        gate["on"] = True
        t.start()
        assert entered.wait(5), "the next scrape never started its fold"
        t0 = time.monotonic()
        status, _, body = _get(port, "/metrics")               # TTL 0: only the running fold can stop it
        assert status == 200 and body.rstrip().endswith("# EOF")
        assert time.monotonic() - t0 < 2.0, "a scrape waited on another scrape's fold"
        assert _series_value(body, "vigil_refusals_total") == 1.0, "the last projected value is served"
        assert len(calls) == 2, "a second fold started while one was running"
        release.set()
        t.join(10)
        assert first["r"][0] == 200 and _series_value(first["r"][2], "vigil_refusals_total") == 2.0
        gate["on"] = False
        assert _series_value(_get(port, "/metrics")[2], "vigil_refusals_total") == 2.0   # lock released
        assert len(calls) == 3
    finally:
        release.set()
        srv.shutdown()


def test_a_fresh_servers_first_scrapes_wait_for_the_first_fold_and_never_report_zero(monkeypatch):
    """Before ANY fold has finished there is no last value to serve: a concurrent scrape waits for the one running
    fold (it never starts its own) and reports the spine's real count — never 0, which a scraper would read as a
    counter reset followed by a spike of phantom refusals."""
    fold, gate, entered, release = _gated_fold()
    gate["on"] = True
    srv, port, _store, calls, _clock = _counting_server(monkeypatch, ttl=15.0, fold=fold)
    out: list = []
    threads = [threading.Thread(target=lambda: out.append(_get(port, "/metrics")), daemon=True) for _ in range(3)]
    try:
        threads[0].start()
        assert entered.wait(5)
        for th in threads[1:]:
            th.start()
        time.sleep(0.2)
        assert out == [], "a scrape answered before the first fold finished"
        release.set()
        for th in threads:
            th.join(10)
        assert [_series_value(b, "vigil_refusals_total") for _s, _c, b in out] == [1.0, 1.0, 1.0]
        assert len(calls) == 1, "the waiting scrapes started folds of their own"
    finally:
        release.set()
        srv.shutdown()


def test_two_servers_in_one_process_each_render_their_own_spine(monkeypatch):
    """The OpenMetrics registry is process-wide; each server serves ITS last projected value, not whichever server
    folded last."""
    a, pa, sa, _ca, _ = _counting_server(monkeypatch, ttl=15.0)
    b, pb, sb, _cb, _ = _counting_server(monkeypatch, ttl=15.0)
    try:
        _deny(sb)
        _deny(sb)
        assert _series_value(_get(pa, "/metrics")[2], "vigil_refusals_total") == 1.0
        assert _series_value(_get(pb, "/metrics")[2], "vigil_refusals_total") == 3.0
        assert _series_value(_get(pa, "/metrics")[2], "vigil_refusals_total") == 1.0   # inside a's TTL
    finally:
        a.shutdown()
        b.shutdown()


def test_the_bound_is_on_by_default():
    srv = build_ui(token=TOKEN, port=0, spine_path=_spine())
    try:
        from sigil.ui.server import METRICS_PROJECTION_TTL_S
        assert METRICS_PROJECTION_TTL_S == 10.0, "the interval docs/OBSERVABILITY.md documents"
        assert srv.metrics_projection_ttl_s == METRICS_PROJECTION_TTL_S
        assert srv.metrics_clock is time.monotonic
    finally:
        srv.server_close()


class _RecordingLock:
    """The projection lock, recording each acquire's arguments; `before_acquire` (once) runs just before one."""

    def __init__(self):
        self._lock = threading.Lock()
        self.calls: list = []
        self.before_acquire = None

    def acquire(self, blocking=True, timeout=-1):
        hook, self.before_acquire = self.before_acquire, None
        if hook is not None:
            hook()
        self.calls.append((blocking, timeout))
        return self._lock.acquire(blocking, timeout)

    def release(self):
        self._lock.release()


def test_only_the_first_fold_is_waited_for_and_never_with_a_timeout(monkeypatch):
    """Structural, not a timing bound: after the first fold, a scrape never blocks on the projection lock at all
    (a waiting scrape would hold a handler thread for as long as a fold runs)."""
    srv, port, _store, _calls, clock = _counting_server(monkeypatch, ttl=15.0)
    lock = _RecordingLock()
    srv._metrics_projection_lock = lock
    try:
        for _ in range(3):
            _get(port, "/metrics")
            clock.t += 20.0
        assert lock.calls == [(True, -1), (False, -1), (False, -1)], lock.calls
    finally:
        srv.shutdown()


def test_freshness_is_re_checked_under_the_lock(monkeypatch):
    """A scrape that reads the timestamp while another fold runs, and takes the lock only after that fold ended,
    must see the fresh timestamp and NOT fold again (no back-to-back folds)."""
    fold, gate, entered, release = _gated_fold()
    srv, port, _store, calls, clock = _counting_server(monkeypatch, ttl=15.0, fold=fold)
    lock = _RecordingLock()
    srv._metrics_projection_lock = lock
    a_done = threading.Event()
    out: dict = {}
    try:
        _get(port, "/metrics")                                 # the first fold
        clock.t += 20.0                                        # stale: the next scrape folds
        gate["on"] = True
        ta = threading.Thread(target=lambda: (out.setdefault("a", _get(port, "/metrics")), a_done.set()),
                              daemon=True)
        ta.start()
        assert entered.wait(5)                                 # fold A is running and holds the lock
        gate["on"] = False
        lock.before_acquire = lambda: a_done.wait(10)          # B reaches the lock only after A has finished
        tb = threading.Thread(target=lambda: out.setdefault("b", _get(port, "/metrics")), daemon=True)
        tb.start()
        time.sleep(0.1)
        release.set()
        ta.join(10)
        tb.join(10)
        assert out["a"][0] == 200 and out["b"][0] == 200
        assert len(calls) == 2, f"{len(calls)} folds: B re-folded right after A"
    finally:
        release.set()
        srv.shutdown()


def test_n_concurrent_scrapes_within_the_ttl_cause_exactly_one_projection(monkeypatch):
    """16 scrapes released at once on a fresh server fold the spine ONCE (the others wait for that one fold), and 16
    more released at once after the interval has passed fold it once more (one wins the lock, the rest serve the
    last value) — whatever the interleaving."""
    srv, port, store, calls, clock = _counting_server(monkeypatch)       # the shipped interval

    def burst(n=16):
        gate = threading.Barrier(n)
        out: list = []

        def one():
            gate.wait(5)
            out.append(_get(port, "/metrics"))

        threads = [threading.Thread(target=one, daemon=True) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        return out

    try:
        out = burst()
        assert len(out) == 16 and all(st == 200 for st, _c, _b in out)
        assert len(calls) == 1, f"{len(calls)} projections for 16 concurrent scrapes on a fresh server"
        assert {_series_value(b, "vigil_refusals_total") for _s, _c, b in out} == {1.0}
        _deny(store)
        clock.t += srv.metrics_projection_ttl_s
        out = burst()
        assert len(out) == 16 and all(st == 200 for st, _c, _b in out)
        assert len(calls) == 2, f"{len(calls) - 1} projections for 16 concurrent scrapes once the interval passed"
    finally:
        srv.shutdown()
