"""
The gated transport stays SAFE when several callers share ONE ``HttpExecutor``.

``HttpExecutor`` is a shared object: ``engage`` builds two of them, the repeater and the
MCP server each build their own, and the scanner's injected ``send`` IS
``gated_fetch``. Its budget counter, its rate anchor, its lazily-built httpx client and
its action-id minter are all mutable state behind that one entry point, so concurrency
must buy wall-clock WITHOUT buying extra traffic, a higher request rate, or a collided
evidence directory — the things §VI of the constitution forbids.

(These guards were written for a concurrent timing sweep in the scanner. That sweep was
measured and REMOVED — see the note in ``AuditEngine.audit``. The guards stay: they are
correct, they are cheap and uncontended on the serial path, they are the difference
between a shared executor being safe and being a silent budget/rate hole, and they will
matter again under free-threaded CPython. Every one of them is pinned by a test below
that fails deterministically when the guard is deleted.)

What is pinned here:

  * the posture's minimum inter-request interval is honoured START-to-START, measured at
    the ORIGIN, so N concurrent callers are spaced by the floor instead of bursting
    through one stale anchor (:func:`test_rate_floor_is_honoured_with_concurrent_callers`);
  * the serial path's spacing semantics are unchanged — still measured from the previous
    request's COMPLETION (:func:`test_serial_spacing_is_unchanged`) — and a dry run, which
    puts nothing on the wire, pays no floor at all
    (:func:`test_a_dry_run_does_not_pay_the_rate_floor`);
  * the per-engagement request budget is a hard cap even with requests in flight that have
    not yet been tallied (:func:`test_budget_is_never_overshot_under_concurrency`), and a
    reservation is NEVER leaked, whatever happens after it is taken
    (:func:`test_a_refusal_after_the_reservation_does_not_leak_a_budget_slot`);
  * the counter bookkeeping really is inside the mutual-exclusion region
    (:func:`test_mark_request_done_runs_under_the_executor_lock`,
    :func:`test_engine_send_counter_runs_under_its_lock`) — an unguarded read-modify-write
    drifts the budget and can move the rate anchor BACKWARDS;
  * evidence directories stay distinct across mints, across two executors in one process
    IN THE SAME MILLISECOND, and across a restart, and the id stays a usable wall-clock
    timestamp (:func:`test_action_ids_are_unique`,
    :func:`test_action_ids_do_not_collide_in_the_same_millisecond`,
    :func:`test_action_id_tracks_the_wall_clock`).

**The origin matters.** ``pytest_httpserver`` serialises the requests it accepts, so a
concurrency assertion made against it measures the FIXTURE, not the executor: the
rate-floor test below passed unchanged with the whole anchor reservation removed. The
rate tests therefore run against a threaded loopback origin that genuinely accepts in
parallel and timestamps each request as it arrives.
"""

from __future__ import annotations

import contextlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2.agents.http_executor import _RATE_PROFILES, HttpExecutor
from framework.v2.common import paths as _paths

_CHARTER = """\
# Engagement charter — `{slug}`

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `{host}` | Test app | Yes |

## 7. Posture

- [x] **TEST**
"""


@pytest.fixture()
def isolated_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    targets_root = tmp_path / "targets"
    targets_root.mkdir()

    def build(slug: str, host: str) -> Path:
        td = targets_root / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(_CHARTER.format(slug=slug, host=host), encoding="utf-8")
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets_root / s / ".halt")
    monkeypatch.setattr(_paths, "evidence_dir",
                        lambda s, a: (targets_root / s / "evidence" / a))
    return build


@dataclass
class _Req:
    url: str
    method: str = "GET"
    headers: list = field(default_factory=list)
    body: str | None = None


class _ConcurrentOrigin(BaseHTTPRequestHandler):
    """A loopback origin that really does serve in parallel, and records WIRE ARRIVAL.

    ``ThreadingHTTPServer`` hands each accepted connection to its own thread, so N gated
    fetches overlap here exactly as they would against a real app — which is the whole
    premise of the interleave, and the thing ``pytest_httpserver`` cannot exhibit."""

    arrivals: list[float] = []
    _lock = threading.Lock()
    delay: float = 0.0

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        with _ConcurrentOrigin._lock:
            _ConcurrentOrigin.arrivals.append(time.monotonic())
        if _ConcurrentOrigin.delay:
            time.sleep(_ConcurrentOrigin.delay)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _concurrent_origin(delay: float = 0.0) -> Iterator[str]:
    _ConcurrentOrigin.arrivals = []
    _ConcurrentOrigin.delay = delay
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _ConcurrentOrigin)
    srv.daemon_threads = True
    srv.request_queue_size = 128
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _executor_at(base_url: str, **kwargs) -> HttpExecutor:
    return HttpExecutor(
        engagement_slug="alpha",
        base_url=base_url,
        prompt_callback=lambda _q, _t: False,
        **kwargs,
    )


def _executor(httpserver: HTTPServer, **kwargs) -> HttpExecutor:
    return HttpExecutor(
        engagement_slug="alpha",
        base_url=f"http://127.0.0.1:{httpserver.port}/",
        prompt_callback=lambda _q, _t: False,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.real_rate_floor
# real_rate_floor: this test IS the rate-floor guard. It reads floor = _RATE_PROFILES["TEST"][0] and
# asserts `floor > 0` outright, then measures that concurrent arrivals are spaced by >= floor*0.85. Under
# the zero-floor override the first assertion fails and the spacing measurement is meaningless — it must
# run against the genuine floor.
def test_rate_floor_is_honoured_with_concurrent_callers(isolated_engagement):
    """N concurrent gated fetches must still leave >= the posture floor between the
    requests ARRIVING AT THE ORIGIN.

    Two things this has to get right, both of which an earlier version got wrong:

    * the origin must genuinely accept in parallel. Against ``pytest_httpserver`` the
      observed "gaps" were the fixture handler's own ``time.sleep(0.25)``, serialised by
      the fixture — that version passed unchanged at base AND with the whole W7 anchor
      reservation removed, i.e. it measured nothing;
    * the arrival timestamps must come from the WIRE, not from the caller. The
      reservation anchors gate EXIT, and anything expensive between gate exit and the
      socket (building the shared httpx client, once) compresses the first inter-arrival
      gap — measured at 0.137s against a 0.2s floor before the client was warmed ahead
      of the spacing window.

    Removing the reservation gives ``gaps=[0,0,0,0,0]``: a full 6x burst past the
    authorized rate. That is the §VI hole the lock closes."""
    isolated_engagement("alpha", "127.0.0.1")
    floor = _RATE_PROFILES["TEST"][0]
    assert floor > 0, "the TEST posture must declare a real rate floor for this test to bite"
    n = 6
    body_delay = 0.25  # a slow endpoint: the idle time the interleave exists to overlap

    with _concurrent_origin(delay=body_delay) as base:
        ex = _executor_at(base + "/", request_budget=100)
        try:
            t0 = time.monotonic()
            with ThreadPoolExecutor(max_workers=n) as pool:
                list(pool.map(lambda i: ex.gated_fetch(_Req(url=f"{base}/probe?i={i}")), range(n)))
            elapsed = time.monotonic() - t0
        finally:
            ex.close()
        arrivals = sorted(_ConcurrentOrigin.arrivals)

    assert len(arrivals) == n
    gaps = [b - a for a, b in zip(arrivals, arrivals[1:])]
    # A small tolerance for scheduling slop; the defect this guards produced gaps of ~0.
    assert min(gaps) >= floor * 0.85, f"rate floor {floor}s breached: gaps={gaps}"
    # …and the requests really did overlap, otherwise the test proves nothing about
    # concurrency: 6 SERIAL 0.25s responses each followed by a 0.2s completion-anchored
    # floor could not fit in this.
    assert elapsed < n * (floor + body_delay) * 0.9, (
        f"no overlap: {elapsed:.2f}s is the serial cost, not the interleaved one")


@pytest.mark.real_rate_floor
# real_rate_floor: asserts elapsed >= 3*body_delay + 2*floor for a serial run, reading the real TEST floor.
# Under the zero-floor override the `2*floor` term vanishes and the test would SILENTLY PASS as a tautology
# on the body delays alone — no longer testing that the serial path is spaced by the floor at all. The
# single worst silent-behaviour-change case in the tree, so it must keep the genuine floor.
def test_serial_spacing_is_unchanged(isolated_engagement):
    """The serial path still spaces from the previous request's COMPLETION — the
    start-instant reservation added for concurrency is superseded by the completion
    timestamp, so a single-threaded run behaves exactly as before."""
    isolated_engagement("alpha", "127.0.0.1")
    body_delay = 0.15
    floor = _RATE_PROFILES["TEST"][0]
    with _concurrent_origin(delay=body_delay) as base:
        ex = _executor_at(base + "/", request_budget=10)
        try:
            t0 = time.monotonic()
            for i in range(3):
                ex.gated_fetch(_Req(url=f"{base}/probe?i={i}"))
            elapsed = time.monotonic() - t0
        finally:
            ex.close()
    # 3 requests: 3 x body_delay of I/O plus 2 completion-anchored floors between them.
    lower = 3 * body_delay + 2 * floor
    assert elapsed >= lower * 0.9, f"serial spacing loosened: {elapsed:.3f}s < {lower:.3f}s"


@pytest.mark.real_rate_floor
# real_rate_floor: the assertion is `elapsed < floor` (8 dry-run actions must cost less than one floor).
# With the zero-floor override floor becomes 0.0 and `elapsed < 0.0` is impossible → the test would FAIL;
# and its premise (a dry run does NOT pay the floor that a real run would) is only meaningful when the
# floor is nonzero. Needs the genuine floor.
def test_a_dry_run_does_not_pay_the_rate_floor(isolated_engagement):
    """A dry run puts nothing on the wire, so it must not be spaced by the posture floor.

    This is not cosmetic: the start-instant reservation, applied unconditionally, made
    every dry-run action wait the full floor — 100 actions went from ~0.0s to ~20s — and
    ``dry_run`` is threaded from real operator paths (repeater.Repeater, its tool,
    mcp.server, engage_fusion), all defaulting False. The anchor tracks bytes on the wire;
    a dry run writes none."""
    isolated_engagement("alpha", "127.0.0.1")
    ex = _executor_at("http://127.0.0.1:1/", request_budget=1000, dry_run=True)
    floor = _RATE_PROFILES["TEST"][0]
    try:
        t0 = time.monotonic()
        for i in range(8):
            out = ex.gated_fetch(_Req(url=f"http://127.0.0.1:1/probe?i={i}"))
            assert not out.get("refused")
        elapsed = time.monotonic() - t0
    finally:
        ex.close()
    assert ex.stats()["requests_made"] == 8      # still budgeted, still tallied
    assert elapsed < floor, (
        f"a dry run paid the rate floor: {elapsed:.3f}s for 8 actions (floor {floor}s each)")


# ---------------------------------------------------------------------------
# budget + counters
# ---------------------------------------------------------------------------


def test_budget_is_never_overshot_under_concurrency(isolated_engagement, httpserver: HTTPServer):
    """The per-engagement budget is a hard cap. With requests in flight that have not yet
    been tallied, the gate counts the RESERVATIONS too, so K concurrent callers cannot each
    spend the same last slot."""
    isolated_engagement("alpha", "127.0.0.1")
    served = {"n": 0}
    lock = threading.Lock()

    def handler(_request) -> Response:
        with lock:
            served["n"] += 1
        time.sleep(0.05)
        return Response("ok", status=200)

    httpserver.expect_request("/probe").respond_with_handler(handler)
    budget = 5
    ex = _executor(httpserver, request_budget=budget)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(
                lambda i: ex.gated_fetch(_Req(url=f"http://127.0.0.1:{httpserver.port}/probe?i={i}")),
                range(20)))
    finally:
        ex.close()

    assert served["n"] <= budget, f"budget {budget} overshot: {served['n']} requests reached the app"
    assert ex.stats()["requests_made"] <= budget
    refused = [r for r in results if r.get("refused")]
    assert refused, "past the budget the executor must REFUSE, not silently pass"


def test_counters_are_exact_under_concurrency(isolated_engagement, httpserver: HTTPServer):
    """Every issued request is tallied exactly once and every in-flight reservation comes
    back. (The read-modify-write race this protects against is not reliably observable
    under the GIL, so the guard itself is pinned deterministically by
    :func:`test_mark_request_done_runs_under_the_executor_lock`; this is the end-to-end
    accounting check.)"""
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/probe").respond_with_data("ok", status=200)
    n = 24
    ex = _executor(httpserver, request_budget=1000)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(
                lambda i: ex.gated_fetch(_Req(url=f"http://127.0.0.1:{httpserver.port}/probe?i={i}")),
                range(n)))
    finally:
        ex.close()
    assert ex.stats()["requests_made"] == n
    assert ex._reserved == 0, "every in-flight reservation must be released"


def _proto() -> HttpExecutor:
    return HttpExecutor(engagement_slug="<proto>", base_url="http://127.0.0.1:1", dry_run=True)


def test_action_ids_are_unique():
    """Two actions in the same millisecond must not share an evidence directory — which
    concurrent probes (and fast loopback traffic) produce routinely."""
    ex = _proto()
    ids: list[str] = []
    lock = threading.Lock()

    def mint(_i: int) -> None:
        got = ex._next_action_id()
        with lock:
            ids.append(got)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(mint, range(500)))
    assert len(set(ids)) == len(ids)
    assert all(i.startswith("H-") for i in ids)
    assert all("/" not in i and "\\" not in i and ".." not in i for i in ids)  # path-safe


def test_action_ids_do_not_collide_in_the_same_millisecond():
    """Within-executor uniqueness is NOT the collision class that bites.

    ``engage`` builds two HttpExecutors in one process, and a restarted process starts
    minting from the clock again — so an id derived only from the clock plus a
    per-executor counter lands on evidence directories another executor (or a previous
    run) already wrote, and ``_evidence_dir`` overwrites the captured exchange.

    The case has to be the SAME MILLISECOND. An earlier version of this test minted 3000
    ids per executor spanning many milliseconds, so the timestamp component alone
    separated them and it passed with the per-executor nonce deleted — it named the right
    collision class and then tested a different one. Measured with the nonce stripped:
    50/50 trials collide. With it: 0/50."""
    a, b = _proto(), _proto()
    by_ms_a: dict[str, set[str]] = {}
    by_ms_b: dict[str, set[str]] = {}
    for _ in range(40):  # back-to-back, so the two executors land on shared milliseconds
        for ex, table in ((a, by_ms_a), (b, by_ms_b)):
            got = ex._next_action_id()
            table.setdefault(got.split("-")[1], set()).add(got)

    shared_ms = set(by_ms_a) & set(by_ms_b)
    assert shared_ms, (
        "both executors never minted inside the same millisecond, so this run did not "
        "exercise the collision class at all")
    for ms in sorted(shared_ms):
        assert not (by_ms_a[ms] & by_ms_b[ms]), (
            f"two executors minted the same action id inside millisecond {ms}: "
            f"{sorted(by_ms_a[ms] & by_ms_b[ms])}")


def test_action_id_tracks_the_wall_clock():
    """The id must stay a TIMESTAMP. §VI.4 asks the operator to grep their own logs and
    find our traffic by it, so the minter may not advance a counter past the clock to buy
    uniqueness: 20,000 mints in ~20 ms once left such a counter 20 SECONDS in the future,
    at which point the id names no real instant at all."""
    ex = _proto()
    ids = [ex._next_action_id() for _ in range(20000)]
    now_ms = int(time.time() * 1000)
    stamps = [int(i.split("-")[1]) for i in ids]
    assert max(stamps) <= now_ms + 50, (
        f"the action-id clock ran {max(stamps) - now_ms} ms ahead of real time")
    assert min(stamps) >= now_ms - 60_000
    assert stamps == sorted(stamps)  # still monotone, so ids still sort by time


# KNOWN, UNFIXED, and deliberately not tested: both the nonce and `_action_seq` are
# captured at INSTANCE CONSTRUCTION, so a pre-forking server — or any `os.fork` after an
# executor is built — hands parent and child byte-identical id streams, and the two would
# overwrite each other's evidence directories. No pre-forking deployment exists today (a
# grep for os.fork / fork() outside tests finds nothing). Closing it is cheap when one
# appears: put `os.getpid()` in the id, or re-mint `_id_nonce` from
# `os.register_at_fork(after_in_child=...)`.


# ---------------------------------------------------------------------------
# the guards themselves — each of these fails if its guard is deleted
# ---------------------------------------------------------------------------


def test_mark_request_done_runs_under_the_executor_lock():
    """``_mark_request_done`` must do its bookkeeping inside the mutual-exclusion region.

    Unguarded, ``self._requests_made += 1`` is a read-modify-write that silently drifts
    the budget, and ``self._last_request_at = max(self._last_request_at, time.time())``
    can LOSE an update and move the anchor BACKWARDS — which lets the next request fire
    before the floor. Both are invisible in a plain concurrency assertion under the GIL,
    so this pins the guard directly and deterministically: holding the executor's lock
    from outside must block every marker."""
    ex = _proto()
    markers = [threading.Thread(target=ex._mark_request_done) for _ in range(32)]
    with ex._lock:
        for t in markers:
            t.start()
        time.sleep(0.1)
        assert ex.stats()["requests_made"] == 0, (
            "a marker tallied while the executor lock was held — the bookkeeping is "
            "outside the critical section")
    for t in markers:
        t.join(timeout=5)
    assert ex.stats()["requests_made"] == 32


def test_a_refusal_after_the_reservation_does_not_leak_a_budget_slot(isolated_engagement):
    """A budget reservation that is taken and never released permanently shrinks the
    engagement: ten leaks turn a budget of ten into zero real requests — a silent
    self-DoS. The reservation is the last thing the gate chain does, and everything after
    it is wrapped so a refusal OR an exception releases it first. This pins that: make the
    only post-reservation step blow up, and the slot must still come back."""
    isolated_engagement("alpha", "127.0.0.1")
    ex = _executor_at("http://127.0.0.1:1/", request_budget=10)
    boom = {"n": 0}

    def _explode() -> None:
        boom["n"] += 1
        raise RuntimeError("rate limiter exploded")

    ex._sleep_for_rate_limit = _explode  # type: ignore[method-assign]
    try:
        for _ in range(10):
            with pytest.raises(RuntimeError, match="rate limiter exploded"):
                ex.gated_fetch(_Req(url="http://127.0.0.1:1/probe"))
            assert ex._reserved == 0, "a post-reservation failure leaked a budget slot"
    finally:
        ex.close()
    assert boom["n"] == 10
    # the budget was never spent, so the next action is still admitted by the budget gate.
    assert ex.stats()["requests_made"] == 0


def test_engine_send_counter_runs_under_its_lock():
    """``AuditEngine._counted_send`` checks the scan budget and spends it; unguarded, K
    concurrent timing probes can each spend the same last slot. Same shape as above:
    holding the engine's send lock from outside must block every sender."""
    from framework.v2.scanner.engine import AuditEngine
    from framework.v2.scanner.insertion import HttpRequest

    engine = AuditEngine(lambda _r: {"status": 200, "body": ""})
    req = HttpRequest(method="GET", url="http://127.0.0.1:1/x")
    senders = [threading.Thread(target=engine._counted_send, args=(req,)) for _ in range(16)]
    with engine._send_lock:
        for t in senders:
            t.start()
        time.sleep(0.1)
        assert engine.requests_sent == 0, (
            "a probe spent the scan budget while the engine send lock was held")
    for t in senders:
        t.join(timeout=5)
    assert engine.requests_sent == 16
