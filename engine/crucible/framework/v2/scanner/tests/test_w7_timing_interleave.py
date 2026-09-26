"""
W7 (performance) — the TIMING INTERLEAVE is VERDICT-EQUIVALENT to the serial sweep.

A statistical timing probe is the sweep's largest wall-clock term and it is ~100% IDLE:
it is blocked on the delay it asked the target to take. ``AuditEngine(timing_workers=N)``
overlaps the idle waits of DIFFERENT insertion points. The claim these tests have to make
false-if-broken is that speed came from removing idle time and from NOTHING else:

  * the oracle's DECISION is unchanged across the range — a genuinely conditionally-slow
    endpoint still CONFIRMS, a uniformly slow one still REFUTES, a jittery one still
    REFUTES (:func:`test_verdicts_identical_across_the_range`);
  * the WITHIN-POINT interleaving of baseline vs treatment observations — the control the
    Mann-Whitney U shift test and the dose-response ratio rest on — is byte-for-byte the
    serial order (:func:`test_within_point_interleaving_preserved`);
  * sample COUNTS and the REQUEST count are identical, including the "first confirmation
    of a bug class at a point short-circuits that class's remaining entries" rule
    (:func:`test_request_count_and_short_circuit_identical`);
  * the retained context (the re-verifiable certificate input) has identical SHAPE and
    ORDER, so an existing certificate still re-fires offline
    (:func:`test_retained_context_shape_and_order_identical`);
  * the emission order of findings and coverage records is canonical
    (:func:`test_emission_order_is_canonical`);
  * and every precondition that would make the staging inexact keeps the sweep SERIAL
    (:func:`test_staging_is_refused_when_not_provably_equivalent`).

Everything here runs against a loopback synthetic origin. Latency is REAL (that is the
point), but no verdict depends on a wall-clock reading the test controls: the oracle sees
only the sample lists.
"""

from __future__ import annotations

import contextlib
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

from framework.v2.scanner.checks import (
    DifferentialCheck,
    TimingCheck,
    TimingObservations,
    interleave_timing_jobs,
)
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate

# The injected delay the payload asks for, and the sample count. Small enough that the
# suite stays quick, large enough that the effect-size floor (half of injected_ms) is a
# real bar for the CONFIRM case and unreachable for the two REFUTE cases.
_DELAY_MS = 120.0
_SAMPLES = 8
_SLEEP_TOKEN = "SLEEP"

# A deterministic "jitter" profile (odd length, so it never phase-locks onto the 2-cycle
# of the baseline/treatment interleaving): latency varies a lot, but there is no
# systematic shift between benign and payload requests, so the oracle must REFUSE.
_JITTER_MS = (0.0, 40.0, 10.0, 90.0, 20.0, 60.0, 5.0)


class _Origin(BaseHTTPRequestHandler):
    """Three behaviours on one loopback origin.

    ``/slow``    delays only when the payload injects one  -> a real time-based channel.
    ``/uniform`` always delays by the same amount          -> no shift; must REFUTE.
    ``/jitter``  delays by a varying, payload-independent  -> noise only; must REFUTE.
                 amount
    """

    _tick = 0
    _tick_lock = threading.Lock()

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        injected = any(_SLEEP_TOKEN in v for vals in q.values() for v in vals)
        if parts.path == "/slow":
            if injected:
                time.sleep(_DELAY_MS / 1000.0)
        elif parts.path == "/uniform":
            time.sleep(_DELAY_MS / 1000.0)
        elif parts.path == "/jitter":
            with _Origin._tick_lock:
                i = _Origin._tick
                _Origin._tick += 1
            time.sleep(_JITTER_MS[i % len(_JITTER_MS)] / 1000.0)
        body = b"ok, nothing interesting here"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


@pytest.fixture(scope="module")
def origin() -> Iterator[str]:
    with _server() as base:
        yield base


def _send(req: HttpRequest) -> dict:
    with urllib.request.urlopen(req.url, timeout=10) as r:  # noqa: S310 (loopback)
        return {"status": r.status, "body": r.read().decode("utf-8", "replace")}


def _request(base: str, path: str, points: int = 4) -> HttpRequest:
    # the un-probed baseline value is "0" so a rendered payload ("1" / "1 SLEEP") is
    # always distinguishable from the untouched params — see the interleaving test.
    query = "&".join(f"p{i}=0" for i in range(points))
    return HttpRequest(method="GET", url=f"{base}{path}?{query}")


def _timing(entry_id: str = "t1", bug_class: str = "time_based_sqli") -> TimingCheck:
    return TimingCheck(
        id=entry_id, bug_class=bug_class, benign="1",
        sleep_payload=f"1 {_SLEEP_TOKEN}", injected_ms=_DELAY_MS, samples=_SAMPLES,
    )


def _run(base: str, path: str, *, workers: int, checks=None, send=_send):
    """One audit over ``path``'s query points. Returns (engine, findings)."""
    engine = AuditEngine(send, timing_workers=workers)
    findings = engine.audit(
        _request(base, path), checks=checks or (_timing(),),
        insertion_kinds=(InsertionKind.QUERY_VALUE,),
    )
    return engine, findings


def _verdicts(engine, findings) -> dict:
    """The decision-bearing projection: what confirmed, and how every probe adjudicated."""
    return {
        "findings": [
            (f.check_id, f.bug_class, f.insertion_point, f.confirmed_by, f.param)
            for f in findings
        ],
        "exercised": [
            (p.insertion_point, p.check_id, p.bug_class, p.verdict, p.oracle_kinds_run)
            for p in engine.exercised
        ],
        "requests": engine.requests_sent,
    }


# ---------------------------------------------------------------------------
# 1. statistical equivalence — the oracle's decision is unchanged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,expect_confirm",
    [("/slow", True), ("/uniform", False), ("/jitter", False)],
    ids=["conditionally-slow-CONFIRM", "uniformly-slow-REFUTE", "jittery-REFUTE"],
)
def test_verdicts_identical_across_the_range(origin: str, path: str, expect_confirm: bool) -> None:
    """Serial and interleaved reach the SAME verdict on the same origin, across the range
    the timing oracle exists to separate: a real conditional delay confirms; a uniformly
    slow endpoint and a noisy one are refused by BOTH paths."""
    serial_engine, serial_findings = _run(origin, path, workers=1)
    inter_engine, inter_findings = _run(origin, path, workers=4)

    assert serial_engine._staged_timing_plan is not None  # sanity: the hook exists
    assert bool(serial_findings) is expect_confirm
    assert bool(inter_findings) is expect_confirm

    s, i = _verdicts(serial_engine, serial_findings), _verdicts(inter_engine, inter_findings)
    assert s == i, f"interleaving changed the adjudication on {path}"
    # Every point was adjudicated on both paths — a refute must be a real CLEAN/
    # INCONCLUSIVE verdict from the oracle, never a silently skipped probe.
    assert len(s["exercised"]) == 4
    if expect_confirm:
        assert {f[3] for f in s["findings"]} == {"timing"}


def test_interleaving_actually_engaged(origin: str) -> None:
    """Guard against the equivalence tests passing because the staged path never ran."""
    engine = AuditEngine(_send, timing_workers=4)
    template = RequestTemplate(_request(origin, "/slow"))
    points = template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
    plan = engine._staged_timing_plan(points, (_timing(),), None)
    assert plan is not None
    assert sum(1 for _p, _fast, slow in plan if slow) == 4


# ---------------------------------------------------------------------------
# 2. the within-point statistical discipline is untouched
# ---------------------------------------------------------------------------


def test_within_point_interleaving_preserved(origin: str) -> None:
    """Per point, the observation sequence is still benign, treatment, benign, treatment …

    This is the control that makes latency drift bias both arms equally, and it is what
    the Mann-Whitney U comparison assumes. Concurrency is ACROSS points only, so each
    point's own sequence must be indistinguishable from the serial one."""
    order: list[tuple[str, str]] = []
    lock = threading.Lock()

    def recording_send(req: HttpRequest) -> dict:
        q = parse_qs(urlsplit(req.url).query)
        hit = [(k, v[0]) for k, v in sorted(q.items()) if v and v[0] != "0"]
        with lock:
            order.append(hit[0] if hit else ("?", "?"))
        return _send(req)

    for workers in (1, 4):
        order.clear()
        _run(origin, "/slow", workers=workers, send=recording_send)
        per_point: dict[str, list[str]] = {}
        for param, value in order:
            per_point.setdefault(param, []).append(
                "treat" if _SLEEP_TOKEN in value else "base")
        assert len(per_point) == 4
        for param, seq in per_point.items():
            assert seq == ["base", "treat"] * _SAMPLES, (
                f"within-point interleaving broken at {param} with workers={workers}")


def test_collect_and_context_compose_to_the_old_probe() -> None:
    """The collect/context split is a refactor, not a behaviour change: the pure half
    turns an observation sequence into exactly the evidence the one-shot probe built."""
    check = TimingCheck(
        id="t", bug_class="time_based_sqli", benign="1", sleep_payload="1 SLEEP",
        injected_ms=1000.0, samples=3, dose_payload="1 SLEEP2", dose_ms=2000.0,
    )
    obs = TimingObservations(baseline=(1.0, 2.0, 3.0), treatment=(11.0, 12.0, 13.0),
                             dose=(21.0, 22.0, 23.0))
    ctx = check.context_from(obs)
    assert ctx is not None
    assert ctx.baseline_latencies == [1.0, 2.0, 3.0]
    assert ctx.treatment_latencies == [11.0, 12.0, 13.0]
    assert ctx.timing_injected_ms == 1000.0
    assert ctx.timing_dose == {
        "low_ms": 1000.0, "low_samples": [11.0, 12.0, 13.0],
        "high_ms": 2000.0, "high_samples": [21.0, 22.0, 23.0],
    }


def test_interleave_helper_preserves_submission_order() -> None:
    """``interleave_timing_jobs`` gathers in SUBMISSION order however the jobs finish, and
    is the plain serial loop at workers <= 1."""
    def job(i: int, delay: float):
        def run() -> int:
            time.sleep(delay)
            return i
        return run

    jobs = [job(i, d) for i, d in enumerate([0.05, 0.0, 0.03, 0.0])]
    assert interleave_timing_jobs(jobs, workers=4) == [0, 1, 2, 3]
    assert interleave_timing_jobs(jobs, workers=1) == [0, 1, 2, 3]


# ---------------------------------------------------------------------------
# 3. sample / request counts and the short-circuit rule
# ---------------------------------------------------------------------------


def test_request_count_and_short_circuit_identical(origin: str) -> None:
    """Two timing entries sharing a bug_class: the first confirmation at a point still
    short-circuits the second, on BOTH paths, so the request count is identical. Speed
    must not come from sending fewer (or more) requests."""
    roster = (_timing("t1"), _timing("t2"))
    serial_engine, serial_findings = _run(origin, "/slow", workers=1, checks=roster)
    inter_engine, inter_findings = _run(origin, "/slow", workers=4, checks=roster)

    assert _verdicts(serial_engine, serial_findings) == _verdicts(inter_engine, inter_findings)
    # 4 points x 1 entry x 2*samples: the second entry is short-circuited everywhere.
    assert serial_engine.requests_sent == 4 * 2 * _SAMPLES
    assert inter_engine.requests_sent == serial_engine.requests_sent
    assert len(serial_findings) == 4


def test_sample_counts_unchanged(origin: str) -> None:
    """Every retained context carries exactly ``samples`` observations per arm — the
    interleave never trades samples for speed."""
    _engine, findings = _run(origin, "/slow", workers=4)
    assert findings
    for f in findings:
        ctx = f.oracle_context or {}
        assert len(ctx["baseline_latencies"]) == _SAMPLES
        assert len(ctx["treatment_latencies"]) == _SAMPLES


# ---------------------------------------------------------------------------
# 4. the retained context (offline re-verification input) is shape/order-identical
# ---------------------------------------------------------------------------


def test_retained_context_shape_and_order_identical(origin: str) -> None:
    """The serialized FindingContext an existing certificate re-runs the oracle over has
    the same keys, the same non-sample values and the same per-point ORDER. (The latency
    floats themselves are measurements, so they differ run to run on either path — the
    VERDICT derived from them is what must not.)"""
    _s_engine, serial_findings = _run(origin, "/slow", workers=1)
    _i_engine, inter_findings = _run(origin, "/slow", workers=4)
    assert len(serial_findings) == len(inter_findings) == 4

    for sf, inf in zip(serial_findings, inter_findings):
        sc, ic = sf.oracle_context or {}, inf.oracle_context or {}
        assert sc.keys() == ic.keys()
        assert sf.insertion_point == inf.insertion_point  # same point, same position
        for key in sc:
            if key in ("baseline_latencies", "treatment_latencies"):
                assert len(sc[key]) == len(ic[key])
                assert all(isinstance(x, float) for x in ic[key])
            else:
                assert sc[key] == ic[key], f"retained {key} diverged"


def test_emission_order_is_canonical(origin: str) -> None:
    """Coverage records and findings come out point-major, in roster order — the order the
    serial sweep produced — even though stage 2 finished the points out of order."""
    roster = (DifferentialCheck(id="d1", bug_class="sqli", benign="1", probe_payload="1'"),
              _timing("t1"))
    serial_engine, serial_findings = _run(origin, "/slow", workers=1, checks=roster)
    inter_engine, inter_findings = _run(origin, "/slow", workers=4, checks=roster)
    assert _verdicts(serial_engine, serial_findings) == _verdicts(inter_engine, inter_findings)
    # point-major: all of p0's probes, then p1's, …
    points = [p.insertion_point for p in inter_engine.exercised]
    assert points == sorted(points, key=points.index)  # no point revisited
    assert [p.check_id for p in inter_engine.exercised] == \
           [p.check_id for p in serial_engine.exercised]


# ---------------------------------------------------------------------------
# 5. the staging refuses itself whenever it would not be provably equivalent
# ---------------------------------------------------------------------------


def test_staging_is_refused_when_not_provably_equivalent(origin: str) -> None:
    template = RequestTemplate(_request(origin, "/slow"))
    points = template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
    timing = _timing()

    # opt-in only
    assert AuditEngine(_send, timing_workers=1)._staged_timing_plan(points, (timing,), None) is None
    # a request budget makes the cut-off order-dependent -> stay serial
    assert AuditEngine(_send, timing_workers=4, max_requests=50)._staged_timing_plan(
        points, (timing,), None) is None
    # nothing to interleave -> stay serial rather than pay for a pool
    one_point = points[:1]
    assert AuditEngine(_send, timing_workers=4)._staged_timing_plan(
        one_point, (timing,), None) is None
    assert AuditEngine(_send, timing_workers=4)._staged_timing_plan(
        points, (DifferentialCheck(id="d", bug_class="sqli", benign="1", probe_payload="1'"),),
        None) is None

    # a bug_class shared with a NON-timing check couples the two stages through the
    # seen-dedup -> that point keeps every check in the serial stage.
    shared = DifferentialCheck(id="d", bug_class="time_based_sqli", benign="1", probe_payload="1'")
    plan = AuditEngine(_send, timing_workers=4)._staged_timing_plan(points, (shared, timing), None)
    assert plan is None or all(not slow for _p, _fast, slow in plan)


def test_bandit_keeps_the_sweep_serial(origin: str) -> None:
    """The bandit re-ranks each point's roster from rewards earned at EARLIER points, so
    overlapping points would change the ordering. The bandit path stays serial."""
    from framework.v2.scanner.learning import ContextualBandit

    template = RequestTemplate(_request(origin, "/slow"))
    points = template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
    engine = AuditEngine(_send, timing_workers=4, bandit=ContextualBandit())
    assert engine._staged_timing_plan(points, (_timing(),), None) is None


# ---------------------------------------------------------------------------
# 6. the measured win: idle time removed
# ---------------------------------------------------------------------------


def test_interleaving_removes_idle_wall_clock(origin: str) -> None:
    """The whole point. Four points, each spending ~2*samples*delay blocked on the target;
    four in flight should finish in materially less wall-clock. The bound is deliberately
    loose (a real speedup here is ~4x) so this asserts the win without being a flaky
    micro-benchmark."""
    t0 = time.monotonic()
    serial_engine, serial_findings = _run(origin, "/slow", workers=1)
    serial_s = time.monotonic() - t0

    t0 = time.monotonic()
    inter_engine, inter_findings = _run(origin, "/slow", workers=4)
    inter_s = time.monotonic() - t0

    assert len(serial_findings) == len(inter_findings) == 4
    assert serial_engine.requests_sent == inter_engine.requests_sent
    assert inter_s < serial_s * 0.6, (
        f"no idle time removed: serial {serial_s:.2f}s vs interleaved {inter_s:.2f}s")
