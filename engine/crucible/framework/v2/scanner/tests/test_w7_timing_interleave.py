"""
W7 (performance) — the TIMING INTERLEAVE: CONCURRENCY FOR SEARCH, SERIAL FOR PROOF.

A statistical timing probe is the sweep's largest wall-clock term and it is ~100% IDLE:
it is blocked on the delay it asked the target to take. ``AuditEngine(timing_workers=N)``
overlaps the idle waits of DIFFERENT insertion points.

The load-bearing claim is NOT that a concurrent measurement equals a serial one. It does
not: the two arms of a probe alternate (base, treat, base, treat …) so overlapping points
PHASE-LOCK — every worker is in the same half-cycle at any instant — and the origin serves
N cheap requests during the baseline window and N expensive ones during the treatment
window. On any origin with a payload-DEPENDENT service time that queueing amplifies the
asymmetry ~N-fold into a ONE-SIDED oracle and can MANUFACTURE a confirmation. So the
concurrent pass only ever produces CANDIDATES, and every candidate point is re-measured
SERIALLY before anything may confirm.

What these tests have to make false-if-broken:

  * a concurrent pass CANNOT mint a timing fact on an origin whose only delay is
    payload-length-dependent — the case that fired 10/60 before the serial re-measure
    existed (:func:`test_concurrency_cannot_manufacture_a_timing_fact`);
  * the oracle's DECISION is unchanged across the range — a genuinely conditionally-slow
    endpoint still CONFIRMS, a uniformly slow one still REFUTES, a jittery one still
    REFUTES (:func:`test_verdicts_identical_across_the_range`);
  * the WITHIN-POINT interleaving of baseline vs treatment observations — the control the
    Mann-Whitney U shift test and the dose-response ratio rest on — is byte-for-byte the
    serial order (:func:`test_within_point_interleaving_preserved`);
  * sample COUNTS are identical and the REQUEST count follows the documented rule — a
    refuted point costs exactly what the serial sweep costs, a FLAGGED point costs it
    twice because it is re-measured — including the "first confirmation of a bug class at
    a point short-circuits that class's remaining entries" rule
    (:func:`test_request_count_and_short_circuit_identical`);
  * the retained context (the re-verifiable certificate input) has identical SHAPE and
    ORDER, so an existing certificate still re-fires offline
    (:func:`test_retained_context_shape_and_order_identical`);
  * the emission order of findings and coverage records is canonical
    (:func:`test_emission_order_is_canonical`);
  * every precondition that would make the staging inexact keeps the sweep SERIAL
    (:func:`test_staging_is_refused_when_not_provably_equivalent`);
  * and a raising ORACLE propagates out of the staged sweep exactly as it does out of the
    serial one, rather than being swallowed into a "clean" zero-coverage pass
    (:func:`test_a_raising_oracle_propagates_from_the_staged_sweep`).

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

# `/asym` — the FALSE-POSITIVE origin. It has NO conditional delay of any kind: its
# service time is a pure function of the probed value's LENGTH, and it is served behind a
# capacity-1 pool (one worker / one DB connection / a global lock), which every real app
# has some version of. Benign "1" costs 12 ms, the payload "1 SLEEP" costs 60 ms, so the
# phase-lock-free truth is a 48 ms shift — far under the 250 ms effect floor. Under a
# phase-locked concurrent sweep the queueing amplifies it ~N-fold and it walks through the
# floor; that is the bug the serial re-measurement closes.
_ASYM_BASE_MS = 4.0
_ASYM_PER_CHAR_MS = 8.0
_ASYM_POINTS = 8
_ASYM_SAMPLES = 6
_ASYM_INJECTED_MS = 500.0   # -> a 250 ms effect floor, 5x the real 48 ms asymmetry


class _Origin(BaseHTTPRequestHandler):
    """Three behaviours on one loopback origin.

    ``/slow``    delays only when the payload injects one  -> a real time-based channel.
    ``/uniform`` always delays by the same amount          -> no shift; must REFUTE.
    ``/jitter``  delays by a varying, payload-independent  -> noise only; must REFUTE.
                 amount
    """

    _tick = 0
    _tick_lock = threading.Lock()
    # `/asym`'s bounded pool: exactly one request is SERVED at a time, while the accept
    # path stays concurrent. This is what turns a phase-locked sweep's own traffic into
    # self-inflicted queueing.
    _capacity = threading.Lock()

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
        elif parts.path == "/asym":
            probed = [v[0] for v in q.values() if v and v[0] != "0"]
            cost = _ASYM_BASE_MS + _ASYM_PER_CHAR_MS * len(probed[0] if probed else "")
            with _Origin._capacity:   # capacity 1 -> concurrent callers QUEUE
                time.sleep(cost / 1000.0)
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


class _Engine(AuditEngine):
    """An AuditEngine that records whether the STAGED sweep actually ran.

    Without this an "identical verdicts" test passes just as happily when the staged path
    silently fell back to the serial one — i.e. when it proves nothing at all."""

    def __init__(self, *a, **kw) -> None:
        super().__init__(*a, **kw)
        self.staged_entered = 0

    def _sweep_staged(self, **kw):  # type: ignore[override]
        self.staged_entered += 1
        return super()._sweep_staged(**kw)


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


def _run(base: str, path: str, *, workers: int, checks=None, send=_send, points: int = 4,
         **engine_kw):
    """One audit over ``path``'s query points. Returns (engine, findings)."""
    engine = _Engine(send, timing_workers=workers, **engine_kw)
    findings = engine.audit(
        _request(base, path, points=points), checks=checks or (_timing(),),
        insertion_kinds=(InsertionKind.QUERY_VALUE,),
    )
    return engine, findings


def _verdicts(engine, findings) -> dict:
    """The decision-bearing projection: what confirmed, and how every probe adjudicated.

    Deliberately NOT including ``requests_sent``. The staged sweep re-measures every point
    its concurrent search pass flagged, so a CONFIRMING point spends its timing sequence
    twice; that is the documented contract, and it is asserted where it belongs
    (:func:`test_request_count_and_short_circuit_identical`) rather than smuggled into an
    equality that is really about the adjudication."""
    return {
        "findings": [
            (f.check_id, f.bug_class, f.insertion_point, f.confirmed_by, f.param)
            for f in findings
        ],
        "exercised": [
            (p.insertion_point, p.check_id, p.bug_class, p.verdict, p.oracle_kinds_run)
            for p in engine.exercised
        ],
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

    # Not "the hook exists" (a bound method is always truthy) — the STAGED SWEEP RAN on
    # the interleaved path and did NOT on the serial one. Without this the equality below
    # is satisfied by a silent fallback to the serial sweep.
    assert serial_engine.staged_entered == 0
    assert inter_engine.staged_entered == 1
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
    point's own sequence must be indistinguishable from the serial one.

    A FLAGGED point is measured twice (concurrent search, then the serial proof), so its
    recorded sequence is that alternation repeated — never a merged or reordered one."""
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
            passes, remainder = divmod(len(seq), 2 * _SAMPLES)
            assert remainder == 0 and passes in (1, 2), (
                f"{param} took {len(seq)} observations with workers={workers}: neither one "
                f"full sequence nor a search pass plus its serial re-measurement")
            assert seq == ["base", "treat"] * (_SAMPLES * passes), (
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
    short-circuits the second, on BOTH paths.

    The request COUNT follows the documented rule, which is not "identical": a point the
    concurrent search pass REFUTES costs exactly what the serial sweep costs, and a point
    it FLAGS costs it twice, because the flag is only a candidate and the proof is a
    serial re-measurement. `/slow` is the worst case for that rule — every point is a real
    bug — so here the staged sweep pays exactly 2x. Speed must never come from sending
    FEWER requests, and the extra ones must be exactly the re-measurements."""
    roster = (_timing("t1"), _timing("t2"))
    serial_engine, serial_findings = _run(origin, "/slow", workers=1, checks=roster)
    inter_engine, inter_findings = _run(origin, "/slow", workers=4, checks=roster)

    assert _verdicts(serial_engine, serial_findings) == _verdicts(inter_engine, inter_findings)
    # 4 points x 1 entry x 2*samples: the second entry is short-circuited everywhere.
    per_point = 2 * _SAMPLES
    assert serial_engine.requests_sent == 4 * per_point
    assert len(serial_findings) == 4
    # all four points flagged -> all four re-measured serially -> exactly 2x, no more.
    assert inter_engine.timing_remeasured == 4
    assert inter_engine.requests_sent == serial_engine.requests_sent + 4 * per_point


def test_a_refuted_point_is_not_re_measured(origin: str) -> None:
    """The wall-clock win rests on this: the re-measurement is paid only by CANDIDATES.
    On an origin where nothing confirms, the staged sweep sends exactly what the serial
    sweep sends and re-measures nothing."""
    serial_engine, serial_findings = _run(origin, "/uniform", workers=1)
    inter_engine, inter_findings = _run(origin, "/uniform", workers=4)
    assert serial_findings == inter_findings == []
    assert inter_engine.staged_entered == 1
    assert inter_engine.timing_remeasured == 0
    assert inter_engine.requests_sent == serial_engine.requests_sent == 4 * 2 * _SAMPLES


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
    """The whole point — measured on the surface the sweep actually meets.

    `/uniform` is slow on EVERY request and confirms nothing, which is the shape of the
    overwhelming majority of real insertion points: idle time to remove, no candidate to
    re-measure. Four points, each spending ~2*samples*delay blocked on the target; four in
    flight should finish in materially less wall-clock. The bound is deliberately loose (a
    real speedup here is ~4x) so this asserts the win without being a flaky
    micro-benchmark.

    NOTE the honest boundary: on a surface where EVERY point is a real bug, the serial
    re-measurement gives the win back — see
    :func:`test_request_count_and_short_circuit_identical`, where the staged sweep pays
    2x. The optimisation is a search accelerator, not a proof accelerator."""
    t0 = time.monotonic()
    serial_engine, serial_findings = _run(origin, "/uniform", workers=1)
    serial_s = time.monotonic() - t0

    t0 = time.monotonic()
    inter_engine, inter_findings = _run(origin, "/uniform", workers=4)
    inter_s = time.monotonic() - t0

    assert serial_findings == inter_findings == []
    assert inter_engine.staged_entered == 1
    assert serial_engine.requests_sent == inter_engine.requests_sent
    assert inter_s < serial_s * 0.6, (
        f"no idle time removed: serial {serial_s:.2f}s vs interleaved {inter_s:.2f}s")


# ---------------------------------------------------------------------------
# 7. PRECISION — a concurrent measurement may not mint
# ---------------------------------------------------------------------------


def test_concurrency_cannot_manufacture_a_timing_fact(origin: str) -> None:
    """The defect this slice had to close, on the origin that produced it.

    `/asym` has NO conditional delay. Its service time is a pure function of the probed
    value's LENGTH (12 ms for the benign "1", 60 ms for "1 SLEEP") behind a capacity-1
    pool. The phase-lock-free truth is therefore a 48 ms shift against a 250 ms effect
    floor — nothing to find, and the serial sweep finds nothing.

    A phase-locked concurrent sweep is a different story: every worker is in the same
    half-cycle at once, so the origin serves N cheap requests during the baseline window
    and N expensive ones during the treatment window, the asymmetry is amplified ~N-fold
    by the sweep's OWN queueing, and the one-sided rank-sum test records the positive
    mode. Before the serial re-measurement this fired 10 times in 60 point-runs at
    workers = 12 and 24, on the same points every repetition.

    The assertions: the search pass must still FLAG (otherwise the fixture stopped
    amplifying and this test proves nothing), and NOTHING may confirm."""
    check = TimingCheck(
        id="asym", bug_class="time_based_sqli", benign="1",
        sleep_payload=f"1 {_SLEEP_TOKEN}", injected_ms=_ASYM_INJECTED_MS,
        samples=_ASYM_SAMPLES,
    )
    serial_engine, serial_findings = _run(
        origin, "/asym", workers=1, checks=(check,), points=_ASYM_POINTS)
    assert serial_findings == [], (
        "the fixture is not a negative control: the SERIAL sweep confirmed on an origin "
        "whose only asymmetry is payload length")

    inter_engine, inter_findings = _run(
        origin, "/asym", workers=_ASYM_POINTS, checks=(check,), points=_ASYM_POINTS)
    assert inter_engine.staged_entered == 1
    assert inter_engine.timing_remeasured >= 1, (
        "the concurrent search pass flagged nothing, so the serial re-measurement was "
        "never exercised — this run proves nothing about the guard")
    assert inter_findings == [], (
        f"a concurrent measurement minted a timing FACT on an origin with no conditional "
        f"delay: {[(f.param, f.confidence) for f in inter_findings]}")
    # and the flagged points really did cost their sequence twice — the proof ran.
    assert inter_engine.requests_sent == (
        serial_engine.requests_sent + inter_engine.timing_remeasured * 2 * _ASYM_SAMPLES)


# ---------------------------------------------------------------------------
# 8. failure propagation — a staged sweep may not swallow what the serial one raises
# ---------------------------------------------------------------------------


def test_a_raising_oracle_propagates_from_the_staged_sweep(
    origin: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_probe_and_adjudicate`` isolates a failing ``check.probe`` — but the ORACLE call
    sits outside that guard, and a raising oracle PROPAGATES out of the serial sweep. The
    staged sweep used to swallow it per check and return a "clean" result with zero
    findings AND zero coverage records: silent coverage loss dressed as a pass. Both paths
    must fail the same way."""
    from framework.v2.scanner import engine as engine_mod

    def _boom(*_a: object, **_kw: object):
        raise RuntimeError("oracle exploded")

    monkeypatch.setattr(engine_mod, "adjudicate_finding", _boom)

    with pytest.raises(RuntimeError, match="oracle exploded"):
        _run(origin, "/slow", workers=1)
    with pytest.raises(RuntimeError, match="oracle exploded"):
        _run(origin, "/slow", workers=4)


def test_stage_one_budget_exhaustion_keeps_what_was_adjudicated(origin: str) -> None:
    """A BudgetExceeded in stage 1 must stop the sweep and still EMIT — not unwind past
    stage 3 and discard every outcome already adjudicated.

    Unreachable through ``_staged_timing_plan`` today (a budgeted sweep is never staged),
    so the plan is built by hand: this pins the guard for whoever relaxes that
    precondition, which is exactly when the trap would spring."""
    diff = DifferentialCheck(id="d1", bug_class="sqli", benign="1", probe_payload="1'")
    timing = _timing()
    engine = _Engine(_send, timing_workers=4, max_requests=3)
    request = _request(origin, "/slow")
    template = RequestTemplate(request)
    points = template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
    plan = [(p, [(0, diff)], [(1, timing)]) for p in points]

    findings: list = []
    engine._sweep_staged(
        template=template, request=request, plan=plan, seen=set(), findings=findings)
    # the budget bit in stage 1; what HAD adjudicated is still on the coverage ledger.
    assert engine.requests_sent == 3
    assert engine.exercised, "a budget stop discarded every coverage record"
    assert engine.timing_remeasured == 0
