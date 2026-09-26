"""
W7 (performance) — the gated transport stays SAFE when the scanner has N probes in flight.

The timing interleave (``AuditEngine(timing_workers=N)``) overlaps the idle waits of
different insertion points, and every one of those requests goes through the SAME
``HttpExecutor.gated_fetch``. Concurrency must therefore buy wall-clock WITHOUT buying
extra traffic or a higher request rate — the two things §VI of the constitution forbids.
These tests pin exactly that:

  * the posture's minimum inter-request interval is honoured START-to-START, so N
    concurrent callers are spaced by the floor instead of bursting through one stale
    anchor (:func:`test_rate_floor_is_honoured_with_concurrent_callers`);
  * the serial path's spacing semantics are unchanged — still measured from the previous
    request's COMPLETION (:func:`test_serial_spacing_is_unchanged`);
  * the per-engagement request budget is a hard cap even with requests in flight that have
    not yet been tallied (:func:`test_budget_is_never_overshot_under_concurrency`);
  * counters stay exact and evidence directories stay distinct
    (:func:`test_counters_are_exact_under_concurrency`,
    :func:`test_action_ids_are_unique`).
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

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


def test_rate_floor_is_honoured_with_concurrent_callers(isolated_engagement, httpserver: HTTPServer):
    """N concurrent gated fetches must still leave >= the posture floor between request
    STARTS. Before the W7 lock each caller read the same stale completion anchor and they
    all fired at once — N x the authorized rate. The floor is the rate limit; overlapping
    the *waits* is allowed, exceeding the *rate* is not."""
    isolated_engagement("alpha", "127.0.0.1")
    starts: list[float] = []
    lock = threading.Lock()

    def handler(_request) -> Response:
        with lock:
            starts.append(time.monotonic())
        time.sleep(0.25)  # a slow endpoint: this is the idle time the interleave overlaps
        return Response("ok", status=200)

    httpserver.expect_request("/probe").respond_with_handler(handler)
    ex = _executor(httpserver, request_budget=100)
    floor = _RATE_PROFILES["TEST"][0]
    assert floor > 0, "the TEST posture must declare a real rate floor for this test to bite"

    n = 6
    try:
        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(
                lambda i: ex.gated_fetch(_Req(url=f"http://127.0.0.1:{httpserver.port}/probe?i={i}")),
                range(n)))
    finally:
        ex.close()

    assert len(starts) == n
    starts.sort()
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    # A small tolerance for scheduling slop; the defect this guards produced gaps of ~0.
    assert min(gaps) >= floor * 0.85, f"rate floor {floor}s breached: gaps={gaps}"
    # …and the requests really did overlap, otherwise the test proves nothing about
    # concurrency: 6 serial 0.25s responses plus 6 x 0.2s spacing could not fit in this.
    assert starts[-1] - starts[0] < n * (floor + 0.25) * 0.9


def test_serial_spacing_is_unchanged(isolated_engagement, httpserver: HTTPServer):
    """The serial path still spaces from the previous request's COMPLETION — the
    start-instant reservation added for concurrency is superseded by the completion
    timestamp, so a single-threaded run behaves exactly as before."""
    isolated_engagement("alpha", "127.0.0.1")
    body_delay = 0.15
    httpserver.expect_request("/probe").respond_with_handler(
        lambda _r: (time.sleep(body_delay), Response("ok", status=200))[1])
    ex = _executor(httpserver, request_budget=10)
    floor = _RATE_PROFILES["TEST"][0]
    try:
        t0 = time.monotonic()
        for i in range(3):
            ex.gated_fetch(_Req(url=f"http://127.0.0.1:{httpserver.port}/probe?i={i}"))
        elapsed = time.monotonic() - t0
    finally:
        ex.close()
    # 3 requests: 3 x body_delay of I/O plus 2 completion-anchored floors between them.
    lower = 3 * body_delay + 2 * floor
    assert elapsed >= lower * 0.9, f"serial spacing loosened: {elapsed:.3f}s < {lower:.3f}s"


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
    """``requests_made`` is a plain ``+= 1`` read-modify-write; under threads it must be
    guarded or the budget silently drifts. Every issued request is tallied exactly once."""
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


def test_action_ids_are_unique():
    """Two actions in the same millisecond must not share an evidence directory — which
    concurrent probes (and fast loopback traffic) produce routinely."""
    ex = HttpExecutor(engagement_slug="<proto>", base_url="http://127.0.0.1:1", dry_run=True)
    ids: list[str] = []
    lock = threading.Lock()

    def mint(_i: int) -> None:
        got = ex._next_action_id()
        with lock:
            ids.append(got)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(mint, range(500)))
    assert len(set(ids)) == len(ids)
    assert all(i.startswith("H-") and len(i) == 11 for i in ids)
