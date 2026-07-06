"""
Performance/cost instrumentation for the comparative harness (A1).

A Scoreboard says how ACCURATE a tool is; RunMetrics says what that accuracy
COST — wall-clock, active-request budget, coverage breadth, best-effort RSS.
These tests pin the honest-gap contract (a number a tool cannot report is None,
never a fabricated 0), the measured comparative path, and the ScanReport timer.
"""

from __future__ import annotations

from framework.v2.eval.validation import (
    CorpusTarget,
    ExpectedFinding,
    MeasuredBoard,
    NormalizedFinding,
    RunMetrics,
    _attributable_rss,
    comparative_report_measured,
    render_measured_table,
)


def _nf(bug_class: str, location: str, *, tool: str) -> NormalizedFinding:
    return NormalizedFinding(tool=tool, bug_class=bug_class, location=location)


class _StubAdapter:
    """A shell-out-style adapter that reports no internal metrics (like an
    incumbent) unless told to."""

    def __init__(self, name, findings, *, available=True, sets_metrics=None):
        self.name = name
        self._findings = findings
        self._available = available
        # what run() will publish into last_metrics (like the real CRUCIBLE
        # adapter does INSIDE run); None means "reports nothing", like an incumbent.
        self._sets_metrics = sets_metrics
        self.last_metrics = None

    def available(self) -> bool:
        return self._available

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        if self._sets_metrics is not None:
            self.last_metrics = self._sets_metrics
        return self._findings


def _target() -> CorpusTarget:
    return CorpusTarget(
        name="T",
        base_url="http://127.0.0.1/",
        expected=[ExpectedFinding(bug_class="xss", location="/a?q")],
    )


def test_attributable_rss_prefers_child_then_self_then_none() -> None:
    # a subprocess incumbent moved RUSAGE_CHILDREN -> that delta wins
    assert _attributable_rss(100, 100, 1000, 3000) == 2000
    # no child movement -> fall back to the self high-water rise
    assert _attributable_rss(1000, 4000, 500, 500) == 3000
    # nothing moved -> honest None, never 0
    assert _attributable_rss(1000, 1000, 500, 500) is None


def test_measured_report_records_time_and_findings_for_every_tool() -> None:
    good = _StubAdapter("good", [_nf("xss", "/a?q", tool="good")])
    measured = comparative_report_measured(_target(), [good])
    assert len(measured) == 1
    mb = measured[0]
    assert isinstance(mb, MeasuredBoard)
    assert mb.scoreboard.precision == 1.0
    # elapsed is always measured; findings_reported counts raw output
    assert mb.metrics.elapsed_s >= 0.0
    assert mb.metrics.findings_reported == 1


def test_incumbent_without_last_metrics_reports_none_not_zero() -> None:
    incumbent = _StubAdapter("wapiti", [_nf("xss", "/a?q", tool="wapiti")])
    (mb,) = comparative_report_measured(_target(), [incumbent])
    # the honest-gap contract: unknown request/discovery -> None
    assert mb.metrics.requests_sent is None
    assert mb.metrics.pages_discovered is None
    assert mb.metrics.requests_discovered is None


def test_crucible_style_last_metrics_is_read_back() -> None:
    crucible = _StubAdapter(
        "crucible",
        [_nf("xss", "/a?q", tool="crucible")],
        sets_metrics={"requests_sent": 42, "pages_discovered": 7, "requests_discovered": 19},
    )
    (mb,) = comparative_report_measured(_target(), [crucible])
    assert mb.metrics.requests_sent == 42
    assert mb.metrics.pages_discovered == 7
    assert mb.metrics.requests_discovered == 19


def test_stale_last_metrics_is_cleared_between_runs() -> None:
    # an adapter reused across runs must not leak a prior run's metrics into a run
    # that sets nothing — the harness clears last_metrics before each run().
    stale = _StubAdapter("x", [_nf("xss", "/a?q", tool="x")], sets_metrics=None)
    stale.last_metrics = {"requests_sent": 999}  # leftover from an imagined prior run
    (mb,) = comparative_report_measured(_target(), [stale])
    assert mb.metrics.requests_sent is None


def test_peak_rss_mb_derives_from_kb() -> None:
    m = RunMetrics(tool="t", target="T", peak_rss_kb=2048)
    assert m.peak_rss_mb == 2.0
    assert RunMetrics(tool="t", target="T").peak_rss_mb is None


def test_render_measured_table_has_cost_columns_and_dash_for_gaps() -> None:
    good = _StubAdapter("wapiti", [_nf("xss", "/a?q", tool="wapiti")])
    measured = comparative_report_measured(_target(), [good])
    table = render_measured_table(measured)
    for col in ("time_s", "reqs", "rss_mb", "found"):
        assert col in table
    # an incumbent's unknown request count renders as a dash, not 0
    body = table.splitlines()[-1]
    assert " - " in body
