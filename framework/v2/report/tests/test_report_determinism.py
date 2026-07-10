"""
Determinism: the report is a pure, reproducible function of the findings. The same
fixture engagement renders byte-identically twice (no wallclock, no RNG on the default
path). A timestamp is opt-in and is the only source of variation.
"""

from __future__ import annotations

from framework.v2.report import ReportMeta, generate_reports
from framework.v2.report.generate import render_technical
from framework.v2.report.grounding import grade_findings

from .conftest import make_demoted, make_fact, make_lead


def _engagement():
    return [make_fact(), make_demoted(), make_lead()]


def test_bundle_renders_byte_identically_twice() -> None:
    meta = ReportMeta(target="acme", window_start="2026-07-01", window_end="2026-07-09")
    a = generate_reports(_engagement(), meta)
    b = generate_reports(_engagement(), meta)
    assert a == b
    for name in a:
        assert a[name] == b[name]


def test_default_render_has_no_timestamp() -> None:
    md = render_technical(grade_findings(_engagement()), ReportMeta(target="acme"))
    assert "Generated:" not in md   # no wallclock on the deterministic path


def test_opt_in_timestamp_is_shown_and_still_reproducible() -> None:
    meta = ReportMeta(target="acme", generated_at="2026-07-10T00:00:00+00:00")
    a = generate_reports(_engagement(), meta)
    b = generate_reports(_engagement(), meta)
    assert a == b                                    # same stamp → still byte-identical
    assert "Generated:** 2026-07-10T00:00:00+00:00" in a["technical"]


def test_finding_order_does_not_change_output() -> None:
    # the renderers sort internally, so input order is irrelevant → still reproducible.
    meta = ReportMeta(target="acme")
    fwd = generate_reports([make_fact(), make_demoted(), make_lead()], meta)
    rev = generate_reports([make_lead(), make_demoted(), make_fact()], meta)
    assert fwd == rev
