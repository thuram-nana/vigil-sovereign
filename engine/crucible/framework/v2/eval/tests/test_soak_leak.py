"""eval.soak — the REAL soak gate: a documented throughput floor + memory-leak detection (W11-6, #487).

This is the FAST, DETERMINISTIC per-PR half of the soak. It rides the required ``CRUCIBLE eval +
benchmark corpus`` job (which runs ``framework/v2/eval`` wholesale), and it pins four things:

  * the leak DETECTOR catches a rising memory series and leaves a flat one alone (pure, synthetic —
    platform-independent);
  * an artificially-LEAKING fixture, sampled over REAL process RSS, IS DETECTED — and its clean twin is
    NOT (the negative control that proves the check is not a no-op, exercised over live memory);
  * a SCALED sustained-load run holds the documented conservative CI throughput floor and stays
    replay-deterministic across iterations, with the scanner itself proven not to leak; and
  * the throughput-floor predicate REJECTS a below-floor number, and the ``passed`` roll-up turns a
    below-floor run into a failure.

The FULL multi-minute sustained soak (the SLA floor over a long run) is the scheduled
``.github/workflows/soak.yml`` job — honestly labelled, NOT a per-PR gate. See
``docs/decisions/W11-6-load-soak-throughput-leak.md``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.eval.soak import (
    CI_THROUGHPUT_FLOOR_RPS,
    LeakingWorkload,
    SustainedSoakResult,
    clean_workload,
    current_rss_mb,
    detect_leak,
    memory_series,
    run_soak_sustained,
    throughput_holds,
)

_NO_RSS = current_rss_mb() is None


# ---- the leak detector, purely (deterministic, platform-independent) ------------------------------
def test_detect_leak_flags_a_rising_series():
    rising = [100.0 + 8.0 * i for i in range(8)]     # +8 MiB/iter — a textbook leak
    v = detect_leak(rising)
    assert v.leaked, v.reason
    assert v.slope_mb_per_iter > 0.5 and v.growth_mb > 4.0


def test_detect_leak_passes_a_noisy_but_stable_series():
    flat = [100.0, 100.4, 99.7, 100.2, 100.1, 99.9, 100.3, 100.0]  # jitter, no trend
    v = detect_leak(flat)
    assert not v.leaked, v.reason


def test_detect_leak_needs_both_slope_and_growth():
    # A single large warmup step then a flat plateau is NOT a leak: net growth is real but the slope of
    # the plateau is ~0, so the AND-of-both rule (which suppresses noise) must not fire.
    stepped = [100.0] + [180.0] * 7
    v = detect_leak(stepped, warmup=1)
    assert not v.leaked, v.reason


def test_detect_leak_is_insufficient_data_safe():
    v = detect_leak([100.0, 101.0])   # fewer than 3 post-warmup points
    assert not v.leaked and "insufficient" in v.reason.lower()


# ---- the artificially-leaking fixture, over REAL RSS (THE negative control) -----------------------
@pytest.mark.skipif(_NO_RSS, reason="no /proc/self/statm RSS sampler on this platform")
def test_leaking_fixture_is_detected():
    """The negative control the acceptance criteria name: an artificial leak MUST be caught. If the
    detector were a no-op this fails, proving the gate is real."""
    series = memory_series(LeakingWorkload(mib=8.0), 8)
    v = detect_leak(series)
    assert v.leaked, f"an 8 MiB/iter leak must be detected; series={series}, reason={v.reason}"


@pytest.mark.skipif(_NO_RSS, reason="no /proc/self/statm RSS sampler on this platform")
def test_clean_fixture_is_not_flagged():
    """The healthy twin: allocate-and-free each iteration must NOT be flagged (no false positive)."""
    series = memory_series(clean_workload(mib=8.0), 8)
    v = detect_leak(series)
    assert not v.leaked, f"healthy churn must not be flagged; series={series}, reason={v.reason}"


# ---- the throughput-floor predicate (pure negative control) ---------------------------------------
def test_throughput_floor_predicate_rejects_below_and_accepts_at_or_above():
    assert throughput_holds(CI_THROUGHPUT_FLOOR_RPS, CI_THROUGHPUT_FLOOR_RPS)
    assert throughput_holds(CI_THROUGHPUT_FLOOR_RPS + 1.0, CI_THROUGHPUT_FLOOR_RPS)
    assert not throughput_holds(CI_THROUGHPUT_FLOOR_RPS - 0.1, CI_THROUGHPUT_FLOOR_RPS)


# ---- a scaled REAL sustained soak, in the required job ---------------------------------------------
def test_scaled_sustained_soak_holds_the_ci_floor_and_stays_deterministic():
    res = run_soak_sustained(4, iterations=4, max_audit_requests=60,
                             floor_rps=CI_THROUGHPUT_FLOOR_RPS)
    assert isinstance(res, SustainedSoakResult)
    assert res.iterations == 4 and res.audit_requests_sent > 0
    assert res.throughput_ok, (
        f"sustained throughput {res.throughput_rps} rps fell below the documented CI floor "
        f"{res.throughput_floor_rps} rps")
    assert res.determinism_stable, "the scan fingerprint diverged across sustained iterations"
    assert not res.leak.leaked, (
        f"the scanner itself leaked across the soak: {res.leak.reason} (rss={res.rss_samples_mb})")
    assert res.passed


def test_sustained_pass_roll_up_fails_below_floor():
    """Negative control on the roll-up: an unreachably-high floor makes an otherwise-healthy run FAIL,
    proving ``passed``/``throughput_ok`` actually gate on the floor rather than always reporting green."""
    res = run_soak_sustained(4, iterations=2, max_audit_requests=30, floor_rps=1e9)
    assert not res.throughput_ok
    assert not res.passed


# ---- the FULL sustained soak is wired as a scheduled job, honestly labelled ------------------------
# engine/crucible/framework/v2/eval/tests/test_soak_leak.py -> repo root is parents[6].
_REPO_ROOT = Path(__file__).resolve().parents[6]
_SOAK_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "soak.yml"


@pytest.mark.skipif(not _SOAK_WORKFLOW.is_file(), reason="soak.yml not present on this ref")
def test_full_soak_is_a_scheduled_job_not_a_pr_gate():
    """Pins the honest split: the full sustained soak is scheduled (never a PR gate), it is labelled as
    a nightly, and it actually invokes the sustained soak. Without this a rename or a downgrade of the
    scheduled job to a no-op would go unnoticed while the docs still claimed a full soak runs."""
    text = _SOAK_WORKFLOW.read_text(encoding="utf-8")
    # schedule + workflow_dispatch, and NOT pull_request — so it can never masquerade as a per-PR gate.
    assert "schedule:" in text and "workflow_dispatch:" in text
    assert "pull_request" not in text, "the full soak must not run on a pull_request (it is the heavy half)"
    # honestly labelled as a nightly, and it really drives the sustained soak entrypoint.
    assert "name: soak full run (nightly)" in text
    assert "framework.v2.eval.soak --sustained" in text
