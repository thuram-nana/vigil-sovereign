"""W11-5 (#486) — flake tracking: historical pass rates + EXPLICIT quarantine, made falsifiable.

Runs in the required ``sigil-governor`` job (whole-dir collection). It loads ``tools/flake/flake_tracker.py``
by PATH (the governor job puts ``apps/sigil`` on PYTHONPATH, not the repo root), so no packaging assumption.
Each positive test is paired with a NEGATIVE CONTROL that drives the SAME code with bad input and asserts it
is rejected — so the guard cannot be a no-op.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]               # apps/sigil/tests -> apps/sigil -> apps -> repo
_TRACKER_PATH = _REPO / "tools" / "flake" / "flake_tracker.py"


def _load_tracker():
    spec = importlib.util.spec_from_file_location("flake_tracker_under_test", _TRACKER_PATH)
    assert spec and spec.loader, f"cannot load flake_tracker from {_TRACKER_PATH}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ft = _load_tracker()


# --------------------------------------------------------------------------------------------------
# Historical pass rate
# --------------------------------------------------------------------------------------------------
def _seed(tmp_path: Path, rows: list[tuple[str, str]]) -> Path:
    led = tmp_path / "ledger.jsonl"
    for i, (tid, outcome) in enumerate(rows):
        ft.record_outcome(led, test_id=tid, outcome=outcome, run_id=f"r{i}")
    return led


def test_pass_rate_computed_from_the_ledger(tmp_path):
    led = _seed(tmp_path, [("t.a", "pass"), ("t.a", "pass"), ("t.a", "fail"), ("t.a", "skip")])
    st = ft.pass_rate(led, "t.a")
    # skip is NOT scored: 2 pass + 1 fail == 3 scored runs -> 2/3.
    assert st == {"test_id": "t.a", "passes": 2, "runs": 3, "skips": 1, "rate": pytest.approx(2 / 3)}


def test_pass_rate_negative_control_flakiness_is_detected(tmp_path):
    """NEGATIVE CONTROL: a test that fails some runs must NOT report rate 1.0, and MUST surface as a
    quarantine candidate. If the metric were hard-coded green this fails."""
    led = _seed(tmp_path, [("t.flaky", "pass"), ("t.flaky", "fail"), ("t.flaky", "pass"),
                           ("t.flaky", "fail"), ("t.flaky", "pass"), ("t.flaky", "pass"),
                           ("t.solid", "pass"), ("t.solid", "pass"), ("t.solid", "pass"),
                           ("t.solid", "pass"), ("t.solid", "pass")])
    assert ft.pass_rate(led, "t.flaky")["rate"] == pytest.approx(4 / 6)
    assert ft.pass_rate(led, "t.solid")["rate"] == 1.0
    candidates = {c["test_id"] for c in ft.flaky_tests(led, threshold=1.0, min_runs=5)}
    assert "t.flaky" in candidates, "a below-threshold test must be flagged as a quarantine candidate"
    assert "t.solid" not in candidates, "a 100%-passing test must NOT be flagged"


def test_record_outcome_refuses_an_unknown_outcome(tmp_path):
    """NEGATIVE CONTROL: a typo outcome is rejected fail-closed — it can never silently corrupt a rate."""
    with pytest.raises(ValueError):
        ft.record_outcome(tmp_path / "l.jsonl", test_id="t", outcome="passd", run_id="r")


def test_malformed_ledger_line_raises_not_undercounts(tmp_path):
    """NEGATIVE CONTROL: a corrupt ledger is LOUD, never silently under-counted."""
    led = tmp_path / "ledger.jsonl"
    led.write_text('{"test_id":"t","outcome":"pass","run_id":"r"}\nNOT JSON\n', encoding="utf-8")
    with pytest.raises(ValueError):
        ft.read_ledger(led)


# --------------------------------------------------------------------------------------------------
# Explicit quarantine
# --------------------------------------------------------------------------------------------------
def test_committed_quarantine_registry_is_valid():
    q = ft.load_quarantine()                               # the real docs/flake/quarantine.json
    assert isinstance(q.get("quarantined"), list)
    # every entry (there may be zero today) is fully formed — load_quarantine enforces this, so this also
    # pins that the committed file loads clean.
    for e in q["quarantined"]:
        assert set(e) >= {"test_id", "reason", "issue", "since"}


def test_quarantine_load_rejects_a_malformed_entry(tmp_path):
    """NEGATIVE CONTROL: an entry missing a reason/issue is rejected — no half-documented quarantine."""
    bad = tmp_path / "q.json"
    bad.write_text(json.dumps({"version": 1, "quarantined": [{"test_id": "t.x"}]}), encoding="utf-8")
    with pytest.raises(ValueError):
        ft.load_quarantine(bad)


def test_duplicate_quarantine_id_is_rejected(tmp_path):
    dup = tmp_path / "q.json"
    dup.write_text(json.dumps({"version": 1, "quarantined": [
        {"test_id": "t.x", "reason": "r", "issue": "#1", "since": "2026-01-01"},
        {"test_id": "t.x", "reason": "r2", "issue": "#2", "since": "2026-01-02"},
    ]}), encoding="utf-8")
    with pytest.raises(ValueError):
        ft.load_quarantine(dup)


def test_quarantine_is_explicit_not_silent():
    """THE core invariant. ``require_registered_quarantine`` admits a REGISTERED id and REFUSES an
    unregistered one — so a test cannot skip itself as flaky without a registry entry a reviewer can read.
    Positive + NEGATIVE CONTROL through the same gate."""
    q = {"version": 1, "quarantined": [
        {"test_id": "t.registered", "reason": "known upstream flake", "issue": "#999", "since": "2026-08-23"}]}
    # positive: a registered id returns its entry
    entry = ft.require_registered_quarantine("t.registered", q)
    assert entry["issue"] == "#999"
    # NEGATIVE CONTROL: an unregistered id is refused (a silent quarantine is impossible)
    with pytest.raises(ft.QuarantineError):
        ft.require_registered_quarantine("t.not_registered", q)


def test_check_quarantine_explicit_flags_only_unregistered(tmp_path):
    q = {"version": 1, "quarantined": [
        {"test_id": "t.ok", "reason": "r", "issue": "#1", "since": "2026-08-23"}]}
    violations = ft.check_quarantine_explicit(["t.ok", "t.silent1", "t.silent2"], q)
    assert violations == ["t.silent1", "t.silent2"], "unregistered quarantine skips must be flagged"
    assert ft.check_quarantine_explicit(["t.ok"], q) == [], "a registered skip is not a violation"


# --------------------------------------------------------------------------------------------------
# The ledger actually records the concurrency stress harness (grounds "historical pass rates").
# --------------------------------------------------------------------------------------------------
def test_committed_ledger_has_real_history_for_the_stress_harness():
    """'Historical pass rates' must be grounded in real runs, not an empty promise. The committed ledger
    records genuine repeats of the concurrency stress suite; assert every stress test id has scored runs."""
    ledger = _REPO / "docs" / "flake" / "ledger.jsonl"
    report = ft.historical_report(ledger)
    stress_ids = [tid for tid in report if "test_spine_concurrency_stress" in tid]
    assert stress_ids, "the committed ledger records no concurrency-stress runs — history is ungrounded"
    for tid in stress_ids:
        assert report[tid]["runs"] >= 1, f"{tid} has no scored runs in the committed ledger"
