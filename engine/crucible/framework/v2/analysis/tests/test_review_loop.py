"""Tests for the autonomous source-review loop (offline, fake reviewer)."""

from __future__ import annotations

from pathlib import Path

from ...authority.killswitch import KillSwitch
from ..analyzers.builtin import PatternAnalyzer
from ..models import AnalysisTarget
from ..review_loop import CritiqueOutcome, run_source_review

_VULN = (
    "import hashlib, requests\n"
    "def a(x):\n"
    "    return eval(x)\n"                       # DAA-EVAL
    "def b(y):\n"
    "    return hashlib.md5(y).hexdigest()\n"     # DAA-WEAK-HASH
    "def c(u):\n"
    "    return requests.get(u, verify=False)\n"  # DAA-TLS-VERIFY-OFF
)


def _target(tmp_path: Path) -> AnalysisTarget:
    f = tmp_path / "vuln.py"
    f.write_text(_VULN, encoding="utf-8")
    return AnalysisTarget(root=str(f))


def _confirm_all(claim: str, evidence: str, context: str) -> CritiqueOutcome:
    return CritiqueOutcome(decision="confirm", is_dryrun=True)


def _refute_all(claim: str, evidence: str, context: str) -> CritiqueOutcome:
    return CritiqueOutcome(decision="objections", is_dryrun=True)


def test_loop_confirms_findings(tmp_path: Path) -> None:
    ks = KillSwitch("t", path=tmp_path / "halt")
    report = run_source_review(
        _target(tmp_path), reviewer=_confirm_all, killswitch=ks,
        analyzers=[PatternAnalyzer()], check_capability=False,
    )
    assert report.total_findings >= 3
    assert report.reviews_run >= 3
    assert report.confirmed_count == report.reviews_run
    assert report.halted is False


def test_budget_caps_model_calls(tmp_path: Path) -> None:
    ks = KillSwitch("t", path=tmp_path / "halt")
    report = run_source_review(
        _target(tmp_path), reviewer=_confirm_all, killswitch=ks, max_reviews=2,
        analyzers=[PatternAnalyzer()], check_capability=False,
    )
    assert report.reviews_run == 2  # budget enforced even with more findings


def test_killswitch_halts_before_any_review(tmp_path: Path) -> None:
    ks = KillSwitch("t", path=tmp_path / "halt")
    ks.trip("operator stop")
    report = run_source_review(
        _target(tmp_path), reviewer=_confirm_all, killswitch=ks,
        analyzers=[PatternAnalyzer()], check_capability=False,
    )
    assert report.reviews_run == 0
    assert report.halted is True
    assert "operator stop" in report.halt_reason


def test_refuted_findings_not_confirmed(tmp_path: Path) -> None:
    ks = KillSwitch("t", path=tmp_path / "halt")
    report = run_source_review(
        _target(tmp_path), reviewer=_refute_all, killswitch=ks,
        analyzers=[PatternAnalyzer()], check_capability=False,
    )
    assert report.reviews_run >= 3
    assert report.confirmed_count == 0
    assert report.confirmed() == []


def test_selective_confirm(tmp_path: Path) -> None:
    def confirm_eval(claim: str, evidence: str, context: str) -> CritiqueOutcome:
        return CritiqueOutcome(decision="confirm" if "eval" in claim.lower() else "objections")

    ks = KillSwitch("t", path=tmp_path / "halt")
    report = run_source_review(
        _target(tmp_path), reviewer=confirm_eval, killswitch=ks,
        analyzers=[PatternAnalyzer()], check_capability=False,
    )
    assert report.confirmed_count == 1
    assert all("eval" in r.claim.lower() for r in report.confirmed())
