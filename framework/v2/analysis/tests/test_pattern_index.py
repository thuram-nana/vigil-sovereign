"""Tests for the built-in pattern analyzer and the symbol index."""

from __future__ import annotations

from pathlib import Path

from ..analyzers.builtin import PatternAnalyzer
from ..index import build_symbol_index
from ..models import AnalysisTarget


def _rule_ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


def test_pattern_analyzer_finds_known_sinks(planted_tree: Path) -> None:
    findings = PatternAnalyzer().analyze(AnalysisTarget(root=str(planted_tree)))
    ids = _rule_ids(findings)
    assert "DAA-EVAL" in ids
    assert "DAA-SHELL-TRUE" in ids
    assert "DAA-YAML-LOAD" in ids
    assert "DAA-WEAK-HASH" in ids
    assert "DAA-SECRET" in ids


def test_pattern_analyzer_is_always_available() -> None:
    available, _ = PatternAnalyzer().is_available()
    assert available is True


def test_clean_file_has_no_findings(tmp_path: Path) -> None:
    f = tmp_path / "clean.py"
    f.write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
    findings = PatternAnalyzer().analyze(AnalysisTarget(root=str(f)))
    assert findings == []


def test_extension_scoping_js_innerhtml(planted_tree: Path) -> None:
    findings = PatternAnalyzer().analyze(AnalysisTarget(root=str(planted_tree)))
    innerhtml = [f for f in findings if f.rule_id == "DAA-MD-INNERHTML"]
    assert innerhtml and innerhtml[0].path == "app.js"


def test_findings_are_sorted_and_have_locations(planted_tree: Path) -> None:
    findings = PatternAnalyzer().analyze(AnalysisTarget(root=str(planted_tree)))
    assert findings == sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))
    for f in findings:
        assert f.line >= 1
        assert f.snippet


# ---- symbol index ---------------------------------------------------------


def test_symbol_index_captures_structure(planted_tree: Path) -> None:
    idx = build_symbol_index(AnalysisTarget(root=str(planted_tree)))
    summary = idx.summary()
    assert summary.get("function", 0) >= 2   # run, add
    assert summary.get("import", 0) >= 1
    assert summary.get("call", 0) >= 1


def test_find_callsites(planted_tree: Path) -> None:
    idx = build_symbol_index(AnalysisTarget(root=str(planted_tree)))
    eval_calls = idx.find_callsites("eval")
    assert eval_calls and eval_calls[0].path == "vuln.py"


def test_find_function(planted_tree: Path) -> None:
    idx = build_symbol_index(AnalysisTarget(root=str(planted_tree)))
    assert idx.find_function("add")


def test_index_handles_syntax_error(tmp_path: Path) -> None:
    bad = tmp_path / "broken.py"
    bad.write_text("def f(:\n  pass\n", encoding="utf-8")
    idx = build_symbol_index(AnalysisTarget(root=str(tmp_path)))
    assert idx.parse_errors  # recorded, not raised
    assert idx.files_indexed == 0
