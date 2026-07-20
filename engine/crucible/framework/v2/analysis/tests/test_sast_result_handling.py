"""
Mock-coverage for the external SAST adapters' RESULT-handling (Semgrep + Joern).

Both adapters' end-to-end tests (``test_semgrep_taint.py`` / ``test_joern_dataflow.py``)
are skip-gated on a real ``semgrep`` / ``joern`` binary, so their parse->normalize
logic — Semgrep's JSON ``_normalize`` (severity map, path relativization, CWE
extraction, deterministic sort) and Joern's JSON-lines ``_parse`` (sink->bug-class
classification) — is NOT verified by a normal run. Here we feed CANNED tool output
to those code paths two ways: (1) directly to the normalize/parse methods, and
(2) through the real ``analyze()`` with a MOCKED ``subprocess`` that plays the tool
(Semgrep prints JSON to stdout; the Joern mock writes the JSON-lines file the real
tool would). The live binaries stay gated; only their output-handling gets tested.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from framework.v2.analysis.analyzers import external as external_mod
from framework.v2.analysis.analyzers import joern as joern_mod
from framework.v2.analysis.analyzers.external import SemgrepAnalyzer
from framework.v2.analysis.analyzers.joern import JoernAnalyzer, _classify
from framework.v2.analysis.models import AnalysisTarget
from framework.v2.common.errors import BackendError, BackendUnavailable


class _FakeProc:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _semgrep_json(root: Path) -> str:
    """A recorded `semgrep --json` document: an ERROR os.system flow (CWE list) and a
    WARNING SSTI flow (CWE string), each with a real absolute path under `root`."""
    return json.dumps({
        "results": [
            {
                "check_id": "python.lang.security.dangerous-os-system",
                "path": str(root / "app.py"),
                "start": {"line": 42},
                "end": {"line": 42},
                "extra": {
                    "severity": "ERROR",
                    "message": "Untrusted input reaches os.system",
                    "lines": "os.system(user_input)",
                    "metadata": {"cwe": ["CWE-78: OS Command Injection", "CWE-77"]},
                },
            },
            {
                "check_id": "python.flask.ssti.render-template-string",
                "path": str(root / "views.py"),
                "start": {"line": 10},
                "extra": {
                    "severity": "WARNING",
                    "message": "Server-side template injection",
                    "lines": "render_template_string(tpl)",
                    "metadata": {"cwe": "CWE-1336"},
                },
            },
        ],
        "errors": [],
    })


# ---------------------------------------------------------------------------
# Semgrep — _normalize (canned JSON) + analyze() over a mocked subprocess
# ---------------------------------------------------------------------------


def test_semgrep_normalize_maps_severity_relativizes_paths_and_extracts_cwe(tmp_path: Path) -> None:
    data = json.loads(_semgrep_json(tmp_path))
    findings = SemgrepAnalyzer()._normalize(data, tmp_path)
    assert len(findings) == 2
    by_path = {f.path: f for f in findings}
    # ERROR -> high, WARNING -> medium; paths relativized to root; first CWE of a list / the string.
    assert by_path["app.py"].severity == "high" and by_path["app.py"].cwe.startswith("CWE-78")
    assert by_path["app.py"].line == 42 and by_path["app.py"].rule_id.endswith("dangerous-os-system")
    assert by_path["views.py"].severity == "medium" and by_path["views.py"].cwe == "CWE-1336"
    # deterministic sort by (path, line, rule_id)
    assert [f.path for f in findings] == sorted(f.path for f in findings)
    assert all(f.analyzer == "semgrep" for f in findings)


def test_semgrep_normalize_is_total_on_garbage() -> None:
    n = SemgrepAnalyzer()._normalize
    assert n({"results": "not-a-list"}, Path("/x")) == []
    assert n(["not", "a", "dict"], Path("/x")) == []
    assert n({"results": [42, "junk", {"path": "z.py", "start": {}, "extra": {}}]}, Path("/x"))[0].path == "z.py"


def _mock_semgrep(monkeypatch: pytest.MonkeyPatch, proc: _FakeProc) -> None:
    monkeypatch.setattr(external_mod.shutil, "which", lambda _b: "/usr/bin/semgrep")
    monkeypatch.setattr(external_mod.subprocess, "run", lambda cmd, **_kw: proc)


def test_semgrep_analyze_over_mocked_subprocess_yields_normalized_findings(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
    _mock_semgrep(monkeypatch, _FakeProc(stdout=_semgrep_json(tmp_path)))
    findings = SemgrepAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))
    assert {f.cwe.split(":")[0] for f in findings} == {"CWE-78", "CWE-1336"}


def test_semgrep_analyze_empty_stdout_zero_exit_is_no_findings(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _mock_semgrep(monkeypatch, _FakeProc(stdout="", returncode=0))
    assert SemgrepAnalyzer().analyze(AnalysisTarget(root=str(tmp_path))) == []


def test_semgrep_analyze_empty_stdout_nonzero_exit_is_a_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _mock_semgrep(monkeypatch, _FakeProc(stdout="", stderr="boom", returncode=2))
    with pytest.raises(BackendError):
        SemgrepAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_semgrep_analyze_invalid_json_is_a_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _mock_semgrep(monkeypatch, _FakeProc(stdout="not json at all", returncode=0))
    with pytest.raises(BackendError):
        SemgrepAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_semgrep_analyze_absent_binary_raises_unavailable(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(external_mod.shutil, "which", lambda _b: None)
    with pytest.raises(BackendUnavailable):
        SemgrepAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


# ---------------------------------------------------------------------------
# Joern — _classify + _parse (canned JSON-lines) + analyze() over a mocked subprocess
# ---------------------------------------------------------------------------


def test_joern_classify_maps_sinks_to_bug_class_and_cwe() -> None:
    assert _classify("os.system(x)") == ("OS Command Injection", "CWE-78")
    assert _classify("cur.execute(q)") == ("SQL Injection", "CWE-89")
    assert _classify("requests.get(u)") == ("SSRF", "CWE-918")
    assert _classify("render_template_string(t)") == ("Server-Side Template Injection", "CWE-1336")
    assert _classify("something.unknown(x)") == ("Tainted Dataflow", "")


def _joern_jsonl(root: Path) -> str:
    return "\n".join([
        json.dumps({"file": str(root / "svc.py"), "line": 7, "sink": "os.system(cmd)"}),
        "",  # blank line skipped
        json.dumps({"file": str(root / "db.py"), "line": 3, "sink": "cur.execute(sql)"}),
        "{ not valid json",  # malformed line skipped, never raised
    ])


def test_joern_parse_classifies_and_normalizes_jsonl(tmp_path: Path) -> None:
    out = tmp_path / "flows.jsonl"
    out.write_text(_joern_jsonl(tmp_path), encoding="utf-8")
    findings = JoernAnalyzer()._parse(out, tmp_path)
    assert len(findings) == 2                      # the blank + malformed lines dropped
    by_path = {f.path: f for f in findings}
    assert by_path["svc.py"].cwe == "CWE-78" and "OS Command Injection" in by_path["svc.py"].message
    assert by_path["db.py"].cwe == "CWE-89" and by_path["db.py"].line == 3
    assert all(f.analyzer == "joern" and f.rule_id == "joern-taint" for f in findings)
    assert [f.path for f in findings] == sorted(f.path for f in findings)   # deterministic sort


def test_joern_analyze_over_mocked_subprocess_writes_and_parses_flows(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "svc.py").write_text("import os\n", encoding="utf-8")
    monkeypatch.setattr(joern_mod, "_joern_binary", lambda: "/usr/bin/joern")

    def _run(argv, **kwargs):
        # analyze() writes taint.sc into a temp dir and expects joern-flows.jsonl beside it;
        # play the tool by writing that sibling file with canned flows on the analyzed root.
        script = Path(argv[argv.index("--script") + 1])
        (script.parent / "joern-flows.jsonl").write_text(_joern_jsonl(src), encoding="utf-8")
        return _FakeProc(returncode=0)

    monkeypatch.setattr(joern_mod.subprocess, "run", _run)
    findings = JoernAnalyzer().analyze(AnalysisTarget(root=str(src)))
    assert {f.cwe for f in findings} == {"CWE-78", "CWE-89"}
    assert all(f.severity == "high" for f in findings)


def test_joern_analyze_no_output_file_is_a_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    monkeypatch.setattr(joern_mod, "_joern_binary", lambda: "/usr/bin/joern")
    monkeypatch.setattr(joern_mod.subprocess, "run", lambda argv, **_kw: _FakeProc(returncode=1))
    with pytest.raises(BackendError):
        JoernAnalyzer().analyze(AnalysisTarget(root=str(src)))


def test_joern_analyze_absent_binary_raises_unavailable(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(joern_mod, "_joern_binary", lambda: None)
    with pytest.raises(BackendUnavailable):
        JoernAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))
