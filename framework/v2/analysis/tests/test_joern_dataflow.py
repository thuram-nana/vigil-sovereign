"""
Real CPG dataflow proof: the JoernAnalyzer resolves an inter-procedural
taint flow (request -> _passthrough -> os.system) through the framework's
normalized interface. Skipped unless joern is provisioned
(CRUCIBLE_JOERN_HOME or joern on PATH); Joern is ~2 GB and JVM-based, so
it is not installed in CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ..analyzers.joern import JoernAnalyzer, _joern_binary
from ..models import AnalysisTarget

_BENCH = Path(__file__).resolve().parent.parent / "benchmark" / "python"

requires_joern = pytest.mark.skipif(
    _joern_binary() is None,
    reason="joern not provisioned (set CRUCIBLE_JOERN_HOME or PATH) — CPG dataflow test",
)


@requires_joern
def test_joern_finds_interprocedural_flow() -> None:
    findings = JoernAnalyzer().analyze(AnalysisTarget(root=str(_BENCH / "interprocedural.py")))
    assert findings, "expected at least one inter-procedural taint finding"
    assert any(f.cwe == "CWE-78" for f in findings)
    assert all(f.analyzer == "joern" for f in findings)


@requires_joern
def test_joern_is_available_when_provisioned() -> None:
    ok, reason = JoernAnalyzer().is_available()
    assert ok is True
    assert "joern at" in reason
