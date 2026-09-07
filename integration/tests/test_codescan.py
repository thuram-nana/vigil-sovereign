"""codescan — the deterministic local-codebase scan that grounds a gated fix (end-to-end round-trip).

A DAA static-rule match over the operator's own source is a re-runnable STATIC fact. run_codescan writes each
into the engagement's signed <base>/<slug>.spine so `vigil patch --from-spine` (and finding_from_spine) can
ground a gated fix on it, and verify_finding_cleared re-runs the rule to confirm a fix removed it.

Needs the framework (DAA analyzers), so it importorskips it and runs in the OFFENSE CI leg."""
from __future__ import annotations

import pytest

pytest.importorskip("framework")   # framework.v2.analysis (DAA) — offense leg only

from vigil_integration import codescan                              # noqa: E402
from vigil_integration.live.trusted_finding import finding_from_spine  # noqa: E402


def _vuln(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "import subprocess\n"
        "def run(x):\n"
        "    return subprocess.call('ls ' + x, shell=True)\n", encoding="utf-8")
    return src


def test_ref_roundtrip():
    ref = codescan.make_ref("DAA-SHELL-TRUE", "pkg/app.py", 3)
    rule, path, line = codescan.parse_ref(ref)
    assert rule == "DAA-SHELL-TRUE" and path == "pkg/app.py" and line == 3
    # argv-safe: no separators / traversal / leading dash
    assert " " not in ref and "/" not in ref and ".." not in ref and not ref.startswith("-")


def test_scan_writes_signed_spine_and_finding_from_spine_reads_it(tmp_path):
    src = _vuln(tmp_path)
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="cb", base_dir=str(base), max_files=50)
    assert res["total"] >= 1
    from pathlib import Path
    assert Path(res["spine"]).is_file()
    # every codescan finding is a re-runnable static fact, CWE-tagged, with an argv-safe ref
    f0 = res["findings"][0]
    assert f0["grounding"] == "fact" and f0["verified_by_oracle"] is True
    assert f0["cwe"] and f0["ref"]
    # the signed spine round-trips: finding_from_spine verifies + rebuilds it into a CONFIRMED finding
    tf = finding_from_spine(base_dir=str(base), slug="cb", target_repo=str(src), finding_ref=f0["ref"])
    assert tf.confirmed is True and tf.ref == f0["ref"] and (tf.evidence_ref or "").strip()
    assert tf.target                                   # "path:line" — so the fix proposer can locate the file


def test_verify_oracle_fires_then_clears(tmp_path):
    src = _vuln(tmp_path)
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="cb", base_dir=str(base), max_files=50)
    shell = [f for f in res["findings"] if f["ref"].startswith("DAA-SHELL-TRUE")][0]
    before = codescan.verify_finding_cleared(root=str(src), ref=shell["ref"], max_files=50)
    assert before["cleared"] is False and before["still_fires_at"]
    # apply the fix (drop shell=True; pass args as a list) and re-verify -> cleared
    (src / "app.py").write_text(
        "import subprocess\n"
        "def run(x):\n"
        "    return subprocess.call(['ls', x])\n", encoding="utf-8")
    after = codescan.verify_finding_cleared(root=str(src), ref=shell["ref"], max_files=50)
    assert after["cleared"] is True and after["still_fires_at"] == []


def test_a_fact_finding_requires_signed_evidence(tmp_path):
    """Doctrine at the type level: the spine Finding used for a codescan fact cannot carry an empty evidence
    reference (a forged evidence-less fact is refused by the model validator)."""
    from vigil_integration.agent.state import Finding
    with pytest.raises(Exception):
        Finding(ref="x", status="fact", evidence_ref="   ")
