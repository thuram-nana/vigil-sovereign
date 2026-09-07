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


def test_rescan_supersedes_by_recency_not_hash(tmp_path):
    """A re-scan (or a slug reused across repos) must SUPERSEDE the prior scan by recency — not let a stale
    or foreign snapshot shadow the latest via hash-ordered global-latest (crypto-notary MEDIUM). The monotonic
    seq makes the latest scan win, and a superseded ref is honestly no longer found."""
    from vigil_integration.live.trusted_finding import TrustedFindingError
    a = tmp_path / "a"; a.mkdir()
    (a / "x.py").write_text("import subprocess\ndef f(y):\n    return subprocess.call('ls '+y, shell=True)\n", encoding="utf-8")
    b = tmp_path / "b"; b.mkdir()
    (b / "y.py").write_text("import yaml\ndef g(s):\n    return yaml.load(s)\n", encoding="utf-8")
    base = tmp_path / "base"
    ra = codescan.run_codescan(root=str(a), slug="shared", base_dir=str(base), max_files=20)
    rb = codescan.run_codescan(root=str(b), slug="shared", base_dir=str(base), max_files=20)
    # the LATEST scan's finding reads back
    tf = finding_from_spine(base_dir=str(base), slug="shared", target_repo=str(b), finding_ref=rb["findings"][0]["ref"])
    assert tf.ref == rb["findings"][0]["ref"]
    # a ref from the SUPERSEDED prior scan is no longer selectable (no wrong-repo / stale patch)
    with pytest.raises(TrustedFindingError):
        finding_from_spine(base_dir=str(base), slug="shared", target_repo=str(a), finding_ref=ra["findings"][0]["ref"])


def test_daa_static_qualifier_survives_to_triagefinding(tmp_path):
    """Honesty (crypto-notary MEDIUM): the daa:<rule_id> static qualifier must survive the spine->patch
    boundary so a code fix is never mistaken for a live-exploit fact."""
    src = _vuln(tmp_path); base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="cb", base_dir=str(base), max_files=50)
    tf = finding_from_spine(base_dir=str(base), slug="cb", target_repo=str(src), finding_ref=res["findings"][0]["ref"])
    assert tf.source.startswith("daa:")     # not a bare/anonymous "confirmed" — labelled as a static match


def test_dirty_rule_ids_roundtrip_and_stay_argv_safe():
    """make_ref/parse_ref are exact inverses AND argv-safe over EVERY rule_id, incl. external ids with
    ~, spaces, or leading dashes (crypto-notary/red-pen 1c+2b)."""
    for rid in ["DAA-EVAL", "sem~grep~rule", "rule with space", "-Xdash", "py.lang.security.audit.eval"]:
        ref = codescan.make_ref(rid, "pkg/app.py", 7)
        assert codescan._ref_is_argv_safe(ref), rid
        rr, pp, ll = codescan.parse_ref(ref)
        assert (rr, pp, ll) == (rid, "pkg/app.py", 7), (rid, ref, rr, pp, ll)


def test_moved_vuln_is_not_reported_cleared(tmp_path):
    """A vulnerable file that MOVES (rename/refactor) must NOT report cleared — cleared requires the
    rule to fire NOWHERE, not merely at the recorded path (red-pen 1a HIGH)."""
    import os
    src = tmp_path / "src"; src.mkdir()
    (src / "app.py").write_text("def f(x):" + chr(10) + "    return eval(x)" + chr(10), encoding="utf-8")
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="mv", base_dir=str(base), max_files=20)
    ref = [f for f in res["findings"] if f["ref"].startswith("DAA-EVAL")][0]["ref"]
    assert codescan.verify_finding_cleared(root=str(src), ref=ref, max_files=20)["cleared"] is False
    os.rename(src / "app.py", src / "renamed.py")   # eval() still present, just moved
    v = codescan.verify_finding_cleared(root=str(src), ref=ref, max_files=20)
    assert v["cleared"] is False and v["moved"] is True
