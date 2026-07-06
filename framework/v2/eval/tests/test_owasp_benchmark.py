"""
Neutral ground-truth loading for the OWASP Benchmark (A2).

The point of OWASP Benchmark in the corpus is fairness: its labels are published,
not co-designed with CRUCIBLE. These tests pin the CSV parse, the true-only
ground-truth rule, the DAST-reachable restriction (a black-box scanner is not
scored on code-level categories it structurally cannot reach), and the
family-collapsing class-key that lets a `boolean_sqli` detection match an `sqli`
label symmetrically.
"""

from __future__ import annotations

import pytest

from framework.v2.eval.owasp_benchmark import (
    DAST_REACHABLE,
    OwaspBenchmarkError,
    load_owasp_expectedresults,
    owasp_class_key,
)

# A miniature expectedresults-1.2.csv: a header, a couple real vulns, a false case,
# and a SAST-only category (weakrand) that a DAST cannot reach.
_SAMPLE = """\
# test name, category, real vulnerability, cwe
BenchmarkTest00001,sqli,true,89
BenchmarkTest00002,sqli,false,89
BenchmarkTest00003,xss,true,79
BenchmarkTest00004,pathtraver,true,22
BenchmarkTest00005,weakrand,true,330
BenchmarkTest00006,cmdi,true,78
"""


def _write(tmp_path, text=_SAMPLE):
    p = tmp_path / "expectedresults-1.2.csv"
    p.write_text(text, encoding="utf-8")
    return p


def test_loads_only_real_vulns_in_dast_reachable_categories(tmp_path) -> None:
    findings = load_owasp_expectedresults(_write(tmp_path))
    # true + DAST-reachable: sqli(1), xss(3), pathtraver(4), cmdi(6) = 4
    # excluded: 00002 (false), 00005 (weakrand is SAST-only)
    assert len(findings) == 4
    locs = {f.location for f in findings}
    assert "/benchmark/BenchmarkTest00001" in locs
    assert "/benchmark/BenchmarkTest00005" not in locs  # weakrand dropped
    assert "/benchmark/BenchmarkTest00002" not in locs  # false case dropped


def test_families_are_neutral_tokens(tmp_path) -> None:
    findings = load_owasp_expectedresults(_write(tmp_path))
    by_loc = {f.location: f.bug_class for f in findings}
    assert by_loc["/benchmark/BenchmarkTest00001"] == "sqli"
    assert by_loc["/benchmark/BenchmarkTest00004"] == "path_traversal"
    assert by_loc["/benchmark/BenchmarkTest00006"] == "command_injection"


def test_dast_only_false_includes_sast_categories(tmp_path) -> None:
    findings = load_owasp_expectedresults(_write(tmp_path), dast_only=False)
    # now weakrand's true row is included too -> 5 (all true rows)
    assert len(findings) == 5
    assert any(f.location == "/benchmark/BenchmarkTest00005" for f in findings)


def test_unknown_category_is_surfaced_not_swallowed(tmp_path) -> None:
    bad = _SAMPLE + "BenchmarkTest00099,quantumhack,true,999\n"
    with pytest.raises(OwaspBenchmarkError, match="unknown OWASP category"):
        load_owasp_expectedresults(_write(tmp_path, bad), dast_only=False)


def test_class_key_collapses_subclasses_symmetrically() -> None:
    # CRUCIBLE subclass vs OWASP family label -> same token
    assert owasp_class_key("boolean_sqli") == owasp_class_key("sqli")
    assert owasp_class_key("error_based_sqli") == owasp_class_key("sqli")
    assert owasp_class_key("lfi") == owasp_class_key("path_traversal")
    assert owasp_class_key("rce") == owasp_class_key("command_injection")
    # genuinely different families still differ (no over-merging)
    assert owasp_class_key("xss") != owasp_class_key("sqli")


def test_dast_reachable_is_the_injection_traversal_xss_subset() -> None:
    assert DAST_REACHABLE == frozenset({"cmdi", "sqli", "xss", "pathtraver", "ldapi", "xpathi"})


def test_missing_file_raises(tmp_path) -> None:
    with pytest.raises(OwaspBenchmarkError, match="cannot read"):
        load_owasp_expectedresults(tmp_path / "nope.csv")
