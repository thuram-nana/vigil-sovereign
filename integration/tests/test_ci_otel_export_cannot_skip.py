"""Guard: the required P5 job cannot pass with the LIVE OTLP export proof skipped.

``test_live_otel_export.py`` importorskips the OpenTelemetry SDK. It skipped on every CI run until P5 began
installing the opt-in hash lock ``infra/supply-chain/otel.lock.txt``. ``.github/scripts/assert_otel_export_ran.py``
now reads P5's JUnit report and fails the job unless the named export proofs executed. This keeps that enforcer
honest, OFFLINE:

  * every proof it requires still EXISTS as a test function (a rename would otherwise make it demand a test that
    can never run — or, worse, be edited to demand nothing);
  * it is NOT VACUOUS: a synthetic report with a skipped / failed / errored / missing proof is rejected, and a
    clean one passes;
  * P5 feeds it the SAME JUnit file the sovereign pytest leg writes.

Framework-free (file reads + stdlib XML), so it runs in the sovereign leg.
"""
from __future__ import annotations

import ast
import importlib.util
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_ENFORCER = _REPO / ".github" / "scripts" / "assert_otel_export_ran.py"
_PROOF_FILE = _REPO / "integration" / "tests" / "test_live_otel_export.py"
_CI = _REPO / ".github" / "workflows" / "ci.yml"


def _enforcer():
    spec = importlib.util.spec_from_file_location("vigil_assert_otel_export_ran", _ENFORCER)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _report(cases: list[tuple[str, str, str | None]]) -> list[ET.Element]:
    """Synthetic JUnit testcases: (name, classname, child-tag or None for a clean pass)."""
    root = ET.Element("testsuite")
    for name, classname, child in cases:
        tc = ET.SubElement(root, "testcase", name=name, classname=classname)
        if child:
            ET.SubElement(tc, child, message="synthetic")
    return list(root.iter("testcase"))


def _clean(mod) -> list[tuple[str, str, str | None]]:
    return [(name, f"integration.tests.{cls}", None) for name, cls in mod.REQUIRED]


def test_enforcer_requires_at_least_the_real_exporter_proof():
    mod = _enforcer()
    names = {n for n, _ in mod.REQUIRED}
    assert "test_a_real_span_arrives_at_a_loopback_endpoint_through_the_real_exporter" in names
    assert len(mod.REQUIRED) >= 4


def test_every_required_proof_still_exists_in_the_proof_file():
    defined = {n.name for n in ast.walk(ast.parse(_PROOF_FILE.read_text(encoding="utf-8")))
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    missing = [n for n, _ in _enforcer().REQUIRED if n not in defined]
    assert not missing, f"assert_otel_export_ran.py requires proofs that no longer exist: {missing}"


def test_a_clean_report_passes():
    mod = _enforcer()
    assert mod.evaluate(_report(_clean(mod))) == []


@pytest.mark.parametrize("child", ["skipped", "failure", "error"])
def test_a_non_executed_proof_is_rejected(child):
    mod = _enforcer()
    cases = _clean(mod)
    name, cls, _ = cases[0]
    cases[0] = (name, cls, child)
    problems = mod.evaluate(_report(cases))
    assert problems and name in problems[0] and child in problems[0]


def test_a_missing_proof_is_rejected():
    mod = _enforcer()
    problems = mod.evaluate(_report(_clean(mod)[1:]))
    assert problems and "NOT collected" in problems[0]


def test_a_same_named_test_in_another_file_does_not_satisfy_it():
    mod = _enforcer()
    cases = [(n, "integration.tests.test_something_else", None) for n, _ in mod.REQUIRED]
    assert len(mod.evaluate(_report(cases))) == len(mod.REQUIRED)


def test_parametrized_ids_match_and_an_unreadable_report_exits(tmp_path):
    mod = _enforcer()
    cases = [(f"{n}[x]", f"integration.tests.{c}", None) for n, c in mod.REQUIRED]
    assert mod.evaluate(_report(cases)) == []
    bad = tmp_path / "junit.xml"
    bad.write_text("<not-xml")
    with pytest.raises(SystemExit):
        mod.main(["x", str(bad)])


def test_main_exit_codes(tmp_path):
    mod = _enforcer()
    ok, skipped = tmp_path / "ok.xml", tmp_path / "skip.xml"
    for path, cases in ((ok, _clean(mod)), (skipped, [(n, c, "skipped") for n, c, _ in _clean(mod)])):
        root = ET.Element("testsuite")
        for tc in _report(cases):
            root.append(tc)
        ET.ElementTree(root).write(path)
    assert mod.main(["x", str(ok)]) == 0
    assert mod.main(["x", str(skipped)]) == 1


def test_p5_feeds_the_enforcer_the_report_the_pytest_leg_writes():
    ci = _CI.read_text(encoding="utf-8")
    junit = '--junit-xml="${RUNNER_TEMP:-/tmp}/sovereign-junit.xml"'
    assert junit in ci, "the P5 sovereign pytest leg no longer writes the JUnit report the enforcers read"
    live = [ln for ln in ci.splitlines() if not ln.lstrip().startswith("#")]
    runs = [ln for ln in live if "assert_otel_export_ran.py" in ln]
    assert runs, "P5 no longer runs assert_otel_export_ran.py — the export proof could skip green"
    assert all('"${RUNNER_TEMP:-/tmp}/sovereign-junit.xml"' in ln for ln in runs), runs
