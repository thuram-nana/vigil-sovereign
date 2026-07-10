"""
CLI: the `report` subcommand is additive and default-safe. It renders from a JSON
findings document (hermetic) and from the blackboard, writes the three files, and
carries the same prove-don't-guess grading (a lead never becomes a fact in the output).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2 import __main__ as v2main
from framework.v2.agents import blackboard as bb_mod
from framework.v2.agents.blackboard import open_blackboard
from framework.v2.report import cli as report_cli

from .conftest import make_demoted, make_fact, make_lead


def _write_findings(tmp_path: Path) -> Path:
    doc = {"findings": [make_fact().model_dump(mode="json"),
                        make_demoted().model_dump(mode="json"),
                        make_lead().model_dump(mode="json")]}
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_from_json_writes_three_reports(tmp_path: Path) -> None:
    src = _write_findings(tmp_path)
    out = tmp_path / "reports"
    rc = report_cli.main(["--from-json", str(src), "--out", str(out), "--target", "acme"])
    assert rc == 0
    for name in ("executive.md", "technical.md", "remediation-roadmap.md"):
        assert (out / name).is_file()
    tech = (out / "technical.md").read_text(encoding="utf-8")
    # prove-don't-guess survives the CLI: fact proven, lead labelled.
    assert "PROVEN FACT" in tech and "sha256:" in tech
    assert "LEAD (unconfirmed)" in tech
    # the demoted finding is a lead in the roadmap, never in the prioritised order.
    road = (out / "remediation-roadmap.md").read_text(encoding="utf-8")
    order = road.partition("## Unconfirmed leads")[0]
    assert "002-stale" not in order


def test_stdout_mode_is_hermetic(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = _write_findings(tmp_path)
    rc = report_cli.main(["--from-json", str(src), "--stdout", "--target", "acme"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "executive" in out and "technical" in out and "remediation-roadmap" in out


def test_only_renders_single_document(tmp_path: Path) -> None:
    src = _write_findings(tmp_path)
    out = tmp_path / "one"
    rc = report_cli.main(["--from-json", str(src), "--out", str(out),
                          "--only", "executive", "--target", "acme"])
    assert rc == 0
    assert (out / "executive.md").is_file()
    assert not (out / "technical.md").exists()


def test_missing_source_errors_cleanly() -> None:
    assert report_cli.main([]) == 2                     # no slug, no json
    assert report_cli.main(["--from-json", "/no/such/file.json"]) == 2


def test_wellformed_json_with_invalid_finding_errors_cleanly_no_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # REGRESSION (Wave-6 review, LOW): a JSON doc that PARSES but carries a finding missing required
    # fields must exit 2 with a clean message — not escape as an unhandled pydantic ValidationError.
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"findings": [{"title": "x"}]}), encoding="utf-8")
    rc = report_cli.main(["--from-json", str(p), "--out", str(tmp_path / "r"), "--target", "acme"])
    assert rc == 2
    assert "error: invalid finding data" in capsys.readouterr().out


def test_dispatch_is_wired_into_main(tmp_path: Path) -> None:
    # additive wiring: `python3 -m framework.v2 report ...` resolves and runs.
    assert "report" in v2main._DISPATCH
    src = _write_findings(tmp_path)
    assert v2main.main(["report", "--from-json", str(src), "--stdout", "--target", "acme"]) == 0


def test_blackboard_source_grades_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # point the default blackboard at a throwaway db so this stays hermetic.
    slug = "report-cli-bb"
    db = tmp_path / "bb.sqlite"

    def _fake_open(**_kw):
        return open_blackboard(db_path=db)

    monkeypatch.setattr(bb_mod, "open_blackboard", _fake_open)

    b = open_blackboard(db_path=db)
    b.engagement_id(slug)
    b.post(engagement=slug, kind="finding", agent_name="exploit",
           payload=make_fact().model_dump())
    b.post(engagement=slug, kind="finding", agent_name="exploit",
           payload=make_lead().model_dump())
    b.close()

    out = tmp_path / "reports"
    rc = report_cli.main([slug, "--out", str(out)])
    assert rc == 0
    tech = (out / "technical.md").read_text(encoding="utf-8")
    assert "PROVEN FACT" in tech                # the confirmed finding graded a fact
    assert "Possible IDOR" in tech              # the lead is present, labelled
    assert "Blackboard event id:" in tech       # blackboard provenance flows through
