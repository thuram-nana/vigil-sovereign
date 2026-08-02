"""
TRUTHENOVATION T1 — the dossier's "N oracle-confirmed FACT(s)" count is a live re-execution.

``report.dossier`` must GRADE each ``reverifiable.json`` finding by RE-FIRING its retained
``oracle_context`` at dossier-build time (via ``report.grounding.grade_finding``) and count as a FACT
ONLY those that reproduce NOW. A finding recorded ``confirmed`` whose proof was tampered so it no
longer re-fires is a lead — it must be EXCLUDED from the fact set, the banner, and the summary count.
Fail-closed: an ungradeable finding is never labelled a fact.

The proof-bundle step (``vigil_integration.proof.bundle``) is stubbed: that integration package is not
on the offense-only test path, and this test is about the fact-GRADING choke point, not bundling.
"""

from __future__ import annotations

import json
import re
import zipfile

from framework.v2.report import dossier as D
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results."}
_DIVERGENT = {"status": 200, "body": "id=1 alice user\nid=2 bob admin\nid=3 carol user"}
_DISC = {"dimensions": ["status", "length", "lexical"]}


def _ctx(mutated: dict) -> dict:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli", discriminator=_DISC).model_dump(mode="json")


def _finding(param: str, ctx: dict) -> dict:
    """A serialized AuditFinding (the shape scanner/console runs write into reverifiable.json),
    with confirmed_by/confidence taken from the REAL oracle re-fire over ``ctx``."""
    c = confirm_finding(finding={"bug_class": "boolean_sqli"},
                        context=FindingContext.model_validate(ctx))
    return {
        "check_id": "s1", "bug_class": "boolean_sqli", "insertion_point": f"query:{param}",
        "param": param, "endpoint": f"http://t/?{param}=1",
        "confidence": c.confidence if c else 0.5,
        "confirmed_by": c.confirmed_by.value if c else "differential_response",
        "oracle_context": ctx,
    }


def _write_run(tmp_path, findings: list[dict]):
    rd = tmp_path / "run1"
    rd.mkdir()
    (rd / "reverifiable.json").write_text(
        json.dumps({"target": "http://t/", "active_findings": findings}), encoding="utf-8")
    return rd


def _tampered(param: str) -> dict:
    """A genuine firing finding whose retained MUTATED response was altered to match the baseline —
    the divergence the oracle keyed on is gone, so it no longer re-fires (a lead, not a fact)."""
    f = _finding(param, _ctx(_DIVERGENT))
    f["oracle_context"]["mutated"] = dict(f["oracle_context"]["baseline"])
    return f


# ---- the choke point itself: _read_reverifiable returns ONLY re-firing facts ----------------------


def test_read_reverifiable_keeps_only_refiring_facts(tmp_path) -> None:
    rd = _write_run(tmp_path, [_finding("good", _ctx(_DIVERGENT)), _tampered("evil")])
    facts = D._read_reverifiable(rd)
    assert [f["param"] for f in facts] == ["good"], "a tampered proof must not count as a fact"


def test_read_reverifiable_excludes_ungradeable_finding_fail_closed(tmp_path) -> None:
    # a finding with NO retained proof, and a garbage entry, are both excluded (never a fact).
    noproof = {"check_id": "s1", "bug_class": "idor", "insertion_point": "query:id",
               "param": "id", "confirmed_by": "achieved_state", "oracle_context": None}
    rd = _write_run(tmp_path, [_finding("good", _ctx(_DIVERGENT)), noproof, {"garbage": 1}])
    facts = D._read_reverifiable(rd)
    assert [f["param"] for f in facts] == ["good"]


# ---- the honest banner + summary: count reflects re-execution -------------------------------------


def _build(tmp_path, findings, monkeypatch):
    rd = _write_run(tmp_path, findings)
    # stub the proof bundle (vigil_integration not on the offense-only test path)
    monkeypatch.setattr(D, "_build_proof_bundle",
                        lambda *a, **k: ({}, {"ok": False, "note": "proof bundle stubbed in test"}))
    out = tmp_path / "d.zip"
    res = D.build_dossier(run_dir=str(rd), out_zip=str(out), engagement_slug="acme")
    return res, zipfile.ZipFile(out)


def test_dossier_banner_and_summary_count_reflect_reexecution(tmp_path, monkeypatch) -> None:
    res, z = _build(tmp_path, [_finding("good", _ctx(_DIVERGENT)), _tampered("evil")], monkeypatch)
    assert res["ok"] and res["facts"] == 1, "summary fact count must reflect re-execution, not the raw file"
    idx = z.read("index.html").decode("utf-8")
    m = re.search(r"(\d+) oracle-confirmed FACT", idx)
    assert m and m.group(1) == "1", "banner must state the re-executed fact count"
    # the tampered finding never appears in the fact table
    assert "query:evil" not in idx and ">evil<" not in idx


def test_dossier_with_all_proofs_tampered_reports_zero_facts(tmp_path, monkeypatch) -> None:
    res, z = _build(tmp_path, [_tampered("a"), _tampered("b")], monkeypatch)
    assert res["facts"] == 0, "no proof re-fires → zero facts, honestly"
    idx = z.read("index.html").decode("utf-8")
    assert "no oracle-confirmed fact" in idx.lower()
    # the fact banner (green) must NOT be shown when nothing re-fired
    assert "oracle-confirmed FACT(s) — each re-verifiable" not in idx
