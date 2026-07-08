"""
Operator-experience data providers (P3): the Evidence Browser re-verifies certificates
offline, and the world-model provider now carries the fields the Attack-Path Explorer
and Timeline-replay screens need (path value, impact-ranked chokes, per-node first_seen).
All read-only and resilient on a fresh tree.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.v2.console import actions, api
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding


def _reverifiable_report() -> dict:
    ctx = FindingContext.from_http_responses(
        {"status": 200, "body": "No results."},
        {"status": 200, "body": "id=1 alice user\nid=2 bob admin"},
        bug_class="boolean_sqli", discriminator={"dimensions": ["status", "length", "lexical"]})
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    return {"target": "https://app/", "active_findings": [{
        "check_id": "boolean-sqli", "bug_class": "boolean_sqli", "insertion_point": "query", "param": "q",
        "confirmed_by": c.confirmed_by.value, "confidence": c.confidence,
        "oracle_context": ctx.model_dump(mode="json")}]}


def _stage_run(tmp_path, monkeypatch) -> str:
    run = tmp_path / "run-1"
    run.mkdir(parents=True)
    (run / "reverifiable.json").write_text(json.dumps(_reverifiable_report()), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda rid: tmp_path / rid)
    return "run-1"


# ---- Evidence Browser -------------------------------------------------------


def test_evidence_is_resilient_on_missing_run() -> None:
    d = api.evidence("no-such-run")
    assert d["findings"] == [] and (d.get("pending") or "error" in d)


def test_evidence_reverifies_certificates(tmp_path, monkeypatch) -> None:
    api.evidence(_stage_run(tmp_path, monkeypatch))  # warm
    d = api.evidence("run-1")
    assert d["total"] == 1 and d["reproduced"] == 1
    f = d["findings"][0]
    assert f["has_certificate"] and f["reproduced"] and f["sound"] and f["bug_class"] == "boolean_sqli"


def test_evidence_flags_a_tampered_certificate(tmp_path, monkeypatch) -> None:
    run = tmp_path / "run-t"
    run.mkdir(parents=True)
    rep = _reverifiable_report()
    rep["active_findings"][0]["oracle_context"]["baseline"]["body"] = "TAMPERED"  # break reproduction
    (run / "reverifiable.json").write_text(json.dumps(rep), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda rid: tmp_path / rid)
    d = api.evidence("run-t")
    assert d["findings"][0]["has_certificate"] and not d["findings"][0]["sound"]


# ---- world-model provider carries the explorer/timeline fields --------------


def test_worldmodel_carries_timeline_and_impact_fields(tmp_path, monkeypatch) -> None:
    d = api.worldmodel(_stage_run(tmp_path, monkeypatch))
    assert d["nodes"], "expected a reconstructed graph"
    n = d["nodes"][0]
    assert "first_seen" in n and "last_seen" in n          # Timeline replay
    for p in d.get("paths", []):
        assert "value" in p                                 # mission-ranked explorer
    for c in d.get("chokes", []):
        assert "impact_disconnected" in c                   # impact-ranked remediation
