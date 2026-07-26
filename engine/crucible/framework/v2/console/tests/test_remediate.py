"""P6 — the Fixes / remediation plan. It composes REAL run data (oracle-confirmed findings + their
remediation guidance) with the served gated ladder-of-record. The honest invariants:
  * ONLY oracle-confirmed FACTs are offered as fixable; unproven leads are counted, never fixable;
  * it NEVER claims live execution — `live_execution` is always False (the console runs no clone/build/PR);
  * a pending/absent run yields an honest empty state, never fabricated fixes.
"""
from __future__ import annotations

import json

from framework.v2.console import actions, api, server


def _write_report(run_id, findings, *, apply_fixes=False):
    rd = actions.run_dir(run_id)
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "meta.json").write_text(json.dumps({"status": "done", "apply_fixes": apply_fixes}), encoding="utf-8")
    (rd / "report.json").write_text(json.dumps({"findings": findings, "summary": "s"}), encoding="utf-8")
    return run_id


def _cleanup(run_id):
    import shutil
    shutil.rmtree(actions.run_dir(run_id), ignore_errors=True)


def test_route_registered():
    assert server._PREFIX_ROUTES.get("/api/remediate/") is api.remediate_plan


def test_only_confirmed_facts_are_fixable():
    rid = "p6test-facts"
    _write_report(rid, [
        {"grounding": "fact", "title": "SQLi", "bug_class": "sqli", "severity": "high",
         "location": "/x", "confirmed_by": "sqli_oracle", "remediation": "Parameterize the query."},
        {"grounding": "hypothesis", "title": "maybe xss", "bug_class": "xss", "severity": "medium",
         "remediation": "n/a"},
        {"grounding": "ungrounded", "title": "lead", "bug_class": "idor", "severity": "low"},
    ])
    try:
        r = api.remediate_plan(rid)
        assert r["fixable_count"] == 1 and r["lead_count"] == 2
        f = r["fixable"][0]
        assert f["bug_class"] == "sqli" and f["remediation"] == "Parameterize the query."
        assert r["live_execution"] is False              # never claims to run a live fix
        assert [s["stage"] for s in r["ladder"]] == ["triage", "clone", "edit", "build", "open-pr", "verify"]
    finally:
        _cleanup(rid)


def test_fixable_sorted_by_severity():
    rid = "p6test-sort"
    _write_report(rid, [
        {"grounding": "fact", "title": "low one", "bug_class": "a", "severity": "low", "remediation": "x"},
        {"grounding": "fact", "title": "crit one", "bug_class": "b", "severity": "critical", "remediation": "y"},
        {"grounding": "fact", "title": "med one", "bug_class": "c", "severity": "medium", "remediation": "z"},
    ])
    try:
        r = api.remediate_plan(rid)
        assert [f["severity"] for f in r["fixable"]] == ["critical", "medium", "low"]
    finally:
        _cleanup(rid)


def test_apply_fixes_request_surfaced_but_inert():
    rid = "p6test-apply"
    _write_report(rid, [{"grounding": "fact", "title": "t", "bug_class": "sqli",
                         "severity": "high", "remediation": "fix"}], apply_fixes=True)
    try:
        r = api.remediate_plan(rid)
        assert r["apply_fixes_requested"] is True          # the launch REQUEST is surfaced...
        assert r["live_execution"] is False                # ...but it never auto-runs a fix
    finally:
        _cleanup(rid)


def test_pending_run_is_honest_empty_not_fabricated():
    r = api.remediate_plan("p6test-does-not-exist")
    assert r.get("pending") is True
    assert r["fixable"] == [] and r["lead_count"] == 0 and r["live_execution"] is False
    assert r["ladder"], "the ladder-of-record is always served (documentation, not run data)"


def test_missing_remediation_text_is_honest_placeholder():
    rid = "p6test-norem"
    _write_report(rid, [{"grounding": "fact", "title": "t", "bug_class": "sqli", "severity": "high"}])
    try:
        r = api.remediate_plan(rid)
        assert "no per-class remediation text" in r["fixable"][0]["remediation"]
    finally:
        _cleanup(rid)
