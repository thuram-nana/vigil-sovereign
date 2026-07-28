"""
K5 — the bounded self-evolve loop (`knowledge_engine.evolve` + the `knowledge evolve` CLI).

Doctrine under test:
  * BOUNDED + DISCLOSURE-ONLY — a horizon over disclosed leads + coverage-gap synthesis (a disclosed bug
    class the oracle substrate cannot adjudicate), never a forecast of undiscovered CVEs;
  * NEVER merged/applied — proposals are DRAFT, described-only (empty patch); `evaluate_merge` returns
    approved=False for a bare draft (authorize≠apply); K5 never calls it;
  * `studied_enough` flips true ONLY when every disclosed lead is deep-learned AND every gap is drafted AND
    the OutcomeLedger has no open predictions;
  * DETERMINISTIC — injected `now`/`seq`; a prediction's `oracle_confirmed=False` (the outcome is recorded
    later by a real engagement, never fabricated); kill-switch gated at the CLI.
"""

from __future__ import annotations

import argparse
import io
import json
from datetime import datetime, timezone

from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.knowledge_engine.deeplearn import deep_learn
from framework.v2.knowledge_engine.evolve import plan_evolution, record_predictions

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_LEADS = [
    {"id": "CVE-2024-0001", "severity": "CRITICAL", "cwes": ["CWE-89"]},   # sqli → oracle-known
    {"id": "CVE-2024-0002", "bug_class": "csrf"},                          # csrf → NOT oracle-known → coverage gap
    {"id": "CVE-2024-0003", "bug_class": "sqli"},                          # known → no coverage gap
]


def test_plan_has_horizon_and_only_uncovered_coverage_gaps(tmp_path):
    plan = plan_evolution(_LEADS, skills_dir=tmp_path, now=NOW)
    assert len(plan.horizon_gaps) == 3                       # one horizon gap per disclosed lead
    assert [g.bug_class for g in plan.coverage_gaps] == ["csrf"]   # ONLY the oracle-uncovered class
    assert len(plan.proposals) == 4                          # 3 horizon + 1 coverage, one draft each


def test_proposals_are_draft_and_described_only(tmp_path):
    # K5 DRAFTS proposals and never applies/merges — every proposal is DRAFT with an empty (described-only)
    # patch, so it carries no self-applying change. `merge_gate.evaluate_merge` (authorize≠apply) is a
    # SEPARATE human gate that K5 never calls (its own suite proves a bare draft returns approved=False).
    plan = plan_evolution(_LEADS, skills_dir=tmp_path, now=NOW)
    assert plan.proposals
    for p in plan.proposals:
        assert p.status.value == "draft" and p.change.patch == ""
        assert p.status.value not in ("approved", "merged")


def test_studied_enough_requires_learned_and_no_open_predictions(tmp_path):
    plan = plan_evolution(_LEADS, skills_dir=tmp_path, now=NOW)
    assert plan.studied_enough["done"] is False and len(plan.unlearned) == 3    # nothing learned yet
    for lead in _LEADS:
        deep_learn(lead, skills_dir=tmp_path, now=NOW)       # write find/detect/prevent skills
    plan2 = plan_evolution(_LEADS, skills_dir=tmp_path, now=NOW)
    assert plan2.unlearned == [] and plan2.studied_enough["done"] is True

    led = OutcomeLedger()
    n = record_predictions(plan2, led, base_seq=0)
    assert n == len(plan2.proposals) and record_predictions(plan2, led, base_seq=99) == 0   # idempotent
    plan3 = plan_evolution(_LEADS, skills_dir=tmp_path, now=NOW, ledger=led)
    assert plan3.studied_enough["done"] is False            # open predictions block completion
    assert plan3.studied_enough["remaining"]["open_predictions"] == n


def test_predictions_are_unconfirmed_and_scored_by_priority(tmp_path):
    plan = plan_evolution(_LEADS, skills_dir=tmp_path, now=NOW)
    led = OutcomeLedger()
    record_predictions(plan, led, base_seq=0)
    for pr in led.predictions():
        assert pr.oracle_confirmed is False and 0.0 <= pr.raw_score <= 1.0   # a forecast, never a fact


def test_plan_is_deterministic(tmp_path):
    a = plan_evolution(_LEADS, skills_dir=tmp_path / "a", now=NOW)
    b = plan_evolution(_LEADS, skills_dir=tmp_path / "b", now=NOW)
    assert [g.id for g in a.horizon_gaps] == [g.id for g in b.horizon_gaps]
    assert [p.id for p in a.proposals] == [p.id for p in b.proposals]


# ---- CLI: kill-switch gated end-to-end -------------------------------------

def test_cli_evolve_end_to_end_and_killswitch(tmp_path, monkeypatch):
    from framework.v2.common import paths
    from framework.v2.intel import cli as intel_cli
    from framework.v2.knowledge_engine import cli as kcli
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    feed = tmp_path / "nvd.json"
    feed.write_text(json.dumps({"vulnerabilities": [{"cve": {
        "id": "CVE-2024-7777", "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.0}, "baseSeverity": "CRITICAL"}]},
        "configurations": []}}]}), encoding="utf-8")
    intel_cli.main(["ingest-intel", "--file", str(feed), "--format", "nvd", "--slug", "kd"])

    cap = io.StringIO()
    monkeypatch.setattr("sys.stdout", cap)
    rc = kcli._evolve(argparse.Namespace(slug="kd", skills_dir=str(tmp_path / "s"), ledger="", record=True))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    assert rc == 0
    out = json.loads(cap.getvalue())
    assert out["horizon_gaps"] >= 1 and out["predictions_recorded"] >= 1

    # kill-switch tripped → refuse before doing anything
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    (tmp_path / "kd.halt").write_text("{}", encoding="utf-8")
    rc2 = kcli._evolve(argparse.Namespace(slug="kd", skills_dir=str(tmp_path / "s2"), ledger="", record=False))
    assert rc2 == 3


def test_cli_record_reflects_open_predictions_in_studied_enough(tmp_path, monkeypatch):
    # N2 regression: a --record run over an ALREADY-learned scope must not report done=True alongside the
    # predictions it just seeded — studied_enough is re-planned AFTER recording, so open predictions win.
    from framework.v2.common import paths
    from framework.v2.intel import cli as intel_cli
    from framework.v2.knowledge_engine import cli as kcli
    from framework.v2.knowledge_engine.deeplearn import deep_learn
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    feed = tmp_path / "nvd.json"
    feed.write_text(json.dumps({"vulnerabilities": [{"cve": {
        "id": "CVE-2024-8888", "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.0}, "baseSeverity": "HIGH"}]},
        "configurations": []}}]}), encoding="utf-8")
    intel_cli.main(["ingest-intel", "--file", str(feed), "--format", "nvd", "--slug", "kd"])
    sk = tmp_path / "sk"
    deep_learn({"id": "CVE-2024-8888"}, skills_dir=sk, now=NOW)   # the lead is now fully learned

    cap = io.StringIO()
    monkeypatch.setattr("sys.stdout", cap)
    rc = kcli._evolve(argparse.Namespace(slug="kd", skills_dir=str(sk), ledger="", record=True))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    out = json.loads(cap.getvalue())
    assert rc == 0 and out["predictions_recorded"] >= 1
    assert out["studied_enough"]["done"] is False            # the just-seeded predictions keep it open
    assert out["studied_enough"]["remaining"]["open_predictions"] == out["predictions_recorded"]
