"""
S9c — the console clean/verdict surface consults the sensor-inconclusive artifact.

``console.api.proof_list`` derives the run's ``clean`` reading. A fusion sensor that returned INCONCLUSIVE
(a declared surface it could NOT assess) writes a FRAMEWORK-OWNED ``<run_dir>/_inconclusive.json`` — the
console reads it with STDLIB ONLY (``_sensor_inconclusive_summary``; no framework->integration import) and
makes ``clean`` impossible, exposing the unassessed surface as its OWN field (distinct from a proof-degrade).

Proven here:
  * an inconclusive artifact makes ``clean`` False and names the surface, even with zero proof records;
  * it is a DISTINCT state from proof-degradation (different field);
  * an absent artifact leaves the clean reading unaffected (byte-identical);
  * a present-but-malformed artifact FAILS CLOSED (still not clean).
"""

from __future__ import annotations

import json

from framework.v2.console import actions, api


def _iso(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")


def _run(tmp_path, run_id):
    rd = actions.run_dir(run_id)
    rd.mkdir(parents=True, exist_ok=True)
    return rd


def test_inconclusive_artifact_makes_clean_impossible(tmp_path, monkeypatch) -> None:
    _iso(monkeypatch, tmp_path)
    rd = _run(tmp_path, "20260101-000000-101")
    (rd / "_inconclusive.json").write_text(json.dumps({"inconclusive": [
        {"sensor": "cloud_live", "missing_prerequisite": "no ambient aws credentials", "count": 1}]}),
        encoding="utf-8")
    d = api.proof_list("20260101-000000-101")
    assert d["total"] == 0, "no proof records, yet the run is not clean"
    assert d["coverage_incomplete"] is True and d["clean"] is False
    assert d["inconclusive_surfaces"][0]["sensor"] == "cloud_live"
    # a coverage-incomplete run is NOT a proof-degraded run — a distinct state, not conflated.
    assert d["verification_degraded"] is False


def test_clean_run_stays_clean_without_the_artifact(tmp_path, monkeypatch) -> None:
    _iso(monkeypatch, tmp_path)
    _run(tmp_path, "20260101-000000-102")     # no _inconclusive.json, no proofs → the only honest clean
    d = api.proof_list("20260101-000000-102")
    assert d["coverage_incomplete"] is False and d["clean"] is True
    assert d["inconclusive_surfaces"] == []


def test_malformed_artifact_fails_closed_not_clean(tmp_path, monkeypatch) -> None:
    _iso(monkeypatch, tmp_path)
    rd = _run(tmp_path, "20260101-000000-103")
    (rd / "_inconclusive.json").write_text("{ corrupt", encoding="utf-8")
    d = api.proof_list("20260101-000000-103")
    assert d["coverage_incomplete"] is True and d["clean"] is False
