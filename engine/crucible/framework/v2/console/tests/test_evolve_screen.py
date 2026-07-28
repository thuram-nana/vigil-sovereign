"""
Ops Console — Self-evolve screen data provider (K5).

`api.evolve_data` is READ-ONLY over the disclosed leads + committed skills: it computes the horizon +
coverage gaps, the DRAFT proposals, and the `studied_enough` completion signal WITHOUT writing anything.
Resilient on a fresh tree; the doctrine string always states the bounded, never-applied scope.
"""

from __future__ import annotations

import io
import json

from framework.v2.console import api

_NVD_FEED = {"vulnerabilities": [{"cve": {
    "id": "CVE-2024-5555", "descriptions": [{"lang": "en", "value": "demo"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}, "baseSeverity": "CRITICAL"}]},
    "configurations": []}}]}


def test_evolve_data_safe_on_empty_and_missing_slug():
    d = api.evolve_data("")
    assert d["slug"] is None and d["proposals"] == [] and "FACT" in d["doctrine"]
    d2 = api.evolve_data("no-such-slug-xyz")
    assert d2["horizon_gaps"] == 0 and d2["proposals"] == [] and "studied_enough" in d2


def test_evolve_data_surfaces_gaps_and_completion(tmp_path, monkeypatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)

    feed = tmp_path / "nvd.json"
    feed.write_text(json.dumps(_NVD_FEED), encoding="utf-8")
    from framework.v2.intel import cli as intel_cli
    monkeypatch.setattr("sys.stdout", io.StringIO())
    intel_cli.main(["ingest-intel", "--file", str(feed), "--format", "nvd", "--slug", "kd"])

    d = api.evolve_data("kd")
    assert d["horizon_gaps"] >= 1                            # a horizon gap for the disclosed lead
    assert len(d["proposals"]) >= 1 and all(p["status"] == "draft" for p in d["proposals"])
    # nothing is learned yet → not done; the disclosed lead is reported unlearned
    assert d["studied_enough"]["done"] is False
    assert "CVE-2024-5555" in d["unlearned_leads"]
