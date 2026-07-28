"""
Ops Console — Knowledge-Engine / vuln-intel screen data provider (K1).

``api.vulnintel_data`` is read-only over the durable intel store: resilient on a fresh tree (no rows),
and it surfaces VULNERABILITY LEADS (never facts) once a feed is ingested. The doctrine string is always
present — the screen states plainly that every entry is a lead, not a confirmed fact.
"""

from __future__ import annotations

import io
import json

from framework.v2.console import api

# an NVD-shaped feed with a CISA-KEV marker (cisaExploitAdd → exploit_known=True) + CVSS severity.
_NVD_FEED = {"vulnerabilities": [{"cve": {
    "id": "CVE-2024-5555", "cisaExploitAdd": "2024-03-01",
    "descriptions": [{"lang": "en", "value": "demo advisory"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}, "baseSeverity": "CRITICAL"}]},
    "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}]}]}],
}}]}


def test_vulnintel_data_safe_on_empty_tree():
    d = api.vulnintel_data("no-such-slug-xyz")
    assert d["vulnerabilities"] == [] and d["affects"] == []
    assert {s["name"] for s in d["sources"]} == {"nvd", "osv", "cisa-kev"}
    assert d["catalog"] and "LEAD" in d["doctrine"]            # catalog present; doctrine states lead-not-fact


def test_vulnintel_data_empty_slug_still_has_catalog_and_doctrine():
    d = api.vulnintel_data("")
    assert d["slug"] is None and d["vulnerabilities"] == []
    assert d["catalog"] and "LEAD" in d["doctrine"]
    assert {s["name"] for s in d["sources"]} == {"nvd", "osv", "cisa-kev"}


def test_vulnintel_data_surfaces_ingested_leads(tmp_path, monkeypatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")

    feed = tmp_path / "nvd.json"
    feed.write_text(json.dumps(_NVD_FEED), encoding="utf-8")
    from framework.v2.intel import cli as intel_cli
    monkeypatch.setattr("sys.stdout", io.StringIO())
    intel_cli.main(["ingest-intel", "--file", str(feed), "--format", "nvd", "--slug", "kdemo"])

    d = api.vulnintel_data("kdemo")
    hit = [v for v in d["vulnerabilities"] if v["id"].upper() == "CVE-2024-5555"]
    assert hit, d["vulnerabilities"]
    assert hit[0]["exploit_known"] is True                    # cisaExploitAdd → known-exploited LEAD
    assert d["counts"]["exploit_known"] >= 1
    assert d["catalog"] and "LEAD" in d["doctrine"]
