"""
Ops Console — Intelligence screen data provider.

`api.intel_data` is read-only over the durable intel store and must be resilient on
a fresh tree (no intel rows) AND surface real entities / source-yield / gated
predictions once recon has been ingested. The screen never invents facts:
predictions come back explicitly gated.
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.console import api


def test_intel_data_safe_on_empty_tree() -> None:
    d = api.intel_data("no-such-slug")
    assert d["entities"] == [] and d["predictions"] == []
    assert "doctrine" in d


def test_intel_data_surfaces_ingested_entities(tmp_path, monkeypatch) -> None:
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")

    # ingest the bundled worked example under a slug
    from framework.v2.intel import cli as intel_cli
    monkeypatch.setattr("sys.stdout", __import__("io").StringIO())
    intel_cli.main(["ingest", "--seed", "company.com", "--slug", "acme",
                    "--archetype", "saas", "--max-depth", "2"])

    d = api.intel_data("acme")
    assert d["observations"] > 0
    assert any(e["owned_by"] for e in d["entities"])          # the AS64501-owned asset
    assert d["predictions"] and all(p["gated"] for p in d["predictions"])
    assert any(y["source_kind"] for y in d["source_yield"])   # yield recorded
