"""Phase B3 — per-tool deep-research pointers (tools/research.py). Offline, advisory, boundary-clean.

Proves: for a tool with a Strix playbook, the official-docs URLs + the canonical web_search query are
extracted; an unknown tool degrades to a generated query (no doc); an unsafe name is refused without a
file read; and an absent Strix yields has_doc=False honestly (never a crash).
"""
from __future__ import annotations

import pytest

from framework.v2.tools import research as R


def test_playbook_tool_yields_official_docs_and_a_query():
    pytest.importorskip("strix")
    r = R.research_refs("nmap")
    if not r["has_doc"]:
        pytest.skip("nmap playbook not present in this Strix build")
    assert r["has_doc"] and r["docs"] and all(u.startswith("http") for u in r["docs"])
    assert any("nmap" in u for u in r["docs"])
    assert r["query"] and isinstance(r["query"], str)


def test_unknown_tool_degrades_to_a_generated_query():
    r = R.research_refs("totally-made-up-tool", purpose="does a thing")
    assert r["has_doc"] is False and not r["docs"]
    assert "totally-made-up-tool" in r["query"] and "does a thing" in r["query"]   # generated, honest


def test_unsafe_name_is_refused_without_a_file_read(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(R, "_tooling_dir", lambda: (_ for _ in ()).throw(AssertionError("should not read")))
    for bad in ("../etc/passwd", "a/b", ".hidden", "x;y"):
        r = R.research_refs(bad)
        assert r["has_doc"] is False        # guarded before any dir/file access
    assert called["n"] == 0


def test_overlong_name_never_raises(monkeypatch):
    # red-pen BLOCK-1: a character-safe name whose <name>.md would exceed NAME_MAX must NOT raise
    # ENAMETOOLONG (the docstring promises "never raises") — it degrades to has_doc=False, honestly.
    # Guarded BEFORE any filesystem touch, so it holds even if a tooling dir exists.
    for n in ("a" * 253, "a" * 300, "a" * 5000):
        r = R.research_refs(n)                       # must not raise
        assert r["has_doc"] is False and r["query"]


def test_absent_strix_is_honest_not_a_crash(monkeypatch):
    monkeypatch.setattr(R, "_tooling_dir", lambda: None)   # simulate Strix not installed
    r = R.research_refs("nmap", purpose="network scanner")
    assert r["has_doc"] is False and r["query"] and "nmap" in r["query"]   # generated query, no crash


def test_research_endpoint_is_safe_wrapped():
    from framework.v2.console import api
    d = api.tool_research_data("nmap")
    assert d["name"] == "nmap" and "query" in d and "docs" in d          # never raises; always a dict
    bad = api.tool_research_data("../secrets")
    assert bad["has_doc"] is False                                        # unsafe name → honest empty
