"""Wave 6 — codebase Q&A is grounded by a pre-built graphify architecture map when the attached codebase
root contains one. The read is confined to the SERVER-computed scan_root (never a model/manifest path),
and a symlinked graphify-out escaping the root is refused.
"""
from __future__ import annotations

import os

from framework.v2.console import chat


def test_graphify_map_reads_a_report_inside_the_root(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "graphify-out").mkdir(parents=True)
    (root / "graphify-out" / "GRAPH_REPORT.md").write_text(
        "# God nodes\n- foo (fan-in 120)\n- bar (fan-in 90)\n\n## Communities\n- auth\n- storage\n",
        encoding="utf-8")
    monkeypatch.setattr(chat, "_scan_offer", lambda cid: {"target": str(root)})
    out = chat._graphify_map("c1")
    assert "God nodes" in out and "foo" in out and "Communities" in out


def test_graphify_map_bounded(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "graphify-out").mkdir(parents=True)
    (root / "graphify-out" / "GRAPH_REPORT.md").write_text("x" * 100_000, encoding="utf-8")
    monkeypatch.setattr(chat, "_scan_offer", lambda cid: {"target": str(root)})
    assert len(chat._graphify_map("c1")) <= chat._GRAPHIFY_MAP_MAX


def test_graphify_map_absent_returns_empty(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(chat, "_scan_offer", lambda cid: {"target": str(root)})
    assert chat._graphify_map("c1") == ""


def test_graphify_map_no_offer_returns_empty(monkeypatch):
    monkeypatch.setattr(chat, "_scan_offer", lambda cid: {})
    assert chat._graphify_map("c1") == ""


def test_graphify_map_symlink_escape_refused(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "GRAPH_REPORT.md").write_text("secret host file", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    try:
        os.symlink(outside, root / "graphify-out")   # graphify-out -> a directory OUTSIDE the root
    except (OSError, NotImplementedError):
        import pytest
        pytest.skip("symlinks not supported here")
    monkeypatch.setattr(chat, "_scan_offer", lambda cid: {"target": str(root)})
    assert chat._graphify_map("c1") == "", "a graphify-out symlinked outside the root must be refused"
