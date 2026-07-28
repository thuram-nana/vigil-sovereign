"""R3 — one-click dossier download.

``build_dossier`` shells the exec-only ``vigil dossier`` (CSRF-guarded POST) to package a run into a
tamper-evident ZIP; the GET ``/api/dossier/<run>.zip`` route then STREAMS the pre-built file. Fail-closed: a
bad run id (``run_dir`` raises ValueError → 404), an unresolvable ``vigil`` bin, or a verb failure each refuse.
"""

from __future__ import annotations

import json

import pytest

from framework.v2.console import actions


def _mk_run(tmp_path, monkeypatch, meta=None):
    rd = tmp_path / "run1"
    rd.mkdir()
    (rd / "meta.json").write_text(json.dumps(meta or {"slug": "acme"}), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda run_id, **kw: rd)
    return rd


def test_build_dossier_no_vigil_bin_fails_closed(tmp_path, monkeypatch):
    _mk_run(tmp_path, monkeypatch)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    r = actions.build_dossier("run1")
    assert r["ok"] is False and "not resolvable" in r["error"]


def test_build_dossier_shells_vigil_dossier(tmp_path, monkeypatch):
    rd = _mk_run(tmp_path, monkeypatch, {"slug": "acme"})
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    captured = {}

    class _P:
        returncode = 0
        stdout = "wrote dossier"
        stderr = ""

    def fake_run(argv, **kw):
        captured["argv"] = argv
        (rd / "dossier.zip").write_bytes(b"PK\x03\x04zip")   # the verb writes the zip
        return _P()

    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    r = actions.build_dossier("run1")
    argv = captured["argv"]
    assert argv[:2] == ["/bin/vigil", "dossier"]
    assert argv[argv.index("--run-dir") + 1] == str(rd)
    assert argv[argv.index("--out") + 1] == str(rd / "dossier.zip")
    assert argv[argv.index("--slug") + 1] == "acme"
    assert r["ok"] is True and r["download"] == "/api/dossier/run1.zip"


def test_build_dossier_reports_verb_failure(tmp_path, monkeypatch):
    _mk_run(tmp_path, monkeypatch)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")

    class _P:
        returncode = 2
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr(actions.subprocess, "run", lambda *a, **k: _P())
    r = actions.build_dossier("run1")
    assert r["ok"] is False and "boom" in r["error"]


def test_dossier_path_is_traversal_guarded():
    with pytest.raises(ValueError):
        actions.dossier_path("../etc/passwd")
