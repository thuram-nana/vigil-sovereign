"""Proof Studio C1 — the `proof_export` console action (shells `vigil proof-export`).

Fail-closed without a `vigil` bin; the run id is traversal-guarded (run_dir raises → do_POST 404s); and the
action shells the RESOLVED run dir (the integration process can't locate the console's runs across the
two-env boundary) with the run's own slug — never the caller's arbitrary text.
"""

from __future__ import annotations

import json

import pytest

from framework.v2.console import actions


def test_proof_export_fails_closed_without_a_vigil_bin(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    r = actions.proof_export("20260101-000000-001")
    assert r["ok"] is False and "vigil" in r["error"]


def test_proof_export_rejects_a_traversal_run_id(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    with pytest.raises(ValueError):
        actions.proof_export("../../etc")           # run_dir guard raises → server maps to a clean 404


def test_proof_export_shells_the_resolved_run_dir_and_run_slug(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    run = "20260101-000000-001"
    rd = actions.run_dir(run)
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "meta.json").write_text(json.dumps({"slug": "acme-web"}), encoding="utf-8")

    captured = {}

    class _P:
        returncode = 0
        stdout = "bundle: x\ncertificates: 1"
        stderr = ""

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return _P()

    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    r = actions.proof_export(run)
    assert r["ok"] is True
    argv = captured["argv"]
    assert argv[:2] == ["/bin/vigil", "proof-export"]
    assert argv[argv.index("--run-dir") + 1] == str(rd)          # the RESOLVED console run dir
    assert argv[argv.index("--slug") + 1] == "acme-web"          # the run's own slug
    assert str(rd) in argv[argv.index("--out") + 1]


def test_proof_export_surfaces_a_verb_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    run = "20260101-000000-002"
    actions.run_dir(run).mkdir(parents=True, exist_ok=True)

    class _P:
        returncode = 1
        stdout = ""
        stderr = "proof-export: no proven findings to export"

    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions.subprocess, "run", lambda *a, **k: _P())
    r = actions.proof_export(run)
    assert r["ok"] is False and "no proven findings" in r["error"]
