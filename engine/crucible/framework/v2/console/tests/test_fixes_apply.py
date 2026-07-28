"""Fixes screen (U1) — the gated ``apply_fix`` action shells ``vigil patch`` (non-destructive, never --open-pr).

``apply_fix`` is fail-closed: an unsafe finding ref, a run with no repository, or an unresolvable ``vigil`` bin
each refuse cleanly. A codebase run shells the SAME gated verb the CLI uses (the driving finding grounded in the
engagement's OWN signed spine) and surfaces its REAL output — a proof-of-fix or its fail-closed refusal. The
console NEVER opens a PR (that stays a deliberate m-of-n CLI act) and never asserts ``remediated``.
"""

from __future__ import annotations

import json

from framework.v2.console import actions


def _mk_run(tmp_path, monkeypatch, meta):
    rd = tmp_path / "run1"
    rd.mkdir()
    (rd / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda run_id, **kw: rd)
    return rd


def test_apply_fix_rejects_unsafe_ref(tmp_path, monkeypatch):
    _mk_run(tmp_path, monkeypatch, {"mode": "codebase", "slug": "acme", "target": "/repo"})
    for bad in ("", "../etc", "a/b", "-x", "a b", "a\tb", "a\\b"):
        r = actions.apply_fix("run1", bad)
        assert r["ok"] is False and "invalid finding reference" in r["error"], bad


def test_apply_fix_no_repo_is_honest_refusal(tmp_path, monkeypatch):
    _mk_run(tmp_path, monkeypatch, {"mode": "url", "slug": "acme", "target": "http://127.0.0.1:8080/"})
    r = actions.apply_fix("run1", "chk-1")
    assert r["ok"] is False and r["runnable"] is False and "no repository to patch" in r["error"]


def test_apply_fix_no_vigil_bin_fails_closed(tmp_path, monkeypatch):
    _mk_run(tmp_path, monkeypatch, {"mode": "codebase", "slug": "acme", "target": "/repo"})
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    r = actions.apply_fix("run1", "chk-1")
    assert r["ok"] is False and "not resolvable" in r["error"]


def test_apply_fix_bad_slug_refuses(tmp_path, monkeypatch):
    _mk_run(tmp_path, monkeypatch, {"mode": "codebase", "slug": "../evil", "target": "/repo"})
    r = actions.apply_fix("run1", "chk-1")
    assert r["ok"] is False and "engagement slug" in r["error"]


def test_apply_fix_no_spine_is_honest_refusal(tmp_path, monkeypatch):
    # a codebase run with a resolvable vigil bin but NO signed offense spine → an HONEST, actionable refusal
    # (names the spine path + the `vigil engage` remedy), never a cryptic raw verb error and never a spawn.
    _mk_run(tmp_path, monkeypatch, {"mode": "codebase", "slug": "acme", "target": "/home/me/proj"})
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "no-such-base"))
    called = {"ran": False}
    monkeypatch.setattr(actions.subprocess, "run", lambda *a, **k: called.__setitem__("ran", True))
    r = actions.apply_fix("run1", "chk-1")
    assert r["ok"] is False and r["runnable"] is False
    assert "no signed offense spine" in r["error"] and "vigil engage --slug acme" in r["error"]
    assert called["ran"] is False                        # no spawn when provenance is absent


def test_apply_fix_shells_gated_vigil_patch_never_open_pr(tmp_path, monkeypatch):
    _mk_run(tmp_path, monkeypatch, {"mode": "codebase", "slug": "acme", "target": "/home/me/proj"})
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    # provision the signed offense spine the gated patch grounds on (the pre-check requires it).
    base = tmp_path / "base"
    base.mkdir()
    (base / "acme.spine").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("VIGIL_BASE_DIR", str(base))
    captured = {}

    class _P:
        returncode = 0
        # the realistic applied-edits, no-PR outcome vocabulary (status: pr-denied, remediated: False).
        stdout = "--- result ---\nstatus         : pr-denied\napplied_paths  : ['app.py']\nremediated     : False\n"
        stderr = ""

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return _P()

    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    r = actions.apply_fix("run1", "chk-1")
    argv = captured["argv"]
    # the gated verb, grounded in the signed spine, applying into a DISPOSABLE clone — NEVER --open-pr.
    assert argv[:2] == ["/bin/vigil", "patch"]
    assert argv[argv.index("--from-spine") + 1] == "acme"
    assert argv[argv.index("--finding-ref") + 1] == "chk-1"
    assert argv[argv.index("--target-repo") + 1] == "/home/me/proj"
    assert argv[argv.index("--base-dir") + 1] == str(base)   # base-dir passed explicitly (check + verb agree)
    assert "--apply-edits" in argv
    assert "--open-pr" not in argv                       # the console NEVER opens a PR
    assert r["ok"] is True and r["runnable"] is True and "pr-denied" in r["output"]
    # honest: the console does not assert remediated — the note says it is oracle-earned on re-drive.
    assert "EARNED only when" in r["note"] and "--open-pr" in r["note"]
