"""The console gate + verify for a deterministic DAA codebase scan (fix-enabled end-to-end).

A DAA codescan run records mode="sast", the source repo as target, its base_dir, and writes the signed
<base>/<slug>.spine. THEN the gated fix is runnable (fix_precondition), and verify_fix re-runs the DAA rule to
confirm the finding cleared. These pin the console halves without importing vigil_integration (the CRUCIBLE
core leg): the spine is faked as a present file (the presence check is what the gate makes), and the
codescan verify subprocess is stubbed."""
from __future__ import annotations

import json
import subprocess
import types

from framework.v2.console import actions


def _run(tmp_path, run_id, meta, *, spine_at=None):
    d = tmp_path / "runs" / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    if spine_at:
        spine_at.parent.mkdir(parents=True, exist_ok=True)
        spine_at.write_text("{}", encoding="utf-8")   # presence is what fix_precondition checks


def test_fix_runnable_for_a_daa_codescan_run(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/vigil")
    base = tmp_path / "base"
    spine = base / "cbslug.spine"
    _run(tmp_path, "r1", {"status": "done", "mode": "sast", "slug": "cbslug",
                          "target": str(tmp_path / "src"), "base_dir": str(base)}, spine_at=spine)
    pre = actions.fix_precondition("r1")
    assert pre["runnable"] is True, pre.get("why_not")
    assert pre["base_dir"] == str(base)          # read from meta, so it matches where codescan wrote the spine
    assert pre["repo"] == str(tmp_path / "src")


def test_fix_refused_when_no_spine(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/vigil")
    base = tmp_path / "base"
    _run(tmp_path, "r2", {"status": "done", "mode": "sast", "slug": "noscan",
                          "target": str(tmp_path / "src"), "base_dir": str(base)})   # no spine written
    pre = actions.fix_precondition("r2")
    assert pre["runnable"] is False and "spine" in pre["why_not"].lower()


def test_verify_fix_reports_cleared(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/vigil")
    base = tmp_path / "base"
    spine = base / "cbslug.spine"
    _run(tmp_path, "r3", {"status": "done", "mode": "sast", "slug": "cbslug",
                          "target": str(tmp_path / "src"), "base_dir": str(base)}, spine_at=spine)

    def _fake_run(cmd, **kw):
        assert cmd[:3] == ["/usr/bin/vigil", "codescan", "--verify"], cmd
        assert "--ref" in cmd and "DAA-EVAL~x~L1" in cmd
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(
            {"ref": "DAA-EVAL~x~L1", "cleared": True, "still_fires_at": []}), stderr="")
    monkeypatch.setattr(subprocess, "run", _fake_run)
    out = actions.verify_fix("r3", "DAA-EVAL~x~L1")
    assert out["ok"] is True and out["cleared"] is True


def test_verify_fix_reports_still_vulnerable(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/vigil")
    base = tmp_path / "base"
    spine = base / "cbslug.spine"
    _run(tmp_path, "r4", {"status": "done", "mode": "sast", "slug": "cbslug",
                          "target": str(tmp_path / "src"), "base_dir": str(base)}, spine_at=spine)

    def _fake_run(cmd, **kw):
        return types.SimpleNamespace(returncode=1, stdout=json.dumps(
            {"ref": "DAA-EVAL~x~L1", "cleared": False, "still_fires_at": ["app.py:1"]}), stderr="")
    monkeypatch.setattr(subprocess, "run", _fake_run)
    out = actions.verify_fix("r4", "DAA-EVAL~x~L1")
    assert out["ok"] is True and out["cleared"] is False and out["still_fires_at"] == ["app.py:1"]


def test_verify_fix_rejects_unsafe_ref(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    _run(tmp_path, "r5", {"status": "done", "mode": "sast", "slug": "s", "target": "/x", "base_dir": "/b"})
    out = actions.verify_fix("r5", "../etc/passwd")
    assert out["ok"] is False and out["cleared"] is False


def test_deep_fix_spawns_vigil_patch_deep(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/vigil")
    base = tmp_path / "base"; spine = base / "cbslug.spine"
    _run(tmp_path, "rd", {"status": "done", "mode": "sast", "slug": "cbslug",
                          "target": str(tmp_path / "src"), "base_dir": str(base)}, spine_at=spine)

    def _fake_run(cmd, **kw):
        # the deep verb: `vigil patch --deep --fix-attempts N --from-spine ... --apply-edits --approve`
        assert cmd[:3] == ["/usr/bin/vigil", "patch", "--deep"], cmd
        assert "--fix-attempts" in cmd and "--from-spine" in cmd and "--apply-edits" in cmd and "--approve" in cmd
        assert "--open-pr" not in cmd   # deep fix is NEVER a PR from the console
        return types.SimpleNamespace(returncode=0, stdout="status         : verified-no-pr\n", stderr="")
    monkeypatch.setattr(subprocess, "run", _fake_run)
    out = actions.deep_fix("rd", "DAA-EVAL~x~L1", fix_attempts=3)
    assert out["ok"] is True and out["verified"] is True and out["runnable"] is True


def test_deep_fix_reports_unverified_on_nonzero(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/vigil")
    base = tmp_path / "base"; spine = base / "cbslug.spine"
    _run(tmp_path, "rd2", {"status": "done", "mode": "sast", "slug": "cbslug",
                           "target": str(tmp_path / "src"), "base_dir": str(base)}, spine_at=spine)
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: types.SimpleNamespace(returncode=1, stdout="status         : verify-still-vulnerable\n", stderr=""))
    out = actions.deep_fix("rd2", "DAA-EVAL~x~L1")
    assert out["ok"] is False and out["verified"] is False   # exit!=0 -> not verified (no false 'fixed')


def test_deep_fix_refused_when_no_spine(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/vigil")
    _run(tmp_path, "rd3", {"status": "done", "mode": "sast", "slug": "noscan",
                           "target": str(tmp_path / "src"), "base_dir": str(tmp_path / "base")})
    out = actions.deep_fix("rd3", "DAA-EVAL~x~L1")
    assert out["ok"] is False and out["runnable"] is False
