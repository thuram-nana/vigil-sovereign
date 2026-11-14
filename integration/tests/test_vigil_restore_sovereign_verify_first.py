"""`vigil restore` of BOTH planes verifies the sovereign part (`sigil restore --verify-only`) BEFORE the offense leg
writes anything, so a sovereign part that would be refused (e.g. a hard-pruned unit that does not verify) leaves both
planes untouched; `--sigil-archive-dir` is forwarded as `sigil restore --archive-dir`; `--resume-sovereign` finishes an
interrupted sovereign restore (`sigil restore --resume`).

Stdlib + the orchestrator only: the sovereign `sigil` leg is a recorded fake (FATAL-2: the orchestrator never imports
sigil; it only ever execs it).
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

import vigil_integration.backup as backup
import vigil_integration.cli as cli


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_BACKUP_TRUST_ANCHOR", str(tmp_path / "trust-anchor.json"))
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", "pw-for-the-test-123")
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    monkeypatch.setattr(cli, "_resolve_crucible_root", lambda: None)


def _two_plane_backup(tmp_path, monkeypatch) -> Path:
    def fake_create(dest, pw, *, base_dir, crucible_root=None):
        Path(dest).write_bytes(b"fake-offense-ciphertext")
        return {"files": 1, "secrets": 0, "scope": "x", "bytes": 23}
    monkeypatch.setattr(backup, "create_offense_backup", fake_create)

    def fake_sigil_backup(args, pw):
        assert args[0] == "backup"
        Path(args[1]).write_bytes(b"fake-sovereign-ciphertext")
        return 0
    monkeypatch.setattr(cli, "_run_sovereign_leg", fake_sigil_backup)
    ns = argparse.Namespace(sovereign_only=False, offense_only=False, out=str(tmp_path / "out"),
                            base_dir=str(tmp_path / "base"), crucible_root="", passphrase_env="VIGIL_BACKUP_PASSPHRASE",
                            push="", prune=False, keep_days=None, keep_last=None, reset_trust_anchor=False)
    assert cli._cmd_backup(ns) == 0
    return sorted(p for p in (tmp_path / "out").iterdir() if p.is_dir())[0]


def _restore_ns(tmp_path, src, **kw):
    d = dict(sovereign_only=False, offense_only=False, src=str(src) if src else None,
             base_dir=str(tmp_path / "restored-base"), crucible_root="", sigil_home=str(tmp_path / "sigil-home"),
             expect_governance_pubkey="", force=False, passphrase_env="VIGIL_BACKUP_PASSPHRASE",
             allow_rollback=False)
    d.update(kw)
    return argparse.Namespace(**d)


def _record(monkeypatch, *, verify_rc=0, restore_rc=0):
    calls: list = []

    def fake_leg(args, pw):
        calls.append(("sigil", list(args)))
        if args[:2] == ["restore", "--verify-only"]:
            return verify_rc
        return restore_rc
    monkeypatch.setattr(cli, "_run_sovereign_leg", fake_leg)

    def fake_offense(off, base_dir, pw, *, crucible_root=None, expect_pubkey=None, force=False):
        calls.append(("offense", base_dir))
        return {"new_base": base_dir, "files": 1, "secrets": 0, "bundles_verified": 0}
    monkeypatch.setattr(backup, "restore_offense_backup", fake_offense)
    return calls


def test_both_planes_verify_the_sovereign_part_before_the_offense_leg(tmp_path, monkeypatch):
    src = _two_plane_backup(tmp_path, monkeypatch)
    calls = _record(monkeypatch)
    assert cli._cmd_restore(_restore_ns(tmp_path, src, sigil_archive_dir=str(tmp_path / "ebs"))) == 0
    home = str(tmp_path / "sigil-home")
    assert [c[0] for c in calls] == ["sigil", "offense", "sigil"]
    assert calls[0][1] == ["restore", "--verify-only", str(src / "sovereign.sglbk"), home,
                           "--archive-dir", str(tmp_path / "ebs")]
    assert calls[2][1] == ["restore", str(src / "sovereign.sglbk"), home, "--archive-dir", str(tmp_path / "ebs")]


def test_a_sovereign_part_that_does_not_verify_leaves_both_planes_untouched(tmp_path, monkeypatch):
    src = _two_plane_backup(tmp_path, monkeypatch)
    calls = _record(monkeypatch, verify_rc=1)
    assert cli._cmd_restore(_restore_ns(tmp_path, src)) == 1
    assert [c[0] for c in calls] == ["sigil"] and calls[0][1][:2] == ["restore", "--verify-only"]
    assert not (tmp_path / "restored-base").exists()


def test_both_planes_need_the_sigil_home_before_anything_is_restored(tmp_path, monkeypatch):
    src = _two_plane_backup(tmp_path, monkeypatch)
    calls = _record(monkeypatch)
    assert cli._cmd_restore(_restore_ns(tmp_path, src, sigil_home="")) == 2
    assert calls == []


@pytest.mark.parametrize("only", ["sovereign_only", "offense_only"])
def test_one_plane_restores_are_not_pre_verified(tmp_path, monkeypatch, only):
    src = _two_plane_backup(tmp_path, monkeypatch)
    calls = _record(monkeypatch)
    assert cli._cmd_restore(_restore_ns(tmp_path, src, **{only: True})) == 0
    assert not any(c[0] == "sigil" and "--verify-only" in c[1] for c in calls)
    assert [c[0] for c in calls] == (["sigil"] if only == "sovereign_only" else ["offense"])


def test_resume_sovereign_runs_sigil_restore_resume(tmp_path, monkeypatch):
    calls = _record(monkeypatch)
    assert cli._cmd_restore(_restore_ns(tmp_path, None, resume_sovereign=True)) == 0
    assert calls == [("sigil", ["restore", "--resume", str(tmp_path / "sigil-home")])]
    calls.clear()
    assert cli._cmd_restore(_restore_ns(tmp_path, None, resume_sovereign=True, sigil_home="")) == 2
    assert calls == []
    calls = _record(monkeypatch, restore_rc=1)
    assert cli._cmd_restore(_restore_ns(tmp_path, None, resume_sovereign=True)) == 1


def test_the_restore_parser_takes_the_new_flags():
    p = cli.build_parser()
    a = p.parse_args(["restore", "--resume-sovereign", "--sigil-home", "/h"])
    assert a.resume_sovereign is True and a.src is None and a.sigil_home == "/h"
    a = p.parse_args(["restore", "/bk", "--sigil-home", "/h", "--sigil-archive-dir", "/ebs/archive"])
    assert a.src == "/bk" and a.sigil_archive_dir == "/ebs/archive" and a.resume_sovereign is False


def test_the_orchestrator_never_imports_sigil():
    import sys
    assert "sigil" not in sys.modules or not cli.__dict__.get("sigil")
    src = Path(cli.__file__).read_text(encoding="utf-8")
    assert "import sigil" not in src and "from sigil" not in src
