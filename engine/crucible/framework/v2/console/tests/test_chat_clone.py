"""Phase D1 — clone a git repo (gated), then work on it as a codebase. The sharpest surface in the chat
orchestrator (egress + fetching arbitrary code), so the tests pin the hardening:

  * the source is validated (no git-flag injection, no transport-helper command execution, scheme allowlist);
  * the clone workdir is CONFINED strictly under the per-chat clone area;
  * a git REPO in a message is cloned (github / .git / scp), while a loopback/other URL is NOT (it stays a
    scan target);
  * chat routes a clone request → the cloned directory becomes a `codebase` target → the gated launcher.

The actual `git clone` subprocess is faked throughout — no network, no real clone.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat


CHAT = "clone-chat"


@pytest.fixture(autouse=True)
def _iso(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


class _R:
    def __init__(self, code=0, err=""):
        self.exit_code = code
        self.stderr = err


def _fake_git(monkeypatch, *, code=0, err="", make_dir=True):
    """Fake subprocess_runner: records that git RAN + its argv, and (optionally) creates the dest dir a
    real clone would. ``seen['called']`` lets a guard test prove the runner was NEVER reached."""
    seen = {"called": False}
    from vigil_integration.live import executor

    def _run(argv, timeout=None, **kw):
        seen["called"] = True
        seen["argv"] = argv
        if make_dir and code == 0 and len(argv) >= 2:
            os.makedirs(argv[-1], exist_ok=True)   # argv[-1] is the dest
        return _R(code, err)

    monkeypatch.setattr(executor, "subprocess_runner", _run)
    return seen


# --- git-repo detection ------------------------------------------------------------------------------

def test_detects_git_repos_only():
    assert chat._git_repo_in_message("clone https://github.com/org/repo and review auth") == "https://github.com/org/repo"
    assert chat._git_repo_in_message("git@github.com:org/repo.git") == "git@github.com:org/repo.git"
    # a loopback / plain web URL is a SCAN target, never a clone
    assert chat._git_repo_in_message("scan http://127.0.0.1:8080 for xss") == ""
    assert chat._git_repo_in_message("check https://myapp.example.com/login") == ""
    # RED-PEN BLOCK-2: host is matched by urlsplit, never substring — look-alike + path-embedded are NOT clones
    assert chat._git_repo_in_message("clone https://github.com.evil.com/x.git") == ""
    assert chat._git_repo_in_message("scan http://127.0.0.1:8080/github.com/x") == ""
    # ...and a .git URL to an INTERNAL/metadata host is NOT a clone (stays out of the clone path)
    assert chat._git_repo_in_message("clone http://169.254.169.254/latest/x.git") == ""
    assert chat._git_repo_in_message("no url here") == ""


# --- clone_codebase guards + confinement -------------------------------------------------------------

def test_clone_rejects_dangerous_sources_and_never_reaches_git(monkeypatch):
    """RED-PEN BLOCK-3: prove the GUARD fired, not just that ok is False (a failed clone is also False).
    Assert the specific rejection reason AND that git was never invoked."""
    seen = _fake_git(monkeypatch)   # spy: if git runs, seen['called'] flips
    r1 = actions_mod.clone_codebase(CHAT, "-x", operator_present=True)
    assert r1["ok"] is False and ("'-'" in r1["error"] or "flag" in r1["error"])
    r2 = actions_mod.clone_codebase(CHAT, "ext::sh -c id", operator_present=True)
    assert r2["ok"] is False and "transport-helper" in r2["error"]
    r3 = actions_mod.clone_codebase(CHAT, "ftp://evil/x", operator_present=True)
    assert r3["ok"] is False and ("scheme" in r3["error"] or "allowed git host" in r3["error"])
    assert seen["called"] is False, "a dangerous source reached the git runner — the guard did not fire"


def test_clone_rejects_ssrf_hosts_and_never_reaches_git(monkeypatch):
    """RED-PEN BLOCK-2: the destination-host allowlist blocks internal/loopback/metadata + look-alikes."""
    seen = _fake_git(monkeypatch)
    for repo in ("http://169.254.169.254/latest/x.git", "http://127.0.0.1:9200/es.git",
                 "https://github.com.evil.com/x.git", "https://git.internal.corp/org/repo.git"):
        out = actions_mod.clone_codebase(CHAT, repo, operator_present=True)
        assert out["ok"] is False and "not an allowed git host" in out["error"], repo
    assert seen["called"] is False, "an SSRF host reached the git runner — the allowlist did not fire"


def test_clone_gate_requires_operator_present(monkeypatch):
    """RED-PEN BLOCK-1: git_clone is WARDEN A2 (queue = needs owner approval). Honor it — a non-operator
    (background) caller is refused; the operator-typed request opens it."""
    seen = _fake_git(monkeypatch)
    bg = actions_mod.clone_codebase(CHAT, "https://github.com/org/repo.git")   # operator_present defaults False
    assert bg["ok"] is False and "gate" in bg["error"] and seen["called"] is False
    ok = actions_mod.clone_codebase(CHAT, "https://github.com/org/repo.git", operator_present=True)
    assert ok["ok"] is True


def test_clone_succeeds_confined_and_hardened(monkeypatch, tmp_path):
    seen = _fake_git(monkeypatch)
    out = actions_mod.clone_codebase(CHAT, "https://github.com/org/repo.git", operator_present=True)
    assert out["ok"] is True and out["name"] == "repo"
    # confined strictly under the per-chat clone base
    base = str((Path(actions_mod._live_base()) / "clones" / CHAT).resolve())
    assert out["path"].startswith(base) and out["path"] != base
    # hardened argv: no shell, `--` terminator, --depth 1, blob-size filter, dest last
    argv = seen["argv"]
    assert argv[:3] == ["git", "clone", "--no-hardlinks"] and "--" in argv
    assert argv[argv.index("--") + 1] == "https://github.com/org/repo.git"
    assert "--depth" in argv and any(a.startswith("--filter=blob:limit") for a in argv)


def test_clone_refused_when_engagement_killswitch_tripped(monkeypatch):
    """The best-effort emergency stop: a tripped engagement kill-switch refuses a clone from that chat."""
    seen = _fake_git(monkeypatch)
    monkeypatch.setattr(actions_mod, "_chat_killswitch_tripped", lambda cid: True)
    out = actions_mod.clone_codebase(CHAT, "https://github.com/org/repo.git", operator_present=True)
    assert out["ok"] is False and "kill-switch" in out["error"] and seen["called"] is False


def test_clone_reports_git_failure(monkeypatch):
    _fake_git(monkeypatch, code=128, err="fatal: repository not found", make_dir=False)
    out = actions_mod.clone_codebase(CHAT, "https://github.com/org/nope.git", operator_present=True)
    assert out["ok"] is False and "git clone failed" in out["error"]


# --- chat routing ------------------------------------------------------------------------------------

def test_chat_send_routes_a_clone_request(monkeypatch, tmp_path):
    # a real dir stands in for the clone, so _resolve_target sees a codebase; capture the launch
    cloned = tmp_path / "cloned-repo"
    cloned.mkdir()
    monkeypatch.setattr(actions_mod, "clone_codebase",
                        lambda cid, repo, **kw: {"ok": True, "path": str(cloned), "name": "cloned-repo"})
    launched = {}
    monkeypatch.setattr(actions_mod, "launch_assessment",
                        lambda body: launched.setdefault("body", body) or {"run_id": "r", "slug": "s",
                                                                           "stream": "progress", "engine": ""})
    out = chat.chat_send({"chat_id": CHAT, "message": "clone https://github.com/org/repo and review auth"})
    assert out["status"] == "running", out
    assert launched["body"]["mode"] == "codebase" and launched["body"]["target"] == str(cloned)
    assert "Cloned https://github.com/org/repo" in out["reply"]


def test_chat_send_reports_a_clone_failure(monkeypatch):
    monkeypatch.setattr(actions_mod, "clone_codebase",
                        lambda cid, repo, **kw: {"ok": False, "error": "git clone failed: not found"})
    out = chat.chat_send({"chat_id": CHAT, "message": "clone https://github.com/org/nope.git"})
    assert out["status"] == "refused" and "couldn't clone" in out["reply"].lower()
