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
    """Fake subprocess_runner: records argv and (optionally) creates the dest dir a real clone would."""
    seen = {}
    from vigil_integration.live import executor

    def _run(argv, timeout=None, **kw):
        seen["argv"] = argv
        if make_dir and code == 0 and len(argv) >= 2:
            os.makedirs(argv[-1], exist_ok=True)   # argv[-1] is the dest
        return _R(code, err)

    monkeypatch.setattr(executor, "subprocess_runner", _run)
    return seen


# --- git-repo detection ------------------------------------------------------------------------------

def test_detects_git_repos_only():
    assert chat._git_repo_in_message("clone https://github.com/org/repo and review auth") == "https://github.com/org/repo"
    assert chat._git_repo_in_message("look at https://example.com/thing.git please").endswith(".git")
    assert chat._git_repo_in_message("git@github.com:org/repo.git") == "git@github.com:org/repo.git"
    # a loopback / plain web URL is a SCAN target, never a clone
    assert chat._git_repo_in_message("scan http://127.0.0.1:8080 for xss") == ""
    assert chat._git_repo_in_message("check https://myapp.example.com/login") == ""
    assert chat._git_repo_in_message("no url here") == ""


# --- clone_codebase guards + confinement -------------------------------------------------------------

def test_clone_rejects_dangerous_sources():
    assert actions_mod.clone_codebase(CHAT, "-x")["ok"] is False                    # git-flag injection
    assert actions_mod.clone_codebase(CHAT, "ext::sh -c id")["ok"] is False         # transport-helper RCE
    assert actions_mod.clone_codebase(CHAT, "ftp://evil/x")["ok"] is False          # scheme off allowlist


def test_clone_succeeds_confined_and_hardened(monkeypatch, tmp_path):
    seen = _fake_git(monkeypatch)
    out = actions_mod.clone_codebase(CHAT, "https://github.com/org/repo.git")
    assert out["ok"] is True and out["name"] == "repo"
    # confined strictly under the per-chat clone base
    base = str((Path(actions_mod._live_base()) / "clones" / CHAT).resolve())
    assert out["path"].startswith(base) and out["path"] != base
    # hardened argv: no shell, `--` terminator, --depth 1, dest last
    argv = seen["argv"]
    assert argv[:3] == ["git", "clone", "--no-hardlinks"] and "--" in argv
    assert argv[argv.index("--") + 1] == "https://github.com/org/repo.git"
    assert "--depth" in argv


def test_clone_reports_git_failure(monkeypatch):
    _fake_git(monkeypatch, code=128, err="fatal: repository not found", make_dir=False)
    out = actions_mod.clone_codebase(CHAT, "https://github.com/org/nope.git")
    assert out["ok"] is False and "git clone failed" in out["error"]


# --- chat routing ------------------------------------------------------------------------------------

def test_chat_send_routes_a_clone_request(monkeypatch, tmp_path):
    # a real dir stands in for the clone, so _resolve_target sees a codebase; capture the launch
    cloned = tmp_path / "cloned-repo"
    cloned.mkdir()
    monkeypatch.setattr(actions_mod, "clone_codebase",
                        lambda cid, repo: {"ok": True, "path": str(cloned), "name": "cloned-repo"})
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
                        lambda cid, repo: {"ok": False, "error": "git clone failed: not found"})
    out = chat.chat_send({"chat_id": CHAT, "message": "clone https://github.com/org/nope.git"})
    assert out["status"] == "refused" and "couldn't clone" in out["reply"].lower()
