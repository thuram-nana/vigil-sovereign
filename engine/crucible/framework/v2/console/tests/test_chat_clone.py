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

# The clone exercises `vigil_integration.live.executor` (subprocess_runner) — an OFFENSE-plane module that
# transitively needs `vigil_gateway`. That is installed in the P5 (two-env) job but NOT in the CRUCIBLE-core
# job, so run these there and skip cleanly where the offense deps are absent (the clone CODE lazy-imports
# them guarded; this guard is only for the TEST's own direct import). Coverage is preserved: P5 runs them.
pytest.importorskip("vigil_integration.live.executor")
# Import codefix_runner NOW, at collection, so its module-level `from .executor import subprocess_runner`
# binds the REAL runner BEFORE any test monkeypatches `executor.subprocess_runner`. Otherwise the first
# clone_codebase call (which lazily imports codefix_runner) would bind codefix_runner to the fake while a
# test's patch is active, and that stale binding would leak into a later test's `CodefixSession.build`.
pytest.importorskip("vigil_integration.live.codefix_runner")

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
    # the clone lands under THIS chat's confined clone area (<live>/clones/<chat>/), where the edit/test
    # routes will accept it — so _resolve_target sees a codebase AND the D2b panel guard (which reuses
    # _confined_clone_path) admits it. A real dir stands in for the clone; the launch is captured.
    clone_base = Path(actions_mod._live_base()) / "clones" / CHAT
    cloned = clone_base / "cloned-repo"
    cloned.mkdir(parents=True)
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
    # D2b contract: because the clone is under the confined clone area, the response AND the persisted
    # launched record carry mode + the codebase path (the resolved, confined form), so the interface offers
    # the gated edit/test affordances on THIS repo. Every codebase route re-confines the path server-side,
    # so echoing it grants no authority — it only tells the UI which repo the panel acts on.
    base = str(clone_base.resolve())
    assert out["mode"] == "codebase" and out["codebase_path"].startswith(base) and out["codebase_path"].endswith("cloned-repo")
    rec = [m for m in chat.read_session(CHAT) if m.get("kind") == "launched"][-1]
    assert rec["mode"] == "codebase" and rec["codebase_path"] == out["codebase_path"]


def test_a_url_launch_carries_no_codebase_path(monkeypatch):
    """Negative control: a NON-codebase (url) launch must NOT carry a codebase_path — the edit/test panel
    is offered only for a repo this chat cloned, never for a web target."""
    monkeypatch.setattr(actions_mod, "launch_assessment",
                        lambda body: {"run_id": "r", "slug": "s", "stream": "progress", "engine": "integration"})
    out = chat.chat_send({"chat_id": CHAT, "message": "assess it", "target": "http://127.0.0.1:8080", "mode": "url"})
    assert out["status"] == "running" and out["mode"] == "url"
    assert "codebase_path" not in out
    rec = [m for m in chat.read_session(CHAT) if m.get("kind") == "launched"][-1]
    assert "codebase_path" not in rec


def test_a_non_clone_codebase_launch_carries_no_codebase_path(monkeypatch, tmp_path):
    """RED-PEN MEDIUM: a codebase run from an extracted archive or a directly-typed local directory is a
    real codebase, but it sits OUTSIDE this chat's clone area — the edit/apply/test routes confine to
    <live>/clones/<chat>/ and would refuse it. So the launched record must NOT carry codebase_path: no
    dead edit/test panel, and no "cloned" label on something that was never cloned. (The gated scan is its
    affordance instead.) This is the guard that makes the panel appear iff its actions can succeed."""
    outside = tmp_path / "typed-project"       # a real dir, NOT under <live>/clones/<chat>/
    outside.mkdir()
    monkeypatch.setattr(actions_mod, "launch_assessment",
                        lambda body: {"run_id": "r", "slug": "s", "stream": "none", "engine": ""})
    out = chat.chat_send({"chat_id": CHAT, "message": "review this", "target": str(outside), "mode": "codebase"})
    assert out["status"] == "running" and out["mode"] == "codebase", out
    assert "codebase_path" not in out
    rec = [m for m in chat.read_session(CHAT) if m.get("kind") == "launched"][-1]
    assert "codebase_path" not in rec


def test_chat_send_reports_a_clone_failure(monkeypatch):
    monkeypatch.setattr(actions_mod, "clone_codebase",
                        lambda cid, repo, **kw: {"ok": False, "error": "git clone failed: not found"})
    out = chat.chat_send({"chat_id": CHAT, "message": "clone https://github.com/org/nope.git"})
    assert out["status"] == "refused" and "couldn't clone" in out["reply"].lower()
