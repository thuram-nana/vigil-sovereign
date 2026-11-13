"""Phase D2 console wrappers — propose/apply a dev-mode codebase edit, confined to a repo THIS chat
cloned. The load-bearing control: `_confined_clone_path` — an edit can only ever touch a clone ROOT,
`<live>/clones/<chat>/<name>` (never a directory nested in it, `.git` least of all), never an arbitrary
path the caller names. Needs `vigil_gateway` transitively (dev_edit → codefix_runner → executor), so it
importorskips and skips in CRUCIBLE-core; it RUNS in the offense leg of "integration two-env boundary
(P5)", which lists it and requires every plane it needs (enforced by
integration/tests/test_ci_cross_plane_tests_run_with_both_planes.py).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip("vigil_integration.live.executor")

from framework.v2.console import actions as actions_mod
from framework.v2.console import sessions


CHAT = "edit-chat"
_DIFF = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a = 1\n+a = 2\n"


@pytest.fixture(autouse=True)
def _iso(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    yield tmp_path


def _clone_area_repo() -> str:
    """A real git repo under THIS chat's clone area (as D1's clone_codebase would leave it)."""
    cid = sessions._safe_session_id(CHAT)
    wd = Path(actions_mod._live_base()) / "clones" / cid / "repo"
    wd.mkdir(parents=True, exist_ok=True)
    (wd / "x.py").write_text("a = 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=wd, check=True)
    subprocess.run(["git", "add", "-A"], cwd=wd, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"], cwd=wd, check=True)
    return str(wd)


# --- confinement (the security control) --------------------------------------------------------------

def test_confined_clone_path():
    wd = _clone_area_repo()
    assert actions_mod._confined_clone_path(CHAT, wd) == str(Path(wd).resolve())
    assert actions_mod._confined_clone_path(CHAT, "/etc") == ""                      # outside the area
    assert actions_mod._confined_clone_path(CHAT, wd + "/../../../etc") == ""        # traversal
    assert actions_mod._confined_clone_path("other-chat", wd) == ""                  # another chat's repo


def test_propose_and_apply_refuse_a_path_outside_the_clone_area():
    assert actions_mod.propose_codebase_edit(CHAT, "/etc", "do x")["ok"] is False
    assert actions_mod.apply_codebase_edit(CHAT, "/tmp/whatever", _DIFF)["ok"] is False


# --- propose + apply (confined) ----------------------------------------------------------------------

def test_propose_returns_a_diff_for_a_confined_repo(monkeypatch):
    wd = _clone_area_repo()
    from vigil_integration.live import dev_edit
    monkeypatch.setattr(dev_edit, "propose_dev_edit", lambda w, instr, **k: _DIFF)
    out = actions_mod.propose_codebase_edit(CHAT, wd, "bump a to 2")
    assert out["ok"] is True and out["diff"] == _DIFF


def test_propose_reports_no_change(monkeypatch):
    wd = _clone_area_repo()
    from vigil_integration.live import dev_edit
    monkeypatch.setattr(dev_edit, "propose_dev_edit", lambda w, instr, **k: "")   # declined/refused/no-key
    assert actions_mod.propose_codebase_edit(CHAT, wd, "x")["ok"] is False


def test_apply_applies_a_reviewed_diff_into_the_confined_repo():
    wd = _clone_area_repo()
    out = actions_mod.apply_codebase_edit(CHAT, wd, _DIFF)   # operator_present forced True inside
    assert out["ok"] is True and out["applied"] == ["x.py"]
    assert (Path(wd) / "x.py").read_text() == "a = 2\n"


def test_killswitch_refuses_apply_and_propose(monkeypatch):
    """RED-PEN BLOCK-1: the engagement kill-switch (emergency stop) refuses BOTH propose and apply — a
    code-mutating action must be at least as protected as the read-only clone (which already honors it)."""
    wd = _clone_area_repo()
    monkeypatch.setattr(actions_mod, "_chat_killswitch_tripped", lambda cid: True)
    ap = actions_mod.apply_codebase_edit(CHAT, wd, _DIFF)
    assert ap["ok"] is False and "kill-switch" in ap["error"]
    assert (Path(wd) / "x.py").read_text() == "a = 1\n", "an edit applied while the kill-switch was engaged"
    pr = actions_mod.propose_codebase_edit(CHAT, wd, "bump a")
    assert pr["ok"] is False and "kill-switch" in pr["error"]


def test_symlinked_clone_path_is_refused(tmp_path):
    """A symlink under the clone area pointing OUTSIDE must not let an edit escape: .resolve()+commonpath
    collapses it and _confined_clone_path refuses."""
    import os
    cid = sessions._safe_session_id(CHAT)
    area = Path(actions_mod._live_base()) / "clones" / cid
    area.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = area / "sneaky"
    os.symlink(str(outside), str(link))
    assert actions_mod._confined_clone_path(CHAT, str(link)) == ""


# --- clone CONTENT is hostile, and the workdir is the clone ROOT only ---------------------------------

def test_files_in_instruction_skips_symlinks_planted_in_the_clone(tmp_path):
    """A cloned repo can commit ``settings.py -> <host file>`` / ``conf -> <host dir>``. Naming them in an
    instruction must not select them as model context (symlinked file AND symlinked parent directory)."""
    wd = Path(_clone_area_repo())
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("TOP-SECRET-HOST-FILE\n", encoding="utf-8")
    (wd / "settings.py").symlink_to(outside / "secret.txt")
    (wd / "conf").symlink_to(outside, target_is_directory=True)
    got = actions_mod._files_in_instruction(str(wd), "please tidy settings.py and conf/secret.txt and x.py")
    assert got == ["x.py"]


def test_files_in_instruction_returns_only_existing_regular_files():
    """A name that is absent, or that names a DIRECTORY, is not model context — only real files are."""
    wd = Path(_clone_area_repo())
    (wd / "pkg.d").mkdir()
    assert actions_mod._files_in_instruction(str(wd), "touch missing.py, pkg.d and x.py") == ["x.py"]


def test_confined_clone_path_is_the_clone_root_only():
    """Clones are created at ``<live>/clones/<chat>/<name>`` and nowhere deeper, so that — not any nested
    directory — is the only valid workdir. ``<clone>/.git`` in particular must never be one."""
    wd = _clone_area_repo()
    (Path(wd) / "pkg").mkdir()
    assert actions_mod._confined_clone_path(CHAT, wd) == str(Path(wd).resolve())
    for nested in ("/.git", "/.git/hooks", "/pkg"):
        assert actions_mod._confined_clone_path(CHAT, wd + nested) == "", nested


def test_apply_into_dot_git_is_refused_so_no_hook_can_be_planted():
    """With ``<clone>/.git`` as the workdir, ``git apply``'s own ``.git`` protection no longer applies (the
    diff path is just ``hooks/post-checkout``) — a reviewed diff would install an executable hook."""
    wd = _clone_area_repo()
    hook = ("diff --git a/hooks/post-checkout b/hooks/post-checkout\nnew file mode 100755\n--- /dev/null\n"
            "+++ b/hooks/post-checkout\n@@ -0,0 +1,2 @@\n+#!/bin/sh\n+true\n")
    out = actions_mod.apply_codebase_edit(CHAT, wd + "/.git", hook)
    assert out["ok"] is False and "no such cloned codebase" in out["error"]
    assert not (Path(wd) / ".git" / "hooks" / "post-checkout").exists()


def test_apply_is_refused_while_the_clones_tests_run(monkeypatch):
    """The clone's tests run ITS code with the clone bound read-write; it can swap a directory for a link
    while `git apply` runs, and git's own symlink check is a check-then-use. So an apply that arrives while
    the tests run is refused (the file is untouched), and the same apply goes through once they finish."""
    wd = _clone_area_repo()
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "/opt/vigil/bin/vigil")
    monkeypatch.setattr(actions_mod, "_chat_killswitch_tripped", lambda cid: False)
    during: dict = {}

    class _Done:
        stdout = '{"ran": true, "exit_code": 0}'
        stderr = ""
        returncode = 0

    real_run = subprocess.run

    def _sandbox(argv, **kw):                         # the box is running the clone's tests right now
        if list(argv[:2]) != ["/opt/vigil/bin/vigil", "sandbox"]:
            return real_run(argv, **kw)               # host-side git (the apply itself) runs for real
        during["apply"] = actions_mod.apply_codebase_edit(CHAT, wd, _DIFF)
        return _Done()

    monkeypatch.setattr(actions_mod.subprocess, "run", _sandbox)
    assert actions_mod.run_codebase_tests(CHAT, wd, "pytest -q", operator_present=True)["ok"] is True
    assert during["apply"]["ok"] is False and "busy" in during["apply"]["error"]
    assert (Path(wd) / "x.py").read_text() == "a = 1\n", "an edit was applied while the clone's tests ran"
    after = actions_mod.apply_codebase_edit(CHAT, wd, _DIFF)
    assert after["ok"] is True and (Path(wd) / "x.py").read_text() == "a = 2\n"
