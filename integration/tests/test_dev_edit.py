"""Phase D2 — general dev-mode codebase edits: propose a change as a unified diff, review, approve, apply.
GENERAL software editing (no security-fix framing, no oracle-confirmed FACT required) that still reuses
the hardened primitives: sovereignty-gated propose, path-confined diff parse, clone-only git-apply, and a
per-edit A2 gate that opens only when the operator is present.

`vigil_gateway` is needed transitively (codefix_runner → executor), so importorskip — runs in P5, skips
in CRUCIBLE-core (matching the clone tests).
"""
from __future__ import annotations

import os
import subprocess
import types
from pathlib import Path

import pytest

pytest.importorskip("vigil_integration.live.executor")

from vigil_integration.live import dev_edit


def _git_repo(tmp_path: Path) -> str:
    wd = tmp_path / "repo"
    wd.mkdir()
    (wd / "x.py").write_text("a = 1\n", encoding="utf-8")
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    subprocess.run(["git", "init", "-q"], cwd=wd, check=True)
    subprocess.run(["git", "add", "-A"], cwd=wd, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
                   cwd=wd, check=True)
    return str(wd)


_DIFF = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a = 1\n+a = 2\n"


# --- apply -------------------------------------------------------------------------------------------

def test_apply_requires_operator_present(tmp_path):
    wd = _git_repo(tmp_path)
    bg = dev_edit.apply_dev_edit(wd, _DIFF, operator_present=False)   # background → A2 queue, not allowed
    assert bg["ok"] is False and "gate" in bg["error"]
    assert (Path(wd) / "x.py").read_text() == "a = 1\n", "an ungated edit changed the file"


def test_apply_when_operator_present_changes_the_clone(tmp_path):
    wd = _git_repo(tmp_path)
    out = dev_edit.apply_dev_edit(wd, _DIFF, operator_present=True)
    assert out["ok"] is True and out["applied"] == ["x.py"]
    assert (Path(wd) / "x.py").read_text() == "a = 2\n"


def test_apply_rejects_empty_or_unconfined_diff(tmp_path):
    wd = _git_repo(tmp_path)
    assert dev_edit.apply_dev_edit(wd, "", operator_present=True)["ok"] is False
    # a traversal path is dropped by parse_unified_diff → no confined changes → refused, file untouched
    eviltxt = "--- a/../../etc/x\n+++ b/../../etc/x\n@@ -1 +1 @@\n-a\n+b\n"
    out = dev_edit.apply_dev_edit(wd, eviltxt, operator_present=True)
    assert out["ok"] is False and "confined" in out["error"]


def test_apply_no_workdir(tmp_path):
    assert dev_edit.apply_dev_edit(str(tmp_path / "nope"), _DIFF, operator_present=True)["ok"] is False


def test_apply_refuses_rename_to_outside_the_repo(tmp_path):
    """RED-PEN MEDIUM-1 defense-in-depth: a diff whose +++ is confined but whose git `rename to` header
    escapes the tree is refused by dev_edit BEFORE git apply (not relying solely on git's own rejection)."""
    wd = _git_repo(tmp_path)
    poison = ("diff --git a/x.py b/x.py\nrename from x.py\nrename to ../../evil\n"
              "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a = 1\n+a = 2\n")
    out = dev_edit.apply_dev_edit(wd, poison, operator_present=True)
    assert out["ok"] is False and "outside the repository" in out["error"]
    assert (Path(wd) / "x.py").read_text() == "a = 1\n", "a rename-escape diff mutated the file"


def test_apply_honors_an_injected_killswitch(tmp_path):
    """When a killswitch IS injected (as the console wrapper does via its own check), a tripped one refuses."""
    wd = _git_repo(tmp_path)

    class _KS:
        def is_tripped(self):
            return True

    out = dev_edit.apply_dev_edit(wd, _DIFF, operator_present=True, killswitch=_KS())
    assert out["ok"] is False and (Path(wd) / "x.py").read_text() == "a = 1\n"


# --- propose -----------------------------------------------------------------------------------------

def _fake_client(diff: str):
    class _B:
        type = "text"

        def __init__(self, t):
            self.text = t

    class _R:
        def __init__(self, t):
            self.content = [_B(t)]

    class _C:
        def __init__(self):
            self.messages = self

        def create(self, **kw):
            return _R(diff)

    return _C()


def test_propose_returns_the_diff(tmp_path, monkeypatch):
    wd = _git_repo(tmp_path)
    monkeypatch.setattr(dev_edit, "llm_egress_refusal", lambda *a, **k: None)   # permitted egress
    out = dev_edit.propose_dev_edit(wd, "bump a to 2", files=["x.py"], client=_fake_client(_DIFF))
    assert out == _DIFF


def test_propose_fail_closed_on_sovereignty_refusal(tmp_path, monkeypatch):
    wd = _git_repo(tmp_path)
    monkeypatch.setattr(dev_edit, "llm_egress_refusal", lambda *a, **k: "AIR_GAPPED: no egress")
    assert dev_edit.propose_dev_edit(wd, "bump a", files=["x.py"], client=_fake_client(_DIFF)) == ""


def test_propose_empty_instruction(tmp_path):
    assert dev_edit.propose_dev_edit(_git_repo(tmp_path), "   ") == ""


# --- clone CONTENT is hostile: symlinks a cloned third-party repo can plant ---------------------------

def test_read_context_never_follows_a_symlink_out_of_the_clone(tmp_path):
    """A cloned repo can commit ``settings.py -> <host file>`` or ``conf -> <host dir>``; naming that file
    in an edit instruction must NOT put the host file's content in the model prompt. Covers the symlinked
    FILE and the symlinked PARENT DIRECTORY (a final-component check alone misses the second)."""
    wd = Path(_git_repo(tmp_path))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("TOP-SECRET-HOST-FILE\n", encoding="utf-8")
    (wd / "settings.py").symlink_to(outside / "secret.txt")
    (wd / "conf").symlink_to(outside, target_is_directory=True)
    ctx = dev_edit._read_context(str(wd), ["settings.py", "conf/secret.txt", "x.py"])
    assert ctx == [("x.py", "a = 1\n")], "a symlink in the clone leaked an out-of-clone file to the model"


def test_read_context_refuses_a_link_but_keeps_real_files_behind_an_in_clone_dir_link(tmp_path):
    """A symlinked FILE is refused even when it resolves inside the clone (it can alias ``.git/config``, and
    ``git apply`` cannot patch through a link anyway); a real file reached through a directory link that
    stays INSIDE the clone is still readable — containment, not 'no links anywhere', is the rule."""
    wd = Path(_git_repo(tmp_path))
    (wd / "pkg").mkdir()
    (wd / "pkg" / "ok.py").write_text("b = 2\n", encoding="utf-8")
    (wd / "alias.py").symlink_to(wd / "x.py")
    (wd / "pkglink").symlink_to(wd / "pkg", target_is_directory=True)
    ctx = dev_edit._read_context(str(wd), ["alias.py", "pkglink/ok.py", "pkg/ok.py"])
    assert ctx == [("pkglink/ok.py", "b = 2\n"), ("pkg/ok.py", "b = 2\n")]


def test_apply_never_writes_through_a_patch_symlink_planted_in_the_clone(tmp_path, monkeypatch):
    """A cloned repo can commit ``.vigil-fix.patch -> <operator-writable host file>``. The patch is staged
    OUTSIDE the clone, so applying a reviewed diff leaves the link's target byte-identical, does not touch
    the repo's own entry, and leaves no staged patch behind. The ``git apply`` argv is observed, so staging
    the patch anywhere inside the clone (even under a fresh random name) fails this test too."""
    import vigil_integration.live.codefix_runner as cr
    applied_from: list = []
    real_runner = cr.subprocess_runner

    def _spy(argv, **kw):
        if "apply" in argv:
            applied_from.append(argv[-1])
        return real_runner(argv, **kw)

    monkeypatch.setattr(cr, "subprocess_runner", _spy)
    wd = Path(_git_repo(tmp_path))
    victim = tmp_path / "authorized_keys"
    victim.write_text("ORIGINAL\n", encoding="utf-8")
    planted = wd / ".vigil-fix.patch"
    planted.symlink_to(victim)
    out = dev_edit.apply_dev_edit(str(wd), _DIFF, operator_present=True)
    assert victim.read_text(encoding="utf-8") == "ORIGINAL\n", "the patch was written through a repo symlink"
    assert applied_from, "git apply never ran"
    for patch in applied_from:                       # staged in the clone's parent, never inside the clone
        assert os.path.dirname(patch) == str(tmp_path), patch
    assert out["ok"] is True and out["applied"] == ["x.py"]
    assert (wd / "x.py").read_text() == "a = 2\n"
    assert planted.is_symlink(), "the repo's own entry must not be touched"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["authorized_keys", "repo"], "a staged patch was left behind"


# --- clone CONTENT changes while it is read: code the repo runs (its tests, in the sandbox) can swap ---------

def _swap_after_check(monkeypatch, swap):
    """Run ``swap`` in the window between the path CHECK and the read — the window code running in the
    clone at the same time (its own test suite, bound read-write into the sandbox) gets for free."""
    from vigil_integration.remediation import codefix
    real_check = codefix.confined_repo_file

    def _check_then_swap(root, rel):
        out = real_check(root, rel)
        if out:
            swap()
        return out

    monkeypatch.setattr(codefix, "confined_repo_file", _check_then_swap)
    monkeypatch.setattr(dev_edit, "confined_repo_file", _check_then_swap, raising=False)


def test_read_context_refuses_a_file_swapped_for_a_link_after_the_check(tmp_path, monkeypatch):
    wd = Path(_git_repo(tmp_path))
    secret = tmp_path / "host_secret"
    secret.write_text("HOST-SECRET\n", encoding="utf-8")
    (wd / "settings.py").write_text("repo = 1\n", encoding="utf-8")

    def swap():
        (wd / ".l").symlink_to(secret)
        os.replace(wd / ".l", wd / "settings.py")

    _swap_after_check(monkeypatch, swap)
    assert dev_edit._read_context(str(wd), ["settings.py"]) == [], "a swapped-in link leaked a host file"


def test_read_context_refuses_a_link_swapped_in_after_the_check_even_inside_the_clone(tmp_path, monkeypatch):
    """Same rule as the static check: a name that IS a link is not read, even when it points inside the
    clone (``settings.py -> .git/config`` would alias git's own config into the model prompt)."""
    wd = Path(_git_repo(tmp_path))
    (wd / "settings.py").write_text("repo = 1\n", encoding="utf-8")

    def swap():
        (wd / ".l").symlink_to(wd / ".git" / "config")
        os.replace(wd / ".l", wd / "settings.py")

    _swap_after_check(monkeypatch, swap)
    assert dev_edit._read_context(str(wd), ["settings.py"]) == []


def test_read_context_refuses_a_parent_dir_swapped_for_a_link_after_the_check(tmp_path, monkeypatch):
    """O_NOFOLLOW only guards the LAST component; a parent directory swapped for a link is caught by
    checking where the opened file really is."""
    wd = Path(_git_repo(tmp_path))
    (wd / "pkg").mkdir()
    (wd / "pkg" / "f.py").write_text("repo = 2\n", encoding="utf-8")
    hostdir = tmp_path / "hostdir"
    hostdir.mkdir()
    (hostdir / "f.py").write_text("HOST-DIR-SECRET\n", encoding="utf-8")

    def swap():
        os.rename(wd / "pkg", wd / ".hidden")
        (wd / "pkg").symlink_to(hostdir, target_is_directory=True)

    _swap_after_check(monkeypatch, swap)
    assert dev_edit._read_context(str(wd), ["pkg/f.py"]) == [], "a swapped-in parent link leaked a host file"


def test_read_context_refuses_a_fifo_swapped_in_after_the_check_without_blocking(tmp_path, monkeypatch):
    """A FIFO swapped in after the check would block a plain open() forever (no writer); the read opens
    non-blocking and refuses anything that is not a regular file."""
    wd = Path(_git_repo(tmp_path))
    (wd / "settings.py").write_text("repo = 1\n", encoding="utf-8")

    def swap():
        os.unlink(wd / "settings.py")
        os.mkfifo(wd / "settings.py")

    _swap_after_check(monkeypatch, swap)
    assert dev_edit._read_context(str(wd), ["settings.py"]) == []


def test_read_context_still_reads_a_real_in_clone_file_swapped_in_after_the_check(tmp_path, monkeypatch):
    """The open-file check refuses only an escape: a file replaced by another REAL in-clone file in that
    window is still read, and so is an untouched one."""
    wd = Path(_git_repo(tmp_path))
    (wd / "settings.py").write_text("repo = 1\n", encoding="utf-8")

    def swap():
        (wd / ".r").write_text("repo = 3\n", encoding="utf-8")
        os.replace(wd / ".r", wd / "settings.py")

    _swap_after_check(monkeypatch, swap)
    assert dev_edit._read_context(str(wd), ["settings.py", "x.py"]) == [("settings.py", "repo = 3\n"),
                                                                        ("x.py", "a = 1\n")]
