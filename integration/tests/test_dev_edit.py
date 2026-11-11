"""Phase D2 — general dev-mode codebase edits: propose a change as a unified diff, review, approve, apply.
GENERAL software editing (no security-fix framing, no oracle-confirmed FACT required) that still reuses
the hardened primitives: sovereignty-gated propose, path-confined diff parse, clone-only git-apply, and a
per-edit A2 gate that opens only when the operator is present.

`vigil_gateway` is needed transitively (codefix_runner → executor), so importorskip — runs in P5, skips
in CRUCIBLE-core (matching the clone tests).
"""
from __future__ import annotations

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


def test_apply_never_writes_through_a_patch_symlink_planted_in_the_clone(tmp_path):
    """A cloned repo can commit ``.vigil-fix.patch -> <operator-writable host file>``. The patch is staged
    OUTSIDE the clone, so applying a reviewed diff leaves the link's target byte-identical, does not touch
    the repo's own entry, and leaves no staged patch behind."""
    wd = Path(_git_repo(tmp_path))
    victim = tmp_path / "authorized_keys"
    victim.write_text("ORIGINAL\n", encoding="utf-8")
    planted = wd / ".vigil-fix.patch"
    planted.symlink_to(victim)
    out = dev_edit.apply_dev_edit(str(wd), _DIFF, operator_present=True)
    assert victim.read_text(encoding="utf-8") == "ORIGINAL\n", "the patch was written through a repo symlink"
    assert out["ok"] is True and out["applied"] == ["x.py"]
    assert (wd / "x.py").read_text() == "a = 2\n"
    assert planted.is_symlink(), "the repo's own entry must not be touched"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["authorized_keys", "repo"], "a staged patch was left behind"
