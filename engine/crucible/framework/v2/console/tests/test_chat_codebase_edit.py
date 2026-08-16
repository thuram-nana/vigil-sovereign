"""Phase D2 console wrappers — propose/apply a dev-mode codebase edit, confined to a repo THIS chat
cloned. The load-bearing control: `_confined_clone_path` — an edit can only ever touch a directory under
`<live>/clones/<chat>/`, never an arbitrary path the caller names. Needs `vigil_gateway` transitively
(dev_edit → codefix_runner → executor), so importorskip (runs in P5, skips in CRUCIBLE-core).
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
