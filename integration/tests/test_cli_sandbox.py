"""The `vigil sandbox` native verb: gate + sealed spine signer reused from build_terminal_runtime, over the
network-isolated bwrap sandbox (executor.execute_sandbox).

sandbox.exec classifies A3, so under the A1 offense ceiling the conjunctive gate QUEUES it and it never
auto-runs; ``--approve`` (the SAME wiring approval path) upgrades the queue to allow. With approval it runs an
ARBITRARY command inside the sandbox (writes confined to <base-dir>/sandbox-workspace) and appends a signed,
redacted ExecRecord to the sandbox history.

Framework-dependent (provisions a real signed authority under --base-dir), so this runs in the OFFENSE
process. The run-with-approve case additionally needs a working bwrap and is skipped where userns is disabled.
Run: PYTHONPATH=integration:engine/crucible:gateway pytest integration/tests/test_cli_sandbox.py -q
"""

from __future__ import annotations

import json
import subprocess

import pytest

from vigil_integration.cli import main
from vigil_integration.live.sandbox_exec import bwrap_path


def _bwrap_works() -> bool:
    b = bwrap_path()
    if not b:
        return False
    try:
        p = subprocess.run([b, "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--", "/bin/true"],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        return p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


_needs_bwrap = pytest.mark.skipif(not _bwrap_works(), reason="bwrap cannot construct namespaces here")


def _run(argv, capsys):
    rc = main(argv)
    out = capsys.readouterr().out
    return rc, json.loads(out)


def test_sandbox_queues_without_approve(tmp_path, capsys):
    # sandbox.exec is A3 → under the A1 ceiling the gate QUEUES it; no --approve ⇒ the executor denies at
    # authorization. Nothing runs, nothing is recorded — and this needs NO bwrap (the gate denies first).
    rc, res = _run(["sandbox", "echo hi", "--base-dir", str(tmp_path)], capsys)
    assert rc == 2
    assert res["ran"] is False and res["outcome"] == "deny" and res["tool"] == "sandbox.exec"
    assert not (tmp_path / "sandbox-history.jsonl").exists()


@_needs_bwrap
def test_sandbox_runs_with_approve_confined_and_signs(tmp_path, capsys):
    rc, res = _run(["sandbox", "echo OBSIDIAN-SBX > out.txt; cat out.txt", "--approve",
                    "--base-dir", str(tmp_path)], capsys)
    assert rc == 0
    assert res["ran"] is True and res["outcome"] == "ran" and res["tier"] == "A3"
    assert "OBSIDIAN-SBX" in res["stdout"] and res["record_id"]
    # the write landed in the confined sandbox workspace (and nowhere else)
    assert (tmp_path / "sandbox-workspace" / "out.txt").read_text().strip() == "OBSIDIAN-SBX"
    hist = tmp_path / "sandbox-history.jsonl"
    assert hist.is_file()
    row = json.loads(hist.read_text(encoding="utf-8").splitlines()[0])
    assert row["tool"] == "sandbox.exec" and row["signature"]
