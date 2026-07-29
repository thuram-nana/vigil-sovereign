"""T2 — the `vigil terminal` native verb: gate + sealed spine signer reused from build_terminal_runtime.

The verb runs a governed LOCAL read/inspect command through the SAME conjunctive gate + spine signer the live
engine uses (``build_terminal_runtime`` reuses ``provision_authority`` → ``_build_gate`` → ``_approval_gate`` →
``load_or_create_spine_keypair``). terminal.run classifies A2, so under the A1 offense ceiling it QUEUES and never
auto-runs; ``--approve`` (the SAME wiring approval path) upgrades the queue to allow. The allowlist inside
``execute_terminal`` still bounds it — an off-allowlist command is refused even with ``--approve``. Every run is a
signed, redacted ExecRecord appended to the terminal history.

Framework-dependent (provisions a real signed authority under --base-dir), so this runs in the OFFENSE process.
Run: PYTHONPATH=integration:engine/crucible:gateway pytest integration/tests/test_cli_terminal.py -q
"""

from __future__ import annotations

import json

from vigil_integration.cli import main


def _run(argv, capsys):
    rc = main(argv)
    out = capsys.readouterr().out
    return rc, json.loads(out)


def test_terminal_queues_without_approve(tmp_path, capsys):
    # terminal.run is A2 → under the A1 ceiling the conjunctive gate QUEUES it; with no --approve the executor
    # denies at authorization. The command is prepared + gated but never runs.
    rc, res = _run(["terminal", "ls", "--base-dir", str(tmp_path)], capsys)
    assert rc == 2
    assert res["ran"] is False and res["outcome"] == "deny"
    assert not (tmp_path / "terminal-history.jsonl").exists()      # nothing recorded for a non-run


def test_terminal_runs_with_approve_and_signs(tmp_path, capsys):
    rc, res = _run(["terminal", "echo", "OBSIDIAN-TEST-T2", "--approve", "--base-dir", str(tmp_path)], capsys)
    assert rc == 0
    assert res["ran"] is True and res["outcome"] == "ran" and res["tier"] == "A2"   # recorded at the WARDEN tier
    assert res["exit_code"] == 0 and "OBSIDIAN-TEST-T2" in res["stdout"]
    assert res["record_id"]                                        # a signed, redacted spine record was produced
    hist = tmp_path / "terminal-history.jsonl"
    assert hist.is_file()
    row = json.loads(hist.read_text(encoding="utf-8").splitlines()[0])
    assert row["tool"] == "terminal.run" and row["argv"][0] == "echo" and row["signature"]


def test_terminal_off_allowlist_refused_even_with_approve(tmp_path, capsys):
    # The allowlist DECIDES, not the operator's --approve: a network/interpreter/writer binary can never run.
    # A command with internal flags is passed as ONE argument (the quoted / console form, ``vigil terminal "…"``).
    for evil in ("curl http://127.0.0.1", "python -c 1", "rm -rf x"):
        rc, res = _run(["terminal", evil, "--approve", "--base-dir", str(tmp_path)], capsys)
        assert rc == 2 and res["ran"] is False, evil
        assert "allowlist" in res["reason"], evil


def test_terminal_shell_metacharacter_refused(tmp_path, capsys):
    # No shell is ever invoked; a redirect/substitution/subshell/separator is refused whole. (The pipe `|` is
    # NOT a shell metachar here — it is an allowlisted-pipeline separator we parse ourselves; a pipeline whose
    # stage is off-allowlist is refused by the allowlist, tested below.)
    for evil in ("cat a > b", "cat `id`", "echo $(id)", "ls; whoami"):
        rc, res = _run(["terminal", evil, "--approve", "--base-dir", str(tmp_path)], capsys)
        assert rc == 2 and res["ran"] is False, evil
        assert "metacharacter" in res["reason"], evil


def test_terminal_pipeline_off_allowlist_stage_refused(tmp_path, capsys):
    # A pipeline may only chain ALLOWLISTED read tools — a network/interpreter stage is refused (no egress).
    rc, res = _run(["terminal", "cat a | curl http://x", "--approve", "--base-dir", str(tmp_path)], capsys)
    assert rc == 2 and res["ran"] is False and "allowlist" in res["reason"]
