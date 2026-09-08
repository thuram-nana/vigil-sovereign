"""Phase E.2 — the agentic (Strix) deep-fix front-end + its trust contract.

The agent is UNTRUSTED: whatever diff it produces is re-verified through the gated deep-fix ladder. These
exercise the orchestrator with an INJECTED fake agent (no Docker, no LLM) — a good agent diff earns
verified-no-pr; an empty/un-appliable one fails closed to no-agent-diff. Needs framework (DAA oracle), so it
importorskips it and runs in the offense leg."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

import pytest

pytest.importorskip("framework")

from vigil_integration import codescan, strix_fix                          # noqa: E402
from vigil_integration.live.codefix_runner import CodefixConfig            # noqa: E402
from vigil_integration.remediation.triage import TriageFinding            # noqa: E402

_HAVE = bool(shutil.which("bwrap") and shutil.which("git"))
_sandbox = pytest.mark.skipif(not _HAVE, reason="needs bwrap + git")

REF = codescan.make_ref("DAA-WEAK-HASH", "svc/config.py", 3)
_GOOD = ("--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,3 +1,3 @@\n import hashlib\n def f(p):\n"
         "-    return hashlib.md5(p).hexdigest()\n+    return hashlib.sha256(p).hexdigest()\n")


def test_extract_keeps_headered_diff_drops_headerless(tmp_path):
    (tmp_path / "vulnerabilities").mkdir()
    (tmp_path / "penetration_test_report.md").write_text(
        "# r\n```diff\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n```\n", encoding="utf-8")
    (tmp_path / "vulnerabilities" / "v.md").write_text("```diff\nno headers here\n```\n", encoding="utf-8")
    ex = strix_fix.extract_unified_diff(str(tmp_path))
    assert "--- a/x.py" in ex and "no headers here" not in ex


def test_extract_drops_workspace_fix_rooted_diff(tmp_path):
    # W4 fails-closed: if the agent emits a diff rooted at the writable /workspace/fix copy (headers NOT a//b/),
    # extraction DROPS it (only git-appliable a//b//dev/null/diff --git headers survive) -> empty -> no-agent-diff.
    (tmp_path / "penetration_test_report.md").write_text(
        "# r\n```diff\n--- /workspace/fix/svc/config.py\n+++ /workspace/fix/svc/config.py\n"
        "@@ -1 +1 @@\n-md5\n+sha256\n```\n", encoding="utf-8")
    assert strix_fix.extract_unified_diff(str(tmp_path)).strip() == ""


def test_default_fix_instruction_mentions_diff_and_finding():
    f = TriageFinding(ref=REF, bug_class="Weak Cryptography", severity="Medium", target="svc/config.py:3",
                      confirmed=True, evidence_ref="sha256:x")
    instr = strix_fix.default_fix_instruction(f, test_cmd="python3 -m compileall -q .")
    assert REF in instr and "diff" in instr.lower() and "compileall" in instr
    # W4: the RO-mount working-copy guidance is present (the mount is read-only; edit a writable copy)
    assert "READ-ONLY" in instr and "/workspace" in instr and "cp -a" in instr


def test_run_strix_fix_uses_mount_not_target_and_captures_argv(tmp_path):
    # W4: the launch argv must use --mount (bind, no OOM copy), NOT --target (file-by-file stream = exit 137).
    seen = {}
    def _fake_launch(argv, *, base_dir, runner):
        seen["argv"] = list(argv)
        return 0                                  # pretend Strix ran and exited clean
    root = str(tmp_path / "clone"); os.makedirs(root, exist_ok=True)
    diff, note = strix_fix.run_strix_fix(root, "fix it", base_dir=str(tmp_path / "b"), launch=_fake_launch)
    assert "--mount" in seen["argv"] and root in seen["argv"]
    assert "--target" not in seen["argv"]                       # the OOM-prone path is gone
    assert seen["argv"][seen["argv"].index("--mount") + 1] == root
    assert diff == "" and "no git-appliable diff" in note        # empty report dir -> fail-closed, no crash


def _repo(tmp_path):
    r = tmp_path / "repo"; (r / "svc").mkdir(parents=True)
    (r / "svc" / "config.py").write_text("import hashlib\ndef f(p):\n    return hashlib.md5(p).hexdigest()\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(r), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"], check=True)
    return r


def _f(repo):
    return TriageFinding(ref=REF, bug_class="Weak Cryptography", severity="Medium", target="svc/config.py:3",
                         confirmed=True, evidence_ref="sha256:x", target_repo=str(repo), source="daa:DAA-WEAK-HASH")


@_sandbox
def test_agentic_workspace_prefixed_diff_fails_closed(tmp_path):
    # W4 fails-closed: an a/fix/... two-level-prefixed git diff survives extraction (diff --git header) but
    # `git apply -p1` strips only `a/`, leaving `fix/svc/config.py` which is NOT in the clone -> build-failed,
    # NEVER verified-no-pr / remediated. Proves a wrong-prefix agent diff cannot forge a verification.
    repo = _repo(tmp_path)
    bad = ("--- a/fix/svc/config.py\n+++ b/fix/svc/config.py\n@@ -1,3 +1,3 @@\n import hashlib\n def f(p):\n"
           "-    return hashlib.md5(p).hexdigest()\n+    return hashlib.sha256(p).hexdigest()\n")
    cfg = CodefixConfig(target_repo=str(repo), base_dir=str(tmp_path / "b"),
                        build_cmd="python3 -m compileall -q .", apply_edits=True, model="x")
    r = strix_fix.agentic_deepfix(_f(repo), config=cfg, verify_oracle=codescan.build_code_fix_oracle(REF),
                                  produce_diff=lambda root, instr: (bad, "fake"))
    assert r.status != "verified-no-pr" and r.remediated is False


@_sandbox
def test_agentic_good_diff_is_reverified(tmp_path):
    repo = _repo(tmp_path)
    cfg = CodefixConfig(target_repo=str(repo), base_dir=str(tmp_path / "b"),
                        build_cmd="python3 -m compileall -q .", apply_edits=True, model="x")
    r = strix_fix.agentic_deepfix(_f(repo), config=cfg, verify_oracle=codescan.build_code_fix_oracle(REF),
                                  produce_diff=lambda root, instr: (_GOOD, "fake"))
    assert r.status == "verified-no-pr" and r.remediated is False


def test_agentic_no_diff_fails_closed(tmp_path):
    repo = _repo(tmp_path)
    cfg = CodefixConfig(target_repo=str(repo), base_dir=str(tmp_path / "b"), apply_edits=True, model="x")
    r = strix_fix.agentic_deepfix(_f(repo), config=cfg, verify_oracle=codescan.build_code_fix_oracle(REF),
                                  produce_diff=lambda root, instr: ("", "agent produced nothing"))
    assert r.status == "no-agent-diff" and r.remediated is False


def test_agentic_agent_error_fails_closed(tmp_path):
    repo = _repo(tmp_path)
    cfg = CodefixConfig(target_repo=str(repo), base_dir=str(tmp_path / "b"), apply_edits=True, model="x")
    def _boom(root, instr): raise RuntimeError("docker down")
    r = strix_fix.agentic_deepfix(_f(repo), config=cfg, verify_oracle=codescan.build_code_fix_oracle(REF),
                                  produce_diff=_boom)
    assert r.status == "no-agent-diff" and r.remediated is False   # an agent crash never verifies
