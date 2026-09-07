"""DEEP FIX (Claude-Code-class, gated, oracle-verified) — Phases A-D.

Repo-aware multi-file context (A), a real build/test gate in the bwrap sandbox clone (B), an iterate-until-green
loop that self-corrects on failure (C), and a pre-PR oracle verification that earns the honest `verified-no-pr`
without ever minting the signed `remediated` (D). The load-bearing invariant: a fix that does NOT clear the
finding is `verify-still-vulnerable`, never verified — a false 'fixed' stays impossible.

Needs the framework (DAA) + git + bwrap for the sandbox legs, so it importorskips framework and skips the
sandbox tests when the tools are absent. Runs in the OFFENSE CI leg."""
from __future__ import annotations

import shutil
import subprocess
import tempfile

import pytest

pytest.importorskip("framework")   # DAA analyzers — offense leg only

from vigil_integration import codescan                                     # noqa: E402
from vigil_integration.live.codefix_runner import CodefixConfig, autopatch_live  # noqa: E402
from vigil_integration.remediation.buildsys import detect_build_plan       # noqa: E402
from vigil_integration.remediation.triage import TriageFinding             # noqa: E402

_HAVE_SANDBOX = bool(shutil.which("bwrap") and shutil.which("git"))
_sandbox = pytest.mark.skipif(not _HAVE_SANDBOX, reason="needs bwrap + git for the sandbox build gate")


def _mkrepo(tmp_path):
    r = tmp_path / "repo"; (r / "svc").mkdir(parents=True)
    (r / "svc" / "config.py").write_text(
        "import hashlib\n\n\ndef fingerprint(pw):\n    # weak hash\n    return hashlib.md5(pw.encode()).hexdigest()\n",
        encoding="utf-8")
    (r / "svc" / "util.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(r), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"], check=True)
    return r


REF = "DAA-WEAK-HASH~c3ZjL2NvbmZpZy5weQ~L6"   # svc/config.py:6


def _finding(repo):
    return TriageFinding(ref=REF, bug_class="Weak Cryptography", severity="Medium", target="svc/config.py:6",
                         confirmed=True, evidence_ref="sha256:demo", target_repo=str(repo), source="daa:DAA-WEAK-HASH")


def _client(diff):
    class _Msg:
        def __init__(s, t): s.content = [type("B", (), {"text": t, "type": "text"})()]
    return type("C", (), {"messages": type("M", (), {"create": staticmethod(lambda **k: _Msg(diff))})()})()


_GOOD = ("--- a/svc/config.py\n+++ b/svc/config.py\n@@ -4,3 +4,3 @@\n def fingerprint(pw):\n"
         "     # weak hash\n-    return hashlib.md5(pw.encode()).hexdigest()\n+    return hashlib.sha256(pw.encode()).hexdigest()\n")
_BROKEN = ("--- a/svc/config.py\n+++ b/svc/config.py\n@@ -4,3 +4,3 @@\n def fingerprint(pw):\n"
           "     # weak hash\n-    return hashlib.md5(pw.encode()).hexdigest()\n+    return hashlib.sha256(pw.encode(.hexdigest()\n")
_NOOP = "--- a/svc/util.py\n+++ b/svc/util.py\n@@ -1,2 +1,3 @@\n def helper():\n+    # noop\n     return 1\n"


# ---- Phase A: repo-aware context ----
def test_gather_repo_context_includes_siblings(tmp_path):
    repo = _mkrepo(tmp_path)
    from vigil_integration.live.codefix_runner import _gather_repo_context
    paths = [p for p, _ in _gather_repo_context(str(repo), "svc/config.py")]
    assert "svc/config.py" in paths and "svc/util.py" in paths   # same-dir siblings


# ---- Phase B: build-system detector ----
def test_buildsys_detects_python_and_skips_unknown(tmp_path):
    repo = _mkrepo(tmp_path)
    plan = detect_build_plan(str(repo))
    assert plan.language == "python" and "compileall" in plan.build_cmd and plan.test_cmd == ""
    bare = tmp_path / "bare"; bare.mkdir()
    assert detect_build_plan(str(bare)).build_cmd == ""   # nothing detected → skip honestly


def _cfg(repo, tmp_path):
    plan = detect_build_plan(str(repo))
    return CodefixConfig(target_repo=str(repo), base_dir=str(tmp_path / "b"),
                         build_cmd=plan.build_cmd, apply_edits=True, model="x")


# ---- Phase B/D: good fix verifies; broken/no-op never do ----
@_sandbox
def test_good_fix_reaches_verified_no_pr(tmp_path):
    repo = _mkrepo(tmp_path)
    r = autopatch_live(_finding(repo), config=_cfg(repo, tmp_path), client=_client(_GOOD),
                       verify_oracle=codescan.build_code_fix_oracle(REF), verify_before_pr=True, max_fix_attempts=2)
    assert r.status == "verified-no-pr" and r.remediated is False and r.patched_paths == ["svc/config.py"]


@_sandbox
def test_broken_fix_is_build_failed_not_verified(tmp_path):
    repo = _mkrepo(tmp_path)
    r = autopatch_live(_finding(repo), config=_cfg(repo, tmp_path), client=_client(_BROKEN),
                       verify_oracle=codescan.build_code_fix_oracle(REF), verify_before_pr=True, max_fix_attempts=1)
    assert r.status == "build-failed" and r.remediated is False


@_sandbox
def test_noop_fix_is_still_vulnerable_never_verified(tmp_path):
    repo = _mkrepo(tmp_path)
    r = autopatch_live(_finding(repo), config=_cfg(repo, tmp_path), client=_client(_NOOP),
                       verify_oracle=codescan.build_code_fix_oracle(REF), verify_before_pr=True, max_fix_attempts=1)
    # the no-op builds fine but the finding still fires → NEVER verified/remediated (no false 'fixed')
    assert r.status == "verify-still-vulnerable" and r.remediated is False


# ---- Phase C: iterate-until-green self-corrects ----
@_sandbox
def test_iterate_recovers_broken_then_good(tmp_path):
    repo = _mkrepo(tmp_path)
    seq = [_BROKEN, _GOOD]
    class _Seq:
        def __init__(s): s.n = 0
        def create(s, **k):
            t = seq[min(s.n, len(seq) - 1)]; s.n += 1
            return type("Msg", (), {"content": [type("B", (), {"text": t, "type": "text"})()]})()
    client = type("C", (), {"messages": _Seq()})()
    r = autopatch_live(_finding(repo), config=_cfg(repo, tmp_path), client=client,
                       verify_oracle=codescan.build_code_fix_oracle(REF), verify_before_pr=True, max_fix_attempts=3)
    assert r.status == "verified-no-pr" and r.remediated is False


# ---- Phase D doctrine: verified-no-pr can NEVER be remediated (type-lock intact) ----
@_sandbox
def test_verified_no_pr_never_mints_remediated(tmp_path):
    repo = _mkrepo(tmp_path)
    r = autopatch_live(_finding(repo), config=_cfg(repo, tmp_path), client=_client(_GOOD),
                       verify_oracle=codescan.build_code_fix_oracle(REF), verify_before_pr=True, max_fix_attempts=1)
    assert r.remediated is False and not r.opened_pr and not r.evidence_ref


# ---- security: repo-context must not follow a symlink out of the repo (red-pen HIGH #5) ----
def test_context_refuses_symlink_escape(tmp_path):
    import os
    from vigil_integration.live.codefix_runner import _gather_repo_context
    repo = tmp_path / "repo"; (repo / "svc").mkdir(parents=True)
    (repo / "svc" / "config.py").write_text("import hashlib\n", encoding="utf-8")
    secret = tmp_path / "outside.py"; secret.write_text('KEY="sk-DO-NOT-EGRESS"\n', encoding="utf-8")
    os.symlink(str(secret), str(repo / "svc" / "notes.py"))   # attacker-planted .py symlink out of repo
    ctx = _gather_repo_context(str(repo), "svc/config.py")
    paths = [pth for pth, _ in ctx]; blob = "".join(c for _, c in ctx)
    assert "svc/notes.py" not in paths and "DO-NOT-EGRESS" not in blob


# ---- security: a rename to an unscanned extension must NOT read as cleared (evasion guard) ----
def test_rename_to_unscanned_extension_is_not_cleared(tmp_path):
    src = tmp_path / "src"; (src).mkdir()
    (src / "config.py").write_text("import hashlib\ndef f(p):\n    return hashlib.md5(p).hexdigest()\n", encoding="utf-8")
    ref = codescan.make_ref("DAA-WEAK-HASH", "config.py", 3)
    assert codescan.verify_finding_cleared(root=str(src), ref=ref)["cleared"] is False   # still there
    # "fix" = rename the vulnerable file to an unscanned extension (the pattern is hidden, not removed)
    (src / "config.py").rename(src / "config.txt")
    res = codescan.verify_finding_cleared(root=str(src), ref=ref)
    assert res["cleared"] is False and res.get("path_removed") is True   # NOT a false 'fixed'
