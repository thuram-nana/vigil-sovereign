"""ARTIFICER (SIGIL §4.4) — engineering: drives headless Claude Code against a repo to own a
coding task end to end. Ceiling A2 (a PR ready-for-review queues for approval); `git push` to a
protected branch, deploys, and dependency additions are A3 — ARTIFICER NEVER pushes.

Correctness discipline (the §4.4 focus): it runs the tests BEFORE claiming done — a PR is
proposed ONLY if the test command passes on the change; a failing change is reported, not
shipped. The result is a local branch + a plain-language diff summary, QUEUED for the human to
review and push. The coder is pluggable: `ClaudeCoder` (headless `claude -p`) or a deterministic
test double."""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Protocol, runtime_checkable

from ..reuse import sha256_hex
from .base import Agent, AgentResult, Proposal, Tier

# commands that "pass" trivially — a PR must never claim tests passing on one of these.
_TRIVIAL_TEST = frozenset({(), ("true",), (":",), ("/bin/true",), ("/usr/bin/true",)})


def _git(repo: str, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def _slug(task: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", task.lower()).strip("-")[:28] or "task"
    return f"{base}-{sha256_hex(task.encode())[:6]}"   # unique per task, stable


@runtime_checkable
class Coder(Protocol):
    def code(self, task: str, workdir: str) -> str: ...   # perform the change; return a summary


class ClaudeCoder:
    """Headless Claude Code (`claude -p`) run inside the repo — the real ARTIFICER worker."""
    def __init__(self, claude_bin: str = "/home/kali/.local/bin/claude", timeout: int = 600):
        self.claude_bin, self.timeout = claude_bin, timeout

    def code(self, task: str, workdir: str) -> str:
        prompt = (f"You are working in the repo at {workdir}. Task: {task}\n"
                  "Make the minimal change to accomplish it. Do not run git. Do not touch unrelated files.")
        # acceptEdits lets the headless coder actually apply Edit/Write in its sandboxed repo (it
        # cannot prompt for permission in -p mode). ARTIFICER's isolation is the per-task branch;
        # git push / deploy stay A3 and are never invoked here.
        try:
            proc = subprocess.run(
                [self.claude_bin, "-p", prompt, "--permission-mode", "acceptEdits"],
                cwd=workdir, capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.SubprocessError, OSError) as e:
            return f"(coder error: {e})"
        return (proc.stdout or "").strip()[:400]


class Artificer(Agent):
    name = "ARTIFICER"
    mandate = "own background coding tasks: tests before done, PRs not pushes"
    ceiling = Tier.A2

    def run(self, task: str, *, repo: str, test_cmd: Optional[List[str]] = None,
            coder: Optional[Coder] = None, branch: Optional[str] = None) -> AgentResult:
        coder = coder or ClaudeCoder()
        base = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
        branch = branch or f"artificer/{_slug(task)}"

        # ISOLATION: the coder works in a dedicated git WORKTREE off `base`, so the real working
        # tree is never touched, no pre-existing/unrelated edits get bundled, and a failure leaves
        # the main repo exactly as it was. The per-task branch survives for the human to review.
        _git(repo, "worktree", "prune", check=False)
        wt = tempfile.mkdtemp(prefix="artificer-wt-")
        _git(repo, "worktree", "add", "-B", branch, wt, base)
        try:
            summary = coder.code(task, wt)
            changed = bool(_git(wt, "status", "--porcelain", check=False).strip())
            diff = _git(wt, "diff", "--stat", check=False).strip()

            if not changed:
                res = AgentResult(agent=self.name)
                res.notes.append("no change produced for the task — nothing to propose.")
                return res

            real_test = test_cmd is not None and tuple(test_cmd) not in _TRIVIAL_TEST
            if not real_test:
                # NEVER claim "tests passing" without a real test command — record UNVERIFIED, withhold PR.
                res = self._dispatch([Proposal("finding", {
                    "summary": f"ARTIFICER task '{task}': change made but NO real test command was run — UNVERIFIED, PR withheld",
                    "branch": branch, "diffstat": diff, "coder": summary}, Tier.A1)])
                res.notes.append("no real test command → change is UNVERIFIED; PR withheld (correctness discipline)")
                return res

            test = subprocess.run(test_cmd, cwd=wt, capture_output=True, text=True)
            if test.returncode != 0:
                tail = (test.stdout + test.stderr).strip().splitlines()
                res = self._dispatch([Proposal("finding", {
                    "summary": f"ARTIFICER task '{task}': change made but tests FAIL — PR withheld",
                    "branch": branch, "test_tail": tail[-3:] if tail else [], "diffstat": diff}, Tier.A1)])
                res.notes.append("tests failed after the change — PR withheld (correctness discipline)")
                return res

            # tests genuinely pass → commit on the branch (in the worktree), propose a PR (A2, QUEUED).
            _git(wt, "add", "-A")
            _git(wt, "commit", "-m", f"ARTIFICER: {task}", check=False)
            res = self._dispatch([Proposal("pr", {
                "subject": task, "branch": branch, "base": base, "diffstat": diff,
                "summary": summary, "tests": f"passing ({' '.join(test_cmd)})",
                "note": "ready-for-review; ARTIFICER does NOT push — a human reviews and pushes"}, Tier.A2)])
            res.notes.append(f"task done, tests PASS → PR proposed on branch '{branch}' (A2, awaiting approval)")
            return res
        finally:
            _git(repo, "worktree", "remove", "--force", wt, check=False)
            shutil.rmtree(wt, ignore_errors=True)
