"""codefix_runner — the LIVE executors for the sovereign auto-patch loop (VIGIL-FUSION, live slice LAP-1).

The remediation/autopatch pipelines (``vigil_integration.autopatch.autopatch`` / ``remediation.run_codefix``)
are pure, fully-injected libraries — they enforce every sovereign invariant (confirmed-FACT-only,
per-file approval with a timeout=REJECT flip, m-of-n for the PR, remediated-only-when-the-exploit-oracle-
goes-silent) but do NOTHING real until a caller supplies executors. This module is the first live caller.

LAP-1 is deliberately NON-DESTRUCTIVE and OFF-by-default at the dangerous legs:
  * PROPOSE  — a real Claude coder returns a minimal unified diff for a CONFIRMED finding (blind/best-effort
    file context read from a LOCAL target repo; no key ⇒ no patch, fail-closed).
  * CLONE    — a real ``git clone`` of the target repo into a disposable workdir + a fix branch. The source
    repo is NEVER modified (we operate on the clone).
  * APPLY    — the approved diffs are ``git apply``'d into the clone (``--check`` first); this is the
    "sandbox build" leg. Edits are approved ONLY when the operator opts in (``apply_edits``); the default is
    a timeout ⇒ REJECT.
  * OPEN-PR  — DISABLED. The destructive PR leg's gate denies (no m-of-n destruction authority is wired
    here) and the executor itself refuses. Real ``git push`` + ``gh pr create`` + the m-of-n quorum + the
    exploit-oracle re-fire + the signed 'remediated' cert are the PROVISIONED, destructive follow-up
    (LAP-3) — they require operator credentials and the quorum keys and are intentionally not enabled here.

Import-clean: stdlib + the injected library seams only; no ``framework``/``strix``/``sigil``.
"""
from __future__ import annotations

import os
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from vigil_core.gate import GateVerdict

from ..autopatch.loop import PatchApproval, PatchResult, autopatch
from ..remediation.codefix import is_safe_repo_path, render_untrusted_finding
from ..warden_gate import decide_tool
from .executor import subprocess_runner
from .think_claude import _build_live_client, _extract_text, _resolve_key
from .wiring import default_classify

_MAX_CONTEXT_BYTES = 8192
_PATCH_NAME = ".vigil-fix.patch"


@dataclass
class CodefixConfig:
    """Deployment config for a live auto-patch run. ``target_repo`` is a LOCAL path or a git URL (LAP-1 is
    exercised with a local codebase). ``apply_edits`` (default False) is the explicit opt-in for the A2
    edit leg — off means every edit times out (REJECT). The PR leg is always off in LAP-1."""
    target_repo: str
    base_dir: str
    target_branch: str = ""
    build_cmd: tuple[str, ...] = ()          # reserved for LAP-later (needs a cwd-capable sandbox runner)
    git_bin: str = "git"
    apply_edits: bool = False
    approve_window_s: float = 3600.0
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 4000
    clone_timeout: float = 120.0
    apply_timeout: float = 120.0


@dataclass
class _Exec:
    ok: bool
    reason: str = ""
    workdir: str = ""
    branch: str = ""
    build_ref: str = ""
    pr_ref: str = ""


@dataclass
class _Quorum:
    approved: bool = False
    reason: str = ""
    signer_ids: list = field(default_factory=list)


def _file_from_target(target: Any) -> str:
    """Best-effort repo-relative file path from a finding's ``target`` (e.g. 'pkg/x.py:42' → 'pkg/x.py').
    A URL (has '://') or an unsafe path yields '' — the coder then proposes without file context."""
    t = str(target or "").strip()
    if not t or "://" in t:
        return ""
    m = re.match(r"^(.+?)(?::\d+)*$", t)
    p = (m.group(1) if m else t).strip()
    ok, _ = is_safe_repo_path(p)
    return p if ok else ""


class CodefixSession:
    """Holds the disposable clone workdir across the loop's executor calls (the loop does NOT thread the
    workdir through). All git runs are argv-list subprocesses (no shell); nothing touches the source repo."""

    def __init__(self, config: CodefixConfig, *, client: Any = None,
                 killswitch: Any = None, operator_present: bool = True) -> None:
        self.config = config
        self._client = client
        self._killswitch = killswitch
        self._operator_present = operator_present
        self.workdir: str = ""

    # -- gate: WARDEN tier + killswitch for the NON-destructive legs; destructive ⇒ deny (LAP-3) ------
    def gate(self, tool_name: str, target: str, destructive: bool = False, *,
             destruction_action: Any = None, destruction_signed: Any = None) -> GateVerdict:
        if destructive:
            return GateVerdict(allowed=False, outcome="deny",
                               reason="destructive stage (open-PR) requires the m-of-n destruction authority "
                                      "— not provisioned here (LAP-3)", crucible_allowed=None, warden=None)
        try:
            if self._killswitch is not None and self._killswitch.is_tripped():
                return GateVerdict(allowed=False, outcome="deny", reason="kill-switch engaged",
                                   crucible_allowed=None, warden=None)
        except Exception:  # noqa: BLE001 — a killswitch read error is fail-closed (treat as tripped)
            return GateVerdict(allowed=False, outcome="deny", reason="kill-switch state unreadable (fail-closed)",
                               crucible_allowed=None, warden=None)
        d = decide_tool(tool_name, classify=default_classify, floor="A2", ceiling="A1")
        if d.outcome == "auto":
            return GateVerdict(allowed=True, outcome="allow", reason=d.reason, crucible_allowed=None, warden=None)
        if d.outcome == "queue" and self._operator_present:
            # the operator personally invoked `vigil patch` → the human-approval leg is satisfied for a
            # non-destructive, reversible local action. (A background/unattended run leaves this False.)
            return GateVerdict(allowed=True, outcome="allow",
                               reason="owner-present (operator-invoked): " + d.reason,
                               crucible_allowed=None, warden=None)
        return GateVerdict(allowed=False, outcome="queue" if d.outcome == "queue" else "deny",
                           reason=d.reason, crucible_allowed=None, warden=None)

    # -- executors -----------------------------------------------------------------------------------
    def clone(self, request: Any) -> _Exec:
        repo = getattr(request, "target_repo", "") or self.config.target_repo
        branch = getattr(request, "fix_branch", "") or "vigil-fix"
        if not repo:
            return _Exec(False, reason="no target repo configured")
        wd = os.path.join(self.config.base_dir, "codefix-" + str(getattr(request, "remediation_id", "run")))
        try:
            if os.path.exists(wd):
                shutil.rmtree(wd, ignore_errors=True)
            os.makedirs(self.config.base_dir, exist_ok=True)
        except OSError as exc:
            return _Exec(False, reason=f"workdir prep failed: {exc}")
        r = subprocess_runner([self.config.git_bin, "clone", "--no-hardlinks", "--quiet", repo, wd],
                              timeout=self.config.clone_timeout)
        if r.exit_code != 0:
            return _Exec(False, reason="git clone failed: " + (r.stderr or "")[:200])
        if self.config.target_branch:
            co = subprocess_runner([self.config.git_bin, "-C", wd, "checkout", self.config.target_branch])
            if co.exit_code != 0:
                return _Exec(False, reason="checkout base branch failed: " + (co.stderr or "")[:160])
        nb = subprocess_runner([self.config.git_bin, "-C", wd, "checkout", "-b", branch])
        if nb.exit_code != 0:
            return _Exec(False, reason="create fix branch failed: " + (nb.stderr or "")[:160])
        self.workdir = wd
        return _Exec(True, reason="cloned + branched", workdir=wd, branch=branch)

    def build(self, request: Any, approved: Any) -> _Exec:
        """The A3 leg: git-apply the approved diffs into the clone (the honest 'sandbox build' for LAP-1 —
        it proves the AI's fix APPLIES to the real code). A full compile/test build is LAP-later (needs a
        cwd-capable sandbox runner). Never modifies the source repo — only the disposable clone."""
        if not self.workdir or not os.path.isdir(self.workdir):
            return _Exec(False, reason="no clone workdir (clone must succeed first)")
        diffs = []
        for pf in (approved or []):
            dt = getattr(pf, "diff_text", "") if not isinstance(pf, str) else ""
            if dt and dt.strip():
                diffs.append(dt if dt.endswith("\n") else dt + "\n")
        if not diffs:
            return _Exec(False, reason="no diff text to apply")
        patch_path = os.path.join(self.workdir, _PATCH_NAME)
        try:
            with open(patch_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(diffs))
        except OSError as exc:
            return _Exec(False, reason=f"could not stage patch file: {exc}")
        try:
            chk = subprocess_runner([self.config.git_bin, "-C", self.workdir, "apply", "--check", patch_path],
                                    timeout=self.config.apply_timeout)
            if chk.exit_code != 0:
                return _Exec(False, reason="patch does not apply cleanly: " + (chk.stderr or "")[:200])
            ap = subprocess_runner([self.config.git_bin, "-C", self.workdir, "apply", patch_path],
                                   timeout=self.config.apply_timeout)
            if ap.exit_code != 0:
                return _Exec(False, reason="git apply failed: " + (ap.stderr or "")[:200])
        finally:
            try:
                os.unlink(patch_path)
            except OSError:
                pass
        return _Exec(True, reason="fix applies cleanly to the real code (sandbox clone)", build_ref=self.workdir)

    @staticmethod
    def open_pr(request: Any, approved: Any) -> _Exec:
        """DISABLED in LAP-1 (belt-and-suspenders — the destructive gate already denies). Real push + PR +
        the m-of-n quorum are the provisioned destructive follow-up (LAP-3)."""
        return _Exec(False, reason="opening a PR is disabled in this build — it is the provisioned, "
                                   "destructive LAP-3 leg (needs credentials + the m-of-n quorum)")

    # -- coder: real Claude unified-diff proposal (fail-closed to '' with no key/client) -------------
    def propose(self, request: Any) -> str:
        finding = getattr(request, "finding", None)
        if finding is None:
            return ""
        fpath = _file_from_target(getattr(finding, "target", ""))
        context = ""
        if fpath and self.config.target_repo and "://" not in self.config.target_repo:
            local = os.path.join(self.config.target_repo, fpath)
            try:
                if os.path.isfile(local):
                    with open(local, encoding="utf-8", errors="replace") as fh:
                        context = fh.read(_MAX_CONTEXT_BYTES)
            except OSError:
                context = ""
        prompt = (
            "You are a security fix engineer. A vulnerability has been CONFIRMED by a deterministic oracle. "
            "Propose the MINIMAL fix as a unified diff.\n\n"
            + render_untrusted_finding(finding)
            + (f"\n\nThe file to fix is `{fpath}`. Its current content:\n```\n{context}\n```\n" if context
               else f"\n\nThe likely file is `{fpath or '(unknown — infer from the finding)'}`.\n")
            + "\nReturn ONLY a unified diff. Each file MUST start with consecutive lines "
              "`--- a/<repo-relative-path>` then `+++ b/<repo-relative-path>` (repo-relative paths only; "
              "no absolute paths, no `..`). No prose, no code fences."
        )
        client = self._client or _build_live_client(_resolve_key(None) or "")
        if client is None:
            return ""   # no API key / SDK → no proposal (honest, fail-closed)
        try:
            resp = client.messages.create(
                model=self.config.model, max_tokens=self.config.max_tokens,
                messages=[{"role": "user", "content": prompt}])
        except Exception:  # noqa: BLE001 — a coder failure degrades to no-patch (the loop is total)
            return ""
        return _extract_text(resp) or ""


def autopatch_live(finding: Any, *, config: CodefixConfig, client: Any = None,
                   killswitch: Any = None, operator_present: bool = True,
                   now: Optional[Callable[[], float]] = None) -> PatchResult:
    """Run the sovereign auto-patch loop against REAL executors, non-destructively (LAP-1): propose (Claude)
    → clone → apply-in-sandbox; the PR leg is gated off. Returns the loop's PatchResult (the full gated
    ladder + the applied paths + status). A confirmed FACT is the only valid input (the loop refuses a lead);
    edits apply only when ``config.apply_edits`` is set (else they time out and are rejected)."""
    session = CodefixSession(config, client=client, killswitch=killswitch, operator_present=operator_present)
    clock = now or time.monotonic

    def approval(_pf: Any) -> PatchApproval:
        if config.apply_edits:
            return PatchApproval(decision="approve", deadline=float(clock()) + config.approve_window_s)
        return PatchApproval(decision="timeout", deadline=0.0)

    def quorum(_request: Any) -> _Quorum:
        return _Quorum(approved=False, reason="m-of-n destruction quorum not provisioned (LAP-3)")

    return autopatch(
        finding, gate=session.gate, oracle=None, propose_patch=session.propose,
        clone=session.clone, build=session.build, open_pr=session.open_pr,
        quorum=quorum, approval=approval, now=clock,
        target_repo=config.target_repo, target_branch=config.target_branch,
    )
