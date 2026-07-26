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
    model: str = "claude-opus-5"             # a CURRENT model; `vigil patch` resolves the Settings choice
    max_tokens: int = 4000
    clone_timeout: float = 120.0
    apply_timeout: float = 120.0
    # --- LAP-3 destructive PR leg (OFF by default) ------------------------------------------------
    pr_enabled: bool = False                 # master switch — off ⇒ the gate DENIES the PR + open_pr refuses
    # repr=False so a stray repr/log of the config can never expose the token (it is sealed at the Settings
    # layer; here it is only ever forwarded into the child ENV for git/gh).
    github_token: str = field(default="", repr=False)   # else resolved from GITHUB_TOKEN env; empty ⇒ refuse
    pr_base: str = ""                        # PR base branch (default: the repo's default branch)
    push_remote: str = "origin"
    gh_bin: str = "gh"
    push_timeout: float = 180.0
    pr_title_prefix: str = "VIGIL auto-fix: "


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
    nonce: str = ""                          # the single-use nonce (surfaced so it can be atomically reserved)


def _safe_workdir(base_dir: str, remediation_id: Any) -> Optional[str]:
    """Resolve the disposable clone workdir, refusing an id that would escape ``base_dir`` (defense in
    depth at the sink — never rely on the id being a slash-free digest two layers up, since a future caller
    could pass one). A separator / '..' / empty / dot id ⇒ None (the clone then fails closed). The result
    is abspath-confirmed to sit strictly under ``base_dir`` before any rmtree/clone touches it."""
    rid = str(remediation_id or "")
    if rid in ("", ".", "..") or "/" in rid or "\\" in rid or ".." in rid or "\x00" in rid:
        return None
    base = os.path.abspath(base_dir)
    wd = os.path.abspath(os.path.join(base, "codefix-" + rid))
    try:
        if os.path.commonpath([base, wd]) != base or wd == base:
            return None
    except ValueError:                     # different drives / mixed abs-rel → refuse
        return None
    return wd


def _repo_ok(repo: str) -> tuple[bool, str]:
    """Validate the clone source: never a leading-dash (git-flag injection), never a transport-helper form
    (``ext::``/``fd::`` → arbitrary command execution), and a scheme, if any, on a short allowlist. A
    schemeless value is a local path or an scp-like ``user@host:path`` (a single ':' is fine)."""
    r = str(repo or "")
    if not r or r.startswith("-"):
        return False, "repo is empty or starts with '-' (git-flag injection refused)"
    if "::" in r:
        return False, "transport-helper repo form refused (e.g. ext::/fd:: → command execution)"
    if "://" in r and not r.lower().startswith(("https://", "http://", "git://", "ssh://")):
        return False, "repo URL scheme not on the allowlist (https/http/git/ssh only)"
    return True, ""


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
        if destructive and not self.config.pr_enabled:
            return GateVerdict(allowed=False, outcome="deny",
                               reason="destructive stage (open-PR) is disabled (pr_enabled=False) — provision "
                                      "a GitHub token + the m-of-n quorum to enable", crucible_allowed=None,
                               warden=None)
        # When pr_enabled, a destructive github_pr leg is allowed on the WARDEN tier + kill-switch here; the
        # m-of-n threshold is enforced ORTHOGONALLY by the pipeline's separate `quorum` callable (run_codefix
        # requires BOTH), so there is ONE m-of-n (the quorum), not a double gate.
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
        ok, why = _repo_ok(repo)
        if not ok:
            return _Exec(False, reason=why)
        if branch.startswith("-") or (self.config.target_branch or "").startswith("-"):
            return _Exec(False, reason="branch name starts with '-' (refused)")   # no ref-as-flag
        wd = _safe_workdir(self.config.base_dir, getattr(request, "remediation_id", "run"))
        if wd is None:
            return _Exec(False, reason="unsafe remediation id — refusing to build a workdir outside base_dir")
        try:
            if os.path.exists(wd):
                shutil.rmtree(wd, ignore_errors=True)   # wd is abspath-confirmed under base_dir (see _safe_workdir)
            os.makedirs(self.config.base_dir, exist_ok=True)
        except OSError as exc:
            return _Exec(False, reason=f"workdir prep failed: {exc}")
        # `--` ends option parsing so a repo/URL can never be read as a git flag.
        r = subprocess_runner([self.config.git_bin, "clone", "--no-hardlinks", "--quiet", "--", repo, wd],
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

    def open_pr(self, request: Any, approved: Any) -> _Exec:
        """The DESTRUCTIVE, outward-facing leg (LAP-3): stage ONLY the explicit approved paths (never
        `git add -A`), commit on the fix branch, push it, and open a PR via `gh`. OFF unless pr_enabled AND
        a GitHub token is provisioned; the token flows via CHILD ENV only (never argv/logs). Reached only
        after the gate (tier/kill-switch) AND the pipeline's m-of-n quorum both pass."""
        if not self.config.pr_enabled:
            return _Exec(False, reason="PR opening is disabled (pr_enabled=False)")
        token = (self.config.github_token or os.environ.get("GITHUB_TOKEN", "")).strip()
        if not token:
            return _Exec(False, reason="no GITHUB_TOKEN provisioned — refusing to open a PR (fail-closed)")
        if not self.workdir or not os.path.isdir(self.workdir):
            return _Exec(False, reason="no clone workdir")
        paths = [p if isinstance(p, str) else getattr(p, "path", "") for p in (approved or [])]
        paths = [p for p in paths if p]
        if not paths:
            return _Exec(False, reason="no approved paths to stage")
        for p in paths:                                   # defense in depth — never stage a flag/bulk/traversal
            ok, why = is_safe_repo_path(p)
            if not ok:
                return _Exec(False, reason=f"refusing to stage unsafe path {p!r}: {why}")
        git = self.config.git_bin
        for p in paths:
            r = subprocess_runner([git, "-C", self.workdir, "add", "--", p], timeout=self.config.apply_timeout)
            if r.exit_code != 0:
                return _Exec(False, reason="git add failed: " + (r.stderr or "")[:160])
        title = (self.config.pr_title_prefix + str(getattr(request, "title", "") or "fix")).strip()
        cm = subprocess_runner([git, "-C", self.workdir, "-c", "user.email=vigil@localhost",
                                "-c", "user.name=VIGIL", "commit", "-m", title],
                               timeout=self.config.apply_timeout)
        if cm.exit_code != 0:
            return _Exec(False, reason="git commit failed: " + (cm.stderr or "")[:160])
        # the token goes in the CHILD ENV, never in argv (argv shows in ps/logs). GIT_ASKPASS/terminal-prompt
        # off so a missing/invalid cred fails instead of hanging; gh reads GH_TOKEN from env.
        child_env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        child_env.update({"GIT_TERMINAL_PROMPT": "0", "GH_TOKEN": token, "GITHUB_TOKEN": token})
        branch = getattr(request, "fix_branch", "") or "vigil-fix"
        push = subprocess_runner([git, "-C", self.workdir, "push", "--set-upstream", self.config.push_remote,
                                  branch], timeout=self.config.push_timeout, env=child_env)
        if push.exit_code != 0:
            return _Exec(False, reason="git push failed: " + (push.stderr or "")[:200])
        pr_argv = [self.config.gh_bin, "pr", "create", "--title", title, "--fill", "--head", branch]
        if self.config.pr_base:
            pr_argv += ["--base", self.config.pr_base]
        pr = subprocess_runner(pr_argv, timeout=self.config.push_timeout, cwd=self.workdir, env=child_env)
        if pr.exit_code != 0:
            return _Exec(False, reason="gh pr create failed: " + (pr.stderr or "")[:200])
        pr_ref = (pr.stdout or "").strip().splitlines()[-1] if (pr.stdout or "").strip() else "opened"
        return _Exec(True, reason="pull request opened", pr_ref=pr_ref)

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


def build_destruction_quorum(*, authority: Any, signed: Any, slug: str, is_consumed: Callable[[str], bool],
                             consume: Optional[Callable[[str], bool]] = None,
                             now: Optional[Callable[[], float]] = None) -> Callable[[Any], _Quorum]:
    """Build the PR-leg m-of-n quorum callable from a PROVISIONED owner-inclusive SignedDestructionAuthorization
    + DestructionAuthority. It rebuilds the per-request DestructiveAction (action_id 'pr-<remediation_id>',
    target=repo, engagement=slug) and verifies the signed authorization via ``authorize_destruction`` — which
    fail-closed checks well-formedness, the gated class, action match, the not_before/not_after dead-man's-
    switch window, the mandatory owner, single-use (``is_consumed``), and the m-of-n threshold.

    SINGLE-USE (atomic): ``is_consumed`` is a cheap advisory early-reject inside ``authorize_destruction``; the
    AUTHORITATIVE guarantee is ``consume`` — an ATOMIC try-consume that returns True iff THIS caller won the
    single use. When ``consume`` is given, the authorized nonce is atomically reserved the instant it
    authorizes (before the PR runs — the replay-safe direction). If ``consume`` returns False the nonce was
    already spent by a prior OR concurrent caller ⇒ DENY (replay). If it raises ⇒ DENY (fail-closed: never
    authorize a destruction we could not exclusively reserve). Because the consume is the serialization
    point, one owner-signed authorization drives exactly ONE destructive PR even under concurrent callers.
    Off without provisioning: ``autopatch_live`` defaults the quorum to a hard DENY."""
    from ..destruction_gate import DestructiveAction, authorize_destruction

    def quorum(request: Any) -> _Quorum:
        try:
            action = DestructiveAction(
                action_id="pr-" + str(getattr(request, "remediation_id", "")),
                engagement_slug=slug,
                target=(getattr(request, "target_repo", "") or getattr(getattr(request, "finding", None),
                        "target", "") or ""),
                blast_class="destructive")
            d = authorize_destruction(action, signed, authority=authority,
                                      now=_epoch(now() if now else None), is_consumed=is_consumed)
            approved = getattr(d, "authorized", False) is True     # STRICT: only real True
            nonce = str(getattr(d, "nonce", "") or "")
            if approved and consume is not None:
                try:
                    won = consume(nonce)                            # ATOMIC reserve — exactly one caller wins
                except Exception:  # noqa: BLE001 — cannot exclusively reserve ⇒ refuse (fail-closed)
                    return _Quorum(approved=False, nonce=nonce,
                                   reason="could not record single-use consumption — refusing (fail-closed)")
                if won is not True:                                 # STRICT: lost the race / already spent
                    return _Quorum(approved=False, nonce=nonce,
                                   reason="authorization already consumed (replay)")
            return _Quorum(approved=approved, reason=getattr(d, "reason", ""), nonce=nonce)
        except Exception:  # noqa: BLE001 — any error ⇒ deny (fail-closed)
            return _Quorum(approved=False, reason="destruction authorization failed (fail-closed)")

    return quorum


def file_backed_quorum(*, authority: Any, signed: Any, slug: str, ledger_path: str,
                       now: Optional[Callable[[], float]] = None) -> Callable[[Any], _Quorum]:
    """Convenience: a destruction quorum whose single-use is backed by a durable, ATOMIC on-disk
    ``NonceLedger`` (``ledger_path`` is its marker directory) — the consume is an ``O_EXCL`` atomic reserve
    that survives restart, so one owner-signed authorization drives exactly ONE destructive PR even across
    process restarts AND concurrent callers of the same authorization."""
    from .nonce_ledger import NonceLedger
    ledger = NonceLedger(ledger_path)
    return build_destruction_quorum(authority=authority, signed=signed, slug=slug,
                                    is_consumed=ledger.is_consumed, consume=ledger.try_consume, now=now)


def _epoch(now_val: Any) -> float:
    from datetime import datetime
    if isinstance(now_val, datetime):
        return now_val.timestamp()
    if isinstance(now_val, (int, float)) and not isinstance(now_val, bool):
        return float(now_val)
    return time.time()


def autopatch_live(finding: Any, *, config: CodefixConfig, client: Any = None,
                   killswitch: Any = None, operator_present: bool = True,
                   quorum: Optional[Callable[[Any], Any]] = None,
                   now: Optional[Callable[[], float]] = None) -> PatchResult:
    """Run the sovereign auto-patch loop against REAL executors: propose (Claude) → clone → apply-in-sandbox
    → (if ``config.pr_enabled`` AND a ``quorum`` passes AND a GitHub token is provisioned) open a gated PR.
    A confirmed FACT is the only valid input (a lead is refused); edits apply only with ``config.apply_edits``
    (else timeout ⇒ reject); the PR leg needs pr_enabled + the m-of-n ``quorum`` + a token (all off by
    default ⇒ no PR). ``remediated`` is minted only if a verify ``oracle`` (not wired here — a PR opens as a
    PROPOSAL) later goes silent. Returns the loop's PatchResult (the full gated ladder + status)."""
    session = CodefixSession(config, client=client, killswitch=killswitch, operator_present=operator_present)
    clock = now or time.monotonic

    def approval(_pf: Any) -> PatchApproval:
        if config.apply_edits:
            return PatchApproval(decision="approve", deadline=float(clock()) + config.approve_window_s)
        return PatchApproval(decision="timeout", deadline=0.0)

    def _deny_quorum(_request: Any) -> _Quorum:
        return _Quorum(approved=False, reason="m-of-n destruction quorum not provisioned")

    return autopatch(
        finding, gate=session.gate, oracle=None, propose_patch=session.propose,
        clone=session.clone, build=session.build, open_pr=session.open_pr,
        quorum=quorum or _deny_quorum, approval=approval, now=clock,
        target_repo=config.target_repo, target_branch=config.target_branch,
    )
