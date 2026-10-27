"""pr_checkout — the GATED PR-head checkout + changed-files seams for the repo-connect PR-bot (3-live-b2).

``make_pr_bot_checkout`` returns the ``checkout(job) -> local_root`` the PR-bot worker consumes: it clones the
connected repo AT THE PR HEAD into a disposable workdir so the diff-scan (and later the fix) sees exactly the
code the PR proposes. ``make_pr_bot_changed_files`` returns the ``changed_files(job) -> set[str]`` from the 3a
gated read client (api.github.com), for diff-scoping.

Gated like the codefix clone (``codefix_runner.CodefixSession.clone``), with the PR-bot-specific guards added:
  * the GitHub token is passed ONLY in the child ENV (``GH_TOKEN``/``GITHUB_TOKEN``), NEVER in argv — argv shows
    in ``ps``/logs (``subprocess_runner`` documents this env contract); an empty token FAILS CLOSED (no clone);
  * ``GIT_TERMINAL_PROMPT=0`` so a missing credential FAILS instead of hanging;
  * argv-list ``gh``/``git`` subprocesses — NO shell, no string interpolation; flag-injection is prevented by the
    repo/pr/workdir guards (``_owner_repo``'s alphanumeric-leading owner, the abspath workdir, the positive-int
    pr), NOT by a ``--`` separator (gh's ``--`` only forwards ``--depth`` through to git);
  * the repo is validated to EXACTLY ``owner/repo`` (``github_client._owner_repo`` — no clone-URL traversal);
  * a disposable workdir CONFINED under ``base_dir`` (``_safe_workdir``), rmtree'd + recreated per job (no bleed);
  * the PR head is checked out via ``gh pr checkout`` (resolves a FORK / non-default-branch head).

HONEST EGRESS BOUNDARY: the git/gh network reach to github.com is governed by ``subprocess_runner``'s egress
guard + the S5 container sandbox — the SAME layer the codefix clone depends on; this is NOT a new scope-confined
git-egress (that is S5 deploy infra). The whole PR-bot execute path is OFF by default (opt-in command, authorized
jobs only), so nothing clones until the operator wires it. FATAL-2: framework-free; offense-side (subprocess).
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Callable, Optional

from ..jobs.model import SecurityJob

Checkout = Callable[[SecurityJob], str]
ChangedFiles = Callable[[SecurityJob], "set[str]"]


class PrCheckoutError(RuntimeError):
    """A PR-head checkout refused or failed — fail-closed (unsafe repo, no token, clone/checkout error, unsafe
    workdir). Raised so ``JobRunner.run_one`` records the job FAILED (re-driveable), never a silent clean."""


def make_pr_bot_checkout(
    *,
    github_token: str,
    base_dir: str,
    git_bin: str = "git",
    gh_bin: str = "gh",
    clone_timeout: float = 180.0,
    checkout_timeout: float = 120.0,
    _runner: Optional[Callable[..., Any]] = None,
) -> Checkout:
    """Build the gated ``checkout(job) -> local_root``: clone the job's repo at the PR head into a disposable
    workdir under ``base_dir`` and return it. Token OFF-ARGV (child env), repo-identity + confined-workdir +
    no-shell guards as above. ``_runner`` is the injected subprocess runner (tests); default is the gated
    ``executor.subprocess_runner`` (argv-list, egress-guard-aware). Raises :class:`PrCheckoutError` on any
    refusal/failure (fail-closed)."""
    from .executor import subprocess_runner
    from .github_client import GitHubReadError, _owner_repo

    runner = _runner or subprocess_runner

    def _child_env() -> dict:
        token = (github_token or os.environ.get("GITHUB_TOKEN", "")).strip()
        if not token:
            raise PrCheckoutError("no GitHub token configured — refusing to clone (fail-closed)")
        # the child's FULL env; the token rides HERE (never argv). PYTHONPATH/HOME dropped like open_pr.
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        env.update({"GIT_TERMINAL_PROMPT": "0", "GH_TOKEN": token, "GITHUB_TOKEN": token})
        return env

    def checkout(job: SecurityJob) -> str:
        try:
            owner_repo = _owner_repo(job.repo)          # EXACT owner/repo — no clone-URL traversal
        except GitHubReadError as e:
            raise PrCheckoutError(f"refusing to clone an unsafe repo identity {job.repo!r}: {e}") from e
        try:
            pr = int(job.pr_number)   # typed refusal — a non-int (incl. None) is the documented PrCheckoutError
        except (TypeError, ValueError) as e:
            raise PrCheckoutError(
                f"job for {job.repo!r} has a non-integer pr_number {job.pr_number!r} — cannot checkout") from e
        if pr <= 0:   # a PR number is always positive; this also keeps str(pr) from ever looking like a flag
            raise PrCheckoutError(f"job for {job.repo!r} has a non-positive pr_number {pr} — refusing")
        wd = _safe_workdir(base_dir, f"prbot-{job.slug}-{pr}")
        if wd is None:
            raise PrCheckoutError("unsafe workdir — refusing to build outside base_dir")
        try:
            if os.path.exists(wd):
                shutil.rmtree(wd, ignore_errors=True)    # confined under base_dir (see _safe_workdir)
            os.makedirs(base_dir, exist_ok=True)
        except OSError as exc:
            raise PrCheckoutError(f"workdir prep failed: {exc}") from exc

        env = _child_env()                               # raises (fail-closed) if no token; token OFF argv
        # clone the repo (token off-argv via GH_TOKEN). The `--` here is gh's separator that FORWARDS `--depth 1`
        # to the underlying git clone — it does NOT shield the preceding owner_repo/wd positionals. Flag-injection
        # safety instead rests on: _owner_repo (owner's first char is alphanumeric, never '-'), wd being an
        # abspath under base_dir (always starts with '/'), and pr being a positive int — all enforced above.
        r = runner([gh_bin, "repo", "clone", owner_repo, wd, "--", "--depth", "1"],
                   timeout=clone_timeout, env=env)
        if getattr(r, "exit_code", None) != 0:
            raise PrCheckoutError(f"gh repo clone {owner_repo} failed: {(getattr(r, 'stderr', '') or '')[:200]}")
        # check out the PR head IN the clone (gh resolves a fork / non-default-branch head); token off-argv
        co = runner([gh_bin, "pr", "checkout", str(pr)], timeout=checkout_timeout, cwd=wd, env=env)
        if getattr(co, "exit_code", None) != 0:
            raise PrCheckoutError(f"gh pr checkout #{pr} failed: {(getattr(co, 'stderr', '') or '')[:200]}")
        return wd

    return checkout


def make_pr_bot_changed_files(github_token: str, *, http: Any = None) -> ChangedFiles:
    """Build the ``changed_files(job) -> set[str]`` from the 3a gated read client, scoped to the job's repo
    engagement slug (api.github.com host-pinned; token off-spine). A read error RAISES (the diff worker then
    fails CLOSED rather than scanning an undetermined scope). ``http`` is the injected double (tests)."""
    def changed_files(job: SecurityJob) -> "set[str]":
        from .github_client import GitHubReadClient, GitHubReadConfig, GitHubReadError
        try:
            pr = int(job.pr_number)   # typed refusal (a read error RAISES; never crash oddly / scan an undetermined scope)
        except (TypeError, ValueError) as e:
            raise GitHubReadError(f"job for {job.repo!r} has a non-integer pr_number {job.pr_number!r}") from e
        slug = SecurityJob(repo=job.repo).slug
        client = GitHubReadClient(GitHubReadConfig(slug=slug, github_token=github_token), http=http)
        return client.changed_files(job.repo, pr, str(job.commit or ""))

    return changed_files


def _safe_workdir(base_dir: str, job_key: str) -> "str | None":
    """A disposable workdir CONFINED under ``base_dir`` for ``job_key`` — reuses the codefix safety helper so the
    confinement check (abspath must stay under base_dir; no traversal) is the ONE vetted implementation."""
    from .codefix_runner import _safe_workdir as _cf_safe_workdir
    return _cf_safe_workdir(base_dir, job_key)


__all__ = ["PrCheckoutError", "make_pr_bot_checkout", "make_pr_bot_changed_files"]
