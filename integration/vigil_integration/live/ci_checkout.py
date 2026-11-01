"""live.ci_checkout — the CI-LOCAL checkout + changed-files seams for the W4 CI Action.

Unlike the PR-bot seams (``pr_checkout.py``) — which CLONE at the PR head and read the changed files from
``api.github.com`` — the CI path runs INSIDE the GitHub Actions job, where ``actions/checkout`` has ALREADY
populated ``$GITHUB_WORKSPACE`` and the git history is local. So:

  * :func:`make_ci_checkout` is an IDENTITY checkout — it validates + returns the on-disk workspace (no
    clone, no network, no token);
  * :func:`make_ci_changed_files` computes the PR diff from the LOCAL git history
    (``git diff --name-only <base>...<head>`` — three-dot, i.e. changes on head since the merge-base,
    matching GitHub's own "Files changed"), returning repo-relative POSIX paths.

Fail-closed: a missing workspace, an unsafe ref, or a git failure RAISES :class:`CiCheckoutError`, so
``JobRunner.run_one`` records the job FAILED (re-driveable) and ``make_diff_codescan_worker`` never falls
through to a silent clean (it also refuses an empty changed-files set upstream). FATAL-2: framework-free;
offense-side (stdlib + the injectable subprocess runner); no ``sigil`` import, no ``api.github.com``.

Note: the three-dot diff needs the merge-base present in local history, so the Action must check out with
enough history (``fetch-depth: 0``, or a fetch of the base) — otherwise the diff fails CLOSED here rather
than reporting a wrong scope.
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable, Optional

from ..jobs.model import SecurityJob

Checkout = Callable[[SecurityJob], str]
ChangedFiles = Callable[[SecurityJob], "set[str]"]

# A git ref/sha safe to place as a positional arg: must start with an alphanumeric (never '-', so it can
# never be read as a flag) and use only ref-legal characters. Fail-closed — reject anything else.
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


class CiCheckoutError(RuntimeError):
    """A CI checkout / diff seam refused or failed — fail-closed (missing workspace, unsafe ref, git error).
    Raised so ``JobRunner.run_one`` records the job FAILED (re-driveable), never a silent clean."""


def _safe_ref(ref: str, what: str) -> str:
    r = str(ref or "").strip()
    if not _SAFE_REF_RE.match(r):
        raise CiCheckoutError(f"unsafe {what} ref {ref!r} — refusing (fail-closed, no flag-injection)")
    return r


def _validated_dir(workspace: str) -> str:
    ws = str(workspace or "").strip()
    if not ws:
        raise CiCheckoutError("no CI workspace configured (GITHUB_WORKSPACE empty) — refusing (fail-closed)")
    root = os.path.abspath(os.path.expanduser(ws))
    if not os.path.isdir(root):
        raise CiCheckoutError(f"CI workspace {root!r} is not an existing directory — refusing")
    return root


def make_ci_checkout(workspace: str) -> Checkout:
    """Build the IDENTITY ``checkout(job) -> local_root``: the CI job runs where ``actions/checkout`` already
    populated ``workspace``, so this validates it is an existing directory and returns its abspath (no clone,
    no network, no token). Raises :class:`CiCheckoutError` if the workspace is empty/missing/not a dir."""
    def checkout(job: SecurityJob) -> str:
        return _validated_dir(workspace)
    return checkout


def make_ci_changed_files(*, base_ref: str, head_ref: str, workspace: str,
                          git_bin: str = "git", timeout: float = 60.0,
                          _runner: Optional[Callable[..., Any]] = None) -> ChangedFiles:
    """Build ``changed_files(job) -> set[str]`` from the LOCAL git history: the PR diff
    ``git diff --name-only <base>...<head>`` run in ``workspace``, parsed into repo-relative POSIX paths.
    Both refs are validated (no flag-injection); the argv is a list with ``--`` ending options (no shell).
    A git failure RAISES :class:`CiCheckoutError` so the diff worker fails CLOSED rather than scanning an
    undetermined scope. ``_runner`` is the injected subprocess runner (tests); default is the gated
    ``executor.subprocess_runner`` (imported lazily, and ONLY when no runner is injected, so the egress-
    guarded executor — and its heavy deps — are never loaded on the injected-runner test path)."""
    base = _safe_ref(base_ref, "base")      # validate BEFORE any import — a bad ref fails closed at build
    head = _safe_ref(head_ref, "head")

    def changed_files(job: SecurityJob) -> "set[str]":
        if _runner is not None:
            runner = _runner
        else:
            from .executor import subprocess_runner
            runner = subprocess_runner
        ws = _validated_dir(workspace)
        # argv-list, no shell; refs are pre-validated non-flags; the trailing `--` ends options so nothing
        # downstream is read as a flag. Three-dot range = the PR's changed files (merge-base diff).
        # `-z` is LOAD-BEARING: `--name-only` WITHOUT it quotes+octal-escapes a non-ASCII name (default
        # core.quotePath) and ALWAYS quotes a name with a newline/tab/quote/backslash — e.g. `café.py` ->
        # `"caf\303\251.py"`. Those quoted strings never equal the real on-disk `af.path` (a filesystem
        # walk) that run_codescan diff-scopes on, so EVERY finding in such a file would be silently dropped
        # (a false-clean the fail-closed contract forbids). `-z` emits the raw path bytes NUL-delimited,
        # ignoring core.quotePath, so every name round-trips exactly; no `.strip()` (it would corrupt a
        # legitimate leading/trailing-space name).
        r = runner([git_bin, "-C", ws, "diff", "-z", "--name-only", f"{base}...{head}", "--"], timeout=timeout)
        if getattr(r, "exit_code", None) != 0:
            raise CiCheckoutError(
                f"git diff {base}...{head} failed (exit {getattr(r, 'exit_code', None)}): "
                f"{(getattr(r, 'stderr', '') or '')[:200]}")
        out = getattr(r, "stdout", "") or ""
        return {p for p in out.split("\0") if p}      # NUL-delimited; drop the trailing empty element
    return changed_files


__all__ = ["CiCheckoutError", "make_ci_checkout", "make_ci_changed_files"]
