"""redpen_system — the RED-PEN SYSTEM (whole-repository) review WORKER (R4).

The System sibling of R3's PR-review worker. A ``SecurityJob`` for a connected repo's System review
(``profile="full"``) resolves a checkout of the DEFAULT-BRANCH HEAD and runs the Red-Pen adversarial reproduction
engine (:func:`vigil_integration.redpen.run_redpen`) over the WHOLE TREE — exactly the PR-review worker, but with NO
``include_paths`` restriction (a diff worker scopes to the PR's changed files; this reviews every tracked file).

The O-1 rule is identical and non-negotiable: only REPRODUCED + oracle-confirmed FACTs are reported (posted via the
SOVEREIGN check run, decision O-5); every LEAD stays on the dashboard and is NEVER posted. The worker itself holds no
GitHub token and writes no check run — it emits an INERT review outcome (:func:`redpen_system_outcome`), and an
injected ``post_outcome`` seam (the sovereign check-run writer, wired by R3) carries only the FACT severities across.

It is invoked ONLY by :meth:`jobs.runner.JobRunner.run_one` — only after the authorization gate allowed the job.

FATAL-2: the framework-backed engine is imported LAZILY, so this module is import-clean in either venv; the real
``run_redpen`` pulls framework only on the offense plane where the worker runs. Registered in
``integration/tests/test_two_env_boundary.py``.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Optional, Sequence

from .model import SecurityJob

Worker = Callable[[SecurityJob], dict]

# A whole-tree review bounds how many files enter the deterministic threat-model context (the engine bounds it again
# per lens; this is the enumeration ceiling so a huge monorepo checkout never walks unbounded).
_DEFAULT_MAX_PATHS = 5000
# Directories never worth reviewing as source (VCS metadata / build caches); skipped during enumeration.
_SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
                        ".pytest_cache", ".tox", ".ruff_cache", "dist", "build", ".idea", ".vscode"})
# Severities that BLOCK a merge / fail the check run (design §12: reproduced Critical and High block).
_BLOCKING_SEVERITIES = frozenset({"critical", "high"})


def enumerate_tree(root: str, *, max_paths: int = _DEFAULT_MAX_PATHS) -> "list[str]":
    """Every reviewable file under ``root`` as a repo-relative POSIX path, in deterministic (sorted) order,
    bounded to ``max_paths``, skipping VCS/build dirs (:data:`_SKIP_DIRS`). This is the WHOLE-TREE analogue of
    the PR worker's changed-files set — the files the System review threat-models. Total: an unreadable subtree
    is skipped, never fatal."""
    base = os.path.realpath(str(root))
    out: "list[str]" = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, base)
            out.append(rel.replace(os.sep, "/"))
            if len(out) >= max_paths:
                return sorted(out)
    return sorted(out)


def redpen_system_outcome(report: Any) -> dict:
    """The INERT review outcome a System review produces — ONLY the reproduced FACTs cross (O-1); LEADs are
    summarized by count but never carried. ``blocking`` is True iff any FACT is Critical/High (design §12 — those
    block the merge via the check run). ``conclusion`` is the check-run conclusion the sovereign writer uses
    (``failure`` iff blocking, else ``neutral`` when non-blocking FACTs exist, else ``success``). Carries no
    GitHub token and no LEAD body."""
    facts = list(getattr(report, "facts", ()) or ())
    leads = list(getattr(report, "leads", ()) or ())
    posted = [{"bug_class": str(getattr(f, "bug_class", "")), "severity": str(getattr(f, "severity", "")),
               "finding_ref": str(getattr(f, "finding_ref", "")), "lens": str(getattr(f, "lens", "")),
               "file": str(getattr(f, "file", "")), "line": int(getattr(f, "line", 0) or 0),
               "confirmed_by": str(getattr(f, "confirmed_by", ""))}
              for f in facts]
    blocking = any(str(getattr(f, "severity", "")).strip().lower() in _BLOCKING_SEVERITIES for f in facts)
    conclusion = "failure" if blocking else ("neutral" if facts else "success")
    return {"facts": posted, "facts_count": len(facts), "leads_count": len(leads),
            "blocking": blocking, "conclusion": conclusion}


def make_redpen_system_worker(
    *,
    checkout: Callable[[SecurityJob], str],
    reviewer: Any,
    signers: "Sequence[tuple[str, str]]",
    enumerate_paths: "Optional[Callable[[SecurityJob, str], Sequence[str]]]" = None,
    sandbox: Any = None,
    confirm: Any = None,
    post_outcome: "Optional[Callable[[SecurityJob, dict], Any]]" = None,
    max_paths: int = _DEFAULT_MAX_PATHS,
    timeout: Any = None,
    runs_required: Any = None,
    _run: Any = None,
) -> Worker:
    """Build the System-review worker for :meth:`JobRunner.run_one`.

    ``checkout(job) -> local_root`` resolves the DEFAULT-BRANCH HEAD to an on-disk tree (a gated clone — tests
    inject a fixture path). ``reviewer`` is the injected Red-Pen model seam (R3 wires the gateway-backed reviewer;
    tests inject a deterministic fake). ``signers`` are the governance authorisers the engine mints a FACT under.
    ``enumerate_paths(job, root) -> paths`` lists the WHOLE-TREE files to review (default: :func:`enumerate_tree`
    over the checkout — NO ``include_paths``); it FAILS CLOSED on an empty result (a checkout that yielded no file
    is a failed clone, never a silent clean). ``post_outcome(job, outcome)`` is the SOVEREIGN check-run writer seam
    (decision O-5) — only FACT severities cross; omitted ⇒ the worker only records the outcome (byte-identical to
    before any check-run wiring). ``sandbox`` / ``confirm`` are the engine's injectable test seams. ``_run`` injects
    ``run_redpen`` for offline tests.

    Returns the engine's outcome dict augmented with ``posted`` (the sovereign post result, if a writer was given)
    and ``post_refused`` (a post that refused/raised — recorded, never aborts the review). FATAL-2: ``run_redpen``
    is imported LAZILY, so this module stays import-clean in either venv and the engine is pulled only on the
    offense plane where the worker runs."""
    def _worker(job: SecurityJob) -> dict:
        run = _run
        if run is None:
            from ..redpen import run_redpen   # lazy (framework reached only via the certify seam)
            run = run_redpen

        root = checkout(job)
        if enumerate_paths is not None:
            paths = list(enumerate_paths(job, root) or [])
        else:
            paths = enumerate_tree(root, max_paths=max_paths)
        # FAIL-CLOSED on an empty whole-tree scope: a connected repo always has >= 1 reviewable file; an empty
        # enumeration means the checkout could not be determined (a failed/partial clone). Raising surfaces it as
        # a job failure (re-driveable by the runner), NEVER a false "clean" with no findings.
        if not paths:
            raise ValueError("redpen-system: the whole-tree scope is empty — the default-branch checkout could "
                             "not be determined; refusing a silent clean")

        kw: "dict[str, Any]" = {}
        if timeout is not None:
            kw["timeout"] = timeout
        if runs_required is not None:
            kw["runs_required"] = runs_required
        report = run(checkout_path=root, changed_paths=paths, reviewer=reviewer, engagement_slug=job.slug,
                     signers=signers, sandbox=sandbox, confirm=confirm, **kw)

        if not getattr(report, "enabled", False):
            # The engine is off (flag): inert, byte-identically absent — nothing reviewed, nothing posted.
            return {"enabled": False, "facts": [], "facts_count": 0, "leads_count": 0,
                    "blocking": False, "conclusion": "skipped", "posted": None, "post_refused": None}

        outcome = redpen_system_outcome(report)
        outcome["enabled"] = True
        outcome["posted"] = None
        outcome["post_refused"] = None
        # The check run is written SOVEREIGN-side from this inert outcome (O-5). A post that refuses/raises is
        # RECORDED, never aborts the review (the FACTs are already on the signed spine).
        if post_outcome is not None:
            try:
                outcome["posted"] = post_outcome(job, outcome)
            except Exception as e:  # noqa: BLE001 — a refused/failed check-run post never sinks the review
                outcome["post_refused"] = f"{type(e).__name__}: {str(e)[:200]}"
        return outcome

    return _worker


__all__ = ["enumerate_tree", "redpen_system_outcome", "make_redpen_system_worker", "Worker"]
