"""pr_bot — the PR-bot WORKER that turns a diff-scoped scan into gated review comments (repo-connect 3-live-a).

This is the "explain" step of the lifecycle: a ``SecurityJob`` for a connected repo's PR is diff-scanned
(``make_diff_codescan_worker``, 3a — oracle-verified findings on the signed spine), and each ORACLE-VERIFIED
finding is posted as a gated PR review comment (``post_review_comment``, 3b). It composes the read half (3a) and
the comment-write half (3b) into the worker ``JobRunner.run_one`` invokes; the fix-PR leg (3c) is wired by
3-live-b. Every control stays where it was proven: the diff worker fails CLOSED on an undetermined scope, and
each comment post is itself gated (``comment_enabled`` OFF by default ∧ the owner-signed repo-exact ``"comment"``
grant ∧ a per-action owner approval) + signed-audited — this module NEVER posts anything the gate would refuse,
it only drives the already-gated executor per finding.

A LEAD is never commented — only a finding carrying ``verified_by_oracle`` is posted (the prove-don't-guess
rule). A single post refusing / failing does NOT abort the job: it is RECORDED (``comments_refused``) and the
loop continues, so one un-approved or transient-failing comment never drops the whole PR review.

FATAL-2: the diff worker + ``post_review_comment`` are imported LAZILY, so this module is import-clean in either
venv; the real ones pull framework only on the offense plane where the worker runs.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .model import SecurityJob

Worker = Callable[[SecurityJob], dict]


def _finding_comment_body(f: dict) -> str:
    """A factual PR review-comment body for ONE oracle-verified finding. Only fields the scan produced — no
    prose the oracle did not ground. ``ref`` is the spine record ref (the finding is re-verifiable from it)."""
    title = str(f.get("title") or "finding")
    sev = str(f.get("severity") or "")
    cwe = f.get("cwe")
    loc = str(f.get("location") or "")
    ref = str(f.get("ref") or "")
    lines = ["**VIGIL** — oracle-verified finding in this PR's changed files", "", f"- **{title}**"]
    if sev:
        lines.append(f"- severity: {sev}")
    if cwe:
        lines.append(f"- CWE: {cwe}")
    if loc:
        lines.append(f"- location: `{loc}`")
    if ref:
        lines.append(f"- evidence ref: `{ref}`")
    lines += ["", "Confirmed by a deterministic oracle over the diff; re-verifiable from the evidence ref."]
    return "\n".join(lines)


def make_pr_bot_worker(
    *,
    base_dir: str,
    checkout: Callable[[SecurityJob], str],
    changed_files: Callable[[SecurityJob], "set[str]"],
    comment_config: Any,                       # live.github_write.GitHubCommentConfig
    trust_root: Any,
    approve: Callable[[str, str, Any], bool],
    audit: Callable[[dict], None],
    now: Any = None,
    max_files: int = 5000,
    grant_path: Any = None,
    epoch_path: Any = None,
    _scan_worker: Optional[Worker] = None,
    _post: Optional[Callable[..., dict]] = None,
) -> Worker:
    """Build the PR-bot worker for :meth:`JobRunner.run_one`. It diff-scans the PR (3a) then, for each
    ORACLE-VERIFIED finding, posts a gated review comment (3b's ``post_review_comment`` — ``comment_enabled`` is
    OFF by default, so with no explicit owner opt-in it posts NOTHING and only the scan runs).

    The comment leg is entered ONLY when ``comment_config.comment_enabled`` is set; then each post is still
    independently gated (grant + approval) + signed-audited. A post that refuses/raises is recorded in
    ``comments_refused`` and the loop continues (one comment never aborts the review). Returns the scan result
    dict augmented with ``comments_posted`` / ``comments_refused``. ``_scan_worker`` / ``_post`` are injection
    seams for offline tests; by default the real 3a diff worker + 3b executor are used."""
    def _worker(job: SecurityJob) -> dict:
        scan = _scan_worker
        if scan is None:
            from .runner import make_diff_codescan_worker   # lazy
            scan = make_diff_codescan_worker(base_dir=base_dir, checkout=checkout,
                                             changed_files=changed_files, max_files=max_files)
        result = scan(job)   # fail-closed on an undetermined diff scope (raises → job failure, re-driveable)

        posted: list = []
        refused: list = []
        if getattr(comment_config, "comment_enabled", False):
            post = _post
            if post is None:
                from ..live.github_write import post_review_comment   # lazy (framework-free module)
                post = post_review_comment
            for f in (result.get("findings") or []):
                if not (isinstance(f, dict) and f.get("verified_by_oracle")):
                    continue   # NEVER comment a LEAD — only an oracle-verified finding (prove-don't-guess)
                ref = str(f.get("ref") or "")
                try:
                    r = post(slug=job.slug, trust_root=trust_root, repo=job.repo, pr_number=job.pr_number,
                             body=_finding_comment_body(f), config=comment_config, approve=approve, audit=audit,
                             now=now, grant_path=grant_path, epoch_path=epoch_path)
                    posted.append({"ref": ref, "result": r})
                except Exception as e:  # noqa: BLE001 — a refused/failed post is RECORDED, never aborts the review
                    refused.append({"ref": ref, "error": f"{type(e).__name__}: {str(e)[:200]}"})
        return {**result, "comments_posted": posted, "comments_refused": refused}

    return _worker


__all__ = ["make_pr_bot_worker"]
