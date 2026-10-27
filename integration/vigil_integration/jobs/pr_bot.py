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

from .model import SecurityJob, _clip

Worker = Callable[[SecurityJob], dict]
FixPr = Callable[[SecurityJob, dict, Optional[str]], Any]


def _finding_comment_body(f: dict) -> str:
    """A factual PR review-comment body for ONE oracle-verified finding. Only fields the scan produced — no
    prose the oracle did not ground. ``ref`` is the spine record ref (the finding is re-verifiable from it).
    Every field is run through ``_clip`` (strips NUL/CR/LF, bounds length) BEFORE splicing: a finding's
    title/location is attacker-influenceable (it is derived from the scanned PR code), so a newline could
    otherwise inject fabricated bullets/sections into the markdown. The body is also owner-approved before it
    posts (3b), so this is defense-in-depth (red-pen LOW)."""
    title = _clip(f.get("title") or "finding")
    sev = _clip(f.get("severity"))
    cwe = _clip(f.get("cwe"))
    loc = _clip(f.get("location"))
    ref = _clip(f.get("ref"))
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


def _fix_summary(result: Any) -> dict:
    """A JSON-safe summary of a fix-PR ``PatchResult`` for the worker's result dict — only the fields the
    operator needs to see (the write itself is signed-audited inside ``authorized_fix_pr``, control 7)."""
    return {
        "status": str(getattr(result, "status", "") or ""),
        "pr_ref": str(getattr(result, "pr_ref", "") or ""),
        "remediated": bool(getattr(result, "remediated", False)),
    }


def make_pr_bot_fix_pr(
    *,
    checkout: Callable[[SecurityJob], str],
    spine_base_dir: str,
    codefix_config: Any,                       # live.codefix_runner.CodefixConfig (template; target_repo per job)
    trust_root: Any,
    audit: Callable[[dict], None],
    quorum: Optional[Callable[[Any], Any]] = None,
    now: Any = None,
    grant_path: Any = None,
    epoch_path: Any = None,
    _fix: Optional[Callable[..., Any]] = None,
    _from_spine: Optional[Callable[..., Any]] = None,
) -> FixPr:
    """Build the PR-bot's fix-PR leg (3c): ``fix_pr(job, finding, local_root=None) -> PatchResult``. For ONE
    oracle-verified finding it (a) rebuilds the CONFIRMED fact from the engagement's OWN signed offense spine —
    ``finding_from_spine`` over ``spine_base_dir`` + the finding's ``ref`` (prove-don't-guess: the fixer is fed
    the signed, re-verified fact, NEVER the in-memory scan dict; an absent, unknown, or ambiguous ref fails
    CLOSED — never a silent fall-back to the sole fact on the spine), (b)
    pins the CodefixConfig to the PR-head clone (``dataclasses.replace(target_repo=root)``), and (c) drives the
    already-gated 3c executor ``authorized_fix_pr``.

    This factory adds NO authority of its own — the fix PR opens ONLY if ``authorized_fix_pr``'s full chain
    clears: ``codefix_config.pr_enabled`` is OFF by default (⇒ refuse before any clone), an owner-signed
    repo-EXACT ``"pr"`` grant authorizes THIS repo, the clone's ``origin`` IS the granted repo, and the PCR
    ladder's WARDEN A3 tier + kill-switch + m-of-n ``quorum`` all pass; every write is signed-audited (control
    7). ``local_root`` lets the worker clone the PR head ONCE per job and reuse it across findings (the ladder
    re-clones ``target_repo`` into its own sandbox per fix anyway); omitted, the leg clones on its own.
    ``_fix`` / ``_from_spine`` are offline-test injection seams. FATAL-2: the framework-backed pieces import
    LAZILY, so this module stays import-clean in either venv and the leg is constructed only on the offense plane."""
    def fix_pr(job: SecurityJob, finding: dict, local_root: Optional[str] = None) -> Any:
        import dataclasses

        # the ref is VIGIL-generated by the scan (never PR content); it is matched RAW (no _clip truncation)
        # against the signed spine. An ABSENT ref fails CLOSED HERE — a fix must positively identify the
        # confirmed fact it remediates; we never fall back to "the sole fact on the spine" (build UP to the
        # guarantee, never soften it), and we refuse BEFORE cloning so a malformed finding costs no clone.
        ref = str((finding or {}).get("ref") or "")
        if not ref:
            from ..live.github_write import GitHubWriteError   # lazy (framework-free)
            raise GitHubWriteError("fix-PR refused: the finding carries no ref — cannot identify the confirmed "
                                   "fact to remediate (fail-closed)")

        fix = _fix
        if fix is None:
            from ..live.github_fix_pr import authorized_fix_pr   # lazy (offense)
            fix = authorized_fix_pr
        from_spine = _from_spine
        if from_spine is None:
            from ..live.trusted_finding import finding_from_spine   # lazy (offense)
            from_spine = finding_from_spine

        root = local_root if local_root is not None else checkout(job)
        # rebuild the CONFIRMED fact from the SIGNED spine by this exact ref (unknown/ambiguous ⇒ fail closed)
        fobj = from_spine(base_dir=spine_base_dir, slug=job.slug, target_repo=root, finding_ref=ref)
        cfg = dataclasses.replace(codefix_config, target_repo=root)
        return fix(slug=job.slug, trust_root=trust_root, repo=job.repo, finding=fobj, config=cfg,
                   audit=audit, quorum=quorum, now=now, grant_path=grant_path, epoch_path=epoch_path)

    return fix_pr


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
    fix_pr: Optional[FixPr] = None,
    _scan_worker: Optional[Worker] = None,
    _post: Optional[Callable[..., dict]] = None,
) -> Worker:
    """Build the PR-bot worker for :meth:`JobRunner.run_one`. It diff-scans the PR (3a) then, for each
    ORACLE-VERIFIED finding, posts a gated review comment (3b's ``post_review_comment`` — ``comment_enabled`` is
    OFF by default, so with no explicit owner opt-in it posts NOTHING and only the scan runs).

    The comment leg is entered ONLY when ``comment_config.comment_enabled`` is set; then each post is still
    independently gated (grant + approval) + signed-audited. The fix-PR leg (3c) is entered ONLY when a
    ``fix_pr`` callable is injected (built by :func:`make_pr_bot_fix_pr` — itself OFF by default via
    ``pr_enabled``); it opens a gated fix PR per oracle-verified finding. The two legs are independent opt-ins
    over the SAME verified findings. A post/fix that refuses/raises is recorded (in ``comments_refused`` /
    ``fixes_refused``) and the loop continues — one finding never aborts the review. Returns the scan result
    dict augmented with ``comments_posted`` / ``comments_refused`` / ``fixes_opened`` / ``fixes_refused``.
    ``_scan_worker`` / ``_post`` are injection seams for offline tests; by default the real 3a diff worker +
    3b executor are used."""
    def _worker(job: SecurityJob) -> dict:
        scan = _scan_worker
        if scan is None:
            from .runner import make_diff_codescan_worker   # lazy
            scan = make_diff_codescan_worker(base_dir=base_dir, checkout=checkout,
                                             changed_files=changed_files, max_files=max_files)
        result = scan(job)   # fail-closed on an undetermined diff scope (raises → job failure, re-driveable)

        posted: list = []
        refused: list = []
        fixes_opened: list = []
        fixes_refused: list = []

        comment_on = getattr(comment_config, "comment_enabled", False)
        post = None
        if comment_on:
            post = _post
            if post is None:
                from ..live.github_write import post_review_comment   # lazy (framework-free module)
                post = post_review_comment

        # ONE pass over the ORACLE-VERIFIED findings drives both opt-in write legs: the reversible comment (3b)
        # and the higher-risk fix PR (3c). Each leg is independently gated inside its own executor and records a
        # refusal rather than aborting the review. fix_root is the PR-head clone the fix leg reuses across
        # findings — cloned at most ONCE per job (on success OR a memoized failure), and only if the fix leg is
        # on AND a verified finding exists.
        fix_root: Optional[str] = None
        fix_checkout_error: Optional[str] = None   # a PERSISTENT PR-head-clone failure for THIS job, memoized
        #                                             so later findings refuse WITHOUT re-cloning (once-per-job)
        for f in (result.get("findings") or []):
            if not (isinstance(f, dict) and f.get("verified_by_oracle") is True):
                continue   # NEVER act on a LEAD — only a genuinely-True oracle-verified finding (`is True`, not
                #            truthiness, so a non-bool value can never pass as a fact — prove-don't-guess)
            if comment_on and post is not None:   # post is set whenever comment_on; the `is not None` narrows it
                ref = ""   # provisional, so a finding that raises even during ref/body prep is RECORDED, not fatal
                try:
                    ref = _clip(f.get("ref"))
                    r = post(slug=job.slug, trust_root=trust_root, repo=job.repo, pr_number=job.pr_number,
                             body=_finding_comment_body(f), config=comment_config, approve=approve, audit=audit,
                             now=now, grant_path=grant_path, epoch_path=epoch_path)
                    posted.append({"ref": ref, "result": r})
                except Exception as e:  # noqa: BLE001 — a refused/failed post is RECORDED, never aborts the review
                    refused.append({"ref": ref, "error": f"{type(e).__name__}: {str(e)[:200]}"})
            if fix_pr is not None:
                ref = ""   # provisional (same record-don't-abort contract as the comment leg)
                try:
                    ref = _clip(f.get("ref"))
                    if fix_checkout_error is not None:
                        # a prior PR-head clone for THIS job already failed; its inputs (repo/pr/token) are fixed
                        # per job, so every later finding would fail identically — record a refusal reusing that
                        # error WITHOUT re-cloning (clone at most ONCE per job; avoids N× clone amplification).
                        fixes_refused.append({"ref": ref, "error": fix_checkout_error})
                    else:
                        if fix_root is None:
                            try:
                                fix_root = checkout(job)   # clone the PR head ONCE per job; reused across findings
                            except Exception as ce:  # noqa: BLE001 — a PERSISTENT clone failure is memoized …
                                fix_checkout_error = f"{type(ce).__name__}: {str(ce)[:200]}"
                                raise                   # … then recorded by the outer except, like any refusal
                        r = fix_pr(job, f, fix_root)
                        fixes_opened.append({"ref": ref, "result": _fix_summary(r)})
                except Exception as e:  # noqa: BLE001 — a refused/failed fix is RECORDED, never aborts the review
                    fixes_refused.append({"ref": ref, "error": f"{type(e).__name__}: {str(e)[:200]}"})
        return {**result, "comments_posted": posted, "comments_refused": refused,
                "fixes_opened": fixes_opened, "fixes_refused": fixes_refused}

    return _worker


def make_pr_bot_runner(
    *,
    queue_root: str,
    base_dir: str,
    trust_root: Any,
    checkout: Optional[Callable[[SecurityJob], str]] = None,
    changed_files: Optional[Callable[[SecurityJob], "set[str]"]] = None,
    comment_config: Any = None,
    approve: Any = None,
    audit: Any = None,
    now: Any = None,
    max_files: int = 5000,
    grant_path: Any = None,
    epoch_path: Any = None,
    fix_pr: Any = None,
    assert_tenant: Any = None,
    _queue: Any = None,
    _gate: Any = None,
    _worker: Any = None,
) -> Any:
    """Assemble the PR-bot execution runner (3-live-b2): the durable ``SecurityJob`` queue + the hard per-job
    authorization gate (``build_repo_gate`` over the pinned authority root — fail-closed) + the PR-bot worker
    (diff-scan → gated comments → gated fix PRs). Returns a :class:`jobs.runner.JobRunner` whose ``drain()`` runs
    each QUEUED job through ``run_one`` — so the authorization gate stays the SOLE executor (no trigger adapter
    ever runs a worker, and a job that fails the gate is refused WITHOUT running). ``fix_pr`` is the optional 3c
    fix-PR leg (built by :func:`make_pr_bot_fix_pr`, itself OFF by default); omitted ⇒ the worker only comments.
    ``_queue`` / ``_gate`` are injection seams for offline tests; the rest are the live seams the ``vigil pr-bot``
    command builds (the gated PR-head ``checkout``, the read-client ``changed_files``, and the comment config /
    owner approver / signed-audit sink)."""
    from .authorize import build_repo_gate
    from .queue import SecurityJobQueue
    from .runner import JobRunner

    queue = _queue if _queue is not None else SecurityJobQueue(queue_root)
    gate = _gate if _gate is not None else build_repo_gate(trust_root, now=now)
    worker = _worker if _worker is not None else make_pr_bot_worker(
        base_dir=base_dir, checkout=checkout, changed_files=changed_files, comment_config=comment_config,
        trust_root=trust_root, approve=approve, audit=audit, now=now, max_files=max_files,
        grant_path=grant_path, epoch_path=epoch_path, fix_pr=fix_pr)
    return JobRunner(queue=queue, gate=gate, worker=worker, assert_tenant=assert_tenant)


__all__ = ["make_pr_bot_fix_pr", "make_pr_bot_worker", "make_pr_bot_runner"]
