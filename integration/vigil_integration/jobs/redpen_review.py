"""redpen_review — the Red-Pen PR-review WORKER (offense plane, VIGIL R3; design §7.2 + decisions O-1..O-6).

A connected repository's pull request is reviewed here: the worker reserves the review against the prepaid wallet
(R2 ``reserve_redpen_review`` — the owner-signed connected-repo record is the authorization of record, decision O-3;
the per-repo monthly spending limit refuses NEW reviews at the ceiling, decision O-2), fetches the PR-head checkout +
the changed files, drives the Red-Pen reproduction engine (:func:`vigil_integration.redpen.run_redpen`) DIFF-SCOPED,
and for each REPRODUCED FACT posts a severity-marked review comment (🔴 Critical/High — merge-blocking · 🟠 Medium ·
🟡 Low) carrying the reproduce command + the evidence ref + a machine-readable **Fix this** marker, via the gated
``post_review_comment``. **LEADs are NEVER posted** (decision O-1). The review's exact charge is then settled (R2
``record_charge`` through the injected settle seam), and two INERT envelopes leave the worker:

  * the review OUTCOME (``vigil.redpen.review-outcome.v1``) for the SOVEREIGN "VIGIL Red-Pen" check-run writer
    (decision O-5) — it carries ONLY reproduced-FACT severities, never a LEAD, so a LEAD can never block a merge;
  * the review RECORD (``vigil.redpen.review-record.v1``) for the customer dashboard — the FACT rows (with the
    GitHub comment each was posted as + its Fix-this ref) AND the LEAD rows, which live ONLY there ("LEADs stay in
    the dashboard"). Neither envelope carries internal diagnostics (no engine reason text, no lens identifiers).

FATAL-2 (the keyless offense plane): this module imports NO ``sigil`` and holds no key. Every SOVEREIGN operation is
an INJECTED SEAM — ``reserve`` (owner-signed wallet reservation), ``settle`` (owner-signed charge record), ``post``
(the gated comment write), ``emit_outcome`` / ``record_review`` (hand an inert envelope across the plane boundary).
This mirrors ``jobs.pr_bot``: the worker drives already-gated executors and never adds authority of its own. The
GitHub App key never reaches here; only the per-repo-scoped install token does, via the seam the ``post`` executor
uses.

Master flag ``VIGIL_REDPEN_ENABLED`` (default OFF): the worker reads it FIRST (the keyless env read R1 uses) and,
when off, returns ``{"review": "disabled"}`` before any side effect — no reserve, no clone, no GitHub read, no post,
no settle, no envelope. Byte-identically absent.

Only :meth:`jobs.runner.JobRunner.run_one` runs this worker (it is a ``Worker``); no trigger adapter ever runs it
directly. A single comment/settle/hand-off that refuses or raises is RECORDED, never aborts the review.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Optional, Sequence

from .model import SecurityJob, _clip

#: The inert review-outcome envelope schema (offense → the sovereign check-run writer, decision O-5). Only
#: reproduced-FACT severities cross; a LEAD never appears here, so a LEAD can never make the check block.
REVIEW_OUTCOME_SCHEMA = "vigil.redpen.review-outcome.v1"
#: The inert review-record schema (offense → the customer dashboard). FACT rows + LEAD rows; customer-safe fields
#: only (no internal reason text, no lens identifiers).
REVIEW_RECORD_SCHEMA = "vigil.redpen.review-record.v1"

#: The machine-readable "Fix this" marker that ends every posted FACT comment: ``<!-- VIGIL-RED-PEN:FIX-THIS
#: ref=<fix_ref> -->``. ``fix_ref`` is the finding's evidence ref, strictly sanitised (:func:`fix_this_marker`) so a
#: model-proposed (diff-influenced) ref can never break out of the HTML comment. R5 (VIGIL Fix) reads it back with
#: :func:`parse_fix_this_marker` and matches it to the review record's ``facts[].fix_ref``.
_FIX_THIS_MARKER = "<!-- VIGIL-RED-PEN:FIX-THIS ref={ref} -->"
_FIX_THIS_RE = re.compile(r"<!-- VIGIL-RED-PEN:FIX-THIS ref=([A-Za-z0-9:_.~/#-]{1,120}) -->")

# A FACT's severity → the comment marker + whether it is a MERGE-BLOCKING severity at the default posture. The
# per-repo threshold is applied SOVEREIGN-side (it holds the connected-repo record); this is only the visual + the
# "blocks merge" words in the comment copy.
_SEVERITY_MARKER = {
    "critical": ("🔴", "Critical", True),
    "high": ("🔴", "High", True),
    "medium": ("🟠", "Medium", False),
    "low": ("🟡", "Low", False),
    "info": ("🟡", "Info", False),
}

Worker = Callable[[SecurityJob], dict]
#: reserve(job) -> {"ok": True, "slug", "org_id", "nonce", "units_reserved", ...} | {"ok": False, "error": str}
Reserve = Callable[[SecurityJob], dict]
#: settle(reservation: dict, report: Any) -> Any  (records the exact charge; sovereign-backed or a test fake)
Settle = Callable[[dict, Any], Any]
#: a hand-off seam: (envelope: dict) -> Any  (an inert spool writer in production, a capture in tests)
Handoff = Callable[[dict], Any]
EmitOutcome = Handoff


def _norm_sev(value: Any) -> str:
    s = str(value or "").strip().lower()
    return s if s in _SEVERITY_MARKER else "medium"


def _safe_marker_ref(ref: Any) -> str:
    """A ref safe to splice INTO the ``<!-- ... -->`` Fix-this marker. The finding ref / bug_class can be
    model-proposed from the reviewed diff (attacker-influenceable), so restrict it to an unambiguous charset and
    bound it — no ``<``/``>`` and no ``-`` run that could spell ``-->``, no control chars. Empty ⇒ ``"finding"``."""
    s = re.sub(r"[^A-Za-z0-9:_.~/#]+", "-", str(ref or "")).strip("-")[:120]
    return s or "finding"


def fix_this_marker(ref: Any) -> str:
    """The exact machine-readable Fix-this marker line for a finding ``ref`` (the last line of its posted comment)."""
    return _FIX_THIS_MARKER.format(ref=_safe_marker_ref(ref))


def parse_fix_this_marker(body: Any) -> Optional[str]:
    """The ``fix_ref`` carried by a posted Red-Pen FACT comment ``body``, or None when it carries no marker. Only the
    LAST marker line counts (the one the worker writes), so a marker-shaped string quoted earlier in the body (e.g.
    inside a bug class) can never be mistaken for it."""
    lines = [ln for ln in str(body or "").splitlines() if ln.strip()]
    if not lines:
        return None
    m = _FIX_THIS_RE.fullmatch(lines[-1].strip())
    return m.group(1) if m else None


def reproduce_command(slug: str, ref: str) -> str:
    """The customer-safe reproduce / re-verify command for one posted FACT. The finding is backed by a SIGNED,
    offline-re-verifiable evidence certificate (minted by the reproduction engine, decision O-1) identified by
    ``ref``; ``vigil proof-export`` assembles the client-verifiable bundle that re-proves it with ZERO trust in
    VIGIL. No AI-model / engine name ever appears (customer-surface rule)."""
    return f"vigil proof-export --slug {_clip(slug, 80)}  # re-verify evidence {_clip(ref, 160)} offline, zero-trust"


def _fact_ref(fact: Any) -> str:
    return str(getattr(fact, "finding_ref", "") or getattr(fact, "bug_class", "") or "finding")


def _fact_line(fact: Any) -> int:
    line = getattr(fact, "line", 0)
    return int(line) if isinstance(line, int) and not isinstance(line, bool) and line > 0 else 0


def _fact_comment_body(fact: Any, *, slug: str) -> str:
    """A factual, severity-marked PR review-comment body for ONE reproduced FACT — a CUSTOMER surface. Carries only
    the bug class, severity, location, the confirming oracle, the evidence ref, the reproduce command and the
    Fix-this marker; never an internal lens identifier or engine reason text. Every attacker-influenceable field
    (bug class / location / ref, all derived from the reviewed diff) is run through ``_clip`` BEFORE splicing
    (strips NUL/CR/LF, bounds length) so a crafted field cannot inject fabricated markdown lines; the marker's ref is
    additionally charset-restricted. Only FACTs reach this — a LEAD is never posted (decision O-1)."""
    sev = _norm_sev(getattr(fact, "severity", "medium"))
    marker, label, blocking = _SEVERITY_MARKER[sev]
    bug_class = _clip(getattr(fact, "bug_class", "") or "finding")
    ref = _fact_ref(fact)
    file = _clip(getattr(fact, "file", ""))
    line = _fact_line(fact)
    confirmed_by = _clip(getattr(fact, "confirmed_by", ""))
    head = f"{marker} **VIGIL Red-Pen — {label}" + (" (blocks merge)" if blocking else "") + "**"
    lines = [head, "", (f"- **{bug_class}** — reproduced twice in an isolated sandbox and confirmed by a "
                        "deterministic oracle")]
    if file:
        lines.append(f"- location: `{file}`" + (f":{line}" if line else ""))
    if confirmed_by:
        lines.append(f"- confirmed by: `{confirmed_by}`")
    lines.append(f"- evidence ref: `{_clip(ref)}`")
    lines += ["", f"Reproduce: `{reproduce_command(slug, ref)}`", "",
              ("Fix this: use the **Fix this** action in the VIGIL dashboard to open a re-checked fix PR (VIGIL "
               "never merges it)."),
              fix_this_marker(ref)]
    return "\n".join(lines)


def _outcome_fact(fact: Any) -> dict:
    """The minimal, JSON-safe row of one FACT for the inert review-outcome envelope — bounded + control-char-free.
    No LEAD field, no model text: only what the sovereign check writer needs to decide the conclusion + annotate."""
    return {
        "bug_class": _clip(getattr(fact, "bug_class", "")),
        "severity": _norm_sev(getattr(fact, "severity", "medium")),
        "finding_ref": _clip(getattr(fact, "finding_ref", "")),
        "file": _clip(getattr(fact, "file", "")),
        "line": _fact_line(fact),
        "confirmed_by": _clip(getattr(fact, "confirmed_by", "")),
    }


def build_review_outcome(job: SecurityJob, report: Any, *, slug: str, org_id: str = "",
                         refused: str = "") -> dict:
    """Build the INERT review-outcome envelope the SOVEREIGN "VIGIL Red-Pen" check writer consumes (decision O-5).

    It carries ONLY reproduced-FACT severities (``fact_severities``) + their minimal rows — **never a LEAD**, so a
    LEAD can never make the check block. ``org_id`` + ``repo`` let the sovereign resolve the owner-signed
    connected-repo record (the authorization of record, O-3), which holds the per-repo merge-blocking threshold +
    the installation id; neither is a secret. ``refused`` (non-empty) marks a review that never ran (reserve
    refused — unconnected / at the monthly limit / empty wallet): no FACTs ⇒ the sovereign writes a NON-blocking
    (neutral) check. ``report`` is duck-typed (a ``redpen.RedPenReport``), so this module pulls no ``framework``."""
    facts = tuple(getattr(report, "facts", ()) or ()) if report is not None else ()
    leads = tuple(getattr(report, "leads", ()) or ()) if report is not None else ()
    rows = [_outcome_fact(f) for f in facts]
    return {
        "schema": REVIEW_OUTCOME_SCHEMA,
        "repo": _clip(job.repo),
        "org_id": _clip(org_id, 64),
        "head_sha": _clip(job.commit, 128),
        "pr_number": job.pr_number,
        "slug": _clip(slug, 80),
        "delivery_id": _clip(job.delivery_id),
        "fact_severities": [r["severity"] for r in rows],   # ONLY reproduced-FACT severities cross
        "facts": rows,
        "lead_count": len(leads),
        "refused": bool(refused),
        "reason": _clip(refused, 512),
    }


def _record_lead(lead: Any) -> dict:
    """One LEAD row for the dashboard record — structured fields only. The engine's ``reason`` text is deliberately
    NOT carried (it is an internal diagnostic and can name engine internals); ``outcome`` is the short status code."""
    return {
        "bug_class": _clip(getattr(lead, "bug_class", "")),
        "severity": _norm_sev(getattr(lead, "severity", "medium")),
        "finding_ref": _clip(getattr(lead, "finding_ref", "")),
        "file": _clip(getattr(lead, "file", "")),
        "line": _fact_line(lead),
        "outcome": _clip(getattr(lead, "outcome", ""), 64),
    }


def build_review_record(job: SecurityJob, report: Any, *, slug: str, org_id: str = "", refused: str = "",
                        comments: "Optional[Sequence[Optional[dict]]]" = None) -> dict:
    """Build the INERT review RECORD for the customer dashboard (``vigil.redpen.review-record.v1``).

    ``facts`` — one row per reproduced FACT: the outcome row plus ``fix_ref`` (what its comment's Fix-this marker
    carries — :func:`parse_fix_this_marker` of the posted body returns exactly this), ``reproduce`` (the command the
    comment shows) and ``comment`` (``{"id", "html_url"}`` of the posted GitHub comment, or None when it was not
    posted — comments off, or the gated post refused). ``comments[i]`` pairs with ``report.facts[i]``.
    ``leads`` — one row per LEAD: they live ONLY here (never posted, never in the check envelope).
    ``refused`` (non-empty) marks a review that never ran (its reason is the reserve's own refusal text). Customer-
    safe fields only: no engine reason text, no lens identifiers, nothing a customer surface must not show."""
    facts = tuple(getattr(report, "facts", ()) or ()) if report is not None else ()
    leads = tuple(getattr(report, "leads", ()) or ()) if report is not None else ()
    posted = list(comments or ())
    fact_rows = []
    for i, f in enumerate(facts):
        ref = _fact_ref(f)
        c = posted[i] if i < len(posted) else None
        fact_rows.append({**_outcome_fact(f), "fix_ref": _safe_marker_ref(ref),
                          "reproduce": reproduce_command(slug, ref),
                          "comment": ({"id": c.get("id"), "html_url": _clip(c.get("html_url"))}
                                      if isinstance(c, dict) else None)})
    return {
        "schema": REVIEW_RECORD_SCHEMA,
        "repo": _clip(job.repo),
        "org_id": _clip(org_id, 64),
        "head_sha": _clip(job.commit, 128),
        "pr_number": job.pr_number,
        "slug": _clip(slug, 80),
        "delivery_id": _clip(job.delivery_id),
        "facts": fact_rows,
        "leads": [_record_lead(x) for x in leads],
        "skipped_lens_count": len(getattr(report, "skipped_lenses", ()) or ()) if report is not None else 0,
        "refused": bool(refused),
        "reason": _clip(refused, 512),
    }


def make_inert_spooler(spool_dir: "str | Any") -> Handoff:
    """A concrete hand-off seam: write an inert envelope to ``<spool_dir>/incoming/<sha256(bytes)[:32]>.json``
    atomically (0600 file in a 0700 dir; O_EXCL temp + fsync + os.replace), content-addressed (re-emitting the same
    envelope is idempotent). The production ``emit_outcome`` (→ the sovereign check-run drain,
    ``governor.redpen_check.RedpenOutcomeDrain``) and ``record_review`` (→ the dashboard ingestion) sinks. stdlib
    only; it carries no key and no model text (the envelopes it is handed contain none)."""
    import hashlib
    import json
    import os
    import secrets
    from pathlib import Path

    def emit(envelope: dict) -> str:
        data = json.dumps(envelope, ensure_ascii=True, sort_keys=True).encode("utf-8")
        incoming = Path(spool_dir) / "incoming"
        incoming.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(incoming, 0o700)
        except OSError:
            pass
        final = incoming / (hashlib.sha256(data).hexdigest()[:32] + ".json")
        if final.exists():
            return str(final)
        tmp = incoming / (".tmp-" + secrets.token_hex(8))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, final)
        return str(final)

    return emit


def _no_candidate_reviewer(request: Any) -> Any:
    """The default reviewer seam: proposes NO candidates for any lens. Fail-closed honesty — until the live
    gateway-backed reviewer is wired (the live flip waits, HANDOFF §12), a review mints no FACT rather than a guessed
    one. ``run_redpen`` consults this per lens; an empty response yields an empty report."""
    from ..redpen import LensResponse   # lazy: redpen is import-clean (framework is lazy behind its certify seam)
    return LensResponse(candidates=())


def make_redpen_review_worker(
    *,
    reserve: Reserve,
    checkout: Callable[[SecurityJob], str],
    changed_files: Callable[[SecurityJob], "set[str]"],
    comment_config: Any,                       # live.github_write.GitHubCommentConfig (comment_enabled OFF by default)
    trust_root: Any,
    approve: Callable[[str, str, Any], bool],
    audit: Callable[[dict], None],
    signers: "Sequence[tuple[str, str]]",
    reviewer: Optional[Callable[[Any], Any]] = None,
    settle: Optional[Settle] = None,
    emit_outcome: Optional[Handoff] = None,
    record_review: Optional[Handoff] = None,
    now: Any = None,
    grant_path: Any = None,
    epoch_path: Any = None,
    lenses: "Optional[Sequence[str]]" = None,
    _run_review: Optional[Callable[..., Any]] = None,
    _post: Optional[Callable[..., dict]] = None,
) -> Worker:
    """Build the Red-Pen PR-review worker for :meth:`JobRunner.run_one`.

    Per job it: (0) returns ``{"review": "disabled"}`` with NO side effect when ``VIGIL_REDPEN_ENABLED`` is off.
    (1) ``reserve(job)`` — the R2 owner-signed reservation (authorization of record = the connected-repo record,
    decision O-3; the monthly spending limit refuses NEW reviews at the ceiling, decision O-2). A refusal
    (unconnected / at the limit / empty wallet) records the refusal, hands off a NON-blocking outcome + a refused
    record, and runs NO review. (2) ``checkout(job)`` + ``changed_files(job)`` — the gated PR-head clone + the changed
    repo paths (fail-closed on an empty/undetermined scope, like the diff worker). (3) ``run_redpen`` DIFF-SCOPED
    over them with the injected ``reviewer`` seam. (4) For each REPRODUCED FACT, a severity-marked
    ``post_review_comment`` (gated: ``comment_enabled`` OFF by default ⇒ posts NOTHING; then the owner-signed
    repo-exact grant + per-action approval). **LEADs are never posted** (decision O-1). (5) ``settle(reservation,
    report)`` records the exact charge (R2 ``record_charge``). (6) ``emit_outcome(outcome)`` hands the INERT outcome
    (FACT severities only) to the sovereign check writer; ``record_review(record)`` hands the dashboard record (FACT
    rows with their comments + the LEAD rows).

    All sovereign ops are injected (FATAL-2). ``reviewer`` defaults to the fail-closed no-candidate reviewer (no FACTs
    until the live reviewer is wired). ``settle`` / ``emit_outcome`` / ``record_review`` are optional. ``_run_review``
    / ``_post`` are offline-test injection seams. A refused/failed post/settle/hand-off is RECORDED, never aborts the
    review. Returns ``{"review": "ran"|"refused"|"disabled", ...}`` (see the module's report for the full shape)."""
    def _worker(job: SecurityJob) -> dict:
        from ..redpen import redpen_enabled   # keyless env read (R1); redpen is import-clean
        if not redpen_enabled():
            return {"review": "disabled", "facts_posted": [], "facts_refused": [], "lead_count": 0}
        res = reserve(job)
        if not (isinstance(res, dict) and res.get("ok")):
            # Reserve refused — the review does NOT run (an unconnected repo, the monthly spending limit reached, an
            # empty wallet, or the reserve unavailable). Hand off a NON-blocking outcome (the check is neutral — no
            # FACTs) and a refused record (the dashboard says why). Nothing is posted; nothing is charged.
            reason = str((res or {}).get("error") or "review reservation refused")
            r_slug = str((res or {}).get("slug") or job.slug)
            r_org = str((res or {}).get("org_id") or "")
            outcome = build_review_outcome(job, None, slug=r_slug, org_id=r_org, refused=reason)
            record = build_review_record(job, None, slug=r_slug, org_id=r_org, refused=reason)
            _handoff(emit_outcome, outcome)
            _handoff(record_review, record)
            return {"review": "refused", "reason": _clip(reason, 512), "facts_posted": [], "facts_refused": [],
                    "lead_count": 0, "outcome": outcome, "record": record}

        slug = str(res.get("slug") or job.slug)
        org_id = str(res.get("org_id") or "")

        run = _run_review
        if run is None:
            from ..redpen import run_redpen   # lazy (redpen import-clean; framework stays behind its certify seam)
            run = run_redpen
        rev = reviewer if reviewer is not None else _no_candidate_reviewer

        root = checkout(job)
        paths = changed_files(job)
        # FAIL-CLOSED on an undetermined scope (mirror make_diff_codescan_worker): a PR always changes >=1 file; an
        # empty/odd result means the diff could not be determined — raise (job failure, re-driveable), never a
        # silent clean review.
        if not isinstance(paths, (set, frozenset)):
            raise TypeError(f"changed_files must return a set of paths, got {type(paths).__name__}")
        if not paths:
            raise ValueError("diff-scope: changed_files returned an empty set — the PR's changed files could not "
                             "be determined; refusing a silent clean review")

        report = run(checkout_path=root, changed_paths=sorted(paths), reviewer=rev, engagement_slug=slug,
                     signers=list(signers), lenses=lenses)

        posted: list = []
        refused: list = []
        comment_on = getattr(comment_config, "comment_enabled", False)
        post = None
        if comment_on:
            post = _post
            if post is None:
                from ..live.github_write import post_review_comment   # lazy (framework-free module)
                post = post_review_comment

        # ONE pass over the REPRODUCED FACTS — and ONLY the facts (LEADs are never posted, decision O-1). Each post
        # is itself gated inside post_review_comment; a refusal/failure is recorded, never aborts the review.
        facts = tuple(getattr(report, "facts", ()) or ())
        comments: "list[Optional[dict]]" = [None] * len(facts)
        for i, fact in enumerate(facts):
            ref = _clip(_fact_ref(fact))
            if comment_on and post is not None:
                try:
                    r = post(slug=slug, trust_root=trust_root, repo=job.repo, pr_number=job.pr_number,
                             body=_fact_comment_body(fact, slug=slug), config=comment_config, approve=approve,
                             audit=audit, now=now, grant_path=grant_path, epoch_path=epoch_path)
                    posted.append({"ref": ref, "result": r})
                    comments[i] = r if isinstance(r, dict) else None
                except Exception as e:  # noqa: BLE001 — a refused/failed post is RECORDED, never aborts the review
                    refused.append({"ref": ref, "error": f"{type(e).__name__}: {str(e)[:200]}"})

        # Settle the EXACT charge (R2 record_charge, through the sovereign-backed seam). A settle failure is
        # recorded — the review (and its posted FACTs) stand; re-settle is idempotent per (slug, nonce).
        settle_error = ""
        if settle is not None:
            try:
                settle(res, report)
            except Exception as e:  # noqa: BLE001
                settle_error = f"{type(e).__name__}: {str(e)[:200]}"

        outcome = build_review_outcome(job, report, slug=slug, org_id=org_id)
        record = build_review_record(job, report, slug=slug, org_id=org_id, comments=comments)
        _handoff(emit_outcome, outcome)
        _handoff(record_review, record)

        return {
            "review": "ran", "slug": slug, "facts_posted": posted, "facts_refused": refused,
            "lead_count": len(getattr(report, "leads", ()) or ()),
            "facts_seen": len(facts),
            "skipped_lenses": len(getattr(report, "skipped_lenses", ()) or ()),
            "settle_error": settle_error, "outcome": outcome, "record": record,
            "reserved": {"units": res.get("units_reserved"), "nonce": res.get("nonce")},
        }

    return _worker


def _handoff(sink: "Optional[Handoff]", envelope: dict) -> None:
    """Hand one inert envelope to its sink, recording-not-aborting: a failed hand-off must never sink a review whose
    FACTs are already posted (the check / the dashboard row can be re-driven from a re-emit)."""
    if sink is None:
        return
    try:
        sink(envelope)
    except Exception:  # noqa: BLE001 — a failed hand-off is non-fatal (the review already ran)
        pass


def make_redpen_review_runner(
    *,
    queue_root: str,
    trust_root: Any,
    reserve: Reserve,
    checkout: Callable[[SecurityJob], str],
    changed_files: Callable[[SecurityJob], "set[str]"],
    comment_config: Any,
    approve: Any,
    audit: Any,
    signers: "Sequence[tuple[str, str]]",
    reviewer: Any = None,
    settle: Any = None,
    emit_outcome: Any = None,
    record_review: Any = None,
    now: Any = None,
    grant_path: Any = None,
    epoch_path: Any = None,
    lenses: Any = None,
    assert_tenant: Any = None,
    _queue: Any = None,
    _gate: Any = None,
    _worker: Any = None,
) -> Any:
    """Assemble the Red-Pen review execution runner (the sibling of :func:`jobs.pr_bot.make_pr_bot_runner`): the
    durable ``SecurityJob`` queue + the hard per-job authorization gate (``build_repo_gate`` over the pinned
    authority root — fail-closed) + the Red-Pen review worker. Returns a :class:`jobs.runner.JobRunner` whose
    ``drain()`` runs each QUEUED job through ``run_one`` — so the authorization gate stays the SOLE executor (no
    trigger adapter ever runs the worker). ``_queue`` / ``_gate`` / ``_worker`` are offline-test injection seams."""
    from .authorize import build_repo_gate
    from .queue import SecurityJobQueue
    from .runner import JobRunner

    queue = _queue if _queue is not None else SecurityJobQueue(queue_root)
    gate = _gate if _gate is not None else build_repo_gate(trust_root, now=now)
    worker = _worker if _worker is not None else make_redpen_review_worker(
        reserve=reserve, checkout=checkout, changed_files=changed_files, comment_config=comment_config,
        trust_root=trust_root, approve=approve, audit=audit, signers=signers, reviewer=reviewer, settle=settle,
        emit_outcome=emit_outcome, record_review=record_review, now=now, grant_path=grant_path,
        epoch_path=epoch_path, lenses=lenses)
    return JobRunner(queue=queue, gate=gate, worker=worker, assert_tenant=assert_tenant)


__all__ = [
    "REVIEW_OUTCOME_SCHEMA", "REVIEW_RECORD_SCHEMA", "fix_this_marker", "parse_fix_this_marker",
    "reproduce_command", "build_review_outcome", "build_review_record", "make_inert_spooler",
    "make_redpen_review_worker", "make_redpen_review_runner",
]
