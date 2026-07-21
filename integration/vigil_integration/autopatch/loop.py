"""
autopatch.loop — the AIxCC AUTO-PATCH loop, layered on the sovereign codefix pipeline (VIGIL phase 32).

redamon-style AI-cyber-challenge patching finds a vulnerability, asks an LLM for a fix, applies it, and
(in the reference systems) accepts the fix on a permissive default. VIGIL keeps the SHAPE — propose →
apply-in-a-sandbox → build → open-PR → verify — but subordinates the whole loop to the sovereign core and
inverts every fail-open default, building directly ON TOP of :mod:`vigil_integration.remediation` (the
gated, tiered codefix boundary) and :mod:`vigil_integration.fsjob` (the path-confinement kernel):

  * **Confirmed-only (the sovereign entry).** :func:`autopatch` refuses fail-closed unless ``finding`` is
    an oracle-confirmed FACT (``remediation.may_remediate`` / ``spawn_remediation``). A LEAD — however
    severe, KEV-flagged, or correlated — can NEVER be auto-patched.
  * **The LLM only PROPOSES.** ``propose_patch`` (the injected coder LLM) returns a *minimal unified-diff*
    proposal — untrusted text. It is parsed FAIL-CLOSED (:func:`parse_unified_diff`): every target path is
    stripped of its ``a/``\\ /\\ ``b/`` prefix and re-validated through the remediation path guard
    (``is_safe_repo_path``) AND the fsjob lexical confinement kernel (``lexical_components``), so a
    malicious diff can never smuggle a ``/dev/null``-only, absolute, flag, or ``..`` path into the patch.
    No valid file → no patch (never an empty PR).
  * **Tiered, gated stages in an fsjob sandbox.** clone/branch = A1, per-file edit = A2, sandbox build =
    A3, opening the PR = A3 **destructive** AND an explicit m-of-n ``quorum``. Every stage routes through
    the injected conjunctive ``gate`` (reusing ``remediation.codefix``'s exact fail-closed normalizers), so
    no gate wired / a gate error / a ``queue`` / a ``deny`` stops the stage. Only the explicit, approved,
    path-validated files are ever staged — NEVER ``git add -A``.
  * **THE CRITICAL FLIP — deadline approval.** Each file's edit needs an explicit ``approve`` that lands
    IN-WINDOW: the injected ``approval`` carries a ``deadline`` and the injected ``now`` clock decides
    expiry. If ``now()`` is past the deadline (a TIMEOUT), or no approval mechanism is wired, or the clock
    is unavailable, or the decision is anything but ``approve`` → the edit is REJECTED. This inverts
    redamon's auto-accept-on-timeout, and it is deterministic (injected clock, no wallclock).
  * **Verify before signing 'remediated'.** The single fix-verification ``oracle`` re-fires the ORIGINAL
    exploit against the PATCHED build. 'remediated' is minted ONLY when the oracle goes SILENT (the exploit
    no longer fires) AND returns a signed certificate. An exploit that STILL fires → 'still-vulnerable'
    (the PR — a fix *proposal* — is open, but nothing is certified); a missing/erroring oracle, or silence
    with no signed cert → 'unverified'. Only a deterministic oracle mints the signed FACT.
  * **Deterministic + secret-free + total.** Step sequence numbers come from an injected counter (no
    wallclock / RNG); the ``remediation_id`` derives from the finding's signed provenance, not ``uuid``;
    every recorded payload is scrubbed through the ONE F3 redaction path. Every public function degrades a
    malformed input to a refusal, never a raise.

Import-clean: pydantic + stdlib + the ``remediation`` (F10) and ``fsjob`` (F9) seams only (the injected
gate / oracle / LLM / clone / build / PR / quorum / approval / clock keep git / build / network out).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field, model_validator

from ..fsjob import PathEscapeError, lexical_components
from ..remediation import (
    FixVerification,
    PipelineStep,
    is_safe_repo_path,
    may_remediate,
    spawn_remediation,
)
from ..remediation.codefix import (
    TIER_BUILD,
    TIER_CLONE,
    TIER_EDIT,
    TIER_PR,
    _BULK_TOKENS,
    _exec_ok,
    _gate_allows,
    _quorum_ok,
    _Recorder,
)

# --- bounds on the untrusted unified-diff proposal (a giant/rambling diff is refused, not parsed) ------
_MAX_DIFF_BYTES = 1_000_000
_MAX_DIFF_FILES = 500

# unified-diff meta lines that belong to a file header block (used to attribute the raw per-file segment)
_GIT_META = (
    "diff --git ", "index ", "old mode ", "new mode ", "similarity ", "dissimilarity ",
    "rename ", "copy ", "new file mode ", "deleted file mode ",
)
_DEVNULL = "\x00__dev_null__"      # sentinel for a "/dev/null" side of a diff header (add/delete marker)
_QUOTE_RE = re.compile(r'^"(.*)"$')


# --- injected-executor / verdict result shapes (duck-typed; the loop only reads attributes) -----------


class CloneResult(BaseModel):
    ok: bool = False
    workdir: str = ""
    branch: str = ""
    reason: str = ""


class BuildResult(BaseModel):
    ok: bool = False
    build_ref: str = ""
    reason: str = ""


class PrResult(BaseModel):
    ok: bool = False
    pr_ref: str = ""
    reason: str = ""


class QuorumOutcome(BaseModel):
    """The m-of-n threshold result for opening the PR. Defaults to DENY (fail-closed)."""

    approved: bool = False
    reason: str = ""
    signer_ids: list[str] = Field(default_factory=list)


class PatchApproval(BaseModel):
    """One per-file approval RESPONSE carrying a DEADLINE. VIGIL flips redamon's auto-accept-on-timeout:
    the edit applies ONLY if ``decision == 'approve'`` AND the injected clock ``now()`` is at-or-before
    ``deadline``. A past-deadline response (or the default) is a TIMEOUT → REJECT. ``deadline`` is a
    logical clock value in the same units the injected ``now`` returns (no wallclock)."""

    decision: str = "timeout"      # only "approve" (in-window) applies an edit
    deadline: float = 0.0          # expired iff now() > deadline
    reason: str = ""


class OracleVerdict(BaseModel):
    """The fix-verification oracle's verdict on the PATCHED build. ``fired`` = the ORIGINAL exploit STILL
    fires (default True — an empty verdict is fail-closed 'still vulnerable'); ``cert`` is the signed
    'remediated' certificate, present ONLY when ``fired`` is False (the oracle went silent)."""

    fired: bool = True
    cert: str = ""
    reason: str = ""


# --- the parsed patch proposal (untrusted → path-validated) -------------------------------------------


class PatchFile(BaseModel):
    """One file touched by the proposed unified diff. ``path`` is an explicit, repo-relative, validated
    path (never a glob / flag / absolute / traversal / ``/dev/null``); ``diff_text`` is that file's raw
    unified-diff segment (the patch a live executor applies inside the sandbox)."""

    path: str
    status: str = "modify"         # "modify" | "add" | "delete"
    diff_text: str = ""


# --- the loop result ----------------------------------------------------------------------------------


class PatchResult(BaseModel):
    """The auto-patch outcome. ``remediated`` can be True ONLY with a signed ``evidence_ref`` AND an opened
    PR (type-level enforcement) — 'remediated' is never asserted without the fix-verification oracle going
    silent on the patched build and minting a signed certificate."""

    remediation_id: str = ""
    status: str
    opened_pr: bool = False
    remediated: bool = False
    evidence_ref: str = ""
    pr_ref: str = ""
    patched_paths: list[str] = Field(default_factory=list)
    verification: Optional[FixVerification] = None
    reason: str = ""
    steps: list[PipelineStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def _remediated_is_earned(self) -> "PatchResult":
        if self.remediated and not (self.evidence_ref or "").strip():
            raise ValueError("a 'remediated' auto-patch requires a signed evidence reference")
        if self.remediated and not self.opened_pr:
            raise ValueError("'remediated' cannot be true without an opened PR")
        return self


# --- untrusted unified-diff parsing (fail-closed, path-validated) -------------------------------------


def _strip_quotes(s: str) -> str:
    m = _QUOTE_RE.match(s)
    return m.group(1) if m else s


def _extract_path(raw: str) -> Optional[str]:
    """The repo-relative path of one side of a diff header line (the text after ``--- ``/``+++ ``).
    Returns the cleaned path, the ``_DEVNULL`` sentinel for ``/dev/null``, or ``None`` when empty/malformed.
    Strips a trailing ``\\t``-timestamp, git quoting, and a single ``a/``/``b/`` prefix. Total."""
    s = raw.rstrip("\r\n")
    if "\t" in s:
        s = s.split("\t", 1)[0]
    s = _strip_quotes(s.strip()).strip()
    if not s:
        return None
    if s == "/dev/null":
        return _DEVNULL
    if s.startswith(("a/", "b/")):
        s = s[2:]
    return s or None


def _resolve_header(old: Optional[str], new: Optional[str]) -> tuple[Optional[str], str]:
    """Resolve a (``---`` old, ``+++`` new) header pair to the concrete repo path to stage and the change
    status. A real new path wins (modify/add); a ``/dev/null`` new side means a deletion (the old path).
    Both ``/dev/null`` (or both empty) → ``(None, "")`` (nothing stageable)."""
    real_new = new is not None and new is not _DEVNULL
    real_old = old is not None and old is not _DEVNULL
    if real_new:
        return new, ("add" if old is _DEVNULL else "modify")
    if real_old:
        return old, "delete"
    return None, ""


def _segment_starts(lines: list[str], headers: list[int]) -> list[int]:
    """For each ``---`` header line index, the start of its raw segment: walk back over any preceding
    git-meta lines (``diff --git``/``index``/``rename``/…) so the per-file ``diff_text`` includes them."""
    starts: list[int] = []
    for hj in headers:
        s = hj
        b = hj - 1
        while b >= 0 and lines[b].startswith(_GIT_META):
            s = b
            b -= 1
        starts.append(s)
    return starts


def parse_unified_diff(text: Any) -> list[PatchFile]:
    """Parse an LLM-proposed unified diff into path-validated :class:`PatchFile` proposals, FAIL-CLOSED.

    A non-string, an empty/blank diff, or a diff larger than the byte bound → ``[]`` (no patch). Each file
    is keyed on a ``--- ``/``+++ `` header pair; its target path is stripped of the ``a/``/``b/`` prefix and
    admitted ONLY if it passes BOTH the remediation path guard (``is_safe_repo_path`` — no bulk/flag/
    absolute/traversal) AND the fsjob lexical confinement (``lexical_components`` — no ``..``/NUL/absolute).
    Duplicate paths collapse to the first occurrence. Never raises."""
    if not isinstance(text, str):
        return []
    body = text
    if not body.strip():
        return []
    if len(body.encode("utf-8", "ignore")) > _MAX_DIFF_BYTES:
        return []
    try:
        lines = body.splitlines(keepends=True)
        headers = [
            j for j in range(len(lines) - 1)
            if lines[j].startswith("--- ") and lines[j + 1].startswith("+++ ")
        ]
        starts = _segment_starts(lines, headers)
        out: list[PatchFile] = []
        seen: set[str] = set()
        for k, hj in enumerate(headers):
            path, status = _resolve_header(_extract_path(lines[hj][4:]),
                                           _extract_path(lines[hj + 1][4:]))
            if path is None or not _path_is_confined(path):
                continue
            if path in seen:
                continue
            seg_end = starts[k + 1] if k + 1 < len(starts) else len(lines)
            diff_text = "".join(lines[starts[k]:seg_end])
            seen.add(path)
            out.append(PatchFile(path=path, status=status, diff_text=diff_text))
            if len(out) >= _MAX_DIFF_FILES:
                break
        return out
    except Exception:   # noqa: BLE001 — a malformed diff yields no patch, never a crash (total)
        return []


def _path_is_confined(path: str) -> bool:
    """A patch target path is admitted ONLY if it clears the remediation path guard AND the fsjob lexical
    confinement kernel (belt-and-suspenders — two independent refusals). Total."""
    ok, _ = is_safe_repo_path(path)
    if not ok:
        return False
    try:
        lexical_components(path)   # raises PathEscapeError on absolute / NUL / '..'-escape
    except (PathEscapeError, ValueError):
        return False
    return True


# --- the injected-clock deadline approval (the redamon-flip) ------------------------------------------


def _as_number(value: Any) -> Optional[float]:
    """Coerce a clock/deadline value to ``float`` (bools rejected). Non-numeric → ``None``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _deadline_decision(approval: Optional[Callable[[PatchFile], Any]],
                       now: Optional[Callable[[], Any]], pf: PatchFile) -> tuple[str, str]:
    """Decide one file's edit approval under the injected clock, with the CRITICAL FLIP. Returns
    ``(decision, reason)`` where only ``"approve"`` applies the edit.

    Fail-closed at every branch: no approval mechanism → ``timeout``; no clock or an unusable clock value
    → ``timeout``; an approval carrying no numeric deadline → ``timeout``; ``now() > deadline`` (the window
    EXPIRED) → ``timeout`` REGARDLESS of the decision (this is the inversion of redamon's auto-accept); an
    approval callable that raises → ``reject``; any non-``approve`` in-window decision → not applied."""
    if approval is None:
        return "timeout", "no approval mechanism wired — auto-REJECT (fail-closed; VIGIL flips auto-accept)"
    if now is None:
        return "timeout", "no clock wired — cannot bound the approval window, auto-REJECT (fail-closed)"
    try:
        t_now = _as_number(now())
    except Exception as exc:   # noqa: BLE001 — an unavailable clock is a REJECT, never an accept
        return "timeout", f"clock unavailable — auto-REJECT (fail-closed): {exc}"
    if t_now is None:
        return "timeout", "clock returned no usable time — auto-REJECT (fail-closed)"
    try:
        resp = approval(pf)
    except Exception as exc:   # noqa: BLE001 — an approval-service error is a REJECT, never an accept
        return "reject", f"approval callable errored — auto-REJECT (fail-closed): {exc}"
    deadline = _as_number(getattr(resp, "deadline", None))
    if deadline is None:
        return "timeout", "approval carried no numeric deadline — auto-REJECT (fail-closed)"
    if t_now > deadline:
        return "timeout", (f"approval window EXPIRED (now {t_now} > deadline {deadline}) — auto-REJECT "
                           "(VIGIL flips redamon's auto-accept-on-timeout)")
    decision = getattr(resp, "decision", None)
    if decision == "approve":
        return "approve", str(getattr(resp, "reason", "") or "")
    coerced = decision if isinstance(decision, str) and decision else "timeout"
    return coerced, str(getattr(resp, "reason", "") or "edit not explicitly approved in-window")


# --- the fix-verification oracle (sign 'remediated' ONLY when it goes silent) -------------------------

# oracle(request, patched_build) -> a verdict. It re-fires the ORIGINAL exploit against the PATCHED build:
# a verdict whose ``fired`` is True (or a truthy exploit ref) means the exploit STILL fires; a verdict with
# ``fired`` False AND a non-empty ``cert`` means the oracle went SILENT and minted the signed certificate.
FixOracle = Callable[[Any, Any], Any]


def _oracle_fired(v: Any) -> Optional[bool]:
    """``True`` = the exploit still fires, ``False`` = the oracle is silent, ``None`` = no usable verdict.
    Fail-closed: an ambiguous/garbage verdict is ``None`` (→ 'unverified'), never a false 'silent'."""
    if v is None:
        return None
    fired = getattr(v, "fired", None)
    if isinstance(fired, bool):
        return fired
    if fired is not None:                 # present but not a bool → unusable
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, str):                # bare exploit-ref style: non-empty ⇒ still fires
        return bool(v.strip())
    return None                           # any other shape carries no confirmable silence


def _oracle_cert(v: Any) -> str:
    """The signed 'remediated' certificate from a silent verdict (an object attribute only — a bare string
    is an exploit ref, never a certificate). ``""`` when absent."""
    for attr in ("cert", "evidence_ref"):
        ref = getattr(v, attr, "")
        if isinstance(ref, str) and ref.strip():
            return ref.strip()
    return ""


def verify_patch(request: Any, patched_build: Any, *, oracle: Optional[FixOracle] = None) -> FixVerification:
    """Re-fire the ORIGINAL exploit oracle against the patched build and decide whether 'remediated' may be
    signed — the same fail-closed shape as ``remediation.verify_fix``, over the single-verdict oracle:

      * no oracle wired, or the oracle raises, or it returns no usable verdict → ``unverified``;
      * the exploit STILL fires → ``still-vulnerable`` (never remediated);
      * the oracle goes SILENT with a signed certificate → ``remediated``; silent with NO cert → ``unverified``.

    'remediated' is therefore minted ONLY after the oracle goes silent on the patched build AND signs."""
    if oracle is None:
        return FixVerification(status="unverified", remediated=False,
                               reason="no fix-verification oracle wired — cannot confirm the fix (fail-closed)")
    try:
        verdict = oracle(request, patched_build)
    except Exception as exc:   # noqa: BLE001 — an oracle error confirms nothing; we cannot claim a fix
        return FixVerification(status="unverified", remediated=False,
                               reason=f"fix-verification oracle errored — cannot confirm the fix (fail-closed): {exc}")
    fired = _oracle_fired(verdict)
    if fired is None:
        return FixVerification(status="unverified", remediated=False,
                               reason="fix-verification oracle returned no usable verdict (fail-closed)")
    if fired:
        return FixVerification(status="still-vulnerable", remediated=False,
                               reason="the ORIGINAL exploit STILL fires on the patched build — not remediated")
    cert = _oracle_cert(verdict)
    if not cert:
        return FixVerification(status="unverified", remediated=False,
                               reason="the exploit oracle went SILENT but minted no signed certificate (fail-closed)")
    return FixVerification(status="remediated", remediated=True, evidence_ref=cert,
                           reason="the ORIGINAL exploit oracle went SILENT on the patched build; remediation certificate minted")


# --- helpers -----------------------------------------------------------------------------------------


def _derive_remediation_id(remediation_id: Any, finding: Any) -> str:
    """A deterministic remediation id (no ``uuid``/wallclock): the caller's value if given, else a digest
    over the finding's signed provenance (ref + spine hash + evidence ref) — stable across identical runs."""
    if isinstance(remediation_id, str) and remediation_id.strip():
        return remediation_id.strip()
    ref = str(getattr(finding, "ref", "") or "")
    spine = str(getattr(finding, "spine_hash", "") or "")
    ev = str(getattr(finding, "evidence_ref", "") or "")
    digest = hashlib.sha256(f"{ref}\x00{spine}\x00{ev}".encode("utf-8")).hexdigest()
    return f"ap-{digest[:12]}"


def _call_propose(propose_patch: Optional[Callable[[Any], Any]], request: Any) -> str:
    """Invoke the injected coder LLM, TOTAL: no callable, an exception, or a ``None`` result → ``""`` (no
    patch). A non-string result is coerced to ``str`` before it is parsed (still fail-closed downstream)."""
    if propose_patch is None:
        return ""
    try:
        out = propose_patch(request)
    except Exception:   # noqa: BLE001 — a raising LLM proposes nothing, never crashes the loop
        return ""
    if out is None:
        return ""
    return out if isinstance(out, str) else str(out)


def _refuse(rec: _Recorder, remediation_id: str, status: str, reason: str, *,
            patched_paths: Optional[list[str]] = None) -> PatchResult:
    return PatchResult(remediation_id=str(remediation_id or ""), status=status, opened_pr=False,
                       remediated=False, patched_paths=patched_paths or [], reason=reason, steps=rec.steps)


# --- the loop ----------------------------------------------------------------------------------------


def autopatch(
    finding: Any,
    *,
    gate: Optional[Callable[..., Any]] = None,
    oracle: Optional[FixOracle] = None,
    propose_patch: Optional[Callable[[Any], Any]] = None,
    clone: Optional[Callable[..., Any]] = None,
    build: Optional[Callable[..., Any]] = None,
    open_pr: Optional[Callable[..., Any]] = None,
    quorum: Optional[Callable[[Any], Any]] = None,
    approval: Optional[Callable[[PatchFile], Any]] = None,
    now: Optional[Callable[[], Any]] = None,
    remediation_id: str = "",
    target_repo: str = "",
    target_branch: str = "",
    seq_start: int = 0,
) -> PatchResult:
    """Drive the AIxCC auto-patch loop for one finding, fail-closed at every stage.

    Order: SOVEREIGN confirmed-only check (a LEAD is refused) → PROPOSE (the injected LLM returns a minimal
    unified diff, parsed fail-closed to path-validated files) → CLONE/branch (A1) → per-file EDIT (A2, each
    gated + DEADLINE-approved via the injected ``approval``/``now``; an expired window auto-REJECTS) →
    sandbox BUILD (A3) → OPEN PR (A3 destructive + m-of-n ``quorum``, staging ONLY the explicit approved
    paths, never ``git add -A``) → VERIFY (the fix-verification ``oracle`` re-fires the original exploit; a
    signed 'remediated' certificate is minted ONLY when the oracle goes silent on the patched build).

    All executors — ``gate``/``oracle``/``propose_patch``/``clone``/``build``/``open_pr``/``quorum``/
    ``approval``/``now`` — are injected callables, so the whole loop runs without a live kernel, git, LLM,
    or sandbox. Total on malformed input: a lead, a non-finding, a garbage diff, or a raising executor
    degrades to a refusal, never a crash. Deterministic: no wallclock / RNG anywhere on the decision path."""
    rec = _Recorder(seq_start)
    rid = _derive_remediation_id(remediation_id, finding)

    # (0) THE SOVEREIGN INVARIANT — auto-patch runs ONLY from an oracle-confirmed FACT. A LEAD is refused.
    allowed, why = may_remediate(finding)
    if not allowed:
        rec.add("sovereign-check", TIER_CLONE, "deny", why)
        return _refuse(rec, rid, "refused-not-confirmed",
                       f"auto-patch REFUSED: {why} — a LEAD can never be patched")

    request = spawn_remediation(finding, remediation_id=rid, target_repo=target_repo,
                                target_branch=target_branch)
    if request is None:   # defense in depth: spawn re-checks the confirmed-only rule
        rec.add("sovereign-check", TIER_CLONE, "deny", "spawn boundary declined (fail-closed)")
        return _refuse(rec, rid, "refused-not-confirmed",
                       "auto-patch REFUSED: the spawn boundary declined a non-confirmed finding")
    repo = request.target_repo or request.finding.target or request.remediation_id

    # (1) PROPOSE — the injected coder LLM returns a minimal unified-diff PROPOSAL (untrusted).
    proposed = parse_unified_diff(_call_propose(propose_patch, request))
    rec.add("propose", TIER_EDIT, "ok" if proposed else "deny",
            f"{len(proposed)} path-safe file(s) in the proposed patch" if proposed
            else "no valid, path-safe unified diff proposed (fail-closed)",
            {"files": [pf.path for pf in proposed]})
    if not proposed:
        return _refuse(rec, rid, "no-patch-proposed",
                       "the LLM proposed no valid, path-safe unified diff — nothing to patch (fail-closed)")

    # (2) CLONE + branch — A1.
    allowed, outcome, gwhy = _gate_allows(gate, "git_clone", repo, False)
    rec.add("clone", TIER_CLONE, outcome, gwhy, {"repo": repo, "branch": request.fix_branch})
    if not allowed:
        return _refuse(rec, rid, "clone-denied", f"clone/branch gate refused: {gwhy}")
    ok, _clone_res, ereason = _exec_ok(clone, request)
    rec.add("clone-exec", TIER_CLONE, "ok" if ok else "fail", ereason,
            {"repo": repo, "branch": request.fix_branch})
    if not ok:
        return _refuse(rec, rid, "clone-failed", f"clone executor failed: {ereason}")

    # (3) EDIT/APPROVE — A2, each proposed file gated + DEADLINE-approved (an expired window ⇒ REJECT).
    approved: list[PatchFile] = []
    for pf in proposed:
        if not _path_is_confined(pf.path):   # re-validate the executor-independent path (defense in depth)
            rec.add("edit", TIER_EDIT, "rejected", "unsafe/unconfined path (never patched)", {"path": pf.path})
            continue
        allowed, outcome, gwhy = _gate_allows(gate, "code_edit", repo, False)
        if not allowed:
            rec.add("edit", TIER_EDIT, outcome, f"edit gate refused: {gwhy}", {"path": pf.path})
            continue
        decision, areason = _deadline_decision(approval, now, pf)
        if decision != "approve":
            rec.add("edit", TIER_EDIT, "rejected",
                    f"patch NOT applied (decision={decision}): {areason}", {"path": pf.path})
            continue
        approved.append(pf)
        rec.add("edit", TIER_EDIT, "ok", "patch approved in-window (explicit path)", {"path": pf.path})

    approved = _dedup_by_path(approved)
    approved_paths = [pf.path for pf in approved]
    if not approved:
        reason = "no patch file approved in-window — refusing to build or open an empty PR (fail-closed)"
        rec.add("edits-empty", TIER_EDIT, "deny", reason)
        return _refuse(rec, rid, "no-edits-approved", reason)
    if any(p in _BULK_TOKENS or p.startswith("-") for p in approved_paths):
        reason = "refusing a wildcard/flag staging path — VIGIL never runs 'git add -A' (fail-closed)"
        rec.add("edits-wildcard", TIER_EDIT, "deny", reason)
        return _refuse(rec, rid, "unsafe-staging", reason, patched_paths=approved_paths)

    # (4) BUILD — A3, inside the disposable, egress-gated fsjob sandbox.
    allowed, outcome, gwhy = _gate_allows(gate, "sandbox_build", repo, False)
    rec.add("build", TIER_BUILD, outcome, gwhy, {"paths": approved_paths})
    if not allowed:
        return _refuse(rec, rid, "build-denied", f"build gate refused: {gwhy}", patched_paths=approved_paths)
    ok, bres, ereason = _exec_ok(build, request, approved)
    rec.add("build-exec", TIER_BUILD, "ok" if ok else "fail", ereason, {"paths": approved_paths})
    if not ok:
        return _refuse(rec, rid, "build-failed", f"sandbox build failed: {ereason}", patched_paths=approved_paths)
    patched_build = getattr(bres, "build_ref", "") or bres

    # (5) OPEN PR — A3 DESTRUCTIVE (the gate's threshold-destruction leg) AND an explicit m-of-n quorum.
    allowed, outcome, gwhy = _gate_allows(gate, "github_pr", repo, True)
    rec.add("pr-gate", TIER_PR, outcome, gwhy, {"paths": approved_paths})
    if not allowed:
        return _refuse(rec, rid, "pr-denied", f"PR gate refused (destructive/threshold): {gwhy}",
                       patched_paths=approved_paths)
    qok, qreason = _quorum_ok(quorum, request)
    rec.add("pr-quorum", TIER_PR, "allow" if qok else "deny", qreason)
    if not qok:
        return _refuse(rec, rid, "pr-quorum-denied",
                       f"PR blocked — m-of-n threshold not met: {qreason}", patched_paths=approved_paths)
    ok, prres, ereason = _exec_ok(open_pr, request, approved)   # stages ONLY the explicit approved files
    rec.add("pr-exec", TIER_PR, "ok" if ok else "fail", ereason, {"paths": approved_paths})
    if not ok:
        return _refuse(rec, rid, "pr-failed", f"opening the PR failed: {ereason}", patched_paths=approved_paths)
    pr_ref = str(getattr(prres, "pr_ref", "") or "")

    # (6) VERIFY — 'remediated' is minted ONLY after the fix-verification oracle goes SILENT.
    verification = verify_patch(request, patched_build, oracle=oracle)
    rec.add("verify", TIER_PR, "ok" if verification.remediated else "fail", verification.reason,
            {"verification": verification.status})

    status = "remediated" if verification.remediated else f"opened-pr-{verification.status}"
    return PatchResult(
        remediation_id=rid, status=status, opened_pr=True, remediated=verification.remediated,
        evidence_ref=verification.evidence_ref, pr_ref=pr_ref, patched_paths=approved_paths,
        verification=verification, reason=verification.reason, steps=rec.steps,
    )


def _dedup_by_path(files: list[PatchFile]) -> list[PatchFile]:
    """Collapse files sharing a path (first occurrence wins) and sort by path — explicit, deduped,
    deterministic staging (mirrors ``remediation.run_codefix``'s ``sorted(set(edited_paths))``)."""
    best: dict[str, PatchFile] = {}
    for pf in files:
        best.setdefault(pf.path, pf)
    return [best[p] for p in sorted(best)]
