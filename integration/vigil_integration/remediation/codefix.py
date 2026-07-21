"""
remediation.codefix — the GATED, DESTRUCTIVE codefix pipeline of CypherFix, re-plumbed sovereign
(VIGIL-FUSION F10).

redamon's CodeFixOrchestrator consumes one remediation, clones a repo, runs a ReAct loop where Claude
drives 11 tree-sitter code tools (read-only ones fan out in parallel, mutating edit/write/bash serialize
behind a per-block approval gate that **AUTO-ACCEPTS on a 300s timeout**), builds in a disposable
sandbox container, commits ONLY the LLM-edited files (never ``git add -A``), and opens a GitHub PR.

VIGIL keeps the SHAPE and the good hygiene, but subordinates the whole fixer to the sovereign core and
inverts every fail-open default. This module is the PURE, INJECTED pipeline (the live git/sandbox/Claude
are a later slice — every side effect is a callable passed in):

  * **Confirmed-only.** ``run_codefix`` refuses fail-closed unless the request was spawned from an
    oracle-confirmed FACT (``TriageFinding.may_spawn_remediation``). A LEAD never reaches a codefix.
  * **Tiered, gated stages.** Each stage routes through the injected conjunctive ``gate(tool_name,
    target, destructive)``: clone/branch = A1, edit/write = A2, sandbox build = A3, opening the PR = A3
    **destructive** (the gate's threshold-destruction leg) AND an explicit m-of-n ``quorum``. No gate
    wired, a gate error, a ``queue``, or a ``deny`` → the stage does not proceed.
  * **THE CRITICAL FLIP.** The per-block approval TIMEOUT AUTO-**REJECTS** (fail-closed). Only an
    explicit ``approve`` applies an edit; a timeout / reject / modify / missing mechanism / a raised
    callable all REJECT the block. This inverts redamon's auto-accept.
  * **Never ``git add -A``.** Only explicit, path-validated files are staged; a wildcard/flag path is
    refused, and an empty edit set never opens a PR.
  * **Verify before signing 'remediated'.** ``verify_fix`` re-fires the ORIGINAL exploit oracle against
    the patched build; 'remediated' is signed ONLY when that oracle goes SILENT (the exploit no longer
    fires) AND a signer mints a signed cert. An oracle that still fires → 'still-vulnerable', never
    remediated; an oracle error / no signer → 'unverified' (fail-closed).
  * **Deterministic + secret-free.** Step sequence numbers come from an injected/internal counter (no
    wallclock, no RNG); every recorded payload is scrubbed through the F3 ``redact_tool_args`` so no
    credential reaches the audit trail. Total on malformed input.

Import-clean: pydantic + stdlib + the F1 safety seam (``wrap_untrusted`` / ``parse_proposal``) + the F3
``redact_tool_args`` + F10 triage only (no ``framework.*``/``strix.*``/git/network).
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from pydantic import BaseModel, Field, model_validator

from ..safety.llm_intake import parse_proposal
from ..safety.prompt_safety import wrap_untrusted
from ..tools.governance import redact_tool_args
from .triage import TriageFinding, may_remediate

# Stage → WARDEN tier (the phase ladder mapped onto tiers, per §5 C8 / ANALYSIS C8).
TIER_CLONE = "A1"    # clone / branch: low blast radius
TIER_EDIT = "A2"     # edit / write: mutating the worktree
TIER_BUILD = "A3"    # sandbox build: highest tier, egress-gated
TIER_PR = "A3"       # opening the PR: A3 + destructive threshold (m-of-n)

# Path tokens that would turn an explicit-path add into a bulk/flag stage — never allowed.
_BULK_TOKENS = frozenset({"-A", "--all", "-a", ".", "*", "", "./", "*.*"})


# --- injected-executor result shapes (duck-typed; the pipeline only reads attributes) ----------


class CloneResult(BaseModel):
    ok: bool = False
    workdir: str = ""
    branch: str = ""
    reason: str = ""


class WriteResult(BaseModel):
    ok: bool = False
    path: str = ""
    reason: str = ""


class BuildResult(BaseModel):
    ok: bool = False
    build_ref: str = ""
    reason: str = ""


class PrResult(BaseModel):
    ok: bool = False
    pr_ref: str = ""
    reason: str = ""


class ApprovalOutcome(BaseModel):
    """The result of a per-block approval. The DEFAULT is ``timeout`` → REJECT: an unanswered / missing
    approval is fail-closed, the inverse of redamon's auto-accept."""

    decision: str = "timeout"   # "approve" is the ONLY value that applies an edit
    reason: str = ""


class QuorumOutcome(BaseModel):
    """The result of the m-of-n threshold check for opening a PR. Defaults to DENY (fail-closed)."""

    approved: bool = False
    reason: str = ""
    signer_ids: list[str] = Field(default_factory=list)


# --- the LLM's proposed edits (untrusted) ------------------------------------------------------


class EditBlock(BaseModel):
    """One proposed source edit — a PROPOSAL from the fixer LLM (untrusted). ``path`` is an explicit,
    repo-relative file path; it is validated (never a glob/flag/absolute/traversal) before it is staged,
    so a malicious proposal cannot smuggle a ``-A``/``..`` into the commit."""

    path: str
    intent: str = ""
    content: str = ""
    status: str = "modify"   # "modify" | "add"


def is_safe_repo_path(path: Any) -> tuple[bool, str]:
    """``(safe, reason)``: a repo-relative path that can be staged explicitly. Refuses a non-string,
    empty, bulk/flag token (``-A``/``.``/``*``/…), an absolute path, a Windows drive path, a leading-dash
    segment (git would read it as a flag), and any ``..`` traversal. Total — never raises."""
    if not isinstance(path, str):
        return False, "non-string path"
    p = path.strip()
    if not p or p in _BULK_TOKENS:
        return False, "empty or bulk/wildcard staging token"
    if p.startswith("-"):
        return False, "path looks like a command flag"
    if p.startswith(("/", "~", "\\")) or (len(p) >= 2 and p[1] == ":"):
        return False, "absolute path"
    segments = p.replace("\\", "/").split("/")
    if any(seg == ".." for seg in segments):
        return False, "path traversal ('..')"
    if any(seg in _BULK_TOKENS or seg.startswith("-") for seg in segments if seg):
        return False, "path segment is a flag/wildcard"
    return True, ""


def parse_edit_blocks(text: str) -> list[EditBlock]:
    """Parse the fixer LLM's raw response into a list of ``EditBlock`` proposals, FAIL-CLOSED. Accepts
    ``{"edits": [...]}`` or a bare JSON array; any malformation → ``[]`` (no edits → no PR). Non-dict
    elements are skipped. Never raises."""

    def _validate(obj: Any) -> list[EditBlock]:
        items = obj.get("edits") if isinstance(obj, dict) else obj
        if not isinstance(items, list):
            raise ValueError("no edit list in proposal")
        return [EditBlock.model_validate(e) for e in items if isinstance(e, dict)]

    return parse_proposal(text, _validate, default=[])


def render_untrusted_finding(finding: TriageFinding) -> str:
    """Frame a confirmed finding's attacker-influenced text (title / evidence) for the fixer LLM prompt
    as inert, marker-bounded DATA (F1 ``wrap_untrusted``) — the prompt-injection defense redamon's
    ``build_codefix_system_prompt`` applies to the finding/evidence it feeds the coder agent."""
    body = (f"ref: {finding.ref}\nbug_class: {finding.bug_class}\nseverity: {finding.severity}\n"
            f"title: {finding.title}\ntarget: {finding.target}")
    return wrap_untrusted(body, label="FINDING")


# --- the codefix request + result --------------------------------------------------------------


class CodeFixRequest(BaseModel):
    """One remediation handed to the codefix pipeline. It carries the CONFIRMED ``finding`` so the
    pipeline can RE-CHECK the sovereign rule at entry (defense in depth, even if the spawn boundary was
    bypassed). Secret-free by construction: no token/credential field — the two-container isolation keeps
    creds inside the injected executors, never in this record."""

    remediation_id: str
    finding: TriageFinding
    target_repo: str = ""
    target_branch: str = "main"
    branch_prefix: str = "vigil-fix/"
    title: str = ""

    @property
    def fix_branch(self) -> str:
        return f"{self.branch_prefix}{self.remediation_id}"


class FixVerification(BaseModel):
    """The verdict of re-firing the original exploit oracle against the patched build. ``remediated`` is
    True ONLY when ``status == 'remediated'`` with a signed ``evidence_ref`` (enforced at the type level,
    closing the deserialization path)."""

    status: str                 # "remediated" | "still-vulnerable" | "unverified"
    remediated: bool = False
    evidence_ref: str = ""
    reason: str = ""

    @model_validator(mode="after")
    def _remediated_needs_evidence(self) -> "FixVerification":
        if self.remediated and (self.status != "remediated" or not (self.evidence_ref or "").strip()):
            raise ValueError("a 'remediated' verification requires status=='remediated' and a signed ref")
        return self


class PipelineStep(BaseModel):
    """One append-only audit row of the pipeline (inert; the spine write is deferred). ``seq`` is a
    deterministic counter (no wallclock); ``payload`` is scrubbed of secrets."""

    seq: int
    stage: str
    tier: str
    outcome: str                # allow | queue | deny | ok | fail | rejected | skip
    reason: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


class CodeFixResult(BaseModel):
    """The pipeline outcome. ``remediated`` can be True ONLY with a signed ``evidence_ref`` and an opened
    PR (type-level enforcement) — 'remediated' is never asserted without the fix-verification oracle
    going silent and signing."""

    remediation_id: str = ""
    status: str
    opened_pr: bool = False
    remediated: bool = False
    evidence_ref: str = ""
    pr_ref: str = ""
    edited_paths: list[str] = Field(default_factory=list)
    verification: Optional[FixVerification] = None
    reason: str = ""
    steps: list[PipelineStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def _remediated_is_earned(self) -> "CodeFixResult":
        if self.remediated and not (self.evidence_ref or "").strip():
            raise ValueError("a 'remediated' result requires a signed evidence reference")
        if self.remediated and not self.opened_pr:
            raise ValueError("'remediated' cannot be true without an opened PR")
        return self


# --- the spawn boundary (constructs a request only from a confirmed fact) ----------------------


def spawn_remediation(finding: Any, *, remediation_id: str, target_repo: str = "",
                      target_branch: str = "", branch_prefix: str = "vigil-fix/") -> Optional[CodeFixRequest]:
    """Construct a ``CodeFixRequest`` from a triage finding — but ONLY if it is an oracle-confirmed FACT.
    A LEAD (or any non-spawnable finding) returns ``None`` fail-closed: a lead can never trigger a
    codefix. Total — never raises."""
    ok, _ = may_remediate(finding)
    if not ok:
        return None
    return CodeFixRequest(
        remediation_id=str(remediation_id),
        finding=finding,
        target_repo=target_repo or finding.target_repo,
        target_branch=target_branch or finding.target_branch or "main",
        branch_prefix=branch_prefix,
        title=finding.title or finding.ref,
    )


# --- fail-closed helpers over the injected callables -------------------------------------------


def _gate_allows(gate: Optional[Callable[..., Any]], tool_name: str, target: str,
                 destructive: bool) -> tuple[bool, str, str]:
    """Normalize the injected conjunctive gate to ``(allowed, outcome, reason)``, fail-closed. No gate,
    a gate error, or an ``allowed``/``outcome`` mismatch → DENY; ``allowed`` is derived from BOTH
    ``.allowed is True`` AND ``.outcome == 'allow'`` so a malformed verdict can never present as allow."""
    if gate is None:
        return False, "deny", "no conjunctive gate wired — stage cannot proceed (fail-closed)"
    try:
        v = gate(tool_name, target, destructive)
    except Exception as exc:   # noqa: BLE001 — any gate error is a DENY, never caught-and-continued
        return False, "deny", f"gate error (fail-closed): {exc}"
    raw = getattr(v, "outcome", "deny")
    allowed = getattr(v, "allowed", False) is True and raw == "allow"
    outcome = "allow" if allowed else ("queue" if raw == "queue" else "deny")
    return allowed, outcome, str(getattr(v, "reason", "") or "")


def _exec_ok(fn: Optional[Callable[..., Any]], *args: Any) -> tuple[bool, Any, str]:
    """Run an injected executor, fail-closed. No executor, an exception, or a result whose ``.ok`` is not
    strictly True → (False, result, reason)."""
    if fn is None:
        return False, None, "no executor wired (fail-closed)"
    try:
        res = fn(*args)
    except Exception as exc:   # noqa: BLE001 — a raising executor is a failed stage, never a crash
        return False, None, f"executor error (fail-closed): {exc}"
    if getattr(res, "ok", False) is not True:
        return False, res, str(getattr(res, "reason", "") or "executor did not report ok")
    return True, res, ""


def _approval(approve_block: Optional[Callable[[EditBlock], Any]], block: EditBlock) -> tuple[str, str]:
    """The per-block approval, with the CRITICAL FLIP: only an explicit ``approve`` applies. No mechanism
    → ``timeout`` (reject); a raising callable → ``reject``; any non-``approve`` decision (timeout /
    reject / modify / None / garbage) → not applied. Returns ``(decision, reason)``."""
    if approve_block is None:
        return "timeout", "no approval mechanism wired — auto-REJECT (fail-closed; VIGIL flips auto-accept)"
    try:
        out = approve_block(block)
    except Exception as exc:   # noqa: BLE001 — an approval error is a REJECT, never an accept
        return "reject", f"approval callable errored — auto-REJECT (fail-closed): {exc}"
    decision = getattr(out, "decision", None)
    if decision == "approve":
        return "approve", str(getattr(out, "reason", "") or "")
    coerced = decision if isinstance(decision, str) and decision else "timeout"
    return coerced, str(getattr(out, "reason", "") or "edit not explicitly approved")


def _quorum_ok(quorum: Optional[Callable[[CodeFixRequest], Any]], request: CodeFixRequest) -> tuple[bool, str]:
    """The m-of-n threshold check for opening a PR, fail-closed. No quorum, an error, or ``approved`` not
    strictly True → DENY (a PR opens ONLY after the m-of-n threshold)."""
    if quorum is None:
        return False, "no m-of-n quorum wired — PR refused (fail-closed)"
    try:
        out = quorum(request)
    except Exception as exc:   # noqa: BLE001 — a quorum error is a DENY
        return False, f"quorum callable errored — PR refused (fail-closed): {exc}"
    if getattr(out, "approved", False) is True:
        return True, str(getattr(out, "reason", "") or "m-of-n threshold met")
    return False, str(getattr(out, "reason", "") or "m-of-n threshold not met")


# --- the fix-verification step (sign 'remediated' only when the oracle goes silent) ------------

# exploit_oracle(request, patched_build) -> a signed evidence ref if the ORIGINAL exploit STILL fires on
# the patched build, else None/"" when the oracle goes SILENT (the vuln is gone). sign_remediated(request,
# patched_build) -> the signed 'remediated' cert ref, called ONLY after the oracle is silent.
ExploitOracle = Callable[[CodeFixRequest, Any], Optional[str]]
RemediationSigner = Callable[[CodeFixRequest, Any], Optional[str]]


def verify_fix(request: CodeFixRequest, patched_build: Any, *,
               exploit_oracle: Optional[ExploitOracle] = None,
               sign_remediated: Optional[RemediationSigner] = None) -> FixVerification:
    """Re-fire the ORIGINAL exploit oracle against the patched build and decide whether 'remediated' may
    be signed. Fail-closed at every branch:

      * no oracle wired, or the oracle raises → ``unverified`` (we cannot claim a fix);
      * the oracle STILL fires (returns a truthy ref) → ``still-vulnerable`` (the fix did not work);
      * the oracle goes SILENT (returns falsy) → THEN, and only then, ``sign_remediated`` mints the
        signed cert; a missing/erroring/empty signer → ``unverified``; a real signed ref → ``remediated``.

    'remediated' is therefore signed ONLY after the exploit oracle goes silent on the patched build."""
    if exploit_oracle is None:
        return FixVerification(status="unverified", remediated=False,
                               reason="no exploit oracle wired — cannot confirm the fix (fail-closed)")
    try:
        still = exploit_oracle(request, patched_build)
    except Exception as exc:   # noqa: BLE001 — an oracle error confirms nothing; we cannot claim a fix
        return FixVerification(status="unverified", remediated=False,
                               reason=f"exploit oracle errored — cannot confirm the fix (fail-closed): {exc}")
    if still is not None and str(still).strip():
        return FixVerification(status="still-vulnerable", remediated=False,
                               reason="the original exploit oracle STILL fires on the patched build")
    # the oracle went SILENT — the exploit no longer fires. Only now may 'remediated' be signed.
    if sign_remediated is None:
        return FixVerification(status="unverified", remediated=False,
                               reason="oracle silent but no remediation signer wired (fail-closed)")
    try:
        cert = sign_remediated(request, patched_build)
    except Exception as exc:   # noqa: BLE001
        return FixVerification(status="unverified", remediated=False,
                               reason=f"remediation signer errored — cannot sign 'remediated' (fail-closed): {exc}")
    if not (cert is not None and str(cert).strip()):
        return FixVerification(status="unverified", remediated=False,
                               reason="oracle silent but signer produced no signed cert (fail-closed)")
    return FixVerification(status="remediated", remediated=True, evidence_ref=str(cert),
                           reason="the original exploit oracle went SILENT on the patched build; remediation signed")


# --- the pipeline ------------------------------------------------------------------------------


class _Recorder:
    """A deterministic, secret-scrubbing append-only step log. ``seq`` is an internal counter seeded by
    an injected ``seq_start`` (no wallclock / RNG); every payload is scrubbed via ``redact_tool_args``."""

    def __init__(self, seq_start: int = 0) -> None:
        self._seq = int(seq_start) if isinstance(seq_start, int) and not isinstance(seq_start, bool) else 0
        self.steps: list[PipelineStep] = []

    def add(self, stage: str, tier: str, outcome: str, reason: str = "",
            payload: Optional[dict[str, Any]] = None) -> None:
        self.steps.append(PipelineStep(
            seq=self._seq, stage=stage, tier=tier, outcome=outcome, reason=reason,
            payload=redact_tool_args(payload or {}),
        ))
        self._seq += 1


def _result(rec: _Recorder, request: Any, status: str, reason: str, *, opened_pr: bool = False,
            edited_paths: Optional[list[str]] = None, pr_ref: str = "",
            verification: Optional[FixVerification] = None) -> CodeFixResult:
    return CodeFixResult(
        remediation_id=str(getattr(request, "remediation_id", "") or ""),
        status=status, opened_pr=opened_pr, remediated=False, pr_ref=pr_ref,
        edited_paths=edited_paths or [], verification=verification, reason=reason, steps=rec.steps,
    )


def run_codefix(
    request: Any,
    edits: Any,
    *,
    gate: Optional[Callable[..., Any]] = None,
    clone: Optional[Callable[..., Any]] = None,
    write_file: Optional[Callable[..., Any]] = None,
    build: Optional[Callable[..., Any]] = None,
    open_pr: Optional[Callable[..., Any]] = None,
    quorum: Optional[Callable[[CodeFixRequest], Any]] = None,
    approve_block: Optional[Callable[[EditBlock], Any]] = None,
    exploit_oracle: Optional[ExploitOracle] = None,
    sign_remediated: Optional[RemediationSigner] = None,
    seq_start: int = 0,
) -> CodeFixResult:
    """Drive the gated, destructive codefix pipeline for one remediation, fail-closed at every stage.

    Order: sovereign confirmed-only check → CLONE/branch (A1) → per-file EDIT (A2, each gated + explicit
    approval, timeout=REJECT) → sandbox BUILD (A3) → OPEN PR (A3 destructive + m-of-n quorum, staging ONLY
    the explicit edited paths, never ``git add -A``) → VERIFY (sign 'remediated' only when the original
    exploit oracle goes silent on the patched build). The gate/oracle/executors/quorum/approval are all
    injected, so the pipeline is fully testable without a live kernel, git, or sandbox. Total on
    malformed input — a bad request or a garbage edit set degrades to a refusal, never a crash."""
    rec = _Recorder(seq_start)

    # (0) THE SOVEREIGN INVARIANT — a remediation runs ONLY from an oracle-confirmed FACT.
    finding = getattr(request, "finding", None)
    if not isinstance(request, CodeFixRequest) or not isinstance(finding, TriageFinding) \
            or not finding.may_spawn_remediation:
        reason = "remediation REFUSED: not spawned from an oracle-confirmed FACT (a LEAD can never fix)"
        rec.add("sovereign-check", TIER_CLONE, "deny", reason)
        return _result(rec, request, "refused-not-confirmed", reason)

    repo = request.target_repo or request.finding.target or request.remediation_id

    # (1) CLONE + branch — A1.
    allowed, outcome, why = _gate_allows(gate, "git_clone", repo, False)
    rec.add("clone", TIER_CLONE, outcome, why, {"repo": repo, "branch": request.fix_branch})
    if not allowed:
        return _result(rec, request, "clone-denied", f"clone/branch gate refused: {why}")
    ok, clone_res, ereason = _exec_ok(clone, request)
    rec.add("clone-exec", TIER_CLONE, "ok" if ok else "fail", ereason,
            {"repo": repo, "branch": request.fix_branch})
    if not ok:
        return _result(rec, request, "clone-failed", f"clone executor failed: {ereason}")

    # (2) EDIT/WRITE — A2, each file gated + explicitly approved (TIMEOUT ⇒ REJECT). Only successfully
    #     written, path-validated files are staged; nothing is ever added with a wildcard/flag.
    edit_list = edits if isinstance(edits, list) else []
    edited_paths: list[str] = []
    for block in edit_list:
        if not isinstance(block, EditBlock):
            rec.add("edit", TIER_EDIT, "skip", "malformed edit block (fail-closed)")
            continue
        safe, sreason = is_safe_repo_path(block.path)
        if not safe:
            rec.add("edit", TIER_EDIT, "rejected", f"unsafe path (never staged): {sreason}",
                    {"path": block.path})
            continue
        allowed, outcome, why = _gate_allows(gate, "code_edit", repo, False)
        if not allowed:
            rec.add("edit", TIER_EDIT, outcome, f"edit gate refused: {why}", {"path": block.path})
            continue
        decision, areason = _approval(approve_block, block)
        if decision != "approve":
            rec.add("edit", TIER_EDIT, "rejected",
                    f"edit NOT applied (decision={decision}): {areason}", {"path": block.path})
            continue
        ok, wres, ereason = _exec_ok(write_file, block)
        if not ok:
            rec.add("edit", TIER_EDIT, "fail", f"write failed: {ereason}", {"path": block.path})
            continue
        written = str(getattr(wres, "path", "") or block.path)
        safe2, sreason2 = is_safe_repo_path(written)   # re-validate the executor-reported path
        if not safe2:
            rec.add("edit", TIER_EDIT, "rejected",
                    f"executor returned an unsafe path (not staged): {sreason2}", {"path": written})
            continue
        if written not in edited_paths:
            edited_paths.append(written)
        rec.add("edit", TIER_EDIT, "ok", "edit applied (explicit path)", {"path": written})

    edited_paths = sorted(set(edited_paths))   # explicit, deduped, deterministic
    if not edited_paths:
        reason = "no edits approved/applied — refusing to build or open an empty PR (fail-closed)"
        rec.add("edits-empty", TIER_EDIT, "deny", reason)
        return _result(rec, request, "no-edits-approved", reason)
    # belt-and-suspenders: never let a bulk/flag token reach the stage list.
    if any(p in _BULK_TOKENS or p.startswith("-") for p in edited_paths):
        reason = "refusing a wildcard/flag staging path — VIGIL never runs 'git add -A' (fail-closed)"
        rec.add("edits-wildcard", TIER_EDIT, "deny", reason)
        return _result(rec, request, "unsafe-staging", reason, edited_paths=edited_paths)

    # (3) BUILD — A3, inside the disposable, egress-gated sandbox.
    allowed, outcome, why = _gate_allows(gate, "sandbox_build", repo, False)
    rec.add("build", TIER_BUILD, outcome, why, {"paths": edited_paths})
    if not allowed:
        return _result(rec, request, "build-denied", f"build gate refused: {why}",
                       edited_paths=edited_paths)
    ok, bres, ereason = _exec_ok(build, request, edited_paths)
    rec.add("build-exec", TIER_BUILD, "ok" if ok else "fail", ereason, {"paths": edited_paths})
    if not ok:
        return _result(rec, request, "build-failed", f"sandbox build failed: {ereason}",
                       edited_paths=edited_paths)
    patched_build = getattr(bres, "build_ref", "") or bres

    # (4) OPEN PR — A3 DESTRUCTIVE (the gate's threshold-destruction leg) AND an explicit m-of-n quorum.
    allowed, outcome, why = _gate_allows(gate, "github_pr", repo, True)
    rec.add("pr-gate", TIER_PR, outcome, why, {"paths": edited_paths})
    if not allowed:
        return _result(rec, request, "pr-denied", f"PR gate refused (destructive/threshold): {why}",
                       edited_paths=edited_paths)
    qok, qreason = _quorum_ok(quorum, request)
    rec.add("pr-quorum", TIER_PR, "allow" if qok else "deny", qreason)
    if not qok:
        return _result(rec, request, "pr-quorum-denied",
                       f"PR blocked — m-of-n threshold not met: {qreason}", edited_paths=edited_paths)
    ok, prres, ereason = _exec_ok(open_pr, request, edited_paths)   # stages ONLY the explicit paths
    rec.add("pr-exec", TIER_PR, "ok" if ok else "fail", ereason, {"paths": edited_paths})
    if not ok:
        return _result(rec, request, "pr-failed", f"opening the PR failed: {ereason}",
                       edited_paths=edited_paths)
    pr_ref = str(getattr(prres, "pr_ref", "") or "")

    # (5) VERIFY — 'remediated' is signed ONLY after the original exploit oracle goes silent.
    verification = verify_fix(request, patched_build, exploit_oracle=exploit_oracle,
                              sign_remediated=sign_remediated)
    rec.add("verify", TIER_PR, "ok" if verification.remediated else "fail", verification.reason,
            {"verification": verification.status})

    status = "remediated" if verification.remediated else f"opened-pr-{verification.status}"
    return CodeFixResult(
        remediation_id=request.remediation_id, status=status, opened_pr=True,
        remediated=verification.remediated, evidence_ref=verification.evidence_ref, pr_ref=pr_ref,
        edited_paths=edited_paths, verification=verification, reason=verification.reason, steps=rec.steps,
    )
