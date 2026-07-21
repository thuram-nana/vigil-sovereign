"""
vigil_integration.remediation — CypherFix-style gated autonomous remediation (VIGIL-FUSION F10).

Ports redamon's two chained CypherFix agents (triage + codefix) into the sovereign core so the LLM only
proposes and the oracle + gate dispose:

  * ``triage`` — the deterministic half. 9 fixed queries over the F4 graph read-model gather ground truth
    at zero LLM cost, then dedup + severity-prioritize into a ``RemediationDraft``. A ``TriageFinding``
    may spawn a remediation ONLY if it is an oracle-confirmed FACT (a graph CONFIRMED node with a signed
    evidence ref) — a LEAD can never trigger a codefix (``may_remediate`` is the boundary).
  * ``codefix`` — the gated, DESTRUCTIVE pipeline. Stages map to WARDEN tiers (clone/branch A1, edit A2,
    build A3, PR A3+m-of-n), the per-block approval TIMEOUT auto-REJECTS (fail-closed, the inverse of
    redamon), only explicit path-validated files are staged (never ``git add -A``), and 'remediated' is
    signed ONLY after the original exploit oracle goes silent on the patched build. The gate, oracle,
    executors, quorum, and approval are injected callables — the pipeline is testable without a live
    kernel/git/sandbox.

Import-clean: pydantic + stdlib + the F1/F3/F4 seams only (no ``framework.*``/``strix.*``/network).
"""

from __future__ import annotations

from .codefix import (
    TIER_BUILD,
    TIER_CLONE,
    TIER_EDIT,
    TIER_PR,
    ApprovalOutcome,
    BuildResult,
    CloneResult,
    CodeFixRequest,
    CodeFixResult,
    EditBlock,
    FixVerification,
    PipelineStep,
    PrResult,
    QuorumOutcome,
    WriteResult,
    is_safe_repo_path,
    parse_edit_blocks,
    render_untrusted_finding,
    run_codefix,
    spawn_remediation,
    verify_fix,
)
from .triage import (
    TRIAGE_QUERIES,
    RemediationDraft,
    TriageFinding,
    TriageQuery,
    may_remediate,
    run_triage,
    severity_rank,
)

__all__ = [
    # triage
    "TriageFinding", "RemediationDraft", "TriageQuery", "TRIAGE_QUERIES",
    "run_triage", "may_remediate", "severity_rank",
    # codefix — request/result/verification
    "CodeFixRequest", "CodeFixResult", "FixVerification", "PipelineStep",
    "spawn_remediation", "run_codefix", "verify_fix",
    # codefix — proposal + safety helpers
    "EditBlock", "parse_edit_blocks", "render_untrusted_finding", "is_safe_repo_path",
    # codefix — injected-executor/approval/quorum result shapes
    "CloneResult", "WriteResult", "BuildResult", "PrResult", "ApprovalOutcome", "QuorumOutcome",
    # codefix — stage→tier constants
    "TIER_CLONE", "TIER_EDIT", "TIER_BUILD", "TIER_PR",
]
