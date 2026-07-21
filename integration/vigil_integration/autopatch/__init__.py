"""
vigil_integration.autopatch — the AIxCC AUTO-PATCH loop (VIGIL phase 32).

The sovereign auto-patch loop layered directly on :mod:`vigil_integration.remediation` (the gated, tiered
codefix boundary) and :mod:`vigil_integration.fsjob` (the path-confinement kernel). :func:`autopatch`
takes an oracle-confirmed FACT, asks the injected coder LLM for a minimal unified-diff proposal, applies it
through the gated clone/edit/build/PR ladder inside an fsjob sandbox, and mints a signed 'remediated'
certificate ONLY after the fix-verification oracle re-fires the original exploit and goes SILENT.

The sovereign invariant (what the red-pen attacks): NO patch is applied or PR'd without an oracle-confirmed
FACT (a LEAD is refused); the per-file approval TIMEOUT auto-REJECTS via the injected clock (never
auto-accepts — the redamon flip); a PR opens ONLY after the m-of-n threshold; only explicit, path-validated
files are ever staged (never ``git add -A``); and 'remediated' is signed ONLY on oracle SILENCE against the
patched build. Every public function is total on malformed input and deterministic.

Import-clean: pydantic + stdlib + the F9/F10 seams only (all side effects are injected callables).
"""

from .loop import (
    BuildResult,
    CloneResult,
    FixOracle,
    OracleVerdict,
    PatchApproval,
    PatchFile,
    PatchResult,
    PrResult,
    QuorumOutcome,
    autopatch,
    parse_unified_diff,
    verify_patch,
)

__all__ = [
    # the loop
    "autopatch",
    # untrusted-diff parsing + fix verification
    "parse_unified_diff", "verify_patch",
    # result / proposal / approval / verdict shapes
    "PatchResult", "PatchFile", "PatchApproval", "OracleVerdict",
    # injected-executor result shapes
    "CloneResult", "BuildResult", "PrResult", "QuorumOutcome",
    # the fix-verification oracle type
    "FixOracle",
]
