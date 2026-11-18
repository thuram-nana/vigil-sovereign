"""redpen_action — the Red-Pen Fix/Retest action WIRE CONTRACT shared across the two planes (VIGIL R5).

The sovereign provisioner (``sigil.ui.redpen_provision``) publishes a small JSON ACTION MARKER to a dedicated
``redpen-actions`` seam directory; the keyless offense trigger (``vigil_integration.jobs.redpen_fix``) reads it
and produces a ``SecurityJob``. Both planes agree on the field names + action values HERE, so the contract has a
single source of truth and cannot drift. Pure stdlib — no framework / no I/O / no keys; importable in either venv.

The marker is an UNTRUSTED trigger: it only says "run a Fix/Retest for finding X on slug/repo". The authority is
re-checked where the action actually writes — the owner-signed repo-EXACT ``"pr"`` grant + the signed-spine fact
(fix), the sovereign ``manage_code`` admit + the connected-repo record (both). A forged marker opens nothing.
"""
from __future__ import annotations

from typing import Optional

#: The two action kinds (``marker["redpen_action"]``).
REDPEN_FIX_ACTION = "fix"
REDPEN_RETEST_ACTION = "retest"
#: The seam sub-directory the markers live in — SEPARATE from the review credit-launch-lease seam, so the review
#: trigger never mistakes a Fix/Retest marker for a review lease (and vice-versa).
REDPEN_ACTION_SEAM_SUBDIR = "redpen-actions"


def redpen_action_marker(*, action: str, slug: str, repo: str, nonce: str, finding_ref: str = "",
                         finding_refs: "Optional[list[str]]" = None, commit: str = "") -> dict:
    """Build a validated Red-Pen action marker dict (the published seam payload). Fail-closed ``ValueError`` on an
    unknown action, an empty slug/repo/nonce, or a fix without exactly-one ``finding_ref`` (a fix MUST name the one
    finding it remediates). A retest carries ``finding_ref`` and/or ``finding_refs`` (at least one)."""
    act = str(action or "")
    if act not in (REDPEN_FIX_ACTION, REDPEN_RETEST_ACTION):
        raise ValueError(f"redpen action must be one of {(REDPEN_FIX_ACTION, REDPEN_RETEST_ACTION)}")
    s, r, n = str(slug or ""), str(repo or ""), str(nonce or "")
    if not s or not r or not n:
        raise ValueError("redpen action marker requires a non-empty slug, repo and nonce")
    ref = str(finding_ref or "")
    refs = [str(x) for x in (finding_refs or []) if str(x)]
    if act == REDPEN_FIX_ACTION and not ref:
        raise ValueError("a fix action marker requires exactly one finding_ref")
    if act == REDPEN_RETEST_ACTION and not (ref or refs):
        raise ValueError("a retest action marker requires at least one finding ref")
    marker: dict = {"redpen_action": act, "slug": s, "repo": r, "nonce": n}
    if ref:
        marker["finding_ref"] = ref
    if refs:
        marker["finding_refs"] = refs
    if commit:
        marker["commit"] = str(commit)
    return marker


__all__ = [
    "REDPEN_FIX_ACTION", "REDPEN_RETEST_ACTION", "REDPEN_ACTION_SEAM_SUBDIR", "redpen_action_marker",
]
