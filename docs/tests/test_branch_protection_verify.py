"""The branch-protection verify logic is real: it detects drift between LIVE protection and the
committed canonical policy ([W0-1] #554).

`.github/workflows/branch-protection-verify.yml` is the live-reality pin — it reads the actual GitHub
branch-protection settings and fails if they drift from `.github/required-status-checks.txt`. That job
is INERT until a fine-grained PAT with Administration:read is provided as the repo secret
BRANCH_PROTECTION_TOKEN (the default GITHUB_TOKEN cannot read branch protection). Provisioning that PAT
is a human/admin action, so the LIVE job cannot run in PR CI. What CAN run in PR CI — and does, here —
is the comparison LOGIC the job uses, now extracted to `tools/governance/branch_protection_check.py`.

This guard drives `compare_protection` with a synthetic "live" protection body and the committed
canonical list, and requires:

  * the real committed policy, matched exactly, produces NO problems; and
  * the NEGATIVE CONTROL the acceptance criterion names — temporarily removing a required check from the
    committed policy (or from the live set) — makes the compare FAIL; and
  * strict=false, allowed force-pushes, allowed deletions, and absent protection are each caught.

It also pins that the workflow actually calls the extracted module (so the tested logic is the real
logic, not a drifting copy).

STDLIB ONLY. Runs in the required `the briefing explains every agent and capability` CI job (which runs
`pytest docs/tests -q`, installing only pytest); the module it imports is stdlib-only and imports
neither trust domain.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GOV = REPO / "tools" / "governance"
CANONICAL = REPO / ".github" / "required-status-checks.txt"
WORKFLOW = REPO / ".github" / "workflows" / "branch-protection-verify.yml"

sys.path.insert(0, str(GOV))
import branch_protection_check as bpc  # noqa: E402 (path set above; stdlib-only)


def _canonical() -> list[str]:
    return bpc.load_canonical(CANONICAL.read_text(encoding="utf-8"))


def _live_matching(canonical: list[str]) -> dict:
    """A protection body that MATCHES the committed policy (the good case)."""
    return {
        "required_status_checks": {"strict": True, "contexts": list(canonical)},
        "required_signatures": {"enabled": True},   # W12-4 (#493): signed commits required
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "enforce_admins": {"enabled": False},
    }


# --------------------------------------------------------------------------------------------------
# The module reads the same canonical file the required-checks test pins (single source of truth).
# --------------------------------------------------------------------------------------------------
def test_load_canonical_reads_the_committed_policy():
    canonical = _canonical()
    assert canonical, "committed required-status-checks.txt parsed to nothing"
    assert len(canonical) == len(set(canonical)), f"duplicate canonical checks: {canonical}"
    # comment/blank lines must be ignored
    assert all(not c.startswith("#") for c in canonical)


# --------------------------------------------------------------------------------------------------
# Positive: matching live protection produces no problems.
# --------------------------------------------------------------------------------------------------
def test_matching_protection_has_no_problems():
    canonical = _canonical()
    assert bpc.compare_protection(_live_matching(canonical), canonical) == []


# --------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL named by the AC: dropping a required check from the committed policy makes it fail.
# --------------------------------------------------------------------------------------------------
def test_dropping_a_required_check_from_the_policy_fails():
    canonical = _canonical()
    live = _live_matching(canonical)  # live still has the FULL set
    dropped = canonical[1:]           # committed policy loses one check
    problems = bpc.compare_protection(live, dropped)
    assert problems, "removing a required check from the committed policy must make the compare FAIL"
    assert any("drifted" in p and canonical[0] in p for p in problems), problems


def test_live_missing_a_required_check_fails():
    canonical = _canonical()
    live = _live_matching(canonical)
    live["required_status_checks"]["contexts"] = canonical[1:]  # live drops one required check
    problems = bpc.compare_protection(live, canonical)
    assert any("missing from live" in p for p in problems), problems


# --------------------------------------------------------------------------------------------------
# The other drift dimensions the workflow guards.
# --------------------------------------------------------------------------------------------------
def test_strict_false_is_flagged():
    canonical = _canonical()
    live = _live_matching(canonical)
    live["required_status_checks"]["strict"] = False
    assert any("strict" in p for p in bpc.compare_protection(live, canonical))


def test_required_signatures_disabled_is_flagged():
    # W12-4 (#493) NEGATIVE CONTROL: live protection that does NOT require signed commits must fail the
    # compare — an unsigned push would otherwise be accepted on main. Proven in both shapes: the flag set
    # false, and the sub-resource absent entirely (as it is on an unprotected branch).
    canonical = _canonical()
    live = _live_matching(canonical)
    live["required_signatures"]["enabled"] = False
    assert any("required_signatures" in p for p in bpc.compare_protection(live, canonical)), \
        "disabled signed-commits must be caught"
    del live["required_signatures"]
    assert any("required_signatures" in p for p in bpc.compare_protection(live, canonical)), \
        "absent required_signatures must be caught (fail closed)"


def test_required_signatures_enabled_passes():
    # And with signatures enabled (plus the rest matching), there is no problem — proving the new check
    # is not a constant failure.
    canonical = _canonical()
    assert bpc.compare_protection(_live_matching(canonical), canonical) == []


def test_force_push_allowed_is_flagged():
    canonical = _canonical()
    live = _live_matching(canonical)
    live["allow_force_pushes"]["enabled"] = True
    assert any("force_pushes" in p or "force" in p for p in bpc.compare_protection(live, canonical))


def test_deletions_allowed_is_flagged():
    canonical = _canonical()
    live = _live_matching(canonical)
    live["allow_deletions"]["enabled"] = True
    assert any("deletions" in p or "deleted" in p for p in bpc.compare_protection(live, canonical))


def test_absent_protection_is_flagged():
    # An empty body (as if protection were absent / unreadable) must not pass: strict is missing and the
    # contexts are empty, so the compare reports drift rather than a clean match.
    canonical = _canonical()
    problems = bpc.compare_protection({}, canonical)
    assert problems, "empty/absent protection must be reported as drift, never a silent pass"


# --------------------------------------------------------------------------------------------------
# The workflow uses the extracted module (no inline copy that could drift from the tested logic).
# --------------------------------------------------------------------------------------------------
def test_workflow_calls_the_extracted_module():
    wf = WORKFLOW.read_text(encoding="utf-8")
    assert "tools/governance/branch_protection_check.py" in wf, (
        "branch-protection-verify.yml must call the extracted, unit-tested module, not an inline copy"
    )
    # The old inline heredoc must be gone, or the tested logic is not the logic that runs.
    assert "<<'PY'" not in wf, "an inline python heredoc has returned — the comparison logic would be a drifting copy"


def test_verify_is_advisory_not_required_until_token_provisioned():
    """The live pin must NOT be in the canonical required set (it no-ops without BRANCH_PROTECTION_TOKEN,
    so requiring it would block every PR). Confirms the promotion prep is correctly deferred."""
    canonical = _canonical()
    assert "branch protection matches the committed policy" not in canonical, (
        "the branch-protection live pin must stay OUT of the required set until BRANCH_PROTECTION_TOKEN "
        "is provisioned (a human/admin action); it is enumerated in KNOWN_ADVISORY instead"
    )
