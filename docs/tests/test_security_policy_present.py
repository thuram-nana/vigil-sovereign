"""W12-2 (#491): a root ``SECURITY.md`` must exist and stay a real disclosure policy.

WHY THIS TEST EXISTS. A security product with no coordinated-disclosure path is a credibility
hole — a researcher who finds a flaw in VIGIL itself has nowhere private to send it, and no
stated promise that a good-faith report will not be met with a lawsuit. W12-2 lands a root
``SECURITY.md`` with the four elements the issue names: a working security contact, a
supported-versions policy, a coordinated-disclosure process, and an explicit safe-harbour
statement for good-faith research. This guard keeps all four true of the file so it cannot be
deleted or silently gutted:

  * the file is missing from the repository root (``test_security_md_exists_at_root``) — the
    exact state on a tree WITHOUT this change, so the guard fails there, observed not assumed;
  * the contact string is gone, so a reporter has no address (``..._has_a_contact_...``);
  * any one of the four required elements is absent (``..._has_all_required_elements``);
  * the README no longer routes a reader to the disclosure path (``..._readme_references_...``).

The negative controls feed ``security_policy_defects`` — the same enforcing helper the positive
tests rely on — a document with one element removed and assert it is reported defective, in the
same run, so the gate is provably not a no-op.

It reads files only — imports nothing, runs no tool, sends no packet — so it is correct to run in
the docs-only ``the briefing explains every agent and capability`` CI job that runs
``pytest docs/tests -q`` and installs only pytest.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SECURITY_MD = REPO / "SECURITY.md"
README = REPO / "README.md"

# The repository's real, already-published security contact (LICENSE-COMMERCIAL.md, LICENSING.md,
# README). W12-2 reuses it rather than inventing an address.
CONTACT_EMAIL = "thuram@thuramnana.com"


def _collapsed(text: str) -> str:
    """Whitespace-collapsed, lower-cased view, so a phrase that wraps across lines and any
    capitalisation still matches as one needle."""
    return re.sub(r"\s+", " ", text).lower()


# --------------------------------------------------------------------------------------------------
# The enforcing helper (this is the claim's ``enforced_by`` symbol). Returns the list of REQUIRED
# elements a candidate SECURITY.md is missing; an empty list means the document satisfies the policy.
# Pure function of the text, so both the positive tests and the negative controls run through it.
# --------------------------------------------------------------------------------------------------
def security_policy_defects(text: str) -> list[str]:
    flat = _collapsed(text)
    defects: list[str] = []

    # 1. A working security contact.
    if CONTACT_EMAIL not in flat:
        defects.append(f"no security contact ({CONTACT_EMAIL} not present)")

    # 2. A supported-versions policy.
    if "supported version" not in flat:
        defects.append("no supported-versions policy ('Supported versions' section missing)")

    # 3. A coordinated-disclosure process.
    if "coordinated" not in flat or "disclosure" not in flat:
        defects.append("no coordinated-disclosure process ('coordinated disclosure' missing)")
    if "report" not in flat:
        defects.append("no reporting instructions (nothing tells a reporter how to report)")

    # 4. An explicit safe-harbour statement for good-faith research.
    if "safe harbour" not in flat and "safe harbor" not in flat:
        defects.append("no safe-harbour statement ('safe harbour'/'safe harbor' missing)")
    if "good faith" not in flat and "good-faith" not in flat:
        defects.append("safe-harbour statement does not mention good-faith research")

    return defects


# A minimal document that satisfies every required element — the baseline the negative controls
# mutate, one element at a time, to prove each check is live.
_VALID_BASELINE = f"""
# Security Policy
## Security contact
Email: {CONTACT_EMAIL}
## Supported versions
Only the latest release is supported.
## Reporting a vulnerability — coordinated disclosure
Report privately; the default coordinated disclosure window is 90 days.
## Safe harbour
Good-faith research conducted under this policy is authorized.
"""


# --------------------------------------------------------------------------------------------------
# Positive assertions against the real, shipped file.
# --------------------------------------------------------------------------------------------------
def test_security_md_exists_at_root():
    # On a tree WITHOUT this change the root SECURITY.md does not exist and this fails here — the
    # "fails without the fix" acceptance criterion, observed rather than assumed.
    assert SECURITY_MD.is_file(), (
        "root SECURITY.md is missing — a security product must publish a coordinated-disclosure path"
    )


def test_security_md_has_a_contact_so_it_cannot_be_silently_gutted():
    text = SECURITY_MD.read_text(encoding="utf-8")
    assert CONTACT_EMAIL in _collapsed(text), (
        f"root SECURITY.md no longer names a working contact ({CONTACT_EMAIL}) — a reporter would "
        "have nowhere private to send a vulnerability"
    )


def test_security_md_has_all_required_elements():
    text = SECURITY_MD.read_text(encoding="utf-8")
    defects = security_policy_defects(text)
    assert defects == [], f"root SECURITY.md is missing required element(s): {defects}"


def test_readme_references_the_disclosure_path():
    readme = README.read_text(encoding="utf-8")
    assert "SECURITY.md" in readme, (
        "README must reference SECURITY.md so a reader finds the disclosure path from the front page"
    )


# --------------------------------------------------------------------------------------------------
# The valid baseline passes — so the negative controls below isolate exactly one missing element.
# --------------------------------------------------------------------------------------------------
def test_valid_baseline_has_no_defects():
    assert security_policy_defects(_VALID_BASELINE) == []


# --------------------------------------------------------------------------------------------------
# Negative controls — a deliberately bad document is REJECTED, in the same run. Proves the gate is
# not a no-op. Each removes exactly one required element from the valid baseline.
# --------------------------------------------------------------------------------------------------
def test_negative_control_missing_contact_is_rejected():
    bad = _VALID_BASELINE.replace(CONTACT_EMAIL, "see the website")
    defects = security_policy_defects(bad)
    assert any("contact" in d for d in defects), defects


def test_negative_control_missing_supported_versions_is_rejected():
    bad = _VALID_BASELINE.replace("## Supported versions", "## Releases").replace(
        "Only the latest release is supported.", "We ship releases.")
    defects = security_policy_defects(bad)
    assert any("supported-versions" in d for d in defects), defects


def test_negative_control_missing_coordinated_disclosure_is_rejected():
    bad = _VALID_BASELINE.replace(
        "## Reporting a vulnerability — coordinated disclosure",
        "## Notes").replace(
        "Report privately; the default coordinated disclosure window is 90 days.",
        "Please be nice.")
    defects = security_policy_defects(bad)
    assert any("coordinated-disclosure" in d or "reporting" in d for d in defects), defects


def test_negative_control_missing_safe_harbour_is_rejected():
    bad = _VALID_BASELINE.replace("## Safe harbour", "## Thanks").replace(
        "Good-faith research conducted under this policy is authorized.", "Thanks for reading.")
    defects = security_policy_defects(bad)
    assert any("safe-harbour" in d or "good-faith" in d for d in defects), defects


def test_negative_control_empty_document_is_rejected():
    assert security_policy_defects("") != []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
