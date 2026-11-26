"""AS-4a — the D13 over-claim lint (``sigil.ui.overclaim_lint``) proves itself and PINS the honest copy.

The lint is the deterministic regression guard that keeps D13 marketing over-claims out of SIGIL's
customer-facing product copy. This suite proves it actually BITES:

  * one NEGATIVE test per enumerated forbidden term — feed the lint a string containing the term and
    assert it is flagged (a lint that cannot fail is not running);
  * a POSITIVE test — the current, fixed copy passes with ZERO findings;
  * the term list is explicit in ``RULES`` and every rule has its own negative sample (so a new rule
    cannot be added without a proof it catches something);
  * the "protected" status rule is precise — it catches a bare "Protected" badge but NOT the plan's
    "protected-host" slot or the "data-protection" law;
  * the mechanism-qualified, provable claim ("zero false positives by construction") is ALLOWED;
  * the lint is deterministic and FAIL-CLOSED (an unreadable surface raises, never passes).
"""
from __future__ import annotations

import pytest

from sigil.ui.overclaim_lint import (
    COPY_SURFACES,
    RULES,
    Finding,
    OverclaimLintError,
    scan_files,
    scan_text,
)

# One sample per enumerated D13 term: a string that CONTAINS the forbidden claim. Keyed by rule name
# so the coverage test below fails loudly if a rule is ever added without a negative proof.
_NEGATIVE_SAMPLES: dict[str, str] = {
    "universal_detection_prevention": "VIGIL offers universal detection of every attack.",
    "zero_false_positives_negatives": "Our engine has zero false negatives, ever.",
    "near_zero_false_positives": "You get near-zero false positives on every host.",
    "complete_mitre_coverage": "VIGIL ships complete MITRE ATT&CK coverage.",
    "permanent_protection": "Buy once for permanent protection of your assets.",
    "fully_protected": "After onboarding your host is fully protected.",
    "all_threats_blocked": "With Respond on, all threats blocked — guaranteed.",
    "protected_status": 'badge = h("span.cust-badge", { text: "Protected" });',
}


def test_every_rule_has_a_negative_sample() -> None:
    """The term list is enumerated and each entry carries a proof-of-catch — no rule ships untested."""
    assert {r.name for r in RULES} == set(_NEGATIVE_SAMPLES), (
        "every RULE must have exactly one negative sample in this test (and vice-versa)"
    )
    # exactly the eight D13 terms the AS-4a plan enumerates
    assert len(RULES) == 8


@pytest.mark.parametrize("rule_name", sorted(_NEGATIVE_SAMPLES))
def test_lint_catches_each_forbidden_term(rule_name: str) -> None:
    """NEGATIVE test, one per forbidden term: the lint flags a string that contains that term."""
    sample = _NEGATIVE_SAMPLES[rule_name]
    hits = scan_text(sample, surface="<negative-sample>")
    assert rule_name in {f.rule for f in hits}, (rule_name, sample, hits)


def test_current_customer_copy_passes() -> None:
    """POSITIVE test: the shipped (fixed) customer-facing copy carries NO D13 over-claim."""
    findings = scan_files()
    assert findings == [], "\n".join(f"{f.surface}: [{f.rule}] {f.phrase!r} — …{f.excerpt}…" for f in findings)


def test_protected_status_is_precise() -> None:
    """The bare "Protected" status is caught; the legitimate hyphenated compounds are not."""
    assert "protected_status" in {f.rule for f in scan_text('text: "Protected"')}
    assert "protected_status" in {f.rule for f in scan_text("Your account is protected.")}
    # a plan's slot feature and the name of a body of law are NOT status over-claims
    assert scan_text("buys protected-host slots (monitor_hosts)") == []
    assert scan_text("applicable data-protection laws") == []
    assert scan_text("the basis for last-admin protection") == []


def test_zero_fp_by_construction_is_allowed_but_the_bare_claim_is_not() -> None:
    """The mechanism-qualified, provable precision claim is allowed; the bare blanket claim is not."""
    assert scan_text("every finding is a FACT — zero false positives by construction") == []
    assert "zero_false_positives_negatives" in {f.rule for f in scan_text("we promise zero false positives")}


def test_lint_is_deterministic_and_ordered() -> None:
    """Pure function of the bytes: same input, same findings, in a stable (rule, position) order."""
    text = "universal detection and all threats blocked and a Protected badge"
    first = scan_text(text, surface="s")
    second = scan_text(text, surface="s")
    assert first == second
    assert [f.rule for f in first] == sorted((f.rule for f in first), key=[r.name for r in RULES].index)


def test_scan_files_is_fail_closed_on_an_unreadable_surface(tmp_path: object) -> None:
    """FAIL-CLOSED: a surface the lint is supposed to read but cannot is a FAILURE, not a pass."""
    from pathlib import Path

    missing = Path(str(tmp_path)) / "does-not-exist.js"
    with pytest.raises(OverclaimLintError):
        scan_files((missing,))


def test_the_enumerated_surfaces_exist() -> None:
    """Every copy surface the lint names is a real file (so the positive run scans what it claims to)."""
    for surface in COPY_SURFACES:
        assert surface.is_file(), surface


def test_finding_is_an_immutable_record() -> None:
    f = Finding(rule="r", phrase="p", surface="s", excerpt="e")
    with pytest.raises(Exception):
        f.rule = "x"  # type: ignore[misc]
