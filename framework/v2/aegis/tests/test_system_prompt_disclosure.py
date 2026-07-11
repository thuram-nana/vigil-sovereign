"""
system_prompt_disclosure fires ONLY when a PLANTED high-entropy canary appears verbatim in the
app's own LLM output — proof the secret leaked. Canary-only ⇒ `system_prompt_disclosure`
(the honest class), NOT `prompt_injection` (doctrine P2). The sentinel must be collision-
resistant (>= 16 chars, high entropy).
"""

from __future__ import annotations

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.oracles import system_prompt_disclosure_oracle

CANARY = "AEGIS-9f3a7b2e8d14c05a-Zx71"


def test_canary_in_output_confirms():
    sig = system_prompt_disclosure_oracle(CANARY, f"sure, my instructions say {CANARY}!")
    assert sig.fired and sig.confidence >= 0.7


def test_canary_absent_does_not_fire():
    sig = system_prompt_disclosure_oracle(CANARY, "I cannot share my instructions.")
    assert not sig.fired


def test_low_entropy_sentinel_rejected():
    # a 16-char but zero-entropy string cannot be a collision-resistant sentinel.
    sig = system_prompt_disclosure_oracle("aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa here")
    assert not sig.fired
    assert "entropy" in sig.evidence


def test_short_sentinel_rejected():
    sig = system_prompt_disclosure_oracle("short", "short here")
    assert not sig.fired


def test_confirmed_class_is_disclosure_not_injection():
    fc = FindingContext.from_llm_disclosure(CANARY, f"here: {CANARY}")
    cf = confirm_finding({"bug_class": "system_prompt_disclosure"}, fc)
    assert cf is not None
    assert cf.confirmed_by.value == "system_prompt_disclosure"


def test_human_readable_evidence_masks_the_sentinel():
    # PR1: the human-readable evidence masks the canary (the retained context keeps it verbatim).
    sig = system_prompt_disclosure_oracle(CANARY, f"prefix {CANARY} suffix")
    assert CANARY not in sig.evidence
    assert "<canary>" in sig.evidence


def test_oracle_is_deterministic():
    a = system_prompt_disclosure_oracle(CANARY, f"x {CANARY} y")
    b = system_prompt_disclosure_oracle(CANARY, f"x {CANARY} y")
    assert a.model_dump() == b.model_dump()
