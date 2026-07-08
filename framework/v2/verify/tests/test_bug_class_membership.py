"""
Anti-hallucination P6 — bug_class value-membership for structured outputs.

Shape-valid is not enough: a structured LLM output can carry an INVENTED bug_class that
passes schema typing yet names something no oracle can prove. P6 promotes the vocabulary
into reusable pydantic validators: canonicalise every class at parse (one spelling
downstream), expose whether a class is oracle-provable, and — where a field asserts an
oracle-provable subject — REJECT an out-of-vocabulary class at parse time. Exploratory
hypotheses are left free to name broader leads; they are flagged, not rejected.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from framework.v2.verify.verifier import (
    BUG_CLASS_ORACLES,
    KnownBugClass,
    NormalizedBugClass,
    canonical_bug_class,
    is_known_bug_class,
    known_bug_classes,
    require_known_bug_class,
)


def test_known_bug_classes_is_the_oracle_vocabulary() -> None:
    vocab = known_bug_classes()
    assert vocab and set(BUG_CLASS_ORACLES) <= vocab
    assert {"idor", "xss", "boolean_sqli"} <= vocab


def test_is_known_normalises_and_checks_membership() -> None:
    assert is_known_bug_class("IDOR") and is_known_bug_class("auth-bypass")   # aliases/spelling
    assert is_known_bug_class("boolean_sqli")
    assert not is_known_bug_class("race")             # legitimate lead, but no oracle proves it
    assert not is_known_bug_class("quantum_sqli")     # invented


def test_canonical_returns_canonical_or_none() -> None:
    assert canonical_bug_class("AUTH-BYPASS") == "auth_bypass"
    assert canonical_bug_class("IDOR") == "idor"
    assert canonical_bug_class("totally_made_up") is None


# ---- the reusable pydantic field types --------------------------------------


class _Strict(BaseModel):
    bc: KnownBugClass


class _Norm(BaseModel):
    bc: NormalizedBugClass


def test_known_bug_class_field_rejects_invented_at_parse() -> None:
    assert _Strict(bc="IDOR").bc == "idor"                    # canonicalised
    assert _Strict.model_validate({"bc": "auth-bypass"}).bc == "auth_bypass"
    with pytest.raises(Exception):                            # invented → parse fails
        _Strict(bc="quantum_sqli")
    with pytest.raises(Exception):
        _Strict(bc="race")                                   # unprovable → not assertable as fact


def test_normalized_bug_class_field_canonicalises_but_does_not_reject() -> None:
    assert _Norm(bc="SQLi ").bc == "sqli"
    # an exploratory / unknown class is normalised and KEPT (leads are not rejected)
    assert _Norm(bc="cache-poisoning").bc == "cache_poisoning"


def test_require_known_helper_raises_on_unknown() -> None:
    assert require_known_bug_class("IDOR") == "idor"
    with pytest.raises(ValueError):
        require_known_bug_class("made_up_class")
