"""
A Verdict's attack_class is a verify KnownBugClass — an out-of-vocabulary (hallucinated) class
is parse-rejected. The confirmed⇔certificate invariant is enforced too.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from framework.v2.aegis.models import CertRef, Verdict


def test_oov_attack_class_is_parse_rejected():
    with pytest.raises(ValidationError):
        Verdict(decision="lead", attack_class="totally_invented_ai_attack")


def test_known_aegis_classes_parse():
    for cls in ("prompt_injection", "system_prompt_disclosure", "automated_access"):
        v = Verdict(decision="lead", attack_class=cls)
        assert v.attack_class == cls


def test_scraping_alias_normalises_to_automated_access():
    # P1: `automated_scraping` can never be its own confirmed class — it folds to automated_access.
    v = Verdict(decision="lead", attack_class="automated_scraping")
    assert v.attack_class == "automated_access"


def test_confirmed_requires_certificate():
    with pytest.raises(ValidationError):
        Verdict(decision="confirmed", attack_class="automated_access", certificate=None)


def test_non_confirmed_must_not_carry_certificate():
    cert = CertRef.mint({"bug_class": "automated_access"}, bug_class="automated_access",
                        confirmed_by="automated_access", confidence=0.95)
    with pytest.raises(ValidationError):
        Verdict(decision="lead", attack_class="automated_access", certificate=cert)


def test_decision_is_never_a_bare_boolean():
    with pytest.raises(ValidationError):
        Verdict(decision=True, attack_class="automated_access")  # type: ignore[arg-type]
