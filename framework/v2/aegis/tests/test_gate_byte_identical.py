"""
The AEGIS appends are additive and default-safe, so `make gate` stays byte-identical:

  * G1 — the unknown-class fallback `_ALL_ORACLES` is FROZEN to the pre-AEGIS OracleKind
    members; it did NOT grow when the AEGIS members were appended, and `oracles_for("<unknown>")`
    does not include an AEGIS oracle. This is the byte-identical gap the design's own test
    would otherwise miss — we assert the FALLBACK path, not just known classes.
  * every pre-existing bug_class maps to exactly its unchanged oracle set.
  * known_bug_classes() grew by EXACTLY the AEGIS classes/aliases.
"""

from __future__ import annotations

from framework.v2.verify import verifier as V
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import BUG_CLASS_ORACLES, OracleVerifier, known_bug_classes

_AEGIS_KINDS = {OracleKind.PROMPT_INJECTION, OracleKind.SYSTEM_PROMPT_DISCLOSURE, OracleKind.AUTOMATED_ACCESS}
_AEGIS_CLASSES = {"prompt_injection", "system_prompt_disclosure", "automated_access"}
_AEGIS_ALIASES = {"jailbreak", "llm_prompt_injection", "indirect_prompt_injection",
                  "system_prompt_leak", "system_prompt_exfiltration", "canary_disclosure",
                  "automated_scraping", "honeypot_hit", "honeypot_fetch", "bot_access"}


def test_all_oracles_fallback_is_frozen_to_pre_aegis_members():
    # G1: the fallback is the 15 pre-AEGIS members, NOT tuple(OracleKind) (which now has 18).
    assert len(V._ALL_ORACLES) == 15
    assert set(V._ALL_ORACLES) == set(OracleKind) - _AEGIS_KINDS
    # and it is NOT derived from the enum (that would have grown it to 18).
    assert set(V._ALL_ORACLES) != set(OracleKind)


def test_unknown_class_fallback_excludes_aegis_oracles():
    # importing aegis must not let an AEGIS oracle leak into the unknown-class fallback.
    import framework.v2.aegis  # noqa: F401  (exercises the additive import)
    fallback = OracleVerifier().oracles_for("some_unknown_class_that_maps_to_nothing")
    assert fallback == V._ALL_ORACLES
    for kind in _AEGIS_KINDS:
        assert kind not in fallback


def test_preexisting_classes_map_to_unchanged_oracle_sets():
    # every non-AEGIS class still resolves to exactly its BUG_CLASS_ORACLES row.
    ver = OracleVerifier()
    for bug_class, expected in BUG_CLASS_ORACLES.items():
        if bug_class in _AEGIS_CLASSES:
            continue
        assert ver.oracles_for(bug_class) == expected
        assert not (set(expected) & _AEGIS_KINDS)


def test_known_bug_classes_grew_by_exactly_the_aegis_vocabulary():
    known = known_bug_classes()
    for cls in _AEGIS_CLASSES:
        assert cls in known
    for alias in _AEGIS_ALIASES:
        assert alias in known


def test_aegis_classes_map_to_their_single_oracle():
    from framework.v2.aegis.registry import verify_registration
    verify_registration()   # asserts every additive append is present + folds correctly
    assert BUG_CLASS_ORACLES["prompt_injection"] == (OracleKind.PROMPT_INJECTION,)
    assert BUG_CLASS_ORACLES["system_prompt_disclosure"] == (OracleKind.SYSTEM_PROMPT_DISCLOSURE,)
    assert BUG_CLASS_ORACLES["automated_access"] == (OracleKind.AUTOMATED_ACCESS,)
