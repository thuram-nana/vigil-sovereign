"""
Pin the grounding vocabularies the P3 Attack-Graph + Findings UI keys on, so a backend rename can't
silently make the graph LIE about what is oracle-proven (the red-pen BLOCK P3 fixed).

Two DISTINCT vocabularies the UI must not confuse:
  * world-model (`worldmodel.models.classify_provenance`): the FACT tier is "grounded" (oracle / signed
    cert / promoted finding); "intel"/"ungrounded"/"unclassified" are inferred/unproven. The UI's
    `p3WmFact(g)` treats ONLY "grounded" as a fact.
  * report (`scanner.report`): the FACT tier is the literal string "fact"; the UI's `p3IsFact(f)` keys on
    `grounding === "fact"`.

If either literal changes, this test fails — forcing the matching UI predicate to be updated in lockstep.
"""
from __future__ import annotations

from framework.v2.worldmodel.models import (
    GROUNDING_GROUNDED,
    GROUNDING_INTEL,
    GROUNDING_UNGROUNDED,
    classify_provenance,
)


def test_worldmodel_fact_tier_literal_is_grounded():
    # p3WmFact(g) == (g === "grounded") — pin the exact literal.
    assert GROUNDING_GROUNDED == "grounded"


def test_oracle_and_finding_provenance_classify_as_grounded():
    # the provenance strings real runs write for confirmed findings / fired oracles → the FACT tier.
    for prov in ("oracle:sqli", "oracle:xss", "finding:sqli", "finding:path_traversal"):
        assert classify_provenance(prov) == GROUNDING_GROUNDED == "grounded", prov


def test_intel_and_llm_provenance_are_not_the_fact_tier():
    # inferred / collected / asserted provenance must NOT be the fact tier (so the UI shows LEAD, not FACT).
    assert classify_provenance("intel:crtsh") == GROUNDING_INTEL != "grounded"
    assert classify_provenance("llm:guess") == GROUNDING_UNGROUNDED != "grounded"
    assert classify_provenance("") != "grounded"          # unclassified, never a fact
    assert classify_provenance("assumption") != "grounded"


def test_report_fact_tier_literal_is_fact():
    # the other vocabulary p3IsFact keys on: the report's FACT label is the literal "fact".
    from framework.v2.scanner import report as _report
    # _grounding_label maps an admitted (oracle-re-fired) finding to "fact"; pin the literal exists.
    src = _report.__file__
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    assert '"fact"' in text, "report grounding fact-label literal changed — update p3IsFact"
