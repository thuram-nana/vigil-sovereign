"""The evidence-tier coverage number is generated from one registry-grounded source, in every document.

WHY THIS TEST EXISTS. The split of detector kinds across evidence tiers — external / own-infrastructure /
local / fixtures — is the system's single most-quoted honesty number. Two shipped documents once
disagreed about it: ``docs/plain-english/05-weakness-types.md`` said ``3 / 2 / 13 / 20`` and
``docs/plain-english/_inventory/E-today-and-catalogues.md`` said ``3 / 2 / 12 / 21``. A number a reader
carries to a national agency must not be maintained by hand in two places. It is now derived once, from
``docs/capability-matrix/coverage-tiers.json`` keyed by the ``OracleKind`` registry, and rendered into
both documents by ``docs/capability-matrix/gen_coverage_tiers.py``. This guard fails the build if either
document drifts from that source, or if the source itself comes loose from the registry.

This test reads files and imports the generator, which uses only the standard library and neither trust
domain — so it is safe in the reads-only ``briefing-completeness`` CI leg (which installs only pytest).
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_GEN = _REPO / "docs" / "capability-matrix" / "gen_coverage_tiers.py"
_MASTER = _REPO / "docs" / "plain-english" / "VIGIL-EXPLAINED.md"
_DOC_E = _REPO / "docs" / "plain-english" / "_inventory" / "E-today-and-catalogues.md"


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_coverage_tiers", _GEN)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


g = _load_generator()


# --------------------------------------------------------------------------------------------
# The source of truth is grounded in the registry, and the documents match it.
# --------------------------------------------------------------------------------------------

def test_source_of_truth_is_grounded_in_the_oracle_kind_registry() -> None:
    """coverage-tiers.json lists EXACTLY the OracleKind members, and no ladder oracle is unknown."""
    counts = g.validate()                       # raises DriftError on any grounding failure
    assert sum(counts.values()) == len(g._oracle_kinds())


def test_both_documents_match_the_generated_block() -> None:
    """The one number the two documents once disagreed about is now identical in both, by generation."""
    problems = g.check()
    assert problems == [], "coverage-tiers drift:\n" + "\n".join(problems)


def test_the_reconciled_numbers_are_3_2_13_20() -> None:
    """Pin the reconciled truth: the 05 chapter (3/2/13/20) was correct; the inventory (3/2/12/21) drifted.

    Derived, not asserted blind — the counts come from the registry-grounded source; this states the
    value that reconciliation landed on so a future edit that changes an honesty number is loud."""
    counts = g.validate()
    assert (counts["external"], counts["own_infrastructure"], counts["local"], counts["fixtures"]) \
        == (3, 2, 13, 20)


def test_the_inventory_inline_quotable_row_matches_the_source() -> None:
    """E-today's PART 8 keeps a one-line quotable ``N / N / N / N``; it must equal the generated counts."""
    counts = g.validate()
    text = _DOC_E.read_text(encoding="utf-8")
    m = re.search(r"\*\*(\d+) / (\d+) / (\d+) / (\d+)\*\* \| Detector kinds with external", text)
    assert m, "the inventory's inline external/own/local/fixture quotable row was not found"
    assert tuple(int(x) for x in m.groups()) \
        == (counts["external"], counts["own_infrastructure"], counts["local"], counts["fixtures"])


def test_the_stale_number_is_gone_everywhere() -> None:
    """The specific drifted string must not reappear in any of the three carrying documents."""
    for path in (_DOC_E, _REPO / "docs" / "plain-english" / "05-weakness-types.md", _MASTER):
        assert "3 / 2 / 12 / 21" not in path.read_text(encoding="utf-8"), f"stale number back in {path}"


def test_the_assembled_master_carries_the_reconciled_block() -> None:
    """VIGIL-EXPLAINED.md is built from chapter 05; the generated block must appear in it too (assembly
    kept in sync). If this fails, re-run docs/plain-english/_assembly/assemble.py."""
    block = g.render_block()
    assert block in _MASTER.read_text(encoding="utf-8"), \
        "assembled master lags chapter 05 — re-run assemble.py after regenerating the block"


# --------------------------------------------------------------------------------------------
# W16-STD-2(d): the one-line evidence-tier SENTENCE is generated from the registry too, and published.
# --------------------------------------------------------------------------------------------

def test_the_generated_tier_sentence_matches_the_registry_counts() -> None:
    """The one-line "of N registered oracle kinds, X external, Y own-infra, Z loopback, W fixtures-only"
    summary is GENERATED from the registry-grounded counts — not hand-maintained. It states the N total and
    the per-tier split derived from ``validate()``. (Before W16-STD-2(d) there was no ``render_sentence`` and
    the prose in OUTSTANDING.md had drifted to "2 external ... ~14 loopback", so this test fails.)"""
    counts = g.validate()
    total = sum(counts.values())
    sentence = g.render_sentence()
    assert f"Of the {total} registered oracle kinds" in sentence
    assert f"{counts['external']} external" in sentence
    assert f"{counts['own_infrastructure']} own-infra" in sentence
    assert f"{counts['local']} loopback" in sentence
    assert f"{counts['fixtures']} fixtures-only" in sentence


def test_the_generated_tier_sentence_is_published_and_in_sync() -> None:
    """The generated sentence is published verbatim in OUTSTANDING.md, and check() (which now covers BOTH the
    table and the sentence) reports no drift."""
    sentence = g.render_sentence()
    doc = g._DOC_OUTSTANDING.read_text(encoding="utf-8")
    region = g._extract_marked(doc, g._DOC_OUTSTANDING, g.SENTENCE_BEGIN, g.SENTENCE_END,
                               "coverage-tiers-sentence")
    assert region == sentence, "OUTSTANDING.md's generated tier sentence has drifted — run gen_coverage_tiers.py"
    assert g.check() == []


def test_the_sentence_is_generated_not_hardcoded() -> None:
    """NEGATIVE CONTROL: move one detector's tier in an in-memory copy; the SENTENCE's numbers must follow —
    proving it is derived from the registry, not a constant string."""
    import copy
    src = copy.deepcopy(g.load_source())
    moved = next(d for d in src["detectors"] if d["tier"] == "local")
    moved["tier"] = "fixtures"
    sentence = g.render_sentence(src)
    assert "12 loopback" in sentence and "21 fixtures-only" in sentence   # the counts followed the move
    assert "13 loopback" not in sentence


def test_check_catches_a_drifted_sentence() -> None:
    """NEGATIVE CONTROL: a tampered sentence region between the markers must be reported — proven on a
    synthetic string carrying the sentence markers."""
    sentence = g.render_sentence()
    good = f"prefix\n{sentence}\nsuffix"
    assert g._extract_marked(good, Path("synthetic"), g.SENTENCE_BEGIN, g.SENTENCE_END, "s") == sentence
    tampered = good.replace("13 loopback", "14 loopback")
    assert g._extract_marked(tampered, Path("synthetic"), g.SENTENCE_BEGIN, g.SENTENCE_END, "s") != sentence


def test_missing_sentence_markers_are_reported_not_silently_ignored() -> None:
    with pytest.raises(g.DriftError):
        g._extract_marked("a document with no sentence markers", Path("synthetic"),
                          g.SENTENCE_BEGIN, g.SENTENCE_END, "coverage-tiers-sentence")


# --------------------------------------------------------------------------------------------
# The guard has teeth — each failure mode is provoked and must be caught.
# --------------------------------------------------------------------------------------------

def test_generation_is_real_not_hardcoded() -> None:
    """Move one detector to a different tier in an in-memory copy; the rendered counts must follow."""
    import copy
    src = copy.deepcopy(g.load_source())
    moved = next(d for d in src["detectors"] if d["tier"] == "local")
    moved["tier"] = "fixtures"
    counts = g.validate(src)
    assert counts["local"] == 12 and counts["fixtures"] == 21     # the very number that drifted, on purpose
    assert "| 12 |" in g.render_block(src)


def test_grounding_rejects_a_phantom_detector() -> None:
    import copy
    src = copy.deepcopy(g.load_source())
    src["detectors"].append({"kind": "not_a_real_oracle", "tier": "fixtures"})
    with pytest.raises(g.DriftError):
        g.validate(src)


def test_grounding_rejects_an_omitted_detector() -> None:
    import copy
    src = copy.deepcopy(g.load_source())
    src["detectors"].pop()
    with pytest.raises(g.DriftError):
        g.validate(src)


def test_grounding_rejects_an_unknown_tier() -> None:
    import copy
    src = copy.deepcopy(g.load_source())
    src["detectors"][0]["tier"] = "made_up_tier"
    with pytest.raises(g.DriftError):
        g.validate(src)


def test_check_catches_a_drifted_document_block() -> None:
    """A tampered block between the markers must be reported by check() — proven on a synthetic string."""
    block = g.render_block()
    good = f"prefix\n{block}\nsuffix"
    assert g._extract_region(good, Path("synthetic")) == block
    tampered = good.replace("| 13 |", "| 12 |")
    assert g._extract_region(tampered, Path("synthetic")) != block


def test_missing_markers_are_reported_not_silently_ignored() -> None:
    with pytest.raises(g.DriftError):
        g._extract_region("a document with no markers", Path("synthetic"))
