"""
W14-2 (#504) — no client legal instrument ships until counsel has reviewed it
AND every placeholder in it is resolved.

The counsel review and the resolution of the governing-law (and every other)
placeholder are HUMAN actions; this suite proves the *enforcement* that makes an
unreviewed or placeholder-bearing instrument unshippable — it does NOT assert
that the human work is done. As of W14-2 all three instruments are recorded
PENDING, so the ship gate refuses every one of them, which is what these tests
pin.

Fail-without-fix: this file imports ``..counsel_review`` at module scope. On a
tree without W14-2 the module does not exist and the file ERRORs at collection.

Negative controls (in this same run):
  * reintroducing a placeholder into an otherwise clean, reviewed instrument
    turns the gate red (``test_reintroducing_a_placeholder_turns_the_gate_red``);
  * an unreviewed instrument is refused even when its text is clean
    (``test_unreviewed_instrument_is_refused``);
  * a missing/malformed manifest, a non-``true`` review flag, and a missing
    instrument file all fail closed.

Positive control (proves the gate is not a constant refusal):
  * a reviewed instrument with fully-resolved, placeholder-free text ships
    (``test_a_reviewed_placeholder_free_instrument_ships``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ...common.errors import EthicsViolation, InstrumentNotShippable
from ..counsel_review import (
    DEFAULT_MANIFEST,
    InstrumentRecord,
    ManifestError,
    assert_shippable,
    check_instrument,
    find_placeholders,
    load_review_manifest,
    review_report,
    ship_instruments,
)

# The three client legal instruments this issue enumerates.
_EXPECTED_IDS = {"authorization-letter", "nda", "dpa"}

# A fully-resolved, placeholder-free instrument body (the positive-control shape):
# real governing law, a real date, no bracket/angle/blank fill-ins.
_CLEAN = (
    "# Mutual non-disclosure agreement — Acme Corp\n\n"
    "This Agreement is entered into on 24 August 2026 between Acme Corp and the "
    "Operator. It is governed by, and construed in accordance with, the laws of "
    "England and Wales, and the parties submit to the exclusive jurisdiction of "
    "the courts of London.\n"
)


def _record(**kw: object) -> InstrumentRecord:
    base: dict[str, object] = dict(
        id="x",
        title="t",
        path=Path("/nonexistent"),
        reviewed_by_counsel=False,
        governing_law_resolved=False,
    )
    base.update(kw)
    return InstrumentRecord(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------------
# The manifest records the human decision, defaulting to PENDING.
# --------------------------------------------------------------------------------------------------
def test_manifest_lists_the_three_instruments_all_pending() -> None:
    records = load_review_manifest()
    assert {r.id for r in records} == _EXPECTED_IDS
    by_id = {r.id: r for r in records}
    # AC(c): COUNSEL REVIEW is recorded PENDING for EVERY instrument — the honest,
    # load-bearing fact the ship gate depends on. Counsel review is a HUMAN action;
    # nothing here marks it done, so no instrument can ship on the review flag.
    for r in records:
        assert r.reviewed_by_counsel is False, f"{r.id} must be recorded PENDING counsel review (human action)"
        assert r.path.is_file(), f"{r.id} instrument file must exist: {r.path}"
    # The GOVERNING-LAW decision is a SEPARATE human action, and the operator has now
    # made it (the Republic of Cameroon; a move to Delaware, USA is planned). The NDA
    # and DPA carry an inline governing-law clause, so they record governing_law_resolved
    # true; the authorization letter inherits its governing law from the signed
    # EngagementAuthorization and keeps no inline clause, so it stays recorded false.
    # Either way the gate STILL refuses to ship (counsel PENDING + per-engagement
    # fill-ins remain) — see the placeholder/ship-gate tests below.
    assert by_id["nda"].governing_law_resolved is True, "NDA governing law is resolved (Republic of Cameroon)"
    assert by_id["dpa"].governing_law_resolved is True, "DPA governing law is resolved (Republic of Cameroon)"
    assert by_id["authorization-letter"].governing_law_resolved is False, \
        "authorization letter has no inline governing-law clause (inherited); recorded unresolved"


def test_default_manifest_path_points_at_the_committed_file() -> None:
    assert DEFAULT_MANIFEST.name == "counsel-review-status.json"
    assert DEFAULT_MANIFEST.is_file()


# --------------------------------------------------------------------------------------------------
# The placeholder scanner — the tokens a shipped instrument must never contain.
# --------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "token",
    ["[GOVERNING LAW]", "<PLACEHOLDER>", "TBD", "<customer legal name>",
     "YYYY-MM-DD", "__________", "<A0 | A1 | A2 | A3>", "TODO", "FIXME"],
)
def test_placeholder_scanner_flags_known_tokens(token: str) -> None:
    found = find_placeholders(f"prefix {token} suffix")
    assert found, f"scanner must flag placeholder {token!r}"
    assert any(p.token == token for p in found)


@pytest.mark.parametrize(
    "text",
    ["[GDPR]", "[1]", "see [the docs](https://example.com) for detail",
     "governed by the laws of England and Wales",
     "contact <https://example.com>", "email <ops@example.com>",
     "<!-- ENVELOPE:BEGIN -->", "signed on 24 August 2026",
     "[SOC2]", "[HIPAA]", "[PCI]"],
)
def test_placeholder_scanner_ignores_legitimate_prose(text: str) -> None:
    # No false positives on markdown links, acronyms (incl. single-word bracket
    # acronyms like [GDPR]/[SOC2] that are NOT curated fill-in words), footnotes,
    # autolinks, emails, HTML comments, or plain prose — so a genuinely clean
    # instrument can pass the gate (otherwise the positive control could never hold).
    assert find_placeholders(text) == []


@pytest.mark.parametrize("token", ["[VENUE]", "[PARTY]", "[ISSUER]", "[JURISDICTION]", "[DATE]"])
def test_single_word_bracket_fill_in_is_flagged(token: str) -> None:
    # Regression: red-pen HIGH. A single-word ALL-CAPS bracket placeholder from the
    # curated legal fill-in set MUST be flagged — the bracket family's
    # internal-separator requirement used to silently miss these, and both shipped
    # templates use [VENUE].
    found = find_placeholders(f"...the exclusive jurisdiction of the courts of {token}.")
    assert found, f"scanner must flag single-word bracket placeholder {token!r}"
    assert any(p.token == token for p in found)


def test_reviewed_instrument_with_only_a_venue_placeholder_is_refused() -> None:
    # Regression (AC a belt-and-suspenders): an otherwise-clean, REVIEWED instrument
    # whose ONLY remaining fill-in is a single-word [VENUE] must NOT ship. This is
    # the exact false-clean the red-pen constructed; it must stay red.
    only_venue = (
        "# Mutual NDA — Acme Corp\n\nThis Agreement is governed by the laws of "
        "England and Wales, and the parties submit to the exclusive jurisdiction "
        "of the courts of [VENUE]. Signed on 24 August 2026.\n"
    )
    reviewed = _record(reviewed_by_counsel=True, governing_law_resolved=True)
    with pytest.raises(InstrumentNotShippable) as exc:
        assert_shippable(reviewed, only_venue)
    assert "[VENUE]" in str(exc.value)


# --------------------------------------------------------------------------------------------------
# The ship gate — conjunctive: counsel review AND no placeholder.
# --------------------------------------------------------------------------------------------------
def test_a_reviewed_placeholder_free_instrument_ships() -> None:
    # POSITIVE control: proves the gate is not a constant "always refuse".
    check = assert_shippable(_record(reviewed_by_counsel=True, governing_law_resolved=True), _CLEAN)
    assert check.shippable is True
    assert check.reasons == []


def test_unreviewed_instrument_is_refused() -> None:
    # Clean text, but counsel has NOT recorded a review → refused (AC c).
    with pytest.raises(InstrumentNotShippable) as exc:
        assert_shippable(_record(reviewed_by_counsel=False), _CLEAN)
    assert "not counsel-reviewed" in str(exc.value)
    # And the typed refusal is an EthicsViolation, so it can never be swallowed
    # into an allow.
    assert isinstance(exc.value, EthicsViolation)


def test_reintroducing_a_placeholder_turns_the_gate_red() -> None:
    # NEGATIVE control (AC b) + belt-and-suspenders (AC a): start from a reviewed,
    # clean, SHIPPABLE instrument, then reintroduce a placeholder — the same
    # reviewed instrument now REFUSES to ship. So even a recorded review cannot
    # ship placeholder-bearing text.
    reviewed = _record(reviewed_by_counsel=True, governing_law_resolved=True)
    assert assert_shippable(reviewed, _CLEAN).shippable is True  # baseline: it shipped

    with_placeholder = _CLEAN + "\n\nGoverning law: [GOVERNING LAW].\n"
    with pytest.raises(InstrumentNotShippable) as exc:
        assert_shippable(reviewed, with_placeholder)
    assert "[GOVERNING LAW]" in str(exc.value)


def test_gate_reports_every_failing_reason_not_just_the_first() -> None:
    # Unreviewed AND placeholder-bearing → both reasons surface (a human sees the
    # whole outstanding worklist).
    check = check_instrument(_record(reviewed_by_counsel=False), "TBD [GOVERNING LAW]")
    assert check.shippable is False
    assert len(check.reasons) == 2


# --------------------------------------------------------------------------------------------------
# AC(a): NO shipped instrument contains an unresolved placeholder — over the REAL instruments.
# --------------------------------------------------------------------------------------------------
def test_no_shipped_instrument_can_contain_a_placeholder() -> None:
    # For every real instrument: even if we FORCE the review flag true, the gate
    # STILL refuses whenever the text carries a placeholder — so no instrument the
    # gate would ship can contain one (AC a, belt-and-suspenders over the review
    # flag). Robust to a future human resolution: an instrument with zero
    # placeholders is allowed to ship, and then it provably carries none.
    any_with_placeholder = False
    for record in load_review_manifest():
        content = record.path.read_text(encoding="utf-8")
        placeholders = find_placeholders(content)
        forced_reviewed = InstrumentRecord(
            id=record.id, title=record.title, path=record.path,
            reviewed_by_counsel=True, governing_law_resolved=True,
        )
        check = check_instrument(forced_reviewed, content)
        if placeholders:
            any_with_placeholder = True
            assert not check.shippable, f"{record.id} has placeholders yet was shippable"
            with pytest.raises(InstrumentNotShippable):
                assert_shippable(forced_reviewed, content)
        if check.shippable:
            assert placeholders == []
    # As of W14-2 every instrument is still a placeholder-bearing template, so the
    # placeholder-refusal path above is genuinely exercised (not vacuous).
    assert any_with_placeholder


def test_review_report_invariant_shippable_implies_no_placeholder() -> None:
    # The property AC(a) states directly: any instrument the report marks
    # shippable carries zero placeholders.
    for check in review_report():
        if check.shippable:
            assert check.placeholders == []


# --------------------------------------------------------------------------------------------------
# The current committed state is honestly PENDING → the whole set is unshippable.
# --------------------------------------------------------------------------------------------------
def test_ship_gate_refuses_the_current_pending_set() -> None:
    with pytest.raises(InstrumentNotShippable):
        ship_instruments()
    # And each instrument is individually unshippable right now.
    reports = {c.instrument_id: c for c in review_report()}
    assert reports.keys() == _EXPECTED_IDS
    for c in reports.values():
        assert c.shippable is False


# --------------------------------------------------------------------------------------------------
# Fail-closed manifest handling.
# --------------------------------------------------------------------------------------------------
def test_missing_manifest_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ManifestError):
        load_review_manifest(tmp_path / "nope.json")


def test_malformed_manifest_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "m.json"
    bad.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_review_manifest(bad)


def test_non_true_review_flag_coerces_to_pending(tmp_path: Path) -> None:
    # Only a real JSON `true` counts as reviewed; a truthy STRING must not ship.
    m = tmp_path / "m.json"
    m.write_text(
        json.dumps({"instruments": [
            {"id": "a", "title": "t", "path": "a.md", "reviewed_by_counsel": "true"},
        ]}),
        encoding="utf-8",
    )
    (tmp_path / "a.md").write_text(_CLEAN, encoding="utf-8")
    records = load_review_manifest(m)
    assert records[0].reviewed_by_counsel is False
    with pytest.raises(InstrumentNotShippable):
        ship_instruments(m)


def test_missing_instrument_file_is_refused_not_skipped(tmp_path: Path) -> None:
    # A manifest that promises a file which does not exist must fail closed, not
    # ship it as vacuously empty/clean.
    m = tmp_path / "m.json"
    m.write_text(
        json.dumps({"instruments": [
            {"id": "a", "title": "t", "path": "missing.md", "reviewed_by_counsel": True},
        ]}),
        encoding="utf-8",
    )
    with pytest.raises(InstrumentNotShippable):
        ship_instruments(m)
    # review_report does not raise, but marks it unshippable.
    assert review_report(m)[0].shippable is False
