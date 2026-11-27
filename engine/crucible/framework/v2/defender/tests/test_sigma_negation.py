"""
Negation-walker hardening for the defender.sigma v2 condition parser (AS-17a).

The condition grammar (``framework.v2.defender.sigma._eval_condition``) is a tiny recursive-descent
boolean evaluator with precedence ``not > and > or``, parentheses, and the ``1|all of
them|<prefix>*`` aggregations. Its negation handling is load-bearing: a Sigma ``filter`` is almost
always expressed as ``selection and not filter``, so a wrong ``not`` silently flips a detection.
The pre-existing tests exercised ``and not`` and the positive aggregations, but did NOT pin the
exact semantics of ``not`` over ``or`` / nested ``not`` / the aggregation quantifiers, nor that a
malformed negation fails CLOSED. These tests pin that correct behaviour so a refactor cannot
regress it.

Each selection ``<n>`` is wired to fire IFF the event carries ``f_<n> == 'hit'`` — so a test can
drive every selection independently to True/False and assert the engine's result against the
hand-computed boolean. (Sentinel values are deliberately NOT YAML booleans like ``yes``/``no``,
which ``safe_load`` would coerce to ``True``/``False`` and break the toggle.)

One of these tests (``test_negated_empty_prefix_glob_fails_closed``) pins the fix for a genuine
fail-OPEN bug found while reading the walker: ``not 1 of <prefix>*`` where the prefix matched NONE
of the rule's own selections used to fire on EVERY event (``not False`` over an empty quantifier),
fabricating a detection — the exact failure mode this fail-closed module forbids.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Sequence

from framework.v2.defender.logsource import LogEvent
from framework.v2.defender.sigma import SigmaRule, parse_sigma_rule, rule_matches_event


def _event(active: frozenset[str], names: Sequence[str]) -> LogEvent:
    """An event on which selection ``<n>`` matches IFF ``<n> in active`` (field ``f_<n>`` == 'hit').
    A non-'hit' value keeps the field PRESENT but non-matching, so this never tests field-absence."""
    fields: dict[str, "str | int"] = {f"f_{n}": ("hit" if n in active else "miss") for n in names}
    return LogEvent(channel="test", fields=fields,
                    raw=" ".join(f"{k}={v}" for k, v in fields.items()))


def _rule(condition: str, names: Sequence[str]) -> SigmaRule:
    """A rule whose selections are exactly ``names`` (each ``f_<n>: hit``) over ``condition``."""
    body = "".join(f"  {n}:\n    f_{n}: hit\n" for n in names)
    rule = parse_sigma_rule(f"title: t\nid: r\ndetection:\n{body}  condition: {condition}\n")
    assert rule is not None, f"rule failed to parse: {condition!r}"
    return rule


def _table(condition: str, names: Sequence[str]) -> dict[frozenset[str], bool]:
    """Evaluate ``condition`` over EVERY subset of ``names`` being active -> truth table."""
    rule = _rule(condition, names)
    out: dict[frozenset[str], bool] = {}
    for size in range(len(names) + 1):
        for combo in itertools.combinations(names, size):
            active = frozenset(combo)
            out[active] = rule_matches_event(rule, _event(active, names))
    return out


def _expected(names: Sequence[str], predicate: Callable[[frozenset[str]], bool]
              ) -> dict[frozenset[str], bool]:
    """The hand-computed truth table for ``predicate`` over every subset of ``names``."""
    out: dict[frozenset[str], bool] = {}
    for size in range(len(names) + 1):
        for combo in itertools.combinations(names, size):
            active = frozenset(combo)
            out[active] = predicate(active)
    return out


# ===========================================================================
# De Morgan — the headline negation identities, pinned to an ABSOLUTE truth table
# ===========================================================================

def test_not_of_or_is_de_morgan_and_of_nots() -> None:
    """``not (a or b)`` == ``(not a) and (not b)`` == the exact De Morgan truth table."""
    names = ("a", "b")
    reference = _expected(names, lambda s: not (("a" in s) or ("b" in s)))
    not_or = _table("not (a or b)", names)
    and_of_nots = _table("(not a) and (not b)", names)
    assert not_or == reference
    assert and_of_nots == reference
    assert not_or == and_of_nots
    # concrete spot-check: fires ONLY when neither selection is present.
    rule = _rule("not (a or b)", names)
    assert rule_matches_event(rule, _event(frozenset(), names)) is True
    assert rule_matches_event(rule, _event(frozenset({"a"}), names)) is False
    assert rule_matches_event(rule, _event(frozenset({"a", "b"}), names)) is False


def test_not_of_and_is_de_morgan_or_of_nots() -> None:
    """``not (a and b)`` == ``(not a) or (not b)`` == the exact De Morgan truth table."""
    names = ("a", "b")
    reference = _expected(names, lambda s: not (("a" in s) and ("b" in s)))
    not_and = _table("not (a and b)", names)
    or_of_nots = _table("(not a) or (not b)", names)
    assert not_and == reference
    assert or_of_nots == reference
    assert not_and == or_of_nots
    # concrete spot-check: fires UNLESS both selections are present.
    rule = _rule("not (a and b)", names)
    assert rule_matches_event(rule, _event(frozenset({"a", "b"}), names)) is False
    assert rule_matches_event(rule, _event(frozenset({"a"}), names)) is True
    assert rule_matches_event(rule, _event(frozenset(), names)) is True


# ===========================================================================
# Double negation
# ===========================================================================

def test_double_negation_is_identity() -> None:
    """``not not a`` == ``a`` (and ``not not not a`` == ``not a``) across the whole table."""
    names = ("a", "b")
    assert _table("not not a", names) == _table("a", names)
    assert _table("not not a", names) == _expected(names, lambda s: "a" in s)
    assert _table("not not not a", names) == _table("not a", names)


# ===========================================================================
# Precedence: not binds TIGHTER than and / or
# ===========================================================================

def test_not_binds_tighter_than_and() -> None:
    """``not a and b`` parses as ``(not a) and b`` — NOT ``not (a and b)``."""
    names = ("a", "b")
    assert _table("not a and b", names) == _table("(not a) and b", names)
    assert _table("not a and b", names) == _expected(
        names, lambda s: (not ("a" in s)) and ("b" in s))
    # the two groupings are genuinely different, so this is a real precedence assertion.
    assert _table("not a and b", names) != _table("not (a and b)", names)


def test_not_binds_tighter_than_or() -> None:
    """``not a or b`` parses as ``(not a) or b`` — NOT ``not (a or b)``."""
    names = ("a", "b")
    assert _table("not a or b", names) == _table("(not a) or b", names)
    assert _table("not a or b", names) == _expected(
        names, lambda s: (not ("a" in s)) or ("b" in s))
    assert _table("not a or b", names) != _table("not (a or b)", names)


# ===========================================================================
# Negation over the aggregation quantifiers
# ===========================================================================

def test_not_one_of_them() -> None:
    """``not 1 of them`` fires IFF NO selection matched (negation of the OR-of-all)."""
    names = ("a", "b")
    assert _table("not 1 of them", names) == _expected(names, lambda s: not bool(s))
    rule = _rule("not 1 of them", names)
    assert rule_matches_event(rule, _event(frozenset(), names)) is True        # none -> fires
    assert rule_matches_event(rule, _event(frozenset({"a"}), names)) is False  # one  -> suppressed
    assert rule_matches_event(rule, _event(frozenset({"a", "b"}), names)) is False


def test_not_all_of_them() -> None:
    """``not all of them`` fires UNLESS every selection matched (negation of the AND-of-all)."""
    names = ("a", "b")
    assert _table("not all of them", names) == _expected(
        names, lambda s: not (("a" in s) and ("b" in s)))


def test_not_all_of_prefix_glob() -> None:
    """``not all of selection*`` negates ``all of <prefix>*`` and is SCOPED to the prefix:
    the unrelated ``other`` selection must not affect it."""
    names = ("selection1", "selection2", "other")
    assert _table("not all of selection*", names) == _expected(
        names, lambda s: not (("selection1" in s) and ("selection2" in s)))
    rule = _rule("not all of selection*", names)
    # both selection* present -> all-of True -> negated to NO match (even if 'other' varies)
    assert rule_matches_event(rule, _event(frozenset({"selection1", "selection2"}), names)) is False
    assert rule_matches_event(
        rule, _event(frozenset({"selection1", "selection2", "other"}), names)) is False
    # one selection* missing -> all-of False -> negated to a match; 'other' alone cannot satisfy it
    assert rule_matches_event(rule, _event(frozenset({"selection1"}), names)) is True
    assert rule_matches_event(rule, _event(frozenset({"other"}), names)) is True


def test_not_one_of_prefix_glob() -> None:
    """``not 1 of selection*`` negates ``1 of <prefix>*`` and is SCOPED to the prefix:
    a matching ``other`` selection must not make it fire or suppress."""
    names = ("selection1", "selection2", "other")
    assert _table("not 1 of selection*", names) == _expected(
        names, lambda s: not (("selection1" in s) or ("selection2" in s)))
    rule = _rule("not 1 of selection*", names)
    # no selection* present -> 1-of False -> negated to a match (even with 'other' present)
    assert rule_matches_event(rule, _event(frozenset({"other"}), names)) is True
    assert rule_matches_event(rule, _event(frozenset(), names)) is True
    # any selection* present -> 1-of True -> negated to NO match
    assert rule_matches_event(rule, _event(frozenset({"selection1"}), names)) is False


def test_selection_and_not_aggregation_filter() -> None:
    """The real-world shape: ``selection and not 1 of filter_*`` — a positive detection with a
    negated group of exclusions. Fires only when ``selection`` matched and NO ``filter_*`` did."""
    names = ("selection", "filter_a", "filter_b")
    assert _table("selection and not 1 of filter_*", names) == _expected(
        names, lambda s: ("selection" in s) and not (("filter_a" in s) or ("filter_b" in s)))


# ===========================================================================
# Fail-closed: a lone / malformed negation must be REJECTED, never silently True
# ===========================================================================

def test_lone_not_fails_closed() -> None:
    """A bare ``not`` with no operand is malformed and must match NOTHING — never fire 'true'
    because the negation had nothing to negate. (Caught at evaluation; fail-closed -> no match.)"""
    names = ("a",)
    rule = _rule("not", names)
    # even on an event that satisfies the (only) selection, the malformed condition does not fire.
    assert rule_matches_event(rule, _event(frozenset({"a"}), names)) is False
    assert rule_matches_event(rule, _event(frozenset(), names)) is False


def test_malformed_negations_fail_closed() -> None:
    """A spread of malformed negations / conditions must all fail CLOSED (match nothing), rather
    than evaluate to a fabricated True. These are caught at evaluation time and yield no match."""
    names = ("a", "b")
    malformed = [
        "not",              # dangling negation
        "a and not",        # dangling negation after 'and'
        "not and a",        # 'not' with an operator as operand
        "not or b",         # ditto for 'or'
        "not of",           # 'of' is not an operand
        "not 1 of",         # aggregation with no target
        "not all of",       # aggregation with no target
        "not ( a",          # unbalanced parenthesis under 'not'
        "not ( )",          # empty parentheses under 'not'
        "a not b",          # two atoms with no operator (bare 'not' misplaced)
    ]
    for cond in malformed:
        rule = _rule(cond, names)
        # Drive BOTH selections True: a "silently true" bug would surface as a spurious match here.
        for active in (frozenset(), frozenset({"a"}), frozenset({"a", "b"})):
            assert rule_matches_event(rule, _event(active, names)) is False, cond


def test_negated_empty_prefix_glob_fails_closed() -> None:
    """Regression for a genuine fail-OPEN bug in the walker: ``not 1 of <prefix>*`` where the
    prefix matches NONE of the rule's own selections.

    ``1 of typo*`` over an empty candidate set is False (no match) — correct and fail-closed. But
    the old code produced that False via ``if not picked: return False``, so under a ``not`` it
    inverted to ``not False == True`` and the rule fired on EVERY event — fabricating a detection,
    the exact outcome this fail-closed module forbids. The fix treats an aggregation whose prefix
    references nothing as MALFORMED, so BOTH forms match nothing."""
    names = ("selection1", "selection2")
    for cond in ("not 1 of typo*", "not all of typo*", "1 of typo*", "all of typo*"):
        rule = _rule(cond, names)
        for size in range(len(names) + 1):
            for combo in itertools.combinations(names, size):
                active = frozenset(combo)
                assert rule_matches_event(rule, _event(active, names)) is False, (cond, active)
    # Control: the correctly-spelled prefix still negates normally (proves the fix is scoped to the
    # empty-candidate case and did not break real ``not <quant> of <prefix>*`` evaluation).
    good = _rule("not 1 of selection*", names)
    assert rule_matches_event(good, _event(frozenset(), names)) is True
    assert rule_matches_event(good, _event(frozenset({"selection1"}), names)) is False
