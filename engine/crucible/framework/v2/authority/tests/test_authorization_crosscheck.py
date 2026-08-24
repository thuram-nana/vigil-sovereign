"""
W13-3 (#496) — the three legs of an engagement's authorization must agree.

The authorization letter (contract), charter.md (runtime), and the signed
EngagementAuthorization (technical) are cross-checked against each other so
scope cannot drift between what the customer signed, what the runtime
enforces, and what the technical object carries.

Fail-without-fix: imports ``..crosscheck`` at module scope (absent on a tree
without W13-3 → collection error).

Negative controls: a signed object that adds a host the other two legs lack,
and a letter that drops a host, are each detected as drift (ScopeDrift raised).

The cross-check covers BOTH halves of the authorization: the in-scope host set
(scope) AND the enforcement envelope (danger ceiling, validity window, rate,
concurrency). The envelope negative controls include the exact red-pen case —
a letter declaring ceiling A1 while the signed object carries A3 is drift.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ...common.errors import EnvelopeDrift, ScopeDrift
from ..authorization import EngagementAuthorization
from ..crosscheck import (
    assert_envelope_consistent,
    assert_scope_consistent,
    crosscheck_envelope,
    crosscheck_scope,
    parse_envelope_declaration,
    parse_scope_table,
)

_TEMPLATES = (
    Path(__file__).resolve().parents[4] / "framework" / "templates"
)

_LETTER = """\
# Engagement authorization letter — acme

## 2. In-scope systems

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
| `acme.example` | Primary web app | Yes |
| `*.acme.example` | Subdomains | Yes |
| `api.acme.example` | API | Yes |

## 3. Enforcement envelope
(elided)
"""

_CHARTER = """\
# Engagement charter — acme

## 2. In-scope systems

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
| `acme.example` | Primary web app | Yes |
| `*.acme.example` | Subdomains | Yes |
| `api.acme.example` | API | Yes |

## 3. Out of scope
(elided)
"""

_SIGNED_SCOPE = ["acme.example", "*.acme.example", "api.acme.example"]


# ---------------------------------------------------------------------------
# The letter and the charter use the SAME table format, parsed the same way
# ---------------------------------------------------------------------------


def test_parse_scope_table_reads_the_host_column() -> None:
    assert parse_scope_table(_LETTER) == ["acme.example", "*.acme.example", "api.acme.example"]


def test_parse_scope_table_absent_header_is_empty() -> None:
    assert parse_scope_table("# no scope table here\n") == []


def test_letter_and_charter_scope_tables_agree() -> None:
    assert parse_scope_table(_LETTER) == parse_scope_table(_CHARTER)


# ---------------------------------------------------------------------------
# All three legs agree
# ---------------------------------------------------------------------------


def test_all_three_legs_agree() -> None:
    result = crosscheck_scope(
        letter=parse_scope_table(_LETTER),
        charter=parse_scope_table(_CHARTER),
        authorization=_SIGNED_SCOPE,
    )
    assert result.agree is True
    assert result.letter == result.charter == result.authorization
    # assert_scope_consistent returns rather than raises when they agree
    assert assert_scope_consistent(
        letter=parse_scope_table(_LETTER),
        charter=parse_scope_table(_CHARTER),
        authorization=_SIGNED_SCOPE,
    ).agree is True


# ---------------------------------------------------------------------------
# NEGATIVE CONTROL — the signed object adds a host the other two legs lack
# ---------------------------------------------------------------------------


def test_negative_control_signed_object_adds_a_host_is_drift() -> None:
    drifted = [*_SIGNED_SCOPE, "evil.example"]
    result = crosscheck_scope(
        letter=parse_scope_table(_LETTER),
        charter=parse_scope_table(_CHARTER),
        authorization=drifted,
    )
    assert result.agree is False
    assert "evil.example" in result.divergences
    # missing from BOTH the letter and the charter
    assert set(result.divergences["evil.example"]) == {"letter", "charter"}
    with pytest.raises(ScopeDrift):
        assert_scope_consistent(
            letter=parse_scope_table(_LETTER),
            charter=parse_scope_table(_CHARTER),
            authorization=drifted,
        )


def test_negative_control_letter_drops_a_host_is_drift() -> None:
    thin_letter = _LETTER.replace("| `api.acme.example` | API | Yes |\n", "")
    result = crosscheck_scope(
        letter=parse_scope_table(thin_letter),
        charter=parse_scope_table(_CHARTER),
        authorization=_SIGNED_SCOPE,
    )
    assert result.agree is False
    assert "api.acme.example" in result.divergences
    assert result.divergences["api.acme.example"] == ["letter"]


def test_crosscheck_is_not_a_no_op_empty_leg_fails_closed() -> None:
    # An empty leg must fail closed, not vacuously "agree" with another empty leg.
    result = crosscheck_scope(letter=[], charter=[], authorization=[])
    assert result.agree is False
    assert "empty scope" in result.reason


def test_normalization_ignores_case_and_backticks_but_not_identity() -> None:
    # Case/backtick differences are NOT drift; a genuinely different host IS.
    agree = crosscheck_scope(
        letter=["`ACME.example`"],
        charter=["acme.example"],
        authorization=["acme.example"],
    )
    assert agree.agree is True
    drift = crosscheck_scope(
        letter=["acme.example"],
        charter=["acme.example"],
        authorization=["other.example"],
    )
    assert drift.agree is False


# ---------------------------------------------------------------------------
# The shipped templates carry the same canonical scope-table header, so the
# two documents' formats cannot structurally drift.
# ---------------------------------------------------------------------------


def test_shipped_templates_share_the_scope_table_header() -> None:
    charter = (_TEMPLATES / "charter.md").read_text(encoding="utf-8")
    letter = (_TEMPLATES / "authorization-letter.md").read_text(encoding="utf-8")
    header = "## 2. In-scope systems"
    assert header in charter, "charter template lost its scope-table header"
    assert header in letter, "authorization-letter template lost its scope-table header"
    # Both parse to a non-empty host column (the template placeholders).
    assert parse_scope_table(charter), "charter template scope table did not parse"
    assert parse_scope_table(letter), "letter template scope table did not parse"


# ===========================================================================
# The ENVELOPE half — the letter's declared ceiling/window/rate/concurrency
# must match the signed EngagementAuthorization.
# ===========================================================================

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
_NB = _NOW - timedelta(hours=1)
_NA = _NOW + timedelta(hours=1)


def _authz(**overrides: object) -> EngagementAuthorization:
    base: dict[str, object] = dict(
        authorization_id="auth-1",
        engagement_slug="eng",
        issuer="governance",
        scope=["acme.example"],
        danger_ceiling="A1",
        not_before=_NB,
        not_after=_NA,
        rate_limit=100,
        rate_window_seconds=60.0,
        concurrency_limit=4,
        issued_at=_NB,
    )
    base.update(overrides)
    return EngagementAuthorization(**base)  # type: ignore[arg-type]


def _letter_envelope(
    *,
    ceiling: str = "A1",
    not_before: datetime = _NB,
    not_after: datetime = _NA,
    rate_limit: int = 100,
    rate_window_seconds: str = "60",
    concurrency_limit: int = 4,
) -> str:
    return (
        "# letter\n\n## 3. Enforcement envelope\n\n"
        "<!-- ENVELOPE:BEGIN -->\n"
        f"    danger_ceiling: {ceiling}\n"
        f"    not_before: {not_before.isoformat()}\n"
        f"    not_after: {not_after.isoformat()}\n"
        f"    rate_limit: {rate_limit}\n"
        f"    rate_window_seconds: {rate_window_seconds}\n"
        f"    concurrency_limit: {concurrency_limit}\n"
        "<!-- ENVELOPE:END -->\n"
    )


def test_parse_envelope_declaration_reads_the_block() -> None:
    env = parse_envelope_declaration(_letter_envelope())
    assert env is not None
    assert set(env) == {
        "danger_ceiling",
        "not_before",
        "not_after",
        "rate_limit",
        "rate_window_seconds",
        "concurrency_limit",
    }
    assert env["danger_ceiling"] == "A1"


def test_parse_envelope_declaration_absent_block_is_none() -> None:
    assert parse_envelope_declaration("# letter with no envelope block\n") is None


def test_matching_envelope_agrees() -> None:
    env = parse_envelope_declaration(_letter_envelope())
    result = crosscheck_envelope(letter=env, authorization=_authz())
    assert result.agree is True
    assert not result.mismatches
    # assert_envelope_consistent returns rather than raises when they agree
    assert assert_envelope_consistent(letter=env, authorization=_authz()).agree is True


def test_negative_control_letter_ceiling_A1_signed_A3_is_drift() -> None:
    # The exact red-pen case: the customer signs a tight A1 ceiling while the
    # signed object the executor honours carries a looser A3.
    env = parse_envelope_declaration(_letter_envelope(ceiling="A1"))
    authz = _authz(danger_ceiling="A3")
    result = crosscheck_envelope(letter=env, authorization=authz)
    assert result.agree is False
    assert result.mismatches["danger_ceiling"] == ("A1", "A3")
    with pytest.raises(EnvelopeDrift):
        assert_envelope_consistent(letter=env, authorization=authz)


def test_envelope_ceiling_gate_is_not_a_no_op() -> None:
    # Same A1 letter: agrees with an A1 signed object, drifts from an A3 one.
    env = parse_envelope_declaration(_letter_envelope(ceiling="A1"))
    assert crosscheck_envelope(letter=env, authorization=_authz(danger_ceiling="A1")).agree is True
    assert crosscheck_envelope(letter=env, authorization=_authz(danger_ceiling="A3")).agree is False


def test_negative_control_rate_limit_drift() -> None:
    env = parse_envelope_declaration(_letter_envelope(rate_limit=10))
    result = crosscheck_envelope(letter=env, authorization=_authz(rate_limit=100))
    assert result.agree is False
    assert result.mismatches["rate_limit"] == ("10", "100")


def test_negative_control_concurrency_drift() -> None:
    env = parse_envelope_declaration(_letter_envelope(concurrency_limit=1))
    result = crosscheck_envelope(letter=env, authorization=_authz(concurrency_limit=4))
    assert result.agree is False
    assert "concurrency_limit" in result.mismatches


def test_negative_control_window_drift() -> None:
    env = parse_envelope_declaration(_letter_envelope(not_after=_NA + timedelta(days=30)))
    result = crosscheck_envelope(letter=env, authorization=_authz())
    assert result.agree is False
    assert "not_after" in result.mismatches


def test_negative_control_missing_envelope_block_fails_closed() -> None:
    # A letter with no ENVELOPE block cannot vacuously agree with any signed object.
    result = crosscheck_envelope(letter=None, authorization=_authz())
    assert result.agree is False
    assert "no machine-checked ENVELOPE" in result.reason
    with pytest.raises(EnvelopeDrift):
        assert_envelope_consistent(letter=None, authorization=_authz())


def test_negative_control_unparseable_placeholder_is_drift() -> None:
    # The shipped TEMPLATE's placeholder values must not be mistaken for a match.
    letter = (_TEMPLATES / "authorization-letter.md").read_text(encoding="utf-8")
    env = parse_envelope_declaration(letter)
    assert env is not None, "letter template lost its ENVELOPE block"
    result = crosscheck_envelope(letter=env, authorization=_authz())
    assert result.agree is False  # placeholders like `<A0 | A1 | A2 | A3>` do not parse


def test_rate_window_seconds_int_and_float_forms_agree() -> None:
    # The letter may write "60" or "60.0"; both equal the signed 60.0.
    for form in ("60", "60.0"):
        env = parse_envelope_declaration(_letter_envelope(rate_window_seconds=form))
        assert crosscheck_envelope(letter=env, authorization=_authz()).agree is True


def test_shipped_letter_template_carries_the_envelope_block() -> None:
    letter = (_TEMPLATES / "authorization-letter.md").read_text(encoding="utf-8")
    assert "<!-- ENVELOPE:BEGIN -->" in letter
    assert "<!-- ENVELOPE:END -->" in letter
    env = parse_envelope_declaration(letter)
    assert env is not None and "danger_ceiling" in env
