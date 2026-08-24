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
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ...common.errors import ScopeDrift
from ..crosscheck import (
    assert_scope_consistent,
    crosscheck_scope,
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
