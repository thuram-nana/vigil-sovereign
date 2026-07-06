"""
The error-signature oracle — confirms error-based injection when a payload
provokes a distinctive datastore/parser error that a benign control does not. The
error-based analogue of the sanitizer oracle: a real backend error is strong,
attributable evidence the input reached and broke the query parser.
"""

from __future__ import annotations

import pytest

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import error_signature_oracle
from framework.v2.verify.verifier import OracleVerifier
from framework.v2.verify.adapter import FindingContext

_MYSQL = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
_ORACLE = "java.sql.SQLException: ORA-00933: SQL command not properly ended"
_MSSQL = "Unclosed quotation mark after the character string ''."
_PG = "PostgreSQL query failed: ERROR: unterminated quoted string at or near \"'\""
_SQLITE = "sqlite3.OperationalError: unrecognized token: \"'\""


@pytest.mark.parametrize("body", [_MYSQL, _ORACLE, _MSSQL, _PG, _SQLITE])
def test_fires_on_known_dbms_error(body: str) -> None:
    sig = error_signature_oracle(f"<html>{body}</html>")
    assert sig.fired and sig.kind is OracleKind.ERROR_SIGNATURE and sig.confidence >= 0.8


def test_does_not_fire_on_clean_response() -> None:
    assert not error_signature_oracle("<html>results: 3 rows</html>").fired


def test_does_not_fire_when_error_also_in_control() -> None:
    # a page that ALWAYS shows this error is not attributable to the payload
    body = f"<html>{_MYSQL}</html>"
    assert not error_signature_oracle(body, control_body=body).fired


def test_generic_error_word_is_not_enough() -> None:
    assert not error_signature_oracle("<html>An error occurred. Please try again.</html>").fired


def test_routes_error_based_sqli_to_error_signature_first() -> None:
    assert OracleVerifier().oracles_for("error_based_sqli")[0] is OracleKind.ERROR_SIGNATURE
    ctx = FindingContext.from_error_signature(f"x {_ORACLE} y", control_body="x clean y")
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert result.confirmed
    assert any(s.kind is OracleKind.ERROR_SIGNATURE and s.fired for s in result.signals)


def test_certificate_round_trips() -> None:
    ctx = FindingContext.from_error_signature(f"boom {_MSSQL}")
    rebuilt = FindingContext.model_validate(ctx.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed
