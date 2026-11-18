"""The parser-state-toggle oracle — confirms a datastore QUERY BREAK (nosqli / ldap_injection /
xpath_injection) by a BREAK-vs-REPAIR toggle re-executed OFFLINE over three retained legs + payloads.

A fire requires ALL of: the break and balanced payloads carry the SAME non-empty metacharacter SET and the
control none (re-derived from the retained payloads); a genuine parser-break MESSAGE on the UNBALANCED break
leg (never a bare package name); NO such message on the re-balanced leg nor the benign control; and the break
leg is not a block/rejection. The binding same-shape negative is the metacharacter-PRESENCE filter — a benign
source of the SAME three-leg shape that errors on BOTH break and balanced — which must NOT fire.
"""
from __future__ import annotations

import pytest

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import parser_state_toggle_oracle
from framework.v2.verify.oracle_version import _ORACLE_FNS, oracle_version
from framework.v2.verify import oracles
from framework.v2.verify.verifier import OracleVerifier

# Genuine datastore parser-break MESSAGES (never a bare package name).
_BREAK_ERR = {
    "mongodb": "Server error: FailedToParse: Expecting '}' or ',' but found end of input",
    "ldap": "org.example: LDAP: error code 87 - Bad search filter near the injected term",
    "xpath": "XPathException: Invalid XPath expression: unexpected token at column 23",
}
# A clean, metacharacter-free render.
_CLEAN = '{"results": [{"id": 1}], "rows": 3}'
# (break, balanced) payloads that carry the SAME metacharacter SET (break UNBALANCED, balanced RE-BALANCED).
_PAYLOADS = {
    "mongodb": ("'\"{}", "''\"\"{}"),
    "ldap": ("*)(|", "*)(|(cn=a)(sn=b)"),
    "xpath": ("'] | //*[", "'] | //*[1] | //x[name='"),
}
_CONTROL = "vfctl0a1b2c3d"


def _leg(body, status=200):
    return {"body": body, "status": status}


def _toggle(engine, *, break_body, balanced_body, control_body,
            break_payload=None, balanced_payload=None, control_payload=_CONTROL,
            break_status=200):
    brk, bal = _PAYLOADS[engine]
    return {
        "engine": engine,
        "break": _leg(break_body, break_status),
        "balanced": _leg(balanced_body),
        "control": _leg(control_body),
        "break_payload": brk if break_payload is None else break_payload,
        "balanced_payload": bal if balanced_payload is None else balanced_payload,
        "control_payload": control_payload,
    }


# --- the FACT (one per grammar) ---------------------------------------------------------------------

@pytest.mark.parametrize("engine", ["mongodb", "ldap", "xpath"])
def test_a_genuine_query_break_fires(engine):
    sig = parser_state_toggle_oracle(_toggle(
        engine, break_body=_BREAK_ERR[engine], balanced_body=_CLEAN, control_body=_CLEAN))
    assert sig.fired, sig.evidence
    assert sig.observed.get("engine") == engine
    assert sig.confidence >= 0.7
    assert sig.conclusive is True   # a fire is always a decisive positive


def test_the_oracle_reuses_the_error_signature_kind_without_drifting_its_version():
    """REUSE (no drift), like smuggling_desync reuses DIFFERENTIAL_RESPONSE: the signal is the FROZEN
    ERROR_SIGNATURE kind, and parser_state_toggle_oracle is NOT in that kind's version closure, so
    oracle_version(ERROR_SIGNATURE) — which the SQL error_signature certificates bind — is untouched."""
    sig = parser_state_toggle_oracle(_toggle(
        "mongodb", break_body=_BREAK_ERR["mongodb"], balanced_body=_CLEAN, control_body=_CLEAN))
    assert sig.kind is OracleKind.ERROR_SIGNATURE
    fns = _ORACLE_FNS[OracleKind.ERROR_SIGNATURE]
    assert oracles.error_signature_oracle in fns
    assert oracles.parser_state_toggle_oracle not in fns, (
        "parser_state_toggle_oracle must NOT be in the ERROR_SIGNATURE version closure (SQL certs bind it)")
    assert oracle_version(OracleKind.ERROR_SIGNATURE).startswith("sha256:")


# --- the BINDING same-shape negative: a metacharacter-PRESENCE filter (errors on break AND balanced) ---

@pytest.mark.parametrize("engine", ["mongodb", "ldap", "xpath"])
def test_a_metacharacter_presence_filter_does_not_fire(engine):
    """The adversary the toggle exists to defeat: a benign source of the SAME three-leg shape that reacts to
    metacharacter PRESENCE errors on BOTH the break and the (same-metacharacter-set) balanced leg — so the
    toggle must NOT fire. This is the same-shape negative control, and it exercises the adversarial shape."""
    sig = parser_state_toggle_oracle(_toggle(
        engine, break_body=_BREAK_ERR[engine], balanced_body=_BREAK_ERR[engine], control_body=_CLEAN))
    assert not sig.fired
    assert sig.conclusive is False   # a non-fire is INCONCLUSIVE, never CLEAN
    assert "BALANCED" in sig.evidence


@pytest.mark.parametrize("engine", ["mongodb", "ldap", "xpath"])
def test_a_static_error_banner_does_not_fire(engine):
    sig = parser_state_toggle_oracle(_toggle(
        engine, break_body=_BREAK_ERR[engine], balanced_body=_BREAK_ERR[engine], control_body=_BREAK_ERR[engine]))
    assert not sig.fired


def test_a_block_response_status_is_refused_before_the_toggle():
    # A 4xx access/validation status is a WAF/validator answer, refused by STATUS even when the body also
    # echoes a parser-break phrase — so the status guard is load-bearing (removing it would mint on a 403).
    sig = parser_state_toggle_oracle(_toggle(
        "mongodb", break_body="403 upstream: FailedToParse appeared while rejecting the input",
        balanced_body=_CLEAN, control_body=_CLEAN, break_status=403))
    assert not sig.fired
    assert "block" in sig.evidence.lower()


def test_block_wording_on_a_200_break_leg_is_refused_before_the_toggle():
    # Block WORDING on a 200 is refused too — load-bearing even when the body carries a genuine parser phrase.
    sig = parser_state_toggle_oracle(_toggle(
        "mongodb", break_body="Request blocked by the web application firewall: FailedToParse detected",
        balanced_body=_CLEAN, control_body=_CLEAN))
    assert not sig.fired
    assert "block" in sig.evidence.lower()


@pytest.mark.parametrize("bare", [
    "500 Internal Server Error\n at com.mongodb.client.MongoClientDelegate.<init>(MongoClientDelegate.java:10)",
    "javax.naming.directory.InitialDirContext failure",
    "System.Xml MS.Internal.Xml handler threw",
])
def test_a_bare_package_name_on_the_break_leg_is_not_a_query_break(bare):
    """A bare driver/package/class name names a SUBSYSTEM, not a query break — it is deliberately NOT a
    parser-break signature, so a 500 whose stack trace merely names the driver does not fire."""
    sig = parser_state_toggle_oracle(_toggle(
        "mongodb", break_body=bare, balanced_body=_CLEAN, control_body=_CLEAN))
    assert not sig.fired


def test_a_balanced_payload_with_a_different_metacharacter_set_is_refused():
    """The same-metacharacter-SET guard, re-derived OFFLINE from the retained payloads: if the balanced
    payload does not carry the SAME metacharacter set as the break, a break-only error is not attributable to
    query balance (the balanced leg's cleanliness could be due to it carrying FEWER/other metacharacters)."""
    sig = parser_state_toggle_oracle(_toggle(
        "mongodb", break_body=_BREAK_ERR["mongodb"], balanced_body=_CLEAN, control_body=_CLEAN,
        balanced_payload="harmless"))
    assert not sig.fired
    assert "metacharacter set" in sig.evidence


def test_a_control_payload_carrying_metacharacters_is_refused():
    sig = parser_state_toggle_oracle(_toggle(
        "mongodb", break_body=_BREAK_ERR["mongodb"], balanced_body=_CLEAN, control_body=_CLEAN,
        control_payload="x'{}"))
    assert not sig.fired


def test_an_error_on_the_benign_control_is_unconditional_not_attributable():
    sig = parser_state_toggle_oracle(_toggle(
        "mongodb", break_body=_BREAK_ERR["mongodb"], balanced_body=_CLEAN, control_body=_BREAK_ERR["mongodb"]))
    assert not sig.fired
    assert "CONTROL" in sig.evidence


def test_a_sql_error_under_a_mongodb_claim_does_not_fire():
    """Attribution: a SQL error provoked under a nosqli probe is SQLi, not nosqli — this oracle carries no SQL
    parser-break signatures, so it does not fire (the arm then keeps the finding class-appropriate)."""
    sig = parser_state_toggle_oracle(_toggle(
        "mongodb", break_body="You have an error in your SQL syntax near '''", balanced_body=_CLEAN,
        control_body=_CLEAN))
    assert not sig.fired


def test_a_missing_leg_is_inconclusive():
    t = _toggle("mongodb", break_body=_BREAK_ERR["mongodb"], balanced_body=_CLEAN, control_body=_CLEAN)
    del t["balanced"]
    sig = parser_state_toggle_oracle(t)
    assert not sig.fired and sig.conclusive is False


def test_an_empty_break_body_is_inconclusive():
    sig = parser_state_toggle_oracle(_toggle(
        "mongodb", break_body="", balanced_body=_CLEAN, control_body=_CLEAN))
    assert not sig.fired and sig.conclusive is False


# --- the verifier re-fires the FROZEN context OFFLINE, and the SQL error_signature path is untouched ------

@pytest.mark.parametrize("bug_class,engine", [
    ("nosqli", "mongodb"), ("ldap_injection", "ldap"), ("xpath_injection", "xpath")])
def test_confirm_re_fires_the_toggle_over_the_retained_context(bug_class, engine):
    ctx = {"bug_class": bug_class,
           "parser_state_toggle": _toggle(engine, break_body=_BREAK_ERR[engine],
                                          balanced_body=_CLEAN, control_body=_CLEAN)}
    result = OracleVerifier().confirm(ctx)
    assert result.confirmed
    assert any(s.kind is OracleKind.ERROR_SIGNATURE and s.fired for s in result.signals)


def test_the_error_observed_path_is_unchanged_for_sql():
    """The existing error_signature re-fire path (error_observed) is byte-identical — a context with no
    parser_state_toggle key routes to error_signature_oracle exactly as before."""
    ctx = {"bug_class": "error_based_sqli",
           "error_observed": "You have an error in your SQL syntax; check the manual", "error_control": "ok"}
    assert OracleVerifier().confirm(ctx).confirmed
