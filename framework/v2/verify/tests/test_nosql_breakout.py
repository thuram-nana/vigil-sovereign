"""
Wave-G2 AEGIS request-side PARSE-PROOF oracle — nosql_injection_breakout.

The request-side sibling of sql/command breakout: it judges a decoded request value AND its parameter
NAME on the REQUEST ALONE and fires ONLY on a deterministic parse-proof that a MongoDB QUERY OPERATOR
was injected as a KEY where a scalar was expected (`user[$ne]=1`, `{"$ne":null}`, `q[$gt]=0`, `$where`).
The two properties that matter for a firewall:

  * PROVEN operator-injection ATTEMPTS fire (so the gateway can block them with a re-runnable
    certificate), AND
  * benign inputs that merely CONTAIN a `$`, a price, an EJSON/JSON-Schema `$`-key, an operator named
    as a data VALUE, or a `$` mid-word do NOT fire (near-zero false positives — a false block breaks a
    real user, the cardinal sin of a provable firewall).

Plus: the class is an oracle-vocabulary member (KnownBugClass-valid), the full confirm path works, the
certificate re-verifies offline, and the new OracleKind member stays OUT of the frozen _ALL_ORACLES
fallback so `make gate` is byte-identical.
"""

from __future__ import annotations

import pytest

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import nosql_injection_breakout_oracle
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES, known_bug_classes, require_known_bug_class

# --------------------------------------------------------------------------- fires (proven attempts)

# (param_name, value). The operator-as-key structure is proven EITHER by the bracket/dot param NAME OR
# by a JSON-object VALUE. All classic, all near-zero-benign.
_NOSQL_ATTACKS = [
    ("user[$ne]", "1"),                     # bracket-nested operator key (qs/PHP/Express -> {user:{$ne:..}})
    ("q[$gt]", "0"),
    ("filter[$where]", "sleep(1000)"),
    ("a[b][$in]", "1"),                     # deeply-nested bracket path (an unambiguous operator)
    ("filter[$nin]", "x"),                  # bracket path (replaces the dropped dot-notation form)
    ("$where", "this.a==this.b"),           # a bare top-level operator key
    ("username", '{"$ne": null}'),          # the classic value-as-JSON auth-bypass blob
    ("password", '{"$gt": ""}'),
    ("search", '{"$where": "1"}'),
    ("q", '{"age": {"$gt": 18}}'),          # operator nested inside a JSON value
    ("ids", '{"$in": [1, 2, 3]}'),
    ("cond", '{"$or": [{"a": 1}, {"b": 2}]}'),
]

# `$` in text, prices, operator-shaped names/regex/emails, EJSON / JSON-Schema / DBRef `$`-keys, and an
# operator named as a data VALUE are ubiquitous in ordinary input; NONE may fire (a false positive
# breaks a real user). These are exactly the shapes the near-zero-FP structure (KNOWN operator AS A KEY)
# is designed to leave inert.
_NOSQL_BENIGN = [
    ("amount", "$5.00"),                    # a price
    ("field", "$net"), ("code", "$ne"),     # a $-prefixed token as a VALUE (not a key)
    ("x", "ne"), ("username", "admin"),     # plain scalars
    ("user.name", "bob"), ("email", "a@b.com"),
    ("pattern", "^admin$"),                 # a regex-looking value ($ is an anchor)
    ("p", "pass$word"), ("field", "cost$negate"),  # a $ mid-word (not a delimited key segment)
    ("tags", '["$ne", "$gt"]'),             # operators as string list ELEMENTS (values, not keys)
    ("desc", '{"note": "use $ne to negate"}'),     # operator inside a string VALUE
    ("user", '{"name": "bob", "age": 5}'),  # a benign JSON object, no operator key
    ("_id", '{"$oid": "507f1f77bcf86cd799439011"}'),   # EJSON ObjectId wrapper (legit body content)
    ("created", '{"$date": "2020-01-01T00:00:00Z"}'),  # EJSON date wrapper
    ("n", '{"$numberLong": "42"}'),         # EJSON number wrapper
    ("meta", '{"$schema": "http://json-schema.org/draft-07/schema#"}'),  # JSON-Schema meta key
    ("ref", '{"$ref": "#/defs/User"}'),     # JSON-Schema / DBRef key
    # DUAL-USE $-keys deliberately dropped from the BLOCK allowlist (review FPs) — MUST stay inert:
    ("savedSearch", '{"$regex": "^admin", "$options": "i"}'),  # legacy-EJSON regex value / regex-search body
    ("rx", '{"$regex": "foo.*bar"}'),        # $regex as a body key (dual-use with EJSON v1 regex)
    ("obj", '{"$type": "MyApp.User, MyApp"}'),  # .NET/System.Text.Json polymorphic type-discriminator
    ("a", '{"b.$ne": "hello"}'),             # a LITERAL dotted key (the flatten edge) — not an operator key
    ("id", "12345"), ("q", "hello world"),  # plain scalars
    ("price", "$100 or $200"),              # prose with $ amounts
    ("json", "{not valid json $ne"),        # malformed -> no parse -> inert
]


@pytest.mark.parametrize("param,value", _NOSQL_ATTACKS)
def test_nosql_breakout_fires_on_proven_operator_injection(param: str, value: str):
    sig = nosql_injection_breakout_oracle(value, param=param)
    assert sig.fired and sig.confidence >= 0.7, f"missed a NoSQL operator injection: param={param!r} value={value!r}"
    assert sig.observed.get("break_out") is True
    assert str(sig.observed.get("operator", "")).startswith("$")
    assert sig.observed.get("vector") in {"operator_as_param_key", "operator_as_json_key"}


@pytest.mark.parametrize("param,value", _NOSQL_BENIGN)
def test_nosql_breakout_never_fires_on_benign(param: str, value: str):
    sig = nosql_injection_breakout_oracle(value, param=param)
    assert not sig.fired, f"FALSE POSITIVE on benign input: param={param!r} value={value!r} — would break a real user"


# --------------------------------------------------------------------------- edge cases

def test_unknown_dollar_key_does_not_fire():
    # a $-prefixed key that is NOT a KNOWN query operator (a custom/framework key) is not a proof.
    assert not nosql_injection_breakout_oracle("1", param="user[$custom]").fired
    assert not nosql_injection_breakout_oracle('{"$myField": 1}', param="x").fired
    # AngularJS-style internal keys / prefix-only tokens are inert too.
    assert not nosql_injection_breakout_oracle('{"$$hashKey": "01"}', param="x").fired


def test_gt_not_preempted_by_gte_and_vice_versa():
    # the longest-first alternation + key-segment lookahead keep prefix operators unambiguous.
    assert nosql_injection_breakout_oracle("0", param="q[$gt]").observed.get("operator") == "$gt"
    assert nosql_injection_breakout_oracle("0", param="q[$gte]").observed.get("operator") == "$gte"


def test_operator_must_be_a_whole_key_segment():
    # `$net`/`$negate` share a prefix with `$ne` but are NOT the operator as a delimited key.
    assert not nosql_injection_breakout_oracle("x", param="user[$negate]").fired
    assert not nosql_injection_breakout_oracle("x", param="a$netb").fired


def test_non_string_payload_is_coerced_not_crashed():
    # a non-str payload (e.g. an int/None) must be handled totally (no exception, no fire).
    assert not nosql_injection_breakout_oracle(5, param="q").fired
    assert not nosql_injection_breakout_oracle(None, param="q").fired


# --------------------------------------------------------------------------- integration + gate

def test_class_is_oracle_vocabulary_member():
    assert "nosql_injection_attempt" in known_bug_classes()
    assert require_known_bug_class("nosql_injection_attempt") == "nosql_injection_attempt"
    # spelling variants fold onto the canonical class.
    for alias in ("nosqli_attempt", "nosql_operator_injection", "mongodb_operator_injection"):
        assert require_known_bug_class(alias) == "nosql_injection_attempt"


def test_full_confirm_path_and_certificate_reverifies():
    """The gateway's path: build a FindingContext from the decoded value + param, confirm via the
    oracle, then the retained certificate RE-FIRES offline (prove-don't-guess)."""
    fc = FindingContext.from_request_payload("1", bug_class="nosql_injection_attempt", param="user[$ne]")
    confirmed = confirm_finding({"bug_class": "nosql_injection_attempt"}, context=fc)
    assert confirmed is not None
    assert confirmed.confirmed_by is OracleKind.NOSQL_INJECTION_BREAKOUT
    r = reverify_context(fc.to_verifier_context(), bug_class="nosql_injection_attempt",
                         claimed_confirmed_by="nosql_injection_breakout",
                         claimed_confidence=confirmed.confidence)
    assert r.ok, "the block certificate did not re-verify offline"


def test_json_value_blob_confirms_through_the_full_path():
    fc = FindingContext.from_request_payload('{"$ne": null}', bug_class="nosql_injection_attempt", param="username")
    confirmed = confirm_finding({"bug_class": "nosql_injection_attempt"}, context=fc)
    assert confirmed is not None and confirmed.confirmed_by is OracleKind.NOSQL_INJECTION_BREAKOUT


def test_benign_never_confirms_through_the_full_path():
    fc = FindingContext.from_request_payload("$5.00", bug_class="nosql_injection_attempt", param="amount")
    assert confirm_finding({"bug_class": "nosql_injection_attempt"}, context=fc) is None


def test_new_kind_excluded_from_frozen_fallback_gate_byte_identical():
    """The new OracleKind must NOT be in the frozen unknown-class fallback, so appending it cannot grow
    the oracle set any pre-existing/unknown class runs — `make gate` stays byte-identical."""
    assert OracleKind.NOSQL_INJECTION_BREAKOUT not in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15


def test_determinism_same_inputs_same_signal():
    a = nosql_injection_breakout_oracle("1", param="user[$ne]")
    b = nosql_injection_breakout_oracle("1", param="user[$ne]")
    assert (a.fired, a.confidence, a.evidence) == (b.fired, b.confidence, b.evidence)
