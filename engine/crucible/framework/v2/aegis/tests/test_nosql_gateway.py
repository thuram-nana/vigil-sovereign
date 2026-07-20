"""
Wave-G2 — the NoSQL operator-injection break-out block, seen through the AEGIS request inspector.

Proves the gateway BLOCKS a proven MongoDB operator-injection attempt (with a re-runnable certificate)
across every request surface it inspects — the bracket/dot query param, a JSON-object param value, and a
JSON BODY whose operator value is non-string — while a benign request (a price, an EJSON/JSON-Schema
body, an operator named as a data value) is forwarded untouched.
"""

from __future__ import annotations

import urllib.parse

from framework.v2.aegis.inspect import inspect_request


def _req(path="/", headers=None, body=None):
    # enforce=True so a confirmed verdict's action is `block` (the request-inspection unit view).
    return inspect_request("GET", path, headers or [], body, enforce=True)


_JSON = [("Content-Type", "application/json")]


def _q(path, value):
    return "/x?" + path + "=" + urllib.parse.quote(value, safe="")


# --------------------------------------------------------------------------- confirmed blocks

def test_bracket_param_operator_is_blocked_with_certificate():
    v = _req(path="/login?user%5B%24ne%5D=1")   # user[$ne]=1, percent-encoded
    assert v is not None and v.decision == "confirmed" and v.attack_class == "nosql_injection_attempt"
    assert v.certificate is not None and v.certificate.reverify() is True
    assert v.contributing == ["user[$ne]"]


def test_gt_query_param_is_blocked():
    v = _req(path="/s?q%5B%24gt%5D=0")          # q[$gt]=0
    assert v is not None and v.attack_class == "nosql_injection_attempt"
    assert v.contributing == ["q[$gt]"]


def test_value_as_json_blob_is_blocked():
    v = _req(path=_q("username", '{"$ne":null}'))
    assert v is not None and v.attack_class == "nosql_injection_attempt"
    assert v.certificate is not None and v.certificate.reverify() is True
    assert v.contributing == ["username"]


def test_json_body_nonstring_leaf_is_blocked_via_body_scan():
    # {"user":{"$ne":null}} — the operator value is null, so the string-leaf candidate walk cannot
    # surface it; the whole-body scan (step 2b) catches it.
    v = _req(path="/login", headers=_JSON, body='{"user":{"$ne":null}}')
    assert v is not None and v.attack_class == "nosql_injection_attempt"
    assert v.certificate is not None and v.certificate.reverify() is True
    assert v.contributing == ["body"]


def test_json_body_array_operator_is_blocked():
    v = _req(path="/login", headers=_JSON, body='{"user":{"$in":[1,2,3]}}')
    assert v is not None and v.attack_class == "nosql_injection_attempt"


def test_json_body_string_leaf_operator_is_blocked_via_body_scan():
    # {"user":{"$ne":"admin"}} — the string leaf flattens to candidate `user.$ne`, but PATH 1 is now
    # BRACKET-only (a dotted param no longer fires — that killed the {"a":{"b.$ne":1}} flatten FP), so the
    # block comes from the whole-body scan (step 2b), which reads the ACTUAL parsed `$ne` key.
    v = _req(path="/login", headers=_JSON, body='{"user":{"$ne":"admin"}}')
    assert v is not None and v.attack_class == "nosql_injection_attempt"
    assert v.contributing == ["body"]


def test_json_body_with_literal_dotted_key_is_forwarded_not_blocked():
    # REGRESSION (review flatten FP): a benign body whose LITERAL key contains a '.$op' segment
    # ({"a":{"b.$ne":"hello"}}) flattens to candidate `a.b.$ne`; the bracket-only PATH 1 must NOT fire,
    # and the whole-body scan sees the real key `b.$ne` (not `$ne`) → forwarded, never blocked.
    v = _req(path="/save", headers=_JSON, body='{"a":{"b.$ne":"hello"}}')
    assert v is None or v.attack_class != "nosql_injection_attempt"


def test_legacy_ejson_regex_and_dotnet_type_bodies_are_forwarded():
    # REGRESSION: $regex (legacy-EJSON regex / regex-search) and $type (.NET type-discriminator) are
    # dual-use and were dropped from the block allowlist — benign bodies carrying them must forward.
    for body in ('{"savedSearch":{"$regex":"^admin","$options":"i"}}',
                 '{"$type":"MyApp.User, MyApp"}'):
        v = _req(path="/save", headers=_JSON, body=body)
        assert v is None or v.attack_class != "nosql_injection_attempt", body


# --------------------------------------------------------------------------- near-zero-FP: forwarded

def test_benign_query_is_forwarded():
    assert _req(path="/s?q=hello&page=2") is None


def test_price_value_is_not_blocked():
    assert _req(path=_q("amount", "$5.00")) is None


def test_benign_json_body_is_not_blocked():
    assert _req(path="/u", headers=_JSON, body='{"user":{"name":"bob"},"age":5}') is None


def test_ejson_and_schema_bodies_are_not_blocked():
    # legitimate `$`-keys that are NOT query operators (EJSON type wrappers, JSON-Schema meta) must pass.
    assert _req(path="/u", headers=_JSON, body='{"_id":{"$oid":"507f1f77bcf86cd799439011"}}') is None
    assert _req(path="/u", headers=_JSON, body='{"created":{"$date":"2020-01-01T00:00:00Z"}}') is None
    assert _req(path="/u", headers=_JSON, body='{"$schema":"http://json-schema.org/draft-07/schema#"}') is None


def test_operator_as_data_value_is_not_blocked():
    # an operator token as a string VALUE / list element is ordinary data, not query structure.
    assert _req(path="/u", headers=_JSON, body='{"tags":["$ne","$gt"]}') is None
    assert _req(path="/u", headers=_JSON, body='{"note":"use $ne to negate"}') is None


def test_unknown_dollar_key_body_is_not_blocked():
    assert _req(path="/u", headers=_JSON, body='{"user":{"$custom":1}}') is None
