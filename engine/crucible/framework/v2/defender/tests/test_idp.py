"""AS-17c — the IdP (Okta System Log) NORMALIZER (``defender.logsource.parse_idp``) + the GATED
``detect_format`` branch.

Proven here (strict acceptance; mirrors the AS-17b CloudTrail normalizer tests):
  * NORMALIZE — a top-level Okta System Log array, a single-record object, a ``{"events":[...]}`` envelope,
    and NDJSON all flatten into ``idp`` ``LogEvent``s, keeping Okta's own dotted field names (incl.
    ``actor.alternateId`` / ``client.ipAddress`` / ``client.userAgent.rawUserAgent`` / ``outcome.result`` /
    ``target.*`` standard Okta Sigma references);
  * TOTAL / FAIL-CLOSED — a malformed blob / record / bad NDJSON line is skipped, never raised; a non-dict
    record is dropped; bounds hold;
  * DETERMINISM — re-parsing the same bytes yields identical events (input order preserved);
  * GATED SNIFF (the mutation-sensitive NEGATIVE CONTROL) — ``detect_format`` returns 'idp' ONLY on a positive
    Okta marker (a top-level array/object whose first record carries ``eventType`` + ``published`` + ``uuid``);
    EVERY non-IdP JSON input (a Windows evtx array/object, a CloudTrail delivery, an Okta-shaped record missing
    one marker field) keeps its v1 sniff byte-for-byte. Remove the marker gate (sniff 'idp' for any array) and
    these controls RED.
  * TIE TO AS-17a — a standard Okta Sigma rule fires on the normalized event (the ingest feeds the UNCHANGED
    Sigma runtime); a benign (successful) login does not trip a failed-login rule.
"""
from __future__ import annotations

import json

from framework.v2.defender.logsource import (
    detect_format,
    parse_cloudtrail,
    parse_evtx_json,
    parse_idp,
    parse_log,
)
from framework.v2.defender.sigma import default_field_map, evaluate_events, parse_sigma_rule

_EVENT = {
    "uuid": "a0000000-1111-2222-3333-444444444444",
    "published": "2024-05-01T12:00:00.000Z",
    "eventType": "user.session.start",
    "version": "0",
    "severity": "INFO",
    "displayMessage": "User login to Okta",
    "legacyEventType": "core.user_auth.login_success",
    "actor": {"id": "00uABCDEF", "type": "User", "alternateId": "alice@example.com", "displayName": "Alice Smith"},
    "client": {"ipAddress": "203.0.113.9", "device": "Computer", "zone": "DefaultZone", "id": "deadbeef",
               "userAgent": {"rawUserAgent": "Mozilla/5.0", "os": "Mac OS X", "browser": "CHROME"}},
    "outcome": {"result": "SUCCESS", "reason": "OK"},
    "authenticationContext": {"externalSessionId": "sess-1", "interface": "FastPass"},
    "securityContext": {"asNumber": 15169, "isp": "google", "domain": "example.com", "isProxy": False},
    "transaction": {"id": "tx-1", "type": "WEB"},
    "target": [{"id": "0oaAPP", "type": "AppInstance", "alternateId": "app-key", "displayName": "My App"}],
}


def _array(*events: dict) -> str:
    return json.dumps(list(events) or [_EVENT])


# --- NORMALIZE ------------------------------------------------------------------------------------
def test_array_flattens_salient_fields():
    evs = parse_idp(_array(_EVENT))
    assert len(evs) == 1
    e = evs[0]
    assert e.channel == "idp" and e.source_format == "idp"
    assert e.get("eventType") == "user.session.start"
    assert e.get("severity") == "INFO"
    assert e.get("displayMessage") == "User login to Okta"
    assert e.get("legacyEventType") == "core.user_auth.login_success"
    assert e.get("uuid") == "a0000000-1111-2222-3333-444444444444"
    # a JSON bool nested under securityContext -> "True"/"False" (Sigma match is case-insensitive)
    assert e.get("securityContext.isProxy") == "False"
    # a numeric value coerces to int exactly as every other parser (``_coerce`` reused verbatim)
    assert e.get("securityContext.asNumber") == 15169


def test_nested_hops_flattened_under_dotted_keys():
    e = parse_idp(_array(_EVENT))[0]
    assert e.get("actor.alternateId") == "alice@example.com"
    assert e.get("actor.displayName") == "Alice Smith"
    assert e.get("client.ipAddress") == "203.0.113.9"
    assert e.get("client.device") == "Computer"
    assert e.get("client.userAgent.rawUserAgent") == "Mozilla/5.0"
    assert e.get("client.userAgent.browser") == "CHROME"
    assert e.get("outcome.result") == "SUCCESS"
    assert e.get("authenticationContext.externalSessionId") == "sess-1"
    assert e.get("transaction.id") == "tx-1"
    # the first target hop (the common single-target case)
    assert e.get("target.type") == "AppInstance"
    assert e.get("target.displayName") == "My App"


def test_single_bare_record_object():
    evs = parse_idp(json.dumps(_EVENT))
    assert len(evs) == 1 and evs[0].get("eventType") == "user.session.start"


def test_wrapped_events_envelope():
    evs = parse_idp(json.dumps({"events": [_EVENT, dict(_EVENT, eventType="user.session.end")]}))
    assert [e.get("eventType") for e in evs] == ["user.session.start", "user.session.end"]


def test_ndjson_one_record_per_line():
    nd = "\n".join(json.dumps(r) for r in (
        dict(_EVENT, eventType="user.session.start"),
        dict(_EVENT, eventType="user.account.lock")))
    evs = parse_idp(nd)
    assert [e.get("eventType") for e in evs] == ["user.session.start", "user.account.lock"]


def test_input_order_preserved_and_deterministic():
    text = _array(dict(_EVENT, uuid="u-A", eventType="A"), dict(_EVENT, uuid="u-B", eventType="B"))
    first = [e.as_dict() for e in parse_idp(text)]
    second = [e.as_dict() for e in parse_idp(text)]
    assert first == second
    assert [e["fields"]["eventType"] for e in first] == ["A", "B"]


# --- TOTAL / FAIL-CLOSED on hostile input ---------------------------------------------------------
def test_malformed_json_is_not_raised():
    assert parse_idp("{not json at all") == []


def test_non_dict_records_are_skipped():
    text = json.dumps([123, "str", None, _EVENT])
    evs = parse_idp(text)
    assert len(evs) == 1 and evs[0].get("eventType") == "user.session.start"


def test_empty_and_whitespace_input():
    assert parse_idp("") == []
    assert parse_idp("   \n  ") == []


def test_ndjson_bad_line_skipped_total():
    nd = json.dumps(dict(_EVENT, eventType="a")) + "\n{garbage\n" + json.dumps(dict(_EVENT, eventType="b"))
    assert [e.get("eventType") for e in parse_idp(nd)] == ["a", "b"]


# --- GATED detect_format sniff (mutation-sensitive NEGATIVE CONTROL) -------------------------------
def test_detect_idp_on_positive_marker():
    # A genuine Okta System Log event carries eventType AND published AND uuid — the three-field marker.
    assert detect_format(_array(_EVENT)) == "idp"
    assert detect_format(json.dumps(_EVENT)) == "idp"
    assert detect_format(json.dumps({"events": [_EVENT]})) == "idp"


def test_detect_non_idp_json_unchanged_evtx():
    # The NEGATIVE CONTROL: a non-IdP JSON must keep its v1 'evtx_json' sniff byte-for-byte.
    assert detect_format('[{"EventID": 4688}]') == "evtx_json"
    assert detect_format('{"EventID": 4688, "CommandLine": "cmd.exe"}') == "evtx_json"
    # an Okta-SHAPED record missing ANY ONE of the three marker fields is NOT a marker (gate tightness)
    assert detect_format(json.dumps([{k: v for k, v in _EVENT.items() if k != "uuid"}])) == "evtx_json"
    assert detect_format(json.dumps([{k: v for k, v in _EVENT.items() if k != "published"}])) == "evtx_json"
    assert detect_format(json.dumps([{k: v for k, v in _EVENT.items() if k != "eventType"}])) == "evtx_json"
    # a non-string eventType is not the marker either
    assert detect_format(json.dumps([dict(_EVENT, eventType=5)])) == "evtx_json"
    # an empty array is not a marker
    assert detect_format("[]") == "evtx_json"


def test_detect_cloudtrail_still_wins_and_cef_syslog_unchanged():
    # A CloudTrail delivery keeps sniffing 'cloudtrail' (the IdP branch did not steal it).
    ct = json.dumps({"Records": [{"eventTime": "2024-05-01T12:00:00Z", "eventID": "abc-123",
                                  "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin"}]})
    assert detect_format(ct) == "cloudtrail"
    assert detect_format("CEF:0|v|p|1|100|name|5|src=1.2.3.4") == "cef"
    assert detect_format("May  1 10:00:00 host app[1]: hello") == "syslog"


def test_detect_evtx_array_parses_byte_for_byte_as_evtx():
    # 'parse exactly as on origin/main': a non-IdP array's auto path IS the evtx path, byte-for-byte.
    evtx = '[{"EventID": 4688, "CommandLine": "cmd.exe"}]'
    assert detect_format(evtx) == "evtx_json"
    assert [e.as_dict() for e in parse_log(evtx, "auto")] == [e.as_dict() for e in parse_evtx_json(evtx)]


def test_parse_log_auto_routes_idp():
    evs = parse_log(_array(_EVENT), "auto")
    assert evs and evs[0].source_format == "idp"
    # explicit format also works
    assert parse_log(json.dumps(_EVENT), "idp")[0].get("eventType") == "user.session.start"


# --- TIE TO AS-17a: a standard Okta Sigma rule fires on the normalized event ----------------------
_FAILED_LOGIN_RULE = """
title: Okta Failed Login
id: okta-failed-login
logsource: {product: okta, service: okta}
detection:
  selection:
    eventType: user.session.start
    outcome.result: FAILURE
  condition: selection
tags: [attack.t1110]
author: tester
license: MIT
"""


def test_standard_okta_sigma_rule_fires_on_failed_login():
    rule = parse_sigma_rule(_FAILED_LOGIN_RULE)
    assert rule is not None and rule.supported
    failed = dict(_EVENT, outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"})
    evs = parse_idp(_array(failed))
    res = evaluate_events([rule], evs, field_map=default_field_map())
    assert res.matched_rule_ids == ["okta-failed-login"]
    assert res.techniques_detected == ["T1110"]


def test_benign_successful_login_does_not_trip_failed_login_rule():
    # near-zero-FP: a SUCCESS login is not a FAILURE — the failed-login rule must NOT fire.
    rule = parse_sigma_rule(_FAILED_LOGIN_RULE)
    evs = parse_idp(_array(_EVENT))      # outcome.result == SUCCESS
    assert evaluate_events([rule], evs, field_map=default_field_map()).matched_rule_ids == []
