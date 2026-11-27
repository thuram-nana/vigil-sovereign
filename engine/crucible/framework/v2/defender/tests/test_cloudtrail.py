"""AS-17b — the AWS CloudTrail NORMALIZER (``defender.logsource.parse_cloudtrail``) + the GATED
``detect_format`` branch.

Proven here (strict acceptance):
  * NORMALIZE — the CloudTrail delivery envelope ``{"Records":[...]}``, a single-record object, and NDJSON
    all flatten into ``cloudtrail`` ``LogEvent``s under AWS' own field names (incl. the dotted
    ``userIdentity.*`` keys standard CloudTrail Sigma references);
  * TOTAL / FAIL-CLOSED — a malformed blob / record / bad line is skipped, never raised; a non-dict record
    is dropped; bounds hold;
  * DETERMINISM — re-parsing the same bytes yields identical events (input order preserved);
  * GATED SNIFF (the mutation-sensitive NEGATIVE CONTROL) — ``detect_format`` returns 'cloudtrail' ONLY on a
    positive CloudTrail marker (a top-level ``Records`` list whose items carry ``eventSource``/
    ``eventVersion``); EVERY non-CloudTrail JSON input (incl. a bare array, a flat object, and a
    ``{"Records":[...]}`` wrapper WITHOUT the marker) keeps its v1 'evtx_json' sniff byte-for-byte. Remove
    the marker gate (sniff 'cloudtrail' for any '{') and these controls RED.
  * TIE TO AS-17a — a standard CloudTrail Sigma rule fires on the normalized event (the ingest feeds the
    UNCHANGED Sigma runtime).
"""
from __future__ import annotations

import json

from framework.v2.defender.logsource import (
    detect_format,
    parse_cef,
    parse_cloudtrail,
    parse_evtx_json,
    parse_log,
    parse_syslog,
)
from framework.v2.defender.sigma import default_field_map, evaluate_events, parse_sigma_rule

_RECORD = {
    "eventVersion": "1.08",
    "eventSource": "signin.amazonaws.com",
    "eventName": "ConsoleLogin",
    "eventTime": "2024-05-01T12:00:00Z",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.9",
    "userAgent": "Mozilla/5.0",
    "errorMessage": "Failed authentication. Authentication failed.",
    "readOnly": False,
    "managementEvent": True,
    "recipientAccountId": "111122223333",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::111122223333:user/alice",
        "accountId": "111122223333",
        "principalId": "AIDAEXAMPLE",
        "userName": "alice",
    },
}


def _envelope(*records: dict) -> str:
    return json.dumps({"Records": list(records)})


# --- NORMALIZE ------------------------------------------------------------------------------------
def test_envelope_flattens_salient_fields():
    evs = parse_cloudtrail(_envelope(_RECORD))
    assert len(evs) == 1
    e = evs[0]
    assert e.channel == "cloudtrail" and e.source_format == "cloudtrail"
    assert e.get("eventSource") == "signin.amazonaws.com"
    assert e.get("eventName") == "ConsoleLogin"
    assert e.get("awsRegion") == "us-east-1"
    assert e.get("sourceIPAddress") == "203.0.113.9"
    # ``_coerce`` is reused VERBATIM, so an all-digit value coerces to int exactly as every other parser
    # (evtx EventID, syslog procid). Sigma matching stays correct (``_scalar_match`` compares as strings).
    assert e.get("recipientAccountId") == 111122223333
    # bool -> "True"/"False" (Sigma match is case-insensitive); a JSON bool never becomes a Python-truthy int
    assert e.get("readOnly") == "False"
    assert e.get("managementEvent") == "True"


def test_user_identity_flattened_under_dotted_keys():
    e = parse_cloudtrail(_envelope(_RECORD))[0]
    assert e.get("userIdentity.type") == "IAMUser"
    assert e.get("userIdentity.arn") == "arn:aws:iam::111122223333:user/alice"
    assert e.get("userIdentity.userName") == "alice"
    assert e.get("userIdentity.principalId") == "AIDAEXAMPLE"


def test_session_issuer_second_hop_flattened():
    rec = dict(_RECORD)
    rec["userIdentity"] = {
        "type": "AssumedRole",
        "sessionContext": {"sessionIssuer": {"type": "Role", "userName": "AdminRole",
                                             "arn": "arn:aws:iam::111122223333:role/AdminRole"}},
    }
    e = parse_cloudtrail(_envelope(rec))[0]
    assert e.get("userIdentity.type") == "AssumedRole"
    assert e.get("userIdentity.sessionContext.sessionIssuer.userName") == "AdminRole"


def test_single_bare_record_object():
    evs = parse_cloudtrail(json.dumps(_RECORD))
    assert len(evs) == 1 and evs[0].get("eventName") == "ConsoleLogin"


def test_ndjson_one_record_per_line():
    nd = "\n".join(json.dumps(r) for r in (
        {"eventSource": "s3.amazonaws.com", "eventName": "GetObject"},
        {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"}))
    evs = parse_cloudtrail(nd)
    assert [e.get("eventName") for e in evs] == ["GetObject", "CreateUser"]


def test_input_order_preserved_and_deterministic():
    text = _envelope({"eventSource": "a", "eventName": "A"}, {"eventSource": "b", "eventName": "B"})
    first = [e.as_dict() for e in parse_cloudtrail(text)]
    second = [e.as_dict() for e in parse_cloudtrail(text)]
    assert first == second
    assert [e["fields"]["eventName"] for e in first] == ["A", "B"]


# --- TOTAL / FAIL-CLOSED on hostile input ---------------------------------------------------------
def test_malformed_json_is_not_raised():
    assert parse_cloudtrail("{not json at all") == []


def test_non_dict_records_are_skipped():
    text = json.dumps({"Records": [123, "str", None, _RECORD]})
    evs = parse_cloudtrail(text)
    assert len(evs) == 1 and evs[0].get("eventName") == "ConsoleLogin"


def test_empty_and_whitespace_input():
    assert parse_cloudtrail("") == []
    assert parse_cloudtrail("   \n  ") == []


def test_ndjson_bad_line_skipped_total():
    nd = json.dumps({"eventSource": "s3", "eventName": "GetObject"}) + "\n{garbage\n" + \
        json.dumps({"eventSource": "iam", "eventName": "CreateUser"})
    evs = parse_cloudtrail(nd)
    assert [e.get("eventName") for e in evs] == ["GetObject", "CreateUser"]


# --- GATED detect_format sniff (mutation-sensitive NEGATIVE CONTROL) -------------------------------
def test_detect_cloudtrail_on_positive_marker():
    assert detect_format(_envelope(_RECORD)) == "cloudtrail"
    # eventVersion alone is also a positive marker.
    assert detect_format(json.dumps({"Records": [{"eventVersion": "1.08", "x": 1}]})) == "cloudtrail"


def test_detect_non_cloudtrail_json_unchanged_evtx():
    # The NEGATIVE CONTROL: a non-CloudTrail JSON must keep its v1 'evtx_json' sniff byte-for-byte.
    assert detect_format('[{"EventID": 4688}]') == "evtx_json"
    assert detect_format('{"EventID": 4688, "CommandLine": "cmd.exe"}') == "evtx_json"
    # a {"Records":[...]} wrapper WITHOUT the eventSource/eventVersion marker is the existing evtx wrapper path
    assert detect_format('{"Records": [{"EventID": 4688, "CommandLine": "x"}]}') == "evtx_json"
    # an empty / non-list Records is not a CloudTrail marker either
    assert detect_format('{"Records": []}') == "evtx_json"
    assert detect_format('{"Records": "nope"}') == "evtx_json"


def test_detect_cef_and_syslog_unchanged():
    assert detect_format("CEF:0|v|p|1|100|name|5|src=1.2.3.4") == "cef"
    assert detect_format("May  1 10:00:00 host app[1]: hello") == "syslog"


def test_evtx_sniff_still_routes_evtx_records_wrapper():
    # Mutation guard: the evtx path still CONSUMES a {"Records":[...]} evtx wrapper (parse_evtx_json reads the
    # 'Records' key), so the gated branch did not steal it — proof the two formats stay disjoint by MARKER.
    evtx_wrapper = '{"Records": [{"EventID": 4688, "CommandLine": "cmd.exe"}]}'
    evs = parse_log(evtx_wrapper, detect_format(evtx_wrapper))
    assert len(evs) == 1 and evs[0].channel == "windows" and evs[0].get("EventID") == 4688


def test_parse_log_auto_routes_cloudtrail():
    evs = parse_log(_envelope(_RECORD), "auto")
    assert evs and evs[0].source_format == "cloudtrail"
    # explicit format also works
    assert parse_log(json.dumps(_RECORD), "cloudtrail")[0].get("eventName") == "ConsoleLogin"


# --- TIE TO AS-17a: a standard CloudTrail Sigma rule fires on the normalized event ----------------
def test_standard_cloudtrail_sigma_rule_fires():
    rule = parse_sigma_rule("""
title: AWS Console Login
id: ct-console-login
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    eventSource: signin.amazonaws.com
    eventName: ConsoleLogin
  condition: selection
tags: [attack.t1078]
author: tester
license: MIT
""")
    assert rule is not None and rule.supported
    evs = parse_cloudtrail(_envelope(_RECORD))
    res = evaluate_events([rule], evs, field_map=default_field_map())
    assert res.matched_rule_ids == ["ct-console-login"]
    assert res.techniques_detected == ["T1078"]


def test_benign_cloudtrail_event_does_not_trip_rule():
    # near-zero-FP: a read-only S3 GetObject is NOT a console login — the rule must NOT fire.
    rule = parse_sigma_rule("""
title: AWS Console Login
id: ct-console-login
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    eventSource: signin.amazonaws.com
    eventName: ConsoleLogin
  condition: selection
author: tester
license: MIT
""")
    benign = parse_cloudtrail(_envelope({"eventVersion": "1.08", "eventSource": "s3.amazonaws.com",
                                         "eventName": "GetObject", "readOnly": True}))
    res = evaluate_events([rule], benign, field_map=default_field_map())
    assert res.matched_rule_ids == []
