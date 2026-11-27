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
    "eventID": "72b8f8a1-1b2c-4d3e-8f90-0a1b2c3d4e5f",
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


def test_leading_zero_account_id_stays_a_string():
    # A 12-digit AWS account id with a LEADING ZERO is an identifier, not an arithmetic integer:
    # ``_coerce`` must NOT drop the leading zero (that is the MEDIUM leading-zero-loss fix). A control
    # account id with no leading zero still coerces to int (byte-for-byte the prior behaviour).
    rec = dict(_RECORD)
    rec["recipientAccountId"] = "012345678901"
    e = parse_cloudtrail(_envelope(rec))[0]
    assert e.get("recipientAccountId") == "012345678901"        # string, leading zero PRESERVED
    assert parse_cloudtrail(_envelope(_RECORD))[0].get("recipientAccountId") == 111122223333   # int (no leading 0)


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
    # A genuine CloudTrail record carries eventTime AND eventID AND an eventSource ending in
    # '.amazonaws.com' — the three-field marker the tightened sniff requires.
    assert detect_format(_envelope(_RECORD)) == "cloudtrail"
    minimal = {"Records": [{"eventTime": "2024-05-01T12:00:00Z", "eventID": "abc-123",
                            "eventSource": "iam.amazonaws.com", "eventName": "CreateUser"}]}
    assert detect_format(json.dumps(minimal)) == "cloudtrail"


def test_detect_non_cloudtrail_json_unchanged_evtx():
    # The NEGATIVE CONTROL: a non-CloudTrail JSON must keep its v1 'evtx_json' sniff byte-for-byte.
    assert detect_format('[{"EventID": 4688}]') == "evtx_json"
    assert detect_format('{"EventID": 4688, "CommandLine": "cmd.exe"}') == "evtx_json"
    # a {"Records":[...]} wrapper WITHOUT the three-field marker is the existing evtx wrapper path
    assert detect_format('{"Records": [{"EventID": 4688, "CommandLine": "x"}]}') == "evtx_json"
    # eventVersion/eventSource ALONE (no eventTime+eventID) is NOT a CloudTrail marker — the loose
    # old marker wrongly sniffed these 'cloudtrail'. (Tighten-gate mutation control.)
    assert detect_format('{"Records": [{"eventVersion": "1.08", "x": 1}]}') == "evtx_json"
    assert detect_format('{"Records": [{"eventSource": "signin.amazonaws.com", "x": 1}]}') == "evtx_json"
    # a CloudTrail-shaped record missing the eventSource '.amazonaws.com' suffix is not a marker either
    assert detect_format('{"Records": [{"eventTime": "t", "eventID": "i", "eventSource": "aws:s3"}]}') == "evtx_json"
    # an empty / non-list Records is not a CloudTrail marker either
    assert detect_format('{"Records": []}') == "evtx_json"
    assert detect_format('{"Records": "nope"}') == "evtx_json"


# The four AWS notification/stream envelopes that ALSO use a top-level ``Records`` list. The loose
# old marker (eventSource OR eventVersion) mis-routed S3 / SQS / DynamoDB to 'cloudtrail', silently
# changing '--format auto' for existing users. Each must sniff 'evtx_json' AND parse BYTE-FOR-BYTE as
# the pre-AS-17b evtx path (i.e. exactly as on origin/main), never 'cloudtrail'.
_S3_NOTIFICATION = json.dumps({"Records": [{
    "eventVersion": "2.1", "eventSource": "aws:s3", "awsRegion": "us-east-1",
    "eventTime": "2024-05-01T12:00:00.000Z", "eventName": "ObjectCreated:Put",
    "s3": {"bucket": {"name": "my-bucket"}, "object": {"key": "a/b.txt"}}}]})
_SNS_ENVELOPE = json.dumps({"Records": [{
    "EventSource": "aws:sns", "EventVersion": "1.0", "EventSubscriptionArn": "arn:aws:sns:...:sub",
    "Sns": {"Type": "Notification", "MessageId": "m-1", "Message": "hello"}}]})
_SQS_ENVELOPE = json.dumps({"Records": [{
    "messageId": "11111111-1111-1111-1111-111111111111", "receiptHandle": "AQEB...",
    "body": "hello", "eventSource": "aws:sqs", "eventSourceARN": "arn:aws:sqs:...:q",
    "awsRegion": "us-east-1"}]})
_DYNAMODB_STREAM = json.dumps({"Records": [{
    "eventID": "1", "eventName": "INSERT", "eventVersion": "1.1", "eventSource": "aws:dynamodb",
    "awsRegion": "us-east-1", "dynamodb": {"Keys": {"Id": {"N": "101"}},
    "SequenceNumber": "111", "ApproximateCreationDateTime": 1700000000},
    "eventSourceARN": "arn:aws:dynamodb:...:stream"}]})


def test_detect_notification_envelopes_are_not_cloudtrail():
    for name, env in (("s3", _S3_NOTIFICATION), ("sns", _SNS_ENVELOPE),
                      ("sqs", _SQS_ENVELOPE), ("dynamodb", _DYNAMODB_STREAM)):
        assert detect_format(env) == "evtx_json", f"{name} must not sniff as cloudtrail"
        # 'parse exactly as on origin/main': the auto path IS the evtx path, byte-for-byte.
        auto = [e.as_dict() for e in parse_log(env, "auto")]
        assert auto == [e.as_dict() for e in parse_evtx_json(env)], f"{name} auto-parse must equal the evtx parse"


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


def test_leading_zero_account_id_sigma_match():
    # The leading-zero-loss fix, end to end through Sigma: a rule keyed on a leading-zero account id
    # fires on the record that carries it. On the OLD _coerce the field was the int 12345678901, whose
    # string form "12345678901" never equals the rule's "012345678901" — so this rule would NOT fire.
    rule = parse_sigma_rule("""
title: Activity in account 012345678901
id: ct-acct-leading-zero
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    recipientAccountId: "012345678901"
  condition: selection
author: tester
license: MIT
""")
    assert rule is not None and rule.supported
    match_rec = dict(_RECORD)
    match_rec["recipientAccountId"] = "012345678901"
    evs = parse_cloudtrail(_envelope(match_rec))
    assert evaluate_events([rule], evs, field_map=default_field_map()).matched_rule_ids == ["ct-acct-leading-zero"]
    # negative control: the SAME 12 digits without the leading zero is a DIFFERENT account — no match.
    other = dict(_RECORD)
    other["recipientAccountId"] = "123456789012"
    assert evaluate_events([rule], parse_cloudtrail(_envelope(other)),
                           field_map=default_field_map()).matched_rule_ids == []
