"""
Tests for mcp.protocol — the SAFE JSON-RPC 2.0 envelope.

Every byte off the wire is untrusted: malformed JSON, oversize, a bad envelope, or a bad id must all
degrade to a clean JSON-RPC error object (never a traceback), and a valid message must validate to a
typed Request. Pure functions — no I/O, no wallclock, no rng.
"""

from __future__ import annotations

from framework.v2.mcp import protocol as P


def test_valid_request_parses_to_typed_fields() -> None:
    req, err = P.parse_request('{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x"}}')
    assert err is None and req is not None
    assert req.method == "tools/call" and req.id == 7 and req.is_notification is False
    assert req.params == {"name": "x"}


def test_notification_has_no_id() -> None:
    req, err = P.parse_request('{"jsonrpc":"2.0","method":"notifications/initialized"}')
    assert err is None and req is not None and req.is_notification is True


def test_malformed_json_is_a_parse_error() -> None:
    req, err = P.parse_request("{ this is not json ")
    assert req is None and err is not None
    assert err["error"]["code"] == P.PARSE_ERROR and err["id"] is None


def test_empty_message_is_a_parse_error() -> None:
    req, err = P.parse_request("   \n  ")
    assert req is None and err["error"]["code"] == P.PARSE_ERROR


def test_non_object_payload_is_invalid_request() -> None:
    for raw in ("[1,2,3]", "42", '"a string"', "true"):
        req, err = P.parse_request(raw)
        assert req is None and err["error"]["code"] == P.INVALID_REQUEST


def test_oversize_message_is_rejected_before_parsing() -> None:
    big = '{"jsonrpc":"2.0","id":1,"method":"x","params":{"blob":"' + ("A" * 5000) + '"}}'
    req, err = P.parse_request(big, max_bytes=1024)
    assert req is None and err["error"]["code"] == P.INVALID_REQUEST
    assert "maximum size" in err["error"]["message"]


def test_wrong_jsonrpc_version_is_invalid_request() -> None:
    req, err = P.parse_request('{"jsonrpc":"1.0","id":1,"method":"x"}')
    assert req is None and err["error"]["code"] == P.INVALID_REQUEST
    # the id is still echoed so the caller can correlate the rejection
    assert err["id"] == 1


def test_missing_or_empty_method_is_invalid_request() -> None:
    for raw in ('{"jsonrpc":"2.0","id":1}', '{"jsonrpc":"2.0","id":1,"method":""}',
                '{"jsonrpc":"2.0","id":1,"method":123}'):
        req, err = P.parse_request(raw)
        assert req is None and err["error"]["code"] == P.INVALID_REQUEST


def test_bad_params_type_is_invalid_params() -> None:
    req, err = P.parse_request('{"jsonrpc":"2.0","id":1,"method":"x","params":"nope"}')
    assert req is None and err["error"]["code"] == P.INVALID_PARAMS


def test_bad_id_type_is_invalid_request() -> None:
    for raw in ('{"jsonrpc":"2.0","id":{"a":1},"method":"x"}',
                '{"jsonrpc":"2.0","id":[1],"method":"x"}',
                '{"jsonrpc":"2.0","id":true,"method":"x"}'):
        req, err = P.parse_request(raw)
        assert req is None and err["error"]["code"] == P.INVALID_REQUEST


def test_bytes_and_bad_utf8_are_handled() -> None:
    ok, err = P.parse_request(b'{"jsonrpc":"2.0","id":1,"method":"ping"}')
    assert err is None and ok is not None and ok.method == "ping"
    bad, err2 = P.parse_request(b"\xff\xfe\x00bad")
    assert bad is None and err2["error"]["code"] == P.PARSE_ERROR


def test_response_builders_echo_id_and_shape() -> None:
    assert P.ok_response(9, {"k": 1}) == {"jsonrpc": "2.0", "id": 9, "result": {"k": 1}}
    e = P.err_response("abc", P.METHOD_NOT_FOUND, "nope")
    assert e["id"] == "abc" and e["error"]["code"] == P.METHOD_NOT_FOUND
    # dumps is single-line (newline-delimited framing safe)
    assert "\n" not in P.dumps(e)
