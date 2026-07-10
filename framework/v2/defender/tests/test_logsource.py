"""
Tests for defender.logsource — OFFLINE log/alert ingestion (syslog / CEF / EVTX-JSON).

The parsers are PURE and TOTAL: same bytes -> same events, and a malformed line/record is
skipped, never raised. The file loader degrades cleanly on a missing/oversized/unreadable file.
All input is treated as UNTRUSTED (bounded, json.loads only, no eval).
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.defender.logsource import (
    LogEvent,
    detect_format,
    load_log_file,
    parse_cef,
    parse_evtx_json,
    parse_log,
    parse_syslog,
)


# --- syslog ----------------------------------------------------------------

def test_syslog_rfc3164_extracts_tag_host_and_kv() -> None:
    line = "<38>Oct 11 22:14:15 web01 sshd[1234]: Failed password for root user=admin src=10.0.0.9"
    ev = parse_syslog(line)[0]
    assert ev.channel == "syslog" and ev.source_format == "syslog"
    assert ev.fields["app"] == "sshd" and ev.fields["host"] == "web01"
    assert ev.fields["procid"] == 1234                     # coerced to int
    assert ev.fields["user"] == "admin" and ev.fields["src"] == "10.0.0.9"
    assert ev.fields["facility"] == 4 and ev.fields["severity"] == 6   # <38> = 4*8+6


def test_syslog_rfc5424_is_parsed() -> None:
    line = ('<165>1 2003-10-11T22:14:15.003Z host.example.com evntslog 8710 ID47 '
            '- an application event log entry action=blocked')
    ev = parse_syslog(line)[0]
    assert ev.fields["host"] == "host.example.com" and ev.fields["app"] == "evntslog"
    assert ev.fields["action"] == "blocked"


def test_syslog_unparseable_line_still_becomes_an_event() -> None:
    # total: a line matching neither RFC still yields an event carrying the whole message
    ev = parse_syslog("this is not really a syslog line at all")[0]
    assert "message" in ev.fields


def test_syslog_quoted_values_are_unquoted() -> None:
    ev = parse_syslog('Jan  1 00:00:00 h app: msg reason="access denied here"')[0]
    assert ev.fields["reason"] == "access denied here"


# --- CEF -------------------------------------------------------------------

def test_cef_header_and_extension() -> None:
    line = "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232"
    ev = parse_cef(line)[0]
    assert ev.channel == "cef"
    assert ev.fields["device_vendor"] == "Security"
    assert ev.fields["device_product"] == "threatmanager"
    assert ev.fields["cef_signature_id"] == "100"          # signature ids are opaque tokens (kept as str)
    assert ev.fields["cef_name"] == "worm successfully stopped"
    assert ev.fields["cef_severity"] == 10
    assert ev.fields["src"] == "10.0.0.1" and ev.fields["spt"] == 1232


def test_cef_escaped_pipe_in_header() -> None:
    line = r"CEF:0|Vendor|Prod\|X|1.0|1|name here|5|act=blocked"
    ev = parse_cef(line)[0]
    assert ev.fields["device_product"] == "Prod|X"    # escaped pipe kept inside the segment
    assert ev.fields["act"] == "blocked"


def test_cef_prefix_syslog_wrapper_is_stripped() -> None:
    line = "Jan 01 00:00:00 host CEF:0|V|P|1|10|evt|3|dst=1.2.3.4"
    ev = parse_cef(line)[0]
    assert ev.fields["cef_signature_id"] == "10" and ev.fields["dst"] == "1.2.3.4"


def test_cef_too_few_segments_is_skipped() -> None:
    assert parse_cef("CEF:0|only|three|segs") == []


# --- EVTX-JSON -------------------------------------------------------------

def test_evtx_flat_array() -> None:
    text = '[{"EventID": 4688, "CommandLine": "powershell -enc AAAA", "Computer": "WS1"}]'
    ev = parse_evtx_json(text)[0]
    assert ev.channel == "windows"
    assert ev.fields["EventID"] == 4688 and ev.fields["CommandLine"] == "powershell -enc AAAA"


def test_evtx_nested_system_and_eventdata_data_array() -> None:
    text = ('{"Event": {"System": {"EventID": 4688, "Computer": "WS1"}, '
            '"EventData": {"Data": [{"@Name": "CommandLine", "#text": "cmd /c whoami"}, '
            '{"@Name": "User", "#text": "SYSTEM"}]}}}')
    ev = parse_evtx_json(text)[0]
    assert ev.fields["EventID"] == 4688
    assert ev.fields["CommandLine"] == "cmd /c whoami" and ev.fields["User"] == "SYSTEM"


def test_evtx_ndjson_one_object_per_line() -> None:
    text = '{"EventID": 1, "Image": "a.exe"}\n{"EventID": 2, "Image": "b.exe"}'
    evs = parse_evtx_json(text)
    assert [e.fields["EventID"] for e in evs] == [1, 2]


def test_evtx_events_wrapper_key() -> None:
    text = '{"Events": [{"EventID": 4625, "TargetUserName": "root"}]}'
    ev = parse_evtx_json(text)[0]
    assert ev.fields["EventID"] == 4625 and ev.fields["TargetUserName"] == "root"


def test_evtx_garbage_is_skipped_not_raised() -> None:
    assert parse_evtx_json("not json at all") == []
    assert parse_evtx_json('[{"ok": 1}, "not-a-dict", 42]')  # the one dict survives; others skipped


# --- format detection + unified entry --------------------------------------

def test_detect_format() -> None:
    assert detect_format('[{"EventID":1}]') == "evtx_json"
    assert detect_format("CEF:0|a|b|c|d|e|f|x=1") == "cef"
    assert detect_format("<34>Oct 11 22:14:15 h app: msg") == "syslog"


def test_parse_log_auto_dispatches() -> None:
    assert parse_log("CEF:0|a|b|c|100|n|3|x=1", "auto")[0].fields["cef_signature_id"] == "100"
    assert parse_log("", "auto") == []
    assert parse_log("anything", "nonsense-format") == []   # unknown fmt -> [] (total)


def test_parsers_are_deterministic() -> None:
    text = "<34>Oct 11 22:14:15 h app: a=1 b=2\n<34>Oct 11 22:14:16 h app: a=3"
    assert [e.fields for e in parse_syslog(text)] == [e.fields for e in parse_syslog(text)]


# --- file loader: graceful absence -----------------------------------------

def test_load_missing_file_is_clean_skip() -> None:
    load = load_log_file("/no/such/log/file.log")
    assert not load.ok and load.events == [] and "not found" in load.note


def test_load_empty_path_is_clean_skip() -> None:
    assert load_log_file("").events == []


def test_load_oversized_file_is_refused(tmp_path: Path) -> None:
    p = tmp_path / "big.log"
    p.write_text("x" * 1000, encoding="utf-8")
    load = load_log_file(str(p), max_bytes=100)
    assert not load.ok and "too large" in load.note and load.events == []


def test_load_real_file_parses(tmp_path: Path) -> None:
    p = tmp_path / "auth.log"
    p.write_text("<38>Oct 11 22:14:15 web01 sshd[1]: Failed password user=admin\n", encoding="utf-8")
    load = load_log_file(str(p))
    assert load.ok and load.format == "syslog" and load.events
    assert load.events[0].fields["user"] == "admin"
