"""
Tests for defender.sigma — the small, deterministic, FAIL-CLOSED Sigma runtime + ATT&CK mapping.

The load-bearing property: a rule using a construct we do not implement (unknown modifier, a
correlation condition, a value-modifier) NEVER matches — an honest "unsupported → not detected",
never a fabricated detection. The supported subset MATCHES a malicious event and does NOT match a
benign one, and maps ATT&CK from the rule's tags.
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.defender.logsource import LogEvent
from framework.v2.defender.sigma import (
    evaluate_events,
    load_sigma_dir,
    parse_sigma_rule,
    rule_matches_event,
)


def _ev(**fields) -> LogEvent:
    return LogEvent(channel="webproxy", fields=dict(fields), raw=" ".join(f"{k}={v}" for k, v in fields.items()))


_SQLI_RULE = """
title: SQL injection in URI query
id: R-WEB-SQLI
detection:
  selection:
    cs_uri_query|contains:
      - "' OR 1=1"
      - "UNION SELECT"
  condition: selection
tags:
  - attack.t1190
  - attack.initial_access
level: high
"""


# --- the core purple-team property -----------------------------------------

def test_malicious_event_matches_benign_does_not() -> None:
    rule = parse_sigma_rule(_SQLI_RULE)
    assert rule is not None and rule.supported
    malicious = _ev(cs_uri_query="id=1' OR 1=1 -- ")
    benign = _ev(cs_uri_query="id=1")
    assert rule_matches_event(rule, malicious) is True
    assert rule_matches_event(rule, benign) is False


def test_attack_technique_and_tactic_extraction() -> None:
    rule = parse_sigma_rule(_SQLI_RULE)
    assert rule.attack_techniques == ("T1190",)
    assert "initial-access" in rule.attack_tactics


def test_sub_technique_id_is_preserved() -> None:
    rule = parse_sigma_rule(
        "title: t\nid: r\ndetection:\n  sel:\n    f: v\n  condition: sel\ntags: [attack.t1059.007]")
    assert rule.attack_techniques == ("T1059.007",)


# --- fail-closed on unsupported constructs ---------------------------------

def test_unsupported_field_modifier_never_matches() -> None:
    # a value modifier we do not implement ('re') must fail closed even when the field is present
    rule = parse_sigma_rule(
        "title: t\nid: r\ndetection:\n  sel:\n    CommandLine|re: '.*evil.*'\n  condition: sel")
    assert rule is not None and rule.supported is False           # honestly flagged unsupported
    assert rule_matches_event(rule, _ev(CommandLine="run evil.exe")) is False


def test_correlation_condition_is_unsupported_and_never_matches() -> None:
    rule = parse_sigma_rule(
        "title: t\nid: r\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel | count() > 5")
    assert rule.supported is False
    assert rule_matches_event(rule, _ev(EventID=4625)) is False   # even the base selection can't fire


def test_unknown_selection_in_condition_fails_closed() -> None:
    rule = parse_sigma_rule(
        "title: t\nid: r\ndetection:\n  sel:\n    f: v\n  condition: sel and missing")
    assert rule_matches_event(rule, _ev(f="v")) is False


def test_empty_selection_never_matches_every_event() -> None:
    # an empty selection ({}) has no criteria — it must NOT fire on all events (a false-detection trap)
    rule = parse_sigma_rule("title: t\nid: r\ndetection:\n  sel: {}\n  condition: sel")
    assert rule_matches_event(rule, _ev(anything="here")) is False


# --- condition grammar -----------------------------------------------------

def test_and_not_condition() -> None:
    rule = parse_sigma_rule("""
title: t
id: r
detection:
  selection:
    EventID: 4688
  filter:
    User: SYSTEM
  condition: selection and not filter
""")
    assert rule_matches_event(rule, _ev(EventID=4688, User="alice")) is True
    assert rule_matches_event(rule, _ev(EventID=4688, User="SYSTEM")) is False


def test_or_condition() -> None:
    rule = parse_sigma_rule("""
title: t
id: r
detection:
  a:
    EventID: 1
  b:
    EventID: 2
  condition: a or b
""")
    assert rule_matches_event(rule, _ev(EventID=2)) is True
    assert rule_matches_event(rule, _ev(EventID=3)) is False


def test_1_of_and_all_of_aggregations() -> None:
    text = """
title: t
id: r
detection:
  selection_a:
    EventID: 1
  selection_b:
    Image: evil.exe
  condition: {cond}
"""
    one = parse_sigma_rule(text.format(cond="1 of selection_*"))
    allof = parse_sigma_rule(text.format(cond="all of selection_*"))
    ev_one = _ev(EventID=1, Image="good.exe")
    ev_all = _ev(EventID=1, Image="evil.exe")
    assert rule_matches_event(one, ev_one) is True
    assert rule_matches_event(allof, ev_one) is False
    assert rule_matches_event(allof, ev_all) is True


def test_parentheses_precedence() -> None:
    rule = parse_sigma_rule("""
title: t
id: r
detection:
  a: {EventID: 1}
  b: {EventID: 2}
  c: {Image: x}
  condition: (a or b) and c
""")
    assert rule_matches_event(rule, _ev(EventID=1, Image="x")) is True
    assert rule_matches_event(rule, _ev(EventID=1, Image="y")) is False


# --- selection shapes ------------------------------------------------------

def test_keywords_selection_freetext() -> None:
    rule = parse_sigma_rule("""
title: t
id: r
detection:
  keywords:
    - mimikatz
    - sekurlsa
  condition: keywords
""")
    assert rule_matches_event(rule, _ev(CommandLine="invoke-mimikatz now")) is True
    assert rule_matches_event(rule, _ev(CommandLine="notepad.exe")) is False


def test_list_of_maps_is_or() -> None:
    rule = parse_sigma_rule("""
title: t
id: r
detection:
  selection:
    - {EventID: 1}
    - {EventID: 4688}
  condition: selection
""")
    assert rule_matches_event(rule, _ev(EventID=4688)) is True
    assert rule_matches_event(rule, _ev(EventID=9)) is False


def test_all_modifier_requires_every_value() -> None:
    rule = parse_sigma_rule("""
title: t
id: r
detection:
  selection:
    CommandLine|contains|all:
      - "-enc"
      - "hidden"
  condition: selection
""")
    assert rule_matches_event(rule, _ev(CommandLine="ps -enc AAA -windowstyle hidden")) is True
    assert rule_matches_event(rule, _ev(CommandLine="ps -enc AAA")) is False   # missing 'hidden'


def test_startswith_endswith() -> None:
    r_start = parse_sigma_rule(
        "title: t\nid: r\ndetection:\n  s:\n    Image|startswith: /usr/bin\n  condition: s")
    r_end = parse_sigma_rule(
        "title: t\nid: r\ndetection:\n  s:\n    Image|endswith: .exe\n  condition: s")
    assert rule_matches_event(r_start, _ev(Image="/usr/bin/curl")) is True
    assert rule_matches_event(r_start, _ev(Image="/opt/curl")) is False
    assert rule_matches_event(r_end, _ev(Image="/tmp/a.exe")) is True
    assert rule_matches_event(r_end, _ev(Image="/tmp/a.txt")) is False


# --- parsing robustness ----------------------------------------------------

def test_parse_rejects_non_dict_and_missing_detection() -> None:
    assert parse_sigma_rule("- just\n- a\n- list") is None
    assert parse_sigma_rule("title: t\nid: r") is None            # no detection
    assert parse_sigma_rule("not: a rule: {bad yaml") is None     # unparseable -> None (total)


# --- ruleset evaluation ----------------------------------------------------

def test_evaluate_events_reports_matches_and_techniques() -> None:
    rule = parse_sigma_rule(_SQLI_RULE)
    events = [_ev(cs_uri_query="hello"), _ev(cs_uri_query="x=UNION SELECT password")]
    res = evaluate_events([rule], events)
    assert res.rules_evaluated == 1 and res.events_evaluated == 2
    assert res.matched_rule_ids == ["R-WEB-SQLI"]
    assert res.techniques_detected == ["T1190"]
    assert res.matches[0].event_index == 1                        # matched the 2nd event


def test_evaluate_counts_unsupported_rules() -> None:
    bad = parse_sigma_rule(
        "title: t\nid: r\ndetection:\n  s:\n    f|base64: v\n  condition: s")
    res = evaluate_events([bad], [_ev(f="v")])
    assert res.rules_unsupported == 1 and res.matches == []


# --- graceful absence ------------------------------------------------------

def test_load_sigma_dir_missing_is_empty_not_crash() -> None:
    assert load_sigma_dir("/no/such/sigma/dir") == []
    assert load_sigma_dir("") == []


def test_load_sigma_dir_reads_yaml_files(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text(_SQLI_RULE, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(
        "title: t2\nid: R-2\ndetection:\n  s:\n    EventID: 1\n  condition: s\ntags: [attack.t1078]",
        encoding="utf-8")
    (tmp_path / "ignore.txt").write_text("not a rule", encoding="utf-8")
    rules = load_sigma_dir(str(tmp_path))
    assert {r.id for r in rules} == {"R-WEB-SQLI", "R-2"}
