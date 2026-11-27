"""
Tests for defender.sigma **v2** (AS-17a): the wildcard fix, author/licence provenance, field
maps, logsource resolution, and the ``not_deployable`` verdict.

The load-bearing guarantees these tests pin:

  * the DEFAULT evaluation path is BYTE-IDENTICAL to v1 — a rule that uses none of the new
    features matches exactly as before (``test_v1_default_path_is_byte_identical``);
  * a plain value with an unescaped ``*``/``?`` is a Sigma glob, not a literal (the §5.E bug);
  * every new feature is OPT-IN and FAIL-CLOSED — it can only ADD an honest match, never fabricate
    one and never remove the v1 match;
  * ``deployable`` gates DISTRIBUTION only; a non-deployable rule still evaluates locally.
"""

from __future__ import annotations

from framework.v2.defender.logsource import LogEvent
from framework.v2.defender.sigma import (
    default_field_map,
    evaluate_events,
    logsource_channels,
    parse_sigma_rule,
    rule_matches_event,
)


def _ev(channel: str = "webproxy", **fields) -> LogEvent:
    return LogEvent(channel=channel, fields=dict(fields),
                    raw=" ".join(f"{k}={v}" for k, v in fields.items()))


def _rule(detection_body: str, *, extra: str = "") -> object:
    return parse_sigma_rule(
        f"title: t\nid: r\n{extra}detection:\n{detection_body}\n  condition: sel")


# ===========================================================================
# 1. Wildcard fix (the §5.E "literal *" bug)
# ===========================================================================

def test_star_gives_contains_startswith_endswith_and_any() -> None:
    contains = _rule("  sel:\n    Image: '*cmd.exe*'")
    endsw = _rule("  sel:\n    Image: '*cmd.exe'")
    startsw = _rule("  sel:\n    Image: 'cmd.exe*'")
    anyval = _rule("  sel:\n    Image: '*'")
    assert rule_matches_event(contains, _ev(Image="C:/win/cmd.exe.bak")) is True
    assert rule_matches_event(endsw, _ev(Image="C:/win/cmd.exe")) is True
    assert rule_matches_event(endsw, _ev(Image="cmd.exe.bak")) is False
    assert rule_matches_event(startsw, _ev(Image="cmd.exe /c whoami")) is True
    assert rule_matches_event(startsw, _ev(Image="run cmd.exe")) is False
    # bare '*' == field present with ANY value (incl. empty), but NOT absent (fail-closed).
    assert rule_matches_event(anyval, _ev(Image="")) is True
    assert rule_matches_event(anyval, _ev(SomethingElse="x")) is False


def test_question_mark_matches_exactly_one_char() -> None:
    rule = _rule("  sel:\n    name: 'file?.log'")
    assert rule_matches_event(rule, _ev(name="file1.log")) is True
    assert rule_matches_event(rule, _ev(name="file.log")) is False   # '?' needs exactly one char
    assert rule_matches_event(rule, _ev(name="file12.log")) is False


def test_middle_star_and_multi_star() -> None:
    rule = _rule("  sel:\n    path: 'admin*dashboard'")
    assert rule_matches_event(rule, _ev(path="admin_super_dashboard")) is True
    assert rule_matches_event(rule, _ev(path="admindashboard")) is True   # '*' is zero-or-more
    assert rule_matches_event(rule, _ev(path="dashboard_admin")) is False


def test_escaped_star_is_a_literal_asterisk() -> None:
    # real newline between keys; '\\*' in the Python string -> YAML single-quoted value 'a\*b'
    rule = _rule("  sel:\n    token: 'a\\*b'")
    assert rule_matches_event(rule, _ev(token="a*b")) is True
    assert rule_matches_event(rule, _ev(token="axb")) is False   # NOT a wildcard — escaped


def test_wildcard_fails_closed_when_field_absent() -> None:
    rule = _rule("  sel:\n    Image: '*cmd*'")
    assert rule_matches_event(rule, _ev(OtherField="cmd.exe")) is False


def test_adversarial_wildcard_pattern_is_linear_no_catastrophe() -> None:
    # A classic regex-catastrophe shape ('a*a*a*...b') against a long non-matching text. The
    # hand-rolled two-pointer glob is linear, so this returns promptly with a correct False.
    rule = _rule("  sel:\n    blob: '" + "a*" * 30 + "b'")
    assert rule_matches_event(rule, _ev(blob="a" * 300 + "c")) is False
    assert rule_matches_event(rule, _ev(blob="a" * 50 + "b")) is True


# ===========================================================================
# 2. Author / licence provenance (acceptance: "Rule, author and licence shown")
# ===========================================================================

_ATTRIBUTED = """
title: Suspicious whoami
id: R-ATTR
author: Jane Blue
license: DRL-1.1
description: detects whoami recon
references:
  - https://example.invalid/whoami
detection:
  sel:
    CommandLine|contains: whoami
  condition: sel
"""


def test_author_licence_references_parsed_and_shown() -> None:
    rule = parse_sigma_rule(_ATTRIBUTED)
    assert rule.author == "Jane Blue"
    assert rule.license == "DRL-1.1"
    assert rule.description == "detects whoami recon"
    assert rule.references == ("https://example.invalid/whoami",)
    shown = rule.describe()
    assert "Jane Blue" in shown and "DRL-1.1" in shown
    prov = rule.provenance
    assert prov["author"] == "Jane Blue" and prov["license"] == "DRL-1.1"


def test_british_licence_spelling_accepted() -> None:
    rule = parse_sigma_rule(
        "title: t\nid: r\nauthor: A\nlicence: MIT\ndetection:\n  sel:\n    f: v\n  condition: sel")
    assert rule.license == "MIT"


def test_missing_attribution_is_empty_strings() -> None:
    rule = _rule("  sel:\n    f: v")
    assert rule.author == "" and rule.license == "" and rule.references == ()


# ===========================================================================
# 3. not_deployable (distribution gate — never suppresses local evaluation)
# ===========================================================================

def test_attributed_supported_rule_is_deployable() -> None:
    rule = parse_sigma_rule(_ATTRIBUTED)
    assert rule.supported is True
    assert rule.deployable is True
    assert rule.deploy_blockers == ()


def test_unattributed_rule_is_not_deployable_but_still_evaluates() -> None:
    rule = _rule("  sel:\n    CommandLine|contains: whoami")   # no author, no licence
    assert rule.deployable is False
    assert any("author" in b for b in rule.deploy_blockers)
    assert any("licence" in b for b in rule.deploy_blockers)
    # ...yet it STILL fires locally: deployability gates DISTRIBUTION, not matching.
    assert rule_matches_event(rule, _ev(CommandLine="run whoami /all")) is True


def test_unsupported_rule_is_not_deployable_and_never_matches() -> None:
    rule = parse_sigma_rule(
        "title: t\nid: r\nauthor: A\nlicense: MIT\n"
        "detection:\n  sel:\n    f|re: '.*evil.*'\n  condition: sel")
    assert rule.supported is False
    assert rule.deployable is False
    assert any("unsupported" in b for b in rule.deploy_blockers)
    assert rule_matches_event(rule, _ev(f="evil")) is False


def test_evaluate_events_tallies_not_deployable_without_suppressing() -> None:
    attributed = parse_sigma_rule(_ATTRIBUTED)
    unattributed = _rule("  sel:\n    CommandLine|contains: whoami")
    events = [_ev(CommandLine="x whoami y")]
    res = evaluate_events([attributed, unattributed], events)
    assert res.rules_not_deployable == 1              # the unattributed one
    assert res.rules_unsupported == 0
    # both still fired (local efficacy is unaffected by deployability)
    assert set(res.matched_rule_ids) == {"R-ATTR", "r"}
    assert "not-deployable" in res.summary()


# ===========================================================================
# 4. Field maps (opt-in alias fallback; direct hit always wins)
# ===========================================================================

def test_field_map_alias_adds_a_match() -> None:
    rule = _rule("  sel:\n    CommandLine|contains: mimikatz")
    ev = _ev(cmdline="invoke-mimikatz")                 # aliased field name
    assert rule_matches_event(rule, ev) is False                        # no map -> v1 behaviour
    assert rule_matches_event(rule, ev, field_map=default_field_map()) is True


def test_field_map_direct_field_hit_wins_over_alias() -> None:
    rule = _rule("  sel:\n    CommandLine|contains: evil")
    # Direct CommandLine present (benign) AND aliased cmdline present (evil):
    ev = _ev(CommandLine="benign", cmdline="evil.exe")
    # the direct field wins, so this must NOT match even with the map (fallback only).
    assert rule_matches_event(rule, ev, field_map=default_field_map()) is False


def test_field_map_none_is_byte_identical() -> None:
    rule = _rule("  sel:\n    EventID: 4688")
    ev = _ev(event_id=4688)                             # only the aliased name present
    assert rule_matches_event(rule, ev) is False        # default: no mapping, missing field


# ===========================================================================
# 5. logsource resolution + opt-in channel narrowing
# ===========================================================================

def test_logsource_channels_resolution() -> None:
    assert logsource_channels({"product": "windows"}) == frozenset({"windows"})
    assert "windows" in (logsource_channels({"category": "process_creation"}) or frozenset())
    assert logsource_channels({"product": "nonsense"}) is None       # unknown -> applies everywhere
    assert logsource_channels("not a dict") is None
    assert logsource_channels({}) is None


def test_match_logsource_narrows_to_resolved_channels() -> None:
    rule = parse_sigma_rule(
        "title: t\nid: r\nauthor: A\nlicense: MIT\n"
        "logsource:\n  product: windows\n"
        "detection:\n  sel:\n    EventID: 4688\n  condition: sel")
    win_ev = _ev(channel="windows", EventID=4688)
    syslog_ev = _ev(channel="syslog", EventID=4688)
    # default (match_logsource=False): fires on both channels (byte-identical v1)
    assert evaluate_events([rule], [syslog_ev]).matched_rule_ids == ["r"]
    # opt-in: a windows rule does NOT fire on a syslog-channel event...
    assert evaluate_events([rule], [syslog_ev], match_logsource=True).matched_rule_ids == []
    # ...but still fires on the windows-channel event.
    assert evaluate_events([rule], [win_ev], match_logsource=True).matched_rule_ids == ["r"]


def test_match_logsource_unknown_logsource_does_not_narrow() -> None:
    rule = parse_sigma_rule(
        "title: t\nid: r\nauthor: A\nlicense: MIT\n"
        "logsource:\n  product: mystery\n"
        "detection:\n  sel:\n    EventID: 4688\n  condition: sel")
    ev = _ev(channel="anything", EventID=4688)
    # unresolvable logsource -> applies everywhere, so it still fires even with narrowing on.
    assert evaluate_events([rule], [ev], match_logsource=True).matched_rule_ids == ["r"]


# ===========================================================================
# 6. v1 byte-identical — the headline guarantee
# ===========================================================================

_V1_SQLI = """
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
"""


def test_v1_default_path_is_byte_identical() -> None:
    """A value with NO wildcard metacharacter, no field_map, match_logsource=False must behave
    exactly as the pre-v2 engine: plain equality is still exact + case-insensitive, and the
    documented v1 matches/techniques are unchanged."""
    # (a) plain equality unchanged: exact (case-insensitive) match only.
    eq_rule = _rule("  sel:\n    Image: cmd.exe")
    assert rule_matches_event(eq_rule, _ev(Image="CMD.EXE")) is True     # case-insensitive, as v1
    assert rule_matches_event(eq_rule, _ev(Image="cmd.exe.bak")) is False  # NOT contains — exact
    assert rule_matches_event(eq_rule, _ev(Image="xcmd.exe")) is False

    # (b) the documented v1 ruleset result is reproduced on the default path.
    rule = parse_sigma_rule(_V1_SQLI)
    events = [_ev(cs_uri_query="hello"), _ev(cs_uri_query="x=UNION SELECT password")]
    res = evaluate_events([rule], events)
    assert res.matched_rule_ids == ["R-WEB-SQLI"]
    assert res.techniques_detected == ["T1190"]
    assert res.matches[0].event_index == 1
    assert rule_matches_event(rule, _ev(cs_uri_query="id=1' OR 1=1 -- ")) is True
    assert rule_matches_event(rule, _ev(cs_uri_query="id=1")) is False
