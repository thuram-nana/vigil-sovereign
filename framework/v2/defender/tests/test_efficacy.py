"""
Tests for defender.efficacy — the detection-efficacy signal + assembled purple-team DefenseReport.

The efficacy is derived from what the scan DID (its oracle-confirmed findings) — prove-don't-guess.
It answers "would the operator's Sigma ruleset catch this class of confirmed action?" mapped to
ATT&CK, and the assembled report also carries the DEL detection-gap analysis + candidate Sigma rules.
All read-only over the report — no traffic, no verdict change.
"""

from __future__ import annotations

from framework.v2.defender.efficacy import (
    attack_technique_for,
    build_defense_report,
    detection_efficacy,
    detection_rule_to_sigma,
    scan_action_descriptors,
    scan_action_events,
)
from framework.v2.defender.gap_report import synthesize_rule
from framework.v2.defender.models import ActionKind
from framework.v2.defender.sigma import parse_sigma_rule
from framework.v2.defender.telemetry import model_telemetry


class _F:
    def __init__(self, bug_class: str, endpoint: str = "", param: str = "q") -> None:
        self.bug_class = bug_class
        self.endpoint = endpoint
        self.insertion_point = f"query:{param}"
        self.param = param


class _Report:
    def __init__(self, findings, target="http://t/") -> None:
        self.target = target
        self.active_findings = list(findings)


_SIGMA_SQLI = """
title: SQLi in query
id: R-SQLI
detection:
  selection:
    cs_uri_query|contains:
      - "OR 1=1"
      - "UNION SELECT"
  condition: selection
tags: [attack.t1190]
level: high
"""


# --- deriving what the scan DID --------------------------------------------

def test_scan_action_descriptors_map_bug_class_to_kind() -> None:
    rep = _Report([_F("sqli", "http://t/s?q=1"), _F("auth_bypass"), _F("exposure")])
    kinds = [d.kind for d in scan_action_descriptors(rep)]
    assert kinds == [ActionKind.INJECTION_PROBE, ActionKind.LOGIN_ATTEMPT, ActionKind.HTTP_REQUEST]


def test_scan_action_descriptor_carries_injection_telemetry() -> None:
    # an injection descriptor must produce a WAF signal the default ruleset can key on
    d = scan_action_descriptors(_Report([_F("sqli", "http://t/s?q=1")]))[0]
    channels = {s.channel for s in model_telemetry(d)}
    assert "waf" in channels


def test_scan_action_events_have_payload_marker_in_query() -> None:
    ev = scan_action_events(_Report([_F("sqli", "http://t/search?q=1")]))[0]
    assert ev.channel == "webproxy"
    assert "OR 1=1" in str(ev.fields["cs_uri_query"])
    assert ev.fields["attack_technique"] == "T1190"
    assert ev.fields["cs_uri_stem"] == "http://t/search"      # query stripped from the stem


def test_attack_technique_mapping() -> None:
    assert attack_technique_for("sqli") == "T1190"
    assert attack_technique_for("xss") == "T1059.007"
    assert attack_technique_for("auth_bypass") == "T1078"
    assert attack_technique_for("totally_unknown_class") == "T1190"   # documented default


# --- efficacy --------------------------------------------------------------

def test_efficacy_catches_sqli_misses_xss() -> None:
    rep = _Report([_F("sqli", "http://t/s?q=1"), _F("xss", "http://t/p")])
    rule = parse_sigma_rule(_SIGMA_SQLI)
    eff = detection_efficacy(rep, [rule])
    assert eff.total == 2 and eff.detected_count == 1
    assert eff.efficacy == 0.5
    assert eff.techniques_covered == ["T1190"]
    assert eff.techniques_missed == ["T1059.007"]
    # the sqli finding is the detected one, credited to the firing rule
    detected = [d for d in eff.per_finding if d.detected]
    assert detected and detected[0].bug_class == "sqli" and "R-SQLI" in detected[0].detected_by


def test_efficacy_zero_when_no_rule_fires() -> None:
    rep = _Report([_F("xss", "http://t/p")])
    eff = detection_efficacy(rep, [parse_sigma_rule(_SIGMA_SQLI)])
    assert eff.efficacy == 0.0 and eff.detected_count == 0


def test_efficacy_is_deterministic() -> None:
    rep = _Report([_F("sqli", "http://t/s?q=1"), _F("rce", "http://t/x")])
    rule = parse_sigma_rule(_SIGMA_SQLI)
    a = detection_efficacy(rep, [rule])
    b = detection_efficacy(rep, [rule])
    assert [(d.bug_class, d.detected) for d in a.per_finding] == \
           [(d.bug_class, d.detected) for d in b.per_finding]


# --- candidate rule -> Sigma round-trip ------------------------------------

def test_candidate_rule_renders_as_parseable_sigma() -> None:
    from framework.v2.defender import ActionDescriptor, ActionKind as AK
    # a directory brute-force under the default threshold produces a synthesized (string) rule
    d = ActionDescriptor(kind=AK.INJECTION_PROBE, target_surface="/search",
                         attributes={"inj_class": "sql_injection"})
    cand = synthesize_rule(model_telemetry(d))
    assert cand is not None
    sigma_text = detection_rule_to_sigma(cand)
    parsed = parse_sigma_rule(sigma_text)
    assert parsed is not None and parsed.id == cand.id       # renders to valid, re-parseable Sigma


# --- assembled defense report ----------------------------------------------

def test_build_defense_report_default_ruleset_flags_gaps() -> None:
    # no operator Sigma rules: still produces the DEL gap analysis + candidate rules
    rep = _Report([_F("sqli", "http://t/s?q=1")])
    dr = build_defense_report(rep)
    assert dr.target == "http://t/"
    assert len(dr.gaps) == 1
    assert dr.efficacy is None and dr.ingested is None


def test_build_defense_report_with_sigma_and_ingested() -> None:
    from framework.v2.defender.logsource import parse_syslog
    rep = _Report([_F("sqli", "http://t/s?q=1"), _F("xss", "http://t/p")])
    rule = parse_sigma_rule(_SIGMA_SQLI)
    ingested = parse_syslog("<38>Oct 11 22:14:15 h app: req cs_uri_query=\"x=UNION SELECT p\"")
    dr = build_defense_report(rep, sigma_rules=[rule], ingested_events=ingested)
    assert dr.efficacy is not None and dr.efficacy.efficacy == 0.5
    assert dr.ingested is not None and dr.ingested_events == 1
    # the report serializes to a plain dict for a spine/JSON sink
    d = dr.to_dict()
    assert d["efficacy"]["techniques_covered"] == ["T1190"]
    assert d["actions_modelled"] == 2


def test_build_defense_report_is_total_on_bad_report() -> None:
    class _Bad:
        target = "http://t/"
        # no active_findings attribute
    dr = build_defense_report(_Bad())
    assert dr.gaps == [] and dr.candidate_sigma == []
