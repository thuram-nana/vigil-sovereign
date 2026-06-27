"""Tests for defender.telemetry and defender.rules."""

from __future__ import annotations

from ..models import ActionDescriptor, ActionKind, ActionSignal, DetectionRule, RuleCondition
from ..rules import DetectionRuleset, default_ruleset
from ..telemetry import model_telemetry


# ---- telemetry ------------------------------------------------------------


def test_http_request_emits_access_log() -> None:
    sig = model_telemetry(ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/x"))
    assert len(sig) == 1
    assert sig[0].channel == "http_access_log"
    assert sig[0].fields["path"] == "/x"


def test_injection_probe_emits_waf_signal() -> None:
    sigs = model_telemetry(
        ActionDescriptor(kind=ActionKind.INJECTION_PROBE, target_surface="/search")
    )
    channels = {s.channel for s in sigs}
    assert "waf" in channels and "http_access_log" in channels


def test_login_attempt_emits_auth_log_with_failed_count() -> None:
    sigs = model_telemetry(
        ActionDescriptor(
            kind=ActionKind.LOGIN_ATTEMPT, attributes={"failed_count": "7"}
        )
    )
    auth = [s for s in sigs if s.channel == "auth_log"][0]
    assert auth.fields["failed_count"] == 7


def test_port_scan_emits_netflow() -> None:
    sigs = model_telemetry(
        ActionDescriptor(kind=ActionKind.PORT_SCAN, attributes={"distinct_ports": "50"})
    )
    assert sigs[0].channel == "netflow"
    assert sigs[0].fields["distinct_ports"] == 50


# ---- rules ----------------------------------------------------------------


def test_injection_fires_waf_rule() -> None:
    sigs = model_telemetry(ActionDescriptor(kind=ActionKind.INJECTION_PROBE, target_surface="/s"))
    hits = default_ruleset().evaluate(sigs)
    assert any(h.rule_id == "R-WAF-INJECTION" for h in hits)


def test_brute_force_threshold() -> None:
    rs = default_ruleset()
    low = model_telemetry(ActionDescriptor(kind=ActionKind.LOGIN_ATTEMPT, attributes={"failed_count": "3"}))
    high = model_telemetry(ActionDescriptor(kind=ActionKind.LOGIN_ATTEMPT, attributes={"failed_count": "9"}))
    assert not any(h.rule_id == "R-AUTH-BRUTE" for h in rs.evaluate(low))
    assert any(h.rule_id == "R-AUTH-BRUTE" for h in rs.evaluate(high))


def test_obsidian_ua_rule_fires_as_expected() -> None:
    sigs = model_telemetry(ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/x"))
    hits = default_ruleset().evaluate(sigs)
    ua = [h for h in hits if h.rule_id == "R-UA-OBSIDIAN"]
    assert ua and ua[0].severity == "info"  # intended, not a footprint


def test_one_hit_per_rule() -> None:
    # Two signals that both match the same rule still yield one hit.
    rule = DetectionRule(
        id="R-T", title="t", channel="http_access_log", severity="low",
        conditions=[RuleCondition(field="status", op="eq", value=404)],
    )
    rs = DetectionRuleset([rule])
    sigs = [
        ActionSignal(channel="http_access_log", fields={"status": 404}),
        ActionSignal(channel="http_access_log", fields={"status": 404}),
    ]
    assert len(rs.evaluate(sigs)) == 1


def test_condition_ops() -> None:
    sig = ActionSignal(channel="c", fields={"n": 10, "s": "hello-world"})
    rs = DetectionRuleset(
        [
            DetectionRule(id="gte", title="t", channel="c", conditions=[RuleCondition(field="n", op="gte", value=10)]),
            DetectionRule(id="lte-fail", title="t", channel="c", conditions=[RuleCondition(field="n", op="lte", value=5)]),
            DetectionRule(id="contains", title="t", channel="c", conditions=[RuleCondition(field="s", op="contains", value="world")]),
            DetectionRule(id="missing", title="t", channel="c", conditions=[RuleCondition(field="absent", op="eq", value="x")]),
        ]
    )
    fired = {h.rule_id for h in rs.evaluate([sig])}
    assert fired == {"gte", "contains"}
