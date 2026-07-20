"""
defender.rules — Sigma-style detection rules and the matching engine.

A `DetectionRuleset` evaluates signals and reports which rules fire. The
matching is small and explicit (no external Sigma runtime): a rule fires
when all its conditions hold against a single signal on the rule's
channel. Operators load their own ruleset to reflect their real SIEM;
the built-in `default_ruleset()` is a sensible baseline of well-known
detections, not a claim to model any specific product.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from ..common.errors import EvalError
from .models import ActionSignal, DetectionHit, DetectionRule, RuleCondition

_RULES_ADAPTER = TypeAdapter(list[DetectionRule])


def _coerce_number(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _condition_holds(cond: RuleCondition, signal: ActionSignal) -> bool:
    if cond.field not in signal.fields:
        return False
    actual = signal.fields[cond.field]
    op = cond.op
    if op == "eq":
        return str(actual) == str(cond.value)
    if op == "ne":
        return str(actual) != str(cond.value)
    if op == "contains":
        return str(cond.value) in str(actual)
    if op == "icontains":
        return str(cond.value).lower() in str(actual).lower()
    if op in ("gte", "lte"):
        a = _coerce_number(actual)
        b = _coerce_number(cond.value)
        if a is None or b is None:
            return False
        return a >= b if op == "gte" else a <= b
    if op == "in":
        choices = cond.value if isinstance(cond.value, list) else [cond.value]
        return str(actual) in {str(c) for c in choices}
    return False


def _rule_fires(rule: DetectionRule, signals: list[ActionSignal]) -> DetectionHit | None:
    for signal in signals:
        if signal.channel != rule.channel:
            continue
        if all(_condition_holds(c, signal) for c in rule.conditions):
            return DetectionHit(
                rule_id=rule.id,
                title=rule.title,
                channel=rule.channel,
                severity=rule.severity,
                why=rule.description,
            )
    return None


class DetectionRuleset:
    """A set of detection rules with an evaluation method."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self._rules = list(rules)

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules)

    def evaluate(self, signals: list[ActionSignal]) -> list[DetectionHit]:
        """Distinct rules that fire against the signals (one hit per rule)."""
        hits: list[DetectionHit] = []
        for rule in self._rules:
            hit = _rule_fires(rule, signals)
            if hit is not None:
                hits.append(hit)
        return hits

    @classmethod
    def from_file(cls, path: str | Path) -> "DetectionRuleset":
        p = Path(path).expanduser()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except OSError as e:
            raise EvalError(f"cannot read ruleset {p}: {e}") from e
        except json.JSONDecodeError as e:
            raise EvalError(f"ruleset {p} is not valid JSON: {e}") from e
        try:
            rules = _RULES_ADAPTER.validate_python(data)
        except ValidationError as e:
            raise EvalError(f"ruleset {p} is not a valid rule list: {e}") from e
        return cls(rules)


def default_ruleset() -> DetectionRuleset:
    """A baseline of well-known detections across the modelled channels."""
    return DetectionRuleset(
        [
            DetectionRule(
                id="R-WAF-INJECTION",
                title="Injection payload pattern at WAF",
                channel="waf",
                severity="high",
                conditions=[RuleCondition(field="category", op="icontains", value="injection")],
                description="A WAF/IDS injection signature is the kind that fires on "
                "this payload class; expect a high-fidelity alert.",
            ),
            DetectionRule(
                id="R-AUTH-BRUTE",
                title="Repeated authentication failures",
                channel="auth_log",
                severity="medium",
                conditions=[RuleCondition(field="failed_count", op="gte", value=5)],
                description="A burst of failed logins trips brute-force detections.",
            ),
            DetectionRule(
                id="R-WEB-DIRSCAN",
                title="Directory enumeration (404 burst)",
                channel="http_access_log",
                severity="medium",
                conditions=[RuleCondition(field="distinct_404", op="gte", value=20)],
                description="Many distinct 404s in a short window is a scan signature.",
            ),
            DetectionRule(
                id="R-NET-PORTSCAN",
                title="Port scan (connection fan-out)",
                channel="netflow",
                severity="medium",
                conditions=[RuleCondition(field="distinct_ports", op="gte", value=10)],
                description="Connection fan-out across many ports shows in flow data.",
            ),
            DetectionRule(
                id="R-UA-OBSIDIAN",
                title="OBSIDIAN authorised-test user agent",
                channel="http_access_log",
                severity="info",
                conditions=[RuleCondition(field="user_agent", op="icontains", value="obsidian")],
                description="EXPECTED to fire: the framework uses a recognisable UA on "
                "purpose so the operator can correlate its traffic (constitution § VI.4). "
                "This 'detection' is a feature, not a footprint to minimise.",
            ),
        ]
    )
