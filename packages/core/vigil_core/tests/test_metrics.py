"""W6-3 #454 — the stdlib-only OpenMetrics exposition (`vigil_core.metrics`).

Pins the invariants the plan requires and that both plane servers render on their `/metrics` route:

  * `/metrics` renders VALID OpenMetrics text — a mini parser here re-reads it (TYPE lines, samples,
    the terminating `# EOF`) and asserts the four DOMAIN counters
    (facts/leads/refusals/gate-denials) and a RED series (requests/errors/duration histogram) are all
    present, plus the process metrics (rss/fds/uptime).
  * The domain counters are FED from the business-counter snapshot (the `telemetry.collect_snapshot`
    shape) — the JSON snapshot is the only thing that existed before this change.
  * NEGATIVE CONTROL — the gate-denial counter is not a no-op: a forced DENY through the REAL
    gate-of-record (`vigil_core.gate.conjunctive_decide`) increments `vigil_gate_denials_total` and is
    reflected in a fresh render, AND crosses the example alert rule's threshold (the harness reads
    `infra/observability/vigil-alerts.yml`); a non-deny verdict (allow / queue) does NOT increment it and
    does NOT fire the alert.

STDLIB ONLY — this runs in the `vigil_core — shared integrity substrate` required CI job, which installs
only the hash-locked runtime + pytest. It imports NO framework/sigil/strix and reads no yaml library (the
alert file is parsed with a small regex), so it stays inside that job's dependency closure.

Run: pytest packages/core/vigil_core/tests/test_metrics.py -q
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from vigil_core.gate import CrucibleResult, conjunctive_decide
from vigil_core.metrics import (
    CONTENT_TYPE,
    MetricsRegistry,
    record_gate_verdict,
)

REPO = Path(__file__).resolve().parents[4]
ALERTS = REPO / "infra" / "observability" / "vigil-alerts.yml"
DASHBOARD = REPO / "infra" / "observability" / "vigil-dashboard.json"


# --------------------------------------------------------------------------------------------------
# A minimal OpenMetrics text parser — enough to re-read what render() produced and assert on it.
# --------------------------------------------------------------------------------------------------
def parse_openmetrics(text: str) -> dict:
    """Return {"types": {family: type}, "samples": {full_name: {frozenset(label items): value}}, "eof": bool}.
    Deliberately strict about the shape render() is contracted to produce (so a regression is caught)."""
    types: dict[str, str] = {}
    samples: dict[str, dict] = {}
    eof = False
    sample_re = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)$")
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line:
            continue
        if line == "# EOF":
            eof = True
            continue
        if line.startswith("# TYPE "):
            _, _, rest = line.partition("# TYPE ")
            name, _, mtype = rest.partition(" ")
            types[name] = mtype
            continue
        if line.startswith("#"):
            continue
        m = sample_re.match(line)
        assert m, f"unparseable OpenMetrics sample line: {line!r}"
        name, labelblob, value = m.group(1), m.group(2) or "", m.group(3)
        labels = {}
        if labelblob:
            for pair in labelblob.strip("{}").split(","):
                if not pair:
                    continue
                k, _, v = pair.partition("=")
                labels[k] = v.strip('"')
        samples.setdefault(name, {})[frozenset(labels.items())] = float(value)
    return {"types": types, "samples": samples, "eof": eof}


def _some(samples: dict, name: str) -> float:
    """Any one sample value for a family sample-name (there is at most one per plane in these tests)."""
    assert name in samples, f"missing series {name}"
    return next(iter(samples[name].values()))


# --------------------------------------------------------------------------------------------------
# render() produces valid OpenMetrics with RED + process + the four domain series
# --------------------------------------------------------------------------------------------------
def test_render_is_valid_openmetrics_with_red_process_and_domain():
    reg = MetricsRegistry(plane="offense")
    reg.observe_request(duration_s=0.02, method="GET", status=200)
    reg.observe_request(duration_s=3.0, method="POST", status=503)
    # domain counters FED FROM THE BUSINESS SNAPSHOT (the collect_snapshot shape).
    reg.update_domain_from_snapshot({"totals": {"facts": 5, "leads": 9, "refusals": 4}})

    parsed = parse_openmetrics(reg.render())
    assert parsed["eof"], "exposition must terminate with # EOF"

    # the four DOMAIN counters are present (this is the AC's domain-counter assertion).
    assert _some(parsed["samples"], "vigil_facts_total") == 5.0
    assert _some(parsed["samples"], "vigil_leads_total") == 9.0
    assert _some(parsed["samples"], "vigil_refusals_total") == 4.0
    assert "vigil_gate_denials_total" in parsed["samples"]

    # a RED series is present (Rate + Errors + Duration histogram).
    assert "vigil_requests_total" in parsed["samples"]
    assert "vigil_request_errors_total" in parsed["samples"]
    assert parsed["types"].get("vigil_request_duration_seconds") == "histogram"
    assert "vigil_request_duration_seconds_bucket" in parsed["samples"]
    assert "vigil_request_duration_seconds_sum" in parsed["samples"]
    assert _some(parsed["samples"], "vigil_request_duration_seconds_count") == 2.0

    # process metrics are present.
    assert "vigil_process_resident_memory_bytes" in parsed["samples"]
    assert "vigil_process_open_fds" in parsed["samples"]
    assert "vigil_process_uptime_seconds" in parsed["samples"]

    # every family carries a declared TYPE.
    for fam in ("vigil_requests", "vigil_request_errors", "vigil_facts", "vigil_leads",
                "vigil_refusals", "vigil_gate_denials"):
        assert parsed["types"].get(fam) == "counter", f"{fam} not typed counter"


def test_content_type_is_openmetrics():
    assert CONTENT_TYPE.startswith("application/openmetrics-text")


def test_error_counter_only_counts_5xx():
    reg = MetricsRegistry(plane="offense")
    reg.observe_request(duration_s=0.01, method="GET", status=200)
    reg.observe_request(duration_s=0.01, method="GET", status=404)  # a 4xx is NOT an error
    assert reg.value("vigil_request_errors_total", {"method": "GET", "plane": "offense"}) == 0.0
    reg.observe_request(duration_s=0.01, method="GET", status=500)
    assert reg.value("vigil_request_errors_total", {"method": "GET", "plane": "offense"}) == 1.0


# --------------------------------------------------------------------------------------------------
# The alert-rule harness: parse the shipped example rule and evaluate its condition on the metrics.
# --------------------------------------------------------------------------------------------------
def _alert_rule(alert_name: str) -> dict:
    """Extract one alert rule (name → {expr, metric, op, threshold}) from the shipped YAML WITHOUT a yaml
    library — a small regex over the `- alert:`/`expr:` lines, matching the metric+comparator+threshold in
    the expr. Enough for the harness to evaluate the rule's firing condition against a scrape."""
    text = ALERTS.read_text(encoding="utf-8")
    # find the block after `- alert: <name>` up to the next `- alert:` or EOF
    blocks = re.split(r"(?m)^\s*- alert:\s*", text)
    for b in blocks[1:]:
        name = b.splitlines()[0].strip()
        if name != alert_name:
            continue
        expr = ""
        m = re.search(r"expr:\s*(.+)", b)
        if m:
            expr = m.group(1).strip()
        cmp = re.search(r"(vigil_[a-z_]+)\b.*?([<>]=?|==)\s*([0-9.]+)", expr)
        assert cmp, f"could not parse a comparator out of expr: {expr!r}"
        return {"expr": expr, "metric": cmp.group(1), "op": cmp.group(2),
                "threshold": float(cmp.group(3))}
    raise AssertionError(f"alert rule {alert_name!r} not found in {ALERTS}")


def _fires(op: str, value: float, threshold: float) -> bool:
    return {">": value > threshold, ">=": value >= threshold,
            "<": value < threshold, "<=": value <= threshold,
            "==": value == threshold}[op]


def test_forced_gate_denial_increments_counter_and_fires_alert():
    """NEGATIVE CONTROL. A forced DENY through the REAL gate-of-record bumps the gate-denial counter, the
    render reflects it, and the shipped VigilGateDenialSpike rule fires on the observed increase — while a
    non-deny verdict neither increments the counter nor fires the alert."""
    reg = MetricsRegistry(plane="offense")
    rule = _alert_rule("VigilGateDenialSpike")
    assert rule["metric"] == "vigil_gate_denials_total"

    labels = {"plane": "offense"}
    before = reg.value("vigil_gate_denials_total", labels)
    # the alert must NOT fire before any denial (increase == 0).
    assert not _fires(rule["op"], before - before, rule["threshold"])

    # a QUEUE verdict (allowed False, but NOT a deny) must NOT be counted as a denial.
    queue_verdict = conjunctive_decide(
        crucible_authorize=lambda: CrucibleResult(True, "in envelope"),
        warden_decide=lambda: SimpleNamespace(outcome="queue", tool="curl", reason="needs approval"),
    )
    assert queue_verdict.outcome == "queue"
    record_gate_verdict(queue_verdict, registry=reg)
    assert reg.value("vigil_gate_denials_total", labels) == before, "a queue is not a denial"

    # a real DENY through the real gate (CRUCIBLE allows, WARDEN denies) — a forced gate denial.
    deny_verdict = conjunctive_decide(
        crucible_authorize=lambda: CrucibleResult(True, "in envelope"),
        warden_decide=lambda: SimpleNamespace(outcome="deny", tool="rm", reason="hard denylist"),
    )
    assert deny_verdict.allowed is False and deny_verdict.outcome == "deny"
    record_gate_verdict(deny_verdict, registry=reg)

    after = reg.value("vigil_gate_denials_total", labels)
    assert after == before + 1.0, "a forced DENY must increment the gate-denial counter"

    # the shipped alert rule fires on the observed increase (a stand-in for increase(...[5m]) across scrapes).
    assert _fires(rule["op"], after - before, rule["threshold"]), \
        "VigilGateDenialSpike must fire after a denial"


def test_record_gate_verdict_returns_verdict_unchanged_and_is_total():
    reg = MetricsRegistry(plane="offense")
    v = conjunctive_decide(
        crucible_authorize=lambda: CrucibleResult(True, "ok"),
        warden_decide=lambda: SimpleNamespace(outcome="auto", tool="cat", reason="A0"),
    )
    assert record_gate_verdict(v, registry=reg) is v          # returned unchanged (inline-wrappable)
    assert reg.value("vigil_gate_denials_total", {"plane": "offense"}) == 0.0  # an allow is not a denial
    assert record_gate_verdict(None, registry=reg) is None      # total on garbage
    assert record_gate_verdict(object(), registry=reg) is not None


def test_shipped_artifacts_exist_and_parse():
    import json
    assert ALERTS.is_file(), "example alert rules must ship"
    assert "VigilGateDenialSpike" in ALERTS.read_text(encoding="utf-8")
    assert DASHBOARD.is_file(), "example dashboard must ship"
    json.loads(DASHBOARD.read_text(encoding="utf-8"))  # valid JSON


def test_update_domain_from_snapshot_is_total_on_garbage():
    reg = MetricsRegistry(plane="offense")
    reg.update_domain_from_snapshot(None)
    reg.update_domain_from_snapshot({"totals": "not-a-dict"})
    reg.update_domain_from_snapshot("garbage")
    # all still zero, nothing raised
    assert reg.value("vigil_facts_total", {"plane": "offense"}) == 0.0
