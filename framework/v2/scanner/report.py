"""
scanner.report — turn a ScanReport into an operator/CI deliverable.

A finding is only as useful as what the operator can do with it. This module
renders a :class:`~scanner.campaign.ScanReport` into three formats, each enriched
with remediation and a re-verification note so a finding carries not just "what"
but "so what" and "prove it":

  * **JSON**  — the full structured report (machine-consumable, stable schema).
  * **SARIF** — SARIF 2.1.0 for CI/CD and code-scanning ingestion (GitHub, etc.):
    one rule per bug class, one result per finding, severity mapped to
    error/warning/note.
  * **HTML**  — a self-contained human report: an executive severity summary and
    a per-finding technical section.

Enrichment is honest: remediation and CWE references are looked up from the
declarative library by the check that produced the finding (falling back to a
per-class default), and every oracle-confirmed active finding is flagged
``re_verifiable`` because it carries the deterministic ``oracle_context``
certificate the ``verify`` re-verifier can re-run offline. This module renders
already-collected results; it sends nothing.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from typing import Any

from .campaign import ScanReport

# Per-class fallback remediation + CWE + severity for built-in checks that are not
# library entries. Library-produced findings prefer the entry's own metadata.
_CLASS_META: dict[str, tuple[str, str, list[str]]] = {
    "boolean_sqli": ("High", "Use parameterised queries / prepared statements.", ["CWE-89"]),
    "time_based_sqli": ("High", "Use parameterised queries; never build SQL from input.", ["CWE-89"]),
    "error_based_sqli": ("High", "Use parameterised queries; disable verbose DB errors.", ["CWE-89"]),
    "sqli": ("High", "Use parameterised queries / prepared statements.", ["CWE-89"]),
    "nosqli": ("High", "Validate/segregate operators; use typed queries.", ["CWE-943"]),
    "xss": ("High", "Context-aware output encoding + a strict CSP.", ["CWE-79"]),
    "dom_xss": ("High", "Avoid dangerous sinks (innerHTML/eval) on untrusted DOM sources; use safe APIs + CSP.", ["CWE-79"]),
    "ssti": ("Critical", "Never render user input as template source; use a sandbox.", ["CWE-1336"]),
    "ssrf": ("High", "Allowlist egress destinations; block internal ranges + metadata IPs.", ["CWE-918"]),
    "blind_xxe": ("High", "Disable external entities/DTDs in the XML parser.", ["CWE-611"]),
    "xxe": ("High", "Disable external entities/DTDs in the XML parser.", ["CWE-611"]),
    "command_injection": ("Critical", "Avoid shell calls; use argv APIs; validate input.", ["CWE-78"]),
    "deserialization": ("Critical", "Do not deserialise untrusted data; use safe formats.", ["CWE-502"]),
    "rce": ("Critical", "Eliminate the code-execution sink; validate + sandbox.", ["CWE-94"]),
    "path_traversal": ("High", "Canonicalise + confine paths to an allowlisted root.", ["CWE-22"]),
    "lfi": ("High", "Do not build file paths from input; allowlist.", ["CWE-98"]),
    "cors": ("Medium", "Reflect only allowlisted origins; do not combine * with credentials.", ["CWE-942"]),
    "host_header_injection": ("Medium", "Validate Host against an allowlist; use absolute config URLs.", ["CWE-644"]),
    "open_redirect": ("Medium", "Allowlist redirect targets; do not redirect to raw input.", ["CWE-601"]),
    "jwt": ("High", "Reject alg=none; verify signatures with a fixed algorithm.", ["CWE-347"]),
    "exposure": ("High", "Remove/authenticate the exposed resource; rotate any leaked secrets.", ["CWE-200"]),
    "idor": ("High", "Enforce object-level authorization on every reference.", ["CWE-639"]),
    "request_smuggling": ("High", "Normalise/reject ambiguous Content-Length/Transfer-Encoding.", ["CWE-444"]),
}

_SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1, "Confirmed": 4}
_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}


@dataclass
class ReportFinding:
    kind: str            # active | passive | dom_xss_candidate
    bug_class: str
    title: str
    severity: str
    confidence: str
    location: str
    confirmed_by: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    re_verifiable: bool = False


def _library_index() -> dict[str, Any]:
    """{entry_id: entry} for remediation/severity/reference lookup. Best-effort:
    a library that fails to load just yields the per-class fallback."""
    try:
        from .library import load_library
        return {e.id: e for e in load_library()}
    except Exception:
        return {}


def _meta_for(check_id: str, bug_class: str, lib: dict[str, Any]) -> tuple[str, str, list[str]]:
    """(severity, remediation, references) — from the library entry that produced
    the finding when available, else the per-class default, else a generic High."""
    entry = lib.get(check_id)
    if entry is not None:
        return entry.severity, entry.remediation or "", list(entry.references)
    if bug_class in _CLASS_META:
        sev, rem, refs = _CLASS_META[bug_class]
        return sev, rem, refs
    return "High", "", []


def _serialize_attack_paths(attack_paths: list | None) -> list[dict]:
    """Serialize forward-reasoning attack paths (duck-typed AttackPath objects from
    scanner.orchestrator) into stable dicts — no import, so report.py stays
    decoupled from the reasoning layer. Each path is the attacker->crown-jewel route
    the confirmed facts unlock, every hop tagged with the technique that made it."""
    out: list[dict] = []
    for ap in attack_paths or []:
        out.append({
            "destination": ap.destination,
            "hops": ap.hops,
            "detection_cost": ap.detection_cost,
            "description": ap.describe(),
            "steps": [
                {"src": s.src, "edge": s.edge, "dst": s.dst, "technique": s.technique}
                for s in ap.steps
            ],
        })
    return out


def build_report(report: ScanReport, *, attack_paths: list | None = None) -> dict:
    """Normalise a ScanReport into a stable, enriched report document.

    ``attack_paths`` (the forward reasoning from :func:`engage.run_engagement` /
    :class:`scanner.orchestrator.AutonomousCampaign`) is optional: when present, the
    document gains an ``attack_paths`` array — the multi-hop routes the confirmed
    findings unlock — so a machine consumer (CI, a dashboard) sees not just isolated
    findings but the chains they compose into."""
    lib = _library_index()
    findings: list[ReportFinding] = []

    for f in report.active_findings:
        sev, rem, refs = _meta_for(f.check_id, f.bug_class, lib)
        findings.append(ReportFinding(
            kind="active", bug_class=f.bug_class,
            title=f"{f.bug_class} confirmed at {f.param}",
            severity=sev, confidence=f"{f.confidence:.2f}",
            location=f"{report.target}  [{f.insertion_point}]",
            confirmed_by=f.confirmed_by, evidence=f.rationale,
            remediation=rem, references=refs,
            re_verifiable=f.oracle_context is not None,
        ))
    for p in report.passive_findings:
        _, rem, refs = _meta_for("", getattr(p, "bug_class", ""), lib)
        findings.append(ReportFinding(
            kind="passive", bug_class=getattr(p, "bug_class", "passive"),
            title=p.title, severity=p.severity, confidence=p.confidence,
            location=p.url, confirmed_by="passive", evidence=p.evidence,
            remediation=rem, references=refs,
        ))
    for c in report.dom_xss_candidates:
        findings.append(ReportFinding(
            kind="dom_xss_candidate", bug_class="dom_xss",
            title=f"DOM-XSS candidate: {c.source} -> {c.sink}",
            severity="Info", confidence=c.confidence, location=report.target,
            confirmed_by="static-lead", evidence=c.evidence,
            remediation=_CLASS_META["dom_xss"][1], references=_CLASS_META["dom_xss"][2],
        ))

    findings.sort(key=lambda x: (-_SEVERITY_RANK.get(x.severity, 0), x.kind, x.bug_class))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return {
        "tool": "CRUCIBLE",
        "target": report.target,
        "summary": {
            "pages_crawled": report.pages_crawled,
            "requests_audited": report.requests_audited,
            "confirmed": len(report.active_findings),
            "passive": len(report.passive_findings),
            "dom_xss_candidates": len(report.dom_xss_candidates),
            "discovered_endpoints": len(report.discovered_endpoints),
            "by_severity": counts,
        },
        "fingerprint": sorted(report.fingerprint.tokens) if report.fingerprint else [],
        "discovered_endpoints": list(report.discovered_endpoints),
        "findings": [f.__dict__ for f in findings],
        "attack_paths": _serialize_attack_paths(attack_paths),
    }


def to_json(report: ScanReport, *, attack_paths: list | None = None, indent: int | None = 2) -> str:
    return json.dumps(
        build_report(report, attack_paths=attack_paths),
        indent=indent, sort_keys=False, ensure_ascii=False,
    )


def to_sarif(report: ScanReport) -> str:
    """SARIF 2.1.0 — one rule per bug class, one result per finding."""
    doc = build_report(report)
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in doc["findings"]:
        rule_id = f["bug_class"]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f["title"]},
                "helpUri": "",
                "properties": {"cwe": f["references"], "remediation": f["remediation"]},
            }
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f"{f['title']} — {f['evidence']}".strip(" —")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["location"]}}}],
            "properties": {
                "kind": f["kind"], "confidence": f["confidence"],
                "confirmedBy": f["confirmed_by"], "reVerifiable": f["re_verifiable"],
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "CRUCIBLE",
                "informationUri": "https://github.com/Water-Hacker/PENTEST",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def to_html(report: ScanReport) -> str:
    """A self-contained human report: severity summary + per-finding cards."""
    doc = build_report(report)
    s = doc["summary"]
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(sev)}</td><td>{n}</td></tr>"
        for sev, n in sorted(s["by_severity"].items(), key=lambda kv: -_SEVERITY_RANK.get(kv[0], 0))
    ) or "<tr><td>none</td><td>0</td></tr>"
    cards = []
    for f in doc["findings"]:
        refs = ", ".join(e(r) for r in f["references"]) or "&mdash;"
        badge = "✓ re-verifiable" if f["re_verifiable"] else e(f["confirmed_by"])
        cards.append(
            f"<div class=card><h3>[{e(f['severity'])}] {e(f['title'])}</h3>"
            f"<p class=meta>{e(f['kind'])} · confirmed by <b>{badge}</b> · confidence {e(f['confidence'])}</p>"
            f"<p><b>Location:</b> <code>{e(f['location'])}</code></p>"
            f"<p><b>Evidence:</b> {e(f['evidence']) or '&mdash;'}</p>"
            f"<p><b>Remediation:</b> {e(f['remediation']) or '&mdash;'}</p>"
            f"<p class=refs><b>Refs:</b> {refs}</p></div>"
        )
    return f"""<!doctype html><html><head><meta charset=utf-8>
<title>CRUCIBLE report — {e(doc['target'])}</title><style>
body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111;max-width:60rem}}
h1{{margin:0 0 .2rem}} .sub{{color:#666}}
table{{border-collapse:collapse;margin:1rem 0}} td,th{{border:1px solid #ddd;padding:.3rem .7rem}}
.card{{border:1px solid #e3e3e3;border-left:4px solid #b00;border-radius:6px;padding:.6rem 1rem;margin:.8rem 0}}
.card h3{{margin:.2rem 0}} .meta{{color:#666;font-size:.85em}} .refs{{color:#666;font-size:.85em}}
code{{background:#f5f5f5;padding:.1rem .3rem;border-radius:3px}}
</style></head><body>
<h1>CRUCIBLE report</h1>
<p class=sub>{e(doc['target'])} · {s['confirmed']} confirmed · {s['passive']} passive · {s['dom_xss_candidates']} DOM-XSS leads · {s['discovered_endpoints']} endpoints</p>
<h2>Severity summary</h2><table><tr><th>Severity</th><th>Count</th></tr>{rows}</table>
<p class=sub>Every "confirmed" finding is oracle-adjudicated and marked re-verifiable — its certificate re-runs offline via <code>python3 -m framework.v2 verify</code>.</p>
<h2>Findings</h2>{''.join(cards) or '<p>No findings.</p>'}
</body></html>"""


def render(report: ScanReport, fmt: str = "json") -> str:
    """Render ``report`` in ``fmt`` (json | sarif | html)."""
    fmt = (fmt or "json").lower()
    if fmt == "json":
        return to_json(report)
    if fmt == "sarif":
        return to_sarif(report)
    if fmt == "html":
        return to_html(report)
    raise ValueError(f"unknown report format {fmt!r}; expected json|sarif|html")
