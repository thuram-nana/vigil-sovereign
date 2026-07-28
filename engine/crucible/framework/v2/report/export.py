"""
report.export — deterministic SARIF 2.1.0 + structured JSON exporters.

The Markdown renderers (``report.generate``) speak to humans; these two speak to
machines — a CI code-scanning ingest (SARIF 2.1.0) and any structured consumer
(a dashboard, a diff, an archival record) (JSON). Both are NEW renderers ALONGSIDE
the Markdown ones: they consume the SAME graded-findings input, so a document and
an export grade a finding identically, and neither can promote a claim the oracle
refused.

Prove-don't-guess is carried into the machine formats, not just the prose:

  * Every exported finding states its ``grounding`` — ``fact`` (its retained oracle
    proof re-fired at export time), ``demoted`` (recorded oracle-confirmed but the
    proof no longer reproduces), or ``lead`` (no deterministic oracle signal).
  * A FACT carries its re-runnable certificate reference (the sha256 of its retained
    ``oracle_context``), its confirming oracle kind, and its calibrated (never 1.0)
    confidence — the same provenance the technical Markdown report shows.
  * In SARIF, only a FACT is levelled by its severity; a LEAD is capped at ``note``
    and tagged ``grounding=lead`` so a CI gate is never *blocked* by an unproven lead
    yet still sees it. The honest default: the export states what re-executes.

Purity + determinism: each exporter is a pure function of the graded findings + a
small ``ReportMeta``. There is no wallclock and no RNG on this path — with
``ReportMeta.generated_at`` unset (the default) the same findings export
byte-identically every time. Read-only over findings; sends no traffic.
"""

from __future__ import annotations

import json
from typing import Iterable

from .generate import (
    ReportMeta,
    _remediation_for,
    _severity_counts,
    _split,
)
from .grounding import GRADE_DEMOTED, GradedFinding, grade_findings
from .howto import howto_export
from .priority import effort_size, prioritize, priority_score

# Tool identity, shared with the scanner export so a CI consumer sees one producer.
_TOOL_NAME = "CRUCIBLE"
_TOOL_URI = "https://github.com/thuram-nana/PENTEST"
_JSON_SCHEMA = "crucible.report/v1"
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Severity → SARIF result level. Applied ONLY to a proven fact; a lead is capped at
# "note" (see ``_sarif_level``) so an unproven finding never blocks a CI gate.
_SARIF_LEVEL: dict[str, str] = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "note",
}


def _grounding_label(g: GradedFinding) -> str:
    """The small, stable export vocabulary for a grade: fact | demoted | lead."""
    if g.is_fact:
        return "fact"
    if g.grade == GRADE_DEMOTED:
        return "demoted"
    return "lead"


def _sarif_level(g: GradedFinding) -> str:
    """A proven fact is levelled by its (context-adjusted) severity; an unproven lead is
    capped at ``note`` so a CI gate keyed on error/warning is never blocked by something
    no oracle confirmed. The finding is still emitted, tagged ``grounding``."""
    if not g.is_fact:
        return "note"
    return _SARIF_LEVEL.get(g.finding.severity, "warning")


def _cvss(g: GradedFinding) -> dict | None:
    f = g.finding
    if not f.cvss_vector and f.cvss_base is None:
        return None
    out: dict = {}
    if f.cvss_vector:
        out["vector"] = f.cvss_vector
    if f.cvss_base is not None:
        out["base"] = f.cvss_base
    return out


def _provenance(g: GradedFinding) -> dict:
    """The finding's grounding provenance. A FACT carries its oracle kind, calibrated
    confidence and re-runnable certificate digest (populated only for a fact by the
    grader); a lead carries the reason it is unproven. Never dresses a lead in a fact's
    provenance — those fields are ``None`` for a lead."""
    f = g.finding
    return {
        "grounding": _grounding_label(g),
        "is_fact": g.is_fact,
        "verified_by_oracle": bool(f.verified_by_oracle),
        "reason": g.reason,
        "oracle_kind": g.oracle_kind,
        "confidence": g.confidence,
        "certificate": (f"sha256:{g.certificate_digest}"
                        if g.certificate_digest else None),
        "derived_from_hypothesis": f.derived_from_hypothesis,
        "event_id": g.event_id,
    }


def _finding_dict(g: GradedFinding) -> dict:
    f = g.finding
    d: dict = {
        "slug": f.finding_slug,
        "title": f.title,
        "severity": f.severity,
        "bug_class": f.bug_class,
        "surface": f.surface,
        "summary": f.summary,
        "impact": f.impact,
        "grounding": _grounding_label(g),
        "remediation": _remediation_for(f.bug_class),
        "effort": effort_size(f.bug_class),
        "priority_score": priority_score(f.severity, f.bug_class),
        "provenance": _provenance(g),
        "how_to_verify": howto_export(g),
    }
    cvss = _cvss(g)
    if cvss is not None:
        d["cvss"] = cvss
    return d


def _grounding_counts(graded: Iterable[GradedFinding]) -> dict[str, int]:
    counts = {"fact": 0, "demoted": 0, "lead": 0}
    for g in graded:
        counts[_grounding_label(g)] += 1
    return counts


def _meta_block(meta: ReportMeta) -> dict:
    """The header block. ``generated_at`` is emitted ONLY when the operator set it — the
    sole non-deterministic input, opt-in, so the default export is reproducible."""
    block: dict = {"target": meta.target, "status": meta.status}
    if meta.window_start or meta.window_end:
        block["window"] = {"start": meta.window_start, "end": meta.window_end}
    if meta.generated_at:
        block["generated_at"] = meta.generated_at
    return block


def _ordered(graded: list[GradedFinding]) -> list[GradedFinding]:
    """Total, stable display order: facts before leads, then priority score desc, then
    finding slug — deterministic regardless of input order."""
    return sorted(
        graded,
        key=lambda g: (
            0 if g.is_fact else 1,
            -priority_score(g.finding.severity, g.finding.bug_class),
            g.finding.finding_slug,
        ),
    )


def build_export_doc(graded: list[GradedFinding], meta: ReportMeta | None = None) -> dict:
    """Normalise graded findings into the stable structured export document — the shared
    intermediate ``to_json`` renders and ``to_sarif`` draws its summary from. Pure +
    deterministic given ``meta``."""
    meta = meta or ReportMeta()
    facts, leads = _split(graded)
    prio = prioritize(graded)  # facts only, ranked
    return {
        "schema": _JSON_SCHEMA,
        "tool": {"name": _TOOL_NAME, "informationUri": _TOOL_URI},
        **_meta_block(meta),
        "summary": {
            "total": len(graded),
            "facts": len(facts),
            "leads": len(leads),
            "by_severity_fact": _severity_counts(facts),
            "by_severity_lead": _severity_counts(leads),
            "by_grounding": _grounding_counts(graded),
        },
        "findings": [_finding_dict(g) for g in _ordered(graded)],
        "priority_order": [
            {
                "rank": r.rank,
                "slug": r.graded.finding.finding_slug,
                "severity": r.graded.finding.severity,
                "effort": r.effort,
                "priority_score": r.score,
                "tier": r.tier,
            }
            for r in prio
        ],
    }


def to_json(graded: list[GradedFinding], meta: ReportMeta | None = None,
            *, indent: int | None = 2) -> str:
    """The structured JSON export (findings + certificates + provenance). Deterministic;
    insertion-ordered (not key-sorted) so the document reads top-down like the report."""
    return json.dumps(build_export_doc(graded, meta), indent=indent,
                      sort_keys=False, ensure_ascii=False)


def sarif_document(rules: Iterable[dict], results: Iterable[dict],
                   *, run_properties: dict | None = None) -> dict:
    """The ONE SARIF 2.1.0 dialect every CRUCIBLE export speaks — the single source of
    truth for the ``$schema`` id, the ``version``, and the tool-driver identity
    (``name`` / ``informationUri``), plus the run/tool envelope shape. Both the ``report``
    exporter (over graded :class:`GradedFinding`s) and the ``scan`` exporter
    (``scanner.report`` over a ``ScanReport``) build their OWN ``rules`` + ``results`` —
    their finding shapes genuinely differ (a graded ``Finding`` carries a slug/certificate/
    oracle-kind; a scan ``AuditFinding`` carries kind/confirmed_by/reVerifiable) — and pour
    them into THIS envelope, so ``scan --format sarif`` and ``report --format sarif`` emit
    the SAME dialect from the SAME producer and can never drift apart. ``run_properties``
    (a run-level ``properties`` block) is emitted between the tool and the results only when
    supplied. Pure + deterministic."""
    run: dict = {"tool": {"driver": {
        "name": _TOOL_NAME,
        "informationUri": _TOOL_URI,
        "rules": list(rules),
    }}}
    if run_properties is not None:
        run["properties"] = run_properties
    run["results"] = list(results)
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def to_sarif(graded: list[GradedFinding], meta: ReportMeta | None = None) -> str:
    """SARIF 2.1.0 — one rule per bug class, one result per finding. A proven fact is
    levelled by its severity; an unproven lead is capped at ``note`` and tagged
    ``grounding=lead``. Each result's properties carry the finding's grounding, its
    confirming oracle + calibrated confidence, and (for a fact) its certificate digest,
    so CI ingest sees the proof, not just the claim. The SARIF envelope + tool identity
    come from the shared :func:`sarif_document` dialect (also used by ``scan``)."""
    meta = meta or ReportMeta()
    doc = build_export_doc(graded, meta)
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for g in _ordered(graded):
        f = g.finding
        rule_id = f.bug_class or "unclassified"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"{rule_id} finding"},
                "helpUri": _TOOL_URI,
                "properties": {"remediation": _remediation_for(f.bug_class)},
            }
        prov = _provenance(g)
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(g),
            "message": {"text": f"{f.title} — {f.summary}".strip(" —") or f.title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.surface}}}],
            "properties": {
                "slug": f.finding_slug,
                "grounding": prov["grounding"],
                "verifiedByOracle": prov["verified_by_oracle"],
                "oracleKind": prov["oracle_kind"],
                "confidence": prov["confidence"],
                "certificate": prov["certificate"],
                "severity": f.severity,
                # Per-finding how-to-verify/test/patch. A LEAD's level is still capped at
                # "note" by _sarif_level; this only ADDS guidance, never lifts the level.
                "howToVerify": howto_export(g),
            },
        })
    sarif = sarif_document(
        rules.values(), results,
        run_properties={"target": doc["target"], "summary": doc["summary"]},
    )
    return json.dumps(sarif, indent=2, sort_keys=False, ensure_ascii=False)


# --- convenience wrappers that grade raw findings first (mirroring generate_reports) ---


def export_json(findings: Iterable, meta: ReportMeta | None = None,
                *, indent: int | None = 2) -> str:
    """Grade raw findings (or ``(finding, event_id)`` pairs), then JSON-export them."""
    return to_json(grade_findings(findings), meta, indent=indent)


def export_sarif(findings: Iterable, meta: ReportMeta | None = None) -> str:
    """Grade raw findings (or ``(finding, event_id)`` pairs), then SARIF-export them."""
    return to_sarif(grade_findings(findings), meta)
