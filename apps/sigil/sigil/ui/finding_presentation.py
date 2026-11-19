"""APEX PR-A — the tenant-scoped POSTURE + TRIAGE read projection (the presentation spine's consumer head).

A PURE, READ-ONLY roll-up of a customer's OWN proven findings into (1) a single posture score 0-100, (2) a
worst-first triage list, and (3) per-finding presentation — plain-language impact + standards chips + exact
remediation. It reads the certificate's SIGNED ``presentation`` block when the engine minted one (so the
plain-language impact + remediation the customer sees are exactly what governance signed), and renders the
standards chips + the deterministic impact×effort priority from the INERT ``vigil_core.standards_mirror``
(generated from the engine's own tables, drift-tested) — so this module NEVER imports the engine.

TENANT ISOLATION (the IDOR class) is STRUCTURAL and INHERITED, not re-implemented: the posture is computed
ONLY over :func:`assessments.all_findings_for_org`, which returns EXACTLY the org's own findings (its slug set
is derived server-side from its own ownership proofs; ``_customer_slug`` is a one-way hash of
``org_id\\x00host``, so another tenant's finding — and its presentation — is never in the set). This head does
no spine scan of its own and never takes a slug/host from the client, so it cannot leak a cross-tenant finding.

PROVEN ONLY: every finding :func:`assessments.all_findings_for_org` returns is an oracle-confirmed FACT (it
carries a certificate whose engagement slug is in the org's set). The posture + triage are therefore derived
ONLY from proven findings — never from an unproven lead, and never from a UI action or a notice.

HONESTY: a plain-language impact / remediation is shown ONLY when it was SIGNED into the certificate (the
``presentation`` block); for a finding minted before the feature existed, the standards chips + severity +
priority are still shown, but the plain-language fields are omitted rather than fabricated. Severity is the
sovereign ``finding_preview.derived_severity`` (the certificate's own value when present, else the conservative
class maximum) — the SAME estimate the preview uses, never presented as signed. No engine/model identifier is
ever shown.

FATAL-2: sovereign-side, stdlib + vigil_core + ui-local only; ``assert_no_offense`` at import.
"""
from __future__ import annotations

from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import standards_mirror as _sm  # noqa: E402  (the inert engine-table mirror; no framework import)

from . import assessments as _assess  # noqa: E402
from . import finding_preview as _fp  # noqa: E402

# Per-severity posture PENALTY weights (an HONEST, owner-ratifiable heuristic — never a measured fact). Keyed by
# the sovereign ``finding_preview`` severity vocabulary; ``unrated`` (no rating on file) is weighted between high
# and medium, exactly as ``finding_preview.SEVERITIES`` ranks it. Under-rating is the dangerous direction, so the
# weights are deliberately conservative (a confirmed critical dominates the score).
_PENALTY: "dict[str, int]" = {
    "critical": 45, "high": 22, "unrated": 12, "medium": 9, "low": 3, "info": 1,
}
# The posture floor/formula constant. posture = 10000 // (100 + total_penalty): 100 when there are no findings,
# strictly decreasing as findings/severity accumulate, bounded to 0-100 and computed in PURE INTEGER arithmetic
# (no float) so the score is byte-stable and reproducible.
_POSTURE_BASE = 100

# Map the sovereign (lower-case) severity to the engine-cased severity the mirrored priority tables key on. An
# ``unrated`` finding has no rating, so it is scored as Medium impact (while still ranking above medium in the
# worst-first order via the sovereign severity rank) — documented, never invented.
_ENGINE_SEVERITY: "dict[str, str]" = {
    "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info",
    "unrated": "Medium",
}


def _severity_rank(severity: str) -> int:
    """Worst-first rank for a sovereign severity (0 = most severe). Uses ``finding_preview.SEVERITIES`` so
    ``unrated`` ranks above medium; an unknown label sorts last."""
    try:
        return _fp.SEVERITIES.index(severity)
    except ValueError:
        return len(_fp.SEVERITIES)


def posture_score(findings: "list[dict]") -> int:
    """The 0-100 posture score for a set of PROVEN findings. 100 when there are none; strictly decreasing as
    findings/severity accumulate. PURE integer arithmetic (reproducible). An HONEST heuristic — see ``_PENALTY``."""
    penalty = 0
    for row in findings:
        if isinstance(row, dict):
            penalty += _PENALTY.get(_fp.derived_severity(row)[0], _PENALTY["unrated"])
    return _POSTURE_BASE * _POSTURE_BASE // (_POSTURE_BASE + penalty)


def _presentation_block(row: dict) -> "Optional[dict]":
    """The SIGNED presentation block on this finding's cert projection, or None (a finding minted before the
    feature, or a malformed block)."""
    pres = row.get("presentation")
    return pres if isinstance(pres, dict) and pres else None


def _controls(row: dict, pres: "Optional[dict]") -> "Optional[dict]":
    """The standards controls for a finding: the SIGNED controls when present AND non-empty (authoritative,
    tamper-evident), else the inert mirror's lookup by bug_class (so a pre-feature finding still shows chips,
    and a signed block that carries EMPTY controls can never HIDE a mapped class's standards — defence in depth
    against a presentation that tried to under-represent a finding). Never invents a mapping."""
    if isinstance(pres, dict):
        std = pres.get("standards")
        if isinstance(std, dict) and isinstance(std.get("controls"), dict) and std["controls"]:
            return std["controls"]
    return _sm.controls_for(str(row.get("bug_class") or ""))


def _triage_row(row: dict) -> "dict[str, Any]":
    """Project ONE proven finding into a triage entry (severity + priority + standards chips + the SIGNED
    plain-language impact / remediation when present). Pure; never fabricates a plain-language field."""
    sev, basis = _fp.derived_severity(row)
    bug_class = str(row.get("bug_class") or "")
    engine_sev = _ENGINE_SEVERITY.get(sev, "Medium")
    effort = _sm.effort_size(bug_class)
    tier = _sm.tier(engine_sev, effort)
    pres = _presentation_block(row)
    out: "dict[str, Any]" = {
        "finding_ref": str(row.get("finding_ref") or ""),
        "engagement_slug": row.get("engagement_slug"),
        "bug_class": bug_class,
        "surface": row.get("surface"),
        "title": _fp.derived_title(row),
        "severity": sev,
        "severity_basis": basis,            # "certificate" (signed) | "estimated" (sovereign class table)
        "priority_score": _sm.priority_score(engine_sev, bug_class),
        "effort": effort,
        "tier": tier,
        "tier_label": _sm.tier_label(tier),
        "standards_chips": _sm.standards_chips(_controls(row, pres)),
        "presentation_signed": pres is not None,
    }
    if pres is not None:
        # Plain-language impact + exact remediation are shown ONLY from the SIGNED block (what governance
        # signed), never improvised. Projected through a small allowlist so no unexpected cert field rides along.
        if isinstance(pres.get("plain_impact"), dict):
            out["plain_impact"] = pres["plain_impact"]
        if isinstance(pres.get("remediation"), str) and pres["remediation"]:
            out["remediation"] = pres["remediation"]
    return out


def _triage(findings: "list[dict]") -> "list[dict[str, Any]]":
    """Worst-first triage: the engine's remediation-roadmap order — highest severity first, then the deterministic
    impact×effort priority (a quick win sorts ahead), then the finding ref for a stable, total order."""
    rows = [_triage_row(f) for f in findings if isinstance(f, dict)]
    rows.sort(key=lambda r: (_severity_rank(r["severity"]), -float(r["priority_score"]), r["finding_ref"]))
    return rows


def _standards_summary(triage: "list[dict]") -> "dict[str, Any]":
    """The union of standards frameworks the org's proven findings implicate, with how many findings touch each —
    a compact coverage-implication summary (DATA, never a coverage assertion). Framework order is canonical."""
    counts: "dict[str, int]" = {}
    for r in triage:
        for chip in r.get("standards_chips", ()):
            fw = chip.get("framework")
            if fw:
                counts[fw] = counts.get(fw, 0) + 1
    frameworks = [
        {"framework": fw, "label": _sm.framework_label(fw), "version": _sm.standard_versions().get(fw, ""),
         "findings": counts[fw]}
        for fw in _sm.frameworks() if fw in counts
    ]
    return {"frameworks": frameworks}


def assessment_posture(store, org_id: str, *, now: float) -> "dict[str, Any]":
    """ONE org's security POSTURE from its OWN proven findings: a 0-100 posture score, a worst-first triage list,
    the severity breakdown, and a standards-implication summary. Tenant-scoped by construction (it reads only
    :func:`assessments.all_findings_for_org`, which returns exactly the org's own findings — another tenant's
    finding, and its presentation, is structurally unreachable). PURE read; assumes the caller already authorized
    ``org_id`` for ``view_assessments``. ``posture_score`` is an HONEST heuristic (see ``_PENALTY``); the basis is
    returned alongside so a reader can see exactly how it was computed."""
    findings = _assess.all_findings_for_org(store, org_id, now=now)
    triage = _triage(findings)
    counts = _fp.severity_counts(findings)
    return {
        "org_id": org_id,
        "posture_score": posture_score(findings),
        "posture_basis": {
            "method": "100 × 100 // (100 + Σ severity penalties) over the org's PROVEN findings",
            "weights": dict(_PENALTY),
            "note": "an honest heuristic for prioritisation, not a measured or certified rating",
        },
        "findings_total": len(findings),
        "severity_counts": counts,
        "triage": triage,
        "standards_summary": _standards_summary(triage),
        "generated_from": "proven_findings",
    }
