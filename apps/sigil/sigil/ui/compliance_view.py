"""PR-G (Area 6) — the tenant-scoped COMPLIANCE view: the OWASP Top 10 / PCI DSS / SOC 2 controls that the
workspace's PROVEN findings implicate, rolled up per framework.

WHAT IT SAYS, AND WHAT IT NEVER SAYS. A control appears as ``weakness_proven`` only when a finding a deterministic
oracle PROVED (an oracle-confirmed FACT with a signed certificate on the spine) implicates it; as ``weakness_fixed``
when every such finding's proof stopped working on a retest; and otherwise as ``no_proven_weakness`` — which is NOT
an assessment that the control is in place. Nothing here ever states that a control is met, covered, satisfied or
compliant: the view is DATA about which controls proven weaknesses touch, the same honesty rule the engine's
``report.standards`` enforces (a mapping is data; it asserts nothing on its own). An OWASP category no VIGIL check
maps to is ``not_mapped`` — said plainly, never folded into "no weakness".

PROVEN ONLY. The rows come ONLY from :func:`assessments.all_findings_for_org` — every row there carries a signed
certificate whose engagement slug is in the org's own set — so an unproven lead, a notice or a UI action can never
appear here. The per-finding controls are the SIGNED presentation controls when the certificate carries them, else
the inert ``vigil_core.standards_mirror`` lookup by class (``finding_presentation._triage_row`` — the same choice the
posture screen makes), so the view and the posture screen never disagree.

TENANT ISOLATION (the IDOR class) is STRUCTURAL and INHERITED: the org's slug set is derived server-side from its own
ownership proofs (``_customer_slug`` is a one-way hash of ``org_id\\x00host``), the host names come from the same
proofs, and the retest overlay is bounded to the already-scoped rows. Nothing is taken from the client.

FATAL-2: sovereign-side — stdlib + vigil_core + ui-local only; ``assert_no_offense`` at import. A pure read: no
spine write, no owner key, no model call, no traffic to any target.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import standards_mirror as _sm  # noqa: E402  (the inert engine-table mirror; no framework import)

from ..governor.asset_ownership import AssetOwnershipRegistry  # noqa: E402
from . import assessments as _assess  # noqa: E402
from . import finding_presentation as _fpres  # noqa: E402

# The frameworks the view rolls up (plan Area 6: OWASP Top 10, PCI DSS, SOC 2), in display order.
FRAMEWORKS = ("owasp", "pci_dss", "soc2")

STATUS_PROVEN = "weakness_proven"      # an OPEN proven finding implicates the control
STATUS_FIXED = "weakness_fixed"        # only findings whose proof stopped working on a retest implicate it
STATUS_NONE = "no_proven_weakness"     # no proven finding implicates it — never an assessment that it is in place
STATUS_NOT_MAPPED = "not_mapped"       # OWASP only: no VIGIL check maps a weakness class to this category
STATUSES = (STATUS_PROVEN, STATUS_FIXED, STATUS_NONE, STATUS_NOT_MAPPED)

# The one sentence every rendering carries (the screen, the report). Fixed words, so a test can strip exactly this
# sentence and prove nothing ELSE in the output claims a control is met.
STATEMENT = ("This view lists only the controls that weaknesses VIGIL proved in this workspace implicate. It never "
             "states that a control is met or compliant: a control with no proven weakness here was not assessed for "
             "compliance, and the absence of a finding is not evidence that the control is in place.")

# The per-finding fields a compliance entry carries — an allowlist (no proof, no fix, no internal slug).
_ENTRY_FIELDS = ("finding_ref", "title", "severity", "severity_basis", "bug_class", "host")


def _natural_key(cid: str) -> "tuple[Any, ...]":
    """Sort ``6.2.4`` before ``10.2.1`` and ``CC6.1`` before ``CC10.1`` (a plain string sort would not)."""
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"(\d+)", str(cid)) if p != "")


def _hosts_by_slug(store, org_id: str, *, now: float) -> "dict[str, str]":
    """slug -> host for the org's CURRENT proven hosts — the same set ``all_findings_for_org`` scopes by."""
    from .target_authorization import _customer_slug
    hosts = AssetOwnershipRegistry(store, owner_key=None).proven_hosts(org_id, now=now)
    return {_customer_slug(org_id, h): h for h in hosts}


def proven_rows(store, org_id: str, *, now: float, retests: bool = False) -> "list[dict[str, Any]]":
    """The org's PROVEN findings, each projected to its triage entry (``finding_presentation._triage_row``: severity,
    standards chips, priority, the SIGNED plain-language fields when present) plus the host, the retest verdict (when
    ``retests`` — the caller passes ``config.customer_retest_ui_enabled()``) and the cert fields a report may show.
    Worst-first, the posture screen's order. Tenant-scoped by construction (see the module docstring). PURE read."""
    findings = _assess.all_findings_for_org(store, org_id, now=now)
    if retests and findings:
        _assess.overlay_retests(store, findings, now=now)
    host_of = _hosts_by_slug(store, org_id, now=now) if findings else {}
    rows: "list[dict[str, Any]]" = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        row = _fpres._triage_row(f)
        row["host"] = host_of.get(str(f.get("engagement_slug") or ""), "")
        rt = f.get("retest")
        row["retest"] = rt.get("status") if isinstance(rt, dict) and rt.get("status") in ("fixed",
                                                                                          "still_vulnerable") else None
        for k in ("confidence", "summary", "how_to_verify", "oracle_context_digest"):
            v = f.get(k)
            if isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v).strip():
                row[k] = v
        rows.append(row)
    rows.sort(key=lambda r: (_fpres._severity_rank(r["severity"]), -float(r["priority_score"]), r["finding_ref"]))
    return rows


def _entry(row: dict) -> "dict[str, Any]":
    out = {k: row.get(k) for k in _ENTRY_FIELDS}
    out["retest"] = row.get("retest")
    return out


def _framework_ids(row: dict) -> "dict[str, list[str]]":
    return {str(c.get("framework") or ""): [str(i) for i in (c.get("ids") or ())]
            for c in row.get("standards_chips", ()) if isinstance(c, dict)}


def rollup(rows: "Iterable[dict]") -> "dict[str, Any]":
    """Roll proven triage rows (from :func:`proven_rows`) up per framework. Every control of a framework's KNOWN
    universe (``standards_mirror.control_universe``; the full Top 10 for OWASP) is listed once, with the findings
    that implicate it, worst-first. PURE + deterministic. Never a statement that a control is met (see STATEMENT)."""
    rows = [r for r in rows if isinstance(r, dict)]
    implicated: "dict[str, dict[str, list[dict]]]" = {fw: {} for fw in FRAMEWORKS}
    elsewhere: "list[dict]" = []
    for r in rows:
        ids = _framework_ids(r)
        hit = False
        for fw in FRAMEWORKS:
            for cid in ids.get(fw, ()):
                implicated[fw].setdefault(cid, []).append(_entry(r))
                hit = True
        if not hit:
            elsewhere.append(_entry(r))
    frameworks: "list[dict[str, Any]]" = []
    for fw in FRAMEWORKS:
        mapped = set(_sm.control_universe(fw))
        universe = mapped | set(implicated[fw])
        if fw == "owasp":
            universe |= set(_sm.owasp_categories())
        controls: "list[dict[str, Any]]" = []
        summary = {s: 0 for s in STATUSES}
        for cid in sorted(universe, key=_natural_key):
            entries = implicated[fw].get(cid, [])
            if any(e["retest"] != "fixed" for e in entries):
                status = STATUS_PROVEN
            elif entries:
                status = STATUS_FIXED
            elif cid not in mapped:
                status = STATUS_NOT_MAPPED
            else:
                status = STATUS_NONE
            summary[status] += 1
            controls.append({"id": cid, "name": _sm.owasp_name(cid) if fw == "owasp" else "", "status": status,
                             "findings": entries})
        frameworks.append({"framework": fw, "label": _sm.framework_label(fw),
                           "version": _sm.standard_versions().get(fw, ""), "controls": controls,
                           "summary": summary})
    return {"frameworks": frameworks, "findings_elsewhere": elsewhere, "statement": STATEMENT}


def compliance_view(store, org_id: str, *, now: float, retests: bool = False) -> "dict[str, Any]":
    """ONE org's compliance view from its OWN proven findings: per framework, every control with the proven findings
    that implicate it. PURE read; assumes the caller already authorized ``org_id`` for ``view_assessments``."""
    rows = proven_rows(store, org_id, now=now, retests=retests)
    out = rollup(rows)
    out.update(org_id=org_id, findings_total=len(rows), generated_from="proven_findings")
    return out
