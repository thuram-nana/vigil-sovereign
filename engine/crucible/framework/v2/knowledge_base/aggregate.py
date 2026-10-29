"""
knowledge_base.aggregate — the per-ORG knowledge-base scoping + aggregation + query layer.

This is the FIRST slice of the enterprise KNOWLEDGE-BASE wave: a read/index/query view over the
engagement artifacts that ALREADY live on disk — it introduces NO new storage and NEVER duplicates
what the scanner / reporter / operator wrote. It reads:

  * ``<slug>.report.json`` (``common.paths.phase_report_path``) — a serialized ``ScanReport``, whose
    ``active_findings`` are ORACLE-CONFIRMED and whose ``passive_findings`` are LEADS;
  * ``targets/<slug>/findings/NNN-*.md`` — operator/agent-authored finding docs (confirmed by the
    OBSIDIAN doctrine: a finding file exists only once confirmed);
  * ``targets/<slug>/reports/*.md`` — the rendered report documents.

Everything is keyed ``(tenant_id, slug)``.

SCOPING (the hard invariant). org == tenant_id, read via ``common.paths.active_tenant()`` (the
validated ``CRUCIBLE_TENANT``, or ``None`` when unsharded/single-tenant — the default/global scope).
Genuine tenant isolation already means ONE ``CRUCIBLE_ROOT`` per tenant (see ``common.tenant``'s
docstring: ``targets/<slug>`` is per-SLUG, NOT per-tenant-sharded, so the ROOT is the boundary).
This module therefore enforces the boundary two ways:

  (a) it NEVER reads outside the active tenant's ``targets_root()`` — slugs are enumerated from
      ``iterdir()`` and the slug dir is containment-checked (``_safe_target_dir``), AND every CONCRETE
      leaf it then reads (``<slug>.report.json``, ``charter.md``, the ``findings/`` & ``reports/``
      sub-dirs, and each ``*.md``) is re-checked with ``paths.is_within`` via ``_contained`` — so a
      symlink planted at a leaf inside a legitimately-contained slug dir cannot escape to another
      tenant's tree (``Path.resolve()`` follows the symlink; an out-of-root target is refused); and
  (b) it keys every record ``(tenant_id, slug)`` AND fails CLOSED at the API boundary — a caller that
      asks for an explicit org other than the active one (``corpus(tenant="B")`` from an ``A`` process)
      raises :class:`KnowledgeBaseScopeError` rather than ever returning another org's artifacts.

FATAL-2 plane hygiene: this module's DIRECT imports are stdlib + ``framework.v2.common.paths`` + the
sibling model types ONLY — no sovereign and no ``vigil_integration``, and no DIRECT ``vigil_core`` (it
is pulled transitively by ``common.paths`` via the shared integrity base, which is plane-safe on both
sides). (The cryptographically-grounded signed
offense-spine reader — ``vigil_integration.live.trusted_finding._load_confirmed_facts`` — lives on the
integration plane; folding the signed spine in is a documented follow-up, NOT this slice.)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from ..common import paths
from .models import (
    Corpus,
    Engagement,
    FindingRecord,
    ReportRecord,
    scope_label,
)

__all__ = [
    "KnowledgeBaseError",
    "KnowledgeBaseScopeError",
    "active_org",
    "list_engagements",
    "corpus",
    "query",
    "show",
]


class KnowledgeBaseError(Exception):
    """Base error for the knowledge-base layer."""


class KnowledgeBaseScopeError(KnowledgeBaseError):
    """A caller asked for a scope it is not allowed to read — a cross-tenant request from a process
    pinned to a different (or to no specific) tenant. Raised FAIL-CLOSED so org A can never read org
    B's corpus, even by explicitly naming it."""


# Canonical severity labels (title-cased) we normalize parsed/stored severity strings to.
_CANON_SEV = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}

# A metadata bullet in a finding doc: ``- **Key:** value`` (the OBSIDIAN finding template shape).
_META_RE = re.compile(r"^\s*[-*]\s*\*\*(?P<key>[^:*]+):\*\*\s*(?P<val>.*?)\s*$")

# Finding-doc Status values that do NOT count as a live confirmed finding: WITHDRAWN means the finding
# was determined invalid (OBSIDIAN: "mark it Status: WITHDRAWN"), DRAFT means not yet confirmed, and the
# false-positive/duplicate/invalid family are non-findings. Every other status (Open, Reported, Fix in
# progress, Verified Fixed, Risk Accepted, Will Not Fix, …) IS a confirmed finding — the vuln was real.
_NONCONFIRMING_STATUS = {
    "draft", "withdrawn", "false positive", "false-positive", "falsepositive",
    "duplicate", "invalid", "not applicable", "n/a", "na", "rejected",
}

# Scaffolding doc copied into every engagement by intake (targets/_template/findings/README.md): it is a
# how-to, not a finding, and must never be counted/indexed as one.
_SCAFFOLD_FINDING_STEMS = {"readme"}


def _status_is_confirmed(status: str) -> bool:
    """A finding doc counts as a CONFIRMED finding unless its Status BEGINS WITH a nonconfirming phrase
    (withdrawn / draft / false-positive / duplicate / invalid / rejected / n-a). An empty Status is
    treated as confirmed (OBSIDIAN: a finding file exists only once confirmed).

    The match is a WORD-BOUNDARY PREFIX, not exact set membership, so a hand-written status that trails
    prose with OR WITHOUT punctuation is classified like its canonical form: ``Duplicate of 003``,
    ``Withdrawn pending re-test``, ``Not Applicable (out of scope)``, ``False positive — benign`` and a
    bare ``Invalid`` all read nonconfirming, while ``Open`` / ``Risk Accepted`` / ``Will Not Fix`` /
    ``Verified Fixed`` (and an unrelated word like ``drafted``) do not. Whitespace is collapsed first."""
    s = re.sub(r"\s+", " ", str(status or "").strip().lower())
    if not s:
        return True
    # bad phrase must be followed by a non-alphanumeric boundary (end / space / punctuation) so it
    # matches a leading status word, never the inside of a longer word (e.g. ``draft`` vs ``drafted``).
    return not any(re.match(re.escape(bad) + r"(?![a-z0-9])", s) for bad in _NONCONFIRMING_STATUS)


# ---------------------------------------------------------------------------
# Scope resolution (the fail-closed org boundary)
# ---------------------------------------------------------------------------


def active_org() -> Optional[str]:
    """The org (tenant id) this process is scoped to — ``common.paths.active_tenant()``. ``None`` when
    unsharded / single-tenant (the default/global scope). Re-raises the fail-closed validation error for
    a set-but-unsafe ``CRUCIBLE_TENANT`` rather than masking it."""
    return paths.active_tenant()


def _resolve_scope(tenant: Optional[str]) -> Optional[str]:
    """Resolve the org scope for a request and ENFORCE the boundary (fail-closed).

      * ``tenant is None`` (or blank)  → the active scope (``active_tenant()``): the convenience default.
      * ``tenant == active_tenant()``  → that scope.
      * active is ``None`` but a specific ``tenant`` was asked for → refuse: an unsharded/global process
        serves no single org's scope.
      * ``tenant != active_tenant()``  → refuse: a cross-tenant read.

    The returned value is the ONLY tenant id this call will key records under, and the artifacts always
    come from under the active root, so a refused request can never leak another org's data."""
    active = paths.active_tenant()
    if tenant is None:
        return active
    requested = str(tenant).strip()
    if not requested:
        return active
    if active is None:
        raise KnowledgeBaseScopeError(
            f"this process is unsharded (CRUCIBLE_TENANT unset — global/default scope); it cannot serve "
            f"the scope of a specific org {requested!r}. Run one CRUCIBLE_ROOT + CRUCIBLE_TENANT per org.")
    if requested != active:
        raise KnowledgeBaseScopeError(
            f"cross-tenant read refused: this process serves org {active!r}, not {requested!r} "
            f"(one CRUCIBLE_ROOT per tenant is the isolation boundary — org {active!r} can never read "
            f"org {requested!r}'s findings).")
    return active


# ---------------------------------------------------------------------------
# Enumeration (strictly under the active tenant's targets/ tree)
# ---------------------------------------------------------------------------


def _engagement_slugs() -> list[str]:
    """The slugs present under the active tenant's ``targets/`` tree, sorted.

    An engagement is a direct sub-directory of ``paths.targets_root()`` whose name does not start with
    ``_`` (the scaffolding dirs ``_template`` / ``_practice``) or ``.`` (hidden). Totally defensive: a
    missing / unreadable ``targets/`` yields ``[]`` (empty corpus, never a crash)."""
    root = paths.targets_root()
    try:
        names = [p.name for p in root.iterdir() if p.is_dir()]
    except OSError:
        return []
    # containment: drop any slug whose target_dir escapes the active tenant root (e.g. a symlink planted under
    # targets/ pointing at another org's root) — _safe_target_dir resolves symlinks via paths.is_within.
    return sorted(n for n in names if not n.startswith(("_", ".")) and _safe_target_dir(n) is not None)


def _safe_target_dir(slug: str) -> Optional[Path]:
    """``paths.target_dir(slug)`` IFF it resolves inside ``targets_root()`` — else ``None`` (defense in
    depth: slugs come from ``iterdir`` and are already safe single components, but this refuses any slug
    that would traverse out of the active tenant's tree, so a per-slug read can never escape the root)."""
    d = paths.target_dir(slug)
    return d if paths.is_within(d, paths.targets_root()) else None


def _contained(p: Path) -> bool:
    """True iff the CONCRETE path ``p`` resolves inside the active tenant's ``targets_root()``.

    ``_safe_target_dir`` only validates the slug DIRECTORY; it does NOT validate the leaf files read
    inside it. A legitimately-contained slug dir can still hold a symlink at ``<slug>.report.json``,
    ``charter.md``, ``findings/`` / ``reports/`` (the whole sub-dir), or an individual ``*.md`` that
    points into ANOTHER tenant's root. ``Path.resolve()`` follows every symlink in ``p``, so gating each
    concrete read on ``is_within(p, targets_root())`` refuses a leaf escape that the directory check
    passes — the fix for the cross-tenant leaf-symlink leak."""
    return paths.is_within(p, paths.targets_root())


# ---------------------------------------------------------------------------
# Artifact readers (defensive — a malformed artifact is skipped, never fatal)
# ---------------------------------------------------------------------------


def _load_report_json(slug: str) -> Optional[dict[str, Any]]:
    """The parsed ``<slug>.report.json`` (a serialized ``ScanReport``) as a dict, or ``None`` when absent
    or malformed. Read as plain JSON (not validated through the model) so the corpus stays import-light
    and degrades gracefully across schema drift."""
    if _safe_target_dir(slug) is None:
        return None                      # containment: a slug whose dir escapes the active tenant root reads nothing
    p = paths.phase_report_path(slug)
    if not _contained(p):
        return None                      # containment: a symlinked <slug>.report.json escaping the root reads nothing
    try:
        if not p.is_file():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _norm_sev(value: Any) -> str:
    """Normalize a severity string to a canonical label (``Critical``/``High``/…) when recognized, else
    the stripped raw token, else ``""``."""
    token = str(value or "").strip()
    if not token:
        return ""
    return _CANON_SEV.get(token.lower(), token)


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> list:
    """A list, or ``[]`` for anything else — so a schema-drifted non-iterable (e.g. ``active_findings: 5``)
    degrades gracefully instead of raising a TypeError that would crash the WHOLE-org corpus when iterated."""
    return value if isinstance(value, list) else []


def _findings_from_report(scope: Optional[str], slug: str,
                          report: Optional[dict[str, Any]]) -> list[FindingRecord]:
    """Confirmed active findings (oracle-confirmed) + passive findings (leads) from a report dict."""
    if not report:
        return []
    out: list[FindingRecord] = []
    src_path = str(paths.phase_report_path(slug))
    for af in _as_list(report.get("active_findings")):
        if not isinstance(af, dict):
            continue
        # oracle_kind names the oracle the report says fired. We ONLY mark oracle_confirmed when the
        # report actually NAMES a confirmer — an active finding with no confirmed_by asserts a confirmation
        # while naming no oracle (contradicting models.py: "oracle_kind names the oracle that fired"), so it
        # is NOT oracle-grounded here. This reflects the UNSIGNED report.json's own claim; the KB does not
        # re-fire the oracle (the signed-spine re-read is the documented follow-up noted in the module docstring).
        oracle_kind = str(af.get("confirmed_by") or "").strip()
        out.append(FindingRecord(
            tenant_id=scope, slug=slug,
            ref=str(af.get("check_id") or ""),
            title=str(af.get("title") or af.get("check_id") or ""),
            severity=_norm_sev(af.get("severity")),
            bug_class=str(af.get("bug_class") or ""),
            source="scan:active", confirmed=True, oracle_confirmed=bool(oracle_kind),
            oracle_kind=oracle_kind,
            endpoint=str(af.get("endpoint") or ""),
            confidence=_as_float(af.get("confidence")),
            path=src_path,
        ))
    for pf in _as_list(report.get("passive_findings")):
        if not isinstance(pf, dict):
            continue
        out.append(FindingRecord(
            tenant_id=scope, slug=slug,
            ref=str(pf.get("check_id") or ""),
            title=str(pf.get("title") or ""),
            severity=_norm_sev(pf.get("severity")),
            bug_class=str(pf.get("check_id") or ""),
            source="scan:passive", confirmed=False, oracle_confirmed=False,
            endpoint=str(pf.get("url") or ""),
            path=src_path,
        ))
    return out


def _primary_value(raw: str) -> str:
    """The canonical value of a metadata bullet. If the value starts with a backtick-quoted token
    (```Medium` *(contextual…)*``, ```Open```), return that token; otherwise the
    whole stripped line (a plain-text ``Title`` is kept intact, even when it contains inline code)."""
    raw = raw.strip()
    if raw.startswith("`"):
        end = raw.find("`", 1)
        if end != -1:
            return raw[1:end].strip()
    return raw.strip("`").strip()


def _parse_finding_file(fp: Path) -> dict[str, str]:
    """Parse the OBSIDIAN finding-template metadata block. Returns best-effort ``title`` / ``severity`` /
    ``status`` / ``bug_class``. Totally defensive: an unreadable file yields ``{}``."""
    meta: dict[str, str] = {}
    heading_title = ""
    try:
        text = fp.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return meta
    for line in text.splitlines():
        if not heading_title and line.startswith("# "):
            # "# Finding 001 — `slug`" → take the text after an em/en dash as a weak title fallback.
            for dash in ("—", "–", " - "):
                if dash in line:
                    heading_title = line.split(dash, 1)[1].strip().strip("`").strip()
                    break
        m = _META_RE.match(line)
        if not m:
            continue
        key = m.group("key").strip().lower()
        val = _primary_value(m.group("val"))
        if key == "title":
            meta["title"] = val
        elif key == "severity":
            meta["severity"] = val.split()[0] if val.split() else ""
        elif key == "status":
            meta["status"] = val
        elif key == "bug class":
            meta["bug_class"] = val
        elif key == "owasp category" and "bug_class" not in meta:
            meta["bug_class"] = val
    if "title" not in meta and heading_title:
        meta["title"] = heading_title
    return meta


def _findings_from_files(scope: Optional[str], slug: str) -> list[FindingRecord]:
    """Authored finding docs (``findings/NNN-*.md``) as CONFIRMED (but not oracle-grounded) findings."""
    d = _safe_target_dir(slug)
    if d is None:
        return []
    fdir = d / "findings"
    if not _contained(fdir):
        return []                        # containment: a symlinked findings/ sub-dir escaping the root reads nothing
    try:
        files = sorted(fdir.glob("*.md"))
    except OSError:
        return []
    out: list[FindingRecord] = []
    for fp in files:
        if fp.name.startswith(("_", ".")) or fp.stem.lower() in _SCAFFOLD_FINDING_STEMS:
            continue                     # skip hidden/scaffold docs (the _template README is not a finding)
        if not _contained(fp):
            continue                     # containment: a per-file symlink escaping the root reads nothing
        meta = _parse_finding_file(fp)
        status = meta.get("status", "")
        out.append(FindingRecord(
            tenant_id=scope, slug=slug,
            ref=fp.stem,
            title=meta.get("title") or fp.stem,
            severity=_norm_sev(meta.get("severity")),
            bug_class=meta.get("bug_class", ""),
            source="finding-file", confirmed=_status_is_confirmed(status), oracle_confirmed=False,
            status=status,
            path=str(fp),
        ))
    return out


def _first_heading(fp: Path) -> str:
    try:
        for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("# "):
                return line[2:].strip()
    except OSError:
        return ""
    return ""


def _reports(scope: Optional[str], slug: str) -> list[ReportRecord]:
    """The rendered report docs (``reports/*.md``) indexed (not re-rendered)."""
    d = _safe_target_dir(slug)
    if d is None:
        return []
    rdir = d / "reports"
    if not _contained(rdir):
        return []                        # containment: a symlinked reports/ sub-dir escaping the root reads nothing
    try:
        files = sorted(rdir.glob("*.md"))
    except OSError:
        return []
    out: list[ReportRecord] = []
    for fp in files:
        if fp.name.startswith(("_", ".")):
            continue
        if not _contained(fp):
            continue                     # containment: a per-file symlink escaping the root reads nothing
        try:
            size = fp.stat().st_size
        except OSError:
            size = 0
        out.append(ReportRecord(
            tenant_id=scope, slug=slug, name=fp.stem, path=str(fp),
            title=_first_heading(fp), size_bytes=size,
        ))
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _build_engagement(scope: Optional[str], slug: str, *,
                      report: Optional[dict[str, Any]],
                      findings: list[FindingRecord],
                      reports: list[ReportRecord]) -> Engagement:
    contained = _safe_target_dir(slug) is not None   # an escaping slug (symlink/traversal) exposes no artifacts
    charter = paths.charter_path(slug)
    scan_report = paths.phase_report_path(slug)
    return Engagement(
        tenant_id=scope, slug=slug,
        # leaf containment too: a symlinked charter.md / <slug>.report.json escaping the root is NOT "present"
        has_charter=contained and _contained(charter) and charter.is_file(),
        has_scan_report=contained and _contained(scan_report) and scan_report.is_file(),
        finding_count=sum(1 for f in findings if f.confirmed),
        # leads are the scanner's unconfirmed passive findings — NOT a withdrawn/draft finding-file
        # (confirmed=False, source="finding-file"), which is indexed as history but counted as neither.
        lead_count=sum(1 for f in findings if f.source == "scan:passive"),
        report_count=len(reports),
        target=str((report or {}).get("target") or ""),
    )


def corpus(tenant: Optional[str] = None) -> Corpus:
    """The aggregated knowledge base for the active org (or an explicitly-named org that MUST equal the
    active one — else :class:`KnowledgeBaseScopeError`). Reads every engagement under the active tenant's
    ``targets/`` tree. Never mutates anything; an empty / missing tree yields an empty corpus."""
    scope = _resolve_scope(tenant)
    engagements: list[Engagement] = []
    all_findings: list[FindingRecord] = []
    all_reports: list[ReportRecord] = []
    for slug in _engagement_slugs():
        report = _load_report_json(slug)
        findings = _findings_from_report(scope, slug, report) + _findings_from_files(scope, slug)
        reports = _reports(scope, slug)
        engagements.append(_build_engagement(
            scope, slug, report=report, findings=findings, reports=reports))
        all_findings.extend(findings)
        all_reports.extend(reports)
    return Corpus(
        tenant_id=scope,
        engagements=tuple(engagements),
        findings=tuple(all_findings),
        reports=tuple(all_reports),
    )


def list_engagements(tenant: Optional[str] = None) -> list[Engagement]:
    """The active org's engagements (one summary row per slug), keyed ``(tenant_id, slug)``."""
    return list(corpus(tenant).engagements)


def query(tenant: Optional[str] = None, *, slug: Optional[str] = None,
          severity: Optional[str] = None, bug_class: Optional[str] = None,
          source: Optional[str] = None, status: Optional[str] = None,
          confirmed_only: bool = False) -> list[FindingRecord]:
    """Filtered findings across the active org's corpus. Every filter is ANDed; all are optional.

    ``slug`` filters the ALREADY-ENUMERATED findings (it never turns an arbitrary caller string into a
    filesystem read), so it cannot be used to reach outside the active tenant's tree."""
    results = list(corpus(tenant).findings)
    if slug is not None:
        results = [f for f in results if f.slug == slug]
    if severity is not None:
        want = str(severity).strip().lower()
        results = [f for f in results if f.severity.lower() == want]
    if bug_class is not None:
        want = str(bug_class).strip().lower()
        results = [f for f in results if f.bug_class.lower() == want]
    if source is not None:
        results = [f for f in results if f.source == source]
    if status is not None:
        want = str(status).strip().lower()
        results = [f for f in results if f.status.lower() == want]
    if confirmed_only:
        results = [f for f in results if f.confirmed]
    return results


def show(slug: str, tenant: Optional[str] = None) -> dict[str, Any]:
    """A single engagement's slice of the corpus (the backing for a future ``vigil kb show <slug>``):
    ``{engagement, findings, reports}`` for ``slug`` under the active org, or ``engagement: None`` when
    the slug is not an engagement under the active tenant's tree. Strictly scoped like :func:`corpus`."""
    c = corpus(tenant)
    eng = next((e for e in c.engagements if e.slug == slug), None)
    return {
        "engagement": eng.to_dict() if eng is not None else None,
        "findings": [f.to_dict() for f in c.findings if f.slug == slug],
        "reports": [r.to_dict() for r in c.reports if r.slug == slug],
    }
