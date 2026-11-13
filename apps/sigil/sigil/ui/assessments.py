"""UI read projection for the tenant-scoped ASSESSMENT RESULTS surface (Slice K6).

A PURE, READ-ONLY projection of the oracle-confirmed FINDINGS a customer's authorized assessments landed on
the owner-signed spine (``kind="finding"`` records, ingested + governance-verified by
``inbound/finding_receiver.py``). Tenant-scoped by construction — THE IDOR defense:

  * the org's engagement-slug set is resolved SERVER-SIDE from the org's OWN current ownership proofs
    (``AssetOwnershipRegistry.proven_hosts(org_id) -> _customer_slug(org_id, host)``), never from a client-
    supplied slug/host — and a finding is returned ONLY if its OWN signed ``certificate.engagement_slug`` is
    in that set. Because ``_customer_slug`` is a one-way hash of ``org_id\x00host``, a finding for another
    tenant can never collide into this org's set, so one tenant's results are structurally unreachable by
    another. Slug knowledge is not authorization: the HTTP route still gates on ``admit(view_assessments)``.

FINDINGS ONLY (first cut): a detection FACT's certificate does not yet carry a signed ``engagement_slug`` (it
cannot be per-engagement-confined — see ``finding_receiver.ingest_detection``), so detections are intentionally
NOT surfaced here; they return once the detection cert declares a signed slug (symmetric with the receiver).

The cert fields are projected through a stable ALLOWLIST (never a raw cert dump) so the API contract is fixed
and an unexpected internal field can never leak. The customer report is rendered on the SOVEREIGN side from
these inert spine fields — this module NEVER imports ``engine/crucible`` (the finding record is already inert
JSON on the spine). FATAL-2: ``assert_no_offense()`` at import; governor + ui-local reads only.
"""
from __future__ import annotations

import copy
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor.asset_ownership import AssetOwnershipRegistry  # noqa: E402
from ..governor.fold_read import UNCACHED as _UNCACHED, cached_unsigned_read  # noqa: E402
from ..governor.orgs import org_tenant_id  # noqa: E402
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0d — the verified incremental fold)

_FINDING_KIND = "finding"
# The stable, inert cert fields a customer may read for one finding. An allowlist (never a raw cert dump) so a
# future internal cert field can never leak and the API shape is fixed. Values are read fail-closed via .get.
_CERT_FIELDS = ("finding_ref", "bug_class", "surface", "confidence", "severity", "title", "summary",
                "how_to_verify", "report_claims", "oracle_context_digest", "artifact_manifest")

# NTF-3: the settle-drain's tenant-scoped assessment-outcome projection (``sigil.inbound.completion_spool``).
_OUTCOME_KIND = "assessment_outcome"
# The stable, inert fields a customer may read for one settled assessment outcome. An allowlist (never a raw
# payload dump) so the API shape is fixed and a future internal field can never leak. NO amount is ever here —
# the outcome record is advisory (money-doctrine clean); it carries no price/charge/refund figure.
_OUTCOME_FIELDS = ("engagement_slug", "outcome", "nonce", "ts")


def valid_org(org_id: object) -> Optional[str]:
    """Validate + normalise a client-supplied org_id to a tenant id, FAIL-CLOSED (None on anything invalid),
    exactly as the billing read API does — the route rejects None with a 400 before any lookup/fold."""
    if not isinstance(org_id, str) or not org_id:
        return None
    try:
        return org_tenant_id(org_id)
    except ValueError:
        return None


def _org_slug_set(store, org_id: str, *, now: float) -> set[str]:
    """The engagement-slug set that belongs to ``org_id`` — derived SERVER-SIDE from the org's OWN current
    ownership proofs, never a client value. A finding is this org's iff its signed engagement_slug is here."""
    from .target_authorization import _customer_slug
    hosts = AssetOwnershipRegistry(store, owner_key=None).proven_hosts(org_id, now=now)
    return {_customer_slug(org_id, h) for h in hosts}


def _finding_json(payload: dict, cert: dict) -> dict[str, Any]:
    out: dict[str, Any] = {"engagement_slug": cert.get("engagement_slug")}
    # finding_ref/oracle_context_digest live at the spine payload top level too (receiver mirrors them); prefer
    # the cert value, fall back to the payload, so the projection is robust to either carrier.
    for f in _CERT_FIELDS:
        v = cert.get(f, payload.get(f))
        if v is not None:
            out[f] = v
    return out


class _AssessmentsView:
    """Front C S0d — the findings + outcomes index the projectors below read instead of scanning the whole spine
    per request: `findings[slug]` / `outcomes[slug]` = [(seq, projected json)] in spine order, built from EXACTLY
    the records the scans keep (same kind / dict / certificate checks; the projection is the same pure
    function). A record whose engagement slug is unhashable (the scans' `in slug_set` would raise on it) poisons
    the view, so every read falls back to the unchanged scan and raises exactly where it did."""

    __slots__ = ("findings", "outcomes", "poisoned")

    def __init__(self) -> None:
        self.findings: dict = {}
        self.outcomes: dict = {}
        self.poisoned = False


def _assessments_step(view: _AssessmentsView, r, _ctx) -> None:
    kind = getattr(r, "kind", None)
    if kind != _FINDING_KIND and kind != _OUTCOME_KIND:
        return
    p = r.payload
    if not isinstance(p, dict):
        return
    if kind == _FINDING_KIND:
        cert = p.get("certificate")
        if not isinstance(cert, dict):
            return
        index, slug, row = view.findings, cert.get("engagement_slug"), _finding_json(p, cert)
    else:
        index, slug, row = view.outcomes, p.get("engagement_slug"), _outcome_json(p)
    try:
        rows = index.setdefault(slug, [])
    except TypeError:
        view.poisoned = True
        return
    rows.append((int(getattr(r, "seq", 0)), row))


_ASSESSMENTS_FOLD = FoldCache("ui.assessments", step=_assessments_step)


def _indexed(store, which: str, slugs) -> Any:
    """[(seq, json)] of the indexed `which` rows ('findings' / 'outcomes') for `slugs`, or `_UNCACHED`. A
    `live_window` read: the scans never load the snapshot, so a snapshot that cannot be loaded declines."""
    return cached_unsigned_read(_ASSESSMENTS_FOLD, store, seed=lambda snap: (_AssessmentsView(), -1), live_window=True,
                                reader=lambda v: [row for s in slugs for row in getattr(v, which).get(s, ())])


def _newest_first(rows: list, limit: int) -> "tuple[list, int]":
    rows.sort(key=lambda t: t[0], reverse=True)     # newest-first by spine seq
    n = max(1, min(int(limit), 1000))
    return [copy.deepcopy(j) for _s, j in rows[:n]], len(rows)


def _all_finding_rows(store, slug_set) -> "list[tuple[int, dict]]":
    """Every (seq, projected row) for `slug_set` — deep copies on the cached path, fresh rows on the scan."""
    if not slug_set:
        return []
    hit = _indexed(store, "findings", slug_set)
    if hit is not _UNCACHED:
        return [(s, copy.deepcopy(j)) for s, j in hit]
    rows: list[tuple[int, dict]] = []
    for r in store.iter_records():
        if getattr(r, "kind", None) != _FINDING_KIND:
            continue
        p = r.payload
        if not isinstance(p, dict):
            continue
        cert = p.get("certificate")
        if not isinstance(cert, dict) or cert.get("engagement_slug") not in slug_set:
            continue
        rows.append((int(getattr(r, "seq", 0)), _finding_json(p, cert)))
    return rows


def _preview_findings(store, org_id: str, *, now: float, limit: int, can_buy: bool) -> dict[str, Any]:
    """The LOCKED (trial preview) findings read: every row projected by `finding_preview.apply_preview` BEFORE
    pagination, so `count` stays the true total and exactly one finding is shown in full."""
    from . import finding_preview as fp
    from .target_authorization import _customer_slug
    own = AssetOwnershipRegistry(store, owner_key=None)
    current = {_customer_slug(org_id, h): h for h in own.proven_hosts(org_id, now=now)}
    ever = {_customer_slug(org_id, h): h for h in own.ever_proven_hosts(org_id)}
    revealed = fp.reveal_seq(_all_finding_rows(store, set(ever)), set(ever))
    rows = fp.apply_preview(_all_finding_rows(store, set(current)), revealed=revealed, host_of={**ever, **current})
    rows.sort(key=lambda t: t[0], reverse=True)
    n = max(1, min(int(limit), 1000))
    return {"org_id": org_id, "findings": [j for _s, j in rows[:n]], "count": len(rows),
            "preview": fp.preview_block(can_buy=can_buy)}


def assessment_findings(store, org_id: str, *, now: float, limit: int = 200, preview: bool = False,
                        can_buy: bool = False) -> dict[str, Any]:
    """The oracle-confirmed findings for ONE org's authorized assessments, newest-first. PURE read; tenant-
    scoped by the org's server-derived slug set (the IDOR class — a line for another tenant is structurally
    never returned). Assumes the caller was already authorized for ``org_id`` by the route. ``count`` is the
    true total so a client can page without ever seeing another tenant's findings. ``preview=True`` (a locked
    trial org, decided by the caller via ``finding_preview.preview_locked``) returns the partial-results
    projection; False returns exactly today's output."""
    if preview:
        return _preview_findings(store, org_id, now=now, limit=limit, can_buy=can_buy)
    slug_set = _org_slug_set(store, org_id, now=now)
    if slug_set:
        hit = _indexed(store, "findings", slug_set)
        if hit is not _UNCACHED:
            page, count = _newest_first(hit, limit)
            return {"org_id": org_id, "findings": page, "count": count}
    rows: list[tuple[int, dict]] = []
    if slug_set:                                    # no proven hosts -> no slugs -> no findings (fail-closed)
        for r in store.iter_records():
            if getattr(r, "kind", None) != _FINDING_KIND:
                continue
            p = r.payload
            if not isinstance(p, dict):
                continue
            cert = p.get("certificate")
            if not isinstance(cert, dict) or cert.get("engagement_slug") not in slug_set:
                continue
            rows.append((int(getattr(r, "seq", 0)), _finding_json(p, cert)))
    rows.sort(key=lambda t: t[0], reverse=True)     # newest-first by spine seq
    n = max(1, min(int(limit), 1000))
    return {"org_id": org_id, "findings": [j for _s, j in rows[:n]], "count": len(rows)}


def _outcome_json(payload: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in _OUTCOME_FIELDS:
        v = payload.get(f)
        if v is not None:
            out[f] = v
    return out


def assessment_outcomes(store, org_id: str, *, now: float, limit: int = 200) -> dict[str, Any]:
    """The settled assessment OUTCOMES (completed / canceled / failed) for ONE org's authorized assessments,
    newest-first. PURE read; tenant-scoped by the org's server-derived slug set EXACTLY as
    :func:`assessment_findings` is (the IDOR class — an outcome for another tenant is structurally never
    returned, because ``_customer_slug`` is a one-way hash of ``org_id\\x00host`` and the slug set is derived
    SERVER-SIDE from THIS org's own current ownership proofs, never a client value). Mirrors the findings
    projector: scan ``kind=="assessment_outcome"``, keep ONLY records whose ``engagement_slug`` is in the org's
    own slug set, allowlist-projected (never a raw payload dump). Assumes the caller was already authorized for
    ``org_id`` by the route/aggregator. ``count`` is the true total so a client can page without ever seeing
    another tenant's outcomes."""
    slug_set = _org_slug_set(store, org_id, now=now)
    if slug_set:
        hit = _indexed(store, "outcomes", slug_set)
        if hit is not _UNCACHED:
            page, count = _newest_first(hit, limit)
            return {"org_id": org_id, "outcomes": page, "count": count}
    rows: list[tuple[int, dict]] = []
    if slug_set:                                    # no proven hosts -> no slugs -> no outcomes (fail-closed)
        for r in store.iter_records():
            if getattr(r, "kind", None) != _OUTCOME_KIND:
                continue
            p = r.payload
            if not isinstance(p, dict):
                continue
            if p.get("engagement_slug") not in slug_set:
                continue
            rows.append((int(getattr(r, "seq", 0)), _outcome_json(p)))
    rows.sort(key=lambda t: t[0], reverse=True)     # newest-first by spine seq
    n = max(1, min(int(limit), 1000))
    return {"org_id": org_id, "outcomes": [j for _s, j in rows[:n]], "count": len(rows)}


def assessment_summary(store, org_id: str, *, now: float, preview: bool = False) -> dict[str, Any]:
    """A coarse per-engagement roll-up for ONE org: for each of the org's proven hosts, its engagement slug,
    the host, whether a current owner-signed launch authority/proof backs it, and how many findings it carries.
    Tenant-scoped identically (the slug set is the org's own). The customer app lists assessments from this."""
    from .target_authorization import _customer_slug
    hosts = AssetOwnershipRegistry(store, owner_key=None).proven_hosts(org_id, now=now)
    by_slug = {_customer_slug(org_id, h): h for h in hosts}
    counts: dict[str, int] = {s: 0 for s in by_slug}
    hit: Any = _indexed(store, "findings", by_slug) if by_slug else _UNCACHED
    if hit is not _UNCACHED:
        for _seq, row in hit:
            counts[row["engagement_slug"]] += 1
    elif by_slug:
        for r in store.iter_records():
            if getattr(r, "kind", None) != _FINDING_KIND:
                continue
            p = r.payload
            if not isinstance(p, dict):
                continue
            cert = p.get("certificate")
            if not isinstance(cert, dict):
                continue
            slug = cert.get("engagement_slug")
            if slug in counts:
                counts[slug] += 1
    out: dict[str, Any] = {"org_id": org_id,
                           "assessments": [{"slug": s, "host": h, "findings": counts[s]}
                                           for s, h in sorted(by_slug.items())]}
    if preview:                     # the teaser: per-host counts by derived severity, no detail
        from . import finding_preview as fp
        rows = _all_finding_rows(store, set(by_slug))
        for a in out["assessments"]:
            a["severity"] = fp.severity_counts(r for _s, r in rows if r.get("engagement_slug") == a["slug"])
        out["preview"] = True
    return out
