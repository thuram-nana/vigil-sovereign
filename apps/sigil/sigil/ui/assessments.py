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
# C1b: the provisioner-written per-finding retest verdict record (``ui.provision.retest``). Tenant-scoped exactly
# as a finding is (its ``engagement_slug`` must be in the reader's server-derived slug set), and read only when its
# spine ``source`` is the provisioner's (the writer and this reader share these two names).
RETEST_KIND = "finding_retest"
RETEST_SOURCE = "provision"
# The stable, inert cert fields a customer may read for one finding. An allowlist (never a raw cert dump) so a
# future internal cert field can never leak and the API shape is fixed. Values are read fail-closed via .get.
_CERT_FIELDS = ("finding_ref", "bug_class", "surface", "confidence", "severity", "title", "summary",
                "how_to_verify", "report_claims", "oracle_context_digest", "artifact_manifest",
                # APEX PR-A — the SIGNED presentation block (plain-language impact + standards chips + exact
                # remediation). Projected through this SAME allowlist, but ONLY while VIGIL_APEX_PRESENTATION is
                # on (see ``_finding_json``), so the flag-off findings read is byte-identical (a presentation-
                # bearing cert is never surfaced) — on the fold-cache path too, whose index is keyed by the flag
                # (see ``_indexed``). It is additive SIGNED data that rides the per-finding tenant-
                # scoped projection, so a cross-tenant presentation can never leak, and is purely descriptive —
                # never read for any verdict.
                "presentation")

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


def _presentation_on() -> bool:
    """True iff the APEX PR-A presentation spine is armed (``config.presentation_enabled``). The scans read it at
    projection time; a fold-cache read reads it ONCE per read and binds that value into the index's cache identity
    (``_indexed``), so the fold index and the scan path agree for EVERY value of the flag — including a flag that
    changes inside a running process, which no longer leaves the index answering with the old value's rows."""
    from .. import config
    return config.presentation_enabled()


def _finding_json(payload: dict, cert: dict, *, present: Optional[bool] = None) -> dict[str, Any]:
    """One finding through the ``_CERT_FIELDS`` allowlist. ``present`` is the presentation flag the projection is
    made under: the fold index passes the value its view was built for (part of its cache identity); a scan passes
    nothing and reads the flag now."""
    out: dict[str, Any] = {"engagement_slug": cert.get("engagement_slug")}
    # finding_ref/oracle_context_digest live at the spine payload top level too (receiver mirrors them); prefer
    # the cert value, fall back to the payload, so the projection is robust to either carrier.
    if present is None:
        present = _presentation_on()
    for f in _CERT_FIELDS:
        if f == "presentation" and not present:
            continue                 # flag OFF -> presentation is never surfaced (the read stays byte-identical)
        v = cert.get(f, payload.get(f))
        if v is not None:
            # deep-copy the presentation block: it is a nested dict read by reference from the spine record, and
            # the scan path returns these rows directly (no later copy), so a caller must never alias the record.
            out[f] = copy.deepcopy(v) if f == "presentation" else v
    return out


class _AssessmentsView:
    """Front C S0d — the findings + outcomes index the projectors below read instead of scanning the whole spine
    per request: `findings[slug]` / `outcomes[slug]` = [(seq, projected json)] in spine order, built from EXACTLY
    the records the scans keep (same kind / dict / certificate checks; the projection is the same pure
    function). A record whose engagement slug is unhashable (the scans' `in slug_set` would raise on it) poisons
    the view, so every read falls back to the unchanged scan and raises exactly where it did.

    `presentation` is the APEX presentation flag the finding rows are projected under — fixed when the view is
    seeded, never re-read while folding, and part of the entry's cache identity (``_indexed``): a read under the
    other value rebuilds rather than answer with rows projected under this one."""

    __slots__ = ("findings", "outcomes", "poisoned", "presentation")

    def __init__(self, presentation: bool = False) -> None:
        self.findings: dict = {}
        self.outcomes: dict = {}
        self.poisoned = False
        self.presentation = bool(presentation)


def _assessments_step(view: _AssessmentsView, r, _ctx) -> None:
    kind = getattr(r, "kind", None)
    if kind != _FINDING_KIND and kind != _OUTCOME_KIND:
        return
    p = r.payload
    if not isinstance(p, dict):
        return
    cert = None
    if kind == _FINDING_KIND:
        cert = p.get("certificate")
        # Agents append kind="finding" records with NO certificate (actor.py, bastion, archivist, artificer):
        # they carry no engagement slug, so no reader can ever ask for them.
        slug = cert.get("engagement_slug") if isinstance(cert, dict) else None
        index = view.findings
    else:
        slug, index = p.get("engagement_slug"), view.outcomes
    try:
        hash(slug)
    except TypeError:
        view.poisoned = True                     # an unhashable slug: the scans compare by ==, so decline
        return
    if not isinstance(slug, str):
        return                                   # readers ask for str slugs only: keep no unreadable rows
    # a str slug on a finding => a dict cert; projected under the view's OWN flag value (its cache identity)
    row = _finding_json(p, cert, present=view.presentation) if isinstance(cert, dict) else _outcome_json(p)
    index.setdefault(slug, []).append((int(getattr(r, "seq", 0)), row))


_ASSESSMENTS_FOLD = FoldCache("ui.assessments", step=_assessments_step)


def _unpresented(row: dict) -> dict:
    """``row`` without its ``presentation`` field — a new dict when it had one (the cached row is never mutated),
    else ``row`` itself."""
    if "presentation" not in row:
        return row
    return {k: v for k, v in row.items() if k != "presentation"}


def _indexed(store, which: str, slugs) -> Any:
    """[(seq, json)] of the indexed `which` rows ('findings' / 'outcomes') for `slugs`, or `_UNCACHED`. A
    `live_window` read: the scans never load the snapshot, so a snapshot that cannot be loaded declines.

    A finding row's projection depends on the APEX presentation flag (``_finding_json``), so the flag is read ONCE
    per read and is part of the fold's cache IDENTITY: the view is seeded with it (every step projects under it) and
    an entry built under the other value never answers — the read rebuilds under its own. A read with the flag OFF
    also drops any ``presentation`` field from the rows it returns: a second, independent refusal, so no cached row
    can surface the signed block while the flag is off."""
    present = _presentation_on()

    def reader(v: _AssessmentsView) -> list:
        rows = [row for s in slugs for row in getattr(v, which).get(s, ())]
        return rows if present else [(seq, _unpresented(j)) for seq, j in rows]

    return cached_unsigned_read(_ASSESSMENTS_FOLD, store, seed=lambda snap: (_AssessmentsView(present), -1),
                                live_window=True, identity=("presentation", present), reader=reader)


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


def all_findings_for_org(store, org_id: str, *, now: float) -> "list[dict[str, Any]]":
    """Every oracle-confirmed finding (projected, newest-first) for ONE org's authorized assessments — the
    COMPLETE tenant-scoped set, UNPAGINATED, for a whole-tenant aggregate such as the APEX PR-A posture score.
    Tenant-scoped identically to :func:`assessment_findings` (the IDOR class — another tenant's finding is
    STRUCTURALLY never returned, because the slug set is the org's OWN server-derived set from its current
    ownership proofs, and ``_customer_slug`` is a one-way hash of ``org_id\\x00host``). Every row is a proven
    finding (it carries a certificate with an engagement slug in the org's set). PURE read; assumes the caller
    already authorized ``org_id`` for ``view_assessments``."""
    slug_set = _org_slug_set(store, org_id, now=now)
    if not slug_set:                                    # no proven hosts -> no slugs -> no findings (fail-closed)
        return []
    rows = _all_finding_rows(store, slug_set)
    rows.sort(key=lambda t: t[0], reverse=True)         # newest-first by spine seq
    return [j for _s, j in rows]


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


def finding_identity(row: "dict[str, Any]") -> "tuple[str, str, str]":
    """C1b — the identity a retest names ONE finding by: ``(engagement_slug, finding_ref, oracle_context_digest)``.
    ``finding_ref`` alone is NOT unique (it is a check id, a finding slug or merely the bug class — two findings on
    one host can share it), so the digest of the finding's retained proof context is part of the identity: a retest
    re-runs exactly ONE proof, and its verdict may mark exactly that finding fixed, never a sibling sharing its ref.
    A missing digest reads as "" on both sides (the lookup and the overlay agree)."""
    return (str(row.get("engagement_slug") or ""), str(row.get("finding_ref") or ""),
            str(row.get("oracle_context_digest") or ""))


def find_finding(store, org_id: str, finding_ref: str, *, engagement_slug: str, oracle_context_digest: str = "",
                 now: float) -> "Optional[dict[str, Any]]":
    """C1b — the org's OWN finding with exactly this identity (:func:`finding_identity`), or None. The slug must be
    one of the org's EVER-proven slugs (``ever_proven_hosts`` → ``_customer_slug``): another tenant's slug is a
    one-way hash of THAT tenant's ``org_id\\x00host`` and is never in this org's set, so naming another tenant's
    finding — even with its exact slug, ref and digest — returns None (the IDOR guard is structural). EVER-proven
    (not only currently proven) so a finding on a host whose proof just lapsed is still FOUND, and the retest's
    launch gate then gives the precise 'verify the host again' refusal rather than a confusing 'not found'. Returns
    the NEWEST matching record's projected fields plus the resolved ``host``. PURE read; assumes the caller already
    authorized ``org_id`` for ``view_assessments``."""
    from .target_authorization import _customer_slug
    want = (str(engagement_slug or ""), str(finding_ref or ""), str(oracle_context_digest or ""))
    if not want[0] or not want[1]:
        return None
    host_of = {_customer_slug(org_id, h): h for h in AssetOwnershipRegistry(store, owner_key=None).ever_proven_hosts(org_id)}
    host = host_of.get(want[0])
    if host is None:                                # not this org's slug → structurally unreachable (IDOR)
        return None
    best: "Optional[tuple[int, dict[str, Any]]]" = None
    for r in store.iter_records():
        if getattr(r, "kind", None) != _FINDING_KIND:
            continue
        p = r.payload
        if not isinstance(p, dict):
            continue
        cert = p.get("certificate")
        if not isinstance(cert, dict) or cert.get("engagement_slug") != want[0]:
            continue
        row = _finding_json(p, cert)
        if finding_identity(row) != want:
            continue
        seq = int(getattr(r, "seq", 0))
        if best is None or seq > best[0]:
            best = (seq, {**row, "host": host})
    return best[1] if best else None


def overlay_retests(store, findings: "list[dict[str, Any]]", *, now: float) -> None:
    """C1b — overlay each shown finding's NEWEST retest verdict in place as ``f["retest"] = {"status", "ts"}``
    (``status`` ∈ {``fixed``, ``still_vulnerable``}), matched on the full :func:`finding_identity` — so a verdict
    marks exactly the finding whose proof was re-run, never a sibling that shares its ``finding_ref``. ``findings``
    is an ALREADY tenant-scoped page (from :func:`assessment_findings`): the scan is bounded to the
    ``engagement_slug`` values present in it, so a ``finding_retest`` record for any other tenant's slug can match
    nothing here (tenant isolation is structural, exactly as the findings read's). A no-op — leaving the page
    byte-identical — when nothing on it was retested. Called ONLY from the customer findings projector while
    ``customer_retest_ui_enabled`` is on, so the shared :func:`assessment_findings` and the owner read stay unchanged."""
    want = {finding_identity(f)[0] for f in findings if isinstance(f, dict)}
    want.discard("")
    if not want:
        return
    latest: "dict[tuple, tuple]" = {}
    for r in store.iter_records():
        if getattr(r, "kind", None) != RETEST_KIND:
            continue
        # a second, independent refusal: only the provisioner's retest action writes verdicts (``source`` is digested
        # record content) — a record of this kind from anywhere else, e.g. a drain that came to admit it, never counts
        if getattr(r, "source", None) != RETEST_SOURCE:
            continue
        p = r.payload
        if not isinstance(p, dict):
            continue
        if p.get("engagement_slug") not in want:    # only the shown findings' own slugs → never another tenant's
            continue
        status = p.get("status")
        if not isinstance(p.get("finding_ref"), str) or status not in ("fixed", "still_vulnerable"):
            continue
        seq = int(getattr(r, "seq", 0))
        key = finding_identity(p)
        prev = latest.get(key)
        if prev is None or seq > prev[0]:           # newest verdict per finding wins
            latest[key] = (seq, status, p.get("ts"))
    if not latest:
        return
    for f in findings:
        if not isinstance(f, dict):
            continue
        v = latest.get(finding_identity(f))
        if v is not None:
            f["retest"] = {"status": v[1], "ts": v[2]}


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
