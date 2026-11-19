"""jobs.notify_drain — PR-D: drain NEW FACT findings to a tenant's out-of-band channels + sync issue trackers.

THE ORCHESTRATOR (Area 3). For each org that has configured notify channels: resolve the org's OWN engagement-slug
set SERVER-SIDE (injected ``slug_set_for`` — wired to ``sigil.ui.assessments._org_slug_set``), read its FACT
findings (injected ``findings_for`` — wired to the ``sigil.ui.assessments`` finding read, already tenant-scoped),
DELIVER each NOT-yet-delivered finding to the org's channels (injected ``deliver`` — wired to
``sigil.governor.notify_channels``), RECORD the delivery (injected ``record_delivery`` — the idempotency ledger),
then PLAN + APPLY issue-tracker actions (open new FACTs, close cleared ones).

TENANT ISOLATION is STRUCTURAL and RE-ASSERTED here. A finding is handed to an org ONLY if its signed
``engagement_slug`` is in THAT org's server-derived slug set — and this drain RE-CHECKS that membership per finding
(belt-and-suspenders), so even a buggy or hostile injected reader can never leak one tenant's finding to another.
Dropping that re-check REDS ``test_notify_drain.test_cross_tenant_reader_is_rejected`` (the mutation-verify).

FATAL-2 + plane-pure. STDLIB ONLY (``dataclasses`` / ``typing``) — this module NEVER imports ``sigil`` (integration
declares ``vigil-core`` only, and nothing here needs it), NEVER imports ``framework`` / ``strix``. ALL sovereign
logic (slug resolution, the finding read, channel delivery, issue sync) is INJECTED through :class:`DrainDeps`, so
the sovereignty boundary is unbroken. A NOTIFICATION IS NEVER A FACT SOURCE: this drain performs NO spine write of
a finding; its only side effects are the delivery/issue LEDGERS (never the signed finding spine) and the egress the
injected deps perform.

FLAG: with ``enabled=False`` (wired from ``config.customer_notify_enabled()``) :func:`drain_once` is a total no-op —
it touches NONE of the injected deps and returns an empty result, so the drain is inert byte-for-byte when the
master flag is off.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, NamedTuple, Optional, Sequence


def finding_identity(row: dict[str, Any]) -> "tuple[str, str, str]":
    """``(engagement_slug, finding_ref, oracle_context_digest)`` — the same stable 3-tuple the sovereign side keys a
    finding by (``sigil.ui.assessments.finding_identity`` / ``governor.issue_sync.finding_identity``). Defined
    locally so the drain stays ``vigil_core``-free; the shape is a contract shared by writer and reader."""
    return (str(row.get("engagement_slug") or ""), str(row.get("finding_ref") or ""),
            str(row.get("oracle_context_digest") or ""))


class DeliverOutcome(NamedTuple):
    """What an injected ``deliver`` reports for ONE channel send: accepted or not, and whether a failure is
    retryable. The sigil wiring maps ``notify_channels.DeliveryResult`` onto this (keeping the drain decoupled from
    the sovereign type)."""

    ok: bool
    transient: bool = False


@dataclass(frozen=True)
class DrainDeps:
    """The injected sovereign seams the drain drives. Every one is wired on the sigil side (which may import both
    planes); the drain itself imports none of them. Issue sync is OPTIONAL — a deployment with channels but no
    tracker leaves ``plan_issues`` / ``apply_issue`` unset and only delivers."""

    #: org_id -> the org's OWN engagement-slug set (server-derived from its ownership proofs). Empty ⇒ nothing.
    slug_set_for: Callable[[str], "set[str]"]
    #: (org_id, slug_set) -> the org's FACT-finding projections (already tenant-scoped by the slug set).
    findings_for: Callable[[str, "set[str]"], "Sequence[dict[str, Any]]"]
    #: org_id -> the org's configured channels (opaque to the drain; passed back to ``deliver``).
    channels_for: Callable[[str], "Sequence[Any]"]
    #: (org_id, channel, finding_row) -> the delivery outcome. The ONLY place a notice egresses.
    deliver: Callable[[str, Any, "dict[str, Any]"], DeliverOutcome]
    #: (org_id, identity) -> True iff this finding was already delivered for this org (idempotency).
    already_delivered: Callable[[str, "tuple[str, str, str]"], bool]
    #: (org_id, identity) -> None. Mark a finding delivered for this org.
    record_delivery: Callable[[str, "tuple[str, str, str]"], None]
    #: (org_id, findings) -> planned issue actions (opaque). Unset ⇒ no issue sync.
    plan_issues: "Optional[Callable[[str, Sequence[dict[str, Any]]], Sequence[Any]]]" = None
    #: (org_id, action) -> "open" | "close" | "" (what was applied). Unset ⇒ no issue sync.
    apply_issue: "Optional[Callable[[str, Any], str]]" = None


@dataclass(frozen=True)
class DrainResult:
    """What one :func:`drain_once` pass did (counts only — never a finding's content, so a log line is inert)."""

    orgs: int = 0
    delivered: int = 0            # findings fully handed off (recorded) this pass
    skipped: int = 0             # findings already delivered (idempotent no-op)
    sends_ok: int = 0            # individual channel sends accepted
    issues_opened: int = 0
    issues_closed: int = 0
    errors: int = 0              # channel send failures, cross-tenant rejections, per-op exceptions
    rejected_cross_tenant: int = 0  # findings refused because their slug was not the org's (the structural guard)
    notes: list[str] = field(default_factory=list)


def _deliver_finding(deps: DrainDeps, org_id: str, channels: "Sequence[Any]",
                     finding: dict[str, Any]) -> "tuple[int, int, bool]":
    """Deliver ONE finding to ALL of an org's channels. Returns (sends_ok, send_errors, any_transient). The finding
    is recorded delivered by the caller only when no send failed TRANSIENTLY (a definitive failure won't be cured by
    a retry, so it does not block the ledger forever; a transient one leaves the finding for the next pass)."""
    ok = errors = 0
    any_transient = False
    for channel in channels:
        try:
            outcome = deps.deliver(org_id, channel, finding)
        except Exception:  # noqa: BLE001 — one channel's failure never sinks the finding or the pass
            errors += 1
            any_transient = True      # an unexpected error is treated as retryable (do not record as delivered)
            continue
        if outcome.ok:
            ok += 1
        else:
            errors += 1
            any_transient = any_transient or bool(outcome.transient)
    return ok, errors, any_transient


def _sync_issues(deps: DrainDeps, org_id: str, findings: "Sequence[dict[str, Any]]") -> "tuple[int, int, int]":
    """Plan + apply this org's issue actions. Returns (opened, closed, errors). A no-op unless BOTH issue-sync deps
    are wired. Each apply is isolated — one failure counts an error and the rest proceed."""
    if deps.plan_issues is None or deps.apply_issue is None:
        return 0, 0, 0
    opened = closed = errors = 0
    try:
        actions = list(deps.plan_issues(org_id, findings))
    except Exception:  # noqa: BLE001 — a planning failure never sinks the pass
        return 0, 0, 1
    for action in actions:
        try:
            applied = deps.apply_issue(org_id, action)
        except Exception:  # noqa: BLE001
            errors += 1
            continue
        if applied == "open":
            opened += 1
        elif applied == "close":
            closed += 1
    return opened, closed, errors


def drain_once(deps: DrainDeps, orgs: "Sequence[str]", *, now: float, enabled: bool = True) -> DrainResult:
    """Run ONE notify-drain pass over ``orgs``. FLAG-GATED: ``enabled=False`` ⇒ a total no-op (NONE of ``deps`` is
    called; an empty :class:`DrainResult` is returned) so the drain is inert when ``VIGIL_CUSTOMER_NOTIFY`` is off.

    For each org: resolve its OWN slug set; read its FACT findings; for each finding NOT already delivered, RE-ASSERT
    its ``engagement_slug`` is in the org's slug set (the structural cross-tenant guard — a finding that fails it is
    REJECTED, never delivered), deliver to the org's channels, and record it; then sync issues. Total — a per-org
    exception is counted and the pass continues."""
    result = DrainResult()
    if not enabled:
        return result
    orgs_seen = delivered = skipped = sends_ok = opened = closed = errors = cross = 0
    notes: list[str] = []
    for org_id in orgs:
        if not isinstance(org_id, str) or not org_id:
            continue
        orgs_seen += 1
        try:
            slug_set = set(deps.slug_set_for(org_id))
        except Exception:  # noqa: BLE001
            errors += 1
            continue
        if not slug_set:                      # no proven host ⇒ no slug ⇒ nothing to deliver (fail-closed)
            continue
        channels = list(deps.channels_for(org_id))
        try:
            findings = list(deps.findings_for(org_id, slug_set))
        except Exception:  # noqa: BLE001
            errors += 1
            continue
        delivered_this: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            identity = finding_identity(finding)
            if not identity[0] or not identity[1]:
                continue                       # not a FACT finding projection (no slug/ref) — never delivered
            slug = str(finding.get("engagement_slug") or "")
            if slug not in slug_set:
                # STRUCTURAL CROSS-TENANT GUARD: a finding whose slug is not this org's own server-derived slug is
                # REFUSED here, even if the injected reader wrongly returned it. Removing this line REDS the
                # cross-tenant mutation test. The finding is never delivered and never recorded for this org.
                cross += 1
                errors += 1
                continue
            delivered_this.append(finding)
            if deps.already_delivered(org_id, identity):
                skipped += 1
                continue
            if channels:
                ok, send_errors, any_transient = _deliver_finding(deps, org_id, channels, finding)
                sends_ok += ok
                errors += send_errors
                if any_transient:
                    continue                   # leave it for the next pass; do NOT record as delivered
            deps.record_delivery(org_id, identity)
            delivered += 1
        o, c, e = _sync_issues(deps, org_id, delivered_this)
        opened += o
        closed += c
        errors += e
    if cross:
        notes.append(f"rejected {cross} cross-tenant finding(s)")
    return DrainResult(orgs=orgs_seen, delivered=delivered, skipped=skipped, sends_ok=sends_ok,
                       issues_opened=opened, issues_closed=closed, errors=errors,
                       rejected_cross_tenant=cross, notes=notes)
