"""AEGIS-SaaS — the SEPARATE owner-signed MONITORING subscription line, and the plan → grant enforcement.

Buying an AEGIS monitoring plan must never overwrite a tenant's credit-plan subscription (``governor.subscription``,
which drives the plan-credit refill). So monitoring rides its OWN record: ``governor.monitoring_subscription``,
keyed per org, with the IDENTICAL owner-signed LWW / high-water / asymmetric-auth semantics (it IS a
``SubscriptionRegistry`` under a different signal — the signal is inside the signed core, so a record of one line
can never be folded into the other) and its own hard-prune seed (snapshot v7 ``monitoring_subscription_*`` +
``spine.prune.stranded_active_monitoring_subscriptions``).

BILLING STANDING BOUNDS MONITORING CONTINUOUSLY (not only at mint):
  * ``plan_enforcement`` is the pure decision: which of an org's monitoring grants the CURRENT monitoring plan
    no longer pays for (no active plan → all; block grants on a non-respond tier; grants beyond the host-slot
    count, keeping the earliest-issued), and which surviving grants were minted in a PRIOR period and should be
    re-minted for the current one (renewal continuity — done by the sovereign provisioner, which holds the key).
  * ``reconcile_monitoring`` applies the retirements (revoke + unpublish; the SAFE direction, keyless). It runs
    as a governor-level cascade on every monitoring-subscription change (cancel / past_due / plan change) and as
    a periodic sweep (``sigil monitoring-reconcile`` / the monitoring-drain watch loop) that catches a period
    lapse with no webhook.

FATAL-2: SOVEREIGN-only; imports no framework.
"""
from __future__ import annotations

from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from .subscription import STATUS_ACTIVE, SubscriptionRegistry  # noqa: E402

MONITORING_SUBSCRIPTION_SIGNAL = "governor.monitoring_subscription"


class MonitoringSubscriptionRegistry(SubscriptionRegistry):
    """The per-org AEGIS monitoring plan line (separate from the credit-plan ``governor.subscription``)."""
    SIGNAL = MONITORING_SUBSCRIPTION_SIGNAL
    _SNAP = "monitoring_subscription"

    def subscribe(self, org_id: str, plan_id: str, allotment: int, *,
                  period_start: float, period_end: float, issued_at: float) -> int:
        """Owner-sign a monitoring plan period, then ENFORCE it on the org's existing grants (tier + slots) at
        ``period_start`` — only when this record is the one the fold honors (a stale/replayed subscribe is inert
        and must not trigger enforcement against a period it does not represent)."""
        from .catalog import monitoring_plan
        if monitoring_plan(plan_id) is None:
            raise ValueError(f"{plan_id!r} is not a catalog monitoring plan")
        seq = super().subscribe(org_id, plan_id, allotment, period_start=period_start, period_end=period_end,
                                issued_at=issued_at)
        s = self.subscription(org_id)
        if s is not None and s.status == STATUS_ACTIVE and (s.plan_id, s.period_start, s.period_end) == \
                (plan_id, float(period_start), float(period_end)):
            reconcile_monitoring(self.store, now=float(period_start), org_id=s.org_id, subscriptions=self)
        return seq

    def _append_down(self, org_id: str, status: str, *, issued_at: float = 0.0) -> int:
        """cancel / past_due (the SAFE direction) — and, when the fold now reads the line NOT active, CASCADE:
        retire (revoke + unpublish) every monitoring grant of the org (like orgs.revoke_org → revoke_org)."""
        seq = super()._append_down(org_id, status, issued_at=issued_at)
        s = self.subscription(org_id)
        if s is None or s.status != STATUS_ACTIVE:
            from .monitoring_authority import MonitoringAuthorityRegistry
            MonitoringAuthorityRegistry(self.store, owner_key=self.owner_key,
                                        trusted_pubkey=self.trusted_pubkey).revoke_org(org_id)
        return seq


def plan_enforcement(store, org_id: str, *, now: float, subscriptions=None, authority=None):
    """The pure decision for one org at ``now``: ``(retire_hosts, renew_grants, subscription)``.

    A grant HOLDS a slot iff it is still backed by its current ownership proof (``authority.owned_at``) and is
    either inside its window at ``now`` (the same predicate as ``active_at``) or was minted in a PRIOR period of
    the active plan (``not_before < period_start`` — a renewal candidate). Grants that hold nothing (expired in
    the current period, ownership lapsed) are left alone — they are already inert and free their slot."""
    from .catalog import monitoring_plan
    from .monitoring_authority import MODE_BLOCK, MonitoringAuthorityRegistry
    t = float(now)
    subs = subscriptions if subscriptions is not None else MonitoringSubscriptionRegistry(store, owner_key=None)
    reg = authority if authority is not None else MonitoringAuthorityRegistry(
        store, owner_key=None, trusted_pubkey=subs.trusted_pubkey)
    grants = sorted(reg.grants(org_id), key=lambda g: (g.issued_at, g.host))
    sub = subs.active_subscription(org_id, now=t)
    plan = monitoring_plan(sub.plan_id) if sub is not None else None
    if sub is None or plan is None:
        return [g.host for g in grants], [], None
    retire: list[str] = []
    renew = []
    kept = 0
    for g in grants:
        prior = g.not_before < sub.period_start
        if not reg.owned_at(org_id, g.host, now=t) or not (g.covers(t) or prior):
            continue                                   # inert already; holds no slot
        if g.mode == MODE_BLOCK and not plan.respond:
            retire.append(g.host)
            continue
        if kept >= plan.host_slots:
            retire.append(g.host)                      # beyond the paid slots: keep earliest-issued
            continue
        kept += 1
        if prior:
            renew.append(g)
    return retire, renew, sub


def reconcile_monitoring(store, *, now: float, org_id: Optional[str] = None, subscriptions=None) -> list:
    """Apply the plan's retirements (revoke + unpublish) for one org, or — the SWEEP — for every org holding a
    monitoring grant or a monitoring subscription. Keyless (revoke is the safe direction). Returns the retired
    ``(org_id, host)`` pairs. Renewal re-mints are NOT done here (they need the owner key: the provisioner)."""
    from .monitoring_authority import MonitoringAuthorityRegistry
    subs = subscriptions if subscriptions is not None else MonitoringSubscriptionRegistry(store, owner_key=None)
    akey = subscriptions.owner_key if subscriptions is not None else None   # the sweep never signs
    reg = MonitoringAuthorityRegistry(store, owner_key=akey, trusted_pubkey=subs.trusted_pubkey)
    if org_id is not None:
        orgs = [org_id]
    else:
        orgs = sorted({o for (o, _h) in reg._fold()} | {s.org_id for s in subs.subscriptions()})
    out = []
    for oid in orgs:
        retire, _renew, _sub = plan_enforcement(store, oid, now=now, subscriptions=subs, authority=reg)
        for h in retire:
            reg.retire(oid, h)
            out.append((oid, h))
    return out
