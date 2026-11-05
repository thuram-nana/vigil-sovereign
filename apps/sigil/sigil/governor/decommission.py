"""Org offboarding / decommission cascade — ONE owner operation that takes a tenant fully out of service.

It composes ONLY existing SAFE-direction governor latches (each owner-signed for audit, honored on sight, fixed
`issued_at` 0.0, idempotent, replay-safe). It mints nothing and grants nothing:

  1. `OrgRegistry.revoke_org`        — org latched revoked; cascade-revokes every membership (no resurrection
                                        if the org_id is ever re-created).
  2. `SubscriptionRegistry.cancel`   — plan latched canceled (no further period mint).
  3. per former member, ONLY IF this org was their LAST active membership:
       `CustomerCredentialRegistry.revoke` for every active credential (passkey/TOTP/OIDC link), then
       `CustomerRegistry.revoke` for the account. A customer still active in ANOTHER org keeps their account
       and factors — decommissioning tenant A must never lock a user out of tenant B.

RETAINED, NOT DELETED (money/audit doctrine): the wallet ledger, invoices and metering records are append-only
signed history and are never erased. They become unreachable by construction — every billing/invoice read is
gated on an ACTIVE membership of an ACTIVE org, both of which step 1 removes.

OUT OF SCOPE until #42: MonitoringAuthority revocation (the AEGIS-SaaS mint path does not exist yet; when it
lands its revoke joins this cascade).

Ordering is fail-SAFE: the org revoke lands FIRST, so a failure later in the cascade still leaves the tenant with
no admitted member. Re-running the cascade is a no-op in effect (every step is an idempotent re-latch).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..reuse import assert_no_offense

assert_no_offense()

from .customer_credentials import CustomerCredentialRegistry  # noqa: E402
from .customers import CustomerRegistry  # noqa: E402
from .orgs import OrgRegistry, _check_org_id  # noqa: E402
from .subscription import SubscriptionRegistry  # noqa: E402


@dataclass
class DecommissionReport:
    org_id: str
    org_seq: int
    subscription_seq: int
    members: list[str] = field(default_factory=list)
    accounts_revoked: list[str] = field(default_factory=list)
    accounts_retained: list[str] = field(default_factory=list)   # still active in another org
    credentials_revoked: list[tuple[str, str]] = field(default_factory=list)


def decommission_org(store, org_id: str, *, owner_key=None, trusted_pubkey=None) -> DecommissionReport:
    """Offboard `org_id` (see module doc). Owner-only: callers must already be on the owner/provisioner path."""
    oid = _check_org_id(org_id)
    kw = {"owner_key": owner_key, "trusted_pubkey": trusted_pubkey}
    orgs = OrgRegistry(store, **kw)
    customers = CustomerRegistry(store, **kw)
    creds = CustomerCredentialRegistry(store, **kw)
    subs = SubscriptionRegistry(store, **kw)

    members = sorted({m.username for m in orgs.memberships(oid)})   # snapshot BEFORE the cascade revokes them

    org_seq = orgs.revoke_org(oid)          # FIRST: fail-safe — the tenant admits no one from here on
    sub_seq = subs.cancel(oid)

    rep = DecommissionReport(org_id=oid, org_seq=org_seq, subscription_seq=sub_seq, members=members)
    for u in members:
        if customers.customer(u) is None:
            continue                        # not a customer principal (e.g. operator membership) — untouched
        if any(m.org_id != oid for m in orgs.memberships() if m.username == u):
            rep.accounts_retained.append(u)  # still a member elsewhere: never cross-tenant collateral
            continue
        for c in creds.for_user(u):
            creds.revoke(u, c.cred_key)
            rep.credentials_revoked.append((u, c.cred_key))
        customers.revoke(u)
        rep.accounts_revoked.append(u)
    return rep
