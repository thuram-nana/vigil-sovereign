"""#4 — the ONE org offboarding/decommission cascade (governor.decommission.decommission_org).

Load-bearing invariants:
  * the whole tenant goes out of service in one owner op: org revoked, every membership revoked, plan canceled,
    and each customer whose ONLY org it was loses their account AND every enrolled factor;
  * NO cross-tenant collateral: a customer still active in another org keeps account + factors + that membership;
  * money records are RETAINED (never erased) yet unreachable — the wallet ledger still holds the balance, but no
    one is admitted to read it (no active member of an active org);
  * idempotent (re-run changes nothing) and no resurrection if the org_id is re-created;
  * a sibling org is untouched.
"""
from __future__ import annotations

import itertools
import tempfile

from sigil.governor.customer_credentials import CustomerCredentialRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.decommission import decommission_org
from sigil.governor.orgs import OrgRegistry
from sigil.governor.subscription import STATUS_CANCELED, SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_iss = itertools.count(1)


def _t():
    return float(next(_iss))


def _kw():
    return {"owner_key": OWNER, "trusted_pubkey": OP}


def _world():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    orgs, cust = OrgRegistry(s, **_kw()), CustomerRegistry(s, **_kw())
    creds, subs = CustomerCredentialRegistry(s, **_kw()), SubscriptionRegistry(s, **_kw())
    wallet = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    for oid in ("orgA", "orgB"):
        orgs.create_org(oid, oid, owner="owner", issued_at=_t())
        subs.subscribe(oid, "plan_pro", 100, period_start=0.0, period_end=1e12, issued_at=_t())
    solo, _ = cust.create("solo@a.com", issued_at=_t(), password="pw-solo-123456")      # only in A
    both, _ = cust.create("both@ab.com", issued_at=_t(), password="pw-both-123456")     # in A and B
    bonly, _ = cust.create("b@b.com", issued_at=_t(), password="pw-bonly-123456")       # only in B
    orgs.grant_membership("orgA", solo, "org_admin", issued_at=_t())
    orgs.grant_membership("orgA", both, "viewer", issued_at=_t())
    orgs.grant_membership("orgB", both, "org_admin", issued_at=_t())
    orgs.grant_membership("orgB", bonly, "viewer", issued_at=_t())
    for u in (solo, both, bonly):
        creds.enroll_totp(u, sealed_secret=f"SEAL-{u}", issued_at=_t())
    creds.enroll_passkey(solo, "cred-solo", cose_alg=-7, public_key_spki_b64="PK", uv=True, issued_at=_t())
    wallet.grant("orgA", 500, "topup", entry_id="seed-a", issued_at=_t())
    wallet.grant("orgB", 300, "topup", entry_id="seed-b", issued_at=_t())
    return s, orgs, cust, creds, subs, wallet, solo, both, bonly


def test_cascade_takes_the_whole_tenant_out_of_service():
    s, orgs, cust, creds, subs, wallet, solo, both, bonly = _world()
    rep = decommission_org(s, "orgA", **_kw())
    o2, c2, cr2, s2 = OrgRegistry(s, **_kw()), CustomerRegistry(s, **_kw()), CustomerCredentialRegistry(s, **_kw()), SubscriptionRegistry(s, **_kw())
    assert o2.org("orgA") is None                                   # org revoked
    assert o2.memberships("orgA") == []                             # every membership revoked
    assert o2.membership_role(solo, "orgA") is None and o2.membership_role(both, "orgA") is None
    assert s2.subscription("orgA").status == STATUS_CANCELED        # plan canceled
    assert c2.customer(solo) is None and cr2.for_user(solo) == []   # sole-org customer: account + factors gone
    assert rep.accounts_revoked == [solo]
    assert sorted(k for u, k in rep.credentials_revoked if u == solo) == ["cred-solo", "totp"]


def test_no_cross_tenant_collateral_for_a_multi_org_customer():
    s, orgs, cust, creds, subs, wallet, solo, both, bonly = _world()
    rep = decommission_org(s, "orgA", **_kw())
    o2, c2, cr2 = OrgRegistry(s, **_kw()), CustomerRegistry(s, **_kw()), CustomerCredentialRegistry(s, **_kw())
    assert both in rep.accounts_retained and both not in rep.accounts_revoked
    assert c2.customer(both) is not None                            # account kept
    assert [c.cred_key for c in cr2.for_user(both)] == ["totp"]     # factors kept
    assert o2.membership_role(both, "orgB") == "org_admin"          # B membership intact


def test_sibling_org_untouched_and_money_retained_but_unreachable():
    s, orgs, cust, creds, subs, wallet, solo, both, bonly = _world()
    decommission_org(s, "orgA", **_kw())
    o2, s2 = OrgRegistry(s, **_kw()), SubscriptionRegistry(s, **_kw())
    w2 = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    assert o2.org("orgB") is not None and s2.subscription("orgB").status != STATUS_CANCELED
    assert o2.membership_role(bonly, "orgB") == "viewer"
    assert w2.available("orgB") == 300
    assert w2.available("orgA") == 500                               # ledger RETAINED (never erased)...
    assert not any(o2.org_role_can(u, "orgA", "view_billing") for u in (solo, both, bonly))  # ...but no one admitted


def test_idempotent_and_no_resurrection_on_recreate():
    s, orgs, cust, creds, subs, wallet, solo, both, bonly = _world()
    decommission_org(s, "orgA", **_kw())
    rep2 = decommission_org(s, "orgA", **_kw())                      # re-run: nothing left to revoke
    assert rep2.members == [] and rep2.accounts_revoked == [] and rep2.credentials_revoked == []
    OrgRegistry(s, **_kw()).create_org("orgA", "orgA reborn", owner="owner", issued_at=_t())
    o3 = OrgRegistry(s, **_kw())
    assert o3.org("orgA") is not None
    assert o3.membership_role(both, "orgA") is None and o3.membership_role(solo, "orgA") is None
