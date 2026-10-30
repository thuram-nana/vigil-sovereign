"""Slice E1 — the dedicated `OrgRegistry.admit_customer` gate (NO global leg).

The design-pass isolation critic flagged `admit`'s global leg as a cross-tenant skeleton key: a customer
request path that copied the operator idiom `admit(global_role=principal.role, …)` and carried a stored
per-org role in `global_role` would be admitted to ANY org. `admit_customer` closes that structurally —
it takes NO `global_role` parameter, so a customer can never present a global role to cross tenants.

Load-bearing invariants:
  * a customer is admitted ONLY for their own org and only for their per-org role's permissions;
  * cross-org and non-member are default-denied;
  * billing != testing holds structurally — a customer (even a per-org `operator`) NEVER reaches
    `offense_authority` / `manage_users` / `secrets` / `manage_billing` (all owner-only), so registering
    or paying can never authorize an assessment;
  * `admit_customer` has no global leg, unlike `admit` (contrast asserted directly).
"""
from __future__ import annotations

import itertools
import tempfile

from sigil.governor.orgs import OrgRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _orgs():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    it = itertools.count(1)
    orgs.create_org("acme", "Acme", owner="owner", issued_at=float(next(it)))
    orgs.create_org("other", "Other", owner="owner", issued_at=float(next(it)))
    orgs.grant_membership("acme", "cust_alice", "operator", issued_at=float(next(it)))
    return orgs


def test_admit_customer_grants_only_own_org():
    orgs = _orgs()
    # alice is a per-org operator in acme → operator-tier perms IN acme (incl. reading her own billing)
    assert orgs.admit_customer(username="cust_alice", org_id="acme", permission="read") is True
    assert orgs.admit_customer(username="cust_alice", org_id="acme", permission="view_billing") is True
    assert orgs.admit_customer(username="cust_alice", org_id="acme", permission="view_invoices") is True
    # ...but NOTHING in another org (no membership there, and NO global leg to fall back on)
    assert orgs.admit_customer(username="cust_alice", org_id="other", permission="read") is False
    assert orgs.admit_customer(username="cust_alice", org_id="other", permission="view_billing") is False
    # a non-member is denied even in acme
    assert orgs.admit_customer(username="cust_bob", org_id="acme", permission="read") is False


def test_admit_customer_never_reaches_testing_or_admin_authority():
    # billing != testing, structurally: a per-org operator customer can never reach the owner-only
    # permissions — above all `offense_authority` (the testing-authority mint `target_add` requires).
    orgs = _orgs()
    for owner_only in ("offense_authority", "manage_users", "secrets", "manage_billing",
                       "manage_members", "manage_org", "promote", "kill_release"):
        assert orgs.admit_customer(username="cust_alice", org_id="acme", permission=owner_only) is False


def test_admit_customer_has_no_global_leg_unlike_admit():
    orgs = _orgs()
    # admit's GLOBAL leg admits ANY caller whose global role carries the perm to ANY org (the skeleton
    # key the critic flagged) — here a non-member with a global operator role reads `other`:
    assert orgs.admit(global_role="operator", username="nobody", org_id="other", permission="read") is True
    # admit_customer has NO global_role parameter, so a customer can never cross tenants that way:
    assert orgs.admit_customer(username="nobody", org_id="other", permission="read") is False


def test_admit_customer_default_deny_on_unmapped_permission():
    orgs = _orgs()
    assert orgs.admit_customer(username="cust_alice", org_id="acme", permission=None) is False
    assert orgs.admit_customer(username="cust_alice", org_id="acme", permission="") is False
    # a revoked membership loses access immediately (resolved live from the fold, never cached)
    orgs.revoke_membership("acme", "cust_alice")
    assert orgs.admit_customer(username="cust_alice", org_id="acme", permission="read") is False
