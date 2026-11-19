"""Consumer PR-F — the OWNER-side shard-placement-on-signup policy (``governor.shard_on_signup``).

Invariants pinned here:
  * LEAST-LOADED + DETERMINISTIC placement — the fewest-tenant shard, tie-broken by shard_id;
  * OWNER-SIGNED, a tenant CANNOT self-assign (RED-PEN #3) — the mint rides ``ShardAssignmentRegistry.assign``
    which requires the owner key; a tenant-supplied shard is never honored;
  * IDEMPOTENT — a tenant already placed is a no-op (safe under the idempotent-forward sign-up retry);
  * FAIL-SAFE — no owner topology ⇒ nothing is placed (never guessed onto a shard).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.shard_assignment import ShardAssignmentRegistry
from sigil.governor.shard_on_signup import assign_on_signup, choose_shard, current_loads
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from vigil_core import ShardAssignmentRecord, sign_shard_assignment_record

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)


def _t() -> float:
    return float(next(_c))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, key=OWNER, pub=OP):
    return ShardAssignmentRegistry(store, owner_key=key, trusted_pubkey=pub)


# -- choose_shard ------------------------------------------------------------------------------------

def test_choose_shard_picks_least_loaded():
    assert choose_shard(["s1", "s2", "s3"], {"s1": 5, "s2": 1, "s3": 9}) == "s2"


def test_choose_shard_prefers_an_empty_shard_absent_from_loads():
    assert choose_shard(["s1", "s2"], {"s1": 3}) == "s2"  # s2 absent -> load 0 -> preferred


def test_choose_shard_tie_breaks_deterministically_by_id():
    assert choose_shard(["s2", "s1"], {"s1": 0, "s2": 0}) == "s1"  # equal load -> lexicographic


def test_choose_shard_none_when_no_topology():
    assert choose_shard([], {}) is None
    assert choose_shard(["", ""], {}) is None  # blank ids filtered out


# -- current_loads -----------------------------------------------------------------------------------

def test_current_loads_counts_active_placements_per_shard():
    s = _store()
    reg = _reg(s)
    reg.assign("acme", "s1", issued_at=_t())
    reg.assign("beta", "s1", issued_at=_t())
    reg.assign("gamma", "s2", issued_at=_t())
    assert current_loads(reg) == {"s1": 2, "s2": 1}


# -- assign_on_signup --------------------------------------------------------------------------------

def test_assign_on_signup_places_a_new_tenant_least_loaded():
    s = _store()
    reg = _reg(s)
    reg.assign("existing", "s1", issued_at=_t())          # s1 now has 1, s2 has 0
    placement = assign_on_signup(reg, "newco", shard_ids=["s1", "s2"], issued_at=_t())
    assert placement is not None and placement.shard_id == "s2"  # least-loaded
    assert reg.placement("newco").shard_id == "s2"        # and it is owner-signed on the spine


def test_assign_on_signup_is_idempotent():
    s = _store()
    reg = _reg(s)
    first = assign_on_signup(reg, "newco", shard_ids=["s1", "s2"], issued_at=_t())
    # a retry (later issued_at, maybe different load) must NOT move the tenant or add a second placement.
    again = assign_on_signup(reg, "newco", shard_ids=["s1", "s2"], issued_at=_t())
    assert first.shard_id == again.shard_id
    assert len([p for p in reg.placements() if p.tenant_id == "newco"]) == 1


def test_assign_on_signup_no_topology_places_nothing():
    s = _store()
    reg = _reg(s)
    assert assign_on_signup(reg, "newco", shard_ids=[], issued_at=_t()) is None
    assert reg.placement("newco") is None                 # unassigned -> routing fails closed for it


# -- RED-PEN #3 — a tenant self-assigns a shard ------------------------------------------------------

def test_redpen_tenant_cannot_self_assign_without_the_owner_key():
    # The policy mints through a registry built WITHOUT the owner key (what a tenant-plane process would hold).
    s = _store()
    keyless = ShardAssignmentRegistry(s, owner_key=None, trusted_pubkey=OP)
    with pytest.raises(ValueError, match="owner signing key"):
        assign_on_signup(keyless, "newco", shard_ids=["s1"], issued_at=_t())
    # nothing was placed — a tenant cannot route itself onto a shard it was never owner-assigned.
    assert _reg(s).placement("newco") is None


def test_redpen_a_tenant_forged_assignment_record_is_inert():
    # Even if a tenant forges a signed assignment with its OWN key and appends it directly, the fold refuses it
    # (verified only under the OWNER pubkey), so the policy still sees the tenant as unassigned.
    s = _store()
    doc = ShardAssignmentRecord(tenant_id="newco", shard_id="s9", epoch=1, issued_at=_t())
    forged = sign_shard_assignment_record(doc, {"owner": ATTACKER.private_key_b64})
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={"signal": "governor.shard_assignment", "record": forged.model_dump(mode="json"),
                      "by": "owner", "requested_by": "owner", "tier": "A0", "decision": "auto", "reason": "forged"})
    reg = _reg(s)
    assert reg.placement("newco") is None                 # forged record inert -> still unassigned
    # a subsequent owner placement is NOT fooled into thinking it is already placed; it places for real.
    placement = assign_on_signup(reg, "newco", shard_ids=["s1"], issued_at=_t())
    assert placement is not None and placement.shard_id == "s1"


def test_redpen_tenant_cannot_choose_its_own_shard():
    # shard_ids is OWNER config; the policy never reads a shard from tenant input. Placing a tenant with an
    # owner topology that does NOT include a tenant's 'wish' shard still lands on an owner-named shard.
    s = _store()
    reg = _reg(s)
    placement = assign_on_signup(reg, "newco", shard_ids=["owner-shard"], issued_at=_t())
    assert placement.shard_id == "owner-shard"            # never a tenant-chosen value
