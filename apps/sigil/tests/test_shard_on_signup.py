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
from sigil.governor.shard_on_signup import (
    assign_on_signup, backfill_placements, choose_shard, current_loads, loads_of,
)
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


# -- cost: the sign-up lock is held for at most two signature-verifying folds per placement ---------------------

def _count_folds(monkeypatch):
    calls = {"n": 0}
    real = ShardAssignmentRegistry._fold

    def counted(self):
        calls["n"] += 1
        return real(self)

    monkeypatch.setattr(ShardAssignmentRegistry, "_fold", counted)
    return calls


def test_a_placement_costs_two_folds_and_an_existing_one_costs_one(monkeypatch):
    s = _store()
    reg = _reg(s)
    reg.assign("existing", "s1", issued_at=_t())
    calls = _count_folds(monkeypatch)
    p = assign_on_signup(reg, "newco", shard_ids=["s1", "s2"], issued_at=_t())
    assert calls["n"] == 2, f"{calls['n']} genesis folds for one placement (was 4)"
    assert (p.tenant_id, p.shard_id, p.epoch) == ("newco", "s2", 1)
    calls["n"] = 0
    assert assign_on_signup(reg, "newco", shard_ids=["s1", "s2"], issued_at=_t()) == reg.placement("newco")
    assert calls["n"] == 2                                # the re-drive fold + the comparison read above


def test_the_returned_placement_is_the_one_the_fold_honours():
    s = _store()
    reg = _reg(s)
    got = assign_on_signup(reg, "newco", shard_ids=["s1"], issued_at=_t())
    assert got == reg.placement("newco")


def test_loads_of_counts_per_shard():
    s = _store()
    reg = _reg(s)
    reg.assign("a", "s1", issued_at=_t())
    reg.assign("b", "s1", issued_at=_t())
    assert loads_of(reg.placements()) == {"s1": 2} == current_loads(reg)


# -- the owner backfill -------------------------------------------------------------------------------------------

class _CountingLock:
    def __init__(self):
        self.entered = 0

    def __call__(self):
        import contextlib
        outer = self

        @contextlib.contextmanager
        def held():
            outer.entered += 1
            yield
        return held()


def test_backfill_places_every_unplaced_org_once_and_is_idempotent():
    s = _store()
    reg = _reg(s)
    reg.assign("org_old", "s1", issued_at=_t())
    lock = _CountingLock()
    r = backfill_placements(reg, ["org_old", "org_a", "org_b", "org_a"], shard_ids=["s1", "s2"], issued_at=_t(),
                            lock=lock)
    assert r == {"placed": 2, "already": 1, "failed": 0}
    assert lock.entered == 2                              # one lock per tenant it placed; none for the placed one
    assert {p.tenant_id: p.shard_id for p in reg.placements()} == {"org_old": "s1", "org_a": "s2", "org_b": "s1"}
    again = backfill_placements(reg, ["org_old", "org_a", "org_b"], shard_ids=["s1", "s2"], issued_at=_t(),
                                lock=lock)
    assert again == {"placed": 0, "already": 3, "failed": 0}
    assert len([p for p in reg.placements()]) == 3


def test_backfill_rechecks_under_the_lock_so_a_concurrent_signup_is_never_placed_twice():
    import contextlib
    s = _store()
    reg = _reg(s)

    @contextlib.contextmanager
    def lock_that_loses_a_race():
        # between the sweep's first read and its lock, a sign-up in another process placed org_a
        if reg.placement("org_a") is None:
            reg.assign("org_a", "s2", issued_at=_t())
        yield

    r = backfill_placements(reg, ["org_a"], shard_ids=["s1", "s2"], issued_at=_t(), lock=lock_that_loses_a_race)
    assert r == {"placed": 0, "already": 1, "failed": 0}
    assert [(p.tenant_id, p.shard_id, p.epoch) for p in reg.placements()] == [("org_a", "s2", 1)]


def test_backfill_counts_an_unplaceable_org_and_goes_on():
    s = _store()
    reg = _reg(s)
    r = backfill_placements(reg, ["../evil", "org_ok"], shard_ids=["s1"], issued_at=_t(), lock=_CountingLock())
    assert r == {"placed": 1, "already": 0, "failed": 1}
    assert [p.tenant_id for p in reg.placements()] == ["org_ok"]


def test_backfill_with_no_topology_places_nothing():
    s = _store()
    reg = _reg(s)
    assert backfill_placements(reg, ["org_a"], shard_ids=[], issued_at=_t(), lock=_CountingLock()) == \
        {"placed": 0, "already": 0, "failed": 0}
    assert reg.placements() == []


def test_backfill_without_the_owner_key_places_nothing():
    s = _store()
    keyless = ShardAssignmentRegistry(s, owner_key=None, trusted_pubkey=OP)
    r = backfill_placements(keyless, ["org_a"], shard_ids=["s1"], issued_at=_t(), lock=_CountingLock())
    assert r == {"placed": 0, "already": 0, "failed": 1}
    assert _reg(s).placements() == []


# -- `sigil shard backfill` ---------------------------------------------------------------------------------------

def _cli(monkeypatch, tmp_path, *, fair, multi, ids, migrated=True):
    """The spine the `sigil` CLI opens — ONE store, shared by the verb and its startup gate. `cli.main()` runs its
    fail-closed startup gates BEFORE the verb, among them the store-operability (migration) gate, which opens
    ``config.SPINE_PATH`` (bound at import and shared by the whole test process). Retarget it to the very spine the
    verb writes, so the gate judges THIS store and never a legacy single-file spine another test in a full run left
    at the shared default (that refuses the verb with exit 3 before its own gates, exit 2, are reached — the CI
    failure). ``migrated``: the segment layout a provisioned home is in (the install flow migrates a fresh home
    once), as in test_founder_role's `_cli_store`; False leaves an UN-migrated legacy spine holding the orgs."""
    from sigil import cli, config
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    path = tmp_path / "spine" / "spine.jsonl"
    monkeypatch.setattr(config, "SPINE_PATH", path)                   # the startup gate's store → this test's
    store = SpineStore(path)
    if migrated:
        store.migrate()
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)     # the verb's default store → this test's
    for name, on in (("VIGIL_CUSTOMER_FAIR_QUEUE", fair), ("VIGIL_MULTI_SHARD", multi)):
        if on:
            monkeypatch.setenv(name, "1")
        else:
            monkeypatch.delenv(name, raising=False)
    if ids:
        monkeypatch.setenv("VIGIL_SHARD_IDS", ids)
    else:
        monkeypatch.delenv("VIGIL_SHARD_IDS", raising=False)
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    for o in ("org_one", "org_two"):
        orgs.create_org(o, o, owner="u", issued_at=_t())
    return cli, store


@pytest.mark.parametrize("fair, multi, ids", [(False, True, "s1"), (True, False, "s1"), (True, True, "")])
def test_the_backfill_verb_refuses_unless_every_gate_is_on(monkeypatch, tmp_path, capsys, fair, multi, ids):
    cli, store = _cli(monkeypatch, tmp_path, fair=fair, multi=multi, ids=ids)
    with pytest.raises(SystemExit) as ex:
        cli.main(["shard", "backfill"])
    err = capsys.readouterr().err
    gate = "shard placement is off" if not (fair and multi) else "no owner shard topology (VIGIL_SHARD_IDS)"
    assert ex.value.code == 2 and "refusing" in err and gate in err, err   # the VERB's own gate refused, by name
    assert ShardAssignmentRegistry(store, owner_key=None).placements() == []


def test_the_backfill_verb_never_writes_an_unmigrated_spine(monkeypatch, tmp_path, capsys):
    # `shard` is a spine WRITER, so it is NOT exempt from the CLI's migration gate: with every placement gate ON, an
    # un-migrated legacy spine that holds data is refused at startup (exit 3, naming the fix) and nothing is placed.
    cli, store = _cli(monkeypatch, tmp_path, fair=True, multi=True, ids="s1,s2", migrated=False)
    with pytest.raises(SystemExit) as ex:
        cli.main(["shard", "backfill"])
    err = capsys.readouterr().err
    assert ex.value.code == 3 and "refusing to run `shard`" in err and "sigil upgrade" in err, err
    assert ShardAssignmentRegistry(store, owner_key=None).placements() == []


def test_the_backfill_verb_places_every_org(monkeypatch, tmp_path, capsys):
    cli, store = _cli(monkeypatch, tmp_path, fair=True, multi=True, ids="s1,s2")
    cli.main(["shard", "backfill"])
    assert "2 placed, 0 already placed, 0 could not be placed" in capsys.readouterr().out
    reg = ShardAssignmentRegistry(store, owner_key=None)
    assert sorted((p.tenant_id, p.shard_id) for p in reg.placements()) == [("org_one", "s1"), ("org_two", "s2")]
    cli.main(["shard", "backfill"])
    assert "0 placed, 2 already placed" in capsys.readouterr().out
