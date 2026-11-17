"""W5 — the reversal ledger survives a hard prune, and its tripwire refuses a seed that would drop it.

The ledger is lifetime state: a prune that dropped an org's owed total would lift a billing hold with no repayment,
and a dropped step key would re-open replay. ``SnapshotState.build`` carries ``billing_reversal_owed`` / ``_ref`` /
``_seen`` across the boundary (``seed_fold``), and ``prune.stranded_billing_reversals`` is the fail-closed tripwire
(it shares build()'s own fold step, so a seed that drops the state is caught).

Mutation-verify target:
  * the prune tripwire ignores the reversal state -> test_the_prune_tripwire_refuses_a_seed_that_drops_the_owed_total
"""
from __future__ import annotations

import pytest

import sigil.config as cfg
import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
import sigil.spine.tail as _tail
from sigil.governor import identity
from sigil.governor.billing_reversal import BillingReversalLedger, REASON_DISPUTE, seed_fold
from sigil.governor.wallet import WalletRegistry
from sigil.spine import prune
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A spine with its own owner key, signed head, floor and prune archive (a real prune needs all of them)."""
    keys = tmp_path / "keys"
    monkeypatch.setattr(cfg, "KEYS_DIR", keys, raising=False)
    monkeypatch.setattr(_cp, "KEYS_DIR", keys)
    for mod in (_cp, identity):
        monkeypatch.setattr(mod, "_PRIV", keys / "owner.priv")
        monkeypatch.setattr(mod, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(identity, "_GENESIS_PUB", keys / "owner.genesis.pub")
    head = tmp_path / "head.json"
    for mod in (cfg, _cp, _snap, _tail):
        monkeypatch.setattr(mod, "HEAD_PATH", head, raising=False)
    monkeypatch.setattr(_fl, "FLOOR_PATH", tmp_path / "floor.json")
    monkeypatch.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(tmp_path / "archive"))
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("VIGIL_FOLD_CACHE_ENABLED", raising=False)
    identity.ensure_owner_keypair()
    return str(tmp_path / "spine.jsonl")


def _seed(world):
    owner = identity.owner_keypair()
    pub = owner.public_key_b64
    s = SpineStore(world)
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    w = WalletRegistry(s, owner_key=owner, trusted_pubkey=pub)
    L = BillingReversalLedger(s, wallet=w, owner_key=owner, trusted_pubkey=pub)
    w.grant("acme", 1000, "topup", entry_id="cs_1", issued_at=1.0)
    w.debit("acme", 300, entry_id="spend1", issued_at=2.0)
    L.reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE, now=3.0, disputed=1000)   # owes 300
    return s, owner, pub


def test_the_snapshot_carries_the_owed_total_and_the_consumed_steps(world):
    s, owner, pub = _seed(world)
    k = max(r.seq for r in s.iter_records(since_seq=-1)) + 1       # every record is below the live window
    snap = build(list(s.iter_records()), trusted_pubkey=pub, base_seq=k, snapshot_seq=-1)
    carried = seed_fold(snap)
    assert carried.owed("acme") == 300
    assert carried.refs[("acme", "cs_1")][2] == 1000              # removed is carried
    assert carried.seen and ("acme", "rev:cs_1:1") in carried.seen


def test_an_older_snapshot_loads_with_empty_reversal_fields():
    v11 = SnapshotState.from_folded({"schema_version": 11})
    assert v11.billing_reversal_owed == [] and seed_fold(v11).owed("acme") == 0


def test_the_prune_tripwire_refuses_a_seed_that_drops_the_owed_total(world, monkeypatch):
    s, owner, pub = _seed(world)
    below = list(s.iter_records(since_seq=-1))
    from sigil.governor import key_history as _kh
    resolver = _kh.key_resolver(s, current=pub)

    def below_seed_with(seed):
        return lambda store, archived, K: (below, seed, resolver)

    # the real seed build() emits for the below-K records carries the reversal state -> the tripwire is clear
    real_seed = build(below, trusted_pubkey=pub, base_seq=99, snapshot_seq=-1)
    monkeypatch.setattr(prune, "_below_seed", below_seed_with(real_seed))
    assert prune.stranded_billing_reversals(s, [], 99) == []

    # a seed that drops ONLY the owed total (ref + seen intact) -> the owed comparison alone must catch it
    owed_dropped = real_seed.model_copy(update={"billing_reversal_owed": []})
    monkeypatch.setattr(prune, "_below_seed", below_seed_with(owed_dropped))
    assert prune.stranded_billing_reversals(s, [], 99) == ["acme"]

    # a seed that drops ONLY the consumed steps (owed + ref intact) -> the seen comparison catches it
    seen_dropped = real_seed.model_copy(update={"billing_reversal_seen": []})
    monkeypatch.setattr(prune, "_below_seed", below_seed_with(seen_dropped))
    assert prune.stranded_billing_reversals(s, [], 99) == ["acme"]
