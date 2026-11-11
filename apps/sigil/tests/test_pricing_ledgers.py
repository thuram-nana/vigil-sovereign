"""S2 — the two inert owner-signed pricing ledgers: `governor.trial_claim` and `governor.report_unlock`.

Load-bearing invariants (each guard is a mutation target):
  * owner-signed only: an unsigned or forged record, or one signed by a rotated-out key at its seq, is inert;
  * trial claims: the FIRST verified claim of a (kind, digest) wins — of two orgs, the lower seq; a replay is a
    no-op; org A's claim never reads as org B's;
  * report unlocks: a billing record may only unlock and the first per org wins; owner records are latest-wins by
    issued_at; an owner relock beats an earlier billing unlock, a later billing unlock does not override an owner
    relock, an owner unlock after a relock unlocks again; org A's records never affect org B;
  * both cross a hard prune through the snapshot seed (schema v10), and `spine.prune` refuses a seed that drops
    one (the `stranded_*` tripwires);
  * an older snapshot loads with the new fields empty; the cached and full folds agree.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.report_unlock import REPORT_UNLOCK_SIGNAL, ReportUnlockRegistry
from sigil.governor.trial_claim import TRIAL_CLAIM_SIGNAL, TrialClaimRegistry, key_digest
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import _MAX_SNAPSHOT_SCHEMA, SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_iss = itertools.count(1)

DA = key_digest("email", "a@acme.io")
DB = key_digest("domain", "acme.io")


def _t() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _tc(s, **kw):
    return TrialClaimRegistry(s, owner_key=OWNER, trusted_pubkey=OP, **kw)


def _ru(s):
    return ReportUnlockRegistry(s, owner_key=OWNER, trusted_pubkey=OP)


def _raw(s, payload):
    return s.append(kind="event", source="governor", actor="WARDEN", payload=payload)


# ==================================================================================================
# trial claims
# ==================================================================================================

def test_digest_is_kind_separated_and_validated():
    assert key_digest("email", "x") != key_digest("domain", "x")
    assert len(DA) == 64
    with pytest.raises(ValueError):
        key_digest("phone", "x")
    with pytest.raises(ValueError):
        key_digest("email", "")
    with pytest.raises(ValueError):
        _tc(_store()).claim("email", "not-hex", "acme", issued_at=1.0)


def test_first_verified_claim_wins_and_replay_is_a_noop():
    s = _store()
    reg = _tc(s)
    seq = reg.claim("email", DA, "org_a", issued_at=_t())
    reg.claim("email", DA, "org_b", issued_at=_t())               # a second org: inert
    _raw(s, s.get(seq).payload)                                   # verbatim replay
    assert reg.claimant("email", DA) == "org_a"
    assert reg.claims_of("org_a") == [("email", DA)]
    assert reg.claims_of("org_b") == []
    assert reg.claimant("domain", DA) is None                     # the kind is part of the key


def test_lower_seq_wins_even_with_a_later_issued_at():
    s = _store()
    reg = _tc(s)
    reg.claim("domain", DB, "org_b", issued_at=900.0)             # lower seq
    reg.claim("domain", DB, "org_a", issued_at=1.0)               # higher seq, earlier time: still loses
    assert reg.claimant("domain", DB) == "org_b"


def test_unsigned_and_forged_claims_are_inert():
    s = _store()
    core = {"signal": TRIAL_CLAIM_SIGNAL, "key_kind": "email", "key_digest": DA, "org_id": "org_x",
            "issued_at": 1.0}
    _raw(s, dict(core))                                           # unsigned
    _raw(s, signed_payload(core, ATTACKER))                       # forged
    tampered = signed_payload(core, OWNER)
    tampered["org_id"] = "org_y"                                  # re-aimed after signing
    _raw(s, tampered)
    reg = _tc(s)
    assert reg.claimant("email", DA) is None
    reg.claim("email", DA, "org_a", issued_at=_t())               # the first VALID claim still wins
    assert reg.claimant("email", DA) == "org_a"


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Owner-key path state in a temp dir (mirrors test_fold_cache_customers.home), so rotation uses real disk."""
    from sigil.governor import identity
    from sigil.governor import key_history as kh
    from sigil.platform.vault import reset_owner_vault_for_test
    from sigil.spine import checkpoint as cp
    from sigil.spine import floor as fl
    keys = tmp_path / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    for mod, name, val in [
        (identity, "_PRIV", keys / "owner.priv"), (identity, "_PUB", keys / "owner.pub"),
        (identity, "_GENESIS_PUB", keys / "owner.genesis.pub"),
        (cp, "_PRIV", keys / "owner.priv"), (cp, "_PUB", keys / "owner.pub"),
        (cp, "KEYS_DIR", keys), (cp, "HEAD_PATH", tmp_path / "head.json"),
        (fl, "FLOOR_PATH", tmp_path / "floor.json"),
    ]:
        monkeypatch.setattr(mod, name, val)
    reset_owner_vault_for_test()
    kh.clear_resolver_cache()
    yield tmp_path
    kh.clear_resolver_cache()
    reset_owner_vault_for_test()


def test_a_record_signed_by_a_rotated_out_key_after_rotation_is_inert(home):
    """Each record verifies under the owner key valid AT ITS SEQ: records signed by the old key before the
    rotation stay valid; one signed by the old key after it is inert."""
    import time

    from sigil.governor import identity
    from sigil.governor import key_history as kh
    store = SpineStore(str(home / "spine.jsonl"))
    old = identity.ensure_owner_keypair()
    TrialClaimRegistry(store, owner_key=old).claim("email", DA, "org_a", issued_at=1.0)
    ReportUnlockRegistry(store, owner_key=old).unlock("org_a", "topup", source_ref="e1", issued_at=1.0)
    kh.rotate(store, issued_at=time.time())
    kh.clear_resolver_cache()
    TrialClaimRegistry(store, owner_key=old).claim("domain", DB, "org_b", issued_at=2.0)   # stale key
    ReportUnlockRegistry(store, owner_key=old).unlock("org_b", "topup", source_ref="e2", issued_at=2.0)
    tc, ru = TrialClaimRegistry(store), ReportUnlockRegistry(store)                       # the rotated-in key
    assert tc.claimant("email", DA) == "org_a" and ru.is_unlocked("org_a")
    assert tc.claimant("domain", DB) is None and not ru.is_unlocked("org_b")


def test_claim_requires_the_owner_key():
    reg = _tc(_store())
    reg.owner_key = None                                          # a keyless (read-only) registry
    with pytest.raises(ValueError):
        reg.claim("email", DA, "a", issued_at=1.0)


# ==================================================================================================
# report unlocks
# ==================================================================================================

def test_billing_unlock_first_wins_and_replay_is_inert():
    s = _store()
    reg = _ru(s)
    assert not reg.is_unlocked("org_a") and reg.unlock_of("org_a") is None
    seq = reg.unlock("org_a", "topup", source_ref="evt_1", issued_at=_t())
    reg.unlock("org_a", "subscription", source_ref="evt_2", issued_at=_t())
    assert reg.unlock_of("org_a").source_ref == "evt_1", "a later purchase does not replace the first unlock"
    _raw(s, s.get(seq).payload)
    u = reg.unlock_of("org_a")
    assert reg.is_unlocked("org_a") and (u.source_kind, u.source_ref) == ("topup", "evt_1")


def test_a_billing_relock_alone_unlocks_nothing_and_blocks_nothing():
    s = _store()
    core = {"signal": REPORT_UNLOCK_SIGNAL, "org_id": "org_a", "entry_id": "x", "action": "relock",
            "source_kind": "topup", "source_ref": "evt_0", "issued_at": 1.0}
    _raw(s, signed_payload(core, OWNER))
    reg = _ru(s)
    assert not reg.is_unlocked("org_a") and reg.unlock_of("org_a") is None
    reg.unlock("org_a", "topup", source_ref="evt_1", issued_at=2.0)
    assert reg.unlock_of("org_a").source_ref == "evt_1"


def test_forged_owner_records_are_inert():
    s = _store()
    reg = _ru(s)
    reg.unlock("org_a", "topup", source_ref="evt_1", issued_at=1.0)
    forged = {"signal": REPORT_UNLOCK_SIGNAL, "org_id": "org_a", "entry_id": "owner:x", "action": "relock",
              "source_kind": "owner", "source_ref": "x", "issued_at": 99.0}
    _raw(s, signed_payload(forged, ATTACKER))
    _raw(s, dict(forged))
    assert reg.is_unlocked("org_a"), "a forged or unsigned owner relock must not relock a paying org"
    _raw(s, signed_payload({**forged, "org_id": "org_b", "action": "unlock"}, ATTACKER))
    assert not reg.is_unlocked("org_b"), "a forged owner unlock must not unlock"


def test_billing_relock_is_inert():
    s = _store()
    reg = _ru(s)
    reg.unlock("org_a", "topup", source_ref="evt_1", issued_at=_t())
    core = {"signal": REPORT_UNLOCK_SIGNAL, "org_id": "org_a", "entry_id": "x", "action": "relock",
            "source_kind": "topup", "source_ref": "evt_9", "issued_at": _t()}
    _raw(s, signed_payload(core, OWNER))                          # owner-signed, but a BILLING relock
    assert reg.is_unlocked("org_a")
    with pytest.raises(ValueError):
        reg.unlock("org_a", "owner", source_ref="x", issued_at=_t())   # the billing API cannot claim owner


def test_owner_precedence():
    s = _store()
    reg = _ru(s)
    reg.unlock("org_a", "topup", source_ref="evt_1", issued_at=10.0)
    reg.owner_set("org_a", "relock", reason="chargeback", issued_at=20.0)
    assert not reg.is_unlocked("org_a"), "an owner relock beats an earlier billing unlock"
    reg.unlock("org_a", "topup", source_ref="evt_2", issued_at=30.0)
    assert not reg.is_unlocked("org_a"), "a later billing unlock does not override an owner relock"
    reg.owner_set("org_a", "unlock", reason="resolved", issued_at=40.0)
    assert reg.is_unlocked("org_a"), "an owner unlock after a relock unlocks again"
    u = reg.unlock_of("org_a")
    assert (u.source_kind, u.action, u.source_ref) == ("owner", "unlock", "resolved")


def test_owner_latest_wins_by_issued_at_and_replay_is_inert():
    s = _store()
    reg = _ru(s)
    reg.owner_set("org_a", "unlock", reason="goodwill", issued_at=50.0)
    reg.owner_set("org_a", "relock", reason="stale", issued_at=40.0)       # older: inert
    assert reg.is_unlocked("org_a")
    seq = reg.owner_set("org_a", "relock", reason="fraud", issued_at=60.0)
    reg.owner_set("org_a", "unlock", reason="same-time", issued_at=60.0)   # equal time: first wins
    assert not reg.is_unlocked("org_a")
    _raw(s, s.get(seq).payload)
    assert not reg.is_unlocked("org_a")


def test_owner_unlock_without_any_purchase():
    reg = _ru(_store())
    reg.owner_set("org_ent", "unlock", reason="enterprise", issued_at=1.0)
    assert reg.is_unlocked("org_ent")


def test_tenant_isolation():
    s = _store()
    reg = _ru(s)
    reg.unlock("org_a", "topup", source_ref="evt_1", issued_at=_t())
    reg.owner_set("org_b", "relock", reason="x", issued_at=_t())
    assert reg.is_unlocked("org_a") and not reg.is_unlocked("org_b")
    assert not reg.is_unlocked("org_c")
    tc = _tc(s)
    tc.claim("email", DA, "org_a", issued_at=_t())
    assert tc.claims_of("org_b") == []


def test_unsigned_forged_and_reaimed_unlocks_are_inert():
    s = _store()
    core = {"signal": REPORT_UNLOCK_SIGNAL, "org_id": "org_a", "entry_id": "unlock:topup:e", "action": "unlock",
            "source_kind": "topup", "source_ref": "e", "issued_at": 1.0}
    _raw(s, dict(core))
    _raw(s, signed_payload(core, ATTACKER))
    good = signed_payload({**core, "org_id": "org_b"}, OWNER)
    good["org_id"] = "org_a"                                      # re-aimed at another tenant
    _raw(s, good)
    assert not _ru(s).is_unlocked("org_a")
    assert not _ru(s).is_unlocked("org_b")


def test_unlock_input_validation():
    reg = _ru(_store())
    with pytest.raises(ValueError):
        reg.unlock("org_a", "topup", source_ref="", issued_at=1.0)
    with pytest.raises(ValueError):
        reg.owner_set("org_a", "delete", reason="x", issued_at=1.0)
    with pytest.raises(ValueError):
        reg.owner_set("org_a", "unlock", reason="", issued_at=1.0)
    keyless = _ru(_store())
    keyless.owner_key = None
    with pytest.raises(ValueError):
        keyless.unlock("org_a", "topup", source_ref="e", issued_at=1.0)


def test_cached_and_full_fold_agree(monkeypatch):
    s = _store()
    tc, ru = _tc(s), _ru(s)
    tc.claim("email", DA, "org_a", issued_at=_t())
    ru.unlock("org_a", "topup", source_ref="e1", issued_at=10.0)
    ru.owner_set("org_b", "relock", reason="x", issued_at=11.0)
    for flag in ("1", ""):
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
        assert tc.claimant("email", DA) == "org_a" and tc.claims_of("org_a") == [("email", DA)]
        assert ru.is_unlocked("org_a") and not ru.is_unlocked("org_b")


# ==================================================================================================
# snapshot (schema v10) and prune
# ==================================================================================================

class PrunedView:
    def __init__(self, inner, K):
        self._inner, self._K = inner, K

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self._K:
                yield r

    def get(self, seq):
        return self._inner.get(seq)

    def append(self, **kw):
        return self._inner.append(**kw)


def _marker(s):
    return s.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})


def test_schema_is_v10_and_an_older_snapshot_loads_with_empty_fields():
    assert _MAX_SNAPSHOT_SCHEMA == 10 and SnapshotState().schema_version == 10
    old = SnapshotState.from_folded({"schema_version": 9})
    assert old.trial_claim_row == [] and old.report_unlock_billing == [] and old.report_unlock_owner == []


def test_claims_and_unlocks_survive_a_hard_prune(monkeypatch):
    s = _store()
    tc, ru = _tc(s), _ru(s)
    c_seq = tc.claim("email", DA, "org_a", issued_at=1.0)          # seq 0
    u_seq = ru.unlock("org_a", "topup", source_ref="e1", issued_at=2.0)
    ru.owner_set("org_b", "relock", reason="fraud", issued_at=3.0)
    captured_unlock = s.get(u_seq).payload
    assert c_seq == 0
    k = _marker(s)
    snap = build([r for r in s.iter_records() if r.seq < k], trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    snap = SnapshotState.model_validate(snap.model_dump())          # the persisted round trip
    _raw(s, captured_unlock)                                        # a replay above the boundary
    tc.claim("email", DA, "org_c", issued_at=4.0)                   # a later claim by another org
    pruned = PrunedView(s, k)
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, st: snap))
    assert TrialClaimRegistry(pruned, owner_key=OWNER, trusted_pubkey=OP).claimant("email", DA) == "org_a"
    r2 = ReportUnlockRegistry(pruned, owner_key=OWNER, trusted_pubkey=OP)
    assert r2.is_unlocked("org_a") and r2.unlock_of("org_a").source_ref == "e1"
    assert not r2.is_unlocked("org_b")

    empty = snap.model_copy(update={"trial_claim_row": [], "report_unlock_billing": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, st: empty))
    assert TrialClaimRegistry(pruned, owner_key=OWNER, trusted_pubkey=OP).claimant("email", DA) == "org_c", \
        "isolates the claim carry: without the seed the pruned first claim is lost and a second org takes it"


def test_build_equals_scan_and_build_rejects_forged_records():
    s = _store()
    tc, ru = _tc(s), _ru(s)
    tc.claim("email", DA, "org_a", issued_at=1.0)
    tc.claim("domain", DB, "org_b", issued_at=2.0)
    ru.unlock("org_a", "subscription", source_ref="e1", issued_at=3.0)
    ru.owner_set("org_a", "relock", reason="x", issued_at=4.0)
    _raw(s, signed_payload({"signal": TRIAL_CLAIM_SIGNAL, "key_kind": "email",
                            "key_digest": key_digest("email", "z@z.io"), "org_id": "org_z", "issued_at": 5.0},
                           ATTACKER))
    _raw(s, signed_payload({"signal": REPORT_UNLOCK_SIGNAL, "org_id": "org_z", "entry_id": "x", "action": "unlock",
                            "source_kind": "topup", "source_ref": "f", "issued_at": 6.0}, ATTACKER))
    b = build(list(s.iter_records()), trusted_pubkey=OP, base_seq=0, snapshot_seq=-1)
    from sigil.governor.report_unlock import seed_state
    from sigil.governor.trial_claim import seed_rows
    assert seed_rows(b) == tc._fold()
    assert seed_state(b) == ru._fold()
    assert all(row[2] != "org_z" for row in b.trial_claim_row)
    assert all(row[0] != "org_z" for row in b.report_unlock_billing)


def _segmented(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _tc(s).claim("email", DA, "org_a", issued_at=1.0)                # seq 0
    _ru(s).unlock("org_a", "topup", source_ref="e1", issued_at=2.0)   # seq 1
    _ru(s).owner_set("org_b", "relock", reason="x", issued_at=3.0)    # seq 2
    for _ in range(2):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})
    s.rotate()                                                       # seal [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})
    s.rotate()
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_prune_allows_a_carried_seed(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    archived = prune.check_prune_safe(s, 5)
    assert prune.stranded_trial_claims(s, archived, 5) == []
    assert prune.stranded_report_unlocks(s, archived, 5) == []


@pytest.mark.parametrize("field, fn, tenant, word", [
    ("trial_claim_row", "stranded_trial_claims", "org_a", "trial claim"),
    ("report_unlock_billing", "stranded_report_unlocks", "org_a", "report unlock"),
    ("report_unlock_owner", "stranded_report_unlocks", "org_b", "report unlock"),
])
def test_prune_refuses_a_seed_that_omits_a_ledger(tmp_path, monkeypatch, field, fn, tenant, word):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    real_build = prune.build

    def incomplete(records, **kw):
        return real_build(records, **kw).model_copy(update={field: []})

    monkeypatch.setattr(prune, "build", incomplete)
    assert getattr(prune, fn)(s, _archived_below(s, 5), 5) == [tenant]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert word in str(e.value) and tenant in str(e.value)


def test_prune_refuses_a_seed_that_corrupts_a_value(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    real_build = prune.build

    def corrupt(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={"trial_claim_row": [[r[0], r[1], "org_evil", r[3]]
                                                           for r in seed.trial_claim_row]})

    monkeypatch.setattr(prune, "build", corrupt)
    assert prune.stranded_trial_claims(s, _archived_below(s, 5), 5) == ["org_a", "org_evil"]


@pytest.mark.parametrize("bad", [
    {"action": [], "source_kind": "owner"},
    {"action": "unlock", "source_kind": {}},
    {"action": {"a": 1}, "source_kind": ["topup"]},
])
def test_a_malformed_unsigned_unlock_never_raises_out_of_a_fold(bad):
    """A hostile append must stay inert: unhashable field values never reach a set-membership test."""
    s = _store()
    reg = _ru(s)
    reg.unlock("paying", "topup", source_ref="e1", issued_at=1.0)
    _raw(s, {"signal": REPORT_UNLOCK_SIGNAL, "org_id": "victim", "entry_id": "x", **bad})
    _raw(s, {"signal": TRIAL_CLAIM_SIGNAL, "key_kind": [], "key_digest": {}, "org_id": "victim"})
    assert reg.is_unlocked("paying") and not reg.is_unlocked("victim")
    assert _tc(s).claimant("email", DA) is None
    b = build(list(s.iter_records()), trusted_pubkey=OP, base_seq=0, snapshot_seq=-1)
    assert [r[0] for r in b.report_unlock_billing] == ["paying"]


def test_malformed_seed_rows_are_skipped():
    from sigil.governor.report_unlock import seed_state
    from sigil.governor.trial_claim import seed_rows
    snap = SnapshotState.from_folded({"trial_claim_row": [[[], DA, "o", 1.0]],
                                      "report_unlock_billing": [["o", "e", {}, "r", 1.0]],
                                      "report_unlock_owner": [["o", "e", [], "r", 1.0]]})
    assert seed_rows(snap) == {} and seed_state(snap) == ({}, {})


def test_prune_refuses_a_seed_that_invents_a_row(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    real_build = prune.build

    def phantom(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "report_unlock_owner": [*seed.report_unlock_owner, ["org_a", "owner:x", "relock", "p", 99.0]],
            "trial_claim_row": [*seed.trial_claim_row, ["domain", key_digest("domain", "x.io"), "org_a", 1.0]]})

    monkeypatch.setattr(prune, "build", phantom)
    archived = _archived_below(s, 5)
    assert prune.stranded_report_unlocks(s, archived, 5) == ["org_a"]
    assert prune.stranded_trial_claims(s, archived, 5) == ["org_a"]


def test_prune_refuses_a_seed_that_invents_a_billing_unlock(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    real_build = prune.build

    def phantom(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "report_unlock_billing": [*seed.report_unlock_billing, ["org_free", "unlock:topup:x", "topup", "x", 1.0]]})

    monkeypatch.setattr(prune, "build", phantom)
    assert prune.stranded_report_unlocks(s, _archived_below(s, 5), 5) == ["org_free"]
