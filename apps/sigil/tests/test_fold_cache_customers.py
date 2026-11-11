"""Front C S0a — the verified incremental FOLD CACHE (`spine/fold_cache.py`) on `CustomerRegistry`.

The cache may change only HOW the customer fold is read, never WHAT it says. Every test here compares the
cached answers (`customer` / `by_email` / `customers`) against the registry's own FULL fold (`_fold`, the
unchanged signature-verifying scan) over the same spine, and checks the cache was actually used:

  * seeded randomized equivalence over every fold-relevant op (create, re-grant / email move, set_password,
    revoke, owner-signed replay, forged and unsigned grants, noise, a second store instance appending);
  * O(new records): a warm read verifies ZERO signatures, and k appends cost exactly k verifications;
  * chain anchor: rollback-then-regrow, a different spine at the same path, and truncation all rebuild;
  * key state: a rotation appended by another process, a genesis repin, and the build-race horizon;
  * the snapshot boundary is part of the key (a prune with the pubkey-dependent bypass);
  * a fault while extending discards and rebuilds; a fault in the rebuild raises as the full fold does;
  * concurrent writers (separate store instances) and readers;
  * flag OFF: the cache is never consulted.
"""
from __future__ import annotations

import itertools
import random
import shutil
import threading
import time

import pytest

from sigil.governor import customers as cust
from sigil.governor import identity
from sigil.governor import key_history as kh
from sigil.governor.authn import signed_payload
from sigil.governor.customers import CustomerRegistry
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()
_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


@pytest.fixture(autouse=True)
def _cache_on(monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    fold_cache.clear_all()
    yield
    fold_cache.clear_all()


def _reg(store, **kw):
    kw.setdefault("owner_key", OWNER)
    kw.setdefault("trusted_pubkey", OWNER_PUB)
    return CustomerRegistry(store, **kw)


def _full_answers(reg, usernames, emails):
    fold = reg._fold()                                             # the unchanged full fold
    by_email = {}
    for e in emails:
        by_email[e] = next((fold[u] for u in sorted(fold) if fold[u].email == e), None)
    return ([fold[u] for u in sorted(fold)], {u: fold.get(u) for u in usernames}, by_email)


def _cached_answers(reg, usernames, emails):
    return (reg.customers(), {u: reg.customer(u) for u in usernames}, {e: reg.by_email(e) for e in emails})


@pytest.fixture
def no_full_fold(monkeypatch):
    """Fail the test if a cached read falls back to the full fold (the cache must actually serve it)."""
    calls = {"n": 0}
    real = CustomerRegistry._fold

    def spy(self):
        calls["n"] += 1
        return real(self)

    monkeypatch.setattr(CustomerRegistry, "_fold", spy)
    return calls


def _assert_equivalent(reg, usernames, emails, no_full_fold=None):
    before = no_full_fold["n"] if no_full_fold is not None else 0
    got = _cached_answers(reg, usernames, emails)
    if no_full_fold is not None:
        assert no_full_fold["n"] == before, "a cached read fell back to the full fold"
    assert got == _full_answers(reg, usernames, emails)


# ---- randomized equivalence ------------------------------------------------------------------------------
@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_randomized_equivalence_with_the_full_fold(tmp_path, seed, no_full_fold):
    rng = random.Random(seed)
    path = str(tmp_path / "spine.jsonl")
    store = SpineStore(path)
    other = SpineStore(path)                      # a second instance on the same file (another process)
    reg = _reg(store)
    reg_other = _reg(other)
    usernames: list[str] = []
    emails = [f"u{i}@acme.com" for i in range(6)]  # few emails, so several usernames share one
    captured: list[dict] = []
    for _step in range(120):
        op = rng.choice(["create", "create", "regrant", "setpw", "revoke", "replay", "forged", "unsigned",
                         "noise", "other_create", "other_revoke"])
        if op in ("create", "other_create"):
            r = reg if op == "create" else reg_other
            u, seq = r.create(rng.choice(emails), issued_at=_iss(),
                              password=rng.choice([None, "customer-pw-1"]))
            usernames.append(u)
            captured.append((other if op == "other_create" else store).get(seq).payload)
        elif op == "regrant" and usernames:       # same username, possibly a different email
            reg.create(rng.choice(emails), issued_at=_iss(), username=rng.choice(usernames))
        elif op == "setpw" and usernames:
            u = rng.choice(usernames)
            if reg._fold().get(u) is not None:
                reg.set_password(u, "customer-pw-2", issued_at=_iss())
        elif op in ("revoke", "other_revoke") and usernames:
            (reg if op == "revoke" else reg_other).revoke(rng.choice(usernames + ["cust_unknown"]))
        elif op == "replay" and captured:
            store.append(kind="event", source="governor", actor="WARDEN", payload=rng.choice(captured))
        elif op == "forged":
            core = {"signal": cust.SIGNAL, "username": rng.choice(usernames or ["cust_x"]),
                    "email": rng.choice(emails), "state": "active", "issued_at": _iss() + 1e6}
            store.append(kind="event", source="governor", actor="WARDEN", payload=signed_payload(core, ATTACKER))
        elif op == "unsigned":
            store.append(kind="event", source="governor", actor="WARDEN",
                         payload={"signal": cust.SIGNAL, "username": rng.choice(usernames or ["cust_y"]),
                                  "email": rng.choice(emails), "state": "active", "issued_at": _iss() + 1e6})
        else:
            store.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": _step})
        _assert_equivalent(reg, usernames + ["cust_unknown"], emails + ["nobody@acme.com"], no_full_fold)
    assert cust._CUSTOMER_FOLD._entries, "the cache must hold the fold after the run"


# ---- the point: O(new records) ---------------------------------------------------------------------------
def test_a_warm_read_verifies_no_signature_and_appends_cost_one_each(tmp_path, monkeypatch):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    reg = _reg(store)
    for i in range(30):
        reg.create(f"c{i}@acme.com", issued_at=_iss())
    count = {"n": 0}
    real = cust.verify_signed

    def counting(*a, **kw):
        count["n"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(cust, "verify_signed", counting)
    assert reg.by_email("c29@acme.com") is not None             # cold: folds (verifies) all 30
    assert count["n"] == 30
    count["n"] = 0
    for _ in range(5):
        assert reg.by_email("c0@acme.com") is not None
        assert reg.customer(reg.by_email("c1@acme.com").username) is not None
    assert count["n"] == 0, "a warm read must not re-verify any signature"
    for i in range(3):
        reg.create(f"n{i}@acme.com", issued_at=_iss())
    assert reg.by_email("n2@acme.com") is not None
    assert count["n"] == 3, "k appends must cost exactly k verifications"
    # control: with the flag OFF every read re-verifies the whole spine
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    count["n"] = 0
    assert reg.by_email("n2@acme.com") is not None
    assert count["n"] == 33


# ---- chain anchor ----------------------------------------------------------------------------------------
def test_rollback_then_regrow_rebuilds(tmp_path, no_full_fold):
    path = tmp_path / "spine.jsonl"
    store = SpineStore(str(path))
    reg = _reg(store)
    a, _ = reg.create("a@acme.com", issued_at=_iss())
    shutil.copy(path, tmp_path / "backup.jsonl")                 # restore point: only `a`
    b, _ = reg.create("b@acme.com", issued_at=_iss())
    c, _ = reg.create("c@acme.com", issued_at=_iss())
    assert reg.by_email("c@acme.com") is not None                 # warm: anchored at c's grant
    shutil.copy(tmp_path / "backup.jsonl", path)                  # ROLLBACK under the live process
    store2 = SpineStore(str(path))
    reg2 = _reg(store2)
    d, _ = reg2.create("d@acme.com", issued_at=_iss())            # regrow past the old anchor seq
    e, _ = reg2.create("e@acme.com", issued_at=_iss())
    names, mails = [a, b, c, d, e], ["a@acme.com", "b@acme.com", "c@acme.com", "d@acme.com", "e@acme.com"]
    _assert_equivalent(reg2, names, mails, no_full_fold)
    assert reg2.by_email("b@acme.com") is None and reg2.by_email("c@acme.com") is None, "rolled-back grants"
    assert reg2.by_email("e@acme.com") is not None


def test_a_different_spine_at_the_same_path_rebuilds(tmp_path, no_full_fold):
    path = tmp_path / "spine.jsonl"
    reg = _reg(SpineStore(str(path)))
    for i in range(4):
        reg.create(f"old{i}@acme.com", issued_at=_iss())
    assert reg.by_email("old3@acme.com") is not None              # warm
    other = tmp_path / "other.jsonl"
    oreg = _reg(SpineStore(str(other)))
    for i in range(6):
        oreg.create(f"new{i}@acme.com", issued_at=_iss())
    shutil.copy(other, path)                                      # same path, same-or-greater length, new chain
    reg2 = _reg(SpineStore(str(path)))
    mails = [f"old{i}@acme.com" for i in range(4)] + [f"new{i}@acme.com" for i in range(6)]
    _assert_equivalent(reg2, [], mails, no_full_fold)
    assert reg2.by_email("old0@acme.com") is None and reg2.by_email("new5@acme.com") is not None


def test_truncation_under_the_same_store_object_rebuilds(tmp_path):
    path = tmp_path / "spine.jsonl"
    store = SpineStore(str(path))
    reg = _reg(store)
    reg.create("a@acme.com", issued_at=_iss())
    shutil.copy(path, tmp_path / "backup.jsonl")
    reg.create("b@acme.com", issued_at=_iss())
    assert reg.by_email("b@acme.com") is not None
    shutil.copy(tmp_path / "backup.jsonl", path)                  # the anchor seq no longer exists
    assert _cached_answers(reg, [], ["a@acme.com", "b@acme.com"]) == _full_answers(reg, [], ["a@acme.com",
                                                                                         "b@acme.com"])
    assert reg.by_email("b@acme.com") is None


# ---- key state ------------------------------------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    """Owner-key path state in a temp dir (mirrors test_key_rotation.home), so rotation uses the real disk."""
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


def _count_builds(monkeypatch):
    n = {"builds": 0}
    real = kh.key_resolver_with_horizon

    def spy(store, *, current):
        n["builds"] += 1
        return real(store, current=current)

    monkeypatch.setattr(kh, "key_resolver_with_horizon", spy)
    return n


def test_a_rotation_appended_by_another_process_rebuilds(home, monkeypatch):
    store = SpineStore(str(home / "spine.jsonl"))
    identity.ensure_owner_keypair()
    reg_old = CustomerRegistry(store)                             # trusted = the genesis key
    pre = [reg_old.create(f"pre{i}@acme.com", issued_at=_iss())[0] for i in range(3)]
    builds = _count_builds(monkeypatch)
    assert reg_old.by_email("pre2@acme.com") is not None and builds["builds"] == 1
    # ANOTHER process rotates: its clear_resolver_cache() cannot reach this process's caches
    monkeypatch.setattr(kh, "clear_resolver_cache", lambda: kh._RESOLVER_CACHE.clear())
    kh.rotate(store, issued_at=time.time())
    kh._RESOLVER_CACHE.clear()
    mails = [f"pre{i}@acme.com" for i in range(3)]
    # the OLD registry (old trusted key): the history record forces a rebuild; answers equal the full fold
    assert _cached_answers(reg_old, pre, mails) == _full_answers(reg_old, pre, mails)
    assert builds["builds"] == 2, "an owner-key-history record must force a rebuild, never an extension"
    # a NEW registry (rotated-in key) keeps every pre-rotation customer and folds new ones
    reg_new = CustomerRegistry(store)
    post, _ = reg_new.create("post@acme.com", issued_at=_iss())
    mails.append("post@acme.com")
    assert _cached_answers(reg_new, pre + [post], mails) == _full_answers(reg_new, pre + [post], mails)
    assert all(reg_new.customer(u) is not None for u in pre + [post])


def test_genesis_repin_is_part_of_the_key(home, monkeypatch):
    store = SpineStore(str(home / "spine.jsonl"))
    identity.ensure_owner_keypair()
    kh.rotate(store, issued_at=time.time())                       # history now exists: genesis pin matters
    reg = CustomerRegistry(store)
    u, _ = reg.create("g@acme.com", issued_at=_iss())
    assert reg.customer(u) is not None                            # warm, under the true genesis
    from sigil.governor import capability as capm
    from sigil.governor import killswitch as ks
    gate, caps = ks.KillSwitch(store), capm.CapabilityGate(store)
    gate.engage(by="owner", reason="t")
    gate.release(issued_at=time.time())
    caps.disable("voice")
    caps.enable("voice", issued_at=time.time())
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    assert gate.is_engaged() is False and caps.is_enabled("voice") is True   # warm the flag-OFF memo caches too
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    assert gate.is_engaged() is False and caps.is_enabled("voice") is True
    identity.pin_genesis(generate_keypair().public_key_b64, force=True)   # repin (no resolver clear), NO append
    assert _cached_answers(reg, [u], ["g@acme.com"]) == _full_answers(reg, [u], ["g@acme.com"])
    assert reg.customer(u) is None, "a genesis that does not chain to the current key denies all"
    cached, cached_cap = gate.is_engaged(), caps.is_enabled("voice")
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    assert gate.is_engaged() is cached is True, "the release no longer verifies: both paths are halted"
    assert caps.is_enabled("voice") is cached_cap is False, "the enable no longer verifies: both paths deny"


def test_a_rotation_the_build_did_not_see_is_answered_but_not_cached(home, monkeypatch):
    """The build race, through the REAL horizon: a rotation lands after the resolver's history scan but before
    the fold pass. The build must answer (as racily as the full fold would) but must NOT be cached."""
    store = SpineStore(str(home / "spine.jsonl"))
    identity.ensure_owner_keypair()
    reg = CustomerRegistry(store)
    u, _ = reg.create("h@acme.com", issued_at=_iss())
    real = kh.key_resolver_with_horizon
    monkeypatch.setattr(kh, "clear_resolver_cache", lambda: kh._RESOLVER_CACHE.clear())   # another process

    def racing(store_, *, current):
        out = real(store_, current=current)
        kh.rotate(store_, issued_at=time.time())                  # lands between the scan and the fold
        return out

    monkeypatch.setattr(kh, "key_resolver_with_horizon", racing)
    reg.customer(u)
    assert not cust._CUSTOMER_FOLD._entries, "a history record above the horizon: the build is NOT cached"
    monkeypatch.setattr(kh, "key_resolver_with_horizon", real)
    kh._RESOLVER_CACHE.clear()
    assert reg.customer(u) == reg._fold().get(u)
    assert cust._CUSTOMER_FOLD._entries, "an unraced build is cached"


def test_the_horizon_is_the_last_seq_scanned(tmp_path):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    assert kh.key_resolver_with_horizon(store, current=OWNER_PUB)[1] == -1
    for i in range(3):
        store.append(kind="event", source="t", actor="u", payload={"i": i})
    res, horizon = kh.key_resolver_with_horizon(store, current=OWNER_PUB)
    assert horizon == 2
    assert res.at(2) == kh.key_resolver(store, current=OWNER_PUB).at(2) == OWNER_PUB


def test_an_entry_built_over_an_empty_window_is_extended_not_rebuilt(tmp_path, monkeypatch):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    reg = _reg(store)
    builds = _count_builds(monkeypatch)
    assert reg.customers() == [] and builds["builds"] == 1          # built over an empty spine: no anchor yet
    u, _ = reg.create("first@acme.com", issued_at=_iss())
    assert reg.customer(u) is not None and builds["builds"] == 1, "nothing folded yet: extend, don't rebuild"
    assert reg.customer(u) == reg._fold().get(u)


def test_key_history_kind_constant_matches():
    assert fold_cache.KEY_HISTORY_KIND == kh.KEY_HISTORY_KIND


# ---- snapshot boundary -----------------------------------------------------------------------------------
class _PrunedView:
    """A hard prune over a real store at the SAME path: hide every record with seq < K."""

    def __init__(self, inner):
        self._inner, self.K, self.path = inner, 0, inner.path

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self.K:
                yield r

    def get(self, seq):
        return self._inner.get(seq) if seq >= self.K else None

    def append(self, **kw):
        return self._inner.append(**kw)


def test_a_prune_moves_the_key_under_the_pubkey_bypass(tmp_path, monkeypatch, no_full_fold):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    reg = _reg(view)
    u, _ = reg.create("p@acme.com", issued_at=_iss())               # seq 0
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    assert reg.customer(u) is not None                              # warm over the unpruned spine
    other = generate_keypair().public_key_b64                       # the snapshot's pubkey differs: BYPASS
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=other, base_seq=k,
                 snapshot_seq=k - 1)
    view.K = k                                                      # [0..k) physically gone
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    _assert_equivalent(reg, [u], ["p@acme.com"], no_full_fold)
    assert reg.customer(u) is None, "the bypass folds only the live window: the pruned grant is gone"


def test_a_seeded_prune_keeps_the_pruned_customer_and_its_high_water(tmp_path, monkeypatch, no_full_fold):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    reg = _reg(view)
    keep, _ = reg.create("keep@acme.com", issued_at=_iss())          # seq 0 — only grant, will be pruned
    gone, gone_seq = reg.create("gone@acme.com", issued_at=_iss())   # seq 1
    captured = store.get(gone_seq).payload
    reg.revoke(gone)                                                 # seq 2
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=OWNER_PUB, base_seq=k,
                 snapshot_seq=k - 1)
    view.K = k
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # live replay
    late, _ = reg.create("late@acme.com", issued_at=_iss())
    names, mails = [keep, gone, late], ["keep@acme.com", "gone@acme.com", "late@acme.com"]
    _assert_equivalent(reg, names, mails, no_full_fold)
    assert reg.by_email("keep@acme.com") is not None, "the seed carries the pruned customer"
    assert reg.customer(gone) is None, "the seeded high-water refuses the replay"
    assert reg.customer(late) is not None


def test_a_different_seed_under_the_same_boundary_rebuilds(tmp_path, monkeypatch, no_full_fold):
    """The key binds the snapshot BY VALUE, not just its (base_seq, snapshot_seq): a seed that differs under
    the same boundary (here the high-water dropped, the neutered control of test_customers) rebuilds."""
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    reg = _reg(view)
    u, g = reg.create("hw@acme.com", issued_at=_iss())
    captured = store.get(g).payload
    reg.revoke(u)
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=OWNER_PUB, base_seq=k,
                 snapshot_seq=k - 1)
    view.K = k
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # live replay
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    assert reg.customer(u) is None                                   # warm: the seeded high-water refuses it
    neutered = snap.model_copy(update={"customer_issued": []})       # same boundary, high-water dropped
    assert (neutered.base_seq, neutered.snapshot_seq) == (snap.base_seq, snap.snapshot_seq)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: neutered))
    _assert_equivalent(reg, [u], ["hw@acme.com"], no_full_fold)
    assert reg.customer(u) is not None, "without the high-water the replay resurrects — in BOTH paths"


# ---- faults ----------------------------------------------------------------------------------------------
def test_a_fault_while_extending_discards_and_rebuilds(tmp_path, monkeypatch):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    reg = _reg(store)
    a, _ = reg.create("a@acme.com", issued_at=_iss())
    assert reg.customer(a) is not None                              # warm
    b, b_seq = reg.create("b@acme.com", issued_at=_iss())
    real = cust._apply_record
    state = {"raised": False}

    def flaky(r, *args):
        if r.seq == b_seq and not state["raised"]:
            state["raised"] = True
            raise RuntimeError("injected fault mid-extension")
        return real(r, *args)

    monkeypatch.setattr(cust, "_apply_record", flaky)
    builds = _count_builds(monkeypatch)
    assert reg.customer(b) is not None and state["raised"]
    assert builds["builds"] == 1, "the faulted entry is discarded and rebuilt from the spine"
    assert _cached_answers(reg, [a, b], ["a@acme.com", "b@acme.com"]) == _full_answers(
        reg, [a, b], ["a@acme.com", "b@acme.com"])


def test_a_fault_in_the_rebuild_raises_as_the_full_fold_does(tmp_path, monkeypatch):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    reg = _reg(store)
    a, _ = reg.create("a@acme.com", issued_at=_iss())

    def broken(*_a):
        raise RuntimeError("fold fault")

    monkeypatch.setattr(cust, "_apply_record", broken)
    with pytest.raises(RuntimeError):
        reg._fold()
    with pytest.raises(RuntimeError):
        reg.customer(a)
    assert not cust._CUSTOMER_FOLD._entries


def test_poisoned_view_falls_back_to_the_full_fold(tmp_path, no_full_fold):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    reg = _reg(store)
    a, _ = reg.create("a@acme.com", issued_at=_iss())
    core = {"signal": cust.SIGNAL, "username": 7, "email": "seven@acme.com", "state": "active",
            "issued_at": _iss()}                                    # owner-signed, non-str id (no code mints one)
    store.append(kind="event", source="governor", actor="WARDEN", payload=signed_payload(core, OWNER))
    before = no_full_fold["n"]
    assert reg.customer(a) == reg._fold().get(a)
    assert no_full_fold["n"] > before + 1, "a poisoned view must answer from the full fold"


# ---- concurrency -----------------------------------------------------------------------------------------
def test_concurrent_writers_and_readers(tmp_path):
    path = str(tmp_path / "spine.jsonl")
    base = _reg(SpineStore(path))
    errors: list[BaseException] = []
    stop = threading.Event()

    def writer(w):
        try:
            r = _reg(SpineStore(path))                              # own instance: cross-process shape
            for i in range(15):
                r.create(f"w{w}-{i}@acme.com", issued_at=_iss())
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    def reader():
        try:
            while not stop.is_set():
                base.customers()
                base.by_email("w0-0@acme.com")
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    readers = [threading.Thread(target=reader) for _ in range(3)]
    writers = [threading.Thread(target=writer, args=(w,)) for w in range(4)]
    for t in readers + writers:
        t.start()
    for t in writers:
        t.join()
    stop.set()
    for t in readers:
        t.join()
    assert not errors, errors
    mails = [f"w{w}-{i}@acme.com" for w in range(4) for i in range(15)]
    assert _cached_answers(base, [], mails) == _full_answers(base, [], mails)
    assert len(base.customers()) == 60


# ---- flag OFF --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["", "0", "false", "off", "no"])
def test_flag_off_never_consults_the_cache(tmp_path, monkeypatch, value):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", value)

    def boom(*_a, **_kw):
        raise AssertionError("the fold cache was consulted with the flag OFF")

    monkeypatch.setattr(cust._CUSTOMER_FOLD, "read", boom)
    reg = _reg(SpineStore(str(tmp_path / "spine.jsonl")))
    u, _ = reg.create("off@acme.com", issued_at=_iss(), password="customer-pw-9")
    assert reg.customer(u) is not None and reg.by_email("off@acme.com") is not None
    assert [c.username for c in reg.customers()] == [u]
    reg.set_password(u, "customer-pw-10", issued_at=_iss())
    assert reg.verify_login("off@acme.com", "customer-pw-10") is not None


def test_store_identity_falls_back_without_a_path():
    class NoPath:
        pass

    assert fold_cache._store_identity(NoPath())                       # stable, non-empty, never raises
