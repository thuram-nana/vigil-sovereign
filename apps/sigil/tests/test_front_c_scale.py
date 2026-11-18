"""Front C S4 (in-repo) — the SIMULATED SCALE TEST: the hot customer / org / wallet reads hold at scale.

This is the falsifiable-in-CI deliverable for "it scales to 1,000,000 users" WITHOUT a deployment. It seeds a
large spine fixture deterministically and offline (`spine/scale_harness.py`, reusing `authn.signed_payload`
so every seeded record folds identically to the registry's own mutation) and proves, for each hot per-request
read, the pure-code properties scaling rests on:

  * P1 INCREMENTAL FOLD — O(new records) per request, FLAT in N. A warm read verifies ZERO signatures, and k
    appends cost EXACTLY k verifications, at every N in a sweep (if it were O(N) the warm count would track N).
    The measured wall was ~150-200 us PER SIGNATURE, so a verification count that does not grow with N is the
    machine-independent O(1)-in-N proof.
  * P2 O(RETURNED) READER — a per-key read (login `by_email`, admission `membership_role`, the meter
    `balance`) touches O(1) folded entries; the all-tenants read touches O(N). Proven by wrapping the warmed
    view's own index dicts with a counting Mapping (lookups AND every iteration API: iter/keys/values/items) —
    a regression that replaced an index lookup with a scan is RED.
  * P3 CORRECTNESS AT SCALE — the cached all-tenants read equals the full (uncached) fold for EVERY one of the N
    entities, and first / middle / last / absent keys read back the seed's ground truth.
  * P4 THE WALL (flag-OFF control) — with the cache OFF the SAME per-key read re-verifies every record (the
    O(N) full fold) and returns the SAME answer: byte-identical behaviour off, and the per-request cost the
    cache removes.
  * P5 SEED FIDELITY — a harness-seeded record folds like a real `create`/`grant`, so the fast offline seed is
    not vacuous.
  * P6 TENANT ISOLATION AT SCALE (sovereign side; org == tenant) — across the N-tenant fleet a member of org i
    is admitted to org i and REFUSED in every other org sampled (boundary pairs + a deterministic sample), and
    the admission check itself stays O(1) per request (zero signature verifications warm).

N is in every test id, so a CI log shows exactly what was proven — there is no silent cap. Default: a
representative sweep (seconds in CI). The owner's real 100,000 / 1,000,000 acceptance run is
`VIGIL_SCALE_N=1000000` (it joins P1's sweep and sets P2/P3/P6's N), or directly
`python -m sigil.spine.scale_harness --fold customer --n 1000000`. Its extra cost is the documented one-time
COLD build (O(N), ~2.5 min per fold at 1M — at boot, off the request path, in production) and the folded
state's memory (one copy per registry per process, sized by N).

Fleet isolation of the OFFENSE workers (one CRUCIBLE_ROOT per tenant) is the offense-plane twin:
`engine/crucible/framework/v2/common/tests/test_tenant_fleet_scale.py`.
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Any, Callable

import pytest

from sigil.governor import customers as cust
from sigil.governor import orgs as orgs_mod
from sigil.governor import wallet as wallet_mod
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine import scale_harness as sh
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
PUB = OWNER.public_key_b64

# The scale point (P2/P3/P6) and P1's sweep. The owner's real-N acceptance: VIGIL_SCALE_N=1000000 — no cap.
_SCALE_N = int(os.environ.get("VIGIL_SCALE_N", "8000"))
_SWEEP = tuple(sorted({1000, 8000, _SCALE_N}))
if _SCALE_N < 16:                                     # loud, never a silently smaller test
    raise ValueError(f"VIGIL_SCALE_N={_SCALE_N} is too small to measure scaling (need >= 16)")
_SEED_CREDITS = 1000                                  # every seeded tenant's grant (scale_harness default)


@pytest.fixture(autouse=True)
def _cache_on(monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    fold_cache.clear_all()
    yield
    fold_cache.clear_all()


# --- a counting Mapping to prove a read is O(1)/O(returned), not a scan of every tenant ----------------
class _CountingDict(dict):
    """A dict that counts every element access: a lookup (`get` / `[]` / `in`) is one, and EVERY iteration API
    (`iter`, `keys`, `values`, `items`) is one PER ELEMENT — so an O(N) scan registers N however it is spelled.
    Dropped into a warmed view's index slot to measure a read's real touch count (the read path never mutates
    the view when nothing was appended, so the list-returning `keys/values/items` change no behaviour)."""

    __slots__ = ("_counter",)

    def __init__(self, inner: dict, counter: list) -> None:
        super().__init__(inner)
        self._counter = counter

    def get(self, key: Any, default: Any = None) -> Any:
        self._counter[0] += 1
        return super().get(key, default)

    def __getitem__(self, key: Any) -> Any:
        self._counter[0] += 1
        return super().__getitem__(key)

    def __contains__(self, key: Any) -> bool:
        self._counter[0] += 1
        return super().__contains__(key)

    def __iter__(self):
        for k in super().__iter__():
            self._counter[0] += 1
            yield k

    def keys(self):  # type: ignore[override]
        return list(self.__iter__())

    def values(self):  # type: ignore[override]
        return [super(_CountingDict, self).__getitem__(k) for k in self.__iter__()]

    def items(self):  # type: ignore[override]
        return [(k, super(_CountingDict, self).__getitem__(k)) for k in self.__iter__()]


def test_the_counting_dict_counts_every_scan_spelling():
    """The instrument itself: a lookup costs 1, a scan costs N whether it is spelled iter / keys / values /
    items / sorted / set / `in keys()` — so P2 cannot be false-passed by re-spelling a scan."""
    c: list = [0]
    d = _CountingDict({i: str(i) for i in range(50)}, c)
    for name, op in [("get", lambda: d.get(3)), ("[]", lambda: d[3]), ("in", lambda: 3 in d)]:
        c[0] = 0
        op()
        assert c[0] == 1, name
    for name, op in [("iter", lambda: list(d)), ("keys", lambda: d.keys()), ("values", lambda: d.values()),
                     ("items", lambda: d.items()), ("sorted", lambda: sorted(d)), ("set", lambda: set(d)),
                     ("in-keys", lambda: 49 in d.keys())]:
        c[0] = 0
        op()
        assert c[0] >= 50, f"{name} scanned {c[0]} (< 50): a scan spelled this way would go uncounted"


def _single_view(fold: fold_cache.FoldCache):
    entries = list(fold._entries.values())
    assert len(entries) == 1, f"expected exactly one warmed fold entry, got {len(entries)}"
    return entries[0].state


def _instrument(view: Any, attrs: tuple) -> "tuple[list, Callable[[], None]]":
    counter: list = [0]
    originals = {a: getattr(view, a) for a in attrs}
    for a, orig in originals.items():
        setattr(view, a, _CountingDict(orig, counter))

    def restore() -> None:
        for a, orig in originals.items():
            setattr(view, a, orig)

    return counter, restore


def _read_flag_off(fn: Callable[[], Any]) -> Any:
    """Run `fn` with the fold cache OFF (the unchanged full fold), restoring the flag after."""
    old = os.environ.get("VIGIL_FOLD_CACHE_ENABLED")
    os.environ["VIGIL_FOLD_CACHE_ENABLED"] = ""
    try:
        return fn()
    finally:
        if old is None:
            os.environ.pop("VIGIL_FOLD_CACHE_ENABLED", None)
        else:
            os.environ["VIGIL_FOLD_CACHE_ENABLED"] = old


# --- per-fold specs: everything the tests need, one place per hot read ---------------------------------
@dataclass
class _Spec:
    name: str
    module: Any                                   # the registry module whose verify_signed the fold calls
    fold: fold_cache.FoldCache
    view_attrs: tuple                             # the view index slots a read touches
    records_per_entity: int                       # signed records the cold fold verifies per entity
    make_reg: Callable[[SpineStore], Any]
    seed: Callable[[SpineStore, int, int], None]  # (store, n, start)
    key_read: Callable[[Any, int], Any]           # the hot single-key read (O(1)); arg = entity index
    all_read: Callable[[Any], Any]                # the all-tenants read (O(N))
    append_k: Callable[[SpineStore, int], int]    # append records for entity `at`; returns how many
    real_create: Callable[[Any, int], Any]        # a real registry mutation (fidelity check)
    ground_truth: Callable[[Any, int], bool]      # the cached key read equals what the seed wrote
    absent_is_empty: Callable[[Any], bool]        # the key read of a never-seeded entity is empty


def _customer_spec() -> _Spec:
    def seed(store, n, start):
        sh.seed_customers(store, n, OWNER, start=start)

    def append_k(store, at):
        sh.seed_customers(store, 3, OWNER, start=at)
        return 3

    def real_create(reg, i):
        reg.create(f"real{i}@scale.test", issued_at=10.0 + i, username=f"cust_real_{i}")
        return reg.by_email(f"real{i}@scale.test")

    def ground_truth(reg, i):
        a = reg.by_email(sh.customer_email(i))
        return (a is not None and a.username == sh.customer_name(i) and a.email == sh.customer_email(i)
                and a.state == "active" and a.password_hash is None and reg.customer(sh.customer_name(i)) == a)

    return _Spec(
        name="customer", module=cust, fold=cust._CUSTOMER_FOLD, view_attrs=("active", "emails"),
        records_per_entity=1,
        make_reg=lambda s: cust.CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=PUB),
        seed=seed, key_read=lambda reg, i: reg.by_email(sh.customer_email(i)),
        all_read=lambda reg: reg.customers(), append_k=append_k, real_create=real_create,
        ground_truth=ground_truth, absent_is_empty=lambda v: v is None)


def _orgs_spec() -> _Spec:
    def seed(store, n, start):
        sh.seed_orgs_memberships(store, n, OWNER, start=start)

    def append_k(store, at):
        sh.seed_orgs_memberships(store, 1, OWNER, start=at)
        return 2                                   # an org record AND a membership record

    def real_create(reg, i):
        reg.create_org(f"org_real_{i}", f"Org real {i}", owner=f"cust_real_{i}", issued_at=10.0 + i)
        reg.grant_membership(f"org_real_{i}", f"cust_real_{i}", "viewer", issued_at=11.0 + i)
        return reg.membership_role(f"cust_real_{i}", f"org_real_{i}")

    def ground_truth(reg, i):
        org = reg.org(sh.org_name(i))
        return (reg.membership_role(sh.customer_name(i), sh.org_name(i)) == "viewer"
                and org is not None and org.owner == sh.customer_name(i))

    return _Spec(
        name="orgs", module=orgs_mod, fold=orgs_mod._ORGS_FOLD,
        view_attrs=("active_orgs", "active_mems", "members"), records_per_entity=2,
        make_reg=lambda s: orgs_mod.OrgRegistry(s, owner_key=OWNER, trusted_pubkey=PUB),
        seed=seed, key_read=lambda reg, i: reg.membership_role(sh.customer_name(i), sh.org_name(i)),
        all_read=lambda reg: reg.memberships(None), append_k=append_k, real_create=real_create,
        ground_truth=ground_truth, absent_is_empty=lambda v: v is None)


def _wallet_spec() -> _Spec:
    def seed(store, n, start):
        sh.seed_wallets(store, n, OWNER, start=start)

    def append_k(store, at):
        sh.seed_wallets(store, 3, OWNER, start=at)
        return 3

    def real_create(reg, i):
        reg.grant(f"org_real_{i}", 500, "topup", entry_id=f"real-{i}", issued_at=10.0 + i)
        return reg.balance(f"org_real_{i}")

    def ground_truth(reg, i):
        b = reg.balance(sh.org_name(i))
        return b.org_id == sh.org_name(i) and b.granted == _SEED_CREDITS and b.debited == 0 and \
            b.available == _SEED_CREDITS

    return _Spec(
        name="wallet", module=wallet_mod, fold=wallet_mod._WALLET_FOLD,
        view_attrs=("granted", "debited", "usage"), records_per_entity=1,
        make_reg=lambda s: wallet_mod.WalletRegistry(s, owner_key=OWNER, trusted_pubkey=PUB),
        seed=seed, key_read=lambda reg, i: reg.balance(sh.org_name(i)),
        all_read=lambda reg: reg.balances(), append_k=append_k, real_create=real_create,
        ground_truth=ground_truth, absent_is_empty=lambda v: v.available == 0 and v.granted == 0)


_SPECS = {s.name: s for s in (_customer_spec(), _orgs_spec(), _wallet_spec())}


def _params(tag: str) -> list:
    """One param per fold, with N in the id (`customer-N=8000`) so a CI log names what was proven."""
    return [pytest.param(name, id=f"{name}-{tag}") for name in sorted(_SPECS)]


def _fresh(spec: _Spec, tmp_path, n: int, tag: str) -> "tuple[SpineStore, Any]":
    store = SpineStore(str(tmp_path / f"{spec.name}-{tag}.jsonl"))
    reg = spec.make_reg(store)
    spec.seed(store, n, 0)
    return store, reg


# ============ P1 — incremental fold: O(new) per request, FLAT in N =====================================
@pytest.mark.parametrize("name", _params("sweep=" + "/".join(str(n) for n in _SWEEP)))
def test_p1_warm_read_is_flat_in_N_and_appends_cost_exactly_k(name, tmp_path):
    """The headline scale claim. Across a sweep of N, a warm per-request read verifies ZERO signatures and k
    appends cost EXACTLY k — both INDEPENDENT of N. The cold full fold's cost grows with N (the wall the
    cache removes). If any read were O(N), its warm verification count would track N, not stay 0."""
    spec = _SPECS[name]
    warm_counts, cold_counts = [], []
    for n in _SWEEP:
        store, reg = _fresh(spec, tmp_path, n, f"p1-{n}")
        with sh.counting_verifications(spec.module) as c:
            spec.key_read(reg, n - 1)                      # COLD: folds + verifies every seeded record
            cold_counts.append(c[0])
            c[0] = 0
            spec.key_read(reg, 0)                          # WARM reads: verify nothing new
            spec.key_read(reg, n // 2)
            assert c[0] == 0, f"{name}: a warm read at N={n} verified {c[0]} signatures (expected 0 — O(N)?)"
            warm_counts.append(c[0])
            k = spec.append_k(store, n)                    # k new records
            spec.key_read(reg, n)                          # one warm read folds exactly the k new records
            assert c[0] == k, f"{name}: {k} appends at N={n} cost {c[0]} verifications (expected {k})"
        assert cold_counts[-1] == spec.records_per_entity * n, f"{name}: cold fold cost != records folded"
    # FLATNESS: the warm per-request cost is identical (0) at every N — the O(1)-in-N proof.
    assert warm_counts == [0] * len(_SWEEP), f"{name}: warm cost not flat across N: {warm_counts}"
    # The wall: the cold full-fold cost GROWS with N (what the cache removes per request when OFF).
    assert cold_counts == [spec.records_per_entity * n for n in _SWEEP], f"{name}: cold costs {cold_counts}"


# ============ P2 — a per-key read is O(returned), the all-tenants read is O(N) =========================
@pytest.mark.parametrize("name", _params(f"N={_SCALE_N}"))
def test_p2_per_key_read_is_O_returned_not_a_scan_of_all_tenants(name, tmp_path):
    """A per-key read touches a BOUNDED number of folded entries regardless of N; the all-tenants read
    touches >= N. Measured by wrapping the warmed view's own index dicts with a counting Mapping, so a
    regression that turned an index lookup back into a scan (O(all-tenants)) is caught."""
    spec = _SPECS[name]
    n = _SCALE_N
    store, reg = _fresh(spec, tmp_path, n, "p2")
    spec.key_read(reg, 0)                                  # warm the cache (one entry)
    view = _single_view(spec.fold)
    counter, restore = _instrument(view, spec.view_attrs)
    try:
        assert spec.key_read(reg, n // 2) is not None      # ONE key
        per_key = counter[0]
        counter[0] = 0
        assert len(spec.all_read(reg)) == n                # ALL tenants
        all_tenants = counter[0]
        assert _single_view(spec.fold) is view, "the measured reads were not served by the instrumented entry"
    finally:
        restore()
    assert per_key <= 8, f"{name}: a per-key read touched {per_key} entries at N={n} (expected O(1))"
    assert all_tenants >= n, f"{name}: the all-tenants read touched {all_tenants} (expected >= N={n})"


# ============ P3 — correctness at scale ================================================================
@pytest.mark.parametrize("name", _params(f"N={_SCALE_N}"))
def test_p3_reads_are_exact_at_scale(name, tmp_path):
    """At the scale point the cached all-tenants read equals the FULL (uncached) fold for every one of the N
    entities, and first / middle / last keys read back exactly what the seed wrote — the cache changed HOW the
    fold is read, never WHAT it says. A never-seeded key reads as empty."""
    spec = _SPECS[name]
    n = _SCALE_N
    store, reg = _fresh(spec, tmp_path, n, "p3")
    cached_all = spec.all_read(reg)
    assert len(cached_all) == n
    full_all = _read_flag_off(lambda: spec.all_read(spec.make_reg(store)))   # ONE full verifying fold
    assert cached_all == full_all, f"{name}: the cached fold of {n} tenants differs from the full fold"
    for i in (0, n // 2, n - 1):
        assert spec.ground_truth(reg, i), f"{name}: key {i} does not read back what the seed wrote (N={n})"
    assert spec.absent_is_empty(spec.key_read(reg, n + 10_000)), f"{name}: an absent key read as non-empty"
    if name == "wallet":                                   # no credit leaks across tenants
        assert all(b.granted == _SEED_CREDITS and b.debited == 0 for b in cached_all)


# ============ P4 — the wall: flag-OFF re-verifies every record, same answer ============================
@pytest.mark.parametrize("name", _params(f"N={_SWEEP[0]}"))
def test_p4_flag_off_is_the_full_fold_and_byte_identical(name, tmp_path):
    """With the cache OFF, one per-key read re-verifies EVERY seeded record (the O(N) full fold) — the exact
    per-request cost the cache removes — and returns the SAME answer the cached path did (byte-identical off).
    Run at the smallest sweep N: the point is the O(N) contrast with P1's flat 0, not the magnitude."""
    spec = _SPECS[name]
    n = _SWEEP[0]
    store, reg = _fresh(spec, tmp_path, n, "p4")
    cached = spec.key_read(reg, n // 2)                    # cache ON (autouse)
    with sh.counting_verifications(spec.module) as c:
        off = _read_flag_off(lambda: spec.key_read(reg, n // 2))   # cache OFF: a full verifying fold
        full_fold_cost = c[0]
    assert cached == off, f"{name}: flag-off answer differs from the cached answer (not byte-identical)"
    assert full_fold_cost >= n, (f"{name}: a flag-off read verified {full_fold_cost} (< N={n}); the cache is "
                                 f"NOT removing an O(N) per-request cost")


# ============ P5 — the fast offline seed folds like a real mutation ====================================
@pytest.mark.parametrize("name", _params("N=50"))
def test_p5_seeded_record_folds_like_a_real_mutation(name, tmp_path):
    """The seed is not vacuous: on ONE spine, seeded entities and one created through the REAL registry
    mutation (`create` / `create_org` + `grant_membership` / `grant`) both read back, and the cached read of a
    seeded entity still equals the full fold's."""
    spec = _SPECS[name]
    store, reg = _fresh(spec, tmp_path, 50, "p5")
    real = spec.real_create(reg, 999)
    assert real is not None, f"{name}: the real mutation did not read back"
    assert spec.ground_truth(reg, 10), f"{name}: a seeded entity did not read back beside a real one"
    assert spec.key_read(reg, 10) == _read_flag_off(lambda: spec.key_read(spec.make_reg(store), 10))


# ============ P6 — tenant isolation at scale (sovereign side: org == tenant) ===========================
def test_p6_cross_tenant_admission_is_refused_across_the_fleet(tmp_path):
    """Across N tenants, a member of org i is admitted to org i and REFUSED in every other org sampled — the
    boundary pairs (first/last, both ways), adjacent pairs and a deterministic sample — and the admission check
    stays O(1) per request: after the one cold build, thousands of admissions verify ZERO signatures."""
    spec = _SPECS["orgs"]
    n = _SCALE_N
    store, reg = _fresh(spec, tmp_path, n, "p6")
    rng = random.Random(1_000_000)
    pairs = [(0, n - 1), (n - 1, 0), (0, 1), (1, 0), (n - 2, n - 1), (n - 1, n - 2)]
    pairs += [(rng.randrange(n), rng.randrange(n)) for _ in range(2000)]
    pairs = [(i, j) for i, j in pairs if i != j]
    assert reg.admit_customer(username=sh.customer_name(0), org_id=sh.org_name(0), permission="read")   # cold
    with sh.counting_verifications(orgs_mod) as c:
        for i, j in pairs:
            u = sh.customer_name(i)
            assert reg.admit_customer(username=u, org_id=sh.org_name(i), permission="read"), (i, "own org")
            assert not reg.admit_customer(username=u, org_id=sh.org_name(j), permission="read"), (i, j)
            assert reg.membership_role(u, sh.org_name(j)) is None, (i, j)
        assert c[0] == 0, f"{len(pairs)} warm admissions verified {c[0]} signatures (expected 0 — O(N)?)"
    # a viewer is never admitted to an operator-tier permission, even in its own org (no global leg)
    assert not reg.admit_customer(username=sh.customer_name(5), org_id=sh.org_name(5), permission="view_billing")


# ============ the harness invariant itself (what `main()` / the owner's acceptance run asserts) =========
@pytest.mark.parametrize("name", _params("N=1500"))
def test_harness_measure_fold_reports_the_scale_invariant(name, tmp_path):
    """`scale_harness.measure_fold` (the `python -m ...` acceptance path) reports warm==0 and k_cost==k at a
    representative N — the same invariant the sweep proves, reached through the harness's own entry point —
    and `main()` exits 0 on it."""
    res = sh.measure_fold(name, 1500, store_path=str(tmp_path / f"{name}-measure.jsonl"))
    assert res["warm"] == 0 and res["k_cost"] == res["k_appends"]
    assert res["cold"] == _SPECS[name].records_per_entity * 1500
    assert sh.main(["--fold", name, "--n", "300", "--store", str(tmp_path / f"{name}-main.jsonl")]) == 0


def test_harness_main_fails_loudly_when_the_invariant_is_violated(tmp_path, monkeypatch, capsys):
    """`main()` is the acceptance verdict: if a warm read re-verified records (an O(N) regression) or k appends
    cost more than k, it exits NON-zero and prints VIOLATED — never a green run over a broken invariant."""
    for bad in ({"cold": 300, "warm": 300, "k_appends": 3, "k_cost": 3},       # a warm read re-folds the spine
                {"cold": 300, "warm": 0, "k_appends": 3, "k_cost": 303}):      # appends re-fold the spine
        monkeypatch.setitem(sh.FOLD_SEEDERS, "customer", lambda *_a, _b=bad: dict(_b))
        assert sh.main(["--fold", "customer", "--n", "300", "--store", str(tmp_path / "v.jsonl")]) == 1
        assert "VIOLATED" in capsys.readouterr().out
