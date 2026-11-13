"""Front C S0d — the remaining money ledgers on the verified incremental fold cache: the invoice / billing
history, the EC-4/EC-5 token-cost ledger (per tenant AND the global pool position), the postpaid account line
and the postpaid arrears ledger (incl. the in-flight reserve/settle pairing the PP-2 invoicing basis holds out).

Money is where a cache must be provably invisible. Every test compares the CACHED public API (and the
module-level PP-2/PP-2b/PP-3 helpers built on it) against the SAME API with the flag OFF — the unchanged full
folds and pairing scans — over the same spine, and checks that a cached read never silently fell back to a full
scan (every full scan builds the memoized owner-key resolver; the cache builds its own, with a horizon). The
generic trust-model cases (anchor, rotation, genesis, build race, faults, concurrency) are proven on the shared
substrate in `test_fold_cache_customers.py`.

  * seeded randomized equivalence over every ledger op: invoices with replayed ids, cost reserve/settle with
    suffixes SHARED across tenants (a cross-tenant collision must never pair), settles that land BEFORE their
    reserve, a settle with no reserve, owner-signed records outside the reserve/settle prefixes (counted, never
    paired), postpaid open / owner latch / fresh and stale webhook close, accrue / reverse / settle at refund
    0, arrears invoicing + payment, replays, forged, unsigned, noise, a second store instance;
  * O(new records): a warm read verifies ZERO signatures; k appends cost exactly k;
  * a seeded hard prune keeps the totals and the consumed entry ids, so a pruned reserve replayed live is
    never a phantom in-flight draw; the pubkey bypass folds the live window only;
  * flag OFF: no ledger cache is consulted.
"""
from __future__ import annotations

import itertools
import random

import pytest

from sigil.governor import cost_ledger as cl
from sigil.governor import invoices as inv
from sigil.governor import key_history as kh
from sigil.governor import postpaid as pp
from sigil.governor.authn import signed_payload
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine.snapshot import SnapshotError, SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()
ORGS = ["acme", "globex", "initech"]
SUFFIXES = ["s:1", "s:2", "s:3", "s:4"]
# Near misses of the settle prefixes, of the SAME length: slicing the prefix off yields a real suffix, so a pairing
# that forgot to check the prefix would wrongly settle that reserve.
NEAR_COST_SETTLE = "settle-cosT:"
NEAR_PP_SETTLE = "settle-postpaiD:"
assert len(NEAR_COST_SETTLE) == len(cl.SETTLE_COST_PREFIX) and len(NEAR_PP_SETTLE) == len(pp.SETTLE_ENTRY_PREFIX)
NOWS = [0.0, 1000.0, 5000.0, 1e9]
_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


@pytest.fixture(autouse=True)
def _cache_on(monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    fold_cache.clear_all()
    yield
    fold_cache.clear_all()


class _Regs:
    def __init__(self, store, key=OWNER, pub=OWNER_PUB):
        kw = {"owner_key": key, "trusted_pubkey": pub}
        self.inv = inv.InvoiceRegistry(store, **kw)
        self.cost = cl.CostEnvelopeLedger(store, **kw)
        self.pp = pp.PostpaidRegistry(store, **kw)
        self.arr = pp.PostpaidArrearsLedger(store, **kw)


@pytest.fixture
def no_full_scan(monkeypatch):
    """Counts full folds / pairing scans: every one builds the memoized owner-key resolver."""
    calls = {"n": 0}
    real = kh.key_resolver

    def spy(*a, **kw):
        calls["n"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(kh, "key_resolver", spy)
    return calls


def _answers(regs, entry_ids):
    out = {"all_invoices": regs.inv.all_invoices(), "tenant_costs": regs.cost.tenant_costs(),
           "global": regs.cost.global_position(), "pp_accounts": regs.pp.accounts()}
    for o in ORGS + ["nope"]:
        out[("invoices", o)] = regs.inv.invoices(o)
        out[("committed", o)] = regs.cost.committed_cost(o)
        out[("in_flight", o)] = regs.cost.in_flight_envelope(o)
        out[("reserved", o)] = regs.cost.reserved_total(o)
        out[("tenant_cost", o)] = regs.cost.tenant_cost(o)
        out[("pp", o)] = regs.pp.account(o)
        out[("is_pp", o)] = regs.pp.is_postpaid(o)
        out[("accrued", o)] = regs.arr.accrued(o)
        out[("pp_in_flight", o)] = regs.arr.in_flight_reserved(o)
        out[("net", o)] = regs.arr.net_settled_consumed(o)
        out[("invoiced", o)] = pp.invoiced_postpaid_total(regs.inv, o)
        out[("paid", o)] = pp.paid_postpaid_total(regs.inv, o)
        out[("outstanding", o)] = pp.postpaid_outstanding(regs.inv, o)
        for now in NOWS:
            out[("overdue", o, now)] = pp.postpaid_overdue_amount(regs.inv, regs.pp, o, now)
        for eid in entry_ids:
            out[("was_reserved", o, eid)] = regs.cost.was_reserved(o, eid)
            out[("was_accrued", o, eid)] = regs.arr.was_accrued(o, eid)
    return out


def _assert_equivalent(regs, entry_ids, monkeypatch, no_full_scan=None):
    before = no_full_scan["n"] if no_full_scan is not None else 0
    cached = _answers(regs, entry_ids)
    if no_full_scan is not None:
        assert no_full_scan["n"] == before, "a cached ledger read fell back to a full scan"
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    try:
        full = _answers(regs, entry_ids)
    finally:
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    assert cached == full


def _raw(store, payload):
    return store.append(kind="event", source="governor", actor="WARDEN", payload=payload)


def _signed(store, core, key=OWNER):
    return _raw(store, signed_payload(core, key))


def _entry_ids():
    return ([cl.RESERVE_COST_PREFIX + s for s in SUFFIXES] + [cl.SETTLE_COST_PREFIX + s for s in SUFFIXES]
            + [pp.RESERVE_ENTRY_PREFIX + s for s in SUFFIXES] + [pp.SETTLE_ENTRY_PREFIX + s for s in SUFFIXES]
            + ["direct-1", "odd-1"])


def _fails_closed_both_ways(monkeypatch, *reads):
    """Every read RAISES `SnapshotError`, with the fold cache ON and OFF alike (never an answer from an empty start)."""
    for flag in ("1", ""):
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
        for read in reads:
            with pytest.raises(SnapshotError, match="does not succeed"):
                read()
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")


@pytest.mark.parametrize("seed", [41, 42, 43])
def test_randomized_equivalence_with_the_full_ledger_folds(tmp_path, seed, monkeypatch, no_full_scan):
    rng = random.Random(seed)
    path = str(tmp_path / "spine.jsonl")
    store, other = SpineStore(path), SpineStore(path)
    regs, regs_other = _Regs(store), _Regs(other)
    entry_ids = _entry_ids()
    captured: list = []
    for step in range(80):
        o, suf = rng.choice(ORGS), rng.choice(SUFFIXES)
        r = regs_other if rng.random() < 0.2 else regs
        op = rng.choice(["invoice", "creserve", "creserve", "csettle", "csettle", "codd", "ppopen", "pplatch",
                         "ppclose", "ppstale", "accrue", "accrue", "direct", "reverse", "settle", "settle0",
                         "bill", "pay", "replay", "forged", "unsigned", "noise"])
        seq = None
        try:
            if op == "invoice":
                seq = r.inv.record(o, invoice_id=rng.choice(["i1", "i2", "i3"]), kind=rng.choice(sorted(inv.INVOICE_KINDS)),
                                   price_id="pro", amount_minor=rng.randint(0, 9000), currency="usd",
                                   credits=rng.randint(0, 50), period_start=0.0, period_end=rng.choice(NOWS),
                                   issued_at=_iss())
            elif op == "creserve":
                seq = r.cost.reserve(o, rng.randint(1, 900), entry_id=cl.RESERVE_COST_PREFIX + suf, issued_at=_iss())
            elif op == "csettle":                  # may land before its reserve, or with no reserve at all
                seq = r.cost.settle(o, rng.randint(0, 900), entry_id=cl.SETTLE_COST_PREFIX + suf,
                                    reserved_cap=rng.choice([None, 300]), issued_at=_iss())
            elif op == "codd":                     # owner-signed, outside the prefixes: counted, never paired
                sig = rng.choice([cl.COST_RESERVE_SIGNAL, cl.COST_SETTLE_SIGNAL])
                eid = rng.choice(["odd-1", NEAR_COST_SETTLE + suf, cl.SETTLE_COST_PREFIX + suf
                                  if sig == cl.COST_RESERVE_SIGNAL else cl.RESERVE_COST_PREFIX + suf])
                seq = _signed(store, {"signal": sig, "org_id": o, "entry_id": eid, "tokens": rng.randint(1, 50),
                                      "engagement_id": "", "issued_at": _iss()})
            elif op == "ppopen":
                seq = r.pp.set_account(o, rng.randint(0, 500), rng.choice([0, 15, 30]), issued_at=_iss())
            elif op == "pplatch":                  # the owner-manual close: honoured on sight
                r.pp.disable(o)
            elif op == "ppclose":                  # webhook-driven, fresher than the last open
                r.pp.disable(o, issued_at=_iss() + 0.5)
            elif op == "ppstale":                  # webhook-driven, OLDER than any open: ignored
                r.pp.disable(o, issued_at=0.25)
            elif op == "accrue":
                seq = r.arr.accrue(o, rng.randint(1, 60), entry_id=pp.RESERVE_ENTRY_PREFIX + suf, issued_at=_iss())
            elif op == "direct":
                seq = r.arr.accrue(o, rng.randint(1, 60), entry_id=rng.choice(["direct-1", None]), issued_at=_iss())
            elif op == "reverse":
                seq = r.arr.reverse(o, rng.randint(1, 30), issued_at=_iss(),
                                    entry_id=rng.choice(["odd-1", NEAR_PP_SETTLE + suf, pp.SETTLE_ENTRY_PREFIX + suf]))
            elif op == "settle":
                seq = r.arr.settle(o, rng.randint(1, 30), entry_id=pp.SETTLE_ENTRY_PREFIX + suf, issued_at=_iss())
            elif op == "settle0":                  # a full-consumption settle: a 0 refund still clears in-flight
                seq = r.arr.settle(o, 0, entry_id=pp.SETTLE_ENTRY_PREFIX + suf, issued_at=_iss())
            elif op == "bill":
                seq = pp.invoice_postpaid_arrears(r.pp, r.arr, r.inv, o, period_end=rng.choice(NOWS[:3]),
                                                  issued_at=_iss())
            elif op == "pay":
                billed = [i.invoice_id for i in r.inv.invoices(o) if i.kind == "postpaid"]
                if billed:
                    seq = pp.pay_postpaid_invoice(r.inv, o, rng.choice(billed), issued_at=_iss())
            elif op == "replay" and captured:
                _raw(store, rng.choice(captured))
            elif op == "forged":
                core = {"signal": cl.COST_SETTLE_SIGNAL, "org_id": o, "entry_id": cl.SETTLE_COST_PREFIX + suf,
                        "tokens": 10**6, "engagement_id": "", "issued_at": _iss()}
                _signed(store, core, key=ATTACKER)
            elif op == "unsigned":
                _raw(store, {"signal": pp.POSTPAID_DEBIT_SIGNAL, "org_id": o, "entry_id": pp.RESERVE_ENTRY_PREFIX + suf,
                             "credits": 10**6, "engagement_id": "", "issued_at": _iss()})
            else:
                store.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": step})
        except ValueError:
            pass                                            # an op the ledger refuses at binding
        if seq is not None:
            captured.append(store.get(seq).payload)
        _assert_equivalent(regs, entry_ids, monkeypatch, no_full_scan)
    assert inv._INVOICES_FOLD._entries and cl._COST_FOLD._entries and pp._ARREARS_FOLD._entries
    assert pp._pp_fold(pp.POSTPAID_SIGNAL)._entries


def test_cross_tenant_suffixes_never_pair_and_settle_first_still_pairs(tmp_path, monkeypatch, no_full_scan):
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    assert regs.cost.global_position().used_tokens == 0                       # warm
    regs.cost.reserve("acme", 100, entry_id=cl.RESERVE_COST_PREFIX + "s:1", issued_at=_iss())
    regs.cost.settle("globex", 40, entry_id=cl.SETTLE_COST_PREFIX + "s:1", issued_at=_iss())   # other tenant
    regs.cost.settle("initech", 30, entry_id=cl.SETTLE_COST_PREFIX + "s:2", issued_at=_iss())  # settle first
    regs.cost.reserve("initech", 70, entry_id=cl.RESERVE_COST_PREFIX + "s:2", issued_at=_iss())
    regs.arr.accrue("acme", 20, entry_id=pp.RESERVE_ENTRY_PREFIX + "s:1", issued_at=_iss())
    regs.arr.settle("globex", 0, entry_id=pp.SETTLE_ENTRY_PREFIX + "s:1", issued_at=_iss())
    _signed(regs.cost.store, {"signal": cl.COST_SETTLE_SIGNAL, "org_id": "acme", "entry_id": NEAR_COST_SETTLE + "s:1",
                              "tokens": 5, "engagement_id": "", "issued_at": _iss()})   # near miss: counted, unpaired
    regs.arr.reverse("acme", 1, entry_id=NEAR_PP_SETTLE + "s:1", issued_at=_iss())
    _assert_equivalent(regs, _entry_ids(), monkeypatch, no_full_scan)
    assert regs.cost.in_flight_envelope("acme") == 100 and regs.cost.in_flight_envelope("initech") == 0
    assert regs.cost.global_position() == cl.GlobalCostPosition(committed_tokens=75, in_flight_tokens=100)
    assert regs.arr.in_flight_reserved("acme") == 20
    regs.cost.settle("acme", 60, entry_id=cl.SETTLE_COST_PREFIX + "s:1", issued_at=_iss())
    regs.arr.settle("acme", 0, entry_id=pp.SETTLE_ENTRY_PREFIX + "s:1", issued_at=_iss())
    _assert_equivalent(regs, _entry_ids(), monkeypatch, no_full_scan)
    assert regs.cost.global_position() == cl.GlobalCostPosition(committed_tokens=135, in_flight_tokens=0)
    assert regs.arr.in_flight_reserved("acme") == 0 and regs.arr.net_settled_consumed("acme") == 19


def test_a_warm_ledger_read_verifies_no_signature_and_appends_cost_one_each(tmp_path, monkeypatch):
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    for i in range(4):
        regs.cost.reserve("acme", 100, entry_id=f"{cl.RESERVE_COST_PREFIX}s:{i}", issued_at=_iss())
        regs.arr.accrue("acme", 10, entry_id=f"{pp.RESERVE_ENTRY_PREFIX}s:{i}", issued_at=_iss())
        regs.inv.record("acme", invoice_id=f"i{i}", kind="topup", price_id="p", amount_minor=100, issued_at=_iss())
    regs.pp.set_account("acme", 500, 30, issued_at=_iss())
    count = {"n": 0}
    for mod in (inv, cl, pp):
        real = mod.verify_signed

        def counting(*a, _real=real, **kw):
            count["n"] += 1
            return _real(*a, **kw)

        monkeypatch.setattr(mod, "verify_signed", counting)

    def read():
        return (regs.cost.global_position(), regs.cost.tenant_cost("acme"), regs.arr.net_settled_consumed("acme"),
                regs.pp.is_postpaid("acme"), len(regs.inv.invoices("acme")))

    assert read() == (cl.GlobalCostPosition(0, 400), cl.TenantCost("acme", 0, 400, 400), 0, True, 4)
    assert count["n"] == 13                                  # cold: every ledger record verified once
    count["n"] = 0
    for _ in range(5):
        read()
    assert count["n"] == 0, "a warm ledger read must not re-verify any signature"
    regs.cost.settle("acme", 80, entry_id=cl.SETTLE_COST_PREFIX + "s:0", issued_at=_iss())
    regs.arr.settle("acme", 3, entry_id=pp.SETTLE_ENTRY_PREFIX + "s:0", issued_at=_iss())
    assert read() == (cl.GlobalCostPosition(80, 300), cl.TenantCost("acme", 80, 400, 300), 7, True, 4)
    assert count["n"] == 2


class _PrunedView:
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


def _pruned_ledgers(tmp_path, monkeypatch, *, snap_pub):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    regs = _Regs(view)
    regs.inv.record("acme", invoice_id="i-old", kind="subscription", price_id="pro", amount_minor=4900,
                    currency="usd", credits=100, period_start=0.0, period_end=1000.0, issued_at=_iss())
    cr = regs.cost.reserve("acme", 100, entry_id=cl.RESERVE_COST_PREFIX + "s:1", issued_at=_iss())
    regs.cost.settle("acme", 60, entry_id=cl.SETTLE_COST_PREFIX + "s:1", issued_at=_iss())
    regs.pp.set_account("acme", 500, 30, issued_at=_iss())
    ar = regs.arr.accrue("acme", 40, entry_id=pp.RESERVE_ENTRY_PREFIX + "s:1", issued_at=_iss())
    regs.arr.settle("acme", 10, entry_id=pp.SETTLE_ENTRY_PREFIX + "s:1", issued_at=_iss())
    captured = [store.get(cr).payload, store.get(ar).payload]
    assert regs.cost.global_position().committed_tokens == 60                # warm, unpruned
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=snap_pub, base_seq=k,
                 snapshot_seq=k - 1)
    view.K = k
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    return store, regs, snap, captured


def test_a_seeded_prune_keeps_totals_and_a_pruned_reserve_replayed_live_is_no_phantom(tmp_path, monkeypatch,
                                                                                        no_full_scan):
    store, regs, snap, captured = _pruned_ledgers(tmp_path, monkeypatch, snap_pub=OWNER_PUB)
    assert snap.cost_settled_map() and snap.postpaid_arrears_debited_map() and snap.invoice_row
    for p in captured:                                  # replay the pruned (already-settled) reserves live
        _raw(store, p)
    regs.cost.reserve("acme", 50, entry_id=cl.RESERVE_COST_PREFIX + "s:2", issued_at=_iss())
    _assert_equivalent(regs, _entry_ids(), monkeypatch, no_full_scan)
    assert regs.cost.global_position() == cl.GlobalCostPosition(committed_tokens=60, in_flight_tokens=50)
    assert regs.arr.in_flight_reserved("acme") == 0 and regs.arr.net_settled_consumed("acme") == 30
    assert [i.invoice_id for i in regs.inv.invoices("acme")] == ["i-old"]
    assert regs.cost.was_reserved("acme", cl.RESERVE_COST_PREFIX + "s:1") and regs.pp.is_postpaid("acme")


def test_a_foreign_key_reader_of_a_pruned_snapshot_fails_closed(tmp_path, monkeypatch):
    """A PRUNED snapshot folded under a key the reader's owner-key succession does not reach (a swapped key, a
    re-genesis) is never trusted, and an empty start over the deleted prefix is not an answer either: every read
    fails CLOSED, cached and uncached alike."""
    store, regs, _snap, _captured = _pruned_ledgers(tmp_path, monkeypatch, snap_pub=OWNER_PUB)
    new_owner = generate_keypair()
    reader = _Regs(regs.inv.store, key=new_owner, pub=new_owner.public_key_b64)
    _fails_closed_both_ways(monkeypatch, reader.cost.global_position, reader.inv.all_invoices,
                            lambda: reader.pp.account("acme"), lambda: reader.arr.accrued("acme"))


@pytest.mark.parametrize("value", ["", "0", "off"])
def test_flag_off_never_consults_a_ledger_cache(tmp_path, monkeypatch, value):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", value)

    def boom(*_a, **_kw):
        raise AssertionError("a ledger fold cache was consulted with the flag OFF")

    for c in (inv._INVOICES_FOLD, cl._COST_FOLD, pp._ARREARS_FOLD, pp._pp_fold(pp.POSTPAID_SIGNAL)):
        monkeypatch.setattr(c, "read", boom)
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    regs.cost.reserve("acme", 100, entry_id=cl.RESERVE_COST_PREFIX + "s:1", issued_at=_iss())
    regs.pp.set_account("acme", 500, 30, issued_at=_iss())
    regs.arr.accrue("acme", 40, entry_id=pp.RESERVE_ENTRY_PREFIX + "s:1", issued_at=_iss())
    regs.inv.record("acme", invoice_id="i1", kind="topup", price_id="p", amount_minor=1, issued_at=_iss())
    assert regs.cost.global_position().in_flight_tokens == 100 and regs.cost.tenant_costs()
    assert regs.arr.in_flight_reserved("acme") == 40 and regs.arr.was_accrued("acme", pp.RESERVE_ENTRY_PREFIX + "s:1")
    assert regs.pp.is_postpaid("acme") and len(regs.inv.all_invoices()) == 1
