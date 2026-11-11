"""Every snapshot-seeded registry fold across a REAL hard prune, flag OFF and ON.

The S0 fold-cache suites (`test_fold_cache_*.py`) simulate a prune by monkeypatching `SnapshotState.load`. Here
nothing about the snapshot, `build()` or a registry fold is patched: the spine is segmented for real, signed
with the persisted owner key (`checkpoint()`), hard-pruned with `commit_prune` at a segment boundary K, then
re-read from a FRESH `SpineStore` on the same path, so every registry seeds from the `kind="snapshot"` record
the prune itself wrote.

Two spines are built from the SAME records: A (segmented, pruned once) and B (a byte-for-byte record mirror of
A that is never pruned — the control). A filler record is appended to B where the prune appended its snapshot
record to A, so both keep identical seqs. The matrix, for `VIGIL_FOLD_CACHE_ENABLED` "0" and "1" (each read is
also cross-checked under the other flag value):

  1. every seeded registry + the kill switch + the capability latches written BELOW K;
  2. after `checkpoint()` + `commit_prune(K)`, the public read answers of A == the never-pruned control;
  3. records appended ABOVE K, then `checkpoint()` (the `sigil sign` path) re-signs a v2 head carrying the
     same boundary; the answers still equal B with the same later records applied;
  4. the kill switch reads ENGAGED after the prune and after the re-sign (the D1 fail-open read False);
  5. head.json deleted on the pruned spine: `SnapshotState.load` and `KillSwitch.is_engaged` fail CLOSED.

Coverage notes (kept out of the below-K set, not weakened):
  * BudgetLedger keeps NO snapshot sub-state by design (`budget.spent` docstring: the retention invariant keeps
    the CURRENT UTC day live; a past day may under-count post-prune — the accepted live-meter semantic). Its
    agent records therefore sit ABOVE K only, and are compared exactly there.
  * `AssetOwnershipRegistry.challenge` is a `live_window` read (its full scan never loads the snapshot), so a
    challenge issued below K is not expected to survive a prune; it is not part of the compared answers. The
    proofs (which ARE seeded) are.
  * `PlanCreditLedger.debited_entry` is a documented LIVE scan ("a reservation is settled well within its lease
    window, so its debit record is never pruned"); no prune guard enforces that, so a plan debit below K is not
    found after the prune (flag OFF and ON alike). It is compared only for a debit written above K.
"""
from __future__ import annotations

import itertools

import pytest

import sigil.config as cfg
import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
import sigil.spine.tail as _tail
from sigil.governor import accounts as acc
from sigil.governor import asset_ownership as ao
from sigil.governor import budget as bd
from sigil.governor import capability as cp
from sigil.governor import cost_ledger as cl
from sigil.governor import customer_credentials as cc
from sigil.governor import customers as cust
from sigil.governor import invoices as inv
from sigil.governor import killswitch as ks
from sigil.governor import metering as mt
from sigil.governor import monitoring_authority as ma
from sigil.governor import monitoring_subscription as ms
from sigil.governor import orgs as og
from sigil.governor import postpaid as pp
from sigil.governor import promotion as pr
from sigil.governor import subscription as sb
from sigil.governor import wallet as wl
from sigil.governor.identity import ensure_owner_keypair, owner_pubkey
from sigil.spine import fold_cache, prune
from sigil.spine.snapshot import SnapshotError, SnapshotState
from sigil.spine.store import SpineStore

ORGS = ["acme", "globex"]
HOSTS = ["a.example.com", "b.example.com"]
AGENTS = ["ALPHA", "BRAVO"]
SCOPES = ["*", "event"]
USERS = ["alice", "bob"]
GOOGLE = ("https://accounts.google.com", "g1")
DAY = "2026-11-11"
NOWS = [None, 1500.0, 2500.0]
OWN_NOWS = [10.0, 1e10]
CAPS = bd.BudgetCaps(daily_actions=3, daily_tokens=20, daily_cost_usd=0.02)
_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


# ---- isolation: per-spine head / floor, a per-test archive, the PERSISTED owner key ----------------------
class _Env:
    def __init__(self, tmp_path, monkeypatch):
        self.tmp, self.mp = tmp_path, monkeypatch
        monkeypatch.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(tmp_path / "archive"))
        # Registries and checkpoint()/prune share ONE owner identity: the key checkpoint._owner_keys signs
        # with and identity.owner_pubkey() (the prune's snapshot trust root) reads back.
        self.key = ensure_owner_keypair()
        assert owner_pubkey() == self.key.public_key_b64 == _cp._owner_keys()[1]

    def use(self, name: str) -> None:
        """Point every HEAD_PATH / FLOOR_PATH reader at spine `name`'s own head + floor."""
        d = self.tmp / name
        d.mkdir(exist_ok=True)
        head, floor = d / "head.json", d / "floor.json"
        for mod in (cfg, _cp, _snap, _tail):
            self.mp.setattr(mod, "HEAD_PATH", head, raising=False)
        for mod in (cfg, _fl):
            self.mp.setattr(mod, "FLOOR_PATH", floor, raising=False)

    def head_path(self, name: str):
        return self.tmp / name / "head.json"

    def store(self, name: str) -> SpineStore:
        (self.tmp / name).mkdir(exist_ok=True)
        return SpineStore(self.tmp / name / "spine.jsonl")

    def flag(self, value: str) -> None:
        self.mp.setenv("VIGIL_FOLD_CACHE_ENABLED", value)
        fold_cache.clear_all()


@pytest.fixture
def env(tmp_path, monkeypatch):
    fold_cache.clear_all()
    yield _Env(tmp_path, monkeypatch)
    fold_cache.clear_all()


class _Regs:
    def __init__(self, store, key):
        kw = {"owner_key": key, "trusted_pubkey": key.public_key_b64}
        self.store = store
        self.cust = cust.CustomerRegistry(store, **kw)
        self.orgs = og.OrgRegistry(store, **kw)
        self.acc = acc.AccountsRegistry(store, **kw)
        self.cred = cc.CustomerCredentialRegistry(store, **kw)
        self.wallet = wl.WalletRegistry(store, **kw)
        self.plan = mt.PlanCreditLedger(store, **kw)
        self.subs = sb.SubscriptionRegistry(store, **kw)
        self.msubs = ms.MonitoringSubscriptionRegistry(store, **kw)
        self.meter = mt.CreditMeter(self.wallet, self.plan, self.subs)
        self.inv = inv.InvoiceRegistry(store, **kw)
        self.cost = cl.CostEnvelopeLedger(store, **kw)
        self.pp = pp.PostpaidRegistry(store, **kw)
        self.arr = pp.PostpaidArrearsLedger(store, **kw)
        self.promo = pr.PromotionPolicy(store, **kw)
        self.budget = bd.BudgetLedger(store, CAPS)
        self.own = ao.AssetOwnershipRegistry(store, **kw)
        self.mon = ma.MonitoringAuthorityRegistry(store, **kw)
        self.kill = ks.KillSwitch(store, **kw)
        self.caps = cp.CapabilityGate(store, **kw)


class _World:
    """What the op batches created (usernames, tokens, entry ids) — the keys the answers are read under."""

    def __init__(self):
        self.customers: list[str] = []
        self.emails: list[str] = []
        self.tokens: list[str] = []
        self.entry_ids = ["paid-1", "spend-1", "refill-1", "res-1", "late-1",
                          cl.RESERVE_COST_PREFIX + "s:1", cl.SETTLE_COST_PREFIX + "s:1",
                          cl.RESERVE_COST_PREFIX + "s:9",
                          pp.RESERVE_ENTRY_PREFIX + "s:1", pp.SETTLE_ENTRY_PREFIX + "s:1", "direct-1"]


def _answers(r: _Regs, w: _World) -> dict:
    out: dict = {
        "customers": r.cust.customers(), "orgs": r.orgs.orgs(), "memberships": r.orgs.memberships(),
        "accounts": r.acc.accounts(), "balances": r.wallet.balances(), "subs": r.subs.subscriptions(),
        "msubs": r.msubs.subscriptions(), "all_invoices": r.inv.all_invoices(),
        "tenant_costs": r.cost.tenant_costs(), "global": r.cost.global_position(), "pp_accounts": r.pp.accounts(),
        "promoted": r.promo.state_all(), "engaged": r.kill.is_engaged(), "caps": r.caps.state_all(),
    }
    for u in w.customers + ["cust_unknown"]:
        out[("customer", u)] = r.cust.customer(u)
        out[("creds", u)] = r.cred.for_user(u)
        out[("totp", u)] = r.cred.totp_for(u)
    for e in w.emails + ["nobody@acme.com"]:
        out[("by_email", e)] = r.cust.by_email(e)
    for cid in ["cidA", "missing"]:
        out[("cid", cid)] = r.cred.by_credential_id(cid)
    out["fed"] = r.cred.by_federated(*GOOGLE)
    for t in w.tokens + ["not-a-token-xxxxxxxxxxxx"]:
        for now in (None, 50.0, 1e7):
            out[("resolve", t, now)] = r.acc.resolve(t, now=now)
    for u in USERS + ["nobody"]:
        out[("account", u)] = r.acc.account(u)
    for a in AGENTS + ["OTHER"]:
        for s in SCOPES:
            out[("is_promoted", a, s)] = r.promo.is_promoted(a, s)
        out[("spent", a)] = r.budget.spent(a, DAY)
        out[("over", a)] = r.budget.over_budget(a, DAY)
    for c in sorted(cp.CAPABILITIES):
        out[("enabled", c)] = r.caps.is_enabled(c)
    for o in ORGS + ["nope"]:
        out[("org", o)] = r.orgs.org(o)
        out[("memberships_of", o)] = r.orgs.memberships(o)
        for u in USERS + ["carol"]:
            out[("role", u, o)] = r.orgs.membership_role(u, o)
            out[("admit", u, o)] = r.orgs.admit_customer(username=u, org_id=o, permission="run_engagement")
        out[("bal", o)] = r.wallet.balance(o)
        out[("wavail", o)] = r.wallet.available(o)
        out[("tranches", o)] = r.plan.tranches(o)
        out[("sub", o)] = r.subs.subscription(o)
        out[("msub", o)] = r.msubs.subscription(o)
        for pe in (2000.0, 3000.0):
            out[("rem", o, pe)] = r.plan.remaining_for_period(o, pe)
        for now in NOWS:
            out[("plan_avail", o, now)] = r.plan.available(o, now)
            out[("active", o, now)] = r.subs.active_subscription(o, now)
            out[("meter", o, now)] = r.meter.available(o, now)
        out[("invoices", o)] = r.inv.invoices(o)
        out[("committed", o)] = r.cost.committed_cost(o)
        out[("in_flight", o)] = r.cost.in_flight_envelope(o)
        out[("reserved", o)] = r.cost.reserved_total(o)
        out[("tenant_cost", o)] = r.cost.tenant_cost(o)
        out[("pp", o)] = r.pp.account(o)
        out[("is_pp", o)] = r.pp.is_postpaid(o)
        out[("accrued", o)] = r.arr.accrued(o)
        out[("pp_in_flight", o)] = r.arr.in_flight_reserved(o)
        out[("net", o)] = r.arr.net_settled_consumed(o)
        out[("invoiced_pp", o)] = pp.invoiced_postpaid_total(r.inv, o)
        out[("paid_pp", o)] = pp.paid_postpaid_total(r.inv, o)
        out[("outstanding", o)] = pp.postpaid_outstanding(r.inv, o)
        out[("debited_entry", o, "late-1")] = r.plan.debited_entry(o, "late-1")   # live-window read: see top
        for eid in w.entry_ids:
            out[("was_reserved", o, eid)] = r.cost.was_reserved(o, eid)
            out[("was_accrued", o, eid)] = r.arr.was_accrued(o, eid)
        out[("grants", o)] = r.mon.grants(o)
        for now in OWN_NOWS:
            out[("proven", o, now)] = r.own.proven_hosts(o, now=now)
        for h in HOSTS:
            out[("proof", o, h)] = r.own.proof(o, h)
            out[("grant_for", o, h)] = r.mon.grant_for(o, h)
            for now in OWN_NOWS:
                out[("current", o, h, now)] = r.own.has_current_proof(o, h, now=now)
                out[("active_at", o, h, now)] = r.mon.active_at(o, h, now=now)
                out[("owned_at", o, h, now)] = r.mon.owned_at(o, h, now=now)
    return out


# ---- the op batches ---------------------------------------------------------------------------------------
def _batch_identity(r: _Regs, w: _World) -> None:
    for i, o in enumerate(ORGS):
        e = f"owner{i}@{o}.com"
        u, _ = r.cust.create(e, issued_at=_iss())
        w.customers.append(u)
        w.emails.append(e)
    r.cust.revoke(w.customers[1])                                  # a revoked customer stays revoked
    r.orgs.create_org("acme", "Acme Inc", owner="owner", issued_at=_iss())
    r.orgs.create_org("globex", "Globex", owner="owner", issued_at=_iss())
    r.orgs.grant_membership("acme", "alice", "org_admin", issued_at=_iss())
    r.orgs.grant_membership("acme", "bob", "viewer", issued_at=_iss())
    r.orgs.grant_membership("globex", "bob", "operator", issued_at=_iss())
    r.orgs.revoke_membership("acme", "bob")
    for u, role, ttl in (("alice", "operator", None), ("bob", "viewer", 1e6)):
        tok = f"bearer-{u}-" + "x" * 24
        r.acc.create(u, role, bearer_token=tok, issued_at=_iss(), ttl_seconds=ttl)
        w.tokens.append(tok)
    r.acc.assign_role("bob", "analyst", issued_at=_iss())
    c0 = w.customers[0]
    r.cred.enroll_passkey(c0, "cidA", cose_alg=-7, public_key_spki_b64="cGs=", uv=True, issued_at=_iss())
    r.cred.enroll_totp(c0, sealed_secret="c2VhbGVk", issued_at=_iss())
    r.cred.link_federated(c0, iss=GOOGLE[0], sub=GOOGLE[1], issued_at=_iss())


def _batch_money(r: _Regs, w: _World) -> None:
    r.wallet.grant("acme", 40, "topup", entry_id="paid-1", issued_at=_iss())
    r.wallet.debit("acme", 15, entry_id="spend-1", issued_at=_iss())
    r.wallet.grant("globex", 9, "trial", issued_at=_iss())
    r.subs.subscribe("acme", "pro", 100, period_start=0.0, period_end=2000.0, issued_at=_iss())
    r.subs.subscribe("globex", "pro", 50, period_start=0.0, period_end=2000.0, issued_at=_iss())
    r.subs.cancel("globex")
    r.plan.grant("acme", 100, period_end=2000.0, entry_id="refill-1", issued_at=_iss())
    r.plan.debit("acme", 30, period_end=2000.0, entry_id="res-1", issued_at=_iss())
    r.msubs.subscribe("acme", "aegis_observe_1h", 3, period_start=0.0, period_end=2000.0, issued_at=_iss())
    r.inv.record("acme", invoice_id="i1", kind="subscription", price_id="pro", amount_minor=4900, currency="usd",
                 credits=100, period_start=0.0, period_end=2000.0, issued_at=_iss())
    r.inv.record("globex", invoice_id="i2", kind="topup", price_id="p", amount_minor=900, issued_at=_iss())


def _batch_ledgers_and_latches(r: _Regs, w: _World) -> None:
    # cost + postpaid reserves are SETTLED below K (an in-flight reserve is a refused prune, by design)
    r.cost.reserve("acme", 100, entry_id=cl.RESERVE_COST_PREFIX + "s:1", issued_at=_iss())
    r.cost.settle("acme", 60, entry_id=cl.SETTLE_COST_PREFIX + "s:1", issued_at=_iss())
    r.pp.set_account("globex", 500, 30, issued_at=_iss())
    r.arr.accrue("globex", 20, entry_id=pp.RESERVE_ENTRY_PREFIX + "s:1", issued_at=_iss())
    r.arr.settle("globex", 5, entry_id=pp.SETTLE_ENTRY_PREFIX + "s:1", issued_at=_iss())
    r.arr.accrue("globex", 7, entry_id="direct-1", issued_at=_iss())
    assert pp.invoice_postpaid_arrears(r.pp, r.arr, r.inv, "globex", period_end=1000.0, issued_at=_iss())
    r.promo.grant("ALPHA", "*", issued_at=_iss())
    r.promo.grant("BRAVO", "event", issued_at=_iss())
    for o in ORGS:
        ch = r.own.issue_challenge(o, HOSTS[0], issued_at=_iss())
        r.own.verify_and_record(o, HOSTS[0], method=ao.METHOD_DNS_TXT, observed=[ch.marker], now=1.0,
                                ttl_seconds=1e9)
    r.mon.grant("acme", HOSTS[0], mode=ma.MODE_OBSERVE, not_before=0.0, not_after=5000.0, now=2.0, issued_at=_iss())
    r.caps.disable("voice")
    r.caps.disable("gesture")
    r.caps.enable("gesture", issued_at=_iss())
    r.kill.engage(reason="halt before the prune")


def _agent(store, actor: str, decision: str = "auto", usage=None) -> int:
    payload = {"decision": decision}
    if usage is not None:
        payload["usage"] = usage
    return store.append(kind="event", source="agent", actor=actor, payload=payload, ts=DAY + "T03:00:00Z")


def _batch_above_k(r: _Regs, w: _World) -> None:
    """The retained segment (≥ K): today's budget records live here (budget has no snapshot sub-state)."""
    _agent(r.store, "ALPHA", usage={"input_tokens": 5, "output_tokens": 7, "cost_usd": 0.01})
    _agent(r.store, "ALPHA", decision="denied")
    _agent(r.store, "BRAVO")
    r.wallet.grant("acme", 2, "refund", issued_at=_iss())


def _batch_later(r: _Regs, w: _World) -> None:
    """Appended AFTER the prune: touches seeded state from every registry so the seed + the live tail compose."""
    e = "late@acme.com"
    u, _ = r.cust.create(e, issued_at=_iss())
    w.customers.append(u)
    w.emails.append(e)
    r.orgs.grant_membership("acme", "carol", "analyst", issued_at=_iss())
    r.orgs.revoke_membership("globex", "bob")
    r.acc.revoke("alice")
    r.cred.revoke(w.customers[0], cc._CRED_KEY_TOTP)
    r.wallet.grant("acme", 5, "topup", entry_id="late-1", issued_at=_iss())
    r.wallet.grant("acme", 40, "topup", entry_id="paid-1", issued_at=_iss())   # a pruned entry id: no re-credit
    r.plan.debit("acme", 10, period_end=2000.0, entry_id="late-1", issued_at=_iss())
    r.subs.mark_past_due("acme")
    r.msubs.cancel("acme")
    r.inv.record("acme", invoice_id="i3", kind="topup", price_id="p", amount_minor=100, issued_at=_iss())
    r.inv.record("acme", invoice_id="i1", kind="subscription", price_id="pro", amount_minor=4900,   # replayed id
                 currency="usd", credits=100, period_start=0.0, period_end=2000.0, issued_at=_iss())
    r.cost.reserve("globex", 40, entry_id=cl.RESERVE_COST_PREFIX + "s:9", issued_at=_iss())    # in flight
    r.arr.accrue("globex", 3, entry_id="direct-2", issued_at=_iss())
    r.promo.revoke("BRAVO", "event")
    r.mon.revoke("acme", HOSTS[0])
    r.caps.disable("autolearn")
    r.caps.enable("voice", issued_at=_iss())
    _agent(r.store, "ALPHA", usage={"input_tokens": 3, "output_tokens": 1, "cost_usd": 0.001})
    _agent(r.store, "BRAVO", decision="queued")


def _mirror(src: SpineStore, dst: SpineStore, since: int) -> None:
    """Append every record of `src` with seq > `since` to `dst` verbatim (same kind/source/actor/payload/ts)."""
    for rec in src.iter_records(since_seq=since):
        seq = dst.append(kind=rec.kind, source=rec.source, actor=rec.actor, payload=rec.payload, ts=rec.ts,
                         parent_id=rec.parent_id, supersedes_id=rec.supersedes_id)
        assert seq == rec.seq, "the control spine must keep A's seqs"


# ---- the scenario ---------------------------------------------------------------------------------------
class _Scenario:
    def __init__(self, env: _Env):
        self.env, self.w = env, _World()

    def answers(self, name: str, flag: str) -> dict:
        """Answers of spine `name` from a FRESH store under `flag`, cross-checked under the other flag value."""
        self.env.use(name)
        other = "0" if flag == "1" else "1"
        self.env.flag(other)
        alt = _answers(_Regs(self.env.store(name), self.env.key), self.w)
        self.env.flag(flag)
        got = _answers(_Regs(self.env.store(name), self.env.key), self.w)
        assert got == alt, f"spine {name}: the fold cache ON and OFF disagree"
        return got

    def build(self) -> int:
        env = self.env
        env.use("A")
        a = env.store("A")
        a.migrate()
        ra = _Regs(a, env.key)
        for batch in (_batch_identity, _batch_money, _batch_ledgers_and_latches):
            batch(ra, self.w)
            a.rotate()
        k = a.next_seq                                      # K: the first seq of the (to be sealed) segment
        _batch_above_k(ra, self.w)
        a.rotate()
        a.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": 0})
        env.use("B")
        b = env.store("B")
        b.migrate()
        _mirror(a, b, -1)
        return k

    def prune(self, k: int) -> dict:
        env = self.env
        env.use("A")
        a = env.store("A")
        _cp.checkpoint(a)
        rep = prune.commit_prune(a, k, confirm=True)
        env.use("B")
        b = env.store("B")                                  # B takes a filler where A took the snapshot record
        b.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": "filler"})
        a2 = SpineStore(env.tmp / "A" / "spine.jsonl")
        assert a2.next_seq == b.next_seq
        return rep


@pytest.mark.parametrize("flag", ["0", "1"])
def test_every_seeded_fold_survives_a_real_prune_and_a_resign(env, flag):
    env.flag(flag)
    sc = _Scenario(env)
    k = sc.build()
    control = sc.answers("B", flag)
    assert sc.answers("A", flag) == control, "sanity: the mirror reads the same as the segmented spine"
    assert control["engaged"] is True and control[("bal", "acme")].granted == 42
    assert control["caps"] == {"autolearn": "enabled", "gesture": "enabled", "voice": "disabled"}

    # ---- 2. a REAL hard prune at the segment boundary K --------------------------------------------------
    rep = sc.prune(k)
    assert rep["base_seq"] == k and rep["files_deleted"] >= 1
    env.use("A")
    a = env.store("A")
    assert a.first_live_seq() == k, "the below-K records must be GONE from the live spine"
    assert SnapshotState.load(a).base_seq == k
    assert sc.answers("B", flag) == control, "the filler record changes nothing"
    after = sc.answers("A", flag)
    assert after["engaged"] is True, "D1: the kill switch must read ENGAGED after a real prune"
    assert after == control

    # ---- 3. records ABOVE K, then the `sigil sign` re-sign carries the boundary forward ----------------------
    env.use("A")
    a = env.store("A")
    old_head = _cp._read_head_on_disk()
    assert old_head.schema_version == 2 and old_head.base_seq == k
    tip = a.next_seq - 1
    _batch_later(_Regs(a, env.key), sc.w)
    env.use("B")
    _mirror(a, env.store("B"), tip)
    env.use("A")
    a = env.store("A")
    assert a.next_seq - k > old_head.entry_count - k, "the live window grew past the pruned head's"
    head = _cp.checkpoint(a)
    assert head.schema_version == 2
    assert (head.base_seq, head.snapshot_seq) == (old_head.base_seq, old_head.snapshot_seq) == (k, rep["snapshot_seq"])
    assert head.last_seq == a.next_seq - 1 and head.entry_count == a.next_seq
    a = env.store("A")
    ok, why = _cp.verify_checkpoint(a)
    assert ok, why
    assert SnapshotState.load(a).base_seq == k
    control2 = sc.answers("B", flag)
    resigned = sc.answers("A", flag)
    assert resigned["engaged"] is True, "D1: the kill switch must read ENGAGED after the re-sign"
    assert control2[("bal", "acme")].granted == 47, "a pruned entry id replayed live never re-credits"
    assert control2["caps"] == {"autolearn": "disabled", "gesture": "enabled", "voice": "enabled"}
    assert resigned == control2


@pytest.mark.parametrize("flag", ["0", "1"])
def test_a_pruned_spine_without_its_head_fails_closed(env, flag):
    env.flag(flag)
    sc = _Scenario(env)
    k = sc.build()
    sc.prune(k)
    env.use("A")
    env.flag(flag)
    regs = _Regs(env.store("A"), env.key)
    assert regs.kill.is_engaged() is True                  # warm (and, flag ON, cached) before the loss
    env.head_path("A").unlink()
    fold_cache.clear_all()
    a = env.store("A")
    with pytest.raises(SnapshotError):
        SnapshotState.load(a)
    with pytest.raises(SnapshotError):
        ks.KillSwitch(a, owner_key=env.key, trusted_pubkey=env.key.public_key_b64).is_engaged()
    with pytest.raises(SnapshotError):                      # the already-warm handle fails closed too
        regs.kill.is_engaged()
