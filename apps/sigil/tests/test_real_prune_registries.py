"""Every seeded registry read, across a REAL hard prune (`prune.commit_prune`) — nothing here monkeypatches
`SnapshotState.load` or any prune internal.

`sigil spine prune -K N --yes` deletes records `[0..K)` and appends a `kind="snapshot"` record whose
`folded_state` is the seed every owner-signed registry fold then starts from. The other prune / snapshot tests
either stop at the chain (`test_spine_prune_cutover.py`) or hand the folds a synthetic seed by monkeypatching
`SnapshotState.load`, so no registry was ever read after a real cutover. This file closes that gap.

For each registry (`SCENARIOS`) the harness (`_pipeline`) builds TWO spines from the same op list, under the same
owner key, with explicit `issued_at` values:

  * the PRUNED spine: `below` ops (two sealed segments) | K | `live` ops | checkpoint | REAL prune at K | then
    three rounds of further ops (`after`, `later`, `latest`), each followed by a segment rotation and an ordinary
    `checkpoint()` — the spine keeps living, and being re-anchored, after the prune;
  * the CONTROL spine: the same ops, never pruned.

and records one verdict per check (`CHECKS`):

  baseline     before the prune, flag ON == flag OFF and the pruned spine == the control (a fixture sanity check)
  below_k      the registry's defining records really sit below K and are gone from `iter_records()` afterwards,
               `SnapshotState.load` names the real boundary, and the reads have teeth (a spine holding only the
               live-window ops answers differently)
  prune1_{off,on}   every read on a FRESH handle == the same read before the prune, with
               `VIGIL_FOLD_CACHE_ENABLED` unset / `=1` (ON: a cache kept warm across the prune, a cold one, and a
               warm re-read) — and on a LONG-LIVED handle opened before the prune (a daemon that outlives it)
  after1_{off,on}   after each round of ops on the pruned spine, and again after the checkpoint that follows it,
               every read == the control spine's
  writes       every op after the prune has the same outcome (ok / the same refusal) on both spines

Reads are compared exactly before/after a prune (same spine). Against the control, fields that legitimately differ
between two independently written spines are scrubbed and named per scenario (`Scenario.salted`: random salts).

Behaviour a docstring declares by design is pinned in the dedicated tests at the bottom (each quotes its source);
everything else is strict equality. The last section covers `checkpoint()` on an already-pruned spine: it must
carry the committed prune boundary forward, or refuse.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_real_prune_registries.py
"""
from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import pytest

import sigil.config as cfg
import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
import sigil.spine.tail as _tail
from sigil.governor import accounts as acc
from sigil.governor import asset_ownership as ao
from sigil.governor import budget as bd
from sigil.governor import capability as cap
from sigil.governor import cost_ledger as cl
from sigil.governor import customer_credentials as cc
from sigil.governor import customers as cu
from sigil.governor import identity
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
from sigil.spine import fold_cache, prune
from sigil.spine.snapshot import SnapshotError, SnapshotState
from sigil.spine.store import SpineStore
from sigil.ui import assessments as ui_assess
from sigil.ui import margin as ui_margin
from sigil.ui.target_authorization import _customer_slug

FLAG = "VIGIL_FOLD_CACHE_ENABLED"
CHECKS = ("baseline", "below_k", "prune1_off", "prune1_on", "after1_off", "after1_on", "writes")
CAPS = bd.BudgetCaps(daily_actions=3, daily_tokens=40, daily_cost_usd=0.05)


# ======================================================================================================
# the harness
# ======================================================================================================
def _isolate_keys(mp, keys: Path) -> None:
    """One owner identity for the whole run: the checkpoint signer and the governance anchor read the SAME
    key files (as in production, where both are `KEYS_DIR/owner.*`)."""
    mp.setattr(cfg, "KEYS_DIR", keys, raising=False)
    mp.setattr(_cp, "KEYS_DIR", keys)
    for mod in (_cp, identity):
        mp.setattr(mod, "_PRIV", keys / "owner.priv")
        mp.setattr(mod, "_PUB", keys / "owner.pub")
    mp.setattr(identity, "_GENESIS_PUB", keys / "owner.genesis.pub")


class _World:
    """One spine with its own signed head, floor and archive. The head / floor paths are process globals, so a
    world must be `activate()`d before it is read or written."""

    def __init__(self, root: Path, mp, owner) -> None:
        self.root, self.mp, self.owner = root, mp, owner
        self.memo: dict = {}                      # per-world scratch the ops / reads share (captured payloads)
        root.mkdir(parents=True)
        self.path = root / "spine.jsonl"
        SpineStore(self.path).migrate()

    def activate(self) -> "_World":
        head = self.root / "head.json"
        for mod in (cfg, _cp, _snap, _tail):
            self.mp.setattr(mod, "HEAD_PATH", head, raising=False)
        self.mp.setattr(_fl, "FLOOR_PATH", self.root / "floor.json")
        self.mp.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(self.root / "archive"))
        fold_cache.clear_all()
        return self

    def store(self) -> SpineStore:
        return SpineStore(self.path)              # always a FRESH handle: no in-memory state survives

    def apply(self, ops: Iterable[Callable]) -> list[str]:
        regs, out = _Regs(self), []
        for op in ops:
            try:
                op(regs)
                out.append("ok")
            except Exception as e:  # noqa: BLE001 — a refusal is an outcome to compare, not a crash
                out.append(f"{type(e).__name__}: {e}")
        return out

    def seal(self) -> int:
        """Seal the active segment; the next seq is then a legal prune boundary once ITS segment is sealed."""
        s = self.store()
        s.rotate()
        return s.next_seq

    def seal_with_tail(self, *, checkpoint: bool) -> None:
        """Seal the segment that starts at the coming boundary and leave an unsealed tail, as on a live install.
        `checkpoint` also signs the owner head (a prune needs a valid one)."""
        s = self.store()
        s.rotate()
        for i in range(3):
            s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "tail": i})
        if checkpoint:
            _cp.checkpoint(s)


class _Regs:
    """Every registry over one fresh store handle, built with the explicit owner key."""

    def __init__(self, world: _World) -> None:
        kw = {"owner_key": world.owner, "trusted_pubkey": world.owner.public_key_b64}
        self.memo, self.store = world.memo, world.store()
        s = self.store
        self.kill = ks.KillSwitch(s, **kw)
        self.caps = cap.CapabilityGate(s, **kw)
        self.cust = cu.CustomerRegistry(s, **kw)
        self.orgs = og.OrgRegistry(s, **kw)
        self.wallet = wl.WalletRegistry(s, **kw)
        self.plan = mt.PlanCreditLedger(s, **kw)
        self.subs = sb.SubscriptionRegistry(s, **kw)
        self.msubs = ms.MonitoringSubscriptionRegistry(s, **kw)
        self.meter = mt.CreditMeter(self.wallet, self.plan, self.subs)
        self.accts = acc.AccountsRegistry(s, **kw)
        self.creds = cc.CustomerCredentialRegistry(s, **kw)
        self.inv = inv.InvoiceRegistry(s, **kw)
        self.cost = cl.CostEnvelopeLedger(s, **kw)
        self.pp = pp.PostpaidRegistry(s, **kw)
        self.arr = pp.PostpaidArrearsLedger(s, **kw)
        self.promo = pr.PromotionPolicy(s, **kw)
        self.budget = bd.BudgetLedger(s, CAPS)
        self.own = ao.AssetOwnershipRegistry(s, **kw)
        self.mon = ma.MonitoringAuthorityRegistry(s, **kw)


@dataclasses.dataclass(frozen=True)
class Scenario:
    name: str
    defining: Callable[[Any], bool]               # the records that DEFINE this registry's state
    below: list                                   # ops landing below K1 (pruned by the first prune)
    live: list                                    # ops in the live window of the first prune (below K2)
    after: list                                   # three rounds of ops after the prune ...
    later: list
    latest: list
    reads: Callable[[_Regs], Iterable[tuple]]     # yields `_r(bound_method, *args, **kw)`
    salted: tuple = ()                            # dataclass fields scrubbed for the CONTROL comparison only
    seed_free: bool = False                       # the registry documents that it carries NO seed (budget)


@dataclasses.dataclass(frozen=True)
class _Raised:
    """A read that raised, as a comparable value (so one raising read does not hide the others)."""
    error: str


def _r(fn: Callable, *args, **kw) -> tuple:
    """One read: (a stable key, the callable, its args). A registry / store argument is keyed by its type."""
    def show(v):
        return repr(v) if v is None or isinstance(v, (str, int, float, bool)) else type(v).__name__
    shown = [show(a) for a in args] + [f"{k}={show(v)}" for k, v in kw.items()]
    return (f"{getattr(fn, '__qualname__', repr(fn))}({', '.join(shown)})", fn, args, kw)


def _signal(*names: str) -> Callable[[Any], bool]:
    return lambda r: isinstance(r.payload, dict) and r.payload.get("signal") in names


def _evaluate(regs: _Regs, sc: Scenario) -> dict:
    out = {}
    for key, fn, args, kw in sc.reads(regs):
        try:
            out[key] = fn(*args, **kw)
        except Exception as e:  # noqa: BLE001 — recorded and compared
            out[key] = _Raised(f"{type(e).__name__}: {e}")
    return out


def _answers(world: _World, sc: Scenario, *, flag: bool, keep_cache: bool = False) -> dict:
    """Every read of `sc` on a FRESH handle. Flag ON also re-reads warm and folds any difference into the
    answer (so a warm/cold disagreement surfaces as a mismatch on that key)."""
    if flag:
        world.mp.setenv(FLAG, "1")
    else:
        world.mp.delenv(FLAG, raising=False)
    if not keep_cache:
        fold_cache.clear_all()
    regs = _Regs(world)
    out = _evaluate(regs, sc)
    if flag:
        for k, v in _evaluate(regs, sc).items():
            if v != out[k]:
                out[k] = ("WARM RE-READ DISAGREES", out[k], v)
    world.mp.delenv(FLAG, raising=False)
    return out


def _scrub(v: Any, fields: tuple) -> Any:
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return (type(v).__name__, tuple((f.name, "<salted>" if f.name in fields and getattr(v, f.name) is not None
                                         else _scrub(getattr(v, f.name), fields)) for f in dataclasses.fields(v)))
    if isinstance(v, dict):
        return {k: _scrub(x, fields) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return type(v)(_scrub(x, fields) for x in v)
    return v


def _diff(want: dict, got: dict, want_label: str, got_label: str, fields: tuple = ()) -> list[str]:
    out = []
    for k in want:
        a, b = _scrub(want[k], fields), _scrub(got.get(k, "<missing>"), fields)
        if a != b:
            out.append(f"{k}: {want_label}={a!r} | {got_label}={b!r}")
    return out


def _defining_below(world: _World, sc: Scenario, K: int) -> list[int]:
    return [r.seq for r in world.store().iter_records() if r.seq < K and sc.defining(r)]


def _prune_and_check(world: _World, sc: Scenario, K: int, problems: list[str]) -> None:
    below = _defining_below(world, sc, K)
    if not below:
        problems.append(f"FIXTURE: no defining record of {sc.name} lies below K={K} — the seed is not exercised")
    rep = prune.commit_prune(world.store(), K, confirm=True)
    fresh = world.store()
    live = [r.seq for r in fresh.iter_records()]
    if not live or live[0] != K:
        problems.append(f"live window starts at {live[:1]} after a prune at K={K}")
    problems.extend(f"defining record seq {q} survived the prune at K={K}" for q in below
                    if q in live or fresh.get(q) is not None)
    st = SnapshotState.load(fresh)
    rec = fresh.get(rep["snapshot_seq"])
    if (st.base_seq, st.snapshot_seq) != (K, rep["snapshot_seq"]) or rec is None or rec.kind != "snapshot":
        problems.append(f"SnapshotState.load names ({st.base_seq}, {st.snapshot_seq}); the prune committed "
                        f"({K}, {rep['snapshot_seq']})")


def _pipeline(sc: Scenario, root: Path) -> dict[str, list[str]]:
    """Run `sc` on the control and the pruned spine; return {check: [problem, ...]} (empty list == pass)."""
    res: dict[str, list[str]] = {}
    step = "setup"
    with pytest.MonkeyPatch.context() as mp:
        try:
            _isolate_keys(mp, root / "keys")
            owner = identity.ensure_owner_keypair()
            half = (len(sc.below) + 1) // 2

            # ---- the CONTROL spine: the same ops, never pruned -------------------------------------------
            ctl = _World(root / "control", mp, owner).activate()
            c_out, c_ans = {}, {}
            for stage, ops in (("base", sc.below + sc.live), ("after", sc.after), ("later", sc.later),
                               ("latest", sc.latest)):
                c_out[stage] = ctl.apply(ops)
                c_ans[stage] = _answers(ctl, sc, flag=False)
            bad = [f"{stage} op #{i}: {o}" for stage, outs in c_out.items() for i, o in enumerate(outs) if o != "ok"]

            # ---- the PRUNED spine --------------------------------------------------------------------------
            step = "baseline"
            w = _World(root / "pruned", mp, owner).activate()
            out = w.apply(sc.below[:half])
            w.seal()
            out += w.apply(sc.below[half:])
            k1 = w.seal()
            out += w.apply(sc.live)
            w.seal_with_tail(checkpoint=True)
            pre_off = _answers(w, sc, flag=False)
            pre_on = _answers(w, sc, flag=True)                 # ... and this cache stays warm across the prune
            held = _Regs(w)                                     # a LONG-LIVED handle (a daemon across the prune)
            _evaluate(held, sc)
            res["baseline"] = ([f"FIXTURE: on the never-pruned control, {b}" for b in bad]
                               + ([] if out == c_out["base"] else [f"FIXTURE: op outcomes differ: {out} vs {c_out['base']}"])
                               + _diff(pre_off, pre_on, "OFF", "ON")
                               + _diff(c_ans["base"], pre_off, "control", "pruned-spine-before-prune", sc.salted))

            step = "below_k"
            res["below_k"] = []
            _prune_and_check(w, sc, k1, res["below_k"])

            step = "prune1_on"
            res["prune1_on"] = (_diff(pre_off, _answers(w, sc, flag=True, keep_cache=True), "before", "after[warm]")
                                + _diff(pre_off, _answers(w, sc, flag=True), "before", "after[cold]"))
            mp.setenv(FLAG, "1")
            res["prune1_on"] += _diff(pre_off, _evaluate(held, sc), "before", "after[long-lived handle]")
            mp.delenv(FLAG)
            step = "prune1_off"
            res["prune1_off"] = (_diff(pre_off, _answers(w, sc, flag=False), "before", "after")
                                 + _diff(pre_off, _evaluate(held, sc), "before", "after[long-lived handle]"))

            # The reads have TEETH: a spine holding only the live-window ops (what a fold with an EMPTY seed would
            # see) answers differently — now, or once a pruned grant is replayed — so the equality above is
            # carried by the seed.
            step = "below_k (teeth)"
            amnesia = _World(root / "amnesia", mp, owner).activate()
            amnesia.memo.update(w.memo)
            amnesia.apply(sc.live)
            forgot = _answers(amnesia, sc, flag=False) != pre_off
            amnesia.apply(sc.after)
            if not (forgot or sc.seed_free or _answers(amnesia, sc, flag=False) != c_ans["after"]):
                res["below_k"].append("FIXTURE: the reads do not depend on anything below K (no teeth)")
            w.activate()

            # ---- the spine keeps living: three rounds of ops, each then sealed and re-anchored ----------------
            res["after1_off"], res["after1_on"], res["writes"] = [], [], []
            for stage, ops in (("after", sc.after), ("later", sc.later), ("latest", sc.latest)):
                step = f"after1 ({stage})"
                want = c_ans[stage]
                _answers(w, sc, flag=True)                       # warm, then extended over the new records
                res["writes"] += _diff({stage: c_out[stage]}, {stage: w.apply(ops)}, "control", "pruned")
                on = [("warm", _answers(w, sc, flag=True, keep_cache=True)), ("cold", _answers(w, sc, flag=True))]
                off = [("", _answers(w, sc, flag=False))]
                w.seal()
                _cp.checkpoint(w.store())                        # `sigil sign` / the consolidate pipeline
                ok, why = _cp.verify_checkpoint(w.store())
                if not ok or "(current)" not in why:
                    res["after1_off"].append(f"after the {stage!r} checkpoint: verify_checkpoint -> ({ok}, {why!r})")
                on += [("warm, re-anchored", _answers(w, sc, flag=True, keep_cache=True)),
                       ("cold, re-anchored", _answers(w, sc, flag=True))]
                off += [("re-anchored", _answers(w, sc, flag=False))]
                for check, got in (("after1_off", off), ("after1_on", on)):
                    for label, ans in got:
                        res[check] += _diff(want, ans, f"control@{stage}", f"pruned[{label}]", sc.salted)
        except Exception as e:  # noqa: BLE001 — the step that raised fails; later checks were not reached
            blocked = f"NOT REACHED — {type(e).__name__} during step {step!r}: {e}"
            unfinished = ("after1_off", "after1_on", "writes") if step.startswith("after1") else ()
            for c in CHECKS:
                if c not in res or c in unfinished:
                    res.setdefault(c, []).append(blocked)
        finally:
            fold_cache.clear_all()
    return res


# ======================================================================================================
# the scenarios — small op lists + the registry's public reads
# ======================================================================================================
ORGS = ["acme", "globex", "initech", "nope"]
NOWS = [None, 0.0, 500.0, 1500.0, 2500.0, 1e12]
GOV = {"kind": "event", "source": "governor", "actor": "WARDEN"}
OIDC = "https://accounts.google.com"


def _stash(name: str, op: Callable) -> Callable:
    """Run `op` and keep the payload it appended for a later replay: the seq it returns (alone or last in a
    tuple), else — for an op that returns a dataclass — the newest record."""
    def run(R):
        seq = op(R)
        seq = seq[-1] if isinstance(seq, tuple) else seq
        R.memo[name] = R.store.get(seq if isinstance(seq, int) else R.store.next_seq - 1).payload
    return run


def _replay(name: str) -> Callable:
    """Re-append a captured owner-signed payload verbatim — the anti-replay probe (the seed must carry the
    high-water / consumed entry id that makes it inert)."""
    return lambda R: R.store.append(payload=R.memo[name], **GOV)


def _noise(i: int) -> Callable:
    return lambda R: R.store.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": i})


def _set(name: str, value: Any) -> Callable:
    return lambda R: R.memo.__setitem__(name, value)


def _killswitch_engaged() -> Scenario:
    return Scenario(
        name="killswitch[engaged below K]", defining=_signal(ks.SIGNAL),
        below=[lambda R: R.kill.engage(reason="incident")],
        live=[_noise(1)],
        after=[_stash("rel", lambda R: R.kill.release(issued_at=10.0))],
        later=[lambda R: R.kill.engage(), _replay("rel")],           # a replayed release must not re-open
        latest=[lambda R: R.kill.release(issued_at=5.0),            # stale: below the honored high-water
                lambda R: R.kill.release(issued_at=11.0), lambda R: R.kill.engage()],
        reads=lambda R: [_r(R.kill.is_engaged)])


def _killswitch_released() -> Scenario:
    return Scenario(
        name="killswitch[released below K]", defining=_signal(ks.SIGNAL),
        below=[lambda R: R.kill.engage(), _stash("rel", lambda R: R.kill.release(issued_at=10.0))],
        live=[_noise(1)],
        after=[lambda R: R.kill.engage(), _replay("rel")],          # replay of the PRUNED release: stays engaged
        later=[_stash("rel2", lambda R: R.kill.release(issued_at=20.0))],
        latest=[lambda R: R.kill.engage(), _replay("rel2"), _replay("rel")],
        reads=lambda R: [_r(R.kill.is_engaged)])


def _capability() -> Scenario:
    def reads(R):
        yield _r(R.caps.state_all)
        for c in sorted(cap.CAPABILITIES):
            yield _r(R.caps.is_enabled, c)
            yield _r(R.caps.is_disabled, c)
    return Scenario(
        name="capability", defining=_signal(cap.SIGNAL),
        below=[lambda R: R.caps.disable("voice"), lambda R: R.caps.disable("gesture"),
               _stash("en", lambda R: R.caps.enable("gesture", issued_at=10.0))],
        live=[lambda R: R.caps.disable("autolearn")],
        after=[lambda R: R.caps.disable("gesture"), _replay("en"),   # replay of the pruned enable: stays disabled
               lambda R: R.caps.enable("voice", issued_at=5.0)],
        later=[_stash("en2", lambda R: R.caps.enable("autolearn", issued_at=30.0))],
        latest=[lambda R: R.caps.disable("autolearn"), _replay("en2"),
                lambda R: R.caps.enable("gesture", issued_at=31.0)],
        reads=reads)


def _customers() -> Scenario:
    emails = ["a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com", "x@example.com"]

    def reads(R):
        yield _r(R.cust.customers)
        for u in ["cust_a", "cust_b", "cust_c", "cust_d", "cust_e", "cust_x"]:
            yield _r(R.cust.customer, u)
        for e in emails:
            yield _r(R.cust.by_email, e)
            for pw in ("pw-one-123456", "pw-two-123456"):
                yield _r(R.cust.verify_login, e, pw)
    return Scenario(
        name="customers", defining=_signal(cu.SIGNAL), salted=("password_hash",),
        below=[_stash("a", lambda R: R.cust.create(emails[0], issued_at=1.0, password="pw-one-123456", username="cust_a")),
               lambda R: R.cust.create(emails[1], issued_at=2.0, username="cust_b"),
               _stash("c", lambda R: R.cust.create(emails[2], issued_at=3.0, password="pw-one-123456", username="cust_c")),
               lambda R: R.cust.revoke("cust_c"),
               lambda R: R.cust.set_password("cust_b", "pw-two-123456", issued_at=4.0)],
        live=[lambda R: R.cust.create(emails[3], issued_at=5.0, password="pw-one-123456", username="cust_d")],
        after=[lambda R: R.cust.create(emails[4], issued_at=6.0, username="cust_e"),
               _replay("c"),                                         # the pruned grant of a revoked customer
               lambda R: R.cust.revoke("cust_a"), _replay("a")],
        later=[lambda R: R.cust.set_password("cust_d", "pw-two-123456", issued_at=7.0)],
        latest=[_replay("c"), _replay("a"), lambda R: R.cust.revoke("cust_e"),
                lambda R: R.cust.create(emails[2], issued_at=8.0, password="pw-two-123456", username="cust_c")],
        reads=reads)


def _orgs() -> Scenario:
    users = ["alice", "bob", "carol", "dave", "cust_a"]

    def reads(R):
        yield _r(R.orgs.orgs)
        yield _r(R.orgs.memberships)
        for o in ORGS:
            yield _r(R.orgs.org, o)
            yield _r(R.orgs.memberships, o)
            for u in users:
                yield _r(R.orgs.membership_role, u, o)
                yield _r(R.orgs.org_role_can, u, o, "view_assessments")
                yield _r(R.orgs.admit, global_role=None, username=u, org_id=o, permission="view_assessments")
                yield _r(R.orgs.admit_customer, username=u, org_id=o, permission="view_assessments")
    return Scenario(
        name="orgs+memberships", defining=_signal(og.ORG_SIGNAL, og.MEMBERSHIP_SIGNAL),
        below=[lambda R: R.orgs.create_org("acme", "Acme Corp", owner="alice", issued_at=1.0),
               _stash("globex", lambda R: R.orgs.create_org("globex", "Globex", owner="bob", issued_at=2.0)),
               lambda R: R.orgs.grant_membership("acme", "alice", "org_admin", issued_at=3.0),
               _stash("bob", lambda R: R.orgs.grant_membership("acme", "bob", "viewer", issued_at=4.0)),
               lambda R: R.orgs.revoke_membership("acme", "bob"),
               lambda R: R.orgs.grant_membership("globex", "cust_a", "analyst", issued_at=5.0)],
        live=[lambda R: R.orgs.grant_membership("acme", "carol", "operator", issued_at=6.0)],
        after=[_replay("bob"),                                       # pruned grant of a revoked membership
               lambda R: R.orgs.revoke_org("globex"), _replay("globex"),
               lambda R: R.orgs.grant_membership("acme", "dave", "viewer", issued_at=7.0)],
        later=[lambda R: R.orgs.grant_membership("acme", "alice", "viewer", issued_at=8.0),
              lambda R: R.orgs.create_org("initech", "Initech", owner="carol", issued_at=9.0)],
        latest=[_replay("bob"), _replay("globex"), lambda R: R.orgs.revoke_membership("acme", "carol"),
                lambda R: R.orgs.grant_membership("initech", "bob", "org_admin", issued_at=10.0)],
        reads=reads)


def _wallet() -> Scenario:
    def reads(R):
        yield _r(R.wallet.balances)
        for o in ORGS:
            yield _r(R.wallet.balance, o)
            yield _r(R.wallet.available, o)
    return Scenario(
        name="wallet", defining=_signal(wl.CREDIT_GRANT_SIGNAL, wl.CREDIT_DEBIT_SIGNAL),
        below=[_stash("g1", lambda R: R.wallet.grant("acme", 100, "trial", entry_id="g1", issued_at=1.0)),
               _stash("d1", lambda R: R.wallet.debit("acme", 30, entry_id="d1", issued_at=2.0)),
               lambda R: R.wallet.grant("globex", 50, "topup", entry_id="g2", issued_at=3.0),
               lambda R: R.wallet.debit("globex", 50, entry_id="d2", issued_at=4.0)],
        live=[lambda R: R.wallet.debit("acme", 10, entry_id="d3", issued_at=5.0)],
        after=[_replay("g1"), _replay("d1"),                         # consumed entry ids: neither re-counts
               lambda R: R.wallet.grant("acme", 100, "trial", entry_id="g1", issued_at=6.0),   # same id, re-signed
               lambda R: R.wallet.grant("initech", 7, "refund", entry_id="g3", issued_at=7.0),
               lambda R: R.wallet.debit("acme", 5, entry_id="d4", issued_at=8.0)],
        later=[lambda R: R.wallet.grant("acme", 20, "topup", entry_id="g4", issued_at=9.0)],
        latest=[_replay("g1"), lambda R: R.wallet.debit("acme", 30, entry_id="d1", issued_at=10.0),
                lambda R: R.wallet.debit("acme", 1, entry_id="d5", issued_at=11.0),
                lambda R: R.wallet.grant("globex", 3, "topup", entry_id="g5", issued_at=12.0)],
        reads=reads)


def _plan_ops() -> dict:
    return dict(
        below=[lambda R: R.subs.subscribe("acme", "pro", 100, period_start=0.0, period_end=1000.0, issued_at=1.0),
               lambda R: R.plan.grant("acme", 100, period_end=1000.0, entry_id="refill-1", issued_at=2.0),
               lambda R: R.plan.debit("acme", 40, period_end=1000.0, entry_id="r0", issued_at=3.0),
               lambda R: R.subs.subscribe("acme", "pro", 100, period_start=1000.0, period_end=2000.0, issued_at=4.0),
               _stash("refill-2", lambda R: R.plan.grant("acme", 100, period_end=2000.0, entry_id="refill-2", issued_at=5.0)),
               _stash("r1", lambda R: R.plan.debit("acme", 30, period_end=2000.0, entry_id="r1", issued_at=6.0)),
               lambda R: R.wallet.grant("acme", 11, "topup", entry_id="w1", issued_at=7.0),
               lambda R: R.plan.grant("globex", 9, period_end=2000.0, entry_id="refill-g", issued_at=8.0)],
        live=[lambda R: R.plan.debit("acme", 10, period_end=2000.0, entry_id="r2", issued_at=9.0)],
        after=[_replay("refill-2"), _replay("r1"),                   # consumed entry ids: neither re-counts
               lambda R: R.plan.debit("acme", 5, period_end=2000.0, entry_id="r3", issued_at=10.0),
               # the consumed id `r0`, re-signed for ANOTHER period: inert (the seen-set is seeded)
               lambda R: R.plan.debit("acme", 3, period_end=3000.0, entry_id="r0", issued_at=10.5),
               lambda R: R.plan.grant("acme", 5, period_end=2000.0, entry_id="refund-r1", issued_at=11.0)],
        later=[lambda R: R.subs.subscribe("acme", "pro", 200, period_start=2000.0, period_end=3000.0, issued_at=12.0),
              lambda R: R.plan.grant("acme", 200, period_end=3000.0, entry_id="refill-3", issued_at=13.0),
              lambda R: R.plan.debit("acme", 20, period_end=3000.0, entry_id="r4", issued_at=14.0)],
        latest=[_replay("refill-2"), _replay("r1"),
                lambda R: R.plan.debit("acme", 7, period_end=3000.0, entry_id="r5", issued_at=15.0),
                lambda R: R.plan.debit("globex", 4, period_end=2000.0, entry_id="r6", issued_at=16.0)])


def _plan_and_meter() -> Scenario:
    def reads(R):
        for o in ORGS:
            yield _r(R.plan.tranches, o)
            for pe in (1000.0, 2000.0, 3000.0, 0.0):
                yield _r(R.plan.remaining_for_period, o, pe)
            for now in NOWS:
                yield _r(R.plan.available, o, now)
                yield _r(R.meter.available, o, now)
                yield _r(R.meter.position, o, now)
    return Scenario(name="plan-credit ledger + CreditMeter", reads=reads,
                    defining=_signal(mt.PLAN_GRANT_SIGNAL, mt.PLAN_DEBIT_SIGNAL), **_plan_ops())


def _subscription(reg: str, signal: str, plan_id: str, label: str) -> Scenario:
    def sub(R):
        return getattr(R, reg)

    def reads(R):
        yield _r(sub(R).subscriptions)
        for o in ORGS:
            yield _r(sub(R).subscription, o)
            for now in NOWS:
                yield _r(sub(R).active_subscription, o, now)
    return Scenario(
        name=label, defining=_signal(signal),
        below=[lambda R: sub(R).subscribe("acme", plan_id, 100, period_start=0.0, period_end=1000.0, issued_at=1.0),
               _stash("globex", lambda R: sub(R).subscribe("globex", plan_id, 50, period_start=0.0, period_end=2000.0, issued_at=2.0)),
               lambda R: sub(R).cancel("globex"),
               _stash("initech", lambda R: sub(R).subscribe("initech", plan_id, 10, period_start=0.0, period_end=2000.0, issued_at=3.0)),
               lambda R: sub(R).mark_past_due("initech", issued_at=4.0)],
        live=[lambda R: sub(R).subscribe("acme", plan_id, 100, period_start=1000.0, period_end=2000.0, issued_at=5.0)],
        after=[_replay("globex"), _replay("initech"),                # stale activations of down lines
               lambda R: sub(R).mark_past_due("acme", issued_at=4.5),   # OLDER than the live activation: ignored
               lambda R: sub(R).subscribe("initech", plan_id, 10, period_start=1000.0, period_end=3000.0, issued_at=6.0)],
        later=[lambda R: sub(R).subscribe("acme", plan_id, 300, period_start=2000.0, period_end=3000.0, issued_at=7.0),
              lambda R: sub(R).mark_past_due("initech")],
        latest=[_replay("globex"), _replay("initech"), lambda R: sub(R).cancel("acme"),
                lambda R: sub(R).subscribe("globex", plan_id, 5, period_start=2000.0, period_end=3000.0, issued_at=8.0)],
        reads=reads)


def _accounts() -> Scenario:
    toks = {u: f"tok-{u}-" + "z" * 24 for u in ("alice", "bob", "carol", "dave", "erin")}

    def reads(R):
        yield _r(R.accts.accounts)
        for u in list(toks) + ["nobody"]:
            for now in (None, 50.0, 1e12):
                yield _r(R.accts.account, u, now=now)
        for t in toks.values():
            for now in (None, 50.0, 1e12):
                yield _r(R.accts.resolve, t, now=now)
    return Scenario(
        name="accounts", defining=_signal(acc.SIGNAL), salted=("cred_hash", "cred_salt", "password_hash"),
        below=[lambda R: R.accts.create("alice", "operator", bearer_token=toks["alice"], issued_at=1.0),
               _stash("bob", lambda R: R.accts.create("bob", "viewer", bearer_token=toks["bob"], issued_at=2.0)),
               lambda R: R.accts.revoke("bob"),
               lambda R: R.accts.enroll_totp("alice", "c2VhbGVk", issued_at=3.0),
               lambda R: R.accts.set_password("alice", "operator-pw-1", issued_at=4.0),
               lambda R: R.accts.create("carol", "analyst", bearer_token=toks["carol"], issued_at=5.0, ttl_seconds=100.0),
               lambda R: R.accts.assign_role("carol", "viewer", issued_at=6.0)],
        live=[lambda R: R.accts.create("dave", "viewer", bearer_token=toks["dave"], issued_at=7.0)],
        after=[_replay("bob"),                                       # pruned grant of a revoked account
               lambda R: R.accts.assign_role("alice", "analyst", issued_at=8.0),
               lambda R: R.accts.create("erin", "operator", bearer_token=toks["erin"], issued_at=9.0)],
        later=[lambda R: R.accts.disable_totp("alice", issued_at=10.0), lambda R: R.accts.revoke("dave")],
        latest=[_replay("bob"), lambda R: R.accts.assign_role("erin", "viewer", issued_at=11.0),
                lambda R: R.accts.create("bob", "viewer", bearer_token=toks["bob"], issued_at=12.0)],
        reads=reads)


def _customer_credentials() -> Scenario:
    pk = dict(cose_alg=-7, public_key_spki_b64="cGs=", uv=True)

    def reads(R):
        for u in ("cust_a", "cust_b", "cust_c", "cust_d"):
            yield _r(R.creds.for_user, u)
            yield _r(R.creds.totp_for, u)
        for cid in ("cidA", "cidB", "cidC", "cidD"):
            yield _r(R.creds.by_credential_id, cid)
        for sub in ("g1", "g2", "g3"):
            yield _r(R.creds.by_federated, OIDC, sub)
    return Scenario(
        name="customer credentials", defining=_signal(cc.SIGNAL),
        below=[lambda R: R.creds.enroll_passkey("cust_a", "cidA", issued_at=1.0, **pk),
               lambda R: R.creds.enroll_totp("cust_a", sealed_secret="c2VhbGVk", issued_at=2.0),
               _stash("oidc", lambda R: R.creds.link_federated("cust_b", iss=OIDC, sub="g1", issued_at=3.0)),
               lambda R: R.creds.revoke("cust_b", cc._CRED_KEY_OIDC),
               lambda R: R.creds.link_federated("cust_c", iss=OIDC, sub="g2", issued_at=4.0)],
        live=[lambda R: R.creds.enroll_passkey("cust_c", "cidC", issued_at=5.0, **pk)],
        after=[_replay("oidc"),                                      # pruned link of a revoked credential
               lambda R: R.creds.enroll_passkey("cust_b", "cidB", issued_at=6.0, **pk),
               lambda R: R.creds.revoke("cust_a", cc._CRED_KEY_TOTP)],
        later=[lambda R: R.creds.link_federated("cust_d", iss=OIDC, sub="g3", issued_at=7.0),
              lambda R: R.creds.revoke("cust_a", "cidA")],
        latest=[_replay("oidc"), lambda R: R.creds.enroll_passkey("cust_d", "cidD", issued_at=8.0, **pk),
                lambda R: R.creds.enroll_totp("cust_a", sealed_secret="c2VhbGVkMg==", issued_at=9.0)],
        reads=reads)


def _invoice(R, org, iid, kind, amount, at, **kw):
    return R.inv.record(org, invoice_id=iid, kind=kind, price_id="pro", amount_minor=amount, currency="usd",
                        issued_at=at, **kw)


def _invoices() -> Scenario:
    def reads(R):
        yield _r(R.inv.all_invoices)
        for o in ORGS:
            yield _r(R.inv.invoices, o)
    return Scenario(
        name="invoices", defining=_signal(inv.INVOICE_SIGNAL),
        below=[_stash("i1", lambda R: _invoice(R, "acme", "i1", "subscription", 9900, 1.0, credits=100, period_end=1000.0)),
               lambda R: _invoice(R, "acme", "i2", "topup", 500, 2.0, credits=5),
               lambda R: _invoice(R, "globex", "i1", "subscription", 4900, 3.0, credits=50, period_end=1000.0)],
        live=[lambda R: _invoice(R, "acme", "i3", "subscription", 9900, 4.0, credits=100, period_start=1000.0, period_end=2000.0)],
        after=[_replay("i1"), lambda R: _invoice(R, "acme", "i1", "topup", 1, 5.0),   # same id: append-only, inert
               lambda R: _invoice(R, "initech", "i9", "topup", 700, 6.0, credits=7)],
        later=[lambda R: _invoice(R, "globex", "i4", "topup", 300, 7.0, credits=3)],
        latest=[_replay("i1"), lambda R: _invoice(R, "acme", "i5", "payment", 9900, 8.0)],
        reads=reads)


def _cost_ops() -> dict:
    res, stl = cl.RESERVE_COST_PREFIX, cl.SETTLE_COST_PREFIX
    return dict(
        below=[_stash("res1", lambda R: R.cost.reserve("acme", 900, entry_id=res + "s:1", issued_at=100.0)),
               _stash("stl1", lambda R: R.cost.settle("acme", 400, entry_id=stl + "s:1", issued_at=200.0)),
               lambda R: R.cost.reserve("globex", 300, entry_id=res + "s:2", issued_at=300.0),
               lambda R: R.cost.settle("globex", 300, entry_id=stl + "s:2", reserved_cap=300, issued_at=400.0)],
        live=[lambda R: R.cost.reserve("acme", 500, entry_id=res + "s:3", issued_at=1100.0)],      # in flight
        after=[_replay("res1"), _replay("stl1"),                     # consumed entry ids: neither re-counts
               lambda R: R.cost.settle("acme", 450, entry_id=stl + "s:3", issued_at=1200.0),
               lambda R: R.cost.reserve("initech", 70, entry_id=res + "s:4", issued_at=1300.0),
               lambda R: R.cost.settle("initech", 60, entry_id=stl + "s:4", issued_at=1400.0)],
        later=[lambda R: R.cost.reserve("globex", 200, entry_id=res + "s:5", issued_at=2100.0)],    # in flight
        latest=[_replay("res1"), _replay("stl1"),
                lambda R: R.cost.settle("globex", 150, entry_id=stl + "s:5", issued_at=2200.0),
                lambda R: R.cost.reserve("acme", 80, entry_id=res + "s:6", issued_at=2300.0)])


def _cost_ledger() -> Scenario:
    def reads(R):
        yield _r(R.cost.tenant_costs)
        yield _r(R.cost.global_position)
        for o in ORGS:
            yield _r(R.cost.committed_cost, o)
            yield _r(R.cost.in_flight_envelope, o)
            yield _r(R.cost.reserved_total, o)
            yield _r(R.cost.tenant_cost, o)
            for n in range(1, 7):
                yield _r(R.cost.was_reserved, o, f"{cl.RESERVE_COST_PREFIX}s:{n}")
    return Scenario(name="cost envelope ledger (+ global position)", reads=reads,
                    defining=_signal(cl.COST_RESERVE_SIGNAL, cl.COST_SETTLE_SIGNAL), **_cost_ops())


def _postpaid() -> Scenario:
    res, stl = pp.RESERVE_ENTRY_PREFIX, pp.SETTLE_ENTRY_PREFIX

    def reads(R):
        yield _r(R.pp.accounts)
        for o in ORGS:
            yield _r(R.pp.account, o)
            yield _r(R.pp.is_postpaid, o)
            yield _r(R.arr.accrued, o)
            yield _r(R.arr.in_flight_reserved, o)
            yield _r(R.arr.net_settled_consumed, o)
            yield _r(pp.invoiced_postpaid_total, R.inv, o)
            yield _r(pp.paid_postpaid_total, R.inv, o)
            yield _r(pp.postpaid_outstanding, R.inv, o)
            for now in (0.0, 5000.0, 1e9):
                yield _r(pp.postpaid_overdue_amount, R.inv, R.pp, o, now)
                yield _r(pp.postpaid_is_overdue, R.inv, R.pp, o, now)
            for eid in [res + f"s:{n}" for n in range(1, 6)] + ["direct-1"]:
                yield _r(R.arr.was_accrued, o, eid)

    def bill(org, period_end, at):
        return lambda R: pp.invoice_postpaid_arrears(R.pp, R.arr, R.inv, org, period_end=period_end, issued_at=at)

    def pay_first(org, at):
        def run(R):
            billed = [i.invoice_id for i in R.inv.invoices(org) if i.kind == "postpaid"]
            return pp.pay_postpaid_invoice(R.inv, org, billed[0], issued_at=at)
        return run
    return Scenario(
        name="postpaid accounts + arrears",
        defining=_signal(pp.POSTPAID_SIGNAL, pp.POSTPAID_DEBIT_SIGNAL, pp.POSTPAID_CREDIT_SIGNAL),
        below=[lambda R: R.pp.set_account("acme", 500, 30, issued_at=1.0),
               _stash("globex", lambda R: R.pp.set_account("globex", 100, 15, issued_at=2.0)),
               lambda R: R.pp.disable("globex"),
               _stash("acc1", lambda R: R.arr.accrue("acme", 60, entry_id=res + "s:1", issued_at=3.0)),
               _stash("set1", lambda R: R.arr.settle("acme", 20, entry_id=stl + "s:1", issued_at=4.0)),
               lambda R: R.arr.accrue("acme", 15, entry_id="direct-1", issued_at=5.0),
               bill("acme", 1000.0, 6.0)],
        live=[lambda R: R.arr.accrue("acme", 30, entry_id=res + "s:2", issued_at=7.0)],            # in flight
        after=[_replay("globex"), _replay("acc1"), _replay("set1"),
               lambda R: R.arr.settle("acme", 10, entry_id=stl + "s:2", issued_at=8.0),
               bill("acme", 2000.0, 9.0), pay_first("acme", 10.0),
               lambda R: R.pp.set_account("initech", 50, 0, issued_at=11.0)],
        later=[lambda R: R.arr.accrue("initech", 25, entry_id=res + "s:3", issued_at=12.0),          # in flight
              lambda R: R.pp.set_account("acme", 900, 15, issued_at=13.0)],
        latest=[_replay("globex"), _replay("acc1"),
                lambda R: R.arr.settle("initech", 0, entry_id=stl + "s:3", issued_at=14.0),
                bill("initech", 3000.0, 15.0), lambda R: R.pp.disable("acme", issued_at=16.0)],
        reads=reads)


def _promotion() -> Scenario:
    def reads(R):
        yield _r(R.promo.state_all)
        for a in ("ALPHA", "BRAVO", "ENVOY", "OTHER"):
            for s in ("*", "event", "action"):
                yield _r(R.promo.is_promoted, a, s)
    return Scenario(
        name="promotion", defining=_signal(pr.SIGNAL),
        below=[lambda R: R.promo.grant("ALPHA", "*", issued_at=1.0),
               _stash("bravo", lambda R: R.promo.grant("BRAVO", "event", issued_at=2.0)),
               lambda R: R.promo.revoke("BRAVO", "event")],
        live=[lambda R: R.promo.grant("ENVOY", "action", issued_at=3.0)],
        after=[_replay("bravo"), lambda R: R.promo.revoke("ALPHA", "*"),
               lambda R: R.promo.grant("BRAVO", "action", issued_at=1.5)],
        later=[_stash("alpha2", lambda R: R.promo.grant("ALPHA", "*", issued_at=4.0)),
              lambda R: R.promo.revoke("ENVOY", "action")],
        latest=[_replay("bravo"), lambda R: R.promo.revoke("ALPHA", "*"), _replay("alpha2"),
                lambda R: R.promo.grant("ENVOY", "action", issued_at=5.0)],
        reads=reads)


def _act(agent: str, day: str, hour: int, decision: str = "auto", kind: str = "event", usage: Optional[dict] = None):
    payload = {"decision": decision, **({"usage": usage} if usage is not None else {})}
    return lambda R: R.store.append(kind=kind, source="agent", actor=agent, payload=payload,
                                    ts=f"{day}T{hour:02d}:00:00Z")


def _budget_current_day() -> Scenario:
    """The ENFORCED read: `over_budget` only ever asks for the CURRENT UTC day. The records below K carry an
    earlier day than every later phase, as `spent` documents ("every pruned record bears a `ts` strictly BEFORE
    today"). `memo['today']` moves with the phases."""
    d1, d2, d3, d4, d5 = (f"2026-11-0{n}" for n in range(1, 6))
    u = {"input_tokens": 5, "output_tokens": 7, "cost_usd": 0.01}

    def reads(R):
        for a in ("ALPHA", "BRAVO", "OTHER"):
            yield _r(R.budget.spent, a, R.memo["today"])
            yield _r(R.budget.over_budget, a, R.memo["today"])
        yield _r(R.budget.report, R.memo["today"])
    return Scenario(
        name="budget[current day]", defining=lambda r: r.source == "agent", seed_free=True,
        below=[_act("ALPHA", d1, 1, usage=u), _act("ALPHA", d1, 2, usage=u), _act("ALPHA", d1, 3, kind="draft"),
               _act("BRAVO", d1, 4, decision="denied")],
        live=[_act("ALPHA", d2, 1, usage=u), _act("BRAVO", d2, 2, decision="queued", usage=u), _set("today", d2)],
        after=[_act("ALPHA", d3, 1, usage=u), _act("ALPHA", d3, 2, usage=u), _set("today", d3)],
        later=[_act("ALPHA", d4, 1, usage=u), _act("BRAVO", d4, 2, kind="draft"), _set("today", d4)],
        latest=[_act("ALPHA", d4, 3, usage=u), _act("ALPHA", d4, 4, usage=u), _act("BRAVO", d5, 1), _set("today", d4)],
        reads=reads)


def _prove(org: str, host: str, tok: str, at: float, ttl: float = 1e9) -> list:
    return [lambda R: R.own.issue_challenge(org, host, issued_at=at, token=tok),
            lambda R: R.own.verify_and_record(org, host, method=ao.METHOD_DNS_TXT,
                                              observed=[ao.expected_marker(tok)], now=at + 0.5, ttl_seconds=ttl)]


HOSTS = ["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"]
OWN_NOWS = [0.0, 50.0, 400.0, 1e6, 1e10]


def _ownership_reads(R):
    for o in ("acme", "globex", "nope"):
        for now in OWN_NOWS:
            yield _r(R.own.proven_hosts, o, now=now)
        for h in HOSTS:
            yield _r(R.own.proof, o, h)
            for now in OWN_NOWS:
                yield _r(R.own.has_current_proof, o, h, now=now)


def _asset_ownership() -> Scenario:
    def stash_proof(name, org, host, tok, at):
        challenge, prove = _prove(org, host, tok, at)
        return [challenge, _stash(name, prove)]
    return Scenario(
        name="asset ownership proofs", defining=_signal(ao.PROOF_SIGNAL),
        below=[*_prove("acme", HOSTS[0], "tok-a", 1.0), *_prove("acme", HOSTS[1], "tok-b", 2.0, ttl=100.0),
               *stash_proof("globex-a", "globex", HOSTS[0], "tok-ga", 3.0),
               lambda R: R.own.revoke_proof("globex", HOSTS[0])],
        live=[*_prove("acme", HOSTS[2], "tok-c", 4.0)],
        after=[_replay("globex-a"),                                  # pruned proof of a revoked pair
               *_prove("globex", HOSTS[3], "tok-gd", 5.0), lambda R: R.own.revoke_proof("acme", HOSTS[2])],
        later=[*_prove("acme", HOSTS[4], "tok-e", 6.0), *_prove("acme", HOSTS[1], "tok-b2", 7.0)],
        latest=[_replay("globex-a"), lambda R: R.own.revoke_proof("acme", HOSTS[0]),
                *_prove("globex", HOSTS[0], "tok-ga2", 8.0)],
        reads=_ownership_reads)


def _ownership_challenge_live_window() -> Scenario:
    """`challenge()` reads an UNSEEDED `live_window=True` fold. Its challenges are issued in the live window
    (never below K), so the strict question is whether the live-window fold answers the same across the two
    phases of the prune and with the cache ON / OFF. Proofs below K make the prune carry real state."""
    def reads(R):
        for o in ("acme", "globex"):
            for h in HOSTS:
                yield _r(R.own.challenge, o, h)
            yield _r(R.own.assets_overview, o, now=50.0)

    def challenge(org, host, tok, at):
        return lambda R: R.own.issue_challenge(org, host, issued_at=at, token=tok)

    def reissue(R):
        """Re-issue every outstanding challenge (the documented remedy for one a prune would drop: 'a pruned
        challenge is re-requested'), so the challenges the reads ask about sit in the live window."""
        for o in ("acme", "globex"):
            for h in HOSTS:
                ch = R.own.challenge(o, h)
                if ch is not None:
                    R.own.issue_challenge(o, h, issued_at=ch.issued_at + 100.0, token=ch.token + "+")
    return Scenario(
        name="asset ownership: challenge() [live_window fold]", defining=_signal(ao.PROOF_SIGNAL),
        below=[*_prove("acme", HOSTS[0], "tok-a", 1.0), *_prove("globex", HOSTS[0], "tok-ga", 2.0)],
        live=[reissue, challenge("acme", HOSTS[1], "tok-b", 3.0), challenge("globex", HOSTS[2], "tok-gc", 4.0)],
        after=[challenge("acme", HOSTS[3], "tok-d", 5.0), *_prove("globex", HOSTS[4], "tok-ge", 5.5),
               lambda R: R.store.append(payload={"signal": ao.CHALLENGE_SIGNAL, "org_id": "globex", "host": HOSTS[2],
                                                 "state": "revoked"}, **GOV)],
        later=[reissue, challenge("globex", HOSTS[4], "tok-ge", 600.0)],
        latest=[challenge("acme", HOSTS[2], "tok-c", 700.0)],
        reads=reads)


def _monitoring_authority() -> Scenario:
    def grant(org, host, at, mode=ma.MODE_OBSERVE, na=5000.0):
        return lambda R: R.mon.grant(org, host, mode=mode, not_before=0.0, not_after=na, now=at, issued_at=at)

    def reads(R):
        yield from _ownership_reads(R)
        for o in ("acme", "globex", "nope"):
            yield _r(R.mon.grants, o)
            for h in HOSTS:
                yield _r(R.mon.grant_for, o, h)
                for now in OWN_NOWS:
                    yield _r(R.mon.active_at, o, h, now=now)
                    yield _r(R.mon.owned_at, o, h, now=now)
    return Scenario(
        name="monitoring authority", defining=_signal(ma.SIGNAL),
        below=[*_prove("acme", HOSTS[0], "tok-a", 1.0), *_prove("acme", HOSTS[1], "tok-b", 2.0),
               *_prove("globex", HOSTS[0], "tok-ga", 3.0),
               grant("acme", HOSTS[0], 10.0), _stash("acme-b", grant("acme", HOSTS[1], 11.0)),
               lambda R: R.mon.revoke("acme", HOSTS[1]), grant("globex", HOSTS[0], 12.0, mode=ma.MODE_BLOCK, na=300.0)],
        live=[*_prove("acme", HOSTS[2], "tok-c", 13.0)],
        after=[_replay("acme-b"),                                    # pruned grant of a revoked pair
               grant("acme", HOSTS[2], 14.0), lambda R: R.own.revoke_proof("globex", HOSTS[0])],   # cascades
        later=[grant("acme", HOSTS[1], 15.0, mode=ma.MODE_BLOCK), lambda R: R.mon.revoke("acme", HOSTS[0])],
        latest=[_replay("acme-b"), lambda R: R.mon.revoke_org("acme"), grant("acme", HOSTS[2], 16.0)],
        reads=reads)


def _finding(org: str, host: str, ref: str) -> Callable:
    cert = {"engagement_slug": _customer_slug(org, host), "finding_ref": ref, "bug_class": "xss", "severity": "high",
            "title": f"finding {ref}", "summary": "s", "confidence": 0.9}
    return lambda R: R.store.append(kind="finding", source="inbound", actor="RECEIVER",
                                    payload={"certificate": cert, "finding_ref": ref})


def _outcome(org: str, host: str, nonce: str) -> Callable:
    return lambda R: R.store.append(kind="assessment_outcome", source="inbound", actor="RECEIVER",
                                    payload={"engagement_slug": _customer_slug(org, host), "outcome": "completed",
                                             "nonce": nonce, "ts": 1.0})


def _ui_assessments_live_window() -> Scenario:
    """The assessment projections read an UNSEEDED `live_window=True` fold. Every finding / outcome here is
    written in the live window, while the ownership proofs that scope them ARE below K (seeded). `memo['orgs']`
    names the orgs a phase's reads ask about."""
    def reads(R):
        for o in R.memo.get("orgs", ("acme", "globex")):
            yield _r(ui_assess.assessment_findings, R.store, o, now=50.0)
            yield _r(ui_assess.assessment_outcomes, R.store, o, now=50.0)
            yield _r(ui_assess.assessment_summary, R.store, o, now=50.0)
    return Scenario(
        name="ui.assessments [live_window fold], rows in the live window", defining=_signal(ao.PROOF_SIGNAL),
        below=[*_prove("acme", HOSTS[0], "tok-a", 1.0), *_prove("globex", HOSTS[1], "tok-gb", 2.0)],
        live=[_finding("acme", HOSTS[0], "F-1"), _finding("globex", HOSTS[1], "F-2"), _outcome("acme", HOSTS[0], "n1")],
        after=[_finding("acme", HOSTS[0], "F-3"), _outcome("globex", HOSTS[1], "n2"),
               *_prove("initech", HOSTS[3], "tok-id", 2.5)],
        later=[_set("orgs", ("initech",)), _finding("initech", HOSTS[3], "F-4"), _outcome("initech", HOSTS[3], "n3")],
        latest=[_finding("initech", HOSTS[3], "F-5"), _outcome("initech", HOSTS[3], "n4")],
        reads=reads)


def _ui_margin() -> Scenario:
    """`margin_overview` (the operator margin page) reads the invoices + cost-ledger folds and its own seeded
    settle-event fold. `periods` is compared separately in `test_margin_periods_...`: its docstring declares that
    a pruned settle moves into the `unscoped` bucket."""
    def overview(store):
        out = ui_margin.margin_overview(store, cost_rate=2_000_000, target_margin=None)
        for t in out.get("tenants", []):
            t["period_tokens_total"] = sum(p.get("committed_tokens", 0) for p in t.pop("periods", []))
        return out

    def reads(R):
        yield _r(overview, R.store)
    ops = _cost_ops()
    return Scenario(
        name="ui.margin overview (tenant totals)", reads=reads,
        defining=_signal(cl.COST_SETTLE_SIGNAL, inv.INVOICE_SIGNAL),
        below=ops["below"] + [lambda R: R.orgs.create_org("acme", "Acme Corp", owner="alice", issued_at=1.0),
                              lambda R: _invoice(R, "acme", "i1", "subscription", 9900, 150.0, period_end=1000.0),
                              lambda R: _invoice(R, "globex", "i2", "topup", 500, 350.0)],
        live=ops["live"] + [lambda R: _invoice(R, "acme", "i3", "subscription", 9900, 1150.0, period_start=1000.0,
                                               period_end=2000.0)],
        after=ops["after"] + [lambda R: _invoice(R, "acme", "i4", "payment", 9900, 1250.0)],
        later=ops["later"] + [lambda R: _invoice(R, "globex", "i5", "subscription", 4900, 2150.0, period_start=2000.0,
                                               period_end=3000.0)],
        latest=ops["latest"])


SCENARIOS: dict[str, Callable[[], Scenario]] = {
    "killswitch_engaged": _killswitch_engaged,
    "killswitch_released": _killswitch_released,
    "capability": _capability,
    "customers": _customers,
    "orgs": _orgs,
    "wallet": _wallet,
    "plan_and_meter": _plan_and_meter,
    "subscription": lambda: _subscription("subs", sb.SUBSCRIPTION_SIGNAL, "pro", "subscription"),
    "monitoring_subscription": lambda: _subscription("msubs", ms.MONITORING_SUBSCRIPTION_SIGNAL, "aegis_observe_1h",
                                                     "monitoring subscription"),
    "accounts": _accounts,
    "customer_credentials": _customer_credentials,
    "invoices": _invoices,
    "cost_ledger": _cost_ledger,
    "postpaid": _postpaid,
    "promotion": _promotion,
    "budget_current_day": _budget_current_day,
    "asset_ownership": _asset_ownership,
    "ownership_challenge_live_window": _ownership_challenge_live_window,
    "monitoring_authority": _monitoring_authority,
    "ui_assessments_live_window": _ui_assessments_live_window,
    "ui_margin": _ui_margin,
}
_RESULTS: dict[str, dict] = {}


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_reads_survive_real_prunes(name, check, tmp_path_factory):
    if name not in _RESULTS:                                  # one pipeline run per scenario, shared by its checks
        _RESULTS[name] = _pipeline(SCENARIOS[name](), tmp_path_factory.mktemp(name))
    problems = _RESULTS[name][check]
    assert not problems, f"{SCENARIOS[name]().name} / {check}: {len(problems)} problem(s)\n  " + "\n  ".join(problems)


# ======================================================================================================
# the snapshot boundary itself
# ======================================================================================================
@pytest.fixture
def world(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path / "keys")
    yield _World(tmp_path / "spine", monkeypatch, identity.ensure_owner_keypair()).activate()
    fold_cache.clear_all()


def _both_flags(world: _World, read: Callable[[_Regs], Any]) -> dict:
    """{'OFF': ..., 'ON': ...} of one read on fresh handles (a raise is captured as `_Raised`)."""
    sc = Scenario(name="adhoc", defining=lambda r: False, below=[], live=[], after=[], later=[], latest=[],
                  reads=lambda R: [("read", read, (R,), {})])
    return {"OFF": _answers(world, sc, flag=False)["read"], "ON": _answers(world, sc, flag=True)["read"]}


def _pruned_killswitch_world(world: _World) -> int:
    """engage + a wallet grant below K, a sealed live segment, an owner-signed head, a REAL prune. Returns K."""
    world.apply([lambda R: R.kill.engage(reason="incident"),
                 lambda R: R.wallet.grant("acme", 100, "trial", entry_id="g1", issued_at=1.0)])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1), _noise(2)])
    world.seal_with_tail(checkpoint=True)
    prune.commit_prune(world.store(), k, confirm=True)
    return k


def test_snapshot_load_names_the_real_boundary_after_a_real_prune(world):
    """The state a real prune persists carries the placeholder `snapshot_seq=-1` (it is built before its own
    record is appended); `load` must accept it and hand the folds the head-verified boundary."""
    world.apply([lambda R: R.kill.engage()])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1)])
    world.seal_with_tail(checkpoint=True)
    rep = prune.commit_prune(world.store(), k, confirm=True)
    fresh = world.store()
    rec = fresh.get(rep["snapshot_seq"])
    assert rec is not None and rec.kind == "snapshot" and rec.seq == rep["snapshot_seq"] >= k
    assert rec.payload["folded_state"]["snapshot_seq"] == -1 and rec.payload["folded_state"]["base_seq"] == k
    st = SnapshotState.load(fresh)
    assert (st.base_seq, st.snapshot_seq) == (k, rec.seq)
    assert st.killswitch_engaged is True
    assert [r.seq for r in fresh.iter_records()][0] == k


def _commit_with_folded(world: _World, k: int, mutate: Callable[[dict, int], dict]) -> int:
    """The real cutover up to the owner-signed head (as `test_finish_prune_rolls_forward_after_head_commit`
    drives it), with the snapshot record's folded state passed through `mutate(folded, its_own_seq)` BEFORE it is
    appended — so the chain, the archive and the owner signature are all genuine and only the folded state's
    self-description differs. (Editing the record on disk instead would break the hash chain `load` verifies
    through `verify_checkpoint`, and prove nothing about this check.)"""
    s = world.store()
    payload = prune.snapshot_payload(s, k)
    payload["folded_state"] = mutate(dict(payload["folded_state"]), s.next_seq)
    prune.archive_copy(s, k, payload)
    seq = prune._append_snapshot_idempotent(s, payload)
    _cp.sign_pruned_head(s, base_seq=k, base_prev_hash=payload["base_prev_hash"],
                         cumulative_merkle_root=payload["cumulative_merkle_root"], snapshot_seq=seq)
    world.store().finish_prune()
    return seq


@pytest.mark.parametrize("label,mutate,accepted", [
    ("the placeholder -1 (what a real prune writes)", lambda f, seq: f, True),
    ("its own real seq, were a writer to stamp it", lambda f, seq: {**f, "snapshot_seq": seq}, True),
    ("another snapshot record's seq", lambda f, seq: {**f, "snapshot_seq": seq + 1}, False),
    ("seq 0", lambda f, seq: {**f, "snapshot_seq": 0}, False),
    ("a lower base_seq", lambda f, seq: {**f, "base_seq": f["base_seq"] - 1}, False),
    ("a higher base_seq", lambda f, seq: {**f, "base_seq": f["base_seq"] + 1}, False),
])
def test_snapshot_load_refuses_a_state_minted_for_another_boundary(world, label, mutate, accepted):
    world.apply([lambda R: R.kill.engage()])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1)])
    world.seal_with_tail(checkpoint=True)
    seq = _commit_with_folded(world, k, mutate)
    assert _cp.verify_checkpoint(world.store())[0], "the fixture's head must be genuinely owner-signed"
    if accepted:
        st = SnapshotState.load(world.store())
        assert (st.base_seq, st.snapshot_seq) == (k, seq), label
        assert _both_flags(world, lambda R: R.kill.is_engaged()) == {"OFF": True, "ON": True}
        return
    with pytest.raises(SnapshotError):
        SnapshotState.load(world.store())
    # ... and the seeded reads fail CLOSED on it (they raise; they never answer from the truncated window).
    got = _both_flags(world, lambda R: R.kill.is_engaged())
    assert all(isinstance(v, _Raised) and v.error.startswith("SnapshotError") for v in got.values()), (label, got)


# ======================================================================================================
# behaviour a docstring declares BY DESIGN — pinned as documented (and ON == OFF)
# ======================================================================================================
def test_budget_past_day_undercounts_after_a_prune_as_documented(world):
    """`BudgetLedger.spent`: "A caller passing a PAST day_iso — e.g. report() — may under-count post-prune: the
    accepted live-meter semantic." Budget keeps no snapshot sub-state; only the current day is exact."""
    past, today, u = "2026-11-01", "2026-11-11", {"input_tokens": 5, "output_tokens": 7, "cost_usd": 0.01}
    world.apply([_act("ALPHA", past, 1, usage=u), _act("ALPHA", past, 2, usage=u)])
    k = world.seal()
    world.apply([_act("ALPHA", today, 1, usage=u)])
    world.seal_with_tail(checkpoint=True)

    def read(R):
        return R.budget.spent("ALPHA", past), R.budget.spent("ALPHA", today), R.budget.report(past)
    before = _both_flags(world, read)
    assert before["OFF"] == before["ON"] and before["OFF"][0].actions == 2
    prune.commit_prune(world.store(), k, confirm=True)
    after = _both_flags(world, read)
    assert after["OFF"] == after["ON"]
    assert after["OFF"][0] == bd.Spend(actions=0, interrupts=0, tokens=0, cost_usd=0.0) and after["OFF"][2] == {}
    assert after["OFF"][1] == before["OFF"][1]                               # the current day stays exact


def test_a_pruned_ownership_challenge_must_be_reissued_as_documented(world):
    """`AssetOwnershipRegistry._fold`: "the CHALLENGE signal (ephemeral — a plain genesis scan, no snapshot seed;
    a pruned challenge is re-requested)". The `live_window=True` cached fold agrees with the scan."""
    world.apply([lambda R: R.own.issue_challenge("acme", HOSTS[0], issued_at=1.0, token="tok-a")])
    k = world.seal()
    world.apply([lambda R: R.own.issue_challenge("acme", HOSTS[1], issued_at=2.0, token="tok-b")])
    world.seal_with_tail(checkpoint=True)

    def read(R):
        return R.own.challenge("acme", HOSTS[0]), R.own.challenge("acme", HOSTS[1])

    def prove(host, tok):
        return world.apply([lambda R: R.own.verify_and_record(
            "acme", host, method=ao.METHOD_DNS_TXT, observed=[ao.expected_marker(tok)], now=3.0)])[0]
    before = _both_flags(world, read)
    assert before["OFF"] == before["ON"] and None not in before["OFF"]
    prune.commit_prune(world.store(), k, confirm=True)
    after = _both_flags(world, read)
    assert after["OFF"] == after["ON"] == (None, before["OFF"][1])
    assert prove(HOSTS[0], "tok-a").startswith("ValueError: no outstanding ownership challenge")
    assert world.apply([lambda R: R.own.issue_challenge("acme", HOSTS[0], issued_at=4.0, token="tok-a2")]) == ["ok"]
    assert prove(HOSTS[0], "tok-a2") == "ok" and prove(HOSTS[1], "tok-b") == "ok"


def test_margin_periods_move_pruned_settles_to_unscoped_as_documented(world):
    """`ui/margin._settle_events`: "The per-settle AMOUNTS come from the LIVE window only (a hard prune archives
    individual settle rows into the snapshot per-org aggregate ...) ... the per-period view reconciles any
    difference as the `unscoped` bucket, so the periods always sum back to the durable lifetime total"."""
    sc = _ui_margin()
    world.apply(sc.below)
    k = world.seal()
    world.apply(sc.live)
    world.seal_with_tail(checkpoint=True)

    def read(R):
        return {t["org_id"]: (t["committed_tokens"], [(p["scoped"], p["period_end"], p["committed_tokens"])
                                                      for p in t["periods"]])
                for t in ui_margin.margin_overview(R.store, cost_rate=2_000_000, target_margin=None)["tenants"]}
    before = _both_flags(world, read)
    assert before["OFF"] == before["ON"] and (True, 1000.0, 400) in before["OFF"]["acme"][1]
    prune.commit_prune(world.store(), k, confirm=True)
    after = _both_flags(world, read)
    assert after["OFF"] == after["ON"]
    for org, (committed, periods) in after["OFF"].items():
        assert committed == before["OFF"][org][0] == sum(tokens for _scoped, _pe, tokens in periods)
    assert (True, 1000.0, 0) in after["OFF"]["acme"][1] and (False, 0.0, 400) in after["OFF"]["acme"][1]


@pytest.mark.parametrize("label,reserve,settle,needle", [
    ("cost envelope", lambda R: R.cost.reserve("acme", 500, entry_id=cl.RESERVE_COST_PREFIX + "s:1", issued_at=1.0),
     lambda R: R.cost.settle("acme", 400, entry_id=cl.SETTLE_COST_PREFIX + "s:1", issued_at=2.0),
     "in-flight cost reserve"),
    ("postpaid arrears", lambda R: R.arr.accrue("acme", 60, entry_id=pp.RESERVE_ENTRY_PREFIX + "s:1", issued_at=1.0),
     lambda R: R.arr.settle("acme", 20, entry_id=pp.SETTLE_ENTRY_PREFIX + "s:1", issued_at=2.0),
     "in-flight postpaid reserve"),
])
def test_an_in_flight_reserve_below_k_refuses_the_prune_as_documented(world, label, reserve, settle, needle):
    """`prune.stranded_active_cost_reserves` / `stranded_active_postpaid_reserves`: "Fail-closed tripwire: block
    the prune while a below-K reserve is still in-flight ... A SETTLED reserve (settle present anywhere) IS
    prunable". The per-reserve amounts are not in the seed, so the refusal is the design — and it drops nothing."""
    assert world.apply([reserve]) == ["ok"]
    k = world.seal()
    world.apply([_noise(0)])
    world.seal_with_tail(checkpoint=True)
    seqs = [r.seq for r in world.store().iter_records()]
    with pytest.raises(prune.PruneUnsafe, match=needle):
        prune.commit_prune(world.store(), k, confirm=True)
    assert [r.seq for r in world.store().iter_records()] == seqs, "a refused prune drops nothing"
    assert world.apply([settle]) == ["ok"]                      # settled in the live tail: now prunable
    assert prune.commit_prune(world.store(), k, confirm=True)["base_seq"] == k


# ======================================================================================================
# re-anchoring an already-pruned spine: `checkpoint()` must carry the committed boundary forward, or refuse
# ======================================================================================================
def _head_bytes(world: _World) -> Optional[bytes]:
    p = world.root / "head.json"
    return p.read_bytes() if p.exists() else None


def _default_key_reads(world: _World) -> dict:
    """(kill switch engaged, acme wallet) through PRODUCTION construction — registries built with no explicit
    key trust the CURRENT owner key — flag OFF and ON, on fresh handles."""
    out = {}
    for label, on in (("OFF", False), ("ON", True)):
        if on:
            world.mp.setenv(FLAG, "1")
        else:
            world.mp.delenv(FLAG, raising=False)
        fold_cache.clear_all()
        vals: list = []
        for fn in (lambda s: ks.KillSwitch(s).is_engaged(), lambda s: wl.WalletRegistry(s).available("acme")):
            try:
                vals.append(fn(world.store()))
            except Exception as e:  # noqa: BLE001 — compared
                vals.append(_Raised(f"{type(e).__name__}: {e}"))
        out[label] = tuple(vals)
    world.mp.delenv(FLAG, raising=False)
    return out


def _sign_pruned_as(store: SpineStore, priv: str, standing) -> None:
    """Write a pruned (v2) head over `store`'s live window, carrying `standing`'s boundary, signed with `priv` —
    whoever holds it. (The fixture for heads that must NOT be carried forward.)"""
    from vigil_core.chain import _head_payload

    from sigil.reuse import Signature, SignedChainHead, evidence_signing_bytes, sign
    live = [e for e in store.entries() if e.seq >= standing.base_seq]
    head = SignedChainHead(schema_version=2, engagement_slug=standing.engagement_slug, last_seq=live[-1].seq,
                           entry_count=standing.base_seq + len(live), head_hash=live[-1].entry_hash,
                           base_seq=standing.base_seq, base_prev_hash=standing.base_prev_hash,
                           base_count=standing.base_seq, cumulative_merkle_root=standing.cumulative_merkle_root,
                           snapshot_seq=standing.snapshot_seq, prev_head_hash=standing.prev_head_hash)
    msg = evidence_signing_bytes(_head_payload(head))
    head = head.model_copy(update={"signatures": [Signature(key_id=cfg.OWNER_KEY_ID, signature_b64=sign(priv, msg))]})
    _cp.HEAD_PATH.write_text(head.model_dump_json(), encoding="utf-8")


@pytest.mark.parametrize("appended", [0, 1, 12])
def test_checkpoint_after_a_prune_carries_the_boundary_forward(world, appended):
    """`sigil sign`, `warden-anchor-set`, `key rotate`, `consolidate --sign` all re-anchor through `checkpoint()`.
    On a pruned spine that must write a pruned (v2) head naming the SAME boundary — repeatedly, idempotently — and
    leave every seeded read exactly as it was."""
    k = _pruned_killswitch_world(world)
    first = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    before = _both_flags(world, lambda R: (R.kill.is_engaged(), R.wallet.available("acme")))
    assert before == {"OFF": (True, 100), "ON": (True, 100)}
    counts = [first.entry_count]
    for rnd in range(3):
        world.apply([_noise(100 * rnd + i) for i in range(appended)])
        head = _cp.checkpoint(world.store())
        ok, why = _cp.verify_checkpoint(world.store())
        assert ok and why.startswith("anchors all") and why.endswith("(current)"), (rnd, why)
        assert head.schema_version == 2
        assert (head.base_seq, head.base_prev_hash, head.base_count, head.cumulative_merkle_root,
                head.snapshot_seq) == (first.base_seq, first.base_prev_hash, first.base_count,
                                       first.cumulative_merkle_root, first.snapshot_seq), rnd
        assert head.base_seq == k
        assert _cp.SignedChainHead.model_validate_json(_head_bytes(world)) == head
        counts.append(head.entry_count)
        st = SnapshotState.load(world.store())
        assert (st.base_seq, st.snapshot_seq) == (k, first.snapshot_seq)
        assert _both_flags(world, lambda R: (R.kill.is_engaged(), R.wallet.available("acme"))) == before, rnd
    assert counts == sorted(counts) and (counts[-1] - counts[0] == 3 * appended)


def _rotate(world, *, issued_at=None, between=()):
    """`sigil key rotate` exactly: validate the standing head under the key being retired, rotate, then re-sign
    carrying THAT head forward (no later sign trusts the retired key). `between` runs after the rotation record
    and before the re-sign (appends landing in that window)."""
    import time

    from sigil.governor import key_history as kh
    standing = _cp.standing_pruned_head(world.store())
    new_kp, seq = kh.rotate(world.store(), issued_at=time.time() if issued_at is None else issued_at)
    if between:
        world.apply(list(between))
    _cp.checkpoint(world.store(), carry=standing)
    return new_kp, seq


def test_owner_key_rotation_on_a_pruned_spine_keeps_every_seed(world):
    """`sigil key rotate` = `key_history.rotate` + `checkpoint()`. The seed was folded under the key of its time;
    registries trust the CURRENT key. After a rotation (twice, so the snapshot's key is two epochs back) the head
    must be re-signed by the new key over the same boundary, and production-constructed registries must still
    read the seed: the kill switch engaged, the wallet funded."""
    import time

    k = _pruned_killswitch_world(world)
    snap_key = SnapshotState.load(world.store()).trusted_pubkey
    assert snap_key == world.owner.public_key_b64
    assert _default_key_reads(world) == {"OFF": (True, 100), "ON": (True, 100)}
    keys = []
    for rnd in range(2):
        new_kp, _seq = _rotate(world, issued_at=time.time() + rnd, between=[_noise(500 + rnd)])
        keys.append(new_kp.public_key_b64)
        head = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
        assert head.schema_version == 2 and head.base_seq == k
        ok, why = _cp.verify_checkpoint(world.store())
        assert ok and why.endswith("(current)"), (rnd, why)
        assert [a.public_key_b64 for a in _cp.trust_root(world.store()).authorizers] == [new_kp.public_key_b64]
        st = SnapshotState.load(world.store())
        assert st.trusted_pubkey == snap_key, "the seed keeps the key it was folded under (never re-bound)"
        assert _snap.seed_applies(st, new_kp.public_key_b64, world.store()) is True
        assert _default_key_reads(world) == {"OFF": (True, 100), "ON": (True, 100)}, rnd
    # a wallet grant signed by the CURRENT key after both rotations folds on top of the seed
    cur = identity.owner_keypair()
    assert cur.public_key_b64 == keys[-1]
    wl.WalletRegistry(world.store()).grant("acme", 5, "topup", entry_id="g2", issued_at=9.0)
    assert _default_key_reads(world) == {"OFF": (True, 105), "ON": (True, 105)}


def test_a_seed_applies_only_to_its_own_key_or_along_the_validated_succession(world):
    """`seed_applies`: the reader's validated succession must say the seed's key was the owner's AT the snapshot seq
    (the seed's own key before any rotation, the succession tip after one). Anything else on a pruned spine RAISES
    (fail closed) — never an empty start over the deleted prefix, and never the seed on key equality alone: after a
    rotation the retired key's succession does not end at it, so it verifies none of the live records. On an
    un-pruned spine a different key starts from genesis."""
    import time

    from sigil.reuse import generate_keypair
    _pruned_killswitch_world(world)
    st = SnapshotState.load(world.store())
    old = world.owner.public_key_b64
    stranger = generate_keypair().public_key_b64
    assert _snap.seed_applies(st, old, world.store()) is True                  # its own key
    for who in (stranger, None, ""):
        with pytest.raises(_snap.SnapshotError, match="does not succeed"):
            _snap.seed_applies(st, who, world.store())
    new_kp, rot_seq = _rotate(world, issued_at=time.time())
    assert _snap.seed_applies(st, new_kp.public_key_b64, world.store()) is True   # the validated tip
    with pytest.raises(_snap.SnapshotError, match="does not succeed"):
        _snap.seed_applies(st, old, world.store())         # its own key, but no longer the end of the succession
    with pytest.raises(_snap.SnapshotError):
        _snap.seed_applies(st, stranger, world.store())
    late = st.model_copy(update={"snapshot_seq": rot_seq + 1})                     # the old key no longer covers it
    with pytest.raises(_snap.SnapshotError):
        _snap.seed_applies(late, new_kp.public_key_b64, world.store())
    tip = st.model_copy(update={"trusted_pubkey": new_kp.public_key_b64})
    with pytest.raises(_snap.SnapshotError):           # a seed naming a key the succession does not place at its seq
        _snap.seed_applies(tip, new_kp.public_key_b64, world.store())
    with pytest.raises(_snap.SnapshotError):
        _snap.seed_applies(tip, old, world.store())     # a seed under the NEW key is not the old key's
    assert _snap.seed_applies(SnapshotState.empty(), stranger, world.store()) is False   # nothing pruned


def test_a_read_whose_key_is_the_seeds_own_walks_the_succession_once_per_spine_state(world, monkeypatch):
    """Even the seed's own key is checked against the succession (key equality alone is not enough — see
    `test_a_reader_still_trusting_a_retired_key_never_reads_the_seed_without_its_live_records`), through the SAME
    memoized resolver the fold itself uses: repeated reads of one spine state walk the owner-key history once."""
    from sigil.governor import key_history as kh
    _pruned_killswitch_world(world)
    st = SnapshotState.load(world.store())
    walks = {"n": 0}
    real = kh._resolver_from_history

    def counting(*a, **kw):
        walks["n"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(kh, "_resolver_from_history", counting)
    kh.clear_resolver_cache()
    store = world.store()
    for _ in range(3):
        assert _snap.seed_applies(st, st.trusted_pubkey, store) is True
    assert walks["n"] == 1, walks


def test_a_checkpoint_between_the_prune_commit_and_its_manifest_rebase(world):
    """Crash window: the pruned head is committed (phase 3) but the manifest is not yet rebased, so the pruned
    prefix is still physically present. A re-anchor there must keep the boundary; the prune then finishes."""
    world.apply([lambda R: R.kill.engage(reason="incident"),
                 lambda R: R.wallet.grant("acme", 100, "trial", entry_id="g1", issued_at=1.0)])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1), _noise(2)])
    world.seal_with_tail(checkpoint=True)
    s = world.store()
    payload = prune.snapshot_payload(s, k)
    prune.archive_copy(s, k, payload)
    seq = prune._append_snapshot_idempotent(s, payload)
    _cp.sign_pruned_head(s, base_seq=k, base_prev_hash=payload["base_prev_hash"],
                         cumulative_merkle_root=payload["cumulative_merkle_root"], snapshot_seq=seq)
    assert [r.seq for r in world.store().iter_records()][0] == 0, "the prefix is still present (pre-rebase)"
    world.apply([_noise(3)])
    head = _cp.checkpoint(world.store())
    assert (head.schema_version, head.base_seq, head.snapshot_seq) == (2, k, seq)
    assert _cp.verify_checkpoint(world.store())[0]
    world.store().finish_prune()
    assert [r.seq for r in world.store().iter_records()][0] == k
    assert _cp.verify_checkpoint(world.store())[0]
    assert _both_flags(world, lambda R: (R.kill.is_engaged(), R.wallet.available("acme"))) == {
        "OFF": (True, 100), "ON": (True, 100)}


def _refused_unchanged(world: _World) -> None:
    """`checkpoint()` refuses (ValueError) and writes NOTHING; the seeded reads fail CLOSED (they raise)."""
    before = _head_bytes(world)
    with pytest.raises(ValueError) as e:
        _cp.checkpoint(world.store())
    assert "run `sigil sign`" not in str(e.value)
    assert _head_bytes(world) == before, "a refused re-anchor must not write head.json"
    got = _both_flags(world, lambda R: R.kill.is_engaged())
    assert all(isinstance(v, _Raised) and v.error.startswith("SnapshotError") for v in got.values()), got


def test_a_pruned_spine_with_no_head_fails_closed(world):
    """head.json deleted (by accident, or a restore that brought the spine back without it): never read as
    un-pruned — that would release the kill switch and zero the wallets with no error."""
    k = _pruned_killswitch_world(world)
    (world.root / "head.json").unlink()
    assert _snap.live_window_start(world.store()) == k
    with pytest.raises(SnapshotError, match=f"starts at seq {k}"):
        SnapshotState.load(world.store())
    ok, why = _cp.verify_checkpoint(world.store())
    assert not ok and "hard-pruned" in why and "run `sigil sign`" not in why
    _refused_unchanged(world)


def test_a_pruned_spine_under_a_plain_v1_head_fails_closed(world):
    """A genuinely owner-signed v1 ("no prune") head over the retained window — what a re-sign by a build that did
    not carry the boundary forward wrote. Reads refuse it; a re-anchor refuses to build on it."""
    from sigil.reuse import sign_head
    _pruned_killswitch_world(world)
    v1 = sign_head(world.store().entries(), engagement_slug=cfg.SCOPE,
                   signers=[(cfg.OWNER_KEY_ID, world.owner.private_key_b64)])
    assert v1.snapshot_seq < 0 and v1.base_seq == 0
    _cp.HEAD_PATH.write_text(v1.model_dump_json(), encoding="utf-8")
    with pytest.raises(SnapshotError, match="declares no prune"):
        SnapshotState.load(world.store())
    _refused_unchanged(world)


def test_a_pruned_head_with_a_corrupted_signature_is_not_carried_forward(world):
    _pruned_killswitch_world(world)
    raw = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    sig = raw.signatures[0]
    flip = "B" if sig.signature_b64[5] == "A" else "A"
    bad = sig.model_copy(update={"signature_b64": sig.signature_b64[:5] + flip + sig.signature_b64[6:]})
    _cp.HEAD_PATH.write_text(raw.model_copy(update={"signatures": [bad]}).model_dump_json(), encoding="utf-8")
    _refused_unchanged(world)


def test_a_pruned_head_signed_by_a_non_owner_key_is_not_carried_forward(world):
    from sigil.reuse import generate_keypair
    _pruned_killswitch_world(world)
    standing = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    _sign_pruned_as(world.store(), generate_keypair().private_key_b64, standing)
    _refused_unchanged(world)


def test_another_pruned_spines_head_is_not_carried_forward(world, tmp_path):
    """A validly owner-signed pruned head — for a DIFFERENT spine (same owner, other boundary)."""
    _pruned_killswitch_world(world)
    other = _World(tmp_path / "other", world.mp, world.owner).activate()
    other.apply([lambda R: R.kill.engage()])
    other.seal()
    other.apply([_noise(i) for i in range(4)])
    k2 = other.seal()
    other.apply([_noise(9)])
    other.seal_with_tail(checkpoint=True)
    prune.commit_prune(other.store(), k2, confirm=True)
    foreign = _head_bytes(other)
    world.activate()
    _cp.HEAD_PATH.write_text(foreign.decode("utf-8"), encoding="utf-8")
    _refused_unchanged(world)


def test_a_head_signed_by_a_retired_key_after_its_epoch_is_not_carried_forward(world):
    """After a rotation, the incumbent key stays acceptable ONLY for a head over records it was authoritative
    for. A pruned head reaching past the rotation but signed by the retired key — a retired-key holder's forgery
    — must not be laundered into a new-key head by the next re-anchor."""
    import time

    _pruned_killswitch_world(world)
    old = world.owner
    _rotate(world, issued_at=time.time())                  # legit: the new key re-signs the boundary
    world.apply([_noise(77)])
    standing = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    _sign_pruned_as(world.store(), old.private_key_b64, standing)
    before = _head_bytes(world)
    with pytest.raises(ValueError):
        _cp.checkpoint(world.store())
    assert _head_bytes(world) == before


def test_an_unpruned_spine_still_gets_a_plain_v1_head(world):
    world.apply([lambda R: R.kill.engage()] + [_noise(i) for i in range(3)])
    head = _cp.checkpoint(world.store())
    assert (head.schema_version, head.base_seq, head.base_count, head.snapshot_seq) == (1, 0, 0, -1)
    assert _cp.verify_checkpoint(world.store()) == (True, f"anchors all {head.entry_count} records (current)")
    assert _snap.live_window_start(world.store()) == 0
    assert SnapshotState.load(world.store()) == SnapshotState.empty()


def test_an_unpruned_spine_without_a_head_reads_as_unpruned(world):
    world.apply([lambda R: R.kill.engage()])
    assert not (world.root / "head.json").exists()
    assert SnapshotState.load(world.store()) == SnapshotState.empty()
    assert _both_flags(world, lambda R: R.kill.is_engaged()) == {"OFF": True, "ON": True}
    assert _cp.verify_checkpoint(world.store()) == (False, "no signed head — run `sigil sign` to anchor the spine")


def test_live_window_start_follows_the_manifest_and_needs_no_layout(world, tmp_path):
    assert _snap.live_window_start(world.store()) == 0
    k = _pruned_killswitch_world(world)
    assert _snap.live_window_start(world.store()) == k     # the memo follows the manifest's atomic replace
    legacy = SpineStore(tmp_path / "legacy" / "spine.jsonl")
    legacy.append(kind="event", source="t", actor="u", payload={"n": 1})
    assert _snap.live_window_start(legacy) == 0
    assert _snap.live_window_start(object()) == 0


def test_a_stale_concurrent_reanchor_returns_the_standing_longer_head(world, monkeypatch):
    """The monotonic head guard on the pruned path: a re-anchor that finds a LONGER head already written (a
    concurrent signer) returns that head and writes nothing; `force=True` (`sigil floor reset`) re-anchors anyway."""
    _pruned_killswitch_world(world)
    real = _cp._read_head_on_disk
    standing = real()
    longer = standing.model_copy(update={"entry_count": standing.entry_count + 10})
    calls = {"n": 0}

    def fake():
        calls["n"] += 1
        return real() if calls["n"] <= 2 else longer       # the head checkpoint() judges + the standing-head
        #                                                    check; then (another signer won) the guard

    monkeypatch.setattr(_cp, "_read_head_on_disk", fake)
    before = _head_bytes(world)
    assert _cp.checkpoint(world.store()) == longer
    assert _head_bytes(world) == before
    calls["n"] = 0
    forced = _cp.checkpoint(world.store(), force=True)
    assert forced.entry_count == standing.entry_count and forced.base_seq == standing.base_seq
    assert _cp.SignedChainHead.model_validate_json(_head_bytes(world)) == forced


def test_the_prune_commit_floor_advance_is_strict_and_the_reanchor_one_best_effort(world, monkeypatch):
    k = _pruned_killswitch_world(world)
    standing = _cp.SignedChainHead.model_validate_json(_head_bytes(world))

    def refuse(*a, **kw):
        raise _fl.FloorDowngrade("refused for the test")

    monkeypatch.setattr(_cp, "advance_floor", refuse)
    kw = dict(base_seq=k, base_prev_hash=standing.base_prev_hash,
              cumulative_merkle_root=standing.cumulative_merkle_root, snapshot_seq=standing.snapshot_seq)
    with pytest.raises(_fl.FloorDowngrade):
        _cp.sign_pruned_head(world.store(), **kw)          # a prune COMMIT must not succeed without its floor
    head = _cp.sign_pruned_head(world.store(), **kw, reanchor=True)   # a re-anchor only warns
    assert head.base_seq == k and _cp.SignedChainHead.model_validate_json(_head_bytes(world)) == head


def test_a_prune_committing_during_a_plain_sign_is_never_overwritten(world, monkeypatch):
    """Race: a `sigil sign` on the un-pruned spine reads it and decides "no prune"; before it takes the floor lock,
    an operator's prune commits its pruned head. The plain head must NOT overwrite the pruned one (that is the
    empty-seed fail-open); the pruned head stands."""
    world.apply([lambda R: R.kill.engage(reason="incident"),
                 lambda R: R.wallet.grant("acme", 100, "trial", entry_id="g1", issued_at=1.0)])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1), _noise(2)])
    world.seal_with_tail(checkpoint=True)
    real_sign_head = _cp.sign_head
    fired = {"n": 0}

    def sign_head_then_a_prune_commits(*a, **kw):
        out = real_sign_head(*a, **kw)
        if not fired["n"]:
            fired["n"] = 1
            prune.commit_prune(world.store(), k, confirm=True)
        return out

    monkeypatch.setattr(_cp, "sign_head", sign_head_then_a_prune_commits)
    returned = _cp.checkpoint(world.store())
    assert fired["n"] == 1
    on_disk = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    assert on_disk.snapshot_seq >= 0 and on_disk.base_seq == k and returned == on_disk
    assert _cp.verify_checkpoint(world.store())[0]
    assert _both_flags(world, lambda R: (R.kill.is_engaged(), R.wallet.available("acme"))) == {
        "OFF": (True, 100), "ON": (True, 100)}


def test_a_reanchor_reads_its_meta_chain_parent_under_the_floor_lock(world, monkeypatch):
    """Two concurrent re-anchors must not both chain from the same floor head (the second head would break the
    meta-chain `sigil verify` checks): the parent is read while the lock is held."""
    _pruned_killswitch_world(world)
    world.apply([_noise(7)])
    held = {"lock": False, "reads": []}
    real_lock, real_load = _cp.floor_lock, _cp.load_floor

    import contextlib

    @contextlib.contextmanager
    def tracking_lock(*a, **kw):
        with real_lock(*a, **kw):
            held["lock"] = True
            try:
                yield
            finally:
                held["lock"] = False

    def tracking_load(*a, **kw):
        held["reads"].append(held["lock"])
        return real_load(*a, **kw)

    monkeypatch.setattr(_cp, "floor_lock", tracking_lock)
    monkeypatch.setattr(_cp, "load_floor", tracking_load)
    head = _cp.checkpoint(world.store())
    assert head.schema_version == 2
    assert held["reads"] and held["reads"][-1] is True, held          # the parent read is inside the lock
    monkeypatch.undo()
    _isolate_keys(world.mp, world.root.parent / "keys")
    world.activate()
    assert _cp.verify_checkpoint(world.store())[0]


def test_a_replayed_older_pruned_head_is_not_carried_forward(world):
    """A validly owner-signed pruned head that is STALE against the durable floor (an older head put back) must
    not be re-signed into a current one. `sigil floor reset` (force=True) re-seeds the floor and may re-anchor."""
    _pruned_killswitch_world(world)
    world.apply([_noise(1)])
    _cp.checkpoint(world.store())
    older = _head_bytes(world)
    world.apply([_noise(2), _noise(3)])
    _cp.checkpoint(world.store())                           # the floor moves past `older`
    _cp.HEAD_PATH.write_bytes(older)
    with pytest.raises(_cp.CheckpointRefused):
        _cp.checkpoint(world.store())
    assert _head_bytes(world) == older
    forced = _cp.checkpoint(world.store(), force=True)
    assert forced.schema_version == 2 and forced.snapshot_seq >= 0


def test_a_corrupt_floor_refuses_a_reanchor(world):
    _pruned_killswitch_world(world)
    before = _head_bytes(world)
    (world.root / "floor.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(_cp.CheckpointRefused, match="floor is unreadable"):
        _cp.checkpoint(world.store())
    assert _head_bytes(world) == before


# -- the CLI verbs that sign: refuse cleanly (exit 2) and BEFORE changing anything ---------------------------
def _cli(world, monkeypatch):
    from sigil import cli
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **kw: world.store())
    return cli


def test_sigil_sign_on_an_unanchored_pruned_spine_exits_2_with_the_recovery(world, monkeypatch, capsys):
    cli = _cli(world, monkeypatch)
    _pruned_killswitch_world(world)
    (world.root / "head.json").unlink()
    monkeypatch.setattr(cli, "_assert_store_operable_or_exit", lambda cmd: None)
    with pytest.raises(SystemExit) as e:
        cli.main(["sign"])
    err = capsys.readouterr().err
    assert e.value.code == 2 and "hard-pruned" in err and "spine/head.json" in err
    assert not (world.root / "head.json").exists()


def test_key_rotate_refuses_before_rotating_on_an_unanchored_pruned_spine(world, monkeypatch):
    from types import SimpleNamespace as NS
    cli = _cli(world, monkeypatch)
    _pruned_killswitch_world(world)
    (world.root / "head.json").unlink()
    n = world.store().next_seq
    pub = (world.root.parent / "keys" / "owner.pub").read_text()
    with pytest.raises(_cp.CheckpointRefused):
        cli.cmd_key(NS(key_cmd="rotate", yes=True, i_understand=False))
    assert world.store().next_seq == n, "no rotation record was appended"
    assert (world.root.parent / "keys" / "owner.pub").read_text() == pub, "the owner key was not swapped"


def test_key_rotate_on_an_anchored_pruned_spine_re_anchors_and_keeps_the_seed(world, monkeypatch, capsys):
    from types import SimpleNamespace as NS
    cli = _cli(world, monkeypatch)
    k = _pruned_killswitch_world(world)
    cli.cmd_key(NS(key_cmd="rotate", yes=True, i_understand=False))
    assert "ROTATED" in capsys.readouterr().out
    head = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    assert (head.schema_version, head.base_seq) == (2, k) and _cp.verify_checkpoint(world.store())[0]
    assert _default_key_reads(world) == {"OFF": (True, 100), "ON": (True, 100)}


def test_key_re_genesis_refuses_on_a_pruned_spine_and_changes_nothing(world, monkeypatch, capsys):
    from types import SimpleNamespace as NS
    cli = _cli(world, monkeypatch)
    _pruned_killswitch_world(world)
    n, before = world.store().next_seq, _head_bytes(world)
    pub = (world.root.parent / "keys" / "owner.pub").read_text()
    with pytest.raises(SystemExit) as e:
        cli.cmd_key(NS(key_cmd="re-genesis", yes=True, i_understand=True))
    assert e.value.code == 2 and "hard-pruned" in capsys.readouterr().err
    assert world.store().next_seq == n and _head_bytes(world) == before
    assert (world.root.parent / "keys" / "owner.pub").read_text() == pub


def test_key_re_genesis_also_refuses_in_the_prune_crash_window(world, monkeypatch, capsys):
    """Pruned head committed, manifest not yet rebased: the live window still starts at 0, the head declares it."""
    from types import SimpleNamespace as NS
    cli = _cli(world, monkeypatch)
    world.apply([lambda R: R.kill.engage()])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1)])
    world.seal_with_tail(checkpoint=True)
    s = world.store()
    payload = prune.snapshot_payload(s, k)
    prune.archive_copy(s, k, payload)
    seq = prune._append_snapshot_idempotent(s, payload)
    _cp.sign_pruned_head(s, base_seq=k, base_prev_hash=payload["base_prev_hash"],
                         cumulative_merkle_root=payload["cumulative_merkle_root"], snapshot_seq=seq)
    assert _snap.live_window_start(world.store()) == 0
    with pytest.raises(SystemExit) as e:
        cli.cmd_key(NS(key_cmd="re-genesis", yes=True, i_understand=True))
    assert e.value.code == 2 and "hard-pruned" in capsys.readouterr().err


def test_warden_anchor_set_refuses_before_appending_on_an_unanchored_pruned_spine(world, monkeypatch):
    from types import SimpleNamespace as NS
    cli = _cli(world, monkeypatch)
    _pruned_killswitch_world(world)
    (world.root / "head.json").unlink()
    monkeypatch.setattr(cli, "_verify_ed25519", lambda *a, **kw: True)
    n = world.store().next_seq
    with pytest.raises(_cp.CheckpointRefused):
        cli.cmd_warden_anchor_set(NS(count=5, head_hash="ab" * 32, pubkey="k", sig="s"))
    assert world.store().next_seq == n


def test_consolidate_with_signing_refuses_before_promoting_on_an_unanchored_pruned_spine(world):
    from sigil.consolidate import pipeline
    _pruned_killswitch_world(world)
    (world.root / "head.json").unlink()
    n = world.store().next_seq
    with pytest.raises(_cp.CheckpointRefused):
        pipeline.run_consolidation(store=world.store(), since_seq=-1, sign=True, save_cursor=False)
    assert world.store().next_seq == n
    pipeline.run_consolidation(store=world.store(), since_seq=-1, sign=False, save_cursor=False, do_brief=False)


def test_a_retired_keys_forgery_is_refused_without_the_floor_too(world):
    """`sigil floor reset` (force=True) re-anchors WITHOUT the durable floor; the signer rule alone must still
    refuse a pruned head forged with a key retired before the head's own last_seq."""
    import time

    _pruned_killswitch_world(world)
    old = world.owner
    _rotate(world, issued_at=time.time())
    world.apply([_noise(78)])
    standing = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    _sign_pruned_as(world.store(), old.private_key_b64, standing)
    before = _head_bytes(world)
    with pytest.raises(_cp.CheckpointRefused):
        _cp.checkpoint(world.store(), force=True)
    assert _head_bytes(world) == before


def test_the_trust_root_is_the_succession_tip_not_a_swapped_in_owner_pub(world):
    """An owner.pub swapped in WITHOUT a cross-signed succession record is not trusted (W9-1, unchanged by the
    refactor onto `owner_succession`). `owner.pub` alone no longer matches `owner.priv`, so no trust root is built
    at all (the owner key loader refuses a mismatched pair); a complete, consistent pair swapped in is still not the
    succession tip."""
    import time

    from sigil.governor import key_history as kh
    from sigil.reuse import generate_keypair
    _pruned_killswitch_world(world)
    new_kp, _ = kh.rotate(world.store(), issued_at=time.time())
    stranger = generate_keypair()
    (world.root.parent / "keys" / "owner.pub").write_text(stranger.public_key_b64, encoding="utf-8")
    with pytest.raises(identity.OwnerKeyUnavailable):
        _cp.trust_root(world.store())
    identity.set_owner_key(stranger)
    assert [a.public_key_b64 for a in _cp.trust_root(world.store()).authorizers] == [new_kp.public_key_b64]


def test_a_forked_succession_falls_back_to_the_on_disk_key_and_never_moves_a_seed(world, monkeypatch):
    from sigil.governor import key_history as kh
    _pruned_killswitch_world(world)
    st = SnapshotState.load(world.store())

    def forked(*a, **kw):
        raise kh.SuccessionError("forked owner-key succession (test)")

    monkeypatch.setattr(kh, "succession_from_store", forked)
    assert _cp.owner_succession(world.store()) is None
    pub = (world.root.parent / "keys" / "owner.pub").read_text(encoding="utf-8").strip()
    assert [a.public_key_b64 for a in _cp.trust_root(world.store()).authorizers] == [pub]
    assert _cp._incumbent_key(world.store()) is None
    head = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    assert _cp.standing_pruned_head(world.store()) == head          # the on-disk key still carries its own head
    assert _snap.seed_applies(st, pub, world.store()) is True
    moved = st.model_copy(update={"trusted_pubkey": "an-older-key"})
    with pytest.raises(_snap.SnapshotError):
        _snap.seed_applies(moved, pub, world.store())


def test_a_prune_committing_after_a_plain_sign_read_its_snapshot_record_is_never_overwritten(world, monkeypatch):
    """The tighter race: the prune has ALREADY appended its snapshot record when `checkpoint()` reads the spine (so
    the plain head it builds has the SAME entry_count as the pruned head), and the pruned head commits while it
    signs. The monotonic guard cannot tell them apart; the prune guard must keep the pruned head."""
    world.apply([lambda R: R.kill.engage(reason="incident"),
                 lambda R: R.wallet.grant("acme", 100, "trial", entry_id="g1", issued_at=1.0)])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1), _noise(2)])
    world.seal_with_tail(checkpoint=True)
    s = world.store()
    payload = prune.snapshot_payload(s, k)
    prune.archive_copy(s, k, payload)
    seq = prune._append_snapshot_idempotent(s, payload)      # phase 2 done; the head is still the plain one
    real_sign_head = _cp.sign_head

    def sign_head_then_the_prune_head_commits(*a, **kw):
        out = real_sign_head(*a, **kw)
        _cp.sign_pruned_head(world.store(), base_seq=k, base_prev_hash=payload["base_prev_hash"],
                             cumulative_merkle_root=payload["cumulative_merkle_root"], snapshot_seq=seq)
        return out

    monkeypatch.setattr(_cp, "sign_head", sign_head_then_the_prune_head_commits)
    _cp.checkpoint(world.store())
    monkeypatch.setattr(_cp, "sign_head", real_sign_head)
    on_disk = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    assert (on_disk.schema_version, on_disk.base_seq, on_disk.snapshot_seq) == (2, k, seq)
    world.store().finish_prune()
    assert _both_flags(world, lambda R: (R.kill.is_engaged(), R.wallet.available("acme"))) == {
        "OFF": (True, 100), "ON": (True, 100)}


# ======================================================================================================
# The review of the cutover: a seed is never moved to another key, and a retired key's head is never laundered
# ======================================================================================================
def _forged_snapshot(world, key_b64: str, snapshot_seq: int) -> int:
    """Append a `snapshot` record whose folded state releases the kill switch (a keyless file write)."""
    real = world.store().get(snapshot_seq).payload["folded_state"]
    forged = dict(real)
    forged["killswitch_engaged"] = False
    forged["trusted_pubkey"] = key_b64
    return world.store().append(kind="snapshot", source="prune", actor="owner", payload={"folded_state": forged})


def _sign_v2_as(store, priv: str, standing, *, upto: int, snapshot_seq: int) -> None:
    from vigil_core.chain import _head_payload

    from sigil.reuse import Signature, SignedChainHead, evidence_signing_bytes, sign
    live = [e for e in store.entries() if standing.base_seq <= e.seq <= upto]
    head = SignedChainHead(schema_version=2, engagement_slug=standing.engagement_slug, last_seq=live[-1].seq,
                           entry_count=standing.base_seq + len(live), head_hash=live[-1].entry_hash,
                           base_seq=standing.base_seq, base_prev_hash=standing.base_prev_hash,
                           base_count=standing.base_seq, cumulative_merkle_root=standing.cumulative_merkle_root,
                           snapshot_seq=snapshot_seq, prev_head_hash="")
    msg = evidence_signing_bytes(_head_payload(head))
    head = head.model_copy(update={"signatures": [Signature(key_id=cfg.OWNER_KEY_ID, signature_b64=sign(priv, msg))]})
    _cp.HEAD_PATH.write_text(head.model_dump_json(), encoding="utf-8")


def _not_released(reads: dict) -> bool:
    """The kill switch reads ENGAGED or the read fails closed (raises) — never released."""
    return all(v[0] is True or isinstance(v[0], _Raised) for v in reads.values())


@pytest.mark.parametrize("delete_floor", [False, True])
def test_a_retired_keys_head_over_a_forged_snapshot_is_never_laundered_by_a_routine_sign(world, delete_floor):
    """A holder of the RETIRED key signs a pruned head that stops just before the rotation (so "the key valid at
    its last_seq" is the retired one) and names a forged snapshot that releases the kill switch; deleting the
    floor is a keyless capability. No routine sign may carry that head forward under the current key."""
    import time
    _pruned_killswitch_world(world)
    old = world.owner
    new_kp, rot_seq = _rotate(world, issued_at=time.time())
    standing = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    fseq = _forged_snapshot(world, new_kp.public_key_b64, standing.snapshot_seq)
    if delete_floor:
        (world.root / "floor.json").unlink()
    _sign_v2_as(world.store(), old.private_key_b64, standing, upto=rot_seq - 1, snapshot_seq=fseq)
    before = _head_bytes(world)
    for force in (False, True):
        with pytest.raises(_cp.CheckpointRefused):
            _cp.checkpoint(world.store(), force=force)
        assert _head_bytes(world) == before
    assert _cp.verify_checkpoint(world.store())[0] is False
    assert _not_released(_default_key_reads(world))


def test_an_owner_pub_swapped_in_without_a_key_fails_closed_on_a_pruned_spine(world):
    """A same-UID writer replaces `owner.pub` (no private key needed): the pair no longer matches, no trust root is
    built and the pruned boundary is not trusted — reads fail CLOSED. With a complete, consistent pair of its own
    swapped in, the head still verifies (the trust root is the succession tip), but no registry may seed from a key
    the succession does not reach: reads fail CLOSED — the kill switch is never released (an un-pruned spine keeps
    it engaged the same way)."""
    import time

    from sigil.governor import key_history as kh
    from sigil.reuse import generate_keypair
    _pruned_killswitch_world(world)
    _rotate(world, issued_at=time.time())
    assert _default_key_reads(world) == {"OFF": (True, 100), "ON": (True, 100)}
    stranger = generate_keypair()
    identity._PUB.write_text(stranger.public_key_b64, encoding="utf-8")
    kh.clear_resolver_cache()
    reads = _default_key_reads(world)
    assert all(isinstance(v[0], _Raised) and v[0].error.startswith("SnapshotError") for v in reads.values()), reads
    identity.set_owner_key(stranger)
    kh.clear_resolver_cache()
    reads = _default_key_reads(world)
    assert all(isinstance(v[0], _Raised) and "does not succeed" in str(v[0]) for v in reads.values()), reads


def test_a_forked_succession_on_a_pruned_spine_fails_closed_and_never_releases(world):
    """A holder of the retired key appends a second, validly cross-signed successor of it: the succession forks
    (DENY-all). The seed is never dropped for an empty start: current-key reads fail closed."""
    import time

    from sigil.governor import key_history as kh
    from sigil.reuse import generate_keypair
    _pruned_killswitch_world(world)
    old = world.owner
    _rotate(world, issued_at=time.time())
    rogue = generate_keypair()
    payload = kh.cross_sign(old, rogue, epoch=1, prev_pubkey=old.public_key_b64, issued_at=time.time() + 5)
    kh._append_history(world.store(), payload, reason="fork")
    kh.clear_resolver_cache()
    reads = _default_key_reads(world)
    assert _not_released(reads), reads
    assert all(isinstance(v[0], _Raised) for v in reads.values()), reads


def test_a_reader_still_holding_the_pre_rotation_key_keeps_every_latch(world):
    """Long-lived objects capture the owner key at construction. After a rotation on a pruned spine a reader that
    still trusts the RETIRED key verifies none of the live records (its succession does not end at its key), so it
    must not read the seed either: it fails closed — the kill switch is never read released, the gesture capability
    never re-enabled. The current key (the validated tip) reads the seed."""
    import time
    world.apply([lambda R: R.kill.engage(reason="incident"),
                 lambda R: cap.CapabilityGate(R.store, owner_key=world.owner).disable("gesture", reason="x"),
                 lambda R: R.wallet.grant("acme", 100, "trial", entry_id="g1", issued_at=1.0)])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1), _noise(2)])
    world.seal_with_tail(checkpoint=True)
    prune.commit_prune(world.store(), k, confirm=True)
    old_pub = world.owner.public_key_b64
    _rotate(world, issued_at=time.time())
    for on in (False, True):
        if on:
            world.mp.setenv(FLAG, "1")
        else:
            world.mp.delenv(FLAG, raising=False)
        fold_cache.clear_all()
        with pytest.raises(SnapshotError, match="does not succeed"):
            ks.KillSwitch(world.store(), trusted_pubkey=old_pub).is_engaged()
        # the capability gate maps any read failure to DISABLED (its own fail-closed direction)
        assert cap.CapabilityGate(world.store(), trusted_pubkey=old_pub).is_disabled("gesture") is True, on
        # ... and the CURRENT key (the validated tip) reads the same seed: never an empty start, re-enabled
        assert ks.KillSwitch(world.store()).is_engaged() is True, on
        assert cap.CapabilityGate(world.store()).is_disabled("gesture") is True, on
    world.mp.delenv(FLAG, raising=False)
    assert k > 0


def test_an_interrupted_rotation_is_finished_only_by_the_owners_explicit_command(world, monkeypatch, capsys):
    """`kh.rotate` appended the rotation record but the process died before the re-sign: the pruned head is still
    under the retired key. A routine sign refuses (it cannot tell this from a retired-key forgery) and names the
    deliberate path; `sigil key rotate --finish --yes` re-signs it under the current key."""
    import time
    from types import SimpleNamespace as NS

    from sigil.governor import key_history as kh
    cli = _cli(world, monkeypatch)
    _pruned_killswitch_world(world)
    kh.rotate(world.store(), issued_at=time.time())          # ... and the process dies here
    before = _head_bytes(world)
    with pytest.raises(_cp.CheckpointRefused, match="key rotate --finish --yes"):
        _cp.checkpoint(world.store())
    assert _head_bytes(world) == before
    with pytest.raises(SystemExit):                          # the --yes confirmation is still required
        cli.cmd_key(NS(key_cmd="rotate", yes=False, finish=True, i_understand=False))
    assert _head_bytes(world) == before
    cli.cmd_key(NS(key_cmd="rotate", yes=True, finish=True, i_understand=False))
    assert "rotation FINISHED" in capsys.readouterr().out
    ok, why = _cp.verify_checkpoint(world.store())
    assert ok and why.endswith("(current)"), why
    assert _default_key_reads(world) == {"OFF": (True, 100), "ON": (True, 100)}


def test_finish_never_carries_a_head_the_floor_does_not_back(world):
    """`--finish` admits the retired key's head only within the durable floor: with the floor deleted (a keyless
    capability) it still refuses."""
    import time

    from sigil.governor import key_history as kh
    _pruned_killswitch_world(world)
    kh.rotate(world.store(), issued_at=time.time())
    (world.root / "floor.json").unlink()
    with pytest.raises(_cp.CheckpointRefused):
        _cp.checkpoint(world.store(), admit_incumbent=True)


def test_a_reset_pruned_spine_is_re_anchored_only_by_a_deliberate_floor_reset(world, monkeypatch, capsys):
    """`sigil ingest --reset` empties the spine but leaves the old pruned head: a routine sign refuses and names
    the deliberate path; `sigil floor reset --yes` re-anchors the fresh spine as an un-pruned one."""
    from types import SimpleNamespace as NS
    cli = _cli(world, monkeypatch)
    _pruned_killswitch_world(world)
    world.store().reset()
    s = world.store()
    s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": 1})
    with pytest.raises(_cp.CheckpointRefused, match="floor reset --yes"):
        _cp.checkpoint(s)
    cli.cmd_floor(NS(action="reset", yes=True))
    assert "RE-SEEDED" in capsys.readouterr().out
    head = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    assert (head.schema_version, head.snapshot_seq) == (1, -1)
    assert _cp.verify_checkpoint(world.store())[0] is True
    assert SnapshotState.load(world.store()) == SnapshotState.empty()


def test_a_floor_reset_supersedes_only_the_pruned_head_it_judged(world, monkeypatch):
    """`sigil floor reset --yes` over a reset spine replaces the stale pruned head it judged — but a DIFFERENT pruned
    head that lands between that judgement and the commit (a prune committed concurrently) stands."""
    _pruned_killswitch_world(world)
    world.store().reset()
    s = world.store()
    s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": 1})
    judged = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    landed = judged.model_copy(update={"entry_count": judged.entry_count + 1}).model_dump_json()
    real_sign = _cp.sign_head

    def a_prune_lands_first(*a, **k):
        (world.root / "head.json").write_text(landed, encoding="utf-8")
        return real_sign(*a, **k)

    monkeypatch.setattr(_cp, "sign_head", a_prune_lands_first)
    out = _cp.checkpoint(s, force=True)
    assert _head_bytes(world).decode() == landed and out.snapshot_seq == judged.snapshot_seq
    monkeypatch.setattr(_cp, "sign_head", real_sign)
    (world.root / "head.json").write_text(judged.model_dump_json(), encoding="utf-8")
    assert _cp.checkpoint(s, force=True).snapshot_seq == -1          # the judged head itself is superseded


def test_floor_reset_on_a_pruned_spine_with_an_unreadable_floor_re_seeds_it(world, monkeypatch, capsys):
    from types import SimpleNamespace as NS
    cli = _cli(world, monkeypatch)
    _pruned_killswitch_world(world)
    (world.root / "floor.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(_cp.CheckpointRefused, match="floor reset --yes"):
        _cp.checkpoint(world.store())
    cli.cmd_floor(NS(action="reset", yes=True))
    assert "RE-SEEDED" in capsys.readouterr().out
    assert _fl.load_floor() is not None
    ok, why = _cp.verify_checkpoint(world.store())
    assert ok, why
    assert _default_key_reads(world) == {"OFF": (True, 100), "ON": (True, 100)}


def test_a_head_that_fails_only_the_floor_is_named_as_such(world):
    """A standing pruned head that verifies under the owner key but is BEHIND the floor (a rolled-back head) is
    refused with a message that says so and names the deliberate reset — not "does not verify under the key"."""
    _pruned_killswitch_world(world)
    old_head = _head_bytes(world)
    world.apply([_noise(90)])
    _cp.checkpoint(world.store())                           # the floor moves to the new head
    world.apply([_noise(91)])
    (world.root / "head.json").write_bytes(old_head)        # roll the head back
    with pytest.raises(_cp.CheckpointRefused, match="anti-rollback floor") as ei:
        _cp.checkpoint(world.store())
    assert "floor reset --yes" in str(ei.value)


def test_a_malformed_head_signature_is_a_refusal_never_a_crash(world):
    _pruned_killswitch_world(world)
    head = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    sig = head.signatures[0].model_copy(update={"signature_b64": "!!not-base64!!"})
    (world.root / "head.json").write_text(head.model_copy(update={"signatures": [sig]}).model_dump_json(),
                                          encoding="utf-8")
    with pytest.raises(_cp.CheckpointRefused, match="malformed signature material"):
        _cp.checkpoint(world.store())


def test_a_re_anchor_never_fails_on_a_floor_that_will_not_advance(world, monkeypatch, capsys):
    """A re-anchor (`checkpoint()` of an already-pruned spine) advances the floor BEST-EFFORT, like every routine
    sign: a floor that refuses to move never bricks signing (it only ever rejects more)."""
    _pruned_killswitch_world(world)
    world.apply([_noise(95)])

    def refuse(*a, **kw):
        raise _fl.FloorDowngrade("refused (test)")

    monkeypatch.setattr(_cp, "advance_floor", refuse)
    head = _cp.checkpoint(world.store())
    assert head.schema_version == 2
    assert "floor not advanced" in capsys.readouterr().err


def test_re_genesis_is_refused_on_a_pruned_spine_even_with_its_head_gone(world, monkeypatch, capsys):
    """The live-window half of the refusal: with the head gone nothing declares a prune, but the live window
    still starts above seq 0."""
    from types import SimpleNamespace as NS
    cli = _cli(world, monkeypatch)
    _pruned_killswitch_world(world)
    (world.root / "head.json").unlink()
    n = world.store().next_seq
    with pytest.raises(SystemExit) as e:
        cli.cmd_key(NS(key_cmd="re-genesis", yes=True, i_understand=True))
    assert e.value.code == 2 and "hard-pruned" in capsys.readouterr().err
    assert _head_bytes(world) is None and world.store().next_seq == n


def test_a_corrupt_head_on_a_pruned_spine_never_advises_a_re_sign(world):
    _pruned_killswitch_world(world)
    (world.root / "head.json").write_text("{not json", encoding="utf-8")
    ok, why = _cp.verify_checkpoint(world.store())
    assert ok is False and "do not re-sign" in why and "run `sigil sign`" not in why


def test_key_status_never_prescribes_re_genesis_on_a_pruned_spine(world, monkeypatch, capsys):
    import time
    from types import SimpleNamespace as NS

    from sigil.reuse import generate_keypair
    cli = _cli(world, monkeypatch)
    _pruned_killswitch_world(world)
    _rotate(world, issued_at=time.time())
    identity._PUB.write_text(generate_keypair().public_key_b64, encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cli.cmd_key(NS(key_cmd="status", yes=False, finish=False, i_understand=False))
    err = capsys.readouterr().err
    assert e.value.code == 2 and "re-genesis is refused on a hard-pruned spine" in err
    assert "recover with `sigil key re-genesis`" not in err


def test_a_pre_flight_on_an_unpruned_spine_decodes_no_records(world, monkeypatch):
    world.apply([lambda R: R.kill.engage()] + [_noise(i) for i in range(3)])
    _cp.checkpoint(world.store())

    def boom(self):
        raise AssertionError("store.entries() decoded the whole spine for a pre-flight")

    monkeypatch.setattr(SpineStore, "entries", boom)
    assert _cp.standing_pruned_head(world.store()) is None


def test_the_rotation_carry_is_only_the_exact_head_it_validated(world):
    """`key rotate` re-signs the head it validated before rotating. A head swapped in between (here: one the
    retiring key signs over a forged snapshot) is not that head, so the carry does not cover it."""
    import time

    from sigil.governor import key_history as kh
    _pruned_killswitch_world(world)
    old = world.owner
    standing = _cp.standing_pruned_head(world.store())
    new_kp, rot_seq = kh.rotate(world.store(), issued_at=time.time())
    fseq = _forged_snapshot(world, new_kp.public_key_b64, standing.snapshot_seq)
    _sign_v2_as(world.store(), old.private_key_b64, standing, upto=rot_seq - 1, snapshot_seq=fseq)
    before = _head_bytes(world)
    with pytest.raises(_cp.CheckpointRefused):
        _cp.checkpoint(world.store(), carry=standing)
    assert _head_bytes(world) == before


def test_a_half_pruned_snapshot_is_treated_as_pruned_and_an_anonymous_reader_walks_no_succession(world, monkeypatch):
    """Only the EMPTY identity (no base, no snapshot) lets a different key start from genesis: a state that names a
    base OR a snapshot seq is a prune. And a reader with no key at all is refused without walking the succession."""
    from sigil.governor import key_history as kh
    from sigil.reuse import generate_keypair
    _pruned_killswitch_world(world)
    stranger = generate_keypair().public_key_b64
    key = world.owner.public_key_b64
    for half in (SnapshotState(base_seq=5, snapshot_seq=-1, trusted_pubkey=key),
                 SnapshotState(base_seq=0, snapshot_seq=3, trusted_pubkey=key)):
        with pytest.raises(_snap.SnapshotError, match="does not succeed"):
            _snap.seed_applies(half, stranger, world.store())

    def boom(*a, **kw):
        raise AssertionError("key_resolver walked for a reader with no key")

    monkeypatch.setattr(kh, "key_resolver", boom)
    st = SnapshotState.load(world.store())
    for anonymous in (None, ""):
        with pytest.raises(_snap.SnapshotError):
            _snap.seed_applies(st, anonymous, world.store())


# ======================================================================================================
# A seed is folded together with the live window, which the reader verifies with its own owner-key succession:
# the seed applies only while that succession places the keys exactly where the prune placed them
# ======================================================================================================
def _device_wallet_world(world, dev_pub: str) -> int:
    """Below K, under the world's owner key: a device authorized and a wallet grant of 100. Returns K (a sealed
    boundary; the head is signed). No prune yet."""
    from sigil.mesh import registry as mreg
    world.apply([lambda R: mreg.authorize_device(R.store, "phone", dev_pub, world.owner, issued_at=1.0),
                 lambda R: R.wallet.grant("acme", 100, "trial", entry_id="g1", issued_at=1.0)])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1), _noise(2)])
    world.seal_with_tail(checkpoint=True)
    return k


def _authz_reads(world, dev_pub: str, key: Optional[str]) -> dict:
    """{'OFF'|'ON': (device authorized, acme wallet)} for a reader trusting `key` (None: production construction,
    the on-disk owner key), on fresh handles; a raise is captured as `_Raised`."""
    from sigil.mesh import registry as mreg
    out = {}
    for label, on in (("OFF", False), ("ON", True)):
        if on:
            world.mp.setenv(FLAG, "1")
        else:
            world.mp.delenv(FLAG, raising=False)
        fold_cache.clear_all()
        vals: list = []
        for fn in (lambda s: dev_pub in mreg.authorized_devices(s, trusted_pubkey=key),
                   lambda s: wl.WalletRegistry(s, trusted_pubkey=key).available("acme")):
            try:
                vals.append(fn(world.store()))
            except Exception as e:  # noqa: BLE001 — compared
                vals.append(_Raised(f"{type(e).__name__}: {e}"))
        out[label] = tuple(vals)
    world.mp.delenv(FLAG, raising=False)
    return out


def _all_refused(reads: dict) -> bool:
    return all(isinstance(v, _Raised) and v.error.startswith("SnapshotError") for vals in reads.values() for v in vals)


def test_a_reader_still_trusting_a_retired_key_never_reads_the_seed_without_its_live_records(world):
    """Prune under K0, rotate to K1, then revoke the device and debit the wallet under K1. A reader that still
    trusts K0 — constructed with it before the rotation, or with K0's own key files put back — walks a succession
    that does not end at its key, so it verifies none of the live records. It must not read the seed on key
    equality: that would answer the device authorized and the full balance. Every such read fails closed."""
    import time

    from sigil.governor import key_history as kh
    from sigil.mesh import registry as mreg
    from sigil.reuse import generate_keypair
    dev = generate_keypair().public_key_b64
    k = _device_wallet_world(world, dev)
    prune.commit_prune(world.store(), k, confirm=True)
    old = world.owner
    assert _authz_reads(world, dev, None) == {"OFF": (True, 100), "ON": (True, 100)}
    new_kp, _ = _rotate(world, issued_at=time.time())
    mreg.revoke_device(world.store(), "phone", dev, new_kp)
    wl.WalletRegistry(world.store(), owner_key=new_kp, trusted_pubkey=new_kp.public_key_b64).debit(
        "acme", 100, entry_id="d1", issued_at=2.0)
    truth = {"OFF": (False, 0), "ON": (False, 0)}
    assert _authz_reads(world, dev, None) == truth
    assert _authz_reads(world, dev, new_kp.public_key_b64) == truth
    assert _all_refused(_authz_reads(world, dev, old.public_key_b64))       # a reader built before the rotation
    identity.set_owner_key(old)                                             # the retired key's files put back
    kh.clear_resolver_cache()
    assert _cp.verify_checkpoint(world.store())[0], "the head itself still verifies under the succession tip"
    assert _all_refused(_authz_reads(world, dev, None))


@pytest.mark.parametrize("pin", ["removed", "set to the current key"])
def test_a_genesis_pin_other_than_the_prunes_never_drops_the_live_records_signed_before_a_rotation(world, pin):
    """The prune runs AFTER a rotation: its seed carries K1, while the live records [K..R) before the rotation are
    K0's — here the device revoke and the wallet debit. With `owner.genesis.pub` removed or set to K1 the succession
    is walked from K1 alone: K1 is still the key at the snapshot, but K0's live records no longer verify. The seed
    must not apply (it would answer the device authorized and the full balance): reads fail closed."""
    import time

    from sigil.governor import key_history as kh
    from sigil.mesh import registry as mreg
    from sigil.reuse import generate_keypair
    dev = generate_keypair().public_key_b64
    k = _device_wallet_world(world, dev)
    old = world.owner
    mreg.revoke_device(world.store(), "phone", dev, old)
    wl.WalletRegistry(world.store(), owner_key=old, trusted_pubkey=old.public_key_b64).debit(
        "acme", 100, entry_id="d1", issued_at=2.0)
    new_kp, rot_seq = _rotate(world, issued_at=time.time())
    assert rot_seq > k
    world.seal_with_tail(checkpoint=True)
    prune.commit_prune(world.store(), k, confirm=True)
    st = SnapshotState.load(world.store())
    assert st.trusted_pubkey == new_kp.public_key_b64 and st.snapshot_seq > rot_seq
    truth = {"OFF": (False, 0), "ON": (False, 0)}
    assert _authz_reads(world, dev, None) == truth
    pin_path = world.root.parent / "keys" / "owner.genesis.pub"
    assert pin_path.read_text(encoding="utf-8").strip() == old.public_key_b64
    if pin == "removed":
        pin_path.unlink()
    else:
        pin_path.write_text(new_kp.public_key_b64, encoding="utf-8")
    kh.clear_resolver_cache()
    assert _cp.verify_checkpoint(world.store())[0], "the head itself still verifies"
    assert _all_refused(_authz_reads(world, dev, None))
    pin_path.write_text(old.public_key_b64, encoding="utf-8")               # the pin the prune walked from
    kh.clear_resolver_cache()
    assert _authz_reads(world, dev, None) == truth


def test_trial_claims_and_report_unlocks_keep_their_seed_across_a_rotation_after_a_prune(world):
    """Both pricing ledgers seed through the same rule as every other registry: after a prune and a routine key
    rotation the current key still reads the pruned claim and unlock (never an empty start that would let the same
    key claim a second trial or re-lock a paying org)."""
    import time

    from sigil.governor import report_unlock as ru
    from sigil.governor import trial_claim as tc
    digest = tc.key_digest("email", "owner@acme.example")
    world.apply([lambda R: tc.TrialClaimRegistry(R.store, owner_key=world.owner).claim(
                     "email", digest, "acme", issued_at=1.0),
                 lambda R: ru.ReportUnlockRegistry(R.store, owner_key=world.owner).unlock(
                     "acme", "topup", source_ref="evt_1", issued_at=1.0)])
    world.seal()
    world.apply([_noise(0)])
    k = world.seal()
    world.apply([_noise(1)])
    world.seal_with_tail(checkpoint=True)
    prune.commit_prune(world.store(), k, confirm=True)

    def reads() -> dict:
        out = {}
        for label, on in (("OFF", False), ("ON", True)):
            if on:
                world.mp.setenv(FLAG, "1")
            else:
                world.mp.delenv(FLAG, raising=False)
            fold_cache.clear_all()
            s = world.store()
            out[label] = (tc.TrialClaimRegistry(s).claimant("email", digest),
                          ru.ReportUnlockRegistry(s).is_unlocked("acme"))
        world.mp.delenv(FLAG, raising=False)
        return out

    assert reads() == {"OFF": ("acme", True), "ON": ("acme", True)}
    _rotate(world, issued_at=time.time())
    assert reads() == {"OFF": ("acme", True), "ON": ("acme", True)}


def test_a_head_naming_a_snapshot_outside_its_own_signed_window_is_refused(world):
    """Every prune appends its snapshot record inside the window the head it signs commits. A pruned head naming a
    record past its own last_seq (in the unsigned tail) is refused even when it is signed by the owner key: no
    signature covers that record."""
    _pruned_killswitch_world(world)
    standing = _cp.SignedChainHead.model_validate_json(_head_bytes(world))
    fseq = _forged_snapshot(world, world.owner.public_key_b64, standing.snapshot_seq)
    (world.root / "floor.json").unlink()
    _sign_v2_as(world.store(), world.owner.private_key_b64, standing, upto=fseq - 1, snapshot_seq=fseq)
    assert _cp.verify_checkpoint(world.store())[0]
    with pytest.raises(SnapshotError, match="outside its own signed window"):
        SnapshotState.load(world.store())
    assert _not_released(_default_key_reads(world))
