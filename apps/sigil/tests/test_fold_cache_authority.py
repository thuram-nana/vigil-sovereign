"""Front C S0d — the remaining request-path folds on the verified incremental fold cache: agent PROMOTION and
the agent BUDGET meter (every governed agent action reads both), ASSET OWNERSHIP proofs + challenges (the launch
gate's ownership check, the customer Domains view, assessments) and MONITORING AUTHORITY (the Aegis monitoring
decision read).

Every test compares the CACHED public API against the SAME API with the flag OFF (the unchanged full folds) over
the same spine, across a grid of `now` instants for the time-dependent reads, and checks that a cached read never
fell back to a full scan. The generic trust-model cases (anchor, rotation, genesis, build race, faults,
concurrency) are proven on the shared substrate in `test_fold_cache_customers.py`.

  * seeded randomized equivalence: promotion grant / revoke / stale + forged + unsigned grants (incl. the
    no-promotion agents); agent action records across two UTC days with taken / denied decisions and hostile
    usage values (negative, NaN, a 400-digit cost); ownership challenge / proof / revoke (cascading to monitoring)
    / an unsigned challenge revoke; monitoring grant / revoke / revoke_org / a bad-mode and a forged grant;
    replays, noise and a second store instance;
  * the budget meter answers a 10-char UTC day only; any other day shape, and a tampered agent record (non-str
    ts / non-dict payload), read the unchanged scan;
  * O(new records): a warm launch-path ownership + monitoring read verifies ZERO signatures;
  * a seeded hard prune keeps a pruned proof, grant and promotion; the pubkey bypass folds the live window only;
  * flag OFF: no cache here is consulted.
"""
from __future__ import annotations

import itertools
import random

import pytest

from sigil.governor import asset_ownership as ao
from sigil.governor import budget as bd
from sigil.governor import key_history as kh
from sigil.governor import monitoring_authority as ma
from sigil.governor import promotion as pr
from sigil.governor.authn import signed_payload
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine.snapshot import SnapshotError, SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()
ORGS = ["acme", "globex"]
HOSTS = ["a.example.com", "b.example.com"]
AGENTS = ["ALPHA", "BRAVO", "ENVOY"]
SCOPES = ["*", "event", "action"]
DAYS = ["2026-11-10", "2026-11-11", "2026-11-12"]
NOWS = [0.0, 50.0, 400.0, 1e6, 1e10]
CAPS = bd.BudgetCaps(daily_actions=3, daily_tokens=20, daily_cost_usd=0.02)
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
        self.store = store
        self.promo = pr.PromotionPolicy(store, **kw)
        self.budget = bd.BudgetLedger(store, CAPS)
        self.own = ao.AssetOwnershipRegistry(store, **kw)
        self.mon = ma.MonitoringAuthorityRegistry(store, **kw)


class _CountingSnapshot:
    """Stands in for `budget.SnapshotState` (the budget meter's full scan only; the cache loads its own)."""

    def __init__(self, calls):
        self.calls = calls

    def load(self, store):
        self.calls["n"] += 1
        return SnapshotState.load(store)


@pytest.fixture
def no_full_scan(monkeypatch):
    """Counts full scans: every signed full fold builds the memoized owner-key resolver; the budget meter's full
    scan loads the snapshot through `budget.SnapshotState`."""
    calls = {"n": 0}
    real = kh.key_resolver

    def spy(*a, **kw):
        calls["n"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(kh, "key_resolver", spy)
    monkeypatch.setattr(bd, "SnapshotState", _CountingSnapshot(calls))
    return calls


def _cached_answers(regs):
    out = {"promoted": regs.promo.state_all()}
    for a in AGENTS:
        for s in SCOPES:
            out[("is_promoted", a, s)] = regs.promo.is_promoted(a, s)
    for a in AGENTS + ["OTHER"]:
        for d in DAYS:
            out[("spent", a, d)] = regs.budget.spent(a, d)
            out[("over", a, d)] = regs.budget.over_budget(a, d)
    for o in ORGS + ["nope"]:
        out[("grants", o)] = regs.mon.grants(o)
        for now in NOWS:
            out[("proven", o, now)] = regs.own.proven_hosts(o, now=now)
            out[("overview", o, now)] = regs.own.assets_overview(o, now=now)
        for h in HOSTS:
            out[("proof", o, h)] = regs.own.proof(o, h)
            out[("grant_for", o, h)] = regs.mon.grant_for(o, h)
            for now in NOWS:
                out[("current", o, h, now)] = regs.own.has_current_proof(o, h, now=now)
                out[("active_at", o, h, now)] = regs.mon.active_at(o, h, now=now)
                out[("owned_at", o, h, now)] = regs.mon.owned_at(o, h, now=now)
    return out


def _full_only_answers(regs):
    """Reads that deliberately keep the unchanged scan: `challenge()` (see `_challenges_cached`) and a budget day
    that is not a 10-char UTC date."""
    out = {}
    for o in ORGS:
        for h in HOSTS:
            out[("challenge", o, h)] = regs.own.challenge(o, h)
    for a in AGENTS:
        out[("spent_month", a)] = regs.budget.spent(a, "2026-11")
    return out


def _assert_equivalent(regs, monkeypatch, no_full_scan=None):
    before = no_full_scan["n"] if no_full_scan is not None else 0
    cached = _cached_answers(regs)
    if no_full_scan is not None:
        assert no_full_scan["n"] == before, "a cached read fell back to a full scan"
    cached.update(_full_only_answers(regs))
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    try:
        full = {**_cached_answers(regs), **_full_only_answers(regs)}
    finally:
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    assert cached == full


def _raw(store, payload):
    return store.append(kind="event", source="governor", actor="WARDEN", payload=payload)


def _agent_action(store, rng):
    usage = rng.choice([None, {"input_tokens": 5, "output_tokens": 7, "cost_usd": 0.01},
                        {"input_tokens": -3, "output_tokens": "4", "cost_usd": "nan"}, {"cost_usd": 10**400},
                        {"input_tokens": 1, "cost_usd": 0.007}])
    payload = {"decision": rng.choice(["auto", "queued", "denied"])}
    if usage is not None:
        payload["usage"] = usage
    return store.append(kind=rng.choice(["event", "draft"]), source="agent", actor=rng.choice(AGENTS + ["OTHER"]),
                        payload=payload, ts=rng.choice(DAYS[:2]) + "T0" + str(rng.randint(0, 9)) + ":00:00Z")


def _fails_closed_both_ways(monkeypatch, *reads):
    """Every read RAISES `SnapshotError`, with the fold cache ON and OFF alike (never an answer from an empty start)."""
    for flag in ("1", ""):
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
        for read in reads:
            with pytest.raises(SnapshotError, match="does not succeed"):
                read()
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")


@pytest.mark.parametrize("seed", [51, 52, 53])
def test_randomized_equivalence_with_the_full_folds(tmp_path, seed, monkeypatch, no_full_scan):
    rng = random.Random(seed)
    path = str(tmp_path / "spine.jsonl")
    store, other = SpineStore(path), SpineStore(path)
    regs, regs_other = _Regs(store), _Regs(other)
    captured: list = []
    for step in range(70):
        o, h, agent, scope = rng.choice(ORGS), rng.choice(HOSTS), rng.choice(AGENTS), rng.choice(SCOPES)
        r = regs_other if rng.random() < 0.2 else regs
        op = rng.choice(["promote", "promote", "demote", "stale_promo", "act", "act", "act", "challenge",
                         "prove", "prove", "unprove", "unchallenge", "monitor", "monitor", "unmonitor", "unmonitor_org",
                         "bad_mode", "replay", "forged", "unsigned", "noise"])
        seq = None
        try:
            if op == "promote":
                seq = r.promo.grant(agent, scope, issued_at=_iss())
            elif op == "demote":
                seq = r.promo.revoke(agent, scope)
            elif op == "stale_promo":              # owner-signed but OLDER than any honored grant: refused
                seq = _raw(store, signed_payload({"signal": pr.SIGNAL, "state": "granted", "agent": agent,
                                                  "scope": scope, "issued_at": 0.5}, OWNER))
            elif op == "act":
                seq = _agent_action(store, rng)
            elif op == "challenge":
                r.own.issue_challenge(o, h, issued_at=_iss(), token=f"tok-{step}")
            elif op == "prove":
                ch = r.own.challenge(o, h)
                if ch is not None:
                    r.own.verify_and_record(o, h, method=ao.METHOD_DNS_TXT, observed=[ch.marker],
                                            now=rng.choice([1.0, 40.0, 300.0]), ttl_seconds=rng.choice([100.0, 1e9]))
            elif op == "unprove":                  # cascades: retires the monitoring grant on this proof
                r.own.revoke_proof(o, h)
            elif op == "unchallenge":              # an UNSIGNED revoke is honoured (the safe direction)
                _raw(store, {"signal": ao.CHALLENGE_SIGNAL, "org_id": o, "host": h, "state": "revoked"})
            elif op == "monitor":
                r.mon.grant(o, h, mode=rng.choice([ma.MODE_OBSERVE, ma.MODE_BLOCK]), not_before=0.0,
                            not_after=rng.choice([500.0, 5000.0]), now=rng.choice([2.0, 45.0]), issued_at=_iss())
            elif op == "unmonitor":
                r.mon.revoke(o, h)
            elif op == "unmonitor_org":
                r.mon.revoke_org(o)
            elif op == "bad_mode":                 # owner-signed, unknown mode: inert
                seq = _raw(store, signed_payload({"signal": ma.SIGNAL, "org_id": o, "host": h, "mode": "pwn",
                                                  "not_before": 0.0, "not_after": 1e9, "proof_sha256": "x",
                                                  "state": "active", "issued_at": _iss()}, OWNER))
            elif op == "replay" and captured:
                _raw(store, rng.choice(captured))
            elif op == "forged":
                core = rng.choice([
                    {"signal": pr.SIGNAL, "state": "granted", "agent": agent, "scope": scope, "issued_at": _iss() + 1e6},
                    {"signal": ao.PROOF_SIGNAL, "org_id": o, "host": h, "method": ao.METHOD_DNS_TXT, "token_sha256": "x",
                     "verified_at": 1.0, "expires_at": 1e12, "state": "active", "issued_at": _iss() + 1e6}])
                _raw(store, signed_payload(core, ATTACKER))
            elif op == "unsigned":
                _raw(store, {"signal": ma.SIGNAL, "org_id": o, "host": h, "mode": ma.MODE_BLOCK, "not_before": 0.0,
                             "not_after": 1e12, "proof_sha256": "x", "state": "active", "issued_at": _iss() + 1e6})
            else:                                  # not an agent record, even under an agent's name: never metered
                store.append(kind="event", source="t", actor=rng.choice(["u", "ALPHA"]), ts=DAYS[0] + "T05:00:00Z",
                             payload={"signal": "noise", "decision": "auto", "i": step})
        except ValueError:
            pass                                            # an op the registry refuses
        if seq is not None and store.get(seq).source == "governor":
            captured.append(store.get(seq).payload)
        _assert_equivalent(regs, monkeypatch, no_full_scan)
    assert pr._PROMOTION_FOLD._entries and bd._BUDGET_FOLD._entries and ao._PROOF_FOLD._entries
    assert ao._CHALLENGE_FOLD._entries and ma._AUTHORITY_FOLD._entries


def test_a_tampered_agent_record_reads_the_unchanged_scan(tmp_path, monkeypatch):
    """The meter cannot answer for a record `spent` would crash on, so the view poisons and every read falls back
    to the scan — which still answers for every agent and day that record does not touch, exactly as before."""
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    regs.store.append(kind="event", source="agent", actor="ALPHA", payload={"decision": "auto"},
                      ts=DAYS[0] + "T01:00:00Z")
    assert regs.budget.spent("ALPHA", DAYS[0]).actions == 1                  # warm
    regs.store.append(kind="event", source="agent", actor="BRAVO", payload=["not", "a", "dict"],
                      ts=DAYS[1] + "T01:00:00Z")
    assert regs.budget.spent("ALPHA", DAYS[0]).actions == 1
    assert bd._BUDGET_FOLD._entries and next(iter(bd._BUDGET_FOLD._entries.values())).state.poisoned
    with pytest.raises(AttributeError):
        regs.budget.spent("BRAVO", DAYS[1])                                   # exactly as the scan always did
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    with pytest.raises(AttributeError):
        regs.budget.spent("BRAVO", DAYS[1])


def test_a_warm_launch_path_ownership_read_verifies_no_signature(tmp_path, monkeypatch):
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    for o in ORGS:
        for h in HOSTS:
            ch = regs.own.issue_challenge(o, h, issued_at=_iss())
            regs.own.verify_and_record(o, h, method=ao.METHOD_DNS_TXT, observed=[ch.marker], now=1.0,
                                       ttl_seconds=1e9)
            regs.mon.grant(o, h, not_before=0.0, not_after=5000.0, now=2.0, issued_at=_iss())
    regs.promo.grant("ALPHA", "*", issued_at=_iss())
    count = {"n": 0}
    for mod in (ao, ma, pr):
        real = mod.verify_signed

        def counting(*a, _real=real, **kw):
            count["n"] += 1
            return _real(*a, **kw)

        monkeypatch.setattr(mod, "verify_signed", counting)

    def read():
        return (regs.own.has_current_proof("acme", HOSTS[0], now=10.0), regs.mon.active_at("acme", HOSTS[0], now=10.0)
                is not None, regs.promo.is_promoted("ALPHA", "event"), len(regs.own.assets_overview("acme", now=10.0)))

    assert read() == (True, True, True, 2)
    count["n"] = 0
    for _ in range(5):
        assert read() == (True, True, True, 2)
    assert count["n"] == 0, "a warm ownership / monitoring / promotion read must not re-verify any signature"
    regs.own.revoke_proof("acme", HOSTS[0])                  # cascades a monitoring revoke
    assert read() == (False, False, True, 2)
    assert count["n"] == 0, "a revoke is the safe direction: honoured without a signature check"


def test_an_orgs_grants_are_listed_in_host_order_and_revoked_together(tmp_path, monkeypatch, no_full_scan):
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    assert regs.mon.grants("acme") == []                                       # warm
    for h in ["z.example.com", "a.example.com", "m.example.com"]:
        ch = regs.own.issue_challenge("acme", h, issued_at=_iss())
        regs.own.verify_and_record("acme", h, method=ao.METHOD_DNS_TXT, observed=[ch.marker], now=1.0,
                                   ttl_seconds=1e9)
        regs.mon.grant("acme", h, not_before=0.0, not_after=5000.0, now=2.0, issued_at=_iss())
    _assert_equivalent(regs, monkeypatch, no_full_scan)
    assert [g.host for g in regs.mon.grants("acme")] == ["a.example.com", "m.example.com", "z.example.com"]
    assert regs.own.proven_hosts("acme", now=10.0) == ["a.example.com", "m.example.com", "z.example.com"]
    assert len(regs.mon.revoke_org("acme")) == 3
    _assert_equivalent(regs, monkeypatch, no_full_scan)
    assert regs.mon.grants("acme") == []


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


def _pruned(tmp_path, monkeypatch, *, snap_pub):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    regs = _Regs(view)
    ch = regs.own.issue_challenge("acme", HOSTS[0], issued_at=_iss())
    regs.own.verify_and_record("acme", HOSTS[0], method=ao.METHOD_DNS_TXT, observed=[ch.marker], now=1.0,
                               ttl_seconds=1e9)
    regs.mon.grant("acme", HOSTS[0], not_before=0.0, not_after=5000.0, now=2.0, issued_at=_iss())
    regs.promo.grant("ALPHA", "*", issued_at=_iss())
    assert regs.mon.active_at("acme", HOSTS[0], now=10.0) is not None        # warm, unpruned
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=snap_pub, base_seq=k,
                 snapshot_seq=k - 1)
    view.K = k
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    return store, regs, snap


def test_a_seeded_prune_keeps_the_proof_the_grant_and_the_promotion(tmp_path, monkeypatch, no_full_scan):
    store, regs, snap = _pruned(tmp_path, monkeypatch, snap_pub=OWNER_PUB)
    assert snap.ownership_proof_row and snap.monitoring_authority_row and snap.promotion_map()
    regs.store.append(kind="event", source="agent", actor="ALPHA", payload={"decision": "auto"},
                      ts=DAYS[1] + "T01:00:00Z")
    _assert_equivalent(regs, monkeypatch, no_full_scan)
    assert regs.mon.active_at("acme", HOSTS[0], now=10.0) is not None and regs.promo.is_promoted("ALPHA", "x")
    assert regs.own.challenge("acme", HOSTS[0]) is None, "a pruned challenge is re-requested (live window only)"
    assert regs.budget.spent("ALPHA", DAYS[1]).actions == 1


def test_a_foreign_key_reader_of_a_pruned_snapshot_fails_closed(tmp_path, monkeypatch):
    """A PRUNED snapshot folded under a key the reader's owner-key succession does not reach (a swapped key, a
    re-genesis) is never trusted, and an empty start over the deleted prefix is not an answer either: every read
    fails CLOSED, cached and uncached alike."""
    _store, regs, _snap = _pruned(tmp_path, monkeypatch, snap_pub=OWNER_PUB)
    new_owner = generate_keypair()
    reader = _Regs(regs.store, key=new_owner, pub=new_owner.public_key_b64)
    _fails_closed_both_ways(monkeypatch, lambda: reader.promo.is_promoted("ALPHA"),
                            lambda: reader.own.proof("acme", HOSTS[0]), lambda: reader.mon.grants("acme"))


@pytest.mark.parametrize("value", ["", "0", "off"])
def test_flag_off_never_consults_a_cache_here(tmp_path, monkeypatch, value):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", value)

    def boom(*_a, **_kw):
        raise AssertionError("a fold cache was consulted with the flag OFF")

    for c in (pr._PROMOTION_FOLD, bd._BUDGET_FOLD, ao._PROOF_FOLD, ao._CHALLENGE_FOLD, ma._AUTHORITY_FOLD):
        monkeypatch.setattr(c, "read", boom)
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    ch = regs.own.issue_challenge("acme", HOSTS[0], issued_at=_iss())
    regs.own.verify_and_record("acme", HOSTS[0], method=ao.METHOD_DNS_TXT, observed=[ch.marker], now=1.0,
                               ttl_seconds=1e9)
    regs.mon.grant("acme", HOSTS[0], not_before=0.0, not_after=5000.0, now=2.0, issued_at=_iss())
    regs.promo.grant("ALPHA", "*", issued_at=_iss())
    regs.store.append(kind="event", source="agent", actor="ALPHA", payload={"decision": "auto"},
                      ts=DAYS[0] + "T01:00:00Z")
    assert regs.mon.active_at("acme", HOSTS[0], now=10.0) is not None and regs.promo.state_all()
    assert regs.own.assets_overview("acme", now=10.0)[0]["status"] == "verified"
    assert regs.budget.spent("ALPHA", DAYS[0]).actions == 1 and regs.mon.grants("acme")
