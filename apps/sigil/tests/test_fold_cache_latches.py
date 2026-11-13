"""Front C S0d — the governed-action latches and the remaining request-path scans on the verified fold cache:

  * the KILL SWITCH (`Governor.decide` reads it on every governed action) and the CAPABILITY gate (the autolearn
    / gesture / voice actions). Both already cached their verdict on the store's change token, but that token
    moves on EVERY append, so under load each check re-scanned the spine; the fold cache extends instead;
  * the customer ASSESSMENTS views (findings / outcomes / summary), indexed per engagement slug;
  * the EC-6 margin view's owner-signed SETTLE stream;
  * the ownership CHALLENGE read, now a `live_window` read (its full scan never loads the snapshot, so a snapshot
    that cannot be loaded makes the cache decline, never raise).

Every test compares the CACHED public API against the SAME API with the flag OFF over the same spine, and checks
that a cached read never fell back to a full scan. The generic trust-model cases are proven on the shared
substrate in `test_fold_cache_customers.py`.
"""
from __future__ import annotations

import itertools
import random
import sys

import pytest

from sigil.governor import asset_ownership as ao
from sigil.governor import capability as cp
from sigil.governor import cost_ledger as cl
from sigil.governor import key_history as kh
from sigil.governor import killswitch as ks
from sigil.governor.authn import signed_payload
from sigil.governor.identity import ensure_owner_keypair
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineError, SpineStore
from sigil.ui import assessments as am
from sigil.ui import margin as mg
from sigil.ui.target_authorization import _customer_slug
from test_spine_store_integrity import write_chained_line

ATTACKER = generate_keypair()
ORGS = ["acme", "globex"]
HOSTS = ["a.example.com", "b.example.com"]
CAPS = sorted(cp.CAPABILITIES)
NOWS = [10.0, 1e10]
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
    """Every registry here trusts the PERSISTED owner key, as in production: the assessments views build their own
    ownership registry under it (one trust root per process — two would only make the per-fold entry rebuild)."""

    def __init__(self, store, key=None):
        key = key if key is not None else ensure_owner_keypair()
        pub = key.public_key_b64
        kw = {"owner_key": key, "trusted_pubkey": pub}
        self.store, self.key, self.pub = store, key, pub
        self.kill = ks.KillSwitch(store, **kw)
        self.caps = cp.CapabilityGate(store, **kw)
        self.own = ao.AssetOwnershipRegistry(store, **kw)
        self.cost = cl.CostEnvelopeLedger(store, **kw)


@pytest.fixture
def no_full_scan(monkeypatch):
    """Counts full scans: every signed full fold builds the memoized owner-key resolver, and the assessments /
    challenge scans read the whole live window (`since_seq < 0`). The fold cache's own (re)build reads it too
    — a cold start, or a legitimate rebuild after a prune — so a scan made from inside the cache is not one."""
    calls = {"n": 0}
    real_resolver, real_iter = kh.key_resolver, SpineStore.iter_records

    def spy_resolver(*a, **kw):
        calls["n"] += 1
        return real_resolver(*a, **kw)

    def from_the_cache() -> bool:
        f = sys._getframe(2)
        while f is not None:
            if f.f_code.co_filename.endswith(("fold_cache.py", "key_history.py")):
                return True
            f = f.f_back
        return False

    def spy_iter(self, *, since_seq=-1):
        if since_seq < 0 and not from_the_cache():
            calls["n"] += 1
        return real_iter(self, since_seq=since_seq)

    monkeypatch.setattr(kh, "key_resolver", spy_resolver)
    monkeypatch.setattr(SpineStore, "iter_records", spy_iter)
    return calls


def _answers(regs):
    out = {"engaged": regs.kill.is_engaged(), "caps": regs.caps.state_all(),
           "settles": mg._settle_events(regs.store, regs.pub)}
    for c in CAPS:
        out[("enabled", c)] = regs.caps.is_enabled(c)
    for o in ORGS + ["nope"]:
        for h in HOSTS:
            out[("challenge", o, h)] = regs.own.challenge(o, h)
        for now in NOWS:
            out[("findings", o, now)] = am.assessment_findings(regs.store, o, now=now, limit=3)
            out[("outcomes", o, now)] = am.assessment_outcomes(regs.store, o, now=now)
            out[("summary", o, now)] = am.assessment_summary(regs.store, o, now=now)
    return out


def _assert_equivalent(regs, monkeypatch, no_full_scan=None):
    before = no_full_scan["n"] if no_full_scan is not None else 0
    cached = _answers(regs)
    if no_full_scan is not None:
        assert no_full_scan["n"] == before, "a cached read fell back to a full scan"
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    try:
        full = _answers(regs)
    finally:
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    assert cached == full


def _raw(store, payload, kind="event"):
    return store.append(kind=kind, source="governor", actor="WARDEN", payload=payload)


def _prove(regs, o, h, *, now=1.0, ttl=1e9):
    ch = regs.own.issue_challenge(o, h, issued_at=_iss())
    regs.own.verify_and_record(o, h, method=ao.METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=ttl)


def _finding(store, slug, i):
    cert = {"engagement_slug": slug, "finding_ref": f"f{i}", "severity": "high", "title": f"t{i}",
            "nested": {"evidence": [i]}}
    return store.append(kind="finding", source="receiver", actor="oracle", payload={"certificate": cert})


@pytest.mark.parametrize("seed", [61, 62, 63])
def test_randomized_equivalence_with_the_full_scans(tmp_path, seed, monkeypatch, no_full_scan):
    rng = random.Random(seed)
    path = str(tmp_path / "spine.jsonl")
    store, other = SpineStore(path), SpineStore(path)
    regs, regs_other = _Regs(store), _Regs(other)
    for o in ORGS:                                  # one proven host per org, so the assessment views have slugs
        _prove(regs, o, HOSTS[0])
    slugs = [_customer_slug(o, h) for o in ORGS for h in HOSTS] + ["someone-else"]
    captured: list = []
    for step in range(70):
        o, h, c = rng.choice(ORGS), rng.choice(HOSTS), rng.choice(CAPS)
        r = regs_other if rng.random() < 0.2 else regs
        op = rng.choice(["engage", "release", "stale_release", "disable", "enable", "stale_enable", "challenge",
                         "prove", "unchallenge", "finding", "finding", "outcome", "bad_finding", "settle", "replay",
                         "forged", "noise"])
        seq = None
        try:
            if op == "engage":
                seq = r.kill.engage(reason="test")
            elif op == "release":
                seq = r.kill.release(issued_at=_iss())
            elif op == "stale_release":            # owner-signed, OLDER than any honored release: refused
                seq = _raw(store, signed_payload({"signal": ks.SIGNAL, "state": "released", "issued_at": 0.5}, regs.key))
            elif op == "disable":
                seq = r.caps.disable(c)
            elif op == "enable":
                seq = r.caps.enable(c, issued_at=_iss())
            elif op == "stale_enable":
                seq = _raw(store, signed_payload({"signal": cp.SIGNAL, "capability": c, "state": "enabled",
                                                  "issued_at": 0.5}, regs.key))
            elif op == "challenge":
                r.own.issue_challenge(o, h, issued_at=_iss(), token=f"tok-{step}")
            elif op == "prove":
                _prove(r, o, h, ttl=rng.choice([5.0, 1e9]))
            elif op == "unchallenge":
                _raw(store, {"signal": ao.CHALLENGE_SIGNAL, "org_id": o, "host": h, "state": "revoked"})
            elif op == "finding":
                _finding(store, rng.choice(slugs), step)
            elif op == "outcome":
                store.append(kind="assessment_outcome", source="jobs", actor="runner",
                             payload={"engagement_slug": rng.choice(slugs), "outcome": "completed",
                                      "nonce": f"n{step}", "ts": "2026-11-11T00:00:00Z"})
            elif op == "bad_finding":              # not a dict certificate / not a dict payload: never indexed
                store.append(kind="finding", source="receiver", actor="oracle",
                             payload=rng.choice([{"certificate": "x"}, {"no": "cert"}]))
            elif op == "settle":
                seq = r.cost.settle(o, rng.randint(0, 90), entry_id=rng.choice(["settle-cost:s:1", "settle-cost:s:2"]),
                                    issued_at=_iss())
            elif op == "replay" and captured:
                _raw(store, rng.choice(captured))
            elif op == "forged":
                core = rng.choice([{"signal": ks.SIGNAL, "state": "released", "issued_at": _iss() + 1e6},
                                   {"signal": cp.SIGNAL, "capability": c, "state": "enabled", "issued_at": _iss() + 1e6},
                                   {"signal": cl.COST_SETTLE_SIGNAL, "org_id": o, "entry_id": f"settle-cost:f{step}",
                                    "tokens": 10**6, "engagement_id": "", "issued_at": _iss()}])
                _raw(store, signed_payload(core, ATTACKER))
            else:
                store.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": step})
        except ValueError:
            pass
        if seq is not None:
            captured.append(store.get(seq).payload)
        _assert_equivalent(regs, monkeypatch, no_full_scan)
    assert ks._KILLSWITCH_FOLD._entries and cp._CAPABILITY_FOLD._entries and am._ASSESSMENTS_FOLD._entries
    assert mg._SETTLE_FOLD._entries and ao._CHALLENGE_FOLD._entries


def test_the_latches_stay_warm_while_the_spine_is_appended_to(tmp_path, monkeypatch):
    """The change-token cache the kill switch and capability gate had re-scanned after ANY append; the fold cache
    verifies only what is new — and a release / enable still lands the moment it is appended."""
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    regs.kill.engage()
    regs.kill.release(issued_at=_iss())
    regs.caps.disable("voice")
    count = {"n": 0}
    for mod in (ks, cp):
        real = mod.verify_signed

        def counting(*a, _real=real, **kw):
            count["n"] += 1
            return _real(*a, **kw)

        monkeypatch.setattr(mod, "verify_signed", counting)
    assert not regs.kill.is_engaged() and not regs.caps.is_enabled("voice")
    count["n"] = 0
    for i in range(20):                                   # unrelated appends: the token moves every time
        regs.store.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": i})
        assert not regs.kill.is_engaged() and not regs.caps.is_enabled("voice") and regs.caps.is_enabled("gesture")
    assert count["n"] == 0, "unrelated appends must not re-verify the latches"
    regs.kill.engage()
    assert regs.kill.is_engaged() and count["n"] == 0, "an engage halts on sight, unsigned-path"
    regs.caps.enable("voice", issued_at=_iss())
    assert regs.caps.is_enabled("voice") and count["n"] == 1   # only the enable is verified, once
    regs.kill.release(issued_at=_iss())
    assert not regs.kill.is_engaged() and count["n"] == 2


def test_a_corrupt_record_fails_the_capability_gate_closed_in_both_paths(tmp_path, monkeypatch):
    """A record the fold cannot read: the capability gate answers DISABLED (fail-closed) and the kill switch
    raises — with the flag on exactly as with it off, and the error is never cached."""
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    assert regs.caps.is_enabled("voice") and not regs.kill.is_engaged()       # warm
    with pytest.raises(SpineError, match="payload is not a JSON object"):     # no append can write it ...
        regs.store.append(kind="event", source="t", actor="u", payload=["not", "a", "dict"])
    write_chained_line(regs.store, ["not", "a", "dict"], kind="event", source="t", actor="u")   # ... a hand edit can
    for flag in ("1", ""):
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
        assert regs.caps.is_enabled("voice") is False
        with pytest.raises(AttributeError):
            regs.kill.is_engaged()


def test_live_window_reads_decline_when_the_snapshot_cannot_load(tmp_path, monkeypatch):
    """The challenge and assessments scans never load the snapshot, so they keep answering when it cannot be
    loaded; the cache declines (no raise). The seeded folds raise exactly as their full folds do."""
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    _prove(regs, "acme", HOSTS[0])
    regs.own.issue_challenge("acme", HOSTS[1], issued_at=_iss(), token="tok-x")
    expected = regs.own.challenge("acme", HOSTS[1])
    assert expected is not None                                               # warm

    def broken(cls, store):
        raise RuntimeError("unverifiable prune head")

    monkeypatch.setattr(SnapshotState, "load", classmethod(broken))
    assert regs.own.challenge("acme", HOSTS[1]) == expected
    with pytest.raises(RuntimeError):
        regs.kill.is_engaged()
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    with pytest.raises(RuntimeError):
        regs.kill.is_engaged()
    assert regs.own.challenge("acme", HOSTS[1]) == expected


def test_an_unhashable_slug_falls_back_to_the_scan_and_raises_where_it_did(tmp_path, monkeypatch):
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    _prove(regs, "acme", HOSTS[0])
    slug = _customer_slug("acme", HOSTS[0])
    _finding(regs.store, slug, 1)
    assert am.assessment_findings(regs.store, "acme", now=10.0)["count"] == 1    # warm
    regs.store.append(kind="finding", source="receiver", actor="oracle",
                      payload={"certificate": {"engagement_slug": ["not", "hashable"]}})
    for flag in ("1", ""):
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
        with pytest.raises(TypeError):
            am.assessment_findings(regs.store, "acme", now=10.0)
        assert am.assessment_findings(regs.store, "globex", now=10.0)["count"] == 0   # no slugs: no scan


def test_findings_are_returned_as_copies(tmp_path):
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    _prove(regs, "acme", HOSTS[0])
    _finding(regs.store, _customer_slug("acme", HOSTS[0]), 1)
    first = am.assessment_findings(regs.store, "acme", now=10.0)["findings"][0]
    first["title"] = "tampered"
    first["nested"] = {"evidence": ["tampered"]}
    again = am.assessment_findings(regs.store, "acme", now=10.0)["findings"][0]
    assert again["title"] == "t1", "a caller mutating its page must never reach the cached index"


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

    def change_token(self):
        return self._inner.change_token()


def _pruned(tmp_path, monkeypatch):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    regs = _Regs(view)
    regs.kill.engage()
    regs.caps.disable("voice")
    regs.caps.enable("voice", issued_at=_iss())
    regs.caps.disable("gesture")
    st = regs.cost.settle("acme", 40, entry_id="settle-cost:s:1", issued_at=_iss())
    captured = store.get(st).payload
    assert regs.kill.is_engaged()                                              # warm, unpruned
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=regs.pub, base_seq=k,
                 snapshot_seq=k - 1)
    view.K = k
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    return store, regs, snap, captured


def test_a_seeded_prune_keeps_the_latches_and_the_consumed_settles(tmp_path, monkeypatch, no_full_scan):
    store, regs, snap, captured = _pruned(tmp_path, monkeypatch)
    assert snap.killswitch_engaged and snap.capability_latch_map()
    _raw(store, captured)                                  # a pruned settle replayed live: not a new event
    _assert_equivalent(regs, monkeypatch, no_full_scan)
    assert regs.kill.is_engaged() and regs.caps.is_enabled("voice") and not regs.caps.is_enabled("gesture")
    assert mg._settle_events(regs.store, regs.pub) == {}


def test_the_pubkey_bypass_folds_the_live_window_only(tmp_path, monkeypatch, no_full_scan):
    _store, regs, _snap, _captured = _pruned(tmp_path, monkeypatch)
    reader = _Regs(regs.store, key=generate_keypair())
    _assert_equivalent(reader, monkeypatch, no_full_scan)
    assert not reader.kill.is_engaged() and reader.caps.is_enabled("gesture")


@pytest.mark.parametrize("value", ["", "0", "off"])
def test_flag_off_never_consults_a_cache_here(tmp_path, monkeypatch, value):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", value)

    def boom(*_a, **_kw):
        raise AssertionError("a fold cache was consulted with the flag OFF")

    for c in (ks._KILLSWITCH_FOLD, cp._CAPABILITY_FOLD, am._ASSESSMENTS_FOLD, mg._SETTLE_FOLD, ao._CHALLENGE_FOLD):
        monkeypatch.setattr(c, "read", boom)
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    regs.kill.engage()
    regs.caps.disable("voice")
    _prove(regs, "acme", HOSTS[0])
    _finding(regs.store, _customer_slug("acme", HOSTS[0]), 1)
    regs.cost.settle("acme", 5, entry_id="settle-cost:s:1", issued_at=_iss())
    assert regs.kill.is_engaged() and not regs.caps.is_enabled("voice")
    assert regs.own.challenge("acme", HOSTS[0]) is not None
    assert am.assessment_summary(regs.store, "acme", now=10.0)["assessments"][0]["findings"] == 1
    assert mg._settle_events(regs.store, regs.pub)["acme"][0][1] == 5
