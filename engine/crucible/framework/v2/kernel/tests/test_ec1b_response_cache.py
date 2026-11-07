"""EC-1b — L2 deterministic response cache (the biggest AI-cost lever).

A deterministic completion (single-shot, temperature 0, older model) is a pure function of its prompt +
selection, so the second identical call is served from a per-tenant local store at zero tokens. Every
assertion here is deterministic and OFFLINE (no key, no network): a fake backend counts provider calls so a
HIT is proven by the provider NOT being called a second time, and the module-level tests exercise the key /
isolation / TTL / fail-safe contract directly.

Mutation-verify targets (each neuter reds a named test):
  * drop `not is_current_model(model)` from is_deterministic   -> test_determinism_gate_excludes_current_model
  * relax `temperature == 0.0` to `<= 0.2`                     -> test_determinism_gate_excludes_nondeterministic
  * drop org_id from l2_key                                    -> test_cross_org_logical_isolation
  * drop the engagement slug from l2_key                       -> test_cross_engagement_isolation
  * invert / remove the TTL comparison                         -> test_ttl_expiry_is_a_miss
  * skip the re-parse-against-live-schema guard                -> test_unparseable_cached_value_is_a_miss
  * a cache HIT still calls the provider (wiring)              -> test_wiring_hit_skips_the_provider
  * cache a non-deterministic call (wiring)                    -> test_wiring_nondeterministic_is_never_cached
  * drop the store's answering-backend provenance guard        -> test_wiring_failover_result_is_not_cached
  * drop the store's expired-row eviction                      -> test_store_evicts_expired_rows
"""
from __future__ import annotations

import pytest
from pydantic import BaseModel

from framework.v2.common import paths
from framework.v2.kernel import llm, response_cache as rc
from framework.v2.kernel.llm import LLMBackend, LLMResult, Prompt, make_call_trace

_OLD = "claude-3-5-sonnet-20241022"      # older model family: L2-cacheable
_CURRENT = "claude-opus-4-8"             # current-gen: never cacheable (drops temperature for effort)


class S(BaseModel):
    x: int


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    """Each test gets a fresh, isolated crucible root (so a fresh L2 store under the test's tmp dir, never the
    repo) and a clean cache-env + stats. ``crucible_root()`` is an ``lru_cache(maxsize=1)`` that another autouse
    fixture may have already frozen to the repo root, so we RESET the cache AFTER pinning CRUCIBLE_ROOT so the
    next resolution picks up this test's tmp root (and reset again on teardown)."""
    for e in ("CRUCIBLE_TENANT", "CRUCIBLE_CACHE_DISABLE", "CRUCIBLE_L2_DISABLED",
              "CRUCIBLE_L2_TTL_S", "CRUCIBLE_L2_CACHE_VERSION", "CRUCIBLE_EFFORT", "CRUCIBLE_ROOT_STRICT"):
        monkeypatch.delenv(e, raising=False)
    root = tmp_path / "root"
    (root / "framework" / "v2").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("")  # the crucible_root sentinel
    monkeypatch.setenv("CRUCIBLE_ROOT", str(root))
    paths._reset_cache()                 # drop any frozen root so crucible_root() re-resolves to THIS tmp root
    rc._STATS.update(hits=0, misses=0, stores=0)
    yield
    paths._reset_cache()


def _p(system="SYS", user="USR", **kw) -> Prompt:
    d = dict(system=system, user=user, schema=S, schema_name="S", cognitive_doc="doc",
             temperature=0.0, samples=1, max_tokens=100)
    d.update(kw)
    return Prompt(**d)


def _res(x: int, raw: str | None = None, backend: str = "fake") -> LLMResult:
    # ``backend`` is the ANSWERING backend recorded in the trace: the L2 store provenance guard caches a result
    # only when its trace.backend matches the backend the key is built from, so a backend double must record its
    # own name here (not a fixed sentinel) or its fresh completions would be (correctly) refused by that guard.
    return LLMResult(parsed=S(x=x),
                     trace=make_call_trace(backend, is_dryrun=False, cognitive_doc="doc",
                                           cognitive_sections=[], tokens_in=7, tokens_out=2),
                     raw_response=raw if raw is not None else ('{"x": %d}' % x))


def _store(p, x, **scope):
    sc = dict(backend="fake", model=_OLD, tier="t", org_id=None, slug=None)
    sc.update(scope)
    rc.store(p, _res(x), **sc)


def _lookup(p, **scope):
    sc = dict(backend="fake", model=_OLD, tier="t", org_id=None, slug=None)
    sc.update(scope)
    return rc.lookup(p, **sc)


# ---- determinism gate -------------------------------------------------------------------------------
def test_determinism_gate_excludes_current_model():
    assert rc.is_deterministic(_p(), _OLD) is True
    assert rc.is_deterministic(_p(), _CURRENT) is False   # current-gen not determinism-guaranteed


def test_determinism_gate_excludes_nondeterministic():
    assert rc.is_deterministic(_p(temperature=0.2), _OLD) is False   # default sampling temperature
    assert rc.is_deterministic(_p(samples=2), _OLD) is False         # self-consistency: stochastic
    assert rc.is_deterministic(_p(temperature=0.0, samples=1), _OLD) is True


# ---- key purity + sensitivity ----------------------------------------------------------------------
def test_key_is_pure_and_stable():
    p = _p()
    k = rc.l2_key(p, backend="b", model="m", tier="t", org_id="o", slug="s")
    assert k == rc.l2_key(p, backend="b", model="m", tier="t", org_id="o", slug="s")   # no wallclock/rng


def test_key_sensitivity_matrix():
    base = dict(backend="b", model="m", tier="t", org_id="o", slug="s")
    k = rc.l2_key(_p(), **base)
    assert k != rc.l2_key(_p(system="OTHER"), **base)
    assert k != rc.l2_key(_p(user="OTHER"), **base)
    assert k != rc.l2_key(_p(schema_name="T"), **base)
    assert k != rc.l2_key(_p(max_tokens=200), **base)
    assert k != rc.l2_key(_p(structured_input={"a": 1}), **base)

    class S2(BaseModel):
        y: str
    assert k != rc.l2_key(_p(schema=S2), **base)          # a different schema class -> different fingerprint

    for fld, val in (("backend", "B2"), ("model", "M2"), ("tier", "T2"), ("org_id", "o2"), ("slug", "s2")):
        b2 = dict(base)
        b2[fld] = val
        assert k != rc.l2_key(_p(), **b2), f"key not sensitive to {fld}"


def test_key_effort_and_cache_version_salt(monkeypatch):
    base = dict(backend="b", model="m", tier="t", org_id="o", slug="s")
    monkeypatch.setenv("CRUCIBLE_EFFORT", "low")
    klow = rc.l2_key(_p(), **base)
    monkeypatch.setenv("CRUCIBLE_EFFORT", "high")
    assert klow != rc.l2_key(_p(), **base)                # effort is in the key
    monkeypatch.delenv("CRUCIBLE_EFFORT")
    k = rc.l2_key(_p(), **base)
    monkeypatch.setenv("CRUCIBLE_L2_CACHE_VERSION", "2")
    assert k != rc.l2_key(_p(), **base)                   # manual-invalidation salt


# ---- store/lookup roundtrip + hit correctness ------------------------------------------------------
def test_store_lookup_roundtrip_and_hit_shape():
    p = _p()
    assert _lookup(p) is None                             # pre-store miss
    _store(p, 5)
    hit = _lookup(p)
    assert hit is not None and hit.parsed.x == 5
    assert hit.trace.cached is True                       # honest provenance: visibly cached
    assert hit.trace.tokens_in == 0 and hit.trace.tokens_out == 0   # a hit spends nothing
    assert hit.raw_response == '{"x": 5}'
    assert rc.stats()["hits"] == 1 and rc.stats()["stores"] == 1


# ---- isolation: org / engagement / tenant shard ----------------------------------------------------
def test_cross_org_logical_isolation():
    p = _p()
    _store(p, 5, org_id="orgA")
    assert _lookup(p, org_id="orgA") is not None
    assert _lookup(p, org_id="orgB") is None              # org B never sees org A's answer


def test_cross_engagement_isolation():
    p = _p()
    _store(p, 5, slug="engA")
    assert _lookup(p, slug="engA") is not None
    assert _lookup(p, slug="engB") is None                # a cached answer never crosses engagements


def test_cross_tenant_physical_shard(monkeypatch):
    p = _p()
    monkeypatch.setenv("CRUCIBLE_TENANT", "tenantA")
    db_a = paths.cache_l2_db()
    _store(p, 5)
    assert _lookup(p) is not None
    monkeypatch.setenv("CRUCIBLE_TENANT", "tenantB")
    db_b = paths.cache_l2_db()
    assert db_a != db_b                                   # physically disjoint shard files
    assert _lookup(p) is None                             # tenant B's process cannot resolve tenant A's shard


# ---- TTL + unparseable (the stored-value correctness guards) ---------------------------------------
def test_ttl_expiry_is_a_miss(monkeypatch):
    p = _p()
    monkeypatch.setenv("CRUCIBLE_L2_TTL_S", "100")
    clock = [1000.0]
    monkeypatch.setattr(rc.time, "time", lambda: clock[0])
    _store(p, 5)
    assert _lookup(p) is not None                         # within TTL
    clock[0] = 1000.0 + 200.0                             # advance past TTL
    assert _lookup(p) is None                             # expired -> miss (recompute refreshes identically)


def test_store_evicts_expired_rows(monkeypatch):
    # Growth bound: an expired row already reads as a MISS, but store() also DELETES expired rows on each fresh
    # write so the on-disk store cannot grow without bound. Seed a stale row directly, then a fresh store must
    # reap it while keeping the fresh row.
    monkeypatch.setenv("CRUCIBLE_L2_TTL_S", "100")
    clock = [1000.0]
    monkeypatch.setattr(rc.time, "time", lambda: clock[0])
    conn = rc._connect()
    assert conn is not None
    conn.execute(
        "INSERT INTO l2 (key, raw_response, schema_name, backend, model, tokens_in, tokens_out, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        ("stale-key", '{"x": 1}', "S", "fake", _OLD, 0, 0, 800.0),   # age 200 > TTL 100 at clock 1000
    )
    conn.commit()
    conn.close()
    _store(_p(user="FRESH"), 9)                            # a fresh store() triggers eviction (threshold 900)
    conn = rc._connect()
    keys = {r[0] for r in conn.execute("SELECT key FROM l2").fetchall()}
    conn.close()
    assert "stale-key" not in keys                         # the expired row was reaped
    assert len(keys) == 1                                  # only the fresh row remains (bounded to the TTL window)


def test_unparseable_cached_value_is_a_miss():
    # a stored raw that no longer parses against the LIVE prompt.schema is a MISS, never a wrong answer.
    p = _p()
    rc.store(p, _res(0, raw='{"not_x": 1}'), backend="fake", model=_OLD, tier="t", org_id=None, slug=None)
    assert _lookup(p) is None


# ---- kill switch (byte-identical off) --------------------------------------------------------------
def test_kill_switch_disables_lookup_and_store(monkeypatch):
    p = _p()
    _store(p, 5)
    assert _lookup(p) is not None
    monkeypatch.setenv("CRUCIBLE_CACHE_DISABLE", "1")
    assert _lookup(p) is None                             # global kill-switch: no lookup
    _store(_p(user="NEW"), 9)                             # ... and no store
    monkeypatch.delenv("CRUCIBLE_CACHE_DISABLE")
    assert _lookup(_p(user="NEW")) is None                # nothing was written while disabled


def test_l2_specific_disable(monkeypatch):
    monkeypatch.setenv("CRUCIBLE_L2_DISABLED", "1")
    assert rc.l2_disabled() is True
    _store(_p(), 5)
    monkeypatch.delenv("CRUCIBLE_L2_DISABLED")
    assert _lookup(_p()) is None                          # the L2-specific opt-out blocked the store


# ---- wiring: complete_with_backend consults L2 (a HIT skips the provider) ---------------------------
class _CountingBackend(LLMBackend):
    name = "counting"

    def __init__(self, model=_OLD, is_dryrun=False):
        self.model = model
        self._dry = is_dryrun
        self.calls = 0

    def is_available(self):
        return True, "ready"

    @property
    def is_dryrun(self):
        return self._dry

    def complete(self, prompt):
        self.calls += 1
        # record THIS backend as the answerer (trace.backend == self.name) so the store's provenance guard
        # accepts it — a real backend builds its trace the same way (make_call_trace(backend=self.name)).
        return _res(self.calls, backend=self.name)        # a DIFFERENT value each call: a hit serves the first


@pytest.fixture
def _no_gateway(monkeypatch):
    # exercise the L2 wrap on the simple raw path (the L2 lookup/store sit outside the egress chokepoint,
    # so this isolates the cache behaviour from the gateway's classify/redact/audit).
    monkeypatch.setattr(llm, "_gw", None)


def test_wiring_hit_skips_the_provider(_no_gateway):
    be = _CountingBackend()
    p = _p()
    r1 = llm.complete_with_backend(be, p)
    r2 = llm.complete_with_backend(be, p)                 # identical deterministic prompt
    assert be.calls == 1                                  # the provider was NOT called a second time
    assert r1.parsed.x == 1 and r2.parsed.x == 1          # the cached (first) value is served
    assert r2.trace.cached is True


def test_wiring_nondeterministic_is_never_cached(_no_gateway):
    be = _CountingBackend()
    p = _p(temperature=0.2)                               # default sampling temperature: not deterministic
    llm.complete_with_backend(be, p)
    llm.complete_with_backend(be, p)
    assert be.calls == 2                                  # every call hits the provider; nothing cached


def test_wiring_current_model_is_never_cached(_no_gateway):
    be = _CountingBackend(model=_CURRENT)                 # current-gen: not determinism-guaranteed
    p = _p()
    llm.complete_with_backend(be, p)
    llm.complete_with_backend(be, p)
    assert be.calls == 2


def test_wiring_dryrun_is_never_cached(_no_gateway):
    be = _CountingBackend(is_dryrun=True)
    p = _p()
    llm.complete_with_backend(be, p)
    llm.complete_with_backend(be, p)
    assert be.calls == 2                                  # a dry-run result is never cached


def test_wiring_kill_switch_byte_identical(_no_gateway, monkeypatch):
    monkeypatch.setenv("CRUCIBLE_CACHE_DISABLE", "1")
    be = _CountingBackend()
    p = _p()
    llm.complete_with_backend(be, p)
    llm.complete_with_backend(be, p)
    assert be.calls == 2                                  # kill-switch: byte-identical to no-L2


def test_wiring_ephemeral_session_disables_l2(_no_gateway, monkeypatch):
    # a ZDR / --ephemeral session must not persist prompts/responses to disk, so L2 is OFF.
    monkeypatch.setattr(llm, "_ephemeral_session_active", lambda: True)
    be = _CountingBackend()
    p = _p()
    llm.complete_with_backend(be, p)
    llm.complete_with_backend(be, p)
    assert be.calls == 2


def test_wiring_failover_hit_survives_budget_clamp(_no_gateway, monkeypatch):
    # The per-tool budget clamp mutates prompt.max_tokens for the provider call. L2 must key the STORE on the
    # ORIGINAL request (as the lookup does) so a deterministic call still HITS under budget pressure — otherwise
    # the clamp silently defeats the cache exactly when cost-saving matters most. (Failover path: get_backend().)
    be = _CountingBackend()
    monkeypatch.setattr(llm, "get_backend", lambda *a, **k: be)
    monkeypatch.setattr(llm, "_tb_clamp", lambda tool, mx: min(int(mx), 50))   # a tight clamp (100 -> 50)
    llm.complete_with_failover(_p(max_tokens=100))
    r2 = llm.complete_with_failover(_p(max_tokens=100))
    assert be.calls == 1 and r2.trace.cached is True    # HIT despite the clamp (keyed on the original max_tokens)


def test_wiring_failover_result_is_not_cached(_no_gateway, monkeypatch):
    # complete_with_failover builds the L2 key from the PRIMARY (get_backend()), but on a transient overload it
    # may fail over IN-TIER to a SECONDARY backend. Caching that answer under the primary's key would
    # mis-provenance the store — and a current-gen secondary is NOT determinism-guaranteed — so a failover
    # result is NEVER cached. Simulate it by having the routed call report a different answering backend than
    # the primary the key is keyed on; the second identical call must therefore re-route (not HIT).
    primary = _CountingBackend(model=_OLD)
    primary.name = "primary"                              # the backend the key is built from
    monkeypatch.setattr(llm, "get_backend", lambda *a, **k: primary)
    routed = [0]

    def _failover_egress(prompt):
        routed[0] += 1
        return _res(routed[0], backend="secondary-overload-failover")   # a DIFFERENT backend answered

    monkeypatch.setattr(llm, "_route_urk_egress", _failover_egress)
    llm.complete_with_failover(_p())
    llm.complete_with_failover(_p())                      # identical deterministic prompt
    assert routed[0] == 2                                 # the second call was NOT served from cache (no store)
    assert rc.stats()["stores"] == 0                      # the failover result was never persisted
