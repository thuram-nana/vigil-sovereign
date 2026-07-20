"""
IntelIngest (the single writer), the ReconPlanner (VOI over collectors), the durable
store, and the egress gate. The end-to-end offline test reproduces the Phase-A worked
example — api + backend + 10.15.4.2 + cert xyz → one asset owned by AS64501 — but this
time DISCOVERED by collectors from a single apex seed, not hand-fed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.intel.collectors import DEFAULT_COLLECTORS, DnsCollector
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import IntelSourceKind, Observation
from framework.v2.intel.planner import ReconPlanner
from framework.v2.intel.refs import canonicalize
from framework.v2.intel.store import IntelStore
from framework.v2.intel.transport import (
    CollectorEgressRefused,
    FixtureTransport,
    GuardedHttpTransport,
    RawRecord,
)
from framework.v2.memory.store import open_store
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind, NodeKind


class _RecordingClient:
    """A stand-in httpx client that records every .get() — lets us prove the egress
    guard checks the host BEFORE any network call (no bytes leave on refusal)."""

    def __init__(self, status: int = 200, payload=None) -> None:
        self.calls: list[str] = []
        self._status = status
        self._payload = payload if payload is not None else {}

    def get(self, url: str):
        self.calls.append(url)
        return _Resp(self._status, self._payload)


class _Resp:
    def __init__(self, status: int, payload) -> None:
        self.status_code = status
        self._p = payload
        self.text = ""

    def json(self):
        return self._p

_FIX = Path(__file__).resolve().parents[1] / "collectors" / "fixtures"


def _transport() -> FixtureTransport:
    return FixtureTransport(_FIX)


# ---- IntelIngest: the single writer -----------------------------------------


def test_ingest_projects_and_resolves() -> None:
    world = WorldModel()
    ing = IntelIngest(world)
    obs = DnsCollector().collect(canonicalize(NodeKind.DOMAIN, "backend.company.com"),
                                 _transport(), seq=1)
    res = ing.ingest(obs)
    assert res.applied >= 1
    # projection happened: the world-model carries the belief
    assert world.get_node("domain:backend.company.com") is not None
    assert world.get_node("host:10.15.4.2") is not None


def test_run_collectors_reproduces_worked_example_offline() -> None:
    world = WorldModel()
    ing = IntelIngest(world)
    res = ing.run_collectors(
        [canonicalize(NodeKind.DOMAIN, "company.com")],
        list(DEFAULT_COLLECTORS), _transport(), seq=0, max_depth=2)

    owned = [e for e in res.entities if e.owned_by]
    assert len(owned) == 1, [e.canonical_id for e in res.entities]
    e = owned[0]
    assert e.canonical_id == "ent:domain:api.company.com"
    assert {m.node_id for m in e.members} == {
        "domain:api.company.com", "domain:backend.company.com",
        "host:10.15.4.2", "certificate:xyz"}
    assert e.owned_by == ["asn:AS64501"]
    # www split off into its own cluster (dedicated cert, no shared infra)
    assert any(x.canonical_id == "ent:domain:www.company.com" for x in res.entities)


def test_ingest_persists_and_round_trips(tmp_path: Path) -> None:
    db = tmp_path / "mls.sqlite"
    store = open_store(db)
    istore = IntelStore(store)
    world = WorldModel()
    ing = IntelIngest(world, store=istore, engagement_slug="acme")
    ing.run_collectors([canonicalize(NodeKind.DOMAIN, "company.com")],
                       list(DEFAULT_COLLECTORS), _transport(), seq=0, max_depth=2)

    assert istore.observation_count(engagement_slug="acme") > 0
    ents = istore.entities(engagement_slug="acme")
    assert any(e.owned_by for e in ents)
    # flattened membership reverse-lookup works
    assert istore.entity_for_node("host:10.15.4.2", engagement_slug="acme") == "ent:domain:api.company.com"
    store.close()


def test_reingest_is_idempotent() -> None:
    world = WorldModel()
    ing = IntelIngest(world)
    seeds = [canonicalize(NodeKind.DOMAIN, "company.com")]
    r1 = ing.run_collectors(seeds, list(DEFAULT_COLLECTORS), _transport(), seq=0, max_depth=2)
    # a fresh ingest of the same substrate resolves to the same clustering
    world2 = WorldModel()
    r2 = IntelIngest(world2).run_collectors(seeds, list(DEFAULT_COLLECTORS), _transport(), seq=0, max_depth=2)
    assert {e.canonical_id for e in r1.entities} == {e.canonical_id for e in r2.entities}


def _node_obs(oid: str, dom: str, seq: int = 1) -> Observation:
    return Observation(obs_id=oid, source="dns", source_kind=IntelSourceKind.DNS,
                       subject=canonicalize(NodeKind.DOMAIN, dom), confidence=0.9, seq=seq)


def _same_as(oid: str, a: str, b: str, seq: int = 1) -> Observation:
    return Observation(obs_id=oid, source="dns", source_kind=IntelSourceKind.DNS,
                       subject=canonicalize(NodeKind.DOMAIN, a), relation=EdgeKind.SAME_AS,
                       object=canonicalize(NodeKind.DOMAIN, b), confidence=0.92, seq=seq)


def test_reingest_same_batch_is_noop() -> None:
    # re-ingesting identical observations must not re-project (false corroboration) or
    # re-accumulate (double-counted SAME_AS/ANNOUNCES).
    world = WorldModel()
    ing = IntelIngest(world)
    batch = [_node_obs("o1", "api.acme.com")]
    ing.ingest(batch)
    b1 = world.get_node("domain:api.acme.com").belief_mean
    res2 = ing.ingest(batch)   # same obs_id again
    b2 = world.get_node("domain:api.acme.com").belief_mean
    assert res2.applied == 0 and abs(b1 - b2) < 1e-12   # belief unchanged — a true no-op


def test_incremental_reingest_gcs_superseded_entities(tmp_path: Path) -> None:
    # domB is a singleton entity after ingest 1; ingest 2 merges domA≡domB (CNAME), so
    # the old ent:domain:domB canonical_id must be GARBAGE-COLLECTED, not left a phantom.
    store = open_store(tmp_path / "mls.sqlite")
    istore = IntelStore(store)
    ing = IntelIngest(WorldModel(), store=istore, engagement_slug="e")
    ing.ingest([_node_obs("o1", "beta.acme.com")])
    assert {e.canonical_id for e in istore.entities(engagement_slug="e")} == {"ent:domain:beta.acme.com"}
    ing.ingest([_same_as("o2", "alpha.acme.com", "beta.acme.com")])   # merges → one cluster
    ids = {e.canonical_id for e in istore.entities(engagement_slug="e")}
    assert ids == {"ent:domain:alpha.acme.com"}, ids          # phantom beta singleton GC'd
    assert istore.entity_for_node("domain:beta.acme.com", engagement_slug="e") == "ent:domain:alpha.acme.com"
    store.close()


def test_run_collectors_seed_order_independent() -> None:
    seeds_a = [canonicalize(NodeKind.DOMAIN, "company.com"),
               canonicalize(NodeKind.DOMAIN, "other.example")]
    seeds_b = list(reversed(seeds_a))
    r1 = IntelIngest(WorldModel()).run_collectors(seeds_a, list(DEFAULT_COLLECTORS), _transport(), max_depth=2)
    r2 = IntelIngest(WorldModel()).run_collectors(seeds_b, list(DEFAULT_COLLECTORS), _transport(), max_depth=2)
    assert {e.canonical_id for e in r1.entities} == {e.canonical_id for e in r2.entities}


# ---- ReconPlanner: value-of-information -------------------------------------


def test_planner_ranks_by_eig_per_cost_deterministically() -> None:
    planner = ReconPlanner(list(DEFAULT_COLLECTORS))
    subj = canonicalize(NodeKind.DOMAIN, "company.com")
    p1 = planner.plan([subj])
    p2 = planner.plan([subj])
    assert p1.model_dump() == p2.model_dump()          # deterministic
    # only DOMAIN-accepting collectors appear (ASN takes host/netblock/asn)
    assert {t.source_kind for t in p1.tasks} == {
        IntelSourceKind.DNS, IntelSourceKind.CERT_TRANSPARENCY, IntelSourceKind.RDAP_WHOIS}
    # sorted descending by eig_per_cost
    vals = [t.eig_per_cost for t in p1.tasks]
    assert vals == sorted(vals, reverse=True)


def test_planner_voi_is_not_greedy_on_prior() -> None:
    # A near-certain source has little left to learn: it must score BELOW an
    # uncertain one even though the certain one has a higher raw prior.
    planner = ReconPlanner(list(DEFAULT_COLLECTORS))
    subj = canonicalize(NodeKind.DOMAIN, "company.com")
    plan = planner.plan([subj], priors={"cert_transparency": 0.98, "dns": 0.5})
    ct = next(t for t in plan.tasks if t.source_kind is IntelSourceKind.CERT_TRANSPARENCY)
    dns = next(t for t in plan.tasks if t.source_kind is IntelSourceKind.DNS)
    assert dns.eig_bits > ct.eig_bits


def test_planner_damps_already_run_tasks() -> None:
    planner = ReconPlanner(list(DEFAULT_COLLECTORS))
    subj = canonicalize(NodeKind.DOMAIN, "company.com")
    fresh = planner.plan([subj])
    ran = planner.plan([subj], already_run={("domain:company.com", "cert_transparency")})
    ct_fresh = next(t for t in fresh.tasks if t.collector == "cert_transparency")
    ct_ran = next(t for t in ran.tasks if t.collector == "cert_transparency")
    assert ct_ran.eig_bits < ct_fresh.eig_bits


# ---- egress gate ------------------------------------------------------------


def test_guarded_transport_refuses_host_off_allowlist() -> None:
    # endpoint host is NOT in collector_hosts → refused before any network call
    t = GuardedHttpTransport(
        collector_hosts=("crt.sh",),
        endpoints={IntelSourceKind.CERT_TRANSPARENCY: "https://evil.example/?q={query}"})
    with pytest.raises(CollectorEgressRefused):
        t.fetch(IntelSourceKind.CERT_TRANSPARENCY, "company.com", seq=1)


def test_guarded_transport_permits_allowlisted_host_and_calls_once() -> None:
    # positive control: an ALLOWLISTED host is permitted, returns ok, and hits the
    # network exactly once (guards against a regression that refuses everything).
    client = _RecordingClient(status=200, payload=[{"fingerprint": "z", "names": ["api.company.com"]}])
    t = GuardedHttpTransport(
        collector_hosts=("crt.sh",),
        endpoints={IntelSourceKind.CERT_TRANSPARENCY: "https://crt.sh/?q={query}"},
        client=client)
    rec = t.fetch(IntelSourceKind.CERT_TRANSPARENCY, "company.com", seq=1)
    assert rec.ok is True and len(client.calls) == 1


def test_guarded_transport_no_bytes_leave_on_refusal() -> None:
    # the host check must happen BEFORE any network call — on refusal client.get is
    # never invoked (this is the load-bearing "before bytes leave" property).
    client = _RecordingClient()
    t = GuardedHttpTransport(
        collector_hosts=("crt.sh",),
        endpoints={IntelSourceKind.CERT_TRANSPARENCY: "https://evil.example/?q={query}"},
        client=client)
    with pytest.raises(CollectorEgressRefused):
        t.fetch(IntelSourceKind.CERT_TRANSPARENCY, "company.com", seq=1)
    assert client.calls == []


def test_guarded_transport_rejects_collector_target_overlap() -> None:
    # recon sources must be disjoint from target scope — construction refuses overlap.
    with pytest.raises(CollectorEgressRefused):
        GuardedHttpTransport(
            collector_hosts=("app.target.com",),
            endpoints={IntelSourceKind.DNS: "https://app.target.com/{query}"},
            target_hosts=("*.target.com",))
    # a genuinely third-party source constructs fine
    GuardedHttpTransport(collector_hosts=("crt.sh",), endpoints={},
                         target_hosts=("app.target.com",))


def test_collector_scope_conflicts_helper() -> None:
    from framework.v2.agents.egress_guard import collector_scope_conflicts
    assert collector_scope_conflicts(("crt.sh",), ("app.target.com",)) == []
    assert collector_scope_conflicts(("app.target.com",), ("*.target.com",)) == ["app.target.com"]
    assert collector_scope_conflicts(("app.target.com",), ("app.target.com",)) == ["app.target.com"]


def test_guarded_transport_requires_nonempty_allowlist() -> None:
    from framework.v2.common.errors import CrucibleError
    with pytest.raises(CrucibleError):
        GuardedHttpTransport(collector_hosts=(), endpoints={})


def test_egress_allowlist_collector_hosts_additive() -> None:
    from framework.v2.agents.egress_guard import EgressAllowlist
    allow = EgressAllowlist(target_hosts=("app.target.com",), collector_hosts=("crt.sh",))
    assert allow.permits("crt.sh")
    assert allow.permits("app.target.com")
    assert not allow.permits("evil.example")
    assert "crt.sh" in allow.all_entries()


# ---- schema migration -------------------------------------------------------


def test_migration_2_creates_intel_tables(tmp_path: Path) -> None:
    from framework.v2.memory import migrate
    store = open_store(tmp_path / "mls.sqlite")
    assert migrate.get_meta(store.conn, "version") == "2"
    tables = {r[0] for r in store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"intel_observations", "intel_entities", "intel_entity_members",
            "intel_merge_log", "intel_source_yield"} <= tables
    store.close()
