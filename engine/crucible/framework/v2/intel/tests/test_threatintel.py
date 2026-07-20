"""
Threat-intel sensors (Wave 5c): offline MISP / STIX 2.x / NVD / OSV feeds → IOC + CVE
observations that project onto the ONE world-model as LEADS (never facts), correlate to
existing assets/packages, carry an exploit-exists signal, and degrade gracefully.

The tests prove the doctrine, not just the happy path:
  * PROVE-DON'T-GUESS — everything minted is GROUNDING_INTEL at a sub-fact belief; no FINDING.
  * CORRELATION — a CVE lands its AFFECTS edge on an existing SBOM node; an IOC corroborates
    (AFFIRMS) or refutes (REFUTES) an in-scope asset through the Beta channel.
  * UNTRUSTED INPUT — malformed feeds yield [] (never raise); the STIX pattern is read, not run.
  * DETERMINISM — claim-keyed obs_ids make re-ingest idempotent.
  * GATING — the live pull refuses target overlap / off-allowlist egress; offline is default.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.intel.from_sbom import observations_from_sbom
from framework.v2.intel.from_threatintel import (
    build_threatintel_live_transport,
    detect_format,
    live_cve_observations,
    observations_from_cve,
    observations_from_misp,
    observations_from_stix,
    observations_from_threat_feed,
)
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.live import normalize_response
from framework.v2.intel.models import IntelSourceKind, Observation, Polarity
from framework.v2.intel.project import project_observation
from framework.v2.intel.refs import canonicalize
from framework.v2.intel.transport import CollectorEgressRefused
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import (
    GROUNDING_GROUNDED,
    GROUNDING_INTEL,
    EdgeKind,
    NodeKind,
    classify_provenance,
)

_FIX = Path(__file__).resolve().parent / "fixtures" / "threatintel"


def _load(name: str) -> dict:
    return json.loads((_FIX / name).read_text(encoding="utf-8"))


def _ids(obs: list[Observation]) -> set[str]:
    return {o.subject.node_id for o in obs} | {o.object.node_id for o in obs if o.object}


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------


def test_misp_mints_expected_ioc_kinds() -> None:
    obs = observations_from_misp(_load("misp_event.json"), seq=1)
    ids = _ids(obs)
    assert "domain:phish-evil.example" in ids            # domain IOC
    assert "host:203.0.113.9" in ids                     # ip IOC → HOST
    assert "identity:attacker@phish-evil.example" in ids  # email → IDENTITY
    assert "vulnerability:CVE-2021-44228" in ids          # vulnerability attr → VULNERABILITY node
    # a hash IOC becomes an INDICATOR node (no asset kind fits a file hash)
    assert any(i.startswith("indicator:sha256:") for i in ids)
    assert any(i.startswith("indicator:md5:") for i in ids)  # from the nested Object
    # the URL IOC lands on its host and carries the raw url in attrs
    url_obs = next(o for o in obs if o.attrs.get("ioc_type") == "url")
    assert url_obs.subject.node_id == "domain:phish-evil.example"
    assert url_obs.attrs["url"].startswith("http://phish-evil.example")


def test_misp_false_positive_refutes() -> None:
    obs = observations_from_misp(_load("misp_event.json"), seq=1)
    fp = next(o for o in obs if o.subject.node_id == "domain:benign-not-really.example")
    assert fp.polarity is Polarity.REFUTES              # false-positive drives belief DOWN
    assert fp.truth_confidence() < 0.5


def test_misp_iocs_are_leads_not_facts() -> None:
    obs = observations_from_misp(_load("misp_event.json"), seq=1)
    # a feed datum is a lead: reliability strictly below a first-hand A/1 source, sub-fact confidence
    for o in obs:
        assert o.reliability() < 0.85
        assert o.confidence <= 0.7


# ---------------------------------------------------------------------------
# STIX
# ---------------------------------------------------------------------------


def test_stix_indicators_and_revoked() -> None:
    obs = observations_from_stix(_load("stix_bundle.json"), seq=1)
    ids = _ids(obs)
    assert "domain:c2.evil.example" in ids
    assert any(i.startswith("indicator:sha256:") for i in ids)   # dash-normalized algo
    revoked = next(o for o in obs if o.subject.node_id == "host:198.51.100.7")
    assert revoked.polarity is Polarity.REFUTES         # a revoked indicator is a retraction


def test_stix_vulnerability_object_mints_cve_node() -> None:
    obs = observations_from_stix(_load("stix_bundle.json"), seq=1)
    vuln = next(o for o in obs if o.subject.kind is NodeKind.VULNERABILITY)
    assert vuln.subject.node_id == "vulnerability:CVE-2021-44228"
    assert vuln.source_kind is IntelSourceKind.VULN_DB


def test_stix_pattern_is_read_not_executed() -> None:
    # a hostile pattern must never be evaluated — it is parsed by regex and yields plain IOCs / nothing.
    evil = {"type": "bundle", "objects": [
        {"type": "indicator", "pattern": "[domain-name:value = '__import__(\"os\").system(\"x\")']"}]}
    obs = observations_from_stix(evil, seq=1)
    # the whole quoted value is treated as an opaque domain string; no code path executes it
    assert all(o.subject.kind is NodeKind.DOMAIN for o in obs)


# ---------------------------------------------------------------------------
# CVE — NVD + OSV
# ---------------------------------------------------------------------------


def test_nvd_cve_affects_with_exploit_signal() -> None:
    obs = observations_from_cve(_load("nvd_cve.json"), seq=1)
    node = next(o for o in obs if o.relation is None and o.subject.kind is NodeKind.VULNERABILITY)
    assert node.subject.node_id == "vulnerability:CVE-2021-44228"
    assert node.attrs["exploit_known"] is True          # CISA KEV / Exploit-tagged reference
    assert node.attrs.get("cvss") == 10.0
    affects = {(o.object.node_id, o.confidence) for o in obs if o.relation is EdgeKind.AFFECTS}
    names = {nid for nid, _ in affects}
    assert "package:log4j" in names                     # name anchor
    assert "application:log4j" in names                 # cpe part 'a' also correlates to an APPLICATION
    assert "package:log4j@2.14.1" in names              # feed-enumerated version → version-pinned edge
    # exploit-exists raised the AFFECTS confidence above the plain-lead baseline
    assert all(c > 0.6 for _, c in affects)
    # the affected version RANGE is carried for the oracle, not proven here
    edge = next(o for o in obs if o.relation is EdgeKind.AFFECTS and o.object.node_id == "package:log4j")
    assert edge.attrs["version_range"].get("fixed") == "2.15.0"


def test_osv_uses_cve_alias_and_enumerated_versions() -> None:
    obs = observations_from_cve(_load("osv_vuln.json"), seq=1)
    # canonical node id folds onto the CVE alias so OSV + NVD collapse to one advisory node
    assert any(o.subject.node_id == "vulnerability:CVE-2021-23337" for o in obs)
    pinned = {o.object.node_id for o in obs if o.relation is EdgeKind.AFFECTS and o.object}
    assert "package:lodash" in pinned
    assert "package:lodash@4.17.20" in pinned and "package:lodash@4.17.19" in pinned


def test_bare_osv_list_is_not_misrouted_to_nvd() -> None:
    # a raw list of OSV records (which also carry `id`) must route to the OSV parser, not NVD —
    # else its `affected` block would be silently dropped.
    obs = observations_from_cve([_load("osv_vuln.json")], seq=1)
    assert any(o.relation is EdgeKind.AFFECTS and o.object.node_id == "package:lodash" for o in obs)


def test_cve_correlates_to_existing_sbom_package_node() -> None:
    """The keystone: a CVE's version-pinned AFFECTS edge lands on the SAME package node the SBOM
    already put in the graph — correlation, without proving version membership (the oracle's job)."""
    world = WorldModel()
    ing = IntelIngest(world)
    # 1) operator SBOM establishes the installed package
    ing.ingest(observations_from_sbom(
        {"application": "myapp", "packages": [{"name": "lodash", "version": "4.17.20"}]}, seq=1))
    assert world.get_node("package:lodash@4.17.20") is not None
    n_before = world.node_count
    # 2) the OSV advisory enumerates 4.17.20 → its AFFECTS edge attaches to the EXISTING node
    ing.ingest(observations_from_cve(_load("osv_vuln.json"), seq=2))
    edge = world.get_edge("vulnerability:CVE-2021-23337", "package:lodash@4.17.20", EdgeKind.AFFECTS)
    assert edge is not None
    # the pinned package node was reused, not duplicated
    assert world.get_node("package:lodash@4.17.20") is not None
    assert world.node_count >= n_before   # new vuln/anchor nodes added, installed node reused


def test_exploit_signal_raises_correlation_belief() -> None:
    world = WorldModel()
    kev = observations_from_cve(_load("osv_vuln.json"), seq=1)                    # known_exploited: true
    no_exploit = json.loads(json.dumps(_load("osv_vuln.json")))
    no_exploit["id"] = "GHSA-quiet-0000-0000"
    no_exploit["aliases"] = ["CVE-2000-0001"]
    no_exploit["database_specific"] = {"severity": "HIGH"}
    no_exploit["references"] = []                                                # strip the EXPLOIT ref
    calm = observations_from_cve(no_exploit, seq=2)
    for o in kev + calm:
        project_observation(world, o)
    hot = world.get_edge("vulnerability:CVE-2021-23337", "package:lodash", EdgeKind.AFFECTS)
    cold = world.get_edge("vulnerability:CVE-2000-0001", "package:lodash", EdgeKind.AFFECTS)
    assert hot.belief_mean > cold.belief_mean            # exploit-exists is a stronger risk signal
    assert hot.attrs["exploit_known"] is True and cold.attrs["exploit_known"] is False


# ---------------------------------------------------------------------------
# correlation / refutation into the world-model (IOC ↔ in-scope asset)
# ---------------------------------------------------------------------------


def test_ioc_corroborates_in_scope_asset() -> None:
    world = WorldModel()
    # a scan already observed this in-scope asset; then a threat feed independently names it.
    ing = IntelIngest(world)
    ing.ingest(observations_from_misp(_load("misp_event.json"), seq=1))
    node = world.get_node("domain:api.company.com")
    assert node is not None
    assert node.attrs.get("threat_intel") is True        # the asset is now flagged in threat intel
    assert node.grounding == GROUNDING_INTEL             # a lead, never oracle-grounded
    assert node.belief_mean > 0.5                        # an AFFIRMS IOC raised belief


def test_affirm_and_refute_move_belief_opposite_ways() -> None:
    world = WorldModel()
    affirm = next(o for o in observations_from_misp(_load("misp_event.json"), seq=1)
                  if o.subject.node_id == "domain:phish-evil.example")
    refute = next(o for o in observations_from_misp(_load("misp_event.json"), seq=1)
                  if o.polarity is Polarity.REFUTES)
    project_observation(world, affirm)
    project_observation(world, refute)
    assert world.get_node("domain:phish-evil.example").belief_mean > 0.5
    assert world.get_node(refute.subject.node_id).belief_mean < 0.5


def test_no_finding_nodes_ever_minted() -> None:
    """A feed can never mint a confirmed FINDING; prove-don't-guess is structural here."""
    all_obs = (observations_from_misp(_load("misp_event.json"), seq=1)
               + observations_from_stix(_load("stix_bundle.json"), seq=1)
               + observations_from_cve(_load("nvd_cve.json"), seq=1)
               + observations_from_cve(_load("osv_vuln.json"), seq=1))
    world = WorldModel()
    for o in all_obs:
        project_observation(world, o)
        assert o.subject.kind is not NodeKind.FINDING
        assert classify_provenance(f"intel:{o.obs_id}") == GROUNDING_INTEL
    assert all(n.kind is not NodeKind.FINDING for n in world.all_nodes())
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


# ---------------------------------------------------------------------------
# untrusted input / totality / determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("junk", [None, 0, 42, "x", [], {}, [1, 2, 3],
                                  {"Event": 5}, {"objects": "bad"}, {"vulnerabilities": {"x": 1}},
                                  {"affected": "nope"}, {"vulns": [1, 2]},
                                  {"Event": {"Attribute": [1, "x", {"type": "domain"}]}}])
def test_parsers_are_total_on_garbage(junk) -> None:
    for fn in (observations_from_misp, observations_from_stix, observations_from_cve,
               observations_from_threat_feed):
        out = fn(junk, seq=1)
        assert isinstance(out, list)


def test_oversized_feed_is_bounded() -> None:
    # a hostile feed with a huge attribute list must not explode node count without bound
    huge = {"Event": {"info": "flood", "Attribute": [
        {"type": "domain", "value": f"h{i}.evil.example", "to_ids": True} for i in range(100000)]}}
    obs = observations_from_misp(huge, seq=1)
    assert len(obs) <= 20000        # _MAX_ATTRS cap


def test_deterministic_obs_ids() -> None:
    a = observations_from_cve(_load("nvd_cve.json"), seq=7)
    b = observations_from_cve(_load("nvd_cve.json"), seq=7)
    assert [o.obs_id for o in a] == [o.obs_id for o in b]


def test_ingest_is_idempotent() -> None:
    world = WorldModel()
    ing = IntelIngest(world)
    obs = observations_from_threat_feed(_load("osv_vuln.json"), seq=1)
    ing.ingest(obs)
    counts = (world.node_count, world.edge_count)
    ing.ingest(obs)                 # same obs_ids → no-op, belief not double-counted
    assert (world.node_count, world.edge_count) == counts


# ---------------------------------------------------------------------------
# format auto-detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,expected", [
    ("misp_event.json", "misp"), ("stix_bundle.json", "stix"),
    ("nvd_cve.json", "cve"), ("osv_vuln.json", "cve")])
def test_detect_format(name, expected) -> None:
    assert detect_format(_load(name)) == expected


def test_forced_format_overrides_sniff() -> None:
    # forcing the wrong parser yields [] rather than misreading (no false observations)
    assert observations_from_threat_feed(_load("nvd_cve.json"), seq=1, fmt="misp") == []


# ---------------------------------------------------------------------------
# normalize_response stays total for the new source kinds (no exhaustive KeyError)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sk", [IntelSourceKind.MISP, IntelSourceKind.STIX, IntelSourceKind.VULN_DB])
def test_normalize_response_total_for_new_kinds(sk) -> None:
    for junk in (None, 1, "x", {"a": 1}, [1, 2]):
        out = normalize_response(sk, junk)
        assert isinstance(out, (dict, list))


# ---------------------------------------------------------------------------
# gated live pull — opt-in, egress-allowlisted, disjoint from target
# ---------------------------------------------------------------------------


class _CannedClient:
    def __init__(self, payload, status=200):
        self.calls: list[str] = []
        self._payload, self._status = payload, status

    def get(self, url):
        self.calls.append(url)
        return _Resp(self._status, self._payload)


class _Resp:
    def __init__(self, status, payload):
        self.status_code, self._p, self.text = status, payload, ""

    def json(self):
        return self._p


def test_live_transport_refuses_target_overlap() -> None:
    with pytest.raises(CollectorEgressRefused):
        build_threatintel_live_transport(collector_hosts=("services.nvd.nist.gov",),
                                         target_hosts=("services.nvd.nist.gov",))


def test_live_transport_refuses_off_allowlist_host() -> None:
    from framework.v2.intel.transport import GuardedHttpTransport
    client = _CannedClient({})
    t = GuardedHttpTransport(
        collector_hosts=("services.nvd.nist.gov",),
        endpoints={IntelSourceKind.VULN_DB: "https://evil.example/{query}"},
        client=client)
    with pytest.raises(CollectorEgressRefused):
        t.fetch(IntelSourceKind.VULN_DB, "CVE-2021-44228", seq=1)
    assert client.calls == []               # nothing left the process


def test_live_pull_reuses_offline_parser() -> None:
    nvd = _load("nvd_cve.json")
    transport = build_threatintel_live_transport(target_hosts=("company.com",),
                                                 client=_CannedClient(nvd))
    obs = live_cve_observations(transport, "CVE-2021-44228", seq=1)
    assert any(o.subject.node_id == "vulnerability:CVE-2021-44228" for o in obs)
    assert any(o.relation is EdgeKind.AFFECTS for o in obs)


def test_live_pull_graceful_on_not_ok_record() -> None:
    # a failed / empty live fetch is a clean skip, not a crash
    transport = build_threatintel_live_transport(target_hosts=("company.com",),
                                                 client=_CannedClient({}, status=500))
    assert live_cve_observations(transport, "CVE-0000-0000", seq=1) == []


# ---------------------------------------------------------------------------
# CLI — offline ingest, graceful absence, kill-switch gating
# ---------------------------------------------------------------------------


def _run_cli(argv) -> tuple[int, dict]:
    import io
    from contextlib import redirect_stdout

    from framework.v2.intel import cli
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.main(argv)
    text = buf.getvalue().strip()
    return rc, (json.loads(text) if text else {})


def test_cli_ingest_intel_offline() -> None:
    rc, out = _run_cli(["ingest-intel", "--file", str(_FIX / "nvd_cve.json")])
    assert rc == 0 and out["present"] is True
    assert out["format"] == "cve"
    assert out["cve_advisories"] == 1 and out["observations"] > 0
    assert out["nodes"] > 0 and out["edges"] > 0


def test_cli_ingest_intel_absent_file_is_clean_skip() -> None:
    rc, out = _run_cli(["ingest-intel", "--file", str(_FIX / "does-not-exist.json")])
    assert rc == 0 and out["present"] is False and out["observations"] == 0


def test_cli_ingest_intel_refuses_when_killswitch_tripped(tmp_path) -> None:
    from framework.v2.authority.killswitch import KillSwitch
    slug = "w5c-threatintel-killswitch-test"
    ks = KillSwitch(slug)
    ks.trip("unit test")
    try:
        rc, out = _run_cli(["ingest-intel", "--file", str(_FIX / "nvd_cve.json"), "--slug", slug])
        assert rc == 3        # refused before reading / persisting anything
    finally:
        ks.clear("unit test")
