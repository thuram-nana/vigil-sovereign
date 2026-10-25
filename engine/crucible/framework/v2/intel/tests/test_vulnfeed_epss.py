"""
EPSS (FIRST.org Exploit Prediction Scoring System) — the predictive-score source added to the K1
vulnerability-intelligence feed.

Doctrine under test (identical to the KEV/NVD/OSV leads, plus the EPSS specifics):
  * LEAD, NEVER A FACT — an EPSS score is a third-party PREDICTION; it mints a ``VULN_DB`` /
    GROUNDING_INTEL observation on the CVE's VULNERABILITY node (``feed="first-epss"``), never a fact.
  * EGRESS-GATED to the single concrete apex host ``api.first.org`` — the gated transport refuses any
    other host, and a source overlapping target scope refuses to construct.
  * TOTAL + BOUNDED — a non-dict doc, a missing/short ``data``, or an entry with no CVE or an
    unparseable ``epss`` is DROPPED, never raised; the list is capped at ``_MAX_ITEMS``.
  * DETERMINISTIC — a pure function of ``(doc, seq)``; ``refresh_vulnintel`` routes the ``epss`` source
    through the EPSS parser and the belief graph carries the epss attrs on the CVE node.
"""

from __future__ import annotations

from framework.v2.intel import vulnfeed
from framework.v2.intel.from_threatintel import (
    _MAX_ITEMS,
    _epss_float,
    observations_from_epss,
)
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import IntelSourceKind
from framework.v2.intel.refs import canonicalize
from framework.v2.intel.transport import RawRecord
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import NodeKind

_NID_0002 = canonicalize(NodeKind.VULNERABILITY, "CVE-2024-0002").node_id

_EPSS = {"status": "OK", "status-code": 200, "version": "1.0", "total": 2, "data": [
    {"cve": "cve-2024-0001", "epss": "0.00892", "percentile": "0.39856", "date": "2024-01-01"},
    {"cve": "CVE-2024-0002", "epss": "0.97310", "percentile": "0.99990", "date": "2024-01-01"},
]}


# ---- source registration: a concrete apex host, selectable by name ---------


def test_epss_is_a_registered_concrete_apex_source() -> None:
    from framework.v2.agents.egress_guard import _collector_host_too_broad

    epss = vulnfeed.source_by_name("epss")
    assert epss is not None and epss.host == "api.first.org" and epss.mode == "per_cve"
    assert epss.source_kind is IntelSourceKind.VULN_DB            # rides the vuln axis, not a new kind
    assert not _collector_host_too_broad(epss.host)              # no wildcard / public-suffix host
    assert "*" not in epss.host and "/" not in epss.host         # concrete, no path/scheme
    assert "{query}" in epss.endpoint                            # per-CVE template


# ---- parse: a LEAD carrying epss/epss_percentile on the CVE node -----------


def test_epss_parse_mints_vuln_db_leads_with_scores() -> None:
    obs = observations_from_epss(_EPSS, seq=5)
    assert len(obs) == 2
    assert all(o.source_kind is IntelSourceKind.VULN_DB for o in obs)       # lead tier, never a fact kind
    assert all(o.relation is None and o.subject.kind is NodeKind.VULNERABILITY for o in obs)
    by_cve = {o.subject.key.upper(): o for o in obs}
    a = by_cve["CVE-2024-0001"]
    assert a.attrs["cve"] == "CVE-2024-0001"                     # cve uppercased
    assert a.attrs["epss"] == 0.00892 and a.attrs["epss_percentile"] == 0.39856   # floats, not strings
    assert a.attrs["feed"] == "first-epss"
    # a LEAD cannot be dressed as a proof — the Observation carries no oracle/grounding field at all
    assert not hasattr(a, "oracle") and not hasattr(a, "grounding")


def test_epss_lead_enters_the_graph_as_intel_never_a_fact() -> None:
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(observations_from_epss(_EPSS, seq=1), seq=1)
    node = world.get_node(_NID_0002)
    assert node is not None
    assert node.provenance.startswith("intel:")                 # GROUNDING_INTEL, never oracle-grounded


# ---- total + bounded over an untrusted feed --------------------------------


def test_epss_parse_is_total_on_malformed_input() -> None:
    assert observations_from_epss({}, seq=0) == []                       # no data
    assert observations_from_epss({"data": "nope"}, seq=0) == []         # data not a list
    assert observations_from_epss(None, seq=0) == []                     # not a dict
    assert observations_from_epss([1, 2, 3], seq=0) == []                # not a dict
    # an entry with no cve, or an unparseable / out-of-range epss, is DROPPED (not raised)
    dirty = {"data": [
        {"epss": "0.5"},                                       # no cve → dropped
        {"cve": "CVE-2024-0003", "epss": "not-a-number"},      # unparseable epss → dropped
        {"cve": "CVE-2024-0004", "epss": "1.5"},               # out of [0,1] → dropped
        {"cve": "CVE-2024-0005", "epss": "0.3"},               # the one good entry
        "not-a-dict",                                          # dropped
    ]}
    obs = observations_from_epss(dirty, seq=0)
    assert len(obs) == 1 and obs[0].subject.key.upper() == "CVE-2024-0005"


def test_epss_drops_a_malformed_or_overlong_cve() -> None:
    # the cve keys a world-model node + an attr — an untrusted feed must not plant a garbage/huge key
    obs = observations_from_epss({"data": [
        {"cve": "not-a-cve", "epss": "0.5"},                 # malformed → dropped
        {"cve": "CVE-2024-" + "9" * 40, "epss": "0.5"},      # absurdly long numeric → dropped
        {"cve": "", "epss": "0.5"},                          # empty → dropped
        {"cve": "CVE-2024-0001", "epss": "0.5"},             # the one well-formed entry
    ]}, seq=0)
    assert len(obs) == 1 and obs[0].subject.key.upper() == "CVE-2024-0001"


def test_epss_percentile_is_optional() -> None:
    obs = observations_from_epss({"data": [{"cve": "CVE-2024-1234", "epss": "0.2"}]}, seq=0)
    assert len(obs) == 1 and "epss_percentile" not in obs[0].attrs      # absent percentile → omitted


def test_epss_parse_caps_an_oversized_feed() -> None:
    big = {"data": [{"cve": f"CVE-2024-{i:05d}", "epss": "0.01"} for i in range(_MAX_ITEMS + 300)]}
    assert len(observations_from_epss(big, seq=0)) == _MAX_ITEMS         # bounded, not 5300


def test_epss_float_bounds() -> None:
    assert _epss_float("0.5") == 0.5 and _epss_float("0") == 0.0 and _epss_float("1") == 1.0
    assert _epss_float("1.0001") is None and _epss_float("-0.1") is None   # out of [0,1]
    assert _epss_float("nan") is None and _epss_float("abc") is None and _epss_float(None) is None


# ---- egress: scoped to the single apex host api.first.org ------------------


def test_epss_transport_permits_only_its_own_host() -> None:
    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return _EPSS

    class _RecordingClient:
        def __init__(self):
            self.calls: list[str] = []

        def get(self, url):
            self.calls.append(url)
            return _Resp()

    epss = vulnfeed.source_by_name("epss")
    client = _RecordingClient()
    t = vulnfeed.build_vulnintel_transport(epss, client=client)
    rec = t.fetch(IntelSourceKind.VULN_DB, "CVE-2024-0001", seq=1)
    assert rec.ok and len(client.calls) == 1
    assert client.calls[0].startswith("https://api.first.org/")         # only its own apex host


# ---- refresh routes the epss source through the EPSS parser ----------------


class _FakeTransport:
    def __init__(self, payload):
        self.payload = payload

    def fetch(self, source_kind, query, *, seq):
        return RawRecord(source_kind=source_kind, query=query, payload=self.payload, ok=True)


def test_refresh_routes_epss_through_its_parser() -> None:
    world = WorldModel()
    ing = IntelIngest(world, engagement_slug="alpha")
    epss = vulnfeed.source_by_name("epss")
    plan = vulnfeed.plan_for([epss], ["CVE-2024-0002"])
    res = vulnfeed.refresh_vulnintel(
        plan, transport_for=lambda s: _FakeTransport(_EPSS), ingest=ing, seq=0)
    assert res.minted_by_source["epss"] >= 1 and res.applied > 0
    node = world.get_node(_NID_0002)
    assert node is not None and node.attrs.get("epss") == 0.97310   # the epss score landed on the CVE node
