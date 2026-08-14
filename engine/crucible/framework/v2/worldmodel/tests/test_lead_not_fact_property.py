"""The product's central claim, made a PROPERTY rather than a set of examples: a tool/collector
Observation NEVER becomes a FACT on its own — only a fired deterministic oracle mints one.

The existing lead-only tests (test_engage_fusion.py, test_imports.py, test_grounding.py) each pin ONE
source: a declared service, an SBOM, a hydra import, a nuclei match. That is coverage by example, and a
new source added tomorrow is not covered by any of them. This file closes that by exhausting the choke
point instead of the sources.

`intel.project.project_observation` is the single seam through which every sensor's and every importer's
Observations reach the world-model (via the single writer `IntelIngest.ingest`). It hardcodes the
provenance prefix to ``intel:``. So the property "no Observation, however it is shaped, can enter as a
fact" is decidable by construction — we generate Observations across the whole shape space an attacker
or a careless collector could produce and assert every node and every edge that lands is a LEAD.

Pure, offline, deterministic: no tool runs, no packet is sent, no wall-clock or RNG is used (the product
is enumerated, not sampled).
"""

from __future__ import annotations

import itertools

from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Polarity,
    Reliability,
    SourceReliability,
)
from framework.v2.intel.project import project_fused, project_observation
from framework.v2.intel.fuse import fuse_observations
from framework.v2.intel.refs import canonicalize
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import GROUNDING_GROUNDED, EdgeKind, NodeKind

# The most adversarial attrs a collector could carry: keys that NAME the fact machinery, values that
# look like a confirmation. If projection honoured any of these, a lead would launder into a fact.
_HOSTILE_ATTRS = {
    "confirmed_by": "boolean_sqli",
    "oracle": "boolean_sqli",
    "grounded": True,
    "provenance": "oracle:pwn",
    "finding": "sqli",
    "tool_confirmed": True,
    "is_fact": True,
    "grounding": "grounded",
}

# The strongest source the Admiralty scale allows (A/1 → weight ≈ 1.0, so c_eff ≈ the raw confidence)
# and a middling one — the extremes that bracket every real source's trust.
_RELIABILITIES = (
    SourceReliability(reliability=Reliability.A, credibility=Credibility.C1),
    SourceReliability(reliability=Reliability.C, credibility=Credibility.C3),
)


def _observations():
    """The product of (every source kind) × (both reliabilities) × (both polarities) ×
    (max and neutral confidence) × (node-only and edge claim), each carrying the hostile attrs."""
    i = 0
    for sk, rel, pol, conf, edge in itertools.product(
        list(IntelSourceKind), _RELIABILITIES, (Polarity.AFFIRMS, Polarity.REFUTES),
        (1.0, 0.5), (False, True),
    ):
        i += 1
        subject = canonicalize(NodeKind.HOST, f"10.0.0.{i % 240 + 1}")
        kwargs = dict(
            obs_id=f"prop-{i}", source="prop-test", source_kind=sk, subject=subject,
            attrs=dict(_HOSTILE_ATTRS), source_reliability=rel, confidence=conf, polarity=pol, seq=i,
        )
        if edge:
            kwargs.update(relation=EdgeKind.RESOLVES_TO,
                          object=canonicalize(NodeKind.DOMAIN, f"h{i}.example.test"))
        yield Observation(**kwargs)


def test_no_observation_shape_projects_as_a_fact_via_project_observation():
    """Drive every shape straight through the choke point. Every node and every edge that lands must
    be a LEAD — grounding never GROUNDED, provenance always the ``intel:`` prefix the seam hardcodes."""
    applied = 0
    for obs in _observations():
        w = WorldModel()
        if project_observation(w, obs):
            applied += 1
        for n in w.all_nodes():
            assert n.grounding != GROUNDING_GROUNDED, (obs.source_kind, obs.attrs, n.provenance)
            assert n.provenance.startswith("intel:"), n.provenance
        for e in w.all_edges():
            assert e.grounding != GROUNDING_GROUNDED, (obs.source_kind, e.provenance)
            assert e.provenance.startswith("intel:"), e.provenance
    # mutation control: the generator must actually be producing applications, or this passes vacuously.
    assert applied >= 100, f"only {applied} observations projected — the shape product collapsed"


def test_no_observation_shape_projects_as_a_fact_through_the_single_writer():
    """The SAME property through the wired path a real run uses: IntelIngest.ingest (durable log →
    projection). A future edit that grounds a write in ingest — not in project_observation — is caught
    here even though the choke-point test above would still pass."""
    ingested = 0
    for obs in _observations():
        w = WorldModel()
        IntelIngest(w, engagement_slug="prop").ingest([obs], seq=obs.seq)
        for n in w.all_nodes():
            assert n.grounding != GROUNDING_GROUNDED, (obs.source_kind, n.provenance)
            if w.all_nodes():
                ingested += 1
                break
    assert ingested >= 100, f"only {ingested} observations reached the graph via ingest"


def test_batch_fused_projection_is_also_a_lead():
    """The OTHER projection path — a batch-fused posterior written directly — must be a lead too."""
    for obs in _observations():
        w = WorldModel()
        fused = fuse_observations([obs])  # a real fused posterior for this observation
        project_fused(w, obs, fused, seq=obs.seq)
        for n in w.all_nodes():
            assert n.grounding != GROUNDING_GROUNDED, (obs.source_kind, n.provenance)
            assert n.provenance.startswith("intel-fused:"), n.provenance
        for e in w.all_edges():
            assert e.grounding != GROUNDING_GROUNDED, (obs.source_kind, e.provenance)
