"""
agents.chain_synthesizer — neurosymbolic multi-hop exploit-chain synthesis.

An LLM is a strong hypothesis generator for attack chains ("leak a credential at
endpoint A -> authenticate as that principal -> reach the datastore"), but its
say-so is not proof. This module extends the project's existing idiom — LLM
proposes, deterministic oracle disposes — from single findings to whole chains:
each hop's primitive is executed and adjudicated by the oracle layer, and ONLY an
oracle-confirmed hop asserts its edge into the world-model. Unproven hops remain
hypotheses. The world-model's path search then reports a route to a crown jewel
only when EVERY edge on it was oracle-confirmed, so a chain is symbolically
verified hop-by-hop rather than asserted by a narrative.

The chain's certificate is the ordered list of its hops' oracle_contexts, each
independently re-verifiable (Wave 3) — a proof-carrying attack path.

The LLM proposal side runs through the existing ``kernel`` backends and is refused
under ``CRUCIBLE_SOVEREIGN_MODE``; this module's core (the discharge engine) is
pure over the world-model and the oracle layer, so it needs no LLM to be tested.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..verify.adapter import FindingContext
from ..verify.confirmation import confirm_finding
from ..verify.verifier import OracleVerifier
from ..worldmodel import pathsearch
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, EdgeKind, Node, NodeKind, Path


@dataclass
class ProposedHop:
    """One hypothesised step of a chain: the primitive to prove and the endpoints
    it would connect in the world-model. ``oracle_context`` is the serialized
    FindingContext collected by running the hop's probe — the oracle adjudicates
    it; the hop is asserted only if it fires."""

    hop_id: str
    src_id: str
    src_kind: NodeKind
    dst_id: str
    dst_kind: NodeKind
    edge_kind: EdgeKind
    bug_class: str
    oracle_context: dict
    description: str = ""


@dataclass
class ChainResult:
    """The discharge of a proposed chain: which hops the oracle confirmed, which
    remained unproven, the crown-jewel routes that exist through the confirmed
    edges, and the re-verifiable per-hop certificate."""

    confirmed_hops: list[str] = field(default_factory=list)
    unproven_hops: list[str] = field(default_factory=list)
    paths: list[Path] = field(default_factory=list)
    certificate: list[dict] = field(default_factory=list)

    @property
    def reached_objective(self) -> bool:
        return bool(self.paths)


def synthesize_chain(
    hops: list[ProposedHop],
    *,
    world: WorldModel,
    source: str,
    objective_kinds: set[NodeKind],
    verifier: OracleVerifier | None = None,
    seq_start: int = 1,
    k: int = 3,
) -> ChainResult:
    """Discharge a proposed chain hop-by-hop against the oracle layer and report
    the crown-jewel routes that the CONFIRMED edges open.

    Each hop's oracle_context is adjudicated by ``confirm_finding``; a fired oracle
    asserts the hop's edge (with ``oracle:<kind>`` provenance and the confirmed
    confidence, so the Wave-8 belief corroborates it), and a non-firing one leaves
    the hop an unproven hypothesis — no edge, no assertion. A path to a crown
    jewel therefore exists only if every edge along it was oracle-confirmed."""
    verifier = verifier or OracleVerifier()
    result = ChainResult()
    seq = seq_start

    for hop in hops:
        ctx = FindingContext.model_validate(hop.oracle_context)
        confirmed = confirm_finding({"bug_class": hop.bug_class}, ctx, verifier)
        if confirmed is None:
            result.unproven_hops.append(hop.hop_id)
            continue

        prov = f"oracle:{confirmed.confirmed_by.value}"
        for nid, kind in ((hop.src_id, hop.src_kind), (hop.dst_id, hop.dst_kind)):
            if not world.has_node(nid):
                world.add_node(Node(id=nid, kind=kind, provenance=prov,
                                    confidence=confirmed.confidence, first_seen=seq, last_seen=seq))
        world.add_edge(Edge(src=hop.src_id, dst=hop.dst_id, kind=hop.edge_kind,
                            provenance=prov, confidence=confirmed.confidence,
                            first_seen=seq, last_seen=seq))
        result.confirmed_hops.append(hop.hop_id)
        result.certificate.append(hop.oracle_context)
        seq += 1

    if world.has_node(source):
        result.paths = pathsearch.best_paths(world, source, objective_kinds, k=k)
    return result
