"""
Wave 12 — neurosymbolic chain synthesis: LLM proposes, the oracle discharges.

A proposed multi-hop chain reaches a crown jewel only when EVERY hop is oracle-
confirmed. A hop the oracle refuses is not asserted, so the chain breaks — the
LLM cannot narrate its way to a crown jewel past an edge that did not prove out.
"""

from __future__ import annotations

from framework.v2.agents.chain_synthesizer import ProposedHop, synthesize_chain
from framework.v2.verify.adapter import FindingContext
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind, NodeKind


def _firing_ctx() -> dict:
    return FindingContext.from_http_responses(
        {"status": 200, "body": "no results"},
        {"status": 200, "body": "id=1 alice admin\n" * 30},  # strong divergence
        bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump()


def _non_firing_ctx() -> dict:
    same = {"status": 200, "body": "no results"}
    return FindingContext.from_http_responses(
        same, dict(same), bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump()


def _chain(hop2_ctx: dict) -> list[ProposedHop]:
    # attacker -> credential -> principal -> datastore (the crown jewel)
    return [
        ProposedHop("h1", "attacker:self", NodeKind.PRINCIPAL, "cred:leaked", NodeKind.CREDENTIAL,
                    EdgeKind.HOLDS, "boolean_sqli", _firing_ctx(), "leak a credential"),
        ProposedHop("h2", "cred:leaked", NodeKind.CREDENTIAL, "principal:svc", NodeKind.PRINCIPAL,
                    EdgeKind.VALID_ON, "boolean_sqli", hop2_ctx, "authenticate as the principal"),
        ProposedHop("h3", "principal:svc", NodeKind.PRINCIPAL, "datastore:vault", NodeKind.DATASTORE,
                    EdgeKind.HAS_GRANT, "boolean_sqli", _firing_ctx(), "reach the datastore"),
    ]


def test_fully_confirmable_chain_yields_an_all_oracle_crown_jewel_path() -> None:
    world = WorldModel()
    result = synthesize_chain(
        _chain(_firing_ctx()), world=world, source="attacker:self",
        objective_kinds={NodeKind.DATASTORE},
    )
    assert result.confirmed_hops == ["h1", "h2", "h3"]
    assert not result.unproven_hops
    assert result.reached_objective
    # the winning path reaches the datastore and every hop is oracle-provenanced
    path = result.paths[0]
    assert path.nodes[-1] == "datastore:vault"
    assert all(p.startswith("oracle:") for p in path.provenance_chain)
    # the certificate is the ordered per-hop evidence (re-verifiable)
    assert len(result.certificate) == 3


def test_refuted_middle_hop_breaks_the_chain() -> None:
    world = WorldModel()
    result = synthesize_chain(
        _chain(_non_firing_ctx()), world=world, source="attacker:self",
        objective_kinds={NodeKind.DATASTORE},
    )
    assert "h2" in result.unproven_hops        # the oracle refused hop 2
    assert result.confirmed_hops == ["h1", "h3"]
    # ...so no complete route to the crown jewel exists (the chain is broken)
    assert not result.reached_objective
