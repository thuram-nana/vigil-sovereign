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



# ATTRIBUTED evidence. The confirmable fixture below is a path_traversal FILE-CONTENT signature with
# its benign CONTROL retained: the signature is present under the payload and ABSENT from the
# control, so the read is attributable. It used to be a boolean_sqli benign-vs-payload differential,
# which is LEAD-only now — that inference has no attribution step (its control is a DIFFERENT
# STRING, not a same-shape negative) and minted High FACTs at rate 1.0 against a static page behind
# a WAF tautology rule and against strict input validation, on targets with no database. See
# verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES. Nothing under test here changes — only the
# evidence it is anchored to.
_SIGNATURE = "root:x:0:0:"
_READ_SINK = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
_CONTROL_SINK = "<p>ordinary document</p>"
_PT = "path_traversal"


def _pt_ctx(*, firing: bool = True) -> "FindingContext":
    """A path_traversal side-effect context. ``firing=False`` puts the signature in the CONTROL too,
    so it is not attributable and the oracle stays silent."""
    return FindingContext.from_side_effect(
        _SIGNATURE, _READ_SINK, bug_class=_PT,
        control_sink=_READ_SINK if not firing else _CONTROL_SINK)


def _firing_ctx() -> dict:
    return _pt_ctx().model_dump()


def _non_firing_ctx() -> dict:
    return _pt_ctx(firing=False).model_dump()


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
