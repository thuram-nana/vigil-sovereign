"""
veracity.firewall — admit(): the one choke point every claim must cross.

`admit()` turns a `Claim` into an `AdmittedClaim` by RE-EXECUTING each cited ground —
never trusting a string — and labelling the result. It is the reusable generalization of
the discipline the scanner already applies at promotion time, made universal:

    contradiction?  → CONTRADICTED   (the world-model refutes an asserted entity)
    named entity not in the graph?   → UNGROUNDED   (a fabricated target)
    ORACLE token re-fires?           → GROUNDED (fact) via verify.reverify
    CERT token 4-layer verifies?     → GROUNDED (fact) via evidence.verify_certificate
    WORLDMODEL node belief-floored + provenance grounded? → GROUNDED (fact)
    HYPOTHESIS gated + prior≤cap?    → GROUNDED (hypothesis — labelled, never a fact)
    none of the above                → UNGROUNDED   (labelled commentary, never dropped)

The layer only ever DEMOTES or abstains: it can turn a fabricated "confirmed" into
UNGROUNDED, but it can NEVER promote a claim the oracle refused. A token whose backing
LLM call was a dry-run cannot ground. This is what makes hallucination structurally
unshippable rather than merely discouraged.
"""

from __future__ import annotations

from ..intel.predict import _PRIOR_CAP
from .claims import AdmittedClaim, Claim, VeracityVerdict
from .consistency import contradicts
from .tokens import Ground, GroundingToken

_BELIEF_FLOOR = 0.5    # a world-model node grounds a fact only above this evidence-discounted belief
_LCB_Z = 1.0
# provenance markers that indicate a claim was NOT deterministically established
# (an LLM assertion or a bare assumption) — such a node never grounds a FACT even if its
# scalar confidence was set high.
_UNGROUNDED_PROV = ("llm", "assume", "guess", "hallucin", "unverified", "ungrounded")


def _provenance_is_grounded(provenance: str) -> bool:
    p = (provenance or "").lower()
    return bool(p) and not any(p.startswith(m) or m in p.split(":")[0] for m in _UNGROUNDED_PROV)


def _oracle_ok(tok: GroundingToken, verifier) -> bool:
    if tok.from_dryrun or not isinstance(tok.oracle_context, dict) or not tok.oracle_context:
        return False
    from ..verify.reverify import reverify_context
    r = reverify_context(tok.oracle_context, bug_class=tok.bug_class,
                         claimed_confirmed_by=tok.claimed_confirmed_by,
                         claimed_confidence=tok.claimed_confidence, verifier=verifier)
    return r.ok


def _cert_ok(tok: GroundingToken, trust_root) -> bool:
    if tok.from_dryrun or trust_root is None or not isinstance(tok.signed_evidence, dict):
        return False
    from ..evidence.certify import verify_certificate
    from ..evidence.models import SignedEvidence
    try:
        signed = SignedEvidence.model_validate(tok.signed_evidence)
    except Exception:
        return False
    return verify_certificate(signed, oracle_context=tok.oracle_context or {},
                              trust_root=trust_root).ok


def _worldmodel_ok(tok: GroundingToken, world, belief_floor: float) -> bool:
    if world is None or not tok.node_id:
        return False
    node = world.get_node(tok.node_id)
    if node is None:
        return False
    lcb = node.belief_lcb(_LCB_Z) if hasattr(node, "belief_lcb") else node.belief_mean
    return lcb >= belief_floor and _provenance_is_grounded(node.provenance)


def _hypothesis_ok(tok: GroundingToken) -> bool:
    return (not tok.from_dryrun and tok.gated is True
            and tok.prior is not None and tok.prior <= _PRIOR_CAP)


# strongest → weakest FACT ground; HYPOTHESIS is grounded-but-not-fact
_FACT_ORDER = (Ground.ORACLE, Ground.CERT, Ground.WORLDMODEL)


def admit(
    claim: Claim,
    *,
    world=None,
    trust_root=None,
    verifier=None,
    belief_floor: float = _BELIEF_FLOOR,
    require_entities: bool = True,
) -> AdmittedClaim:
    """Admit a claim by re-executing its grounds. See the module docstring for the
    decision order. Never mutates; never promotes an oracle-refused claim."""
    # 1. contradiction — the world-model actively refutes a named entity.
    contra, score, creason = contradicts(claim.entity_refs, world)
    if contra:
        return AdmittedClaim(claim=claim, verdict=VeracityVerdict.CONTRADICTED,
                             reason=creason)

    # 2. fabricated entity — a named target that does not exist in the graph.
    if require_entities and world is not None and claim.entity_refs:
        missing = [r for r in claim.entity_refs if not world.has_node(r)]
        if missing:
            return AdmittedClaim(
                claim=claim, verdict=VeracityVerdict.UNGROUNDED,
                reason=f"claim names entities absent from the world-model (fabricated?): {missing}")

    # 3. validate each ground by RE-EXECUTION; keep the strongest that resolves.
    resolved: set[Ground] = set()
    for tok in claim.tokens:
        ok = False
        if tok.ground is Ground.ORACLE:
            ok = _oracle_ok(tok, verifier)
        elif tok.ground is Ground.CERT:
            ok = _cert_ok(tok, trust_root)
        elif tok.ground is Ground.WORLDMODEL:
            ok = _worldmodel_ok(tok, world, belief_floor)
        elif tok.ground is Ground.HYPOTHESIS:
            ok = _hypothesis_ok(tok)
        if ok:
            resolved.add(tok.ground)

    # 4. a dry-run claim can only stand on re-executable proof (oracle/cert), never on
    #    its own LLM reasoning (worldmodel-via-llm / hypothesis).
    if claim.from_dryrun:
        resolved &= {Ground.ORACLE, Ground.CERT}

    # 5. label — fact strength first, then hypothesis, then ungrounded.
    fact = next((g for g in _FACT_ORDER if g in resolved), None)
    if fact is not None:
        conf = claim.proposed_confidence
        return AdmittedClaim(claim=claim, verdict=VeracityVerdict.GROUNDED, strength=fact,
                             grounded_by=[g.value for g in resolved], calibrated_confidence=conf,
                             reason=f"grounded by re-executed {fact.value}")
    if Ground.HYPOTHESIS in resolved:
        prior = next((t.prior for t in claim.tokens if t.ground is Ground.HYPOTHESIS), None)
        return AdmittedClaim(claim=claim, verdict=VeracityVerdict.GROUNDED, strength=Ground.HYPOTHESIS,
                             grounded_by=["hypothesis"], calibrated_confidence=prior,
                             reason="admitted as a gated, prior-capped hypothesis (not a fact)")
    return AdmittedClaim(
        claim=claim, verdict=VeracityVerdict.UNGROUNDED,
        reason="no cited ground re-verified — rendered as labelled analyst commentary, never as fact")
