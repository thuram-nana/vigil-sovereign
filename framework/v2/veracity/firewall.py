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

A ground is BOUND to the claim it backs: an oracle must re-fire for the CLAIM's own
bug_class (a SQLi proof cannot ground an RCE claim), a cert must certify that bug_class,
and a world-model node must be one the claim names AND whose provenance traces to a real
oracle/cert (an allowlist — collected intelligence and derivations do not reach fact
strength). A fact claim must declare its subject; an unbound proof grounds nothing.

NOTE ON PHASING: this is the caller-less PRIMITIVE (veracity P0). Runtime enforcement is
wired in the subsequent phases — the world-model admission gate (P2) routes every
add_node/add_edge through admit(), and the reporting gate (P4) binds report prose. Until
then admit() is exercised only by its tests; that is by design, not a gap.
"""

from __future__ import annotations

from ..intel.predict import _PRIOR_CAP
from .claims import AdmittedClaim, Claim, VeracityVerdict
from .consistency import contradicts
from .tokens import Ground, GroundingToken

_BELIEF_FLOOR = 0.5    # a world-model node grounds a fact only above this evidence-discounted belief
_LCB_Z = 1.0
# Provenance ALLOWLIST (belief-tracing, NOT a denylist): a world-model node grounds a
# FACT only if its provenance traces to a real deterministic origin — a fired oracle, a
# signed cert, or a promoted finding. Collected intelligence ("intel:"), derivations
# ("derived:"), and LLM assertions do NOT reach fact strength here (they are legitimate
# but weaker grounds handled elsewhere). An allowlist can't be bypassed by a post-colon
# marker the way the old denylist could.
_GROUNDED_PROV_PREFIXES = ("oracle:", "cert:", "finding:", "evidence:")


def _provenance_traces_to_proof(provenance: str) -> bool:
    p = (provenance or "").lower()
    return any(p.startswith(pre) for pre in _GROUNDED_PROV_PREFIXES)


def _oracle_ok(tok: GroundingToken, claim: "Claim", verifier) -> tuple[bool, float]:
    """The oracle grounds the claim only if it RE-FIRES for the CLAIM's OWN bug_class —
    a SQLi context cannot ground a 'balance drain' claim, because reverifying it under
    that bug_class won't fire. Returns (ok, re-executed confidence)."""
    if tok.from_dryrun or not isinstance(tok.oracle_context, dict) or not tok.oracle_context:
        return (False, 0.0)
    bug_class = claim.bug_class or tok.bug_class
    if claim.bug_class and tok.bug_class and claim.bug_class != tok.bug_class:
        return (False, 0.0)   # the token claims to prove a different subject than the claim
    from ..verify.reverify import reverify_context
    r = reverify_context(tok.oracle_context, bug_class=bug_class,
                         claimed_confirmed_by=tok.claimed_confirmed_by,
                         claimed_confidence=tok.claimed_confidence, verifier=verifier)
    return (r.ok, r.confidence)


def _cert_ok(tok: GroundingToken, claim: "Claim", trust_root) -> bool:
    if tok.from_dryrun or trust_root is None or not isinstance(tok.signed_evidence, dict):
        return False
    from ..evidence.certify import verify_certificate
    from ..evidence.models import SignedEvidence
    try:
        signed = SignedEvidence.model_validate(tok.signed_evidence)
    except Exception:
        return False
    # bind: the certificate must certify the CLAIM's subject, not an unrelated finding.
    if claim.bug_class and signed.certificate.bug_class and signed.certificate.bug_class != claim.bug_class:
        return False
    return verify_certificate(signed, oracle_context=tok.oracle_context or {},
                              trust_root=trust_root).ok


def _worldmodel_ok(tok: GroundingToken, claim: "Claim", world, belief_floor: float) -> bool:
    if world is None or not tok.node_id:
        return False
    # bind: the claim must actually be ABOUT this node (name it in entity_refs).
    if tok.node_id not in (claim.entity_refs or []):
        return False
    node = world.get_node(tok.node_id)
    if node is None:
        return False
    lcb = node.belief_lcb(_LCB_Z) if hasattr(node, "belief_lcb") else node.belief_mean
    # belief-floored AND its provenance traces to a real oracle/cert proof.
    return lcb >= belief_floor and _provenance_traces_to_proof(node.provenance)


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

    # 3. validate each ground by RE-EXECUTION, BOUND to this claim's subject; keep the
    #    strongest that resolves. A ground proves THIS claim, not merely that a proof
    #    exists somewhere — the oracle must re-fire for the claim's own bug_class, the
    #    cert must certify it, the world-model node must be one the claim names.
    resolved: set[Ground] = set()
    oracle_conf: float | None = None
    for tok in claim.tokens:
        if tok.ground is Ground.ORACLE:
            ok, conf = _oracle_ok(tok, claim, verifier)
            if ok:
                resolved.add(Ground.ORACLE)
                oracle_conf = conf if oracle_conf is None else max(oracle_conf, conf)
        elif tok.ground is Ground.CERT:
            if _cert_ok(tok, claim, trust_root):
                resolved.add(Ground.CERT)
        elif tok.ground is Ground.WORLDMODEL:
            if _worldmodel_ok(tok, claim, world, belief_floor):
                resolved.add(Ground.WORLDMODEL)
        elif tok.ground is Ground.HYPOTHESIS:
            if _hypothesis_ok(tok):
                resolved.add(Ground.HYPOTHESIS)

    # 4. a dry-run claim can only stand on re-executable proof (oracle/cert), never on
    #    its own LLM reasoning (worldmodel-via-llm / hypothesis).
    if claim.from_dryrun:
        resolved &= {Ground.ORACLE, Ground.CERT}

    # 5. label — fact strength first, then hypothesis, then ungrounded.
    fact = next((g for g in _FACT_ORDER if g in resolved), None)
    if fact is not None:
        # a FACT claim must declare a subject the ground is bound to: bug_class for
        # oracle/cert (the re-fire already checked it), a named entity for worldmodel
        # (the node-in-entity_refs binding already checked it).
        if fact in (Ground.ORACLE, Ground.CERT) and not claim.bug_class:
            return AdmittedClaim(
                claim=claim, verdict=VeracityVerdict.UNGROUNDED,
                reason="a re-executed proof is present but the claim declares no bug_class "
                       "subject to bind it to — an unbound proof grounds nothing")
        # the calibrated confidence is the RE-EXECUTED oracle value, not a proposer number.
        conf = oracle_conf if (fact is Ground.ORACLE and oracle_conf is not None) else claim.proposed_confidence
        return AdmittedClaim(claim=claim, verdict=VeracityVerdict.GROUNDED, strength=fact,
                             grounded_by=[g.value for g in resolved], calibrated_confidence=conf,
                             reason=f"grounded by re-executed {fact.value} bound to the claim's subject")
    if Ground.HYPOTHESIS in resolved:
        prior = next((t.prior for t in claim.tokens if t.ground is Ground.HYPOTHESIS), None)
        return AdmittedClaim(claim=claim, verdict=VeracityVerdict.GROUNDED, strength=Ground.HYPOTHESIS,
                             grounded_by=["hypothesis"], calibrated_confidence=prior,
                             reason="admitted as a gated, prior-capped hypothesis (not a fact)")
    return AdmittedClaim(
        claim=claim, verdict=VeracityVerdict.UNGROUNDED,
        reason="no cited ground re-verified — rendered as labelled analyst commentary, never as fact")
