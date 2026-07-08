"""
The veracity firewall — the core anti-hallucination invariant. A claim becomes a FACT
only when a cited ground RE-EXECUTES: a real oracle re-fires, a signed cert re-verifies,
a world-model node is belief-floored with grounded provenance, or a gated hypothesis is
admitted as a labelled hypothesis (never a fact). Every forgery path — a string
provenance, an LLM 'said so', a dry-run, a fabricated entity, a refuted assertion — is
demoted, never promoted. The firewall can only ever demote or abstain.
"""

from __future__ import annotations

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence import build_certificate, sign_certificate
from framework.v2.veracity import Claim, Ground, GroundingToken, VeracityVerdict, admit
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import Node, NodeKind

_BASE = {"status": 200, "body": "No results."}
_DIVERGENT = {"status": 200, "body": "id=1 alice user\nid=2 bob admin\nid=3 carol user"}


def _oracle_ctx(mutated=_DIVERGENT) -> dict:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]}).model_dump(mode="json")


def _trust_root():
    kps = [generate_keypair() for _ in range(3)]
    tr = TrustRoot(schema_version=1, threshold=2, authorizers=[
        AuthorizerKey(key_id=f"g{i}", name=f"A{i}", public_key_b64=k.public_key_b64) for i, k in enumerate(kps)])
    return tr, [(f"g{i}", k.private_key_b64) for i, k in enumerate(kps[:2])]


# ---- ORACLE ground: re-execution, not trust --------------------------------


def test_oracle_ground_admits_a_reproducing_context() -> None:
    ctx = _oracle_ctx()
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=FindingContext.model_validate(ctx))
    claim = Claim(text="boolean sqli at q", source="llm:critique", tokens=[
        GroundingToken.oracle(ctx, bug_class="boolean_sqli",
                              confirmed_by=c.confirmed_by.value, confidence=c.confidence)])
    a = admit(claim)
    assert a.verdict is VeracityVerdict.GROUNDED and a.is_fact and a.strength is Ground.ORACLE


def test_oracle_ground_rejects_a_non_firing_context() -> None:
    claim = Claim(text="fabricated sqli", tokens=[
        GroundingToken.oracle(_oracle_ctx(_BASE), bug_class="boolean_sqli",  # non-divergent → won't fire
                              confirmed_by="differential_response")])
    a = admit(claim)
    assert a.verdict is VeracityVerdict.UNGROUNDED and not a.is_fact


# ---- CERT ground ------------------------------------------------------------


def test_cert_ground_admits_a_verifying_certificate() -> None:
    tr, signers = _trust_root()
    ctx = _oracle_ctx()
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=FindingContext.model_validate(ctx))
    finding = {"check_id": "s1", "bug_class": "boolean_sqli", "confirmed_by": c.confirmed_by.value,
               "confidence": c.confidence, "oracle_context": ctx}
    signed = sign_certificate(build_certificate(finding, seq=0), signers)
    claim = Claim(text="signed sqli", tokens=[
        GroundingToken.cert(signed.model_dump(mode="json"), oracle_context=ctx)])
    a = admit(claim, trust_root=tr)
    assert a.is_fact and a.strength is Ground.CERT

    # without the trust root, an unauthenticated cert cannot ground
    assert not admit(claim, trust_root=None).is_fact


# ---- WORLDMODEL ground: belief floor + provenance must be grounded ----------


def _world() -> WorldModel:
    w = WorldModel()
    for _ in range(4):  # corroborate a real fact above the belief floor
        w.add_node(Node(id="endpoint:real", kind=NodeKind.ENDPOINT, provenance="oracle:finding-1",
                        confidence=0.9, first_seen=1, last_seen=1))
    # a high-scalar-confidence node whose provenance is an LLM assertion (forgery)
    w.add_node(Node(id="host:forged", kind=NodeKind.HOST, provenance="llm-said-so",
                    confidence=0.99, first_seen=1, last_seen=1))
    # a net-refuted node (belief driven down by failed re-observation)
    for c in (0.05, 0.05, 0.05):
        w.add_node(Node(id="host:refuted", kind=NodeKind.HOST, provenance="oracle:x",
                        confidence=c, first_seen=1, last_seen=1))
    return w


def test_worldmodel_ground_admits_belief_floored_grounded_node() -> None:
    a = admit(Claim(text="real endpoint", entity_refs=["endpoint:real"],
                    tokens=[GroundingToken.worldmodel("endpoint:real")]), world=_world())
    assert a.is_fact and a.strength is Ground.WORLDMODEL


def test_worldmodel_ground_rejects_llm_provenance_even_at_high_confidence() -> None:
    # the forgery the maps named: provenance='llm-said-so' with confidence 0.99 must NOT ground
    a = admit(Claim(text="forged", entity_refs=["host:forged"],
                    tokens=[GroundingToken.worldmodel("host:forged")]), world=_world())
    assert not a.is_fact and a.verdict is VeracityVerdict.UNGROUNDED


def test_contradiction_when_world_refutes_the_entity() -> None:
    a = admit(Claim(text="refuted host is exploitable", entity_refs=["host:refuted"]), world=_world())
    assert a.verdict is VeracityVerdict.CONTRADICTED


def test_fabricated_entity_is_ungrounded() -> None:
    a = admit(Claim(text="attack on ghost", entity_refs=["host:does-not-exist"]), world=_world())
    assert a.verdict is VeracityVerdict.UNGROUNDED and "absent" in a.reason


# ---- HYPOTHESIS ground: grounded, but NEVER a fact --------------------------


def test_gated_hypothesis_is_grounded_but_not_fact() -> None:
    a = admit(Claim(text="staging.x probably exists",
                    tokens=[GroundingToken.hypothesis(gated=True, prior=0.4)]))
    assert a.verdict is VeracityVerdict.GROUNDED and a.is_hypothesis and not a.is_fact
    assert a.render_as == "hypothesis"


def test_overconfident_or_ungated_hypothesis_is_ungrounded() -> None:
    assert not admit(Claim(tokens=[GroundingToken.hypothesis(gated=True, prior=0.95)])).is_fact
    assert admit(Claim(tokens=[GroundingToken.hypothesis(gated=False, prior=0.4)])).verdict \
        is VeracityVerdict.UNGROUNDED


# ---- dry-run + no-token + demote-only --------------------------------------


def test_dryrun_claim_cannot_self_ground() -> None:
    # a dry-run LLM 'hypothesis' is fabricated → cannot ground
    a = admit(Claim(text="dryrun guess", from_dryrun=True,
                    tokens=[GroundingToken.hypothesis(gated=True, prior=0.4, from_dryrun=True)]))
    assert a.verdict is VeracityVerdict.UNGROUNDED


def test_dryrun_claim_still_stands_on_reexecutable_oracle_proof() -> None:
    # re-executable proof stands on its own regardless of how the claim was authored
    ctx = _oracle_ctx()
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=FindingContext.model_validate(ctx))
    a = admit(Claim(text="dryrun-authored but oracle-proven", from_dryrun=True, tokens=[
        GroundingToken.oracle(ctx, bug_class="boolean_sqli", confirmed_by=c.confirmed_by.value)]))
    assert a.is_fact


def test_no_token_is_ungrounded_never_dropped() -> None:
    a = admit(Claim(text="bare llm assertion", source="llm:critique"))
    assert a.verdict is VeracityVerdict.UNGROUNDED and a.render_as == "analyst-commentary"
