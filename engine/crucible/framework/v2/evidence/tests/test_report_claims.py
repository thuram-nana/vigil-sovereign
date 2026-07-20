"""
Anti-hallucination P4 — report sentences bound INTO the evidence certificate.

A certificate authenticates a finding's replayable oracle_context; P4 also binds the
atomic report SENTENCES about that finding into the same signed object. So the governance
signature covers them (flip a sentence → authenticity fails), and verify_certificate gains
a 5th layer: every sentence presented AS a fact must RE-ADMIT as a fact through the
firewall. Because a proof is bound to its subject, a sentence that asserts a different (or
larger) class than the evidence proves — a laundered claim — does NOT ground and fails the
certificate closed. Non-fact sentences are retained as labelled commentary, never asserted.

Everything is additive + byte-identical for certs without bound claims.
"""

from __future__ import annotations

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence import (
    ReportClaim,
    build_certificate,
    claims_for_finding,
    decompose_prose,
    sign_certificate,
    verify_certificate,
)
from framework.v2.evidence.models import EvidenceCertificate
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200,
              "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user"}


def _finding(mutated=_DIVERGENT) -> dict:
    ctx = FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    return {
        "check_id": "boolean-sqli", "bug_class": "boolean_sqli",
        "confirmed_by": c.confirmed_by.value if c else "differential_response",
        "confidence": c.confidence if c else 0.9,
        "oracle_context": ctx.model_dump(mode="json"),
    }


def _trust_root(threshold=2, n=3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    return tr, [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]


# ---- byte-identity: a cert without bound claims is unchanged -----------------


def test_cert_without_claims_serialises_byte_identically() -> None:
    f = _finding()
    plain = build_certificate(f, engagement_slug="acme", seq=0)
    d = plain.model_dump(mode="json")
    assert "report_claims" not in d                 # the field never leaks into canonical bytes
    assert plain.schema_version == 1                 # stays v1 without claims
    # a fresh identical build has the identical digest (the serializer is stable)
    assert build_certificate(f, engagement_slug="acme", seq=0).cert_digest == plain.cert_digest


# ---- a fact sentence that re-grounds passes; a laundered one fails closed ----


def test_canonical_fact_claim_regrounds_and_verifies() -> None:
    tr, signers = _trust_root()
    f = _finding()
    claims = claims_for_finding(f)                   # the canonical STRUCTURED fact
    assert [c.render_as for c in claims] == ["fact"]
    cert = build_certificate(f, report_claims=claims, seq=0)
    assert cert.schema_version == 2                  # claim-bearing certs are v2
    signed = sign_certificate(cert, signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.claims_grounded and v.ok


def test_relabelled_fact_claim_fails_the_certificate_closed() -> None:
    # THE ENFORCED BINDING: a boolean_sqli finding whose bound fact claim DECLARES a
    # different class (rce) than the evidence proves must NOT verify — the class does not
    # re-ground, so claims_grounded is False and the whole certificate is not ok, EVEN
    # THOUGH the signature is valid and the oracle reproduces for the real class.
    tr, signers = _trust_root()
    f = _finding()
    relabelled = ReportClaim(sentence="The attacker achieves remote code execution.",
                             bug_class="rce", render_as="fact")
    cert = build_certificate(f, report_claims=[relabelled], seq=0)
    signed = sign_certificate(cert, signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.authentic and v.bound and v.reproduced   # the finding itself is sound...
    assert not v.claims_grounded and not v.ok         # ...but its relabelled fact claim is not


def test_deterministic_gate_does_not_certify_natural_language() -> None:
    # HONEST LIMITATION (documented, not a bug): the gate binds + signs + checks the
    # declared CLASS re-executes; it does NOT do natural-language entailment. A hand-built
    # fact claim whose TEXT over-claims but whose declared class MATCHES the evidence still
    # passes — a deterministic gate cannot read English. The load-bearing mitigation is
    # that the sanctioned builder never mints a fact claim from arbitrary prose.
    tr, signers = _trust_root()
    f = _finding()   # boolean_sqli
    overclaim = ReportClaim(sentence="The attacker achieves full RCE and drains every account.",
                            bug_class="boolean_sqli", render_as="fact")   # class MATCHES
    cert = build_certificate(f, report_claims=[overclaim], seq=0)
    signed = sign_certificate(cert, signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.claims_grounded and v.ok                 # the boundary: no NL entailment
    # ...but claims_for_finding NEVER stamps free prose as fact — over-claim prose is
    # always labelled analyst commentary, so it cannot launder through the sanctioned path.
    built = claims_for_finding(f, commentary_prose="The attacker achieves full RCE.")
    assert [c.render_as for c in built if "RCE" in c.sentence] == ["analyst-commentary"]
    assert sum(c.render_as == "fact" for c in built) == 1   # exactly one structured fact


def test_commentary_sentence_imposes_no_obligation() -> None:
    # a sentence bound as labelled analyst commentary is retained but asserts nothing, so
    # it never blocks the certificate — even wild prose is fine as long as it is labelled.
    tr, signers = _trust_root()
    f = _finding()
    claims = claims_for_finding(f, commentary_prose="This may indicate a deeper architectural flaw worth review.")
    cert = build_certificate(f, report_claims=claims, seq=0)
    signed = sign_certificate(cert, signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.claims_grounded and v.ok


def test_tampering_a_bound_sentence_breaks_authenticity() -> None:
    # the sentences are SIGNED with the cert: flipping one after signing breaks the
    # m-of-n signature (canonical bytes change), so authenticity fails.
    tr, signers = _trust_root()
    f = _finding()
    cert = build_certificate(f, report_claims=claims_for_finding(f), seq=0)
    signed = sign_certificate(cert, signers[:2])
    signed.certificate.report_claims[0].sentence = "The attacker drains every account."  # tamper
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert not v.authentic and not v.ok


def test_verify_certificate_refires_the_oracle_once(monkeypatch) -> None:
    # Speed X1 — verify_certificate re-fires the retained oracle TWICE over byte-identical
    # evidence: once for the reproduction check (layer 4) and again inside the 5th-layer
    # claims-grounded re-admission (a fact sentence whose declared class == the cert's class).
    # The pure-function reverify memo collapses those into ONE oracle run without changing a
    # verdict. Build + sign first, then install the counter, so only verify is measured.
    import framework.v2.verify.reverify as reverify

    tr, signers = _trust_root()
    f = _finding()
    signed = sign_certificate(
        build_certificate(f, report_claims=claims_for_finding(f), seq=0), signers[:2])

    reverify._reverify_cached.cache_clear()
    calls = {"n": 0}
    real = reverify.confirm_finding

    def _counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(reverify, "confirm_finding", _counting)
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.ok and v.claims_grounded
    assert calls["n"] == 1        # reproduction + claims-grounding share ONE memoized re-fire


def test_fact_claim_fails_closed_when_context_cannot_reground() -> None:
    # a fact claim whose backing evidence no longer re-fires (non-divergent context)
    # fails closed — reproduced AND claims_grounded both False.
    tr, signers = _trust_root()
    f = _finding(_BASE)   # non-divergent → oracle does not fire
    cert = build_certificate(f, report_claims=claims_for_finding(f), seq=0)
    signed = sign_certificate(cert, signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert not v.claims_grounded and not v.ok


# ---- deterministic decomposition -------------------------------------------


def test_decompose_prose_is_deterministic_and_atomic() -> None:
    text = "SQLi is confirmed on q.  It returns admin rows! Is it exploitable? Yes."
    got = decompose_prose(text)
    assert got == ["SQLi is confirmed on q.", "It returns admin rows!",
                   "Is it exploitable?", "Yes."]
    assert decompose_prose(got and text) == got     # stable / idempotent input
    assert decompose_prose("") == [] and decompose_prose("   ") == []


def test_claims_for_finding_labels_fact_vs_commentary() -> None:
    f = _finding()
    claims = claims_for_finding(f, commentary_prose="B might matter. So might C.")
    kinds = [(c.render_as, c.bug_class) for c in claims]
    assert kinds[0] == ("fact", "boolean_sqli")                       # exactly one structured fact, first
    assert kinds.count(("fact", "boolean_sqli")) == 1
    assert ("analyst-commentary", "boolean_sqli") in kinds           # prose -> commentary


def test_build_certificate_sorts_claims_deterministically() -> None:
    f = _finding()
    a = build_certificate(f, report_claims=[
        ReportClaim(sentence="zeta.", bug_class="boolean_sqli"),
        ReportClaim(sentence="alpha.", bug_class="boolean_sqli")], seq=0)
    b = build_certificate(f, report_claims=[
        ReportClaim(sentence="alpha.", bug_class="boolean_sqli"),
        ReportClaim(sentence="zeta.", bug_class="boolean_sqli")], seq=0)
    assert a.cert_digest == b.cert_digest            # order-independent canonical bytes
    assert [c.sentence for c in a.report_claims] == ["alpha.", "zeta."]
