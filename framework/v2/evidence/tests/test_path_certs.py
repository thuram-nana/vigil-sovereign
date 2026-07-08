"""
Anti-hallucination P4c — derived attack paths are CERTIFIED evidence, bound to the
findings under them.

A forward-reasoning attack path (attacker → crown jewel) is a CLAIM about what the
confirmed facts compose into; it is only as sound as the findings that establish its hops.
A PathCertificate records the hops and the cert_digests of the backing findings, is
anchored in the SAME signed chain as those findings, and verify_bundle FAILS CLOSED when a
path cites backing that is absent, unverified, or missing entirely — so a fabricated or
under-supported route can never pass as a proven path. Everything is additive: a bundle
with no path certificates verifies exactly as before.
"""

from __future__ import annotations

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence import (
    build_certificate,
    build_chain,
    build_path_certificate,
    sign_certificate,
    sign_head,
    verify_bundle,
)
from framework.v2.scanner.orchestrator import AttackPath, ChainedConclusion
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200, "body": "id=1 name=alice role=user\nid=2 name=bob role=admin"}


def _finding(mutated=_DIVERGENT) -> dict:
    ctx = FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    return {"check_id": "boolean-sqli", "bug_class": "boolean_sqli",
            "confirmed_by": c.confirmed_by.value if c else "differential_response",
            "confidence": c.confidence if c else 0.9, "oracle_context": ctx.model_dump(mode="json")}


def _trust_root(threshold=2, n=3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    return tr, [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]


def _path() -> AttackPath:
    return AttackPath(steps=[
        ChainedConclusion(src="attacker", edge="reaches", dst="endpoint:q", technique="boolean_sqli"),
        ChainedConclusion(src="endpoint:q", edge="pivots_to", dst="crown:db", technique="exfil"),
    ])


def _ctx_map(f: dict) -> dict:
    return {"boolean-sqli": f["oracle_context"]}


# ---- a path backed by a verified finding cert verifies -----------------------


def test_path_backed_by_verified_finding_verifies() -> None:
    tr, signers = _trust_root()
    f = _finding()
    fcert = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])
    fdig = fcert.certificate.cert_digest
    pcert = build_path_certificate(_path(), backing_cert_digests=[fdig], engagement_slug="acme", seq=1)
    chain = build_chain([fdig, pcert.cert_digest])          # finding THEN path
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])

    v = verify_bundle([fcert], chain, head, contexts=_ctx_map(f), trust_root=tr, path_certs=[pcert])
    assert v.ok and v.cert_set_bound
    assert v.path_results and v.path_results[0].backing_bound
    assert v.path_results[0].destination == "crown:db"


# ---- a path with no / absent / unverified backing FAILS CLOSED ---------------


def test_path_with_no_backing_fails_closed() -> None:
    tr, signers = _trust_root()
    f = _finding()
    fcert = sign_certificate(build_certificate(f, seq=0), signers[:2])
    fdig = fcert.certificate.cert_digest
    pcert = build_path_certificate(_path(), backing_cert_digests=[], seq=1)   # NO backing
    chain = build_chain([fdig, pcert.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])

    v = verify_bundle([fcert], chain, head, contexts=_ctx_map(f), trust_root=tr, path_certs=[pcert])
    assert not v.path_results[0].backing_bound and not v.ok
    assert "NO backing" in v.path_results[0].reason


def test_path_citing_absent_backing_fails_closed() -> None:
    tr, signers = _trust_root()
    f = _finding()
    fcert = sign_certificate(build_certificate(f, seq=0), signers[:2])
    fdig = fcert.certificate.cert_digest
    pcert = build_path_certificate(_path(), backing_cert_digests=["de" * 32], seq=1)  # bogus digest
    chain = build_chain([fdig, pcert.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])

    v = verify_bundle([fcert], chain, head, contexts=_ctx_map(f), trust_root=tr, path_certs=[pcert])
    assert not v.path_results[0].backing_bound and not v.ok
    assert "absent or unverified" in v.path_results[0].reason


def test_path_backed_by_a_finding_that_fails_verification_fails_closed() -> None:
    # the backing finding's evidence does NOT re-fire (non-divergent) → its cert is not
    # .ok → not in the verified set → the path that leans on it is refused.
    tr, signers = _trust_root()
    fbad = _finding(_BASE)
    fcert = sign_certificate(build_certificate(fbad, seq=0), signers[:2])
    fdig = fcert.certificate.cert_digest
    pcert = build_path_certificate(_path(), backing_cert_digests=[fdig], seq=1)
    chain = build_chain([fdig, pcert.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])

    v = verify_bundle([fcert], chain, head, contexts=_ctx_map(fbad), trust_root=tr, path_certs=[pcert])
    assert not v.certificate_results[0].ok        # the finding itself did not reproduce
    assert not v.path_results[0].backing_bound and not v.ok


# ---- tamper + chain anchoring + determinism + default-safety -----------------


def test_tampering_a_path_step_breaks_the_chain_set_binding() -> None:
    tr, signers = _trust_root()
    f = _finding()
    fcert = sign_certificate(build_certificate(f, seq=0), signers[:2])
    fdig = fcert.certificate.cert_digest
    pcert = build_path_certificate(_path(), backing_cert_digests=[fdig], seq=1)
    chain = build_chain([fdig, pcert.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])

    tampered = pcert.model_copy(update={"destination": "crown:evil"})  # digest now differs
    v = verify_bundle([fcert], chain, head, contexts=_ctx_map(f), trust_root=tr, path_certs=[tampered])
    assert not v.cert_set_bound and not v.ok       # its digest no longer matches the chain


def test_build_path_certificate_is_deterministic() -> None:
    a = build_path_certificate(_path(), backing_cert_digests=["b" * 64, "a" * 64], seq=1)
    b = build_path_certificate(_path(), backing_cert_digests=["a" * 64, "a" * 64, "b" * 64], seq=1)
    assert a.backing_cert_digests == ["a" * 64, "b" * 64]   # sorted + de-duped
    assert a.cert_digest == b.cert_digest


def test_path_requires_a_valid_signed_head_to_anchor() -> None:
    # THE FABRICATION BYPASS (review fix): path certs are NOT individually signed, so a
    # signed head is their only governance anchor. Without one, an attacker could fabricate
    # a route citing a genuine finding and rebuild the (unsigned) chain to match — so an
    # unsigned bundle must refuse the path CLOSED.
    tr, signers = _trust_root()
    f = _finding()
    fcert = sign_certificate(build_certificate(f, seq=0), signers[:2])
    fdig = fcert.certificate.cert_digest
    pcert = build_path_certificate(_path(), backing_cert_digests=[fdig], seq=1)
    chain = build_chain([fdig, pcert.cert_digest])

    unsigned = verify_bundle([fcert], chain, None, contexts=_ctx_map(f), trust_root=tr, path_certs=[pcert])
    assert not unsigned.path_results[0].backing_bound and not unsigned.ok
    assert "not anchored" in unsigned.path_results[0].reason
    # the SAME path, once anchored by a valid signed head, verifies
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    signed = verify_bundle([fcert], chain, head, contexts=_ctx_map(f), trust_root=tr, path_certs=[pcert])
    assert signed.ok and signed.path_results[0].backing_bound


def test_bundle_without_paths_is_unchanged() -> None:
    tr, signers = _trust_root()
    f = _finding()
    fcert = sign_certificate(build_certificate(f, seq=0), signers[:2])
    chain = build_chain([fcert.certificate.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    v = verify_bundle([fcert], chain, head, contexts=_ctx_map(f), trust_root=tr)
    assert v.ok and v.cert_set_bound and v.path_results == []
