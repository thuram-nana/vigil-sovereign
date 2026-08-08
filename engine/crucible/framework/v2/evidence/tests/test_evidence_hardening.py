"""PHASE 0.2 — evidence-verification hardening (operator review of certify.py).

Each test pins a protection the review found CLAIMED-but-not-ENFORCED, so the comment and the code now
agree. Grouped by the review's findings; the three highest-priority first.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence import (
    build_certificate,
    build_chain,
    sign_certificate,
    sign_head,
    verify_bundle,
    verify_certificate,
)
from framework.v2.evidence.certify import SUPPORTED_SCHEMA_VERSIONS, trust_root_fingerprint
from framework.v2.evidence.manifest import verify_manifest
from framework.v2.evidence.models import ArtifactRef, ReportClaim
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200,
              "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user"}


def _trust_root(threshold=2, n=3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _finding(ref="boolean-sqli", engagement="acme"):
    ctx = FindingContext.from_http_responses(
        _BASE, _DIVERGENT, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    return {"check_id": ref, "bug_class": "boolean_sqli",
            "confirmed_by": c.confirmed_by.value if c else "differential_response",
            "confidence": c.confidence if c else 0.9,
            "oracle_context": ctx.model_dump(mode="json")}, ctx.model_dump(mode="json")


# ============ #1 (CRITICAL) — a signed head is REQUIRED for BundleVerification.ok ==================

def test_unsigned_head_bundle_is_not_ok_even_with_signed_certs():
    tr, signers = _trust_root()
    f, ctx = _finding()
    cert = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])
    chain = build_chain([cert.certificate.cert_digest])
    # head=None: an internally-consistent UNSIGNED chain must NOT pass — the exact hole the review found.
    r = verify_bundle([cert], chain, None, contexts={"boolean-sqli": ctx}, trust_root=tr)
    assert r.chain_ok is True          # the unsigned chain is internally consistent...
    assert r.head_anchored is False    # ...but it is NOT anchored by a governance-signed head
    assert r.ok is False               # so the bundle is NOT sound
    # the same bundle WITH a valid signed head verifies
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    r2 = verify_bundle([cert], chain, head, contexts={"boolean-sqli": ctx}, trust_root=tr)
    assert r2.head_anchored is True and r2.ok is True


# ============ #2 — oracle version stamped AND surfaced (informational, non-gating) =================

def test_stale_oracle_version_flagged_but_still_sound():
    tr, signers = _trust_root()
    f, ctx = _finding()
    cert = build_certificate(f, engagement_slug="acme", seq=0)
    # tamper the stamped oracle_version to a value that differs from the current oracle body
    forged = cert.model_copy(update={"oracle_version": "sha256:0000deadbeef"})
    signed = sign_certificate(forged, signers[:2])
    v = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    assert v.oracle_version_current is False          # the change is DETECTED + surfaced
    assert v.reproduced is True and v.ok is True       # but reproduction (current oracle) holds → still sound
    assert "ORACLE-VERSION CHANGED" in v.reason


# ============ #3 — authenticated freshness: three distinct states ==================================

def test_freshness_three_states():
    tr, signers = _trust_root()
    f, ctx = _finding()
    # a cert with a 60s TTL
    cert = build_certificate({**f, "freshness_ttl_seconds": 60}, engagement_slug="acme", seq=0)
    signed = sign_certificate(cert, signers[:2])
    # (a) no authenticated time → freshness NOT asserted
    v0 = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    assert v0.currently_fresh is None and v0.ok is True
    # (b) anchored, within TTL → fresh
    v1 = verify_certificate(signed, oracle_context=ctx, trust_root=tr, now=1000, anchor_gen_time=990)
    assert v1.currently_fresh is True and v1.ok is True
    # (c) anchored, beyond TTL → STALE, but authenticity/soundness SURVIVE expiration
    v2 = verify_certificate(signed, oracle_context=ctx, trust_root=tr, now=100000, anchor_gen_time=990)
    assert v2.currently_fresh is False and v2.ok is True and v2.authentic is True


def test_zero_ttl_is_non_expiring_once_anchored():
    tr, signers = _trust_root()
    f, ctx = _finding()
    signed = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])  # ttl 0
    v = verify_certificate(signed, oracle_context=ctx, trust_root=tr, now=10**9, anchor_gen_time=0)
    assert v.currently_fresh is True


# ============ #4 — trust-root fingerprint enforced at the entry point ==============================

def test_trust_root_pin_refuses_a_swapped_trust_root():
    tr, signers = _trust_root()
    f, ctx = _finding()
    signed = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])
    good_fp = trust_root_fingerprint(tr)
    # correct pin → authentic
    ok = verify_certificate(signed, oracle_context=ctx, trust_root=tr, expected_trust_root_fingerprint=good_fp)
    assert ok.authentic is True and ok.ok is True
    # an ATTACKER-supplied trust root (fresh keys) that validly signs a forged cert...
    atr, asigners = _trust_root()
    forged = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), asigners[:2])
    # ...its own signatures verify against ITS trust root, but the out-of-band pin refuses it:
    bad = verify_certificate(forged, oracle_context=ctx, trust_root=atr,
                             expected_trust_root_fingerprint=good_fp)
    assert bad.authentic is False and bad.ok is False and "PIN MISMATCH" in bad.reason


# ============ #5 — unknown schema version fails closed ============================================

def test_unknown_schema_version_fails_closed():
    tr, signers = _trust_root()
    f, ctx = _finding()
    cert = build_certificate(f, engagement_slug="acme", seq=0)
    forged = cert.model_copy(update={"schema_version": 999})
    signed = sign_certificate(forged, signers[:2])
    v = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    assert v.schema_ok is False and v.ok is False
    assert 999 not in SUPPORTED_SCHEMA_VERSIONS


# ============ #6 — render_as is a closed label set ================================================

def test_render_as_rejects_unknown_label():
    ReportClaim(sentence="x", bug_class="boolean_sqli", render_as="fact")               # ok
    ReportClaim(sentence="x", render_as="analyst-commentary")                            # ok
    for bad in ("verified", "machine-fact", "FACT", ""):
        with pytest.raises(ValidationError):
            ReportClaim(sentence="x", render_as=bad)


# ============ #7 — duplicate finding_ref bundle refused ===========================================

def test_duplicate_finding_ref_bundle_refused():
    tr, signers = _trust_root()
    f, ctx = _finding(ref="dup")
    c0 = sign_certificate(build_certificate({**f, "seq": 0}, engagement_slug="acme", seq=0), signers[:2])
    c1 = sign_certificate(build_certificate({**f, "confidence": 0.8}, engagement_slug="acme", seq=1), signers[:2])
    chain = build_chain([c0.certificate.cert_digest, c1.certificate.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    r = verify_bundle([c0, c1], chain, head, contexts={"dup": ctx}, trust_root=tr)
    assert r.refs_unique is False and r.ok is False and "DUPLICATE finding_ref" in r.chain_note


# ============ #8 — cross-engagement bundle refused ================================================

def test_cross_engagement_bundle_refused():
    tr, signers = _trust_root()
    fa, ca = _finding(ref="a", engagement="acme")
    fb, cb = _finding(ref="b", engagement="acme")
    c0 = sign_certificate(build_certificate(fa, engagement_slug="acme", seq=0), signers[:2])
    c1 = sign_certificate(build_certificate(fb, engagement_slug="OTHER", seq=1), signers[:2])  # different engagement
    chain = build_chain([c0.certificate.cert_digest, c1.certificate.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    r = verify_bundle([c0, c1], chain, head, contexts={"a": ca, "b": cb}, trust_root=tr)
    assert r.single_engagement is False and r.ok is False and "CROSS-ENGAGEMENT" in r.chain_note


# ============ #9 — artifact symlink / non-regular refused ==========================================

def test_manifest_refuses_a_symlinked_artifact(tmp_path):
    root = tmp_path / "ev"
    root.mkdir()
    (root / "real.txt").write_bytes(b"hello")
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"SECRET-OUTSIDE-ROOT")
    # (a) a symlink pointing OUTSIDE the root — caught by the confinement resolve ("escapes root").
    (root / "out.txt").symlink_to(secret)
    ro = verify_manifest([ArtifactRef(path="out.txt", sha256="0" * 64, size=19)], root=root)
    assert ro and ro[0][1] is False and "escape" in ro[0][2].lower()
    # (b) a symlink pointing INSIDE the root (to a real file) — resolves within root, so it passes the
    #     confinement check; the explicit is_symlink refusal is the load-bearing defense here.
    (root / "in.txt").symlink_to(root / "real.txt")
    ri = verify_manifest([ArtifactRef(path="in.txt", sha256="0" * 64, size=5)], root=root)
    assert ri and ri[0][1] is False and "symlink" in ri[0][2].lower()


# ============ tool_version + freshness_ttl round-trip + byte-identity when absent ==================

def test_tool_version_and_freshness_signed_and_absent_is_byte_identical():
    from framework.v2.evidence.canonical import evidence_signing_bytes
    tr, signers = _trust_root()
    f, ctx = _finding()
    # a cert WITHOUT the new fields serialises byte-identically to a cert that never had them
    plain = build_certificate(f, engagement_slug="acme", seq=0)
    assert "tool_version" not in plain.model_dump() and "freshness_ttl_seconds" not in plain.model_dump()
    # a cert WITH the fields carries them in the SIGNED bytes
    stamped = build_certificate({**f, "tool_version": "nmap 7.99", "freshness_ttl_seconds": 3600},
                                engagement_slug="acme", seq=0)
    d = stamped.model_dump()
    assert d["tool_version"] == "nmap 7.99" and d["freshness_ttl_seconds"] == 3600
    # the signature covers them: a signed stamped cert verifies, and tampering the tool_version breaks it
    signed = sign_certificate(stamped, signers[:2])
    assert verify_certificate(signed, oracle_context=ctx, trust_root=tr).ok is True
    tampered = signed.model_copy(update={"certificate": stamped.model_copy(update={"tool_version": "evil"})})
    assert verify_certificate(tampered, oracle_context=ctx, trust_root=tr).authentic is False
