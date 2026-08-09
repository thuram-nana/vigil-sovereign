"""
D2 — artifact IDENTITY + SCOPE + FRESHNESS + COMPLETENESS bound into the evidence certificate.

A posture FACT must prove WHICH artifact, of WHAT scope, captured WHEN, and whether the
capture was COMPLETE — otherwise a valid m-of-n signature could ride over an obsolete,
partial, or unrelated artifact and still "verify". These OPTIONAL fields bind that
provenance INTO the signed certificate. Two invariants are load-bearing here:

  * PRESENT  → the fields land in the SIGNED canonical bytes (a flipped value breaks
    authenticity) and SURVIVE ``verify_certificate`` (surfaced as ``bound_identity``,
    which does not gate ``.ok``).
  * ABSENT   → the certificate serialises BYTE-IDENTICALLY to one built before these
    fields existed — no existing signature, digest, or PCF export changes.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence import (
    build_certificate,
    sign_certificate,
    verify_certificate,
)
from framework.v2.evidence.models import EvidenceCertificate
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200,
              "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user"}

# One representative population of every D2 field (resource_scope with a subset of allowed keys).
_D2 = dict(
    artifact_sha256="a" * 64,
    collector_id="cloud-collector",
    collector_version="sha256:collectorbody",
    resource_scope={"provider": "aws", "account": "111122223333", "region": "us-east-1"},
    capture_time_epoch=1_700_000_000,
    capture_method="api:list",
    requested_scope="account:111122223333/*",
    returned_scope="account:111122223333/us-east-1",
    completeness="partial",
    collector_signature="opaque-collector-sig",
)


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


# ---- ABSENT: byte-identity to a pre-D2 certificate --------------------------------------------------


def test_cert_without_d2_fields_serialises_byte_identically() -> None:
    f = _finding()
    plain = build_certificate(f, engagement_slug="acme", seq=0)
    d = plain.model_dump(mode="json")
    # NONE of the D2 members leak into the canonical bytes when unset.
    for k in EvidenceCertificate._D2_FIELDS:
        assert k not in d, f"empty D2 field {k!r} leaked into canonical bytes"
    # a fresh identical build has the identical digest (the serializer is stable + order-independent)
    assert build_certificate(f, engagement_slug="acme", seq=0).cert_digest == plain.cert_digest
    assert plain.bound_identity == {}


def test_empty_string_and_empty_scope_are_still_dropped() -> None:
    # explicitly passing "" / {} / None must be treated as absent — byte-identical to passing nothing.
    f = _finding()
    plain = build_certificate(f, seq=3)
    explicit_empty = build_certificate(
        f, seq=3, artifact_sha256="", collector_id="", resource_scope={},
        capture_time_epoch=None, completeness="")
    assert explicit_empty.cert_digest == plain.cert_digest
    assert "resource_scope" not in explicit_empty.model_dump(mode="json")


# ---- PRESENT: fields land in the signed bytes and survive verify ------------------------------------


def test_d2_fields_land_in_canonical_bytes_and_change_the_digest() -> None:
    f = _finding()
    plain = build_certificate(f, seq=0)
    bound = build_certificate(f, seq=0, **_D2)
    d = bound.model_dump(mode="json")
    for k, v in _D2.items():
        assert d[k] == v, f"D2 field {k!r} not in canonical form"
    # binding real provenance MUST change the signed bytes (else it could not be tamper-evident)
    assert bound.cert_digest != plain.cert_digest


def test_d2_fields_survive_verify_and_are_surfaced_not_gating() -> None:
    tr, signers = _trust_root()
    f = _finding()
    signed = sign_certificate(build_certificate(f, seq=0, **_D2), signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.ok                                   # D2 fields do NOT gate .ok
    assert v.authentic and v.bound and v.reproduced
    # every populated field is surfaced, faithfully, through verification
    assert v.bound_identity == _D2
    assert "identity:" in v.reason


def test_flipping_a_bound_d2_field_breaks_authenticity() -> None:
    # the fields are SIGNED with the cert: mutating one after signing breaks the m-of-n signature.
    tr, signers = _trust_root()
    f = _finding()
    signed = sign_certificate(build_certificate(f, seq=0, **_D2), signers[:2])
    signed.certificate.completeness = "complete"   # tamper: partial -> complete
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert not v.authentic and not v.ok


def test_flipping_a_scope_value_breaks_authenticity() -> None:
    tr, signers = _trust_root()
    f = _finding()
    signed = sign_certificate(build_certificate(f, seq=0, **_D2), signers[:2])
    signed.certificate.resource_scope = dict(_D2["resource_scope"], region="eu-west-1")  # tamper region
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert not v.authentic and not v.ok


def test_partial_population_only_binds_present_fields() -> None:
    f = _finding()
    cert = build_certificate(f, seq=0, artifact_sha256="b" * 64, completeness="complete")
    d = cert.model_dump(mode="json")
    assert d["artifact_sha256"] == "b" * 64 and d["completeness"] == "complete"
    assert "collector_id" not in d and "resource_scope" not in d
    assert cert.bound_identity == {"artifact_sha256": "b" * 64, "completeness": "complete"}


# ---- validation: enum + scope-key allowlist --------------------------------------------------------


def test_completeness_enum_is_enforced() -> None:
    with pytest.raises(ValidationError):
        EvidenceCertificate(finding_ref="x", oracle_context_digest="d", completeness="mostly")
    # the three valid values + "" all parse
    for good in ("", "complete", "partial", "unknown"):
        EvidenceCertificate(finding_ref="x", oracle_context_digest="d", completeness=good)


def test_resource_scope_key_allowlist_and_string_values() -> None:
    with pytest.raises(ValidationError):
        EvidenceCertificate(finding_ref="x", oracle_context_digest="d",
                            resource_scope={"provider": "aws", "evil": "1"})
    with pytest.raises(ValidationError):
        EvidenceCertificate(finding_ref="x", oracle_context_digest="d",
                            resource_scope={"account": 12345})   # non-string value


def test_capture_time_epoch_rejects_negative() -> None:
    with pytest.raises(ValidationError):
        EvidenceCertificate(finding_ref="x", oracle_context_digest="d", capture_time_epoch=-1)


# ---- the fields survive a full PCF export / offline re-verify ---------------------------------------


def test_d2_fields_ride_the_pcf_export_and_verify() -> None:
    # the D2 provenance is authenticated by the embedded signed certificate; a full PCF round-trip
    # (project -> offline verify) still verifies with the fields present.
    from framework.v2.evidence.pcf import to_pcf, verify_pcf

    tr, signers = _trust_root()
    f = _finding()
    signed = sign_certificate(build_certificate(f, seq=0, **_D2), signers[:2])
    pcf = to_pcf(signed, oracle_context=f["oracle_context"])
    # the fields live on the authoritative embedded certificate (covered by the signature)
    assert pcf["_crucible"]["certificate"]["completeness"] == "partial"
    r = verify_pcf(pcf, tr)
    assert r.verified, f"{r.step}: {r.reason}"
    # tamper a D2 field in the embedded cert -> the signature no longer covers it -> rejected
    pcf["_crucible"]["certificate"]["completeness"] = "complete"
    assert not verify_pcf(pcf, tr).verified
