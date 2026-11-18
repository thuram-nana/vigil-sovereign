"""APEX PR-A — the certificate's additive SIGNED ``presentation`` block.

Invariants under test (a false-green either changes existing signed bundles' bytes, lets the block ride
without the flag, or — the self-red-pen — lets a forged/benign presentation change a FACT verdict):
  * DROPPED-WHEN-EMPTY / FLAG-OFF: with ``VIGIL_APEX_PRESENTATION`` unset, ``build_certificate`` embeds no
    block and the cert serialises BYTE-IDENTICALLY to one built before the field existed (old signatures hold).
  * EMBEDDED + SIGNED when on: the block is deterministic (no wallclock/rng) and part of the canonical bytes.
  * SELF-RED-PEN RP2 — the presentation can NEVER alter a FACT verdict: the oracle re-fire (``reproduced``) is
    identical whatever the presentation says, and mutating a signed cert's presentation is caught as a TAMPER
    (``authentic`` False) rather than silently flipping the verdict.
"""
from __future__ import annotations

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot

from framework.v2.evidence.canonical import evidence_signing_bytes
from framework.v2.evidence.certify import (
    _build_presentation,
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


def _reproducing_finding() -> dict:
    ctx = FindingContext.from_http_responses(
        _BASE, _DIVERGENT, bug_class="error_based_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})
    confirmed = confirm_finding(finding={"bug_class": "error_based_sqli"}, context=ctx)
    return {
        "check_id": "error-based-sqli", "bug_class": "error_based_sqli",
        "confirmed_by": confirmed.confirmed_by.value if confirmed else "differential_response",
        "confidence": confirmed.confidence if confirmed else 0.9,
        "severity": "Critical", "title": "SQL injection confirmed at q",
        "insertion_point": "GET /search?q=", "param": "q",
        "oracle_context": ctx.model_dump(mode="json"),
    }


def _trust_root(threshold: int, n: int):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"Authoriser {i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


# ---- pure derivation -------------------------------------------------------------------------------
def test_build_presentation_is_deterministic_and_shaped():
    f = _reproducing_finding()
    b1 = _build_presentation(f)
    assert isinstance(b1, dict)
    assert set(b1) >= {"schema", "plain_impact", "remediation", "priority", "standards"}
    assert b1["plain_impact"]["what"] and b1["plain_impact"]["established"]
    assert b1["remediation"] and "q" in b1["remediation"]          # finding-specific remediation
    assert b1["standards"]["controls"]["owasp"].startswith("A03") and "CWE-89" in b1["standards"]["controls"]["cwe"]
    assert b1["priority"]["effort"] in ("S", "M", "L", "XL")
    # deterministic: same finding -> identical block
    assert _build_presentation(_reproducing_finding()) == b1
    # a malformed finding never raises -> None (byte-identical, never fatal); a non-mapping input hits the
    # fail-open path and yields None rather than crashing the mint.
    assert _build_presentation(None) is None  # type: ignore[arg-type]


# ---- flag-off byte-identity ------------------------------------------------------------------------
def test_flag_off_is_byte_identical(monkeypatch):
    monkeypatch.delenv("VIGIL_APEX_PRESENTATION", raising=False)
    f = _reproducing_finding()
    cert = build_certificate(f, engagement_slug="acme", seq=1)
    dumped = cert.model_dump(mode="json")
    assert "presentation" not in dumped, "flag OFF must not embed a presentation block"
    # the signed bytes equal those of a cert built with the field explicitly absent (old bundles unchanged)
    assert cert.presentation is None


def test_serializer_drops_empty_presentation():
    empty = EvidenceCertificate(finding_ref="x", oracle_context_digest="sha256:deadbeef")
    assert "presentation" not in empty.model_dump(mode="json")
    withp = EvidenceCertificate(finding_ref="x", oracle_context_digest="sha256:deadbeef",
                                presentation={"schema": 1, "remediation": "patch"})
    assert withp.model_dump(mode="json").get("presentation") == {"schema": 1, "remediation": "patch"}


# ---- flag-on embedding -----------------------------------------------------------------------------
def test_flag_on_embeds_and_signs(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    f = _reproducing_finding()
    cert = build_certificate(f, engagement_slug="acme", seq=1)
    assert isinstance(cert.presentation, dict) and cert.presentation
    d = cert.model_dump(mode="json")
    assert "presentation" in d
    # the presentation is INSIDE the signed canonical bytes (tamper-evident), and flipping it changes them
    bytes_a = evidence_signing_bytes(d)
    d2 = dict(d)
    d2["presentation"] = {"schema": 1, "remediation": "SOMETHING ELSE"}
    assert evidence_signing_bytes(d2) != bytes_a
    # deterministic mint
    assert evidence_signing_bytes(build_certificate(f, engagement_slug="acme", seq=1).model_dump(mode="json")) == bytes_a


# ---- SELF-RED-PEN RP2: the presentation can NEVER change a FACT verdict -----------------------------
def test_presentation_cannot_alter_a_fact_verdict(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    tr, signers = _trust_root(threshold=2, n=3)
    f = _reproducing_finding()
    signed = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.authentic and v.bound and v.reproduced and v.ok, "the honest FACT must verify"

    # (1) MUTATE the signed cert's presentation to a benign lie (downgrade severity, bless it "no action
    # needed") WITHOUT re-signing. The tamper is CAUGHT (authentic False) and — crucially — the oracle
    # re-fire is UNCHANGED (reproduced still True): the verdict is a pure function of the oracle_context, not
    # of the presentation. So a forged benign presentation can neither ride silently nor flip the verdict.
    benign = {"schema": 1, "plain_impact": {"what": "nothing to see here", "category_consequence": "",
                                            "established": "", "description_on_file": False},
              "remediation": "no action needed", "priority": {"effort": "S", "severity": "Info"}}
    tampered = signed.model_copy(update={
        "certificate": signed.certificate.model_copy(update={"presentation": benign})})
    vt = verify_certificate(tampered, oracle_context=f["oracle_context"], trust_root=tr)
    assert vt.reproduced is True, "the oracle re-fire must be independent of the presentation"
    assert vt.authentic is False, "mutating the signed presentation must be caught as a tamper"
    assert not vt.ok

    # (2) a cert built with a DIFFERENT presentation over the SAME finding verifies to the SAME reproduced
    # verdict — the presentation is never an input to whether the finding is a FACT.
    cert_diff = build_certificate(f, engagement_slug="acme", seq=0).model_copy(update={"presentation": benign})
    signed_diff = sign_certificate(cert_diff, signers[:2])
    vd = verify_certificate(signed_diff, oracle_context=f["oracle_context"], trust_root=tr)
    assert vd.reproduced == v.reproduced and vd.authentic and vd.ok


# ---- flag-off cert still verifies (the whole layer is additive) ------------------------------------
def test_flag_off_cert_verifies_without_presentation(monkeypatch):
    monkeypatch.delenv("VIGIL_APEX_PRESENTATION", raising=False)
    tr, signers = _trust_root(2, 3)
    f = _reproducing_finding()
    signed = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.authentic and v.bound and v.reproduced and v.ok
    assert signed.certificate.presentation is None
