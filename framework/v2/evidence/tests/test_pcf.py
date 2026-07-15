"""evidence.pcf — the Proof-Carrying Findings (PCF v0.1) conformance suite.

PCF §12 asks for a public test suite of certificates that MUST verify and adversarial certificates
(tampered evidence, relabelled claims, benign inputs, stale oracle) that MUST be rejected. This is that
suite, over the REAL evidence layer: a certificate minted from a genuine oracle fire re-verifies offline,
and every tamper class fails closed at the correct step.
"""

from __future__ import annotations

import copy

import pytest

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence.certify import build_certificate, sign_certificate
from framework.v2.evidence.pcf import PCF_VOCABULARY, pcf_vocabulary, to_pcf, verify_pcf
from framework.v2.verify.adapter import FindingContext


def _trust_root(threshold: int, n: int):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _finding_from(oc: dict, check_id: str) -> dict:
    """A finding whose confirmed_by + confidence come FROM the oracle (as a real producer's do), so the
    certificate faithfully records the verdict."""
    from framework.v2.verify.reverify import reverify_context
    rr = reverify_context(oc, bug_class=str(oc.get("bug_class", "")))
    assert rr.ok, f"fixture context did not re-fire: {rr.note}"
    return {"check_id": check_id, "bug_class": str(oc.get("bug_class", "")),
            "confirmed_by": rr.confirmed_by, "confidence": rr.confidence, "oracle_context": oc}


def _mesh_finding():
    oc = FindingContext.from_mesh_control(
        {"resource_kind": "PeerAuthentication", "provider": "istio", "name": "default",
         "namespace": "istio-system", "mtls_mode": "PERMISSIVE"}).to_verifier_context()
    return _finding_from(oc, "mesh-1"), oc


def _signed_pcf(threshold=2, n=3):
    finding, oc = _mesh_finding()
    tr, signers = _trust_root(threshold, n)
    signed = sign_certificate(build_certificate(finding, seq=7), signers[:threshold])
    return to_pcf(signed, oracle_context=oc), tr, oc


# ---- MUST VERIFY -----------------------------------------------------------

def test_a_real_fire_round_trips_to_verified():
    pcf, tr, _ = _signed_pcf()
    assert pcf["oracle"]["version"].startswith("sha256:")   # PCF requires oracle.version for a FACT
    assert pcf["claim"]["vocabulary"] == PCF_VOCABULARY
    r = verify_pcf(pcf, tr)
    assert r.verified, f"{r.step}: {r.reason}"


def test_cloud_fire_round_trips():
    oc = FindingContext.from_cloud_control(
        {"id": "s3/secrets", "kind": "datastore", "sensitive": True, "encrypted": False}
    ).to_verifier_context()
    finding = _finding_from(oc, "cloud-1")
    tr, signers = _trust_root(2, 3)
    pcf = to_pcf(sign_certificate(build_certificate(finding), signers[:2]), oracle_context=oc)
    assert verify_pcf(pcf, tr).verified


def test_vocabulary_export_is_versioned():
    v = pcf_vocabulary()
    assert v["version"] == PCF_VOCABULARY and "mesh_misconfiguration" in v["classes"]


# ---- MUST REJECT (adversarial) — each at the correct step ------------------

_UNSET = object()


def _rejects_at(mutate, step, *, trust=_UNSET):
    pcf, tr, _ = _signed_pcf()
    mutate(pcf)
    r = verify_pcf(pcf, tr if trust is _UNSET else trust)   # `trust=None` is explicit (fail-closed), not "default"
    assert not r.verified, "tampered certificate VERIFIED"
    assert r.step == step, f"expected reject at {step!r}, got {r.step!r}: {r.reason}"


def test_reject_missing_member():
    _rejects_at(lambda p: p.pop("oracle"), "schema")


def test_reject_unknown_pcf_version():
    _rejects_at(lambda p: p.__setitem__("pcf_version", "9.9"), "schema")


def test_reject_out_of_vocabulary_class():
    _rejects_at(lambda p: (p["claim"].__setitem__("class", "made_up_class"),
                           p["_crucible"]["certificate"].__setitem__("bug_class", "made_up_class")), "vocabulary")


def test_reject_wrong_vocabulary():
    _rejects_at(lambda p: p["claim"].__setitem__("vocabulary", "pcf-classes/999"), "vocabulary")


def test_reject_evidence_altered():
    _rejects_at(lambda p: p["evidence"]["oracle_context"]["value"].__setitem__(
        "mesh_control", {"mtls_mode": "STRICT"}), "evidence")


def test_reject_verdict_flipped():
    _rejects_at(lambda p: p["verdict"].__setitem__("fired", False), "signature")


def test_reject_claim_relabelled_in_view():
    _rejects_at(lambda p: p["claim"].__setitem__("class", "sqli"), "signature")


def test_reject_oracle_id_swapped_in_view():
    _rejects_at(lambda p: p["oracle"].__setitem__("id", "cloud_posture"), "signature")


def test_reject_oracle_version_tampered_in_view():
    _rejects_at(lambda p: p["oracle"].__setitem__("version", "sha256:deadbeef"), "signature")


def test_reject_embedded_certificate_relabelled():
    # tampering the AUTHORITATIVE embedded cert breaks the signature over its bytes
    _rejects_at(lambda p: p["_crucible"]["certificate"].__setitem__("bug_class", "sqli"), "signature")


def test_reject_untrusted_issuer_key():
    other, _ = _trust_root(1, 1)   # a trust root that did not sign
    _rejects_at(lambda p: None, "signature", trust=other)


def test_reject_no_trust_root_is_fail_closed():
    _rejects_at(lambda p: None, "signature", trust=None)


def test_reject_below_threshold_signature():
    finding, oc = _mesh_finding()
    tr, signers = _trust_root(threshold=2, n=3)
    signed = sign_certificate(build_certificate(finding), signers[:1])   # only 1 of 2
    r = verify_pcf(to_pcf(signed, oracle_context=oc), tr)
    assert not r.verified and r.step == "signature"


def test_reject_stale_oracle_version(monkeypatch):
    # THE id@version integrity property: if the oracle body changes after issue, the previously-minted
    # certificate re-fires (step 4 reproduction) but must be REJECTED for a version mismatch.
    pcf, tr, _ = _signed_pcf()
    assert verify_pcf(pcf, tr).verified                    # sound before the "change"
    # verify_pcf imports oracle_version inside the function, so patching the module attr changes the
    # "current" version it compares the certificate's stamped version against — simulating a body edit.
    from framework.v2.verify import oracle_version as ovmod
    monkeypatch.setattr(ovmod, "oracle_version", lambda kind: "sha256:changed-body")
    r = verify_pcf(pcf, tr)
    assert not r.verified and r.step == "oracle" and "version mismatch" in r.reason


def test_reject_claim_not_grounded(monkeypatch):
    # step 5: if the fired oracle is not a confirmer for the claimed class, reject at 'claim'
    pcf, tr, _ = _signed_pcf()
    from framework.v2.verify import verifier as vf
    monkeypatch.setattr(vf, "oracle_confirms_class", lambda cb, bc: False)
    r = verify_pcf(pcf, tr)
    assert not r.verified and r.step == "claim"


def test_cli_round_trip_certify_export_verify(tmp_path):
    # the operator-facing path: certify (sign) -> pcf-export (project) -> pcf-verify (offline). Exit 0 iff
    # sound; a tampered PCF cert exits 2.
    import json

    from framework.v2.evidence.cli import main
    finding, oc = _mesh_finding()
    tr, signers = _trust_root(2, 3)
    (tmp_path / "report.json").write_text(json.dumps({"active_findings": [finding]}))
    (tmp_path / "trust-root.json").write_text(tr.model_dump_json())
    s = [f"{kid}:{priv}" for kid, priv in signers[:2]]
    assert main(["certify", "--report", str(tmp_path / "report.json"), "--slug", "t",
                 "--out", str(tmp_path / "bundle"), "--signer", s[0], "--signer", s[1]]) == 0
    assert main(["pcf-export", "--report", str(tmp_path / "report.json"),
                 "--bundle", str(tmp_path / "bundle"), "--out", str(tmp_path / "pcf.json")]) == 0
    assert main(["pcf-verify", "--pcf", str(tmp_path / "pcf.json"),
                 "--trust-root", str(tmp_path / "trust-root.json")]) == 0
    # tamper the exported PCF cert -> pcf-verify exits non-zero
    doc = json.loads((tmp_path / "pcf.json").read_text())
    doc["pcf_certificates"][0]["claim"]["statement"] = "Confirmed RCE"
    (tmp_path / "pcf.json").write_text(json.dumps(doc))
    assert main(["pcf-verify", "--pcf", str(tmp_path / "pcf.json"),
                 "--trust-root", str(tmp_path / "trust-root.json")]) == 2


def test_malformed_input_is_rejection_not_crash():
    assert not verify_pcf(None, None).verified
    assert not verify_pcf("not a cert", None).verified
    assert not verify_pcf({}, None).verified


# ---- review fixes: the faithful-projection guarantee (no lying wrapper) ----

def test_reject_claim_statement_lie():
    # review [MED]: a relay must not display an arbitrary (e.g. RCE) statement over a mesh-misconfig proof
    _rejects_at(lambda p: p["claim"].__setitem__("statement", "Confirmed RCE as root on the payment host"),
                "signature")


def test_reject_grounding_mutation():
    # review [MED]: grounding is re-derived as FACT and view-checked; any other value is rejected
    for bad in ("LEAD", "ADVISORY", "TOTALLY_FAKE", "", None):
        _rejects_at(lambda p, b=bad: p.__setitem__("grounding", b), "signature")


def test_reject_descriptive_view_field_mutations():
    # review [LOW]: subject.context, oracle.binding, provenance.collected_by are all authenticated now
    _rejects_at(lambda p: p["subject"]["context"].__setitem__("surface", "elsewhere"), "signature")
    _rejects_at(lambda p: p["oracle"].__setitem__("binding", "crucible/verify:evil"), "signature")
    _rejects_at(lambda p: p["provenance"].__setitem__("collected_by", "trusted-authority"), "signature")


def test_malformed_members_are_rejections_not_crashes():
    # review [crash]: a member of the wrong type must be a REJECTION, never an exception
    for member, bad in (("claim", ["x"]), ("oracle", "str"), ("verdict", 3),
                        ("evidence", None), ("signature", [])):
        pcf, tr, _ = _signed_pcf()
        pcf[member] = bad
        r = verify_pcf(pcf, tr)
        assert not r.verified and r.step == "schema", f"{member}={bad!r} -> {r.step}"
    # a signatures block that is not a list
    pcf, tr, _ = _signed_pcf()
    pcf["signature"]["signatures"] = "not-a-list"
    assert not verify_pcf(pcf, tr).verified
