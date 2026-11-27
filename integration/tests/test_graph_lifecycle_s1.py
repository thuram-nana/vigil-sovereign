"""F4 slice S4 — the REAL framework wiring of the lifecycle projection (``make_default_lifecycle``).

The deterministic logic of the projector is proven offline with injected fakes in test_graph_lifecycle.py.
THIS file proves the NOVEL S1 integration end-to-end against REAL on-disk artifacts: a real signed evidence
(finding) bundle written through the framework evidence layer, and a real signed RemediationCertificate, such
that:

  * the DEFAULT wiring re-verifies the RemediationCertificate through the EXISTING
    ``verify_remediation_certificate`` (no second verifier), and
  * it RESOLVES + re-verifies the referenced finding cert through the EXISTING S1
    ``evidence.resolver.resolve_and_verify`` (→ the one ``verify_certificate``), and only THEN projects the
    ``Finding -[REMEDIATED_BY]-> Remediation`` edge — and S1's tenant-scoping makes a cross-tenant finding
    cert (one that resolves only under ANOTHER root) resolve to None, so no edge is projected.

Needs ``framework`` (the real oracle re-execution for both the evidence cert and the remediation cert) →
``importorskip('framework')``; this file is registered in the OFFENSE leg of .github/workflows/ci.yml (see
test_ci_framework_tests_run_in_offense_leg.py, which FAILS the build if it is not).
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("framework")

from framework.v2.entitlement.crypto import generate_keypair as _gen_gov  # noqa: E402
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot  # noqa: E402
from framework.v2.evidence.audit_package import write_package  # noqa: E402
from framework.v2.evidence.certify import (  # noqa: E402
    build_certificate,
    sign_certificate,
    trust_root_fingerprint,
)
from framework.v2.evidence.chain import build_chain, sign_head  # noqa: E402
from framework.v2.verify.adapter import FindingContext  # noqa: E402
from framework.v2.verify.reverify import reverify_context  # noqa: E402

from vigil_core import generate_keypair  # noqa: E402
from vigil_integration.graph import (  # noqa: E402
    EdgeType,
    NodeLabel,
    SpineRecord,
    make_default_lifecycle,
    project,
)
from vigil_integration.remediation.remediation_cert import mint_remediation_certificate  # noqa: E402


# --------------------------------------------------------------------------------------------------
# Builders — a real oracle fire + signed PCF bundle (finding cert), and a real RemediationCertificate.
# --------------------------------------------------------------------------------------------------
def _mesh_oc() -> dict:
    return FindingContext.from_mesh_control(
        {"resource_kind": "PeerAuthentication", "provider": "istio", "name": "default",
         "namespace": "istio-system", "mtls_mode": "PERMISSIVE"}).to_verifier_context()


def _finding(oc: dict, check_id: str) -> dict:
    rr = reverify_context(oc, bug_class=str(oc.get("bug_class", "")))
    assert rr.ok, rr.note
    return {"check_id": check_id, "bug_class": str(oc.get("bug_class", "")),
            "confirmed_by": rr.confirmed_by, "confidence": rr.confidence, "oracle_context": oc}


def _gov_trust_root(threshold: int = 2, n: int = 3):
    keys = [_gen_gov() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _write_finding_bundle(out_dir: Path, *, check_id: str, slug: str):
    """A real signed finding cert in a PCF bundle. Returns (cert_digest, finding_ref, trust_root, contexts)."""
    oc = _mesh_oc()
    f = _finding(oc, check_id)
    tr, signers = _gov_trust_root()
    cert = build_certificate(f, engagement_slug=slug, seq=0)
    signed = sign_certificate(cert, signers[:2])
    chain = build_chain([signed.certificate.cert_digest])
    head = sign_head(chain, engagement_slug=slug, signers=signers[:2])
    contexts = {signed.certificate.finding_ref: oc}
    write_package(out_dir, certificates=[signed], chain=chain, head=head, contexts=contexts,
                  trust_root=tr, engagement_slug=slug)
    return signed.certificate.cert_digest, signed.certificate.finding_ref, tr, contexts


def _error_context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class="error_based_sqli", resolve=lambda r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''"
_BENIGN = b"HTTP/1.1 200\r\n\r\n{\"results\": []}"


def _real_remediation_cert(*, finding_cert_digest: str):
    """A real, re-verifiable RemediationCertificate (oracle silent on the patched build, control fires)."""
    signer = generate_keypair()
    signer_pubkeys = {"rem0": signer.public_key_b64}
    cert = mint_remediation_certificate(
        finding_ref="errsqli-1", bug_class="error_based_sqli",
        patched_oracle_context=_error_context(_BENIGN), positive_control_context=_error_context(_SQL_ERROR),
        engagement_slug="acme", signers=[("rem0", signer.private_key_b64)], surface="GET /search?q=",
        original_finding_cert_digest=finding_cert_digest)
    return cert, signer_pubkeys


# ==================================================================================================
# The real end-to-end: a RemediationCertificate re-verifies AND its referenced finding cert resolves (S1)
# + re-verifies → the Finding-[REMEDIATED_BY]->Remediation edge is projected.
# ==================================================================================================
def test_default_wiring_links_remediation_to_resolved_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_GRAPH_LIFECYCLE", "1")
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")        # S1 resolver armed (S4 depends on S1)
    root = tmp_path / "tenant"
    cid, finding_ref, tr, contexts = _write_finding_bundle(root / "audit", check_id="mesh-1", slug="eng")
    rem_cert, signer_pubkeys = _real_remediation_cert(finding_cert_digest=cid)

    lifecycle = make_default_lifecycle(signer_pubkeys=signer_pubkeys, root=root, trust_root=tr,
                                       contexts=contexts)
    recs = [
        SpineRecord(seq=1, hash="h1", kind="finding", finding_ref=finding_ref, status="fact",
                    evidence_ref=cid, signature_ref="sig", props={"ref": finding_ref}),
        SpineRecord(seq=2, hash="r1", kind="remediation",
                    props={"remediation_cert": rem_cert, "remediation_id": "REM"}),
    ]
    v = project(recs, lifecycle=lifecycle)

    assert len(v.active_nodes(NodeLabel.REMEDIATION)) == 1                  # the remediation re-verified
    edges = [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY]
    assert len(edges) == 1, "the REMEDIATED_BY edge should form once the finding cert resolves (S1) + verifies"
    assert edges[0].src == f"finding:{finding_ref}" and edges[0].dst == "remediation:REM"
    assert edges[0].props.get("finding_cert_digest") == cid


def test_default_wiring_links_when_pinned_by_out_of_band_fingerprint(tmp_path, monkeypatch):
    # The RECOMMENDED anchor: pin via the engagement's out-of-band governance FINGERPRINT (never the bundle's
    # own trust-root.json). With the genuine fingerprint, authenticity is pinned → the edge forms.
    monkeypatch.setenv("VIGIL_GRAPH_LIFECYCLE", "1")
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    root = tmp_path / "tenant"
    cid, finding_ref, tr, contexts = _write_finding_bundle(root / "audit", check_id="mesh-1", slug="eng")
    rem_cert, signer_pubkeys = _real_remediation_cert(finding_cert_digest=cid)
    lifecycle = make_default_lifecycle(
        signer_pubkeys=signer_pubkeys, root=root, contexts=contexts,
        expected_trust_root_fingerprint=trust_root_fingerprint(tr))          # out-of-band pin, NOT the bundle
    v = project([SpineRecord(seq=1, hash="r1", kind="remediation",
                             props={"remediation_cert": rem_cert, "remediation_id": "REM"})],
                lifecycle=lifecycle)
    edges = [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY]
    assert len(edges) == 1 and edges[0].src == f"finding:{finding_ref}"


def test_unpinned_self_authenticating_bundle_projects_no_edge(tmp_path, monkeypatch):
    # THE S1 RED-PEN FIX, at the S4 boundary: the finding cert RESOLVES and INTERNALLY verifies (the bundle's
    # own trust-root.json validly signs its certs), but authenticity is NOT pinned to any out-of-band anchor
    # (no trust_root, no fingerprint) → rv.ok is False (a bundle cannot self-authenticate) → NO confirmed edge.
    monkeypatch.setenv("VIGIL_GRAPH_LIFECYCLE", "1")
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    root = tmp_path / "tenant"
    cid, finding_ref, _tr, contexts = _write_finding_bundle(root / "audit", check_id="mesh-1", slug="eng")
    rem_cert, signer_pubkeys = _real_remediation_cert(finding_cert_digest=cid)
    # NO trust_root AND NO expected_trust_root_fingerprint → UNPINNED (bundle-sourced root only).
    lifecycle = make_default_lifecycle(signer_pubkeys=signer_pubkeys, root=root, contexts=contexts)
    v = project([SpineRecord(seq=1, hash="r1", kind="remediation",
                             props={"remediation_cert": rem_cert, "remediation_id": "REM"})],
                lifecycle=lifecycle)
    assert len(v.active_nodes(NodeLabel.REMEDIATION)) == 1                  # the remediation itself re-verified
    assert [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY] == [], \
        "an UNPINNED (self-authenticating) bundle must not earn a confirmed REMEDIATED_BY edge"


def test_wrong_out_of_band_fingerprint_projects_no_edge(tmp_path, monkeypatch):
    # Pinning to the WRONG out-of-band fingerprint (a different governance root) fails authenticity → no edge.
    monkeypatch.setenv("VIGIL_GRAPH_LIFECYCLE", "1")
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    root = tmp_path / "tenant"
    cid, _finding_ref, _tr, contexts = _write_finding_bundle(root / "audit", check_id="mesh-1", slug="eng")
    rem_cert, signer_pubkeys = _real_remediation_cert(finding_cert_digest=cid)
    other_tr, _ = _gov_trust_root()                                         # a DIFFERENT governance root
    lifecycle = make_default_lifecycle(
        signer_pubkeys=signer_pubkeys, root=root, contexts=contexts,
        expected_trust_root_fingerprint=trust_root_fingerprint(other_tr))   # wrong anchor
    v = project([SpineRecord(seq=1, hash="r1", kind="remediation",
                             props={"remediation_cert": rem_cert, "remediation_id": "REM"})],
                lifecycle=lifecycle)
    assert [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY] == []


def test_cross_tenant_finding_cert_is_not_linked_by_real_resolver(tmp_path, monkeypatch):
    # The finding cert lives ONLY under tenant B's root. The default lifecycle is rooted at tenant A, so S1's
    # tenant-scoped resolver returns None for B's digest → NO edge is projected onto A's engagement.
    monkeypatch.setenv("VIGIL_GRAPH_LIFECYCLE", "1")
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    root_a = tmp_path / "tenant-a"
    root_b = tmp_path / "tenant-b"
    cid_b, ref_b, tr_b, ctx_b = _write_finding_bundle(root_b / "audit", check_id="b-1", slug="b")
    rem_cert, signer_pubkeys = _real_remediation_cert(finding_cert_digest=cid_b)

    # lifecycle rooted at tenant A (which has NO bundle) — B's finding cert is invisible to it.
    lifecycle = make_default_lifecycle(signer_pubkeys=signer_pubkeys, root=root_a, trust_root=tr_b,
                                       contexts=ctx_b)
    v = project([SpineRecord(seq=1, hash="r1", kind="remediation",
                             props={"remediation_cert": rem_cert, "remediation_id": "REM"})],
                lifecycle=lifecycle)
    assert len(v.active_nodes(NodeLabel.REMEDIATION)) == 1                  # the remediation re-verified
    assert [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY] == []   # but no cross-tenant link


def test_default_wiring_fail_closed_when_finding_cert_absent(tmp_path, monkeypatch):
    # A real remediation cert whose referenced finding digest resolves to NOTHING (no bundle holds it) →
    # the node projects (it re-verified) but NO edge (fail-closed) — the real S1 path, not a fake.
    monkeypatch.setenv("VIGIL_GRAPH_LIFECYCLE", "1")
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    root = tmp_path / "tenant"
    root.mkdir()
    rem_cert, signer_pubkeys = _real_remediation_cert(finding_cert_digest="sha256:" + "ab" * 32)
    lifecycle = make_default_lifecycle(signer_pubkeys=signer_pubkeys, root=root)
    v = project([SpineRecord(seq=1, hash="r1", kind="remediation",
                             props={"remediation_cert": rem_cert, "remediation_id": "REM"})],
                lifecycle=lifecycle)
    assert len(v.active_nodes(NodeLabel.REMEDIATION)) == 1
    assert [e for e in v.edges if e.type == EdgeType.REMEDIATED_BY] == []
