"""
AEGIS TT-STG DONE record (AS-25 / D33) — a signed binding over a verification manifest that
re-verifies OFFLINE and deterministically, and fails on any single tampered byte.

Everything here is offline and deterministic: an ephemeral trust root (provisioning keys),
an in-memory verification manifest, no clock, no network. The positive path verifies; every
negative control denies, fail-closed. The headline guarantees (plan §13.3, task spec):

  * a record verifies offline;
  * a 1-byte flip fails — in the bound MANIFEST (digest) and in the signed RECORD (signature);
  * the binding covers the WHOLE manifest (a field the binding does not separately re-state is
    still caught by the whole-manifest digest).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot

from framework.v2.evidence.aegis_tt import (
    BuildRef,
    DEMONSTRATION_SCHEMA,
    MANIFEST_SCHEMA,
    RequiredCases,
    SignedDemonstration,
    SubjectRef,
    TopologyRef,
    UiLeg,
    build_demonstration,
    demonstration_signing_bytes,
    load_trust_root_doc,
    load_trust_root_doc_file,
    manifest_digest,
    project_state,
    sign_demonstration,
    trust_root_fingerprint,
    verify_demonstration,
    CAPABILITY_STATES,
    STATE_IMPLEMENTED_AND_DEMONSTRATED,
    STATE_IMPLEMENTED_NOT_VALIDATED,
)
from framework.v2.evidence.canonical import canonical_json, evidence_signing_bytes

# Repo root: .../engine/crucible/framework/v2/evidence/tests/<this file>
_REPO_ROOT = Path(__file__).resolve().parents[6]
_TRUST_ROOT_DOC = _REPO_ROOT / "docs" / "evidence" / "aegis-tt" / "trust-root.json"
_STATUS_PROJECTION = _REPO_ROOT / "docs" / "capability-matrix" / "aegis-saas-status.json"


# --------------------------------------------------------------------------------------
# Fixtures (pure helpers — no pytest fixtures needed, everything is deterministic).
# --------------------------------------------------------------------------------------
def _trust_root(threshold: int = 1, n: int = 1) -> tuple[TrustRoot, list[tuple[str, str]]]:
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"tt-{i}", name=f"TT evidence authoriser {i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"tt-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _manifest() -> dict[str, Any]:
    """A realistic passing vigil-verification-manifest/1 record (shape per tools/verification_manifest.py)."""
    return {
        "schema": MANIFEST_SCHEMA,
        "command": ["pytest", "IT/test_aegis_tt_rig.py", "-q"],
        "commit": "a" * 40,
        "branch": "staging",
        "dirty": False,
        "exit_status": 0,
        "counts": {"passed": 42, "failed": 0, "error": 0, "skipped": 0, "total": 42},
        "skips": [],
        "suite": {
            "files": ["IT/test_aegis_tt_rig.py"],
            "file_count": 1,
            "node_count": 42,
            "node_digest": "b" * 64,
        },
        "environment": {"python": "3.11.0", "platform": "linux", "pythonpath": "", "executable": "/usr/bin/python3"},
        "duration_seconds": 12.34,
        "output_sha256": "c" * 64,
        "output_bytes": 2048,
        "junit_sha256": "d" * 64,
        "junit_path": "artifacts/verify.junit.xml",
    }


def _demo(manifest: dict[str, Any]):
    return build_demonstration(
        manifest=manifest,
        slice_id="AS-1b",
        claim_ids=["AS-1b.observe", "AS-1b.evidence"],
        build=BuildRef(build_id="build-2026-11-26", artifacts="VALID"),
        topology=TopologyRef.model_validate({"class": "iac", "digest": "e" * 64}),
        subject=SubjectRef(paths=["engine/crucible/framework/v2/aegis/"], digest="f" * 64),
        tenants=["TT-A", "TT-B"],
        ui_legs=[UiLeg(route="#/monitoring/overview", screen="overview", session="tt-a-session")],
        required_cases=RequiredCases(positive=3, benign=2, benign_same_shape=1, negative=4,
                                     cross_tenant=1, failure_class=1),
    )


def _signed(manifest: dict[str, Any], tr_signers: tuple[TrustRoot, list[tuple[str, str]]] | None = None):
    tr, signers = tr_signers if tr_signers is not None else _trust_root()
    signed = sign_demonstration(_demo(manifest), signers)
    return signed, tr


# --------------------------------------------------------------------------------------
# Positive path.
# --------------------------------------------------------------------------------------
def test_record_verifies_offline() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert v.ok, v.reasons
    assert v.authentic and v.non_production and v.manifest_bound and v.run_ok
    assert v.cases_present and v.legs_nonempty and v.no_skip_ok and v.artifacts_valid
    assert not v.stale
    assert v.valid_signers == ("tt-0",)
    assert signed.demonstration.schema_id == DEMONSTRATION_SCHEMA


def test_record_round_trips_through_json_and_still_verifies() -> None:
    """A record serialized to JSON and reloaded (as an auditor would) still verifies — the offline
    path does not depend on in-memory object identity, only on the canonical bytes."""
    manifest = _manifest()
    signed, tr = _signed(manifest)
    reloaded = SignedDemonstration.model_validate(json.loads(signed.model_dump_json(by_alias=True)))
    v = verify_demonstration(reloaded, manifest=manifest, trust_root=tr, environment="staging")
    assert v.ok, v.reasons


# --------------------------------------------------------------------------------------
# 1-byte flips.
# --------------------------------------------------------------------------------------
def test_one_byte_flip_in_the_bound_manifest_fails() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    # A genuine single-byte flip in the serialized (compact canonical) manifest, landing inside a
    # value the binding does NOT separately re-state (duration_seconds 12.34 -> 12.35). Re-parse.
    # Only the whole-manifest digest can catch this.
    raw = bytearray(canonical_json(manifest))
    needle = b'"duration_seconds":12.34'
    idx = raw.index(needle) + len(needle) - 1  # the final '4'
    assert raw[idx:idx + 1] == b"4"
    raw[idx] = ord("5")  # exactly one byte changed
    tampered = json.loads(bytes(raw))
    assert tampered["duration_seconds"] == 12.35
    v = verify_demonstration(signed, manifest=tampered, trust_root=tr, environment="staging")
    assert not v.ok and not v.manifest_bound
    assert any("manifest digest does not match" in r for r in v.reasons)


def test_one_byte_flip_in_the_signed_record_fails() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    # Flip one character of the signed binding's commit; keep the ORIGINAL signatures. The signing
    # bytes now differ from what was signed, so the Ed25519 signature no longer verifies.
    tampered_demo = signed.demonstration.model_copy(deep=True)
    object.__setattr__(tampered_demo, "commit", "b" + signed.demonstration.commit[1:])
    tampered = SignedDemonstration(demonstration=tampered_demo, signatures=signed.signatures)
    v = verify_demonstration(tampered, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.ok and not v.authentic
    assert v.valid_signers == ()


def test_binding_covers_the_whole_manifest() -> None:
    """Mutating a manifest field the binding does not separately re-state (output_bytes) still
    voids the record: the binding covers the WHOLE manifest by a single digest, not just the
    handful of fields it names. The per-field checks (junit/suite/commit) still pass — proving it
    was the whole-manifest digest, and nothing else, that caught the change."""
    manifest = _manifest()
    signed, tr = _signed(manifest)
    tampered = copy.deepcopy(manifest)
    tampered["output_bytes"] = manifest["output_bytes"] + 1
    assert manifest_digest(tampered) != manifest_digest(manifest)
    v = verify_demonstration(signed, manifest=tampered, trust_root=tr, environment="staging")
    assert not v.ok and not v.manifest_bound
    # junit/suite/commit are unchanged, so ONLY the whole-manifest digest reason appears.
    digest_reasons = [r for r in v.reasons if "manifest digest does not match" in r]
    field_reasons = [r for r in v.reasons if "junit_sha256" in r or "suite_digest" in r or "commit" in r]
    assert digest_reasons and not field_reasons


# --------------------------------------------------------------------------------------
# Authenticity negative controls.
# --------------------------------------------------------------------------------------
def test_forged_signature_from_untrusted_key_does_not_count() -> None:
    manifest = _manifest()
    tr, _ = _trust_root()
    _, rogue = _trust_root()  # a key NOT in tr
    signed = sign_demonstration(_demo(manifest), rogue)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.authentic and not v.ok


def test_threshold_not_met_is_inauthentic() -> None:
    manifest = _manifest()
    tr, signers = _trust_root(threshold=2, n=3)
    signed = sign_demonstration(_demo(manifest), signers[:1])  # 1 of 2 required
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.authentic and not v.ok


def test_two_of_three_threshold_is_authentic() -> None:
    manifest = _manifest()
    tr, signers = _trust_root(threshold=2, n=3)
    signed = sign_demonstration(_demo(manifest), signers[:2])
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert v.authentic and v.ok and len(v.valid_signers) == 2


def test_trust_root_fingerprint_pin_mismatch_fails() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    other_tr, _ = _trust_root()
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging",
                             expected_trust_root_fingerprint=trust_root_fingerprint(other_tr))
    assert not v.authentic and not v.ok
    assert any("fingerprint" in r for r in v.reasons)


def test_trust_root_fingerprint_pin_match_passes() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging",
                             expected_trust_root_fingerprint=trust_root_fingerprint(tr))
    assert v.ok


# --------------------------------------------------------------------------------------
# Non-production-root / environment negative controls.
# --------------------------------------------------------------------------------------
def test_production_root_is_refused() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="production")
    assert not v.non_production and not v.ok
    assert any("non-production" in r for r in v.reasons)


# --------------------------------------------------------------------------------------
# Run-quality negative controls.
# --------------------------------------------------------------------------------------
def test_dirty_run_is_refused() -> None:
    manifest = _manifest()
    manifest["dirty"] = True
    signed, tr = _signed(manifest)  # bind the dirty manifest so the digest still matches
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.run_ok and not v.ok
    assert any("DIRTY" in r for r in v.reasons)


def test_failed_run_is_refused() -> None:
    manifest = _manifest()
    manifest["exit_status"] = 1
    manifest["counts"] = {"passed": 40, "failed": 2, "error": 0, "skipped": 0, "total": 42}
    signed, tr = _signed(manifest)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.run_ok and not v.ok


# --------------------------------------------------------------------------------------
# Case-class / UI-leg / no-skip / artifact negative controls.
# --------------------------------------------------------------------------------------
def test_missing_case_class_is_refused() -> None:
    manifest = _manifest()
    tr, signers = _trust_root()
    demo = _demo(manifest)
    object.__setattr__(demo.required_cases, "cross_tenant", 0)  # drop the cross-tenant class
    signed = sign_demonstration(demo, signers)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.cases_present and not v.ok
    assert any("cross_tenant" in r for r in v.reasons)


def test_empty_ui_legs_is_refused() -> None:
    manifest = _manifest()
    tr, signers = _trust_root()
    demo = _demo(manifest)
    object.__setattr__(demo, "ui_legs", [])
    signed = sign_demonstration(demo, signers)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.legs_nonempty and not v.ok


def test_route_outside_the_census_is_refused() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    census = {"#/monitoring/evidence", "#/monitoring/health"}  # does NOT include the leg's route
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging",
                             census_routes=census)
    assert not v.routes_in_census and not v.ok


def test_route_inside_the_census_passes() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    census = {"#/monitoring/overview", "#/monitoring/health"}
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging",
                             census_routes=census)
    assert v.routes_in_census and v.ok


def test_skipped_tt_b_term_is_refused() -> None:
    """A run that SKIPPED a test covering the control tenant (TT-B) must not back a demonstration —
    the claim would rest on the exact behaviour that did not run (plan §13.3 no_skip_terms)."""
    manifest = _manifest()
    manifest["skips"] = [{"test": "IT/test_aegis_tt_rig.py::test_tt_b_sees_nothing",
                          "reason": "TT-B tenant not provisioned", "category": "unavailable_capability"}]
    signed, tr = _signed(manifest)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.no_skip_ok and not v.ok
    assert any("TT-B" in r for r in v.reasons)


def test_binding_missing_a_required_no_skip_term_is_refused() -> None:
    manifest = _manifest()
    tr, signers = _trust_root()
    demo = build_demonstration(
        manifest=manifest, slice_id="AS-1b", claim_ids=["AS-1b.observe"],
        build=BuildRef(build_id="b1", artifacts="VALID"),
        topology=TopologyRef.model_validate({"class": "iac", "digest": "e" * 64}),
        subject=SubjectRef(paths=["p"], digest="f" * 64), tenants=["TT-A", "TT-B"],
        ui_legs=[UiLeg(route="#/monitoring/overview", screen="overview", session="s")],
        required_cases=RequiredCases(positive=1, benign=1, benign_same_shape=1, negative=1,
                                     cross_tenant=1, failure_class=1),
        no_skip_terms=["TT-B", "cross-uid", "browser"],  # missing isolation + tenant
    )
    signed = sign_demonstration(demo, signers)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.no_skip_ok and not v.ok
    assert any("isolation" in r and "tenant" in r for r in v.reasons)


def test_build_artifacts_not_valid_is_refused() -> None:
    manifest = _manifest()
    tr, signers = _trust_root()
    demo = _demo(manifest)
    object.__setattr__(demo.build, "artifacts", "PENDING")
    signed = sign_demonstration(demo, signers)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert not v.artifacts_valid and not v.ok


def test_a_swapped_but_internally_valid_manifest_is_refused() -> None:
    """Presenting a DIFFERENT (but well-formed, passing) manifest than the one bound fails the
    binding — the record is bound to one run, not to any passing run."""
    manifest = _manifest()
    signed, tr = _signed(manifest)
    other = _manifest()
    other["commit"] = "9" * 40
    other["suite"]["node_digest"] = "7" * 64
    v = verify_demonstration(signed, manifest=other, trust_root=tr, environment="staging")
    assert not v.manifest_bound and not v.ok


# --------------------------------------------------------------------------------------
# Staleness is a STATE, not a failure.
# --------------------------------------------------------------------------------------
def test_staleness_by_subject_digest_is_a_state_not_a_failure() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging",
                             current_subject_digest="0" * 64)  # moved since signing
    assert v.stale and v.ok  # stale but still cryptographically + structurally sound
    assert any("STALE" in r for r in v.reasons)


def test_staleness_by_topology_digest_is_a_state_not_a_failure() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    v = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging",
                             current_topology_digest="0" * 64)
    assert v.stale and v.ok


def test_matching_current_digests_are_not_stale() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    v = verify_demonstration(
        signed, manifest=manifest, trust_root=tr, environment="staging",
        current_subject_digest=signed.demonstration.subject.digest,
        current_topology_digest=signed.demonstration.topology.digest)
    assert not v.stale and v.ok


# --------------------------------------------------------------------------------------
# Determinism + domain separation.
# --------------------------------------------------------------------------------------
def test_building_is_deterministic() -> None:
    manifest = _manifest()
    a = _demo(manifest)
    b = _demo(manifest)
    assert demonstration_signing_bytes(a) == demonstration_signing_bytes(b)
    assert a.manifest_sha256 == b.manifest_sha256 == manifest_digest(manifest)


def test_domain_separation_from_evidence_certificates() -> None:
    """The demonstration signing bytes carry a DISTINCT domain tag from evidence certificates, so a
    signature over one payload can never be replayed as the other document type."""
    manifest = _manifest()
    demo = _demo(manifest)
    payload = demo.model_dump(mode="json", by_alias=True)
    assert demonstration_signing_bytes(demo) != evidence_signing_bytes(payload)
    assert demonstration_signing_bytes(demo).startswith(b"vigil-aegis-tt-demonstration-v1\x00")


# --------------------------------------------------------------------------------------
# Committed trust-root doc (docs/evidence/aegis-tt/trust-root.json).
# --------------------------------------------------------------------------------------
def test_committed_trust_root_doc_loads_as_unprovisioned_staging() -> None:
    doc = load_trust_root_doc_file(_TRUST_ROOT_DOC)
    assert doc.environment == "staging"
    assert doc.status == "unprovisioned"
    assert doc.trust_root is None       # no staging key provisioned yet
    assert not doc.is_production
    assert not doc.is_usable            # fail-closed: an unprovisioned root can verify nothing


def test_trust_root_doc_rejects_wrong_schema() -> None:
    import pytest
    with pytest.raises(ValueError):
        load_trust_root_doc({"schema": "not-the-trust-root", "environment": "staging"})


def test_a_provisioned_doc_round_trips_to_a_usable_root() -> None:
    """When the AS-26 ceremony fills the doc, it loads to a usable non-production root that verifies
    a real record. Proven here with an ephemeral key standing in for the staging key."""
    manifest = _manifest()
    key = generate_keypair()
    doc_json = {
        "schema": "vigil-aegis-tt-trust-root/1", "environment": "staging", "status": "provisioned",
        "schema_version": 1, "threshold": 1,
        "authorizers": [{"key_id": "tt-staging", "name": "TT evidence key (staging)",
                         "public_key_b64": key.public_key_b64}],
    }
    doc = load_trust_root_doc(doc_json)
    assert doc.is_usable and doc.trust_root is not None
    signed = sign_demonstration(_demo(manifest), [("tt-staging", key.private_key_b64)])
    v = verify_demonstration(signed, manifest=manifest, trust_root=doc.trust_root,
                             environment=doc.environment)
    assert v.ok


# --------------------------------------------------------------------------------------
# Status projection drift guard (docs/capability-matrix/aegis-saas-status.json, plan §13.7).
# --------------------------------------------------------------------------------------
def test_status_projection_drift_guard() -> None:
    data = json.loads(_STATUS_PROJECTION.read_text(encoding="utf-8"))
    assert data["schema"] == "vigil-aegis-saas-status/1"
    declared_states = {s["id"] for s in data["states"]}
    assert declared_states == set(CAPABILITY_STATES), "the file's state vocabulary must be the closed set"
    for claim in data["claims"]:
        assert claim["state"] in CAPABILITY_STATES, f"{claim['claim_id']}: unknown state {claim['state']}"
        # The §13.3 honesty invariant, mechanical: nothing reads "demonstrated" without a record.
        if claim.get("demonstrated_by") is None:
            assert claim["state"] != STATE_IMPLEMENTED_AND_DEMONSTRATED, (
                f"{claim['claim_id']} claims demonstrated with no record")


def test_project_state_requires_a_current_valid_record() -> None:
    manifest = _manifest()
    signed, tr = _signed(manifest)
    good = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging")
    assert project_state(good) == STATE_IMPLEMENTED_AND_DEMONSTRATED
    # No record → not validated.
    assert project_state(None) == STATE_IMPLEMENTED_NOT_VALIDATED
    # Stale record → not validated (cannot display demonstrated on a stale record).
    stale = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="staging",
                                 current_subject_digest="0" * 64)
    assert stale.stale and project_state(stale) == STATE_IMPLEMENTED_NOT_VALIDATED
    # Invalid record (production root) → not validated.
    bad = verify_demonstration(signed, manifest=manifest, trust_root=tr, environment="production")
    assert project_state(bad) == STATE_IMPLEMENTED_NOT_VALIDATED
