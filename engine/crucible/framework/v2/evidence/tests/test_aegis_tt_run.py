"""
AEGIS TT-STG RUN orchestration (AS-1b) — the staging-run counterpart to AS-1a's TT-CI rig.

Everything here is offline and deterministic: a constructed AS-1a-shaped acceptance result, an
in-memory verification manifest, an ephemeral provisioning trust root, no clock, no network. The
headline guarantees:

  * a gated-OK run assembles an AS-25 binding that SIGNS and SELF-VERIFIES offline (the full record);
  * the record's world is DERIVED from the run, never asserted: the IaC topology digest over the real
    AS-26 templates, the subject digest, and the six case-class counts from the passed JUnit nodes;
  * every gate is fail-closed — a failed acceptance, the in-process (not distinct-uid) mode, a dirty or
    failing manifest, a skipped no-skip term, or a missing case class each yields NO binding;
  * the derivation and digests are deterministic (order-independent; a one-byte change moves a digest);
  * the LIVE residual is honest — the committed staging trust root is unprovisioned, so a real record
    cannot verify under it in CI (the AS1B-live-fire-tt-stg residual).
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot

from framework.v2.evidence.aegis_tt import (
    MANIFEST_SCHEMA,
    REQUIRED_CASE_CLASSES,
    BuildRef,
    UiLeg,
    demonstration_signing_bytes,
    load_trust_root_doc_file,
)
from framework.v2.evidence.aegis_tt_run import (
    DEFAULT_SUBJECT_PATHS,
    as26_template_paths,
    build_tt_stg_demonstration,
    derive_required_cases,
    gate_tt_stg_run,
    iac_topology_digest,
    junit_passed_case_nodes,
    record_tt_stg_run,
    subject_digest,
)

# .../engine/crucible/framework/v2/evidence/tests/<this file> -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[6]
_TRUST_ROOT_DOC = _REPO_ROOT / "docs" / "evidence" / "aegis-tt" / "trust-root.json"


# --------------------------------------------------------------------------------------
# Fixtures (pure helpers — everything is deterministic, no pytest fixtures needed).
# --------------------------------------------------------------------------------------
def _trust_root(threshold: int = 1, n: int = 1) -> tuple[TrustRoot, list[tuple[str, str]]]:
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"tt-{i}", name=f"TT evidence authoriser {i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"tt-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _acceptance() -> dict[str, Any]:
    """A passing DISTINCT-UID acceptance, the shape ``aegis.tt_rig.run_tt_acceptance`` returns."""
    return {
        "ok": True,
        "mode": "distinct-uids",
        "attack_tenant": "tt-a",
        "control_tenant": "tt-b",
        "expected_attack_classes": ["automated_access", "path_traversal_attempt", "sqli_attempt"],
        "checks": {
            "attack_event_visible_to_attack_tenant": True,
            "benign_baseline_recorded": True,
            "cross_tenant_control_sees_nothing": True,
            "observe_never_blocked": True,
            "cross_tenant_uid_cannot_read_peer_feed": True,
        },
        "cross_tenant_fs_probe": {"attempted": True, "denied": True,
                                  "no_supplementary_group_leak": True, "ok": True},
        "tenants": {"tt-a": {}, "tt-b": {}},
    }


def _manifest() -> dict[str, Any]:
    """A realistic passing vigil-verification-manifest/1 record (shape per tools/verification_manifest.py)."""
    return {
        "schema": MANIFEST_SCHEMA,
        "command": ["pytest", "IT/test_aegis_tt_stg_e2e.py", "-q"],
        "commit": "a" * 40,
        "branch": "staging",
        "dirty": False,
        "exit_status": 0,
        "counts": {"passed": 24, "failed": 0, "error": 0, "skipped": 0, "total": 24},
        "skips": [],
        "suite": {"files": ["IT/test_aegis_tt_stg_e2e.py"], "file_count": 1,
                  "node_count": 24, "node_digest": "b" * 64},
        "environment": {"python": "3.11.0", "platform": "linux", "pythonpath": "", "executable": "/usr/bin/python3"},
        "duration_seconds": 42.0,
        "output_sha256": "c" * 64,
        "output_bytes": 4096,
        "junit_sha256": "d" * 64,
        "junit_path": "artifacts/verify.junit.xml",
    }


def _passed_nodes() -> list[str]:
    """Passed JUnit nodes covering ALL six required case classes (bracketed tokens)."""
    return [
        "IT.test_aegis_tt_stg_e2e::test_attack_fires_in_tt_a[positive]",
        "IT.test_aegis_tt_stg_e2e::test_benign_forwards_clean[benign]",
        "IT.test_aegis_tt_stg_e2e::test_same_shape_benign_fires_nothing[benign_same_shape]",
        "IT.test_aegis_tt_stg_e2e::test_discriminating_control[negative]",
        "IT.test_aegis_tt_stg_e2e::test_tt_b_sees_nothing[cross_tenant]",
        "IT.test_aegis_tt_stg_e2e::test_upstream_down_fails_closed[failure_class]",
    ]


def _ui_legs() -> list[UiLeg]:
    return [UiLeg(route="#/monitoring/overview", screen="overview", session="tt-a-session")]


def _build() -> BuildRef:
    return BuildRef(build_id="stg-build-2026-11-27", artifacts="VALID")


def _run_result(**overrides: Any):
    kwargs: dict[str, Any] = dict(
        acceptance=_acceptance(), manifest=_manifest(), passed_nodes=_passed_nodes(),
        repo_root=_REPO_ROOT, slice_id="AS-1b", claim_ids=["AS-1b.tt-stg-run"],
        build=_build(), ui_legs=_ui_legs(),
    )
    kwargs.update(overrides)
    return build_tt_stg_demonstration(**kwargs)


# --------------------------------------------------------------------------------------
# Positive path — a gated-OK run assembles a binding that signs and self-verifies.
# --------------------------------------------------------------------------------------
def test_gated_ok_run_assembles_a_binding() -> None:
    run = _run_result()
    assert run.ok, run.reasons
    assert run.demonstration is not None
    demo = run.demonstration
    assert demo.slice_id == "AS-1b"
    assert demo.topology.kind == "iac"
    assert demo.tenants == ["tt-a", "tt-b"]
    # the world was DERIVED: the topology digest is the real AS-26 template digest.
    assert demo.topology.digest == iac_topology_digest(as26_template_paths(_REPO_ROOT))
    assert demo.subject.digest == subject_digest(_REPO_ROOT)
    # every case class present (count >= 1), derived from the passed nodes.
    for c in REQUIRED_CASE_CLASSES:
        assert getattr(demo.required_cases, c) >= 1


def test_record_signs_and_self_verifies_offline() -> None:
    tr, signers = _trust_root()
    rec = record_tt_stg_run(
        acceptance=_acceptance(), manifest=_manifest(), passed_nodes=_passed_nodes(),
        repo_root=_REPO_ROOT, slice_id="AS-1b", claim_ids=["AS-1b.tt-stg-run"],
        build=_build(), ui_legs=_ui_legs(), signers=signers, trust_root=tr, environment="staging",
    )
    assert rec.ok, rec.reasons
    assert rec.signed is not None and rec.verification is not None
    assert rec.verification.ok
    assert rec.verification.topology_is_iac and rec.verification.cases_present
    assert rec.verification.valid_signers == ("tt-0",)
    assert not rec.verification.stale


def test_record_respects_the_gate5_census_when_supplied() -> None:
    tr, signers = _trust_root()
    rec = record_tt_stg_run(
        acceptance=_acceptance(), manifest=_manifest(), passed_nodes=_passed_nodes(),
        repo_root=_REPO_ROOT, slice_id="AS-1b", claim_ids=["AS-1b.tt-stg-run"],
        build=_build(), ui_legs=_ui_legs(), signers=signers, trust_root=tr, environment="staging",
        census_routes={"#/monitoring/overview"},
    )
    assert rec.ok, rec.reasons
    assert rec.verification is not None and rec.verification.routes_in_census


# --------------------------------------------------------------------------------------
# Determinism — same inputs, same binding bytes; digests stable and order-independent.
# --------------------------------------------------------------------------------------
def test_binding_is_deterministic() -> None:
    a, b = _run_result().demonstration, _run_result().demonstration
    assert a is not None and b is not None
    assert demonstration_signing_bytes(a) == demonstration_signing_bytes(b)


def test_topology_digest_is_order_independent_and_change_sensitive(tmp_path: Path) -> None:
    f1 = tmp_path / "00.yaml"
    f2 = tmp_path / "10.yaml"
    f1.write_text("Resources: {A: 1}\n")
    f2.write_text("Resources: {B: 2}\n")
    d_forward = iac_topology_digest([f1, f2])
    d_reverse = iac_topology_digest([f2, f1])
    assert d_forward == d_reverse
    f2.write_text("Resources: {B: 3}\n")  # one-byte flip 2 -> 3
    assert iac_topology_digest([f1, f2]) != d_forward


def test_subject_digest_is_change_sensitive(tmp_path: Path) -> None:
    (tmp_path / "s.py").write_text("x = 1\n")
    d1 = subject_digest(tmp_path, ["s.py"])
    (tmp_path / "s.py").write_text("x = 2\n")
    d2 = subject_digest(tmp_path, ["s.py"])
    assert d1 != d2


# --------------------------------------------------------------------------------------
# Case-class derivation — from the run, never asserted.
# --------------------------------------------------------------------------------------
def test_case_counts_are_derived_from_passed_nodes() -> None:
    nodes = _passed_nodes() + ["m::extra_positive[positive]"]
    rc = derive_required_cases(nodes)
    assert rc.positive == 2  # two [positive] nodes
    assert rc.benign == 1 and rc.benign_same_shape == 1
    assert rc.negative == 1 and rc.cross_tenant == 1 and rc.failure_class == 1


def test_benign_token_does_not_match_benign_same_shape() -> None:
    # a single [benign_same_shape] node must NOT also increment the broader benign count (bracket tokens).
    rc = derive_required_cases(["m::t[benign_same_shape]"])
    assert rc.benign_same_shape == 1 and rc.benign == 0


def test_junit_passed_case_nodes_excludes_failed_and_skipped(tmp_path: Path) -> None:
    junit = tmp_path / "verify.junit.xml"
    junit.write_text(
        '<testsuite>'
        '<testcase classname="IT.e2e" name="ok[positive]"/>'
        '<testcase classname="IT.e2e" name="bad[benign]"><failure message="x"/></testcase>'
        '<testcase classname="IT.e2e" name="skip[negative]"><skipped/></testcase>'
        '<testcase classname="IT.e2e" name="err[failure_class]"><error message="y"/></testcase>'
        '</testsuite>'
    )
    nodes = junit_passed_case_nodes(junit)
    assert nodes == ["IT.e2e::ok[positive]"]  # only the passed node
    rc = derive_required_cases(nodes)
    assert rc.positive == 1 and rc.benign == 0 and rc.negative == 0 and rc.failure_class == 0


# --------------------------------------------------------------------------------------
# Fail-closed gates — each negative control yields NO binding.
# --------------------------------------------------------------------------------------
def test_acceptance_not_ok_denies() -> None:
    acc = _acceptance()
    acc["ok"] = False
    run = _run_result(acceptance=acc)
    assert not run.ok and run.demonstration is None
    assert any("acceptance.ok" in r for r in run.reasons)


def test_in_process_mode_denies() -> None:
    acc = _acceptance()
    acc["mode"] = "in-process"
    run = _run_result(acceptance=acc)
    assert not run.ok and run.demonstration is None
    assert any("distinct-uids" in r for r in run.reasons)


def test_any_false_check_denies() -> None:
    acc = _acceptance()
    acc["checks"]["cross_tenant_control_sees_nothing"] = False
    run = _run_result(acceptance=acc)
    assert not run.ok and run.demonstration is None
    assert any("cross_tenant_control_sees_nothing" in r for r in run.reasons)


def test_missing_cross_uid_check_denies() -> None:
    acc = _acceptance()
    del acc["checks"]["cross_tenant_uid_cannot_read_peer_feed"]
    run = _run_result(acceptance=acc)
    assert not run.ok and run.demonstration is None
    assert any("cross-uid OS-boundary" in r or "cross_tenant_uid_cannot_read_peer_feed" in r
               for r in run.reasons)


def test_fs_probe_not_ok_denies() -> None:
    acc = _acceptance()
    acc["cross_tenant_fs_probe"]["ok"] = False
    run = _run_result(acceptance=acc)
    assert not run.ok and run.demonstration is None
    assert any("cross_tenant_fs_probe" in r for r in run.reasons)


def test_failing_manifest_denies() -> None:
    m = _manifest()
    m["exit_status"] = 1
    run = _run_result(manifest=m)
    assert not run.ok and run.demonstration is None
    assert any("FAILED" in r for r in run.reasons)


def test_dirty_manifest_denies() -> None:
    m = _manifest()
    m["dirty"] = True
    run = _run_result(manifest=m)
    assert not run.ok and run.demonstration is None
    assert any("DIRTY" in r for r in run.reasons)


def test_failed_test_count_denies() -> None:
    m = _manifest()
    m["counts"]["failed"] = 2
    run = _run_result(manifest=m)
    assert not run.ok and run.demonstration is None
    assert any("failing test" in r for r in run.reasons)


@pytest.mark.parametrize("term", ["TT-B", "cross-uid", "browser", "isolation", "tenant"])
def test_skipped_no_skip_term_denies(term: str) -> None:
    m = _manifest()
    m["skips"] = [{"test": f"IT::test_{term.lower()}_leg", "reason": f"needs live {term}"}]
    run = _run_result(manifest=m)
    assert not run.ok and run.demonstration is None
    assert any("no-skip term" in r for r in run.reasons)


def test_missing_case_class_denies() -> None:
    nodes = [n for n in _passed_nodes() if "[failure_class]" not in n]
    run = _run_result(passed_nodes=nodes)
    assert not run.ok and run.demonstration is None
    assert any("failure_class" in r for r in run.reasons)


def test_non_valid_build_artifacts_deny_at_record_time() -> None:
    # The build-artifacts VALID check lives in the AS-25 verifier; a non-VALID build gates the signed record.
    tr, signers = _trust_root()
    rec = record_tt_stg_run(
        acceptance=_acceptance(), manifest=_manifest(), passed_nodes=_passed_nodes(),
        repo_root=_REPO_ROOT, slice_id="AS-1b", claim_ids=["AS-1b.tt-stg-run"],
        build=BuildRef(build_id="b", artifacts="PENDING"), ui_legs=_ui_legs(),
        signers=signers, trust_root=tr, environment="staging",
    )
    assert not rec.ok and rec.signed is None
    assert any("artifacts" in r for r in rec.reasons)


# --------------------------------------------------------------------------------------
# Record-time self-verification is fail-closed (production root / off-census route).
# --------------------------------------------------------------------------------------
def test_production_environment_denies_the_record() -> None:
    tr, signers = _trust_root()
    rec = record_tt_stg_run(
        acceptance=_acceptance(), manifest=_manifest(), passed_nodes=_passed_nodes(),
        repo_root=_REPO_ROOT, slice_id="AS-1b", claim_ids=["AS-1b.tt-stg-run"],
        build=_build(), ui_legs=_ui_legs(), signers=signers, trust_root=tr, environment="production",
    )
    assert not rec.ok and rec.signed is None
    assert any("non-production" in r or "production" in r for r in rec.reasons)


def test_off_census_route_denies_the_record() -> None:
    tr, signers = _trust_root()
    rec = record_tt_stg_run(
        acceptance=_acceptance(), manifest=_manifest(), passed_nodes=_passed_nodes(),
        repo_root=_REPO_ROOT, slice_id="AS-1b", claim_ids=["AS-1b.tt-stg-run"],
        build=_build(), ui_legs=[UiLeg(route="#/not/in/census", screen="x", session="s")],
        signers=signers, trust_root=tr, environment="staging", census_routes={"#/monitoring/overview"},
    )
    assert not rec.ok and rec.signed is None
    assert any("census" in r for r in rec.reasons)


def test_wrong_signer_denies_the_record() -> None:
    tr, _ = _trust_root()
    _, other_signers = _trust_root()  # signs under a DIFFERENT key than the trust root
    rec = record_tt_stg_run(
        acceptance=_acceptance(), manifest=_manifest(), passed_nodes=_passed_nodes(),
        repo_root=_REPO_ROOT, slice_id="AS-1b", claim_ids=["AS-1b.tt-stg-run"],
        build=_build(), ui_legs=_ui_legs(), signers=other_signers, trust_root=tr, environment="staging",
    )
    assert not rec.ok and rec.signed is None


# --------------------------------------------------------------------------------------
# The gate's structured verdict.
# --------------------------------------------------------------------------------------
def test_gate_verdict_is_structured() -> None:
    gate = gate_tt_stg_run(acceptance=_acceptance(), manifest=_manifest(), passed_nodes=_passed_nodes())
    assert gate.ok
    assert gate.acceptance_reasons == () and gate.manifest_reasons == ()
    assert gate.no_skip_reasons == () and gate.case_reasons == ()
    # a broken run names the failing sub-gate.
    bad = gate_tt_stg_run(acceptance={"ok": False}, manifest=_manifest(), passed_nodes=_passed_nodes())
    assert not bad.ok and bad.acceptance_reasons


# --------------------------------------------------------------------------------------
# The LIVE residual is honest — registered as AS1B-live-fire-tt-stg in docs/limitations/inventory.json.
# --------------------------------------------------------------------------------------
def test_committed_trust_root_is_unprovisioned_so_no_live_record_verifies_in_ci() -> None:
    """The real staging TT-evidence key is KMS-wrapped in the staging control plane, not in CI. The
    committed trust-root doc is honestly ``unprovisioned`` (empty authorisers), so a record cannot be
    signed/verified under the REAL root here — the live half is the registered deploy-gated residual."""
    doc = load_trust_root_doc_file(_TRUST_ROOT_DOC)
    assert doc.environment == "staging"
    assert doc.status == "unprovisioned"
    assert doc.trust_root is None
    assert not doc.is_usable


def test_default_subject_paths_all_exist() -> None:
    # the subject digest binds real files; a drifted subject path would silently narrow the binding.
    for rel in DEFAULT_SUBJECT_PATHS:
        assert (_REPO_ROOT / rel).exists(), rel
