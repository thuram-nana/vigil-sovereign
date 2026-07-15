"""
Tests for engage_fusion — fuse GATED sensors into a live engagement's world-model (Workstream B).

``fuse_sensors(world, slug, ctx)`` runs a small set of SAFE, OFFLINE sensors through the existing
gated pipeline (``run_sensor`` -> ``invoke_tool``'s fail-closed chain), folds their observations into
the passed world-model as ``GROUNDING_INTEL`` LEADS, and lets the existing oracles re-verify in-run:
the version-range oracle over SBOM advisories promotes a confirmed LEAD to an ``oracle:``-grounded
FACT. Doctrine under test: everything gated; nothing enters as a FACT without an oracle re-firing;
deterministic + idempotent (caller seq, no wallclock/rng).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.v2.agents.tools import ToolContext
from framework.v2.engage_fusion import fuse_sensors
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import (
    GROUNDING_GROUNDED,
    GROUNDING_INTEL,
    EdgeKind,
    NodeKind,
)


# A signed charter listing the declared host in scope — a sensor acting on args['host'] is
# charter-scope-gated, so a minting run needs a real charter (mirrors sensors/tests/test_sensors.py).
_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `10.0.0.5` | Declared host | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""

# grype JSON: log4j-core@2.14.1 matched by two CVEs whose ranges (<2.15.0, <2.16.0) BOTH contain
# 2.14.1 — so the version-range oracle CONFIRMS both (the scanner match is a lead; the oracle proves).
_GRYPE = """
{"matches": [
  {"vulnerability": {"id": "CVE-2021-44228"},
   "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"},
   "matchDetails": [{"found": {"versionConstraint": ">=2.0.0,<2.15.0 (unknown)"}}]},
  {"vulnerability": {"id": "CVE-2021-45046"},
   "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"},
   "matchDetails": [{"found": {"versionConstraint": ">=2.0.0,<2.16.0"}}]}
]}
"""

_DECL_ARGS = {"host": "10.0.0.5", "services": [
    {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.18.0"},
    {"port": 22, "protocol": "tcp", "state": "closed"},   # closed -> not minted
]}

_PKG_ID = "package:log4j-core@2.14.1"
_VULN_ID = "vulnerability:CVE-2021-44228"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate the per-slug paths to tmp_path and lay down a signed charter for 'alpha'."""
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    td = tmp_path / "alpha"
    td.mkdir(parents=True, exist_ok=True)
    (td / "charter.md").write_text(_CHARTER.format(slug="alpha"), encoding="utf-8")


def _grype_report(tmp_path: Path, text: str = _GRYPE) -> str:
    p = tmp_path / "grype.json"
    p.write_text(text, encoding="utf-8")
    return str(p)


def _ctx(*tasks) -> SimpleNamespace:
    """A minimal caller ctx carrying an explicit fusion plan (WS-A's path)."""
    return SimpleNamespace(fusion_tasks=list(tasks))


# ---- declared_service: LEADs fold into the world, nothing grounded ----------


def test_declared_service_fuses_leads_into_the_world() -> None:
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "declared_service", "args": _DECL_ARGS}))
    assert minted, "declared_service should mint observations"
    # the HOST + SERVICE + HOSTS structure folded into the PASSED world-model
    assert world.has_node("host:10.0.0.5")
    assert world.has_node("service:10.0.0.5:443/tcp")
    assert world.get_edge("host:10.0.0.5", "service:10.0.0.5:443/tcp", EdgeKind.HOSTS) is not None
    assert not world.has_node("service:10.0.0.5:22/tcp")   # the closed port minted nothing


def test_declared_service_output_is_a_lead_never_a_fact() -> None:
    # No live service-reachability handshake oracle runs offline, so a declared 'open' stays a LEAD:
    # every node fusion produced from this sensor is intel-grounded, none is oracle-grounded.
    world = WorldModel()
    fuse_sensors(world, "alpha", _ctx({"sensor": "declared_service", "args": _DECL_ARGS}))
    assert world.get_node("service:10.0.0.5:443/tcp").grounding == GROUNDING_INTEL
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


# ---- sbom: an oracle re-fires in-run and promotes a LEAD to a FACT ----------


def test_sbom_lead_is_promoted_to_a_fact_by_the_version_range_oracle(tmp_path: Path) -> None:
    world = WorldModel()
    report = _grype_report(tmp_path)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "sbom_vuln", "args": {"report": report}}))
    # the sensor minted the PACKAGE as a LEAD (intel-grounded) — never a confirmed vuln by itself
    assert any(o.subject.node_id == _PKG_ID for o in minted)
    assert world.get_node(_PKG_ID).grounding == GROUNDING_INTEL
    # the version-range oracle re-fired in-run: the vulnerability + AFFECTS edge are oracle-GROUNDED
    vuln = world.get_node(_VULN_ID)
    assert vuln is not None and vuln.grounding == GROUNDING_GROUNDED
    assert vuln.provenance.startswith("oracle:")
    edge = world.get_edge(_VULN_ID, _PKG_ID, EdgeKind.AFFECTS)
    assert edge is not None and edge.grounding == GROUNDING_GROUNDED
    # the promoted FACT is written to the world, NOT returned as a minted observation
    assert all(o.subject.node_id != _VULN_ID for o in minted)


def test_sbom_patched_version_stays_a_lead_no_oracle_no_fact(tmp_path: Path) -> None:
    # A patched version is out of every affected range: the scanner still "matched" (a LEAD) but the
    # oracle REFUSES — so no vulnerability fact is minted. Nothing enters as a fact without an oracle.
    world = WorldModel()
    report = _grype_report(tmp_path, _GRYPE.replace("2.14.1", "2.17.1"))
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "sbom_vuln", "args": {"report": report}}))
    assert any(o.subject.node_id == "package:log4j-core@2.17.1" for o in minted)   # the LEAD
    assert not world.has_node(_VULN_ID)                                            # no fact
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


# ---- everything gated, fail-closed ------------------------------------------


def test_a_tripped_kill_switch_refuses_every_sensor_and_mints_nothing(tmp_path: Path) -> None:
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("test halt")
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", _ctx(
        {"sensor": "declared_service", "args": _DECL_ARGS},
        {"sensor": "sbom_vuln", "args": {"report": _grype_report(tmp_path)}}))
    assert minted == []
    assert world.all_nodes() == []           # gate ran BEFORE any minting or oracle re-verification


def test_an_out_of_scope_declared_host_is_refused_and_mints_nothing() -> None:
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", _ctx(
        {"sensor": "declared_service", "args": {"host": "8.8.8.8", "services": [{"port": 53}]}}))
    assert minted == []
    assert not world.has_node("host:8.8.8.8")


def test_active_sensor_tasks_are_dropped_in_the_first_slice() -> None:
    # An active/live sensor (nmap) is NOT in the offline allowlist: it is dropped before invocation
    # (roadmap), so nothing is minted and no live binary is ever reached.
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "nmap", "args": {"target": "10.0.0.5"}}))
    assert minted == []
    assert world.all_nodes() == []


# ---- plan resolution: ctx (attr + dict) and the operator manifest -----------


def test_empty_plan_returns_empty_no_manifest() -> None:
    world = WorldModel()
    assert fuse_sensors(world, "alpha", SimpleNamespace()) == []
    assert world.all_nodes() == []


def test_a_dict_ctx_carrying_a_plan_is_honoured() -> None:
    world = WorldModel()
    minted = fuse_sensors(world, "alpha",
                          {"fusion_tasks": [{"sensor": "declared_service", "args": _DECL_ARGS}]})
    assert minted and world.has_node("host:10.0.0.5")


def test_a_tool_context_ctx_is_accepted(tmp_path: Path) -> None:
    # WS-A may pass a plain ToolContext; fuse still resolves a plan from the manifest fallback.
    (tmp_path / "alpha" / "fusion.json").write_text(
        '[{"sensor": "declared_service", "args": '
        '{"host": "10.0.0.5", "services": [{"port": 443, "protocol": "tcp"}]}}]', encoding="utf-8")
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", ToolContext(slug="alpha"))
    assert minted and world.has_node("service:10.0.0.5:443/tcp")


def test_operator_manifest_fallback_is_read(tmp_path: Path) -> None:
    (tmp_path / "alpha" / "fusion.json").write_text(
        '{"tasks": [{"sensor": "sbom_vuln", "args": {"report": "%s"}}]}' % _grype_report(tmp_path),
        encoding="utf-8")
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", SimpleNamespace())   # no ctx plan -> manifest
    assert any(o.subject.node_id == _PKG_ID for o in minted)
    assert world.get_node(_VULN_ID).grounding == GROUNDING_GROUNDED


# ---- determinism + idempotence ----------------------------------------------


def test_fusion_is_deterministic_across_fresh_worlds(tmp_path: Path) -> None:
    plan = _ctx(
        {"sensor": "declared_service", "args": _DECL_ARGS},
        {"sensor": "sbom_vuln", "args": {"report": _grype_report(tmp_path)}})

    def _run():
        w = WorldModel()
        m = fuse_sensors(w, "alpha", plan)
        return [o.obs_id for o in m], sorted((n.id, n.grounding) for n in w.all_nodes())

    ids_a, nodes_a = _run()
    ids_b, nodes_b = _run()
    assert ids_a == ids_b            # identical obs_ids (pure function of caller seq + claim)
    assert nodes_a == nodes_b        # identical world state incl. grounding tiers


def test_re_running_fusion_on_the_same_world_is_idempotent(tmp_path: Path) -> None:
    plan = _ctx(
        {"sensor": "declared_service", "args": _DECL_ARGS},
        {"sensor": "sbom_vuln", "args": {"report": _grype_report(tmp_path)}})
    world = WorldModel()
    fuse_sensors(world, "alpha", plan)
    n_nodes = len(world.all_nodes())
    ids = {n.id for n in world.all_nodes()}
    # re-run: node ids are keyed by claim identity, so a second pass re-asserts the SAME nodes
    # (a legitimate corroboration) — it never spawns duplicate/phantom nodes. Graph shape is stable.
    fuse_sensors(world, "alpha", plan)
    assert len(world.all_nodes()) == n_nodes
    assert {n.id for n in world.all_nodes()} == ids


# =============================================================================
# Workstream-3 — the dormant OFFLINE producers fuse alongside their promotion oracle.
# =============================================================================

# kube-bench: control 1.2.1 hard-FAILED with a concrete insecure setting in its actual_value; 1.2.2
# PASSED (skipped by the sensor). The k8s-posture oracle promotes ONLY the proven insecure control.
_KB_INSECURE = """
{"Controls": [
  {"id": "1", "text": "Master", "tests": [
    {"section": "1.2", "desc": "API Server", "results": [
      {"test_number": "1.2.1", "test_desc": "Ensure --anonymous-auth is false", "status": "FAIL",
       "actual_value": "kube-apiserver --anonymous-auth=true --profiling=false",
       "remediation": "set --anonymous-auth=false"},
      {"test_number": "1.2.2", "test_desc": "Ensure --basic-auth-file is not set", "status": "PASS",
       "actual_value": "kube-apiserver --anonymous-auth=false"}
    ]}
  ]}
]}
"""

# kube-bench: a hard FAIL whose observed value shows the SECURE setting — a LEAD, never a fact.
_KB_BENIGN_FAIL = """
{"Controls": [
  {"id": "1", "text": "Master", "tests": [
    {"section": "1.3", "desc": "API Server", "results": [
      {"test_number": "1.3.1", "test_desc": "Some manual review control", "status": "FAIL",
       "actual_value": "kube-apiserver --anonymous-auth=false --insecure-port=0 --profiling=false"}
    ]}
  ]}
]}
"""

# native cloud inventory: a public bucket (public exposure), a sensitive datastore with an admin grant
# (over-broad trust), and a benign private resource (no lead, no fact).
_CLOUD_NATIVE = """
{"provider": "aws",
 "principals": [{"id": "role/dev", "can_assume": ["role/admin"]}, {"id": "role/admin"}],
 "resources": [
   {"id": "s3/public-bucket", "public": true},
   {"id": "s3/customer-data", "kind": "datastore", "sensitive": true,
    "grants": [{"principal": "role/admin", "access": "admin"}]},
   {"id": "s3/internal", "grants": [{"principal": "role/dev", "access": "read"}]}
 ]}
"""

# a benign cloud inventory: nothing public, nothing over-privileged-on-sensitive — no fact.
_CLOUD_BENIGN = """
{"provider": "aws",
 "principals": [{"id": "role/dev"}],
 "resources": [{"id": "s3/internal", "grants": [{"principal": "role/dev", "access": "read"}]}]}
"""


def _write(tmp_path: Path, name: str, text: str) -> str:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    """Grant the ACTIVE_RECON entitlement the gated live reachability handshake requires (the charter
    scope + kill-switch gates still apply)."""
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


# ---- 3a: kube_bench LEAD -> k8s-posture FACT --------------------------------


def test_kube_bench_insecure_control_is_promoted_by_the_k8s_posture_oracle(tmp_path: Path) -> None:
    world = WorldModel()
    report = _write(tmp_path, "kube-bench.json", _KB_INSECURE)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "kube_bench", "args": {"report": report}}))
    # the failed control folded in as a LEAD (intel-grounded), never oracle-proof by itself
    assert any(o.subject.node_id == "control:cis-k8s:1.2.1" for o in minted)
    assert world.get_node("control:cis-k8s:1.2.1").grounding == GROUNDING_INTEL
    # the k8s-posture oracle re-fired in-run: a FINDING + EVIDENCES edge is oracle-GROUNDED
    finding = world.get_node("finding:k8s_posture:cis-k8s:1.2.1")
    assert finding is not None and finding.grounding == GROUNDING_GROUNDED
    assert finding.provenance.startswith("oracle:")
    edge = world.get_edge("finding:k8s_posture:cis-k8s:1.2.1", "control:cis-k8s:1.2.1", EdgeKind.EVIDENCES)
    assert edge is not None and edge.grounding == GROUNDING_GROUNDED
    # the PASS control (1.2.2) was skipped by the sensor — no lead, no fact
    assert not world.has_node("control:cis-k8s:1.2.2")


def test_kube_bench_benign_fail_stays_a_lead_no_oracle_no_fact(tmp_path: Path) -> None:
    world = WorldModel()
    report = _write(tmp_path, "kube-bench.json", _KB_BENIGN_FAIL)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "kube_bench", "args": {"report": report}}))
    assert any(o.subject.node_id == "control:cis-k8s:1.3.1" for o in minted)   # the LEAD
    assert not world.has_node("finding:k8s_posture:cis-k8s:1.3.1")             # no fact
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


# ---- cicd_workflows: dangerous workflow control LEAD -> CI/CD-posture FACT ---
# A dangerous GitHub-Actions workflow: pull_request_target + PR-head checkout (pwn_request), an unpinned
# third-party action (unpinned_action), and a run interpolating an untrusted title (script_injection).
_WF_VULN = """
name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: evil-org/evil-action@main
      - run: echo "PR ${{ github.event.pull_request.title }}"
"""

# A benign workflow: SHA-pinned first-party checkout + a static run under a plain pull_request trigger.
_WF_BENIGN = """
name: ci
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abcabcabcabcabcabcabcabcabcabcabcabcabca
      - run: make build
"""


def test_cicd_dangerous_workflow_control_is_promoted_by_the_cicd_posture_oracle(tmp_path: Path) -> None:
    world = WorldModel()
    report = _write(tmp_path, "ci.yml", _WF_VULN)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "cicd_workflows", "args": {"workflow": report}}))
    # the workflow constructs folded in as CONTROL LEADS (intel-grounded), never oracle-proof by themselves
    leads = [o for o in minted if o.subject.node_id.startswith("control:cicd:")]
    assert leads, "no CI/CD control leads minted"
    assert all(world.get_node(o.subject.node_id).grounding == GROUNDING_INTEL for o in leads)
    # the CI/CD-posture oracle re-fired in-run: each dangerous construct is an oracle-GROUNDED FINDING.
    # The dangerous VULN workflow has exactly three: pwn_request, unpinned (evil-action), script_injection.
    facts = [n for n in world.all_nodes()
             if n.id.startswith("finding:cicd_posture:") and n.grounding == GROUNDING_GROUNDED]
    assert len(facts) == 3, f"expected 3 CI/CD facts, got {[n.id for n in facts]}"
    assert all(n.provenance.startswith("oracle:") for n in facts)
    # each grounded finding hangs off its CONTROL lead via an oracle-GROUNDED EVIDENCES edge
    for f in facts:
        control_id = "control:" + f.id.split("finding:cicd_posture:", 1)[1]
        edge = world.get_edge(f.id, control_id, EdgeKind.EVIDENCES)
        assert edge is not None and edge.grounding == GROUNDING_GROUNDED


def test_cicd_benign_workflow_stays_a_lead_no_oracle_no_fact(tmp_path: Path) -> None:
    world = WorldModel()
    report = _write(tmp_path, "ci.yml", _WF_BENIGN)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "cicd_workflows", "args": {"workflow": report}}))
    # the SHA-pinned first-party checkout is still ingested as a LEAD, but the oracle rejects it
    assert any(o.subject.node_id.startswith("control:cicd:") for o in minted), "the LEAD"
    assert not any(n.id.startswith("finding:cicd_posture:") for n in world.all_nodes())  # no fact
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


# ---- mobsf_static: embedded private-key control LEAD -> mobile-posture FACT --
def _rsa_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(65537, 2048).private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode()


def test_mobsf_embedded_private_key_is_promoted_by_the_mobile_posture_oracle(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    world = WorldModel()
    report = _write(tmp_path, "mobsf.json", json.dumps({
        "app_name": "DemoApp", "package_name": "com.demo.app",
        "possible_secrets": [_rsa_key_pem(), "AKIAIOSFODNN7EXAMPLE"],
    }))
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "mobsf_static", "args": {"report": report}}))
    # the secret controls folded in as CONTROL LEADS (intel-grounded), never oracle-proof by themselves
    leads = [o for o in minted if o.subject.node_id.startswith("control:mobile:")]
    assert leads and all(world.get_node(o.subject.node_id).grounding == GROUNDING_INTEL for o in leads)
    # the mobile-posture oracle re-fired in-run: the embedded key is an oracle-GROUNDED FACT; the AKIA
    # example string is NOT a private key → stays a lead. Exactly one fact.
    facts = [n for n in world.all_nodes()
             if n.id.startswith("finding:mobile_posture:") and n.grounding == GROUNDING_GROUNDED]
    assert len(facts) == 1, f"expected 1 mobile fact, got {[n.id for n in facts]}"
    assert facts[0].provenance.startswith("oracle:")
    control_id = "control:" + facts[0].id.split("finding:mobile_posture:", 1)[1]
    edge = world.get_edge(facts[0].id, control_id, EdgeKind.EVIDENCES)
    assert edge is not None and edge.grounding == GROUNDING_GROUNDED


def test_mobsf_no_key_stays_a_lead_no_oracle_no_fact(tmp_path: Path) -> None:
    world = WorldModel()
    report = _write(tmp_path, "mobsf.json", json.dumps({
        "app_name": "DemoApp", "package_name": "com.demo.app",
        "manifest_analysis": {"manifest_findings": [
            {"title": "Activity is exported", "severity": "high", "rule": "exported_activity"}]},
        "possible_secrets": ["AKIAIOSFODNN7EXAMPLE"],
    }))
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "mobsf_static", "args": {"report": report}}))
    assert any(o.subject.node_id.startswith("control:mobile:") for o in minted), "the LEAD"
    assert not any(n.id.startswith("finding:mobile_posture:") for n in world.all_nodes())  # no fact
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


def test_mobsf_report_with_no_app_identity_promotes_no_orphan_fact(tmp_path: Path) -> None:
    # review defect [LOW]: without app metadata the sensor mints NO lead (mobsf_observations short-
    # circuits), so the fusion promotion must ALSO short-circuit — never a grounded fact on a control
    # node the sensor never minted as a lead.
    pytest.importorskip("cryptography")
    world = WorldModel()
    report = _write(tmp_path, "mobsf.json", json.dumps({"possible_secrets": [_rsa_key_pem()]}))  # no package/name
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "mobsf_static", "args": {"report": report}}))
    assert minted == []                                        # no lead minted
    assert world.all_nodes() == []                             # and no orphan fact/stub control


# ---- android_manifest: an exported unguarded provider LEAD -> mobile-posture FACT ----
_ANDROID_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.app">
  <application>
    <provider android:name="com.demo.Unguarded" android:exported="true" android:authorities="com.demo.a"/>
    <provider android:name="com.demo.Guarded" android:exported="true" android:permission="com.demo.PERM"/>
  </application>
</manifest>"""


def test_android_manifest_exported_provider_is_promoted_by_the_mobile_posture_oracle(tmp_path: Path) -> None:
    world = WorldModel()
    report = _write(tmp_path, "AndroidManifest.xml", _ANDROID_MANIFEST)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "android_manifest", "args": {"manifest": report}}))
    leads = [o for o in minted if o.subject.node_id.startswith("control:mobile:component:provider:")]
    assert leads and all(world.get_node(o.subject.node_id).grounding == GROUNDING_INTEL for o in leads)
    # ONLY the explicitly-exported UNGUARDED provider promotes to a grounded FACT (the guarded one stays a lead)
    facts = [n for n in world.all_nodes()
             if n.id.startswith("finding:mobile_posture:") and n.grounding == GROUNDING_GROUNDED]
    assert len(facts) == 1, f"expected 1 provider fact, got {[n.id for n in facts]}"
    assert "unguarded" in facts[0].id.lower()
    control_id = "control:" + facts[0].id.split("finding:mobile_posture:", 1)[1]
    edge = world.get_edge(facts[0].id, control_id, EdgeKind.EVIDENCES)
    assert edge is not None and edge.grounding == GROUNDING_GROUNDED


# ---- tls_cert: a broken-hash cert LEAD -> weak-crypto-artifact FACT ----------
def test_tls_cert_broken_hash_signature_is_promoted_by_the_weak_crypto_oracle(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from framework.v2.verify.tests.test_weak_crypto import _SHA1_CERT_PEM
    world = WorldModel()
    report = _write(tmp_path, "weak.pem", _SHA1_CERT_PEM)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "tls_cert", "args": {"cert": report}}))
    # the cert folded in as a CONTROL LEAD (intel-grounded), never oracle-proof by itself
    leads = [o for o in minted if o.subject.node_id.startswith("control:crypto:")]
    assert leads and all(world.get_node(o.subject.node_id).grounding == GROUNDING_INTEL for o in leads)
    # the weak-crypto oracle re-fired in-run: the SHA-1 signature is an oracle-GROUNDED FACT
    facts = [n for n in world.all_nodes()
             if n.id.startswith("finding:tls_weakness:crypto:") and n.grounding == GROUNDING_GROUNDED]
    assert len(facts) == 1, f"expected 1 weak-crypto fact, got {[n.id for n in facts]}"
    assert facts[0].provenance.startswith("oracle:")
    control_id = "control:" + facts[0].id.split("finding:tls_weakness:", 1)[1]
    edge = world.get_edge(facts[0].id, control_id, EdgeKind.EVIDENCES)
    assert edge is not None and edge.grounding == GROUNDING_GROUNDED


def test_tls_cert_modern_sha256_stays_a_lead_no_oracle_no_fact(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.hashes import SHA256
    from framework.v2.verify.tests.test_weak_crypto import _cert
    world = WorldModel()
    report = _write(tmp_path, "modern.pem", _cert(SHA256()).decode())
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "tls_cert", "args": {"cert": report}}))
    assert any(o.subject.node_id.startswith("control:crypto:") for o in minted), "the LEAD"
    assert not any(n.id.startswith("finding:tls_weakness:crypto:") for n in world.all_nodes())  # no fact
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


# ---- mesh_config: a permissive Istio control LEAD -> mesh-posture FACT -------
_MESH_PERMISSIVE = json.dumps([
    {"kind": "PeerAuthentication", "metadata": {"name": "default", "namespace": "istio-system"},
     "spec": {"mtls": {"mode": "PERMISSIVE"}}},
    {"kind": "PeerAuthentication", "metadata": {"name": "strict", "namespace": "istio-system"},
     "spec": {"mtls": {"mode": "STRICT"}}},
])


def test_mesh_permissive_mtls_is_promoted_by_the_mesh_posture_oracle(tmp_path: Path) -> None:
    world = WorldModel()
    report = _write(tmp_path, "istio.json", _MESH_PERMISSIVE)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "mesh_config", "args": {"config": report}}))
    leads = [o for o in minted if o.subject.node_id.startswith("control:mesh:")]
    assert leads and all(world.get_node(o.subject.node_id).grounding == GROUNDING_INTEL for o in leads)
    # ONLY the PERMISSIVE PeerAuthentication promotes to a grounded FACT; the STRICT one stays a lead
    facts = [n for n in world.all_nodes()
             if n.id.startswith("finding:mesh_posture:") and n.grounding == GROUNDING_GROUNDED]
    assert len(facts) == 1, f"expected 1 mesh fact, got {[n.id for n in facts]}"
    assert "istio-system/default" in facts[0].id
    control_id = "control:" + facts[0].id.split("finding:mesh_posture:", 1)[1]
    edge = world.get_edge(facts[0].id, control_id, EdgeKind.EVIDENCES)
    assert edge is not None and edge.grounding == GROUNDING_GROUNDED


def test_mesh_strict_config_stays_a_lead_no_oracle_no_fact(tmp_path: Path) -> None:
    world = WorldModel()
    report = _write(tmp_path, "istio.json", json.dumps([
        {"kind": "PeerAuthentication", "metadata": {"name": "default", "namespace": "istio-system"},
         "spec": {"mtls": {"mode": "STRICT"}}}]))
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "mesh_config", "args": {"config": report}}))
    assert any(o.subject.node_id.startswith("control:mesh:") for o in minted), "the LEAD"
    assert not any(n.id.startswith("finding:mesh_posture:") for n in world.all_nodes())  # no fact
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


# ---- 3b: cloud_import LEAD -> policy-path FACT (no live cloud) ---------------


def test_cloud_public_and_overbroad_leads_are_promoted_by_the_policy_path_oracle(tmp_path: Path) -> None:
    world = WorldModel()
    inv = _write(tmp_path, "cloud.json", _CLOUD_NATIVE)
    fuse_sensors(world, "alpha", _ctx({"sensor": "cloud_import", "args": {"inventory_file": inv}}))
    # public exposure: the anonymous principal reaches the public bucket via a real grant path -> FACT
    pub = world.get_node("finding:policy_path:s3/public-bucket")
    assert pub is not None and pub.grounding == GROUNDING_GROUNDED and pub.provenance.startswith("oracle:")
    assert world.get_edge("finding:policy_path:s3/public-bucket",
                          "cloud_resource:s3/public-bucket", EdgeKind.EVIDENCES) is not None
    # over-broad trust: role/admin's admin grant over the sensitive datastore -> FACT (attached to the
    # SAME datastore node the topology minter created)
    over = world.get_node("finding:policy_path:s3/customer-data")
    assert over is not None and over.grounding == GROUNDING_GROUNDED
    assert world.get_edge("finding:policy_path:s3/customer-data",
                          "datastore:s3/customer-data", EdgeKind.EVIDENCES) is not None
    # the benign private resource was never a lead and is never a fact
    assert not world.has_node("finding:policy_path:s3/internal")


def test_cloud_benign_posture_promotes_nothing(tmp_path: Path) -> None:
    world = WorldModel()
    inv = _write(tmp_path, "cloud.json", _CLOUD_BENIGN)
    fuse_sensors(world, "alpha", _ctx({"sensor": "cloud_import", "args": {"inventory_file": inv}}))
    # topology leads may fold in, but NOTHING is oracle-grounded (no public/over-broad path)
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())
    assert not any(n.id.startswith("finding:policy_path:") for n in world.all_nodes())


# ---- 3b (G1): cloud_misconfiguration LEAD -> cloud-posture FACT (no live cloud) ---

# a sensitive datastore with encryption-at-rest DISABLED — the achieved-state misconfiguration lead the
# policy-path oracle STRUCTURALLY cannot prove (no reachability path proves an at-rest-encryption gap).
_CLOUD_UNENCRYPTED = """
{"provider": "aws",
 "resources": [{"id": "s3/secrets", "kind": "datastore", "sensitive": true, "encrypted": false}]}
"""

# a sensitive datastore that IS encrypted at rest — a compliant control, no lead, no fact.
_CLOUD_ENCRYPTED = """
{"provider": "aws",
 "resources": [{"id": "s3/secure", "kind": "datastore", "sensitive": true, "encrypted": true}]}
"""

# the SAME sensitive datastore is BOTH over-privileged (excessive_privilege -> policy-path) AND
# unencrypted-at-rest (misconfiguration -> cloud-posture); a second sensitive resource is compliant.
_CLOUD_MIXED = """
{"provider": "aws",
 "principals": [{"id": "role/admin"}],
 "resources": [
   {"id": "s3/customer-data", "kind": "datastore", "sensitive": true, "encrypted": false,
    "grants": [{"principal": "role/admin", "access": "admin"}]},
   {"id": "s3/logs", "kind": "datastore", "sensitive": true, "encrypted": true}
 ]}
"""


def test_cloud_unencrypted_sensitive_lead_is_promoted_by_the_cloud_posture_oracle(tmp_path: Path) -> None:
    world = WorldModel()
    inv = _write(tmp_path, "cloud.json", _CLOUD_UNENCRYPTED)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "cloud_import", "args": {"inventory_file": inv}}))
    # the misconfiguration lead folded in on the datastore node as an intel-grounded LEAD
    assert any(o.subject.node_id == "datastore:s3/secrets" for o in minted)
    assert world.get_node("datastore:s3/secrets").grounding == GROUNDING_INTEL
    # the cloud-posture oracle re-fired in-run over the retained achieved state: a FINDING + EVIDENCES
    # edge is oracle-GROUNDED, attached to the SAME resource node the topology minter created
    finding = world.get_node("finding:cloud_posture:s3/secrets")
    assert finding is not None and finding.grounding == GROUNDING_GROUNDED
    assert finding.provenance.startswith("oracle:")
    edge = world.get_edge("finding:cloud_posture:s3/secrets", "datastore:s3/secrets", EdgeKind.EVIDENCES)
    assert edge is not None and edge.grounding == GROUNDING_GROUNDED
    # the un-reachability-provable lead is NOT a policy-path fact (that oracle cannot prove it)
    assert not world.has_node("finding:policy_path:s3/secrets")


def test_cloud_encrypted_sensitive_control_stays_a_lead_no_oracle_no_fact(tmp_path: Path) -> None:
    # A compliant control (encryption ON) mints no misconfiguration lead and the cloud-posture oracle
    # REFUSES — so no fact enters. Nothing is promoted without the oracle firing.
    world = WorldModel()
    inv = _write(tmp_path, "cloud.json", _CLOUD_ENCRYPTED)
    fuse_sensors(world, "alpha", _ctx({"sensor": "cloud_import", "args": {"inventory_file": inv}}))
    assert not world.has_node("finding:cloud_posture:s3/secure")
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


def test_cloud_misconfig_promotion_is_additive_and_leaves_the_policy_path_leads_unchanged(
        tmp_path: Path) -> None:
    world = WorldModel()
    inv = _write(tmp_path, "cloud.json", _CLOUD_MIXED)
    fuse_sensors(world, "alpha", _ctx({"sensor": "cloud_import", "args": {"inventory_file": inv}}))
    # the non-misconfiguration lead is UNCHANGED: the excessive-privilege grant path is still a
    # policy-path FACT on the datastore node (the G1 wiring did not disturb it)
    over = world.get_node("finding:policy_path:s3/customer-data")
    assert over is not None and over.grounding == GROUNDING_GROUNDED
    assert world.get_edge("finding:policy_path:s3/customer-data",
                          "datastore:s3/customer-data", EdgeKind.EVIDENCES) is not None
    # ADDITIVELY, the achieved-state misconfiguration is now ALSO a cloud-posture FACT on the SAME node
    misc = world.get_node("finding:cloud_posture:s3/customer-data")
    assert misc is not None and misc.grounding == GROUNDING_GROUNDED
    assert world.get_edge("finding:cloud_posture:s3/customer-data",
                          "datastore:s3/customer-data", EdgeKind.EVIDENCES) is not None
    # the compliant (encrypted) sensitive resource is never a misconfiguration fact
    assert not world.has_node("finding:cloud_posture:s3/logs")


def test_cloud_misconfig_promotion_is_idempotent(tmp_path: Path) -> None:
    # re-running fusion over the same world re-asserts the SAME cloud-posture fact node — a stable
    # finding id, never a duplicate/phantom (pure over the caller seq, claim-keyed).
    world = WorldModel()
    inv = _write(tmp_path, "cloud.json", _CLOUD_UNENCRYPTED)
    plan = _ctx({"sensor": "cloud_import", "args": {"inventory_file": inv}})
    fuse_sensors(world, "alpha", plan)
    ids = {n.id for n in world.all_nodes()}
    assert "finding:cloud_posture:s3/secrets" in ids
    fuse_sensors(world, "alpha", plan)
    assert {n.id for n in world.all_nodes()} == ids


# ---- 3c: declared_service 'open' LEAD -> reachability FACT (opt-in, gated) ---


def test_reachability_promotes_open_lead_only_when_opted_in_and_gated(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _grant_active_recon(monkeypatch)
    world = WorldModel()
    # opt-in per task (confirm_reachable) + an injected connector so the handshake is deterministic/offline
    args = {"host": "10.0.0.5", "confirm_reachable": True,
            "services": [{"port": 443, "protocol": "tcp"}]}
    ctx = SimpleNamespace(fusion_tasks=[{"sensor": "declared_service", "args": args}],
                          reach_connect=lambda h, p, t, b: (f"{h}:{p}", "HTTP/1.1 400"))
    fuse_sensors(world, "alpha", ctx)
    # the SERVICE folded in as a LEAD; the gated handshake confirmed it -> an oracle-grounded FACT
    assert world.get_node("service:10.0.0.5:443/tcp").grounding == GROUNDING_INTEL
    finding = world.get_node("finding:service_reachability:10.0.0.5:443/tcp")
    assert finding is not None and finding.grounding == GROUNDING_GROUNDED
    assert world.get_edge("finding:service_reachability:10.0.0.5:443/tcp",
                          "service:10.0.0.5:443/tcp", EdgeKind.EVIDENCES) is not None


def test_reachability_is_not_confirmed_without_the_per_task_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    _grant_active_recon(monkeypatch)
    world = WorldModel()
    # NO confirm_reachable — the live handshake never runs even though a connector is present
    called = {"n": 0}
    ctx = SimpleNamespace(
        fusion_tasks=[{"sensor": "declared_service",
                       "args": {"host": "10.0.0.5", "services": [{"port": 443, "protocol": "tcp"}]}}],
        reach_connect=lambda *a: (called.update(n=called["n"] + 1) or ("x", "")))
    fuse_sensors(world, "alpha", ctx)
    assert called["n"] == 0                                                   # no live probe attempted
    assert not world.has_node("finding:service_reachability:10.0.0.5:443/tcp")
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


def test_reachability_fails_closed_without_the_active_recon_entitlement(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # opt-in but NOT entitled: capture_handshake's gate refuses BEFORE dialling -> no fact (fail-closed).
    from framework.v2 import entitlement

    def _deny(cap):
        raise PermissionError("active_recon not entitled")

    monkeypatch.setattr(entitlement, "require_capability", _deny)
    world = WorldModel()
    reached = {"n": 0}
    ctx = SimpleNamespace(
        fusion_tasks=[{"sensor": "declared_service",
                       "args": {"host": "10.0.0.5", "confirm_reachable": True,
                                "services": [{"port": 443, "protocol": "tcp"}]}}],
        reach_connect=lambda *a: (reached.update(n=reached["n"] + 1) or ("x", "")))
    fuse_sensors(world, "alpha", ctx)
    assert reached["n"] == 0                                                  # never connected
    assert not world.has_node("finding:service_reachability:10.0.0.5:443/tcp")


def test_reachability_out_of_scope_host_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _grant_active_recon(monkeypatch)
    world = WorldModel()
    # 8.8.8.8 is not in the 'alpha' charter scope; the declared_service sensor itself is scope-refused,
    # so nothing folds and no reachability probe is even reached.
    ctx = SimpleNamespace(
        fusion_tasks=[{"sensor": "declared_service",
                       "args": {"host": "8.8.8.8", "confirm_reachable": True,
                                "services": [{"port": 53, "protocol": "tcp"}]}}],
        reach_connect=lambda h, p, t, b: (f"{h}:{p}", "banner"))
    minted = fuse_sensors(world, "alpha", ctx)
    assert minted == [] and not world.has_node("finding:service_reachability:8.8.8.8:53/tcp")


# ---- live TLS: declared TLS service -> weak-TLS + weak-crypto FACTs (opt-in, gated) ----
def _sha1_der() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from framework.v2.verify.tests.test_weak_crypto import _SHA1_CERT_PEM
    return x509.load_pem_x509_certificate(_SHA1_CERT_PEM.encode()).public_bytes(Encoding.DER)


def _tls_task(**extra):
    return {"sensor": "declared_service",
            "args": {"host": "10.0.0.5", "confirm_tls": True,
                     "services": [{"port": 443, "protocol": "tcp"}], **extra}}


def test_tls_live_promotes_weak_protocol_and_weak_cert(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("cryptography")
    _grant_active_recon(monkeypatch)
    world = WorldModel()
    # injected 4-tuple connector: a deprecated protocol + a SHA-1-signed leaf cert -> BOTH oracles fire
    ctx = SimpleNamespace(fusion_tasks=[_tls_task()],
                          tls_connect=lambda h, p, t: ("TLSv1", "AES128-SHA", 128, _sha1_der()))
    fuse_sensors(world, "alpha", ctx)
    ids = {n.id for n in world.all_nodes() if n.grounding == GROUNDING_GROUNDED}
    assert "finding:tls_weakness:10.0.0.5:443/tcp" in ids          # weak protocol/cipher
    assert "finding:weak_crypto_artifact:10.0.0.5:443/tcp" in ids  # SHA-1 cert (distinct node, no collision)


def test_tls_live_strong_endpoint_promotes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.serialization import Encoding
    from framework.v2.verify.tests.test_weak_crypto import _cert
    modern = x509.load_pem_x509_certificate(_cert(SHA256())).public_bytes(Encoding.DER)
    _grant_active_recon(monkeypatch)
    world = WorldModel()
    ctx = SimpleNamespace(fusion_tasks=[_tls_task()],
                          tls_connect=lambda h, p, t: ("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, modern))
    fuse_sensors(world, "alpha", ctx)
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())   # no fact


def test_tls_live_requires_the_confirm_tls_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    _grant_active_recon(monkeypatch)
    world = WorldModel()
    probed = {"n": 0}
    # NO confirm_tls flag → the live probe must never be attempted
    ctx = SimpleNamespace(
        fusion_tasks=[{"sensor": "declared_service",
                       "args": {"host": "10.0.0.5", "services": [{"port": 443, "protocol": "tcp"}]}}],
        tls_connect=lambda *a: (probed.update(n=probed["n"] + 1) or ("TLSv1", "AES128-SHA", 128, b"")))
    fuse_sensors(world, "alpha", ctx)
    assert probed["n"] == 0
    assert not any(n.id.startswith(("finding:tls_weakness", "finding:weak_crypto_artifact"))
                   for n in world.all_nodes())


def test_tls_live_non_tls_port_is_not_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    _grant_active_recon(monkeypatch)
    world = WorldModel()
    probed = {"n": 0}
    # port 22 is not a well-known TLS port and not flagged tls → no handshake attempted
    ctx = SimpleNamespace(
        fusion_tasks=[{"sensor": "declared_service",
                       "args": {"host": "10.0.0.5", "confirm_tls": True,
                                "services": [{"port": 22, "protocol": "tcp"}]}}],
        tls_connect=lambda *a: (probed.update(n=probed["n"] + 1) or ("TLSv1", "AES128-SHA", 128, b"")))
    fuse_sensors(world, "alpha", ctx)
    assert probed["n"] == 0


def test_tls_live_out_of_scope_host_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # 8.8.8.8 is not in the 'alpha' charter scope → the declared_service sensor is scope-refused and the
    # gated TLS handshake's own _authorize would also refuse fail-closed; nothing folds, no fact.
    pytest.importorskip("cryptography")
    _grant_active_recon(monkeypatch)
    world = WorldModel()
    ctx = SimpleNamespace(
        fusion_tasks=[{"sensor": "declared_service",
                       "args": {"host": "8.8.8.8", "confirm_tls": True,
                                "services": [{"port": 443, "protocol": "tcp"}]}}],
        tls_connect=lambda h, p, t: ("TLSv1", "AES128-SHA", 128, _sha1_der()))
    minted = fuse_sensors(world, "alpha", ctx)
    assert minted == []
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())
