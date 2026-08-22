"""PHASE 0.6 — the per-tool manifest + capability-matrix invariants (integration criteria 2, 6, 12).

Sovereign-safe (no framework import): tool_manifest is pure data + validation. The committed capability
matrix (docs/capability-matrix/hexstrike.json) is the machine-readable, anti-overclaim source of truth —
these tests are its CI sync-check: it must be internally valid, and no tool can be `fact_capable` without an
oracle family, nor both excluded and fact-capable.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration.live.tool_manifest import (
    ToolManifest,
    load_manifests,
    validate_all,
    validate_manifest,
)

_MATRIX = Path(__file__).resolve().parents[2] / "docs" / "capability-matrix" / "hexstrike.json"


def test_committed_capability_matrix_is_valid():
    manifests = load_manifests(_MATRIX)
    assert manifests, "capability matrix is empty"
    errs = validate_all(manifests)
    assert not errs, "capability matrix invariant violations:\n  " + "\n  ".join(errs)


def test_fact_capable_tools_name_an_oracle_family_and_are_not_excluded():
    for m in load_manifests(_MATRIX):
        if m.fact_capable:
            assert m.oracle_family, f"{m.name}: fact_capable without an oracle_family"
            assert not m.excluded, f"{m.name}: fact_capable AND excluded"


def test_the_only_fact_capable_tools_are_the_ones_with_a_shipped_re_drive():
    # Anti-overclaim: the matrix must not claim FACT-capability beyond what actually has a runner-owned
    # re-drive today (nmap → SERVICE_REACHABILITY, sslscan → TLS_WEAKNESS). Growing this set is deliberate.
    fact = {m.name for m in load_manifests(_MATRIX) if m.fact_capable}
    assert fact == {"nmap", "sslscan"}, f"unexpected fact_capable set: {fact}"


def test_track_c_scanner_reports_stay_lead_only():
    """Track C (evidence-authority doctrine): a config/posture SCANNER's report is a LEAD, never a FACT — its
    say-so cannot confirm itself; a FACT comes only from VIGIL parsing the primary artifact (Track A) or a
    VIGIL-owned live capture (Track B). This is the NAMED guard: each of these tools must be present,
    fact_capable=false, and not excluded — so a future edit cannot quietly wire an oracle re-drive onto a
    scanner (the aggregate {nmap,sslscan} pin also catches it; this names the doctrine tool-by-tool)."""
    track_c = {"prowler", "scout-suite", "checkov", "terrascan", "trivy", "kube-bench", "kube-hunter"}
    by = {m.name: m for m in load_manifests(_MATRIX)}
    for name in track_c:
        assert name in by, f"Track-C scanner {name!r} missing from the capability matrix"
        m = by[name]
        assert m.fact_capable is False, f"{name}: a scanner report must stay LEAD-only (fact_capable=false)"
        assert m.excluded is False, f"{name}: a Track-C scanner is a LEAD proposer, not excluded"


def test_offense_categories_must_be_excluded():
    for m in load_manifests(_MATRIX):
        if m.category in ("exploitation", "credential-access", "persistence", "destructive"):
            assert m.excluded, f"{m.name}: offense/credential category not marked excluded"


def test_validator_rejects_overclaims():
    # fact_capable without an oracle family
    assert validate_manifest(ToolManifest(name="x", category="recon", fact_capable=True))
    # excluded AND fact_capable
    assert validate_manifest(ToolManifest(name="x", category="exploitation", excluded=True, fact_capable=True,
                                          oracle_family="Y"))
    # an offense category that is NOT excluded
    assert validate_manifest(ToolManifest(name="x", category="exploitation", excluded=False))
    # unknown category / network_effect / privileges
    assert validate_manifest(ToolManifest(name="x", category="bogus"))
    assert validate_manifest(ToolManifest(name="x", category="recon", network_effect="lasers"))
    # a clean recon LEAD-only tool validates
    assert validate_manifest(ToolManifest(name="httpx", category="recon", network_effect="connects-out")) == []


def test_known_offense_binary_cannot_escape_exclusion_by_relabeling():
    """Red-pen FINDING-3 backstop: relabeling a known offense binary's category cannot escape exclusion."""
    # sqlmap mislabeled as recon + not excluded → still caught by the NAME backstop
    errs = validate_manifest(ToolManifest(name="sqlmap", category="recon", excluded=False))
    assert any("known offense" in e for e in errs)
    for name in ("metasploit", "hydra", "responder", "hashcat"):
        assert validate_manifest(ToolManifest(name=name, category="recon", excluded=False))
    # correctly excluded → clean
    assert validate_manifest(ToolManifest(name="sqlmap", category="exploitation", excluded=True)) == []


# --- S8: the evidence-branch registry validator (the SAME ladder, validated sovereign-side) -----------

from vigil_integration.live.tool_manifest import (  # noqa: E402
    load_branch_registry,
    validate_branch_registry,
    validate_branch_row,
)

_BRANCHES = Path(__file__).resolve().parents[2] / "docs" / "capability-matrix" / "evidence-branches.json"


def test_committed_evidence_branch_registry_passes_the_s8_column_validator():
    """The shipped evidence-branch ladder is sound under the S8-column invariants (fact_capable ⇒
    oracle_version, LEAD-only ⇒ none, control_requirements a non-empty list of non-empty strings). Runs in
    the sovereign leg: tool_manifest is pure data + validation, no framework import."""
    rows = load_branch_registry(_BRANCHES)
    assert rows, "the evidence-branch registry is empty"
    errs = validate_branch_registry(rows)
    assert not errs, "evidence-branch S8-column violations:\n  " + "\n  ".join(errs)


def test_branch_validator_rejects_the_new_column_overclaims():
    ok_fact = {"id": "x.fact", "fact_capable": True, "oracle_version": "service_reachability",
               "control_requirements": ["warden_scope_gate"]}
    ok_lead = {"id": "x.lead", "fact_capable": False, "oracle_version": "",
               "control_requirements": ["missing_redrive"]}
    assert validate_branch_row(ok_fact) == []
    assert validate_branch_row(ok_lead) == []
    # fact_capable without a named oracle version
    assert validate_branch_row({**ok_fact, "oracle_version": ""})
    # a LEAD-only branch may not borrow an oracle version it does not mint under
    assert validate_branch_row({**ok_lead, "oracle_version": "tls_weakness"})
    # a branch that depends on no control at all
    assert validate_branch_row({**ok_fact, "control_requirements": []})
    # a mistyped control_requirements (not a list)
    assert validate_branch_row({**ok_fact, "control_requirements": "warden_scope_gate"})


def test_the_strix_candidate_families_are_lead_only_in_the_committed_registry():
    """A Strix producer report is a LEAD, never a FACT, until VIGIL re-drives it (operator decision 2). The
    seven candidate families ship fact_capable=false with a non-empty oracle_version forbidden."""
    strix = {"strix.dom_execution", "strix.auth_outcome", "strix.source_to_sink",
             "strix.service_reachability", "strix.tls_negotiation",
             "strix.cloud_credential_confirmation", "strix.misconfiguration_artifact"}
    by = {b["id"]: b for b in load_branch_registry(_BRANCHES)}
    assert strix <= set(by), f"missing Strix families: {sorted(strix - set(by))}"
    for bid in sorted(strix):
        b = by[bid]
        assert b["fact_capable"] is False, f"{bid}: must be LEAD-only"
        assert b.get("oracle_version", "") == "", f"{bid}: LEAD-only branch must name no oracle_version"
        assert validate_branch_row(b) == [], f"{bid}: fails the S8-column validator"
