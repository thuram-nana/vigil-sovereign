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
