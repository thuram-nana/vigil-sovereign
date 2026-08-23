"""Proving test for W13-9 (#502): the reviewer readiness package is a VERIFIABLE ASSURANCE
ARCHITECTURE — script-assembled from committed sources, evidence-bound, and never a certification.

This rides the already-required ``the briefing explains every agent and capability`` job
(``pytest docs/tests -q``), which installs only pytest. It therefore imports nothing beyond the
standard library plus the assembler module under test — which is itself stdlib-only — loaded by path.

What it pins (the four-part bar):
- BEHAVIOUR: ``build_package()`` assembles the package from the committed sources and passes its gates.
- FAILS-WITHOUT-FIX: without ``tools/reviewer-package/assemble.py`` this file errors at collection;
  with the module but no ``W13-9`` registry entry, ``build_package`` raises ``EvidenceMissing``.
- NEGATIVE CONTROLS (same run): removing a proving test makes the FULL build fail; inserting
  certification wording trips the wording gate; a missing required input fails the build.
- REQUIRED CI + REGISTRY: runs in the required briefing job; the ``W13-9`` claim is in the registry.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_ASSEMBLER = _REPO / "tools" / "reviewer-package" / "assemble.py"
_REGISTRY = _REPO / "docs" / "claims" / "registry.json"


def _load_assembler():
    assert _ASSEMBLER.is_file(), "the reviewer-package assembler must exist"
    spec = importlib.util.spec_from_file_location("vigil_reviewer_assemble", _ASSEMBLER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses need the module registered before exec
    spec.loader.exec_module(mod)
    return mod


asm = _load_assembler()


# --------------------------------------------------------------------------------------------------
# BEHAVIOUR — the package assembles from committed sources.
# --------------------------------------------------------------------------------------------------
def test_build_package_assembles_from_committed_sources():
    pkg = asm.build_package(_REPO)
    assert isinstance(pkg, str) and pkg.strip()
    # It is presented as a verifiable assurance architecture, and says how it was produced.
    assert "verifiable assurance architecture" in pkg.lower()
    assert "assembled by a script" in pkg.lower()
    assert "Source content digest" in pkg
    # It embeds the actual committed source documents (not a hand-built summary).
    for needle in ("PRIVACY.md", "SECURITY.md", "DATA-GROUND-TRUTH.md",
                   "crypto-shred", "coordinated disclosure"):
        assert needle in pkg, f"assembled package is missing embedded source content: {needle!r}"
    # The evidence table is present with the required CI job column.
    assert "Assurance statements and their evidence" in pkg
    assert "the briefing explains every agent and capability" in pkg
    # The derived artifact must NOT reintroduce canonical `<!-- CLAIM:id -->` markers (embedded source
    # copies are neutralised), or it would collide with the claims-registry bijection guard.
    import re as _re
    assert not _re.search(r"<!--\s*CLAIM:[A-Za-z0-9]", pkg), \
        "the reviewer package must not carry canonical claim markers copied from embedded sources"
    assert "claim-anchor:W14-3" in pkg, "embedded source markers should survive as inert anchors"


def test_assembler_is_stdlib_only():
    """The assembler must import nothing beyond the stdlib, so it runs in the briefing job."""
    tree = ast.parse(_ASSEMBLER.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    allowed = {
        "argparse", "ast", "hashlib", "json", "re", "sys", "pathlib", "dataclasses",
        "__future__", "typing",
    }
    assert roots <= allowed, f"assembler imports beyond the stdlib allowlist: {sorted(roots - allowed)}"


# --------------------------------------------------------------------------------------------------
# EVERY CLAIM RESOLVES to a registry entry with a passing (existing, required-CI) test.
# --------------------------------------------------------------------------------------------------
def test_every_assurance_claim_resolves_to_a_passing_registry_test():
    registry = asm.load_registry(_REPO)
    registered = {c["id"] for c in registry["claims"]}
    for cid, so_what in asm.ASSURANCE_CLAIMS:
        assert cid in registered, f"{cid}: assurance claim not in the claims registry"
        assert so_what.strip(), f"{cid}: assurance claim has no reviewer-facing meaning"
        ev = asm.resolve_claim(cid, registry, _REPO)          # raises EvidenceMissing if unbacked
        # the enforcing symbol and every proving test really exist, and the CI job is required
        assert asm.symbol_defined(_REPO, ev.enforced_file, ev.enforced_symbol)
        for t in ev.proved_tests:
            assert asm.test_function_defined(_REPO, ev.proved_file, t)
        assert ev.ci_job in asm.required_check_names(_REPO)
    # W13-9 (this very claim) is one of them: the package makes an evidence-bound claim about itself.
    assert "W13-9" in dict(asm.ASSURANCE_CLAIMS)


# --------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL 1 — removing a proving test makes the FULL package build FAIL.
# A self-contained scratch repo is assembled against, then the proving test function is removed.
# --------------------------------------------------------------------------------------------------
def _write_scratch_repo(root: Path) -> Path:
    (root / ".github").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "required-status-checks.txt").write_text(
        "# scratch\nscratch required job\n", encoding="utf-8")
    (root / "code.py").write_text("def scratch_enforcer():\n    return True\n", encoding="utf-8")
    testfile = root / "test_scratch_proof.py"
    testfile.write_text("def test_scratch_proof():\n    assert True\n", encoding="utf-8")
    (root / "DOC.md").write_text("# Scratch doc\n\nNo banned wording here at all.\n", encoding="utf-8")
    (root / "docs" / "claims").mkdir(parents=True, exist_ok=True)
    registry = {
        "registry_version": 1,
        "failure_classes": {"n-a": "straightforward"},
        "claims": [{
            "id": "SCRATCH",
            "title": "scratch claim",
            "claim": "scratch",
            "source": "DOC.md:1",
            "enforced_by": {"file": "code.py", "symbol": "scratch_enforcer"},
            "proved_by": {"file": "test_scratch_proof.py", "tests": ["test_scratch_proof"]},
            "ci_job": "scratch required job",
            "failure_class": "n-a",
            "default": "on",
        }],
    }
    (root / "docs" / "claims" / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
    return testfile


def test_removing_a_proving_test_makes_the_build_fail(tmp_path, monkeypatch):
    testfile = _write_scratch_repo(tmp_path)
    monkeypatch.setattr(asm, "ASSURANCE_CLAIMS", [("SCRATCH", "the scratch so-what")])
    monkeypatch.setattr(asm, "input_manifest",
                        lambda: [asm.InputSource("doc", "Scratch doc", ["DOC.md"])])

    # With the proving test present, the package builds.
    built = asm.build_package(tmp_path)
    assert "Scratch doc" in built

    # Remove the proving test function -> the build must FAIL (pack cannot outlive its evidence).
    testfile.write_text("def something_else():\n    pass\n", encoding="utf-8")
    with pytest.raises(asm.EvidenceMissing):
        asm.build_package(tmp_path)


def test_resolve_claim_rejects_an_unregistered_claim():
    registry = asm.load_registry(_REPO)
    with pytest.raises(asm.EvidenceMissing):
        asm.resolve_claim("NO-SUCH-CLAIM-zzz", registry, _REPO)


# --------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL 2 — no wording asserts certification; inserting it trips the gate.
# --------------------------------------------------------------------------------------------------
def test_no_wording_asserts_a_compliance_accreditation():
    pkg = asm.build_package(_REPO)
    hits = asm.certification_wording_hits(pkg)
    assert not hits, f"the reviewer package asserts certification: {hits}"
    # ...and it explicitly frames itself as NOT a certification, using compliance vocabulary.
    low = pkg.lower()
    assert "not" in low and ("accreditation" in low and "attestation" in low)


def test_inserting_forbidden_wording_fails_the_gate():
    # The gate rejects the certify/certification family...
    for bad in ("we are ISO 27001 certified",
                "this constitutes a certification",
                "the tool certifies compliance",
                "an independent body will certify us"):
        with pytest.raises(asm.CertificationWordingError):
            asm.assert_no_certification_wording(bad)
    # ...but must NOT trip on the legitimate cryptographic word "certificate".
    asm.assert_no_certification_wording("a signed evidence certificate and its certificates verify offline")
    # And the real package output passes the gate.
    asm.assert_no_certification_wording(asm.build_package(_REPO))


# --------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL 3 — pending inputs are flagged, never fabricated; missing required input fails.
# --------------------------------------------------------------------------------------------------
def test_pending_inputs_are_flagged_not_fabricated():
    inputs = asm.resolve_inputs(_REPO)
    by_key = {s.key: s for s in inputs}
    # EXPORT.md (#504 counsel) and the three client instruments (#500 VSCP) are declared pending
    # while their files are absent from the tree.
    assert not (_REPO / "EXPORT.md").is_file(), "test assumes EXPORT.md is still a pending dep input"
    assert by_key["export"].status == "pending" and by_key["export"].pending_issue == "#504"
    assert by_key["client-instruments"].status == "pending"
    assert by_key["client-instruments"].pending_issue == "#500"
    # The three client instruments are exactly three declared files.
    assert len(by_key["client-instruments"].paths) == 3

    pkg = asm.build_package(_REPO)
    assert "PENDING" in pkg
    assert "#504" in pkg and "#500" in pkg
    # Nothing legal/client-facing is fabricated: no invented export-control classification text.
    assert "EXPORT.md" in pkg  # named as pending, not embedded as content


def test_a_missing_required_input_fails_the_build(tmp_path, monkeypatch):
    # A required input whose file is absent must fail the build (not silently drop the section).
    monkeypatch.setattr(asm, "input_manifest",
                        lambda: [asm.InputSource("gone", "A required file that is absent",
                                                 ["DOES-NOT-EXIST.md"], required=True)])
    with pytest.raises(asm.MissingRequiredInput):
        asm.resolve_inputs(tmp_path)


# --------------------------------------------------------------------------------------------------
# REGISTRY — the W13-9 claim is registered and wired to THIS test in a required job.
# --------------------------------------------------------------------------------------------------
def test_w13_9_is_registered_against_this_test_in_a_required_job():
    entry = next((c for c in json.loads(_REGISTRY.read_text(encoding="utf-8"))["claims"]
                  if c["id"] == "W13-9"), None)
    assert entry is not None, "W13-9 must be registered in docs/claims/registry.json"
    assert entry["enforced_by"] == {"file": "tools/reviewer-package/assemble.py", "symbol": "build_package"}
    assert entry["proved_by"]["file"] == "docs/tests/test_w13_9_reviewer_package.py"
    assert "test_removing_a_proving_test_makes_the_build_fail" in entry["proved_by"]["tests"]
    assert entry["ci_job"] in asm.required_check_names(_REPO)
