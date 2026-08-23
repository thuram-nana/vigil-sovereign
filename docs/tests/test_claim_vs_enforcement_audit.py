"""The claim-vs-enforcement audit is machine-checked: every audited enforcement-flavoured claim carries
a verdict and a deciding code reference that resolves, every FALSE or SCOPED verdict is pinned by a
claims-registry entry, and all eight named surfaces are represented — or the build goes red (W15-3 #395).

WHY THIS TEST EXISTS. #395 (W15-3) asked, of every enforcement-flavoured claim on the buyer- and
reviewer-facing surfaces (README, AS-BUILT, POSTURE, CONTRIBUTING, SUPPLY-CHAIN, the in-app Manual, the
served remediation ladder, and the in-app authorization/legal text), whether it is TRUE of the code — and
demanded that no FALSE self-verifiable claim be left un-flagged, because a self-verifiable false claim is
the cheapest way for an evaluator to discredit the project. `docs/audit/claim-audit.json` is the manifest
of that audit; `docs/claim-audit.md` is its human rendering. This guard makes the manifest answer to the
code:

  * every entry names a verdict in {TRUE, SCOPED, FALSE, UNVERIFIABLE} and a surface in the eight the AC
    names;
  * the claim text is really present in the source file it cites (so a manifest cannot classify a claim
    that has silently left the docs) and the cited source line is real;
  * the deciding code_ref file exists, and a named `.py` symbol really resolves by AST (no import) — so a
    verdict cannot cite code that is not there;
  * EVERY FALSE or SCOPED verdict names a claims-registry entry that EXISTS in docs/claims/registry.json —
    the pin the AC requires, so a conditional or false-and-tracked claim can never sit un-pinned;
  * all eight surfaces are represented, and the human doc mentions every entry id WITH its verdict, so the
    rendering cannot silently drop or mis-state a row.

A single `validate_audit_entry` validator is exercised by BOTH the real manifest AND deliberately-broken
negative controls in the same run, so the gate is provably not a no-op.

STDLIB ONLY. Runs in the required `the briefing explains every agent and capability` CI job (pytest only):
`json` + `ast` + `pathlib` + `re`, imports neither trust domain, runs no tool — the same discipline as
`test_claims_registry.py`, which is why the manifest is JSON.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "docs" / "audit" / "claim-audit.json"
HUMAN_DOC = REPO / "docs" / "claim-audit.md"
REGISTRY = REPO / "docs" / "claims" / "registry.json"

VERDICTS = {"TRUE", "SCOPED", "FALSE", "UNVERIFIABLE"}
SURFACES = {"README", "AS-BUILT", "POSTURE", "CONTRIBUTING", "SUPPLY-CHAIN", "MANUAL", "LADDER", "LEGAL"}
# The two categories the AC requires be pinned by a claims-registry entry.
MUST_BE_PINNED = {"FALSE", "SCOPED"}
REQUIRED_FIELDS = ("id", "surface", "source", "claim", "verdict", "code_ref", "registry", "rationale")


# --------------------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------------------
def _load() -> dict:
    assert MANIFEST.is_file(), f"claim-audit manifest missing: {MANIFEST}"
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert isinstance(data.get("claims"), list) and data["claims"], "manifest has no claims"
    return data


def _claims() -> list[dict]:
    return _load()["claims"]


def _registry_ids() -> set[str]:
    if not REGISTRY.is_file():
        return set()
    reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return {c["id"] for c in reg.get("claims", [])}


def _collapsed(text: str) -> str:
    return re.sub(r"\s+", " ", text)


# --------------------------------------------------------------------------------------------------
# AST symbol resolution — no import, so a heavy/framework module never loads in this docs-only job.
# --------------------------------------------------------------------------------------------------
def _find_symbol(body: list, parts: list[str]) -> bool:
    head, rest = parts[0], parts[1:]
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == head:
            if not rest:
                return True
            return isinstance(node, ast.ClassDef) and _find_symbol(node.body, rest)
        if not rest and isinstance(node, ast.Assign):
            for tgt in node.targets:
                names = [tgt] if isinstance(tgt, ast.Name) else (
                    list(tgt.elts) if isinstance(tgt, (ast.Tuple, ast.List)) else [])
                if any(isinstance(n, ast.Name) and n.id == head for n in names):
                    return True
        if (not rest and isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name) and node.target.id == head):
            return True
    return False


def symbol_defined(file_path: str, dotted: str) -> bool:
    p = REPO / file_path
    if not p.is_file():
        return False
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError:
        return False
    return _find_symbol(tree.body, dotted.split("."))


def claim_text_present(file_path: str, claim: str) -> bool:
    p = REPO / file_path
    return p.is_file() and _collapsed(claim) in _collapsed(p.read_text(encoding="utf-8"))


def line_in_range(file_path: str, line: int) -> bool:
    p = REPO / file_path
    if not p.is_file():
        return False
    n = len(p.read_text(encoding="utf-8").splitlines())
    return 1 <= line <= n


# --------------------------------------------------------------------------------------------------
# The per-entry validator. Real manifest and negative controls both run through THIS one function.
# --------------------------------------------------------------------------------------------------
def validate_audit_entry(entry: dict, registry_ids: set[str]) -> list[str]:
    errs: list[str] = []
    for f in REQUIRED_FIELDS:
        if f not in entry:
            errs.append(f"missing field {f!r}")
    if errs:
        return errs
    cid = entry["id"]

    if entry["verdict"] not in VERDICTS:
        errs.append(f"{cid}: verdict {entry['verdict']!r} not in {sorted(VERDICTS)}")
    if entry["surface"] not in SURFACES:
        errs.append(f"{cid}: surface {entry['surface']!r} not in {sorted(SURFACES)}")

    # source = path:line — the source file must exist, the line must be real, and the claim text must
    # actually be present in that file (so a manifest cannot classify a claim that is not in the docs).
    src_file, _, src_line = entry["source"].partition(":")
    if not src_line.isdigit() or not line_in_range(src_file, int(src_line)):
        errs.append(f"{cid}: source {entry['source']!r} is not a real path:line")
    if not claim_text_present(src_file, entry["claim"]):
        errs.append(f"{cid}: claim text not found in source {src_file}")

    # code_ref = the deciding code. Its file must exist (unless explicitly n-a for UNVERIFIABLE), and a
    # named .py symbol must resolve by AST — so a verdict cannot cite code that is not there.
    cr = entry["code_ref"]
    if not isinstance(cr, dict) or "file" not in cr:
        errs.append(f"{cid}: code_ref must be an object with a file")
    else:
        f = cr["file"]
        if f != "n-a":
            if not (REPO / f).is_file():
                errs.append(f"{cid}: code_ref file missing: {f}")
            sym = cr.get("symbol")
            if sym and f.endswith(".py") and not symbol_defined(f, sym):
                errs.append(f"{cid}: code_ref symbol {sym!r} not defined in {f}")
        elif entry["verdict"] != "UNVERIFIABLE":
            errs.append(f"{cid}: code_ref 'n-a' is only allowed for an UNVERIFIABLE verdict "
                        f"(verdict is {entry['verdict']!r}) — a checkable verdict must cite deciding code")

    # THE PIN. Every FALSE or SCOPED verdict must name a claims-registry entry that EXISTS. This is the
    # AC's core honesty gate: no conditional or false-and-tracked claim may sit un-pinned.
    if entry["verdict"] in MUST_BE_PINNED:
        reg = entry.get("registry")
        if not reg or reg == "n-a":
            errs.append(f"{cid}: a {entry['verdict']} verdict must name a claims-registry entry (got {reg!r})")
        elif reg not in registry_ids:
            errs.append(f"{cid}: registry entry {reg!r} is not present in docs/claims/registry.json")
    return errs


# ==================================================================================================
# The real manifest
# ==================================================================================================
def test_manifest_parses_and_every_entry_has_the_full_schema():
    ids = [c.get("id") for c in _claims()]
    assert len(ids) == len(set(ids)), f"duplicate audit ids: {ids}"
    for c in _claims():
        for f in REQUIRED_FIELDS:
            assert f in c, f"{c.get('id')}: missing {f}"


def test_every_audit_entry_is_valid():
    """The whole validator, over the whole manifest — the single assertion the AC turns on."""
    reg = _registry_ids()
    problems = {c["id"]: validate_audit_entry(c, reg) for c in _claims()}
    bad = {k: v for k, v in problems.items() if v}
    assert not bad, "audit entries with problems:\n" + json.dumps(bad, indent=2)


def test_every_false_or_scoped_verdict_is_pinned_by_a_registry_entry():
    reg = _registry_ids()
    for c in _claims():
        if c["verdict"] in MUST_BE_PINNED:
            r = c.get("registry")
            assert r and r != "n-a" and r in reg, \
                f"{c['id']}: {c['verdict']} verdict not pinned by an existing registry entry (registry={r!r})"


def test_all_eight_named_surfaces_are_represented():
    seen = {c["surface"] for c in _claims()}
    missing = SURFACES - seen
    assert not missing, f"the audit does not cover surface(s): {sorted(missing)}"


def test_no_false_self_verifiable_claim_is_left_unflagged():
    """The AC's headline invariant. A FALSE verdict is only acceptable if it is pinned (registry) AND has a
    rationale — never silently present. (After the W15-3 fixes the live manifest carries no FALSE rows; this
    guard keeps it impossible to ADD an un-flagged one.)"""
    reg = _registry_ids()
    for c in _claims():
        if c["verdict"] == "FALSE":
            assert c.get("registry") in reg, f"{c['id']}: FALSE claim not pinned by a registry/tracking entry"
            assert c.get("rationale", "").strip(), f"{c['id']}: FALSE claim carries no rationale"


def test_registered_in_claims_registry():
    assert "W15-3" in _registry_ids(), \
        "claim W15-3 (the audit-completeness claim) is not registered in docs/claims/registry.json"


def test_human_doc_carries_the_marker_and_mentions_every_row_with_its_verdict():
    assert HUMAN_DOC.is_file(), f"human audit doc missing: {HUMAN_DOC}"
    text = HUMAN_DOC.read_text(encoding="utf-8")
    assert re.search(r"<!--\s*CLAIM:W15-3\s*-->", text), "docs/claim-audit.md must carry the W15-3 CLAIM marker"
    lines = text.splitlines()
    for c in _claims():
        # some PHYSICAL line of the human table must carry the id AND its verdict together, so the human
        # rendering can neither silently omit a row nor mis-state its verdict.
        assert any(c["id"] in ln and c["verdict"] in ln for ln in lines), \
            f"{c['id']}: no line in docs/claim-audit.md carries it with verdict {c['verdict']}"


# ==================================================================================================
# Negative controls — a deliberately bad entry is REJECTED, in the same run. Proves the gate is not a
# no-op. Each mutates a real, valid entry so only the one broken facet is under test.
# ==================================================================================================
def _a_valid_entry() -> dict:
    reg = _registry_ids()
    entry = next(c for c in _claims() if not validate_audit_entry(c, reg))
    return json.loads(json.dumps(entry))  # deep copy


def test_negative_control_bad_verdict_is_rejected():
    reg = _registry_ids()
    e = _a_valid_entry()
    e["verdict"] = "PROBABLY_FINE"
    assert any("verdict" in x for x in validate_audit_entry(e, reg))


def test_negative_control_false_without_registry_is_rejected():
    """The AC's core mechanism: a FALSE (or SCOPED) verdict with no registry pin must be refused."""
    reg = _registry_ids()
    e = _a_valid_entry()
    e["verdict"] = "FALSE"
    e["registry"] = "n-a"
    errs = validate_audit_entry(e, reg)
    assert any("must name a claims-registry entry" in x for x in errs), errs


def test_negative_control_scoped_with_nonexistent_registry_is_rejected():
    reg = _registry_ids()
    e = _a_valid_entry()
    e["verdict"] = "SCOPED"
    e["registry"] = "W-DOES-NOT-EXIST-zzz"
    errs = validate_audit_entry(e, reg)
    assert any("not present in docs/claims/registry.json" in x for x in errs), errs


def test_negative_control_code_ref_to_missing_file_is_rejected():
    reg = _registry_ids()
    e = _a_valid_entry()
    e["code_ref"] = {"file": "integration/vigil_integration/this_file_does_not_exist_zzz.py"}
    errs = validate_audit_entry(e, reg)
    assert any("code_ref file missing" in x for x in errs), errs


def test_negative_control_code_ref_symbol_that_is_absent_is_rejected():
    reg = _registry_ids()
    e = _a_valid_entry()
    e["code_ref"] = {"file": "integration/vigil_integration/conjunctive_gate.py", "symbol": "NoSuchSymbol_zzz"}
    errs = validate_audit_entry(e, reg)
    assert any("code_ref symbol" in x for x in errs), errs


def test_negative_control_absent_claim_text_is_rejected():
    reg = _registry_ids()
    e = _a_valid_entry()
    e["claim"] = "this exact sentence appears in no source surface anywhere zzz"
    errs = validate_audit_entry(e, reg)
    assert any("claim text not found" in x for x in errs), errs


def test_negative_control_nonverifiable_code_na_on_a_checkable_verdict_is_rejected():
    """A TRUE/SCOPED/FALSE verdict may not hide behind code_ref 'n-a' — only UNVERIFIABLE may."""
    reg = _registry_ids()
    e = _a_valid_entry()
    e["verdict"] = "TRUE"
    e["code_ref"] = {"file": "n-a"}
    errs = validate_audit_entry(e, reg)
    assert any("only allowed for an UNVERIFIABLE" in x for x in errs), errs


if __name__ == "__main__":  # pragma: no cover
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
