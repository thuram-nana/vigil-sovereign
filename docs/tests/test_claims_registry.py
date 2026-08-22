"""The claims registry is machine-checked: every product claim resolves to a real enforcing symbol
and a real proving test, or the build goes red (W0-3 #398).

WHY THIS TEST EXISTS. The W0 credibility programme keeps finding claims the code does not actually
enforce. `docs/decisions/W5-1-...md`'s own model, `test_fix_ladder_matches_the_gate.py`, pins ONE
claim to ONE gate. This generalises it: `docs/claims/registry.json` maps EVERY registered claim to
the code symbol that enforces it and the test that proves it, and this guard fails the build when:

  * a registered claim names a symbol that is not defined in the file it cites (the claim has no code);
  * a registered claim names a proving test that does not exist — so DELETING the proving test for any
    registered claim turns CI red (the registry is not advisory);
  * the claim text is not present at the file:line the registry records (silent doc drift);
  * a `<!-- CLAIM:<id> -->` marker exists in the docs with no registry entry (a doc claim with no
    backing), or a registry entry's marker is missing from its source;
  * the proving test does not run in a REQUIRED CI job.

It also addresses, as first-class schema, the three drift classes the W0 plan names: (1) a claim about
configuration stated as a claim about code, (2) enforcement that ships opt-in but is documented as a
default, (3) a display bug that manufactures evidence. Each is a `failure_class` value, and one test
asserts each class is exercised by at least one claim.

STDLIB ONLY. The required `the briefing explains every agent and capability` CI job (which runs
`pytest docs/tests -q`) installs only pytest, so this guard parses the registry with `json`, resolves
symbols with `ast`, and reads files with `pathlib` — it imports NEITHER trust domain and runs no tool.
That is also why the registry is JSON, not YAML: PyYAML is not on that job's path.
"""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "docs" / "claims" / "registry.json"
CI_YAML = REPO / ".github" / "workflows" / "ci.yml"
REQUIRED_CHECKS = REPO / ".github" / "required-status-checks.txt"

REQUIRED_FIELDS = ("id", "title", "claim", "source", "enforced_by", "proved_by", "ci_job",
                   "failure_class", "default")
DEFAULT_VALUES = {"on", "off", "n-a"}
FAILURE_CLASSES = {"config-stated-as-code", "opt-in-stated-as-default",
                   "display-manufactures-evidence", "n-a"}
# The three DRIFT classes (the AC's "three failure-mode classes"), each of which must be exercised.
DRIFT_CLASSES = FAILURE_CLASSES - {"n-a"}

# Marker token that anchors a claim in a doc. Strict HTML-comment form so ordinary prose that merely
# mentions a claim id never registers as a marker.
_MARKER = re.compile(r"<!--\s*CLAIM:([A-Za-z0-9][A-Za-z0-9._-]*)\s*-->")

# The docs tree is scanned for markers, EXCEPT vendored trees and this registry's own meta-directory
# (whose README documents the convention and legitimately shows example markers).
_SCAN_EXCLUDE_DIRS = ("vendor", "node_modules", ".git")
_SCAN_EXCLUDE_PREFIX = (str(Path("docs") / "claims"),)


# --------------------------------------------------------------------------------------------------
# Registry loading
# --------------------------------------------------------------------------------------------------
def _load() -> dict:
    assert REGISTRY.is_file(), f"claims registry missing: {REGISTRY}"
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    assert isinstance(data.get("claims"), list) and data["claims"], "registry has no claims"
    return data


def _claims() -> list[dict]:
    return _load()["claims"]


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
            # Only a class can carry a further attribute (Class.method); a function cannot.
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
    """True IFF `dotted` (e.g. ``SpineStore.append`` or ``_REMEDIATION_LADDER``) is defined at the
    top level of `file_path` (descending only through classes). Pure AST, no import."""
    p = REPO / file_path
    if not p.is_file():
        return False
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError:
        return False
    return _find_symbol(tree.body, dotted.split("."))


def proving_test_defined(file_path: str, name: str) -> bool:
    p = REPO / file_path
    if not p.is_file():
        return False
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return True
    return False


def claim_text_present(file_path: str, claim: str) -> bool:
    p = REPO / file_path
    return p.is_file() and _collapsed(claim) in _collapsed(p.read_text(encoding="utf-8"))


def marker_at_line(file_path: str, claim_id: str, line: int) -> bool:
    p = REPO / file_path
    if not p.is_file():
        return False
    lines = p.read_text(encoding="utf-8").splitlines()
    if not (1 <= line <= len(lines)):
        return False
    m = _MARKER.search(lines[line - 1])
    return bool(m) and m.group(1) == claim_id


# --------------------------------------------------------------------------------------------------
# CI coverage — the proving test must run in a REQUIRED job that actually collects it.
# --------------------------------------------------------------------------------------------------
def required_job_names() -> set[str]:
    out = set()
    for raw in REQUIRED_CHECKS.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            out.add(s)
    return out


def _job_block(ci_job: str) -> str | None:
    lines = CI_YAML.read_text(encoding="utf-8").splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == f"name: {ci_job}"), None)
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end])


def _dir_slices(file_path: str) -> list[str]:
    """Contiguous >=2-component slices of the file's directory, so a job that `cd`s into a subtree
    (e.g. CRUCIBLE core runs `pytest framework/v2` from engine/crucible) is still matched."""
    parts = os.path.dirname(file_path).split("/")
    slices = []
    for i in range(len(parts)):
        for j in range(i + 2, len(parts) + 1):
            slices.append("/".join(parts[i:j]))
    return slices


def ci_collects(block: str, file_path: str) -> bool:
    lines = block.splitlines()
    non_ignore = [l for l in lines if "--ignore=" not in l]
    base = os.path.basename(file_path)
    ignored = any(
        os.path.basename(l.split("--ignore=", 1)[1].strip().rstrip(" \\")) == base
        for l in lines if "--ignore=" in l)
    explicit = any(file_path in l for l in non_ignore)              # offense-leg explicit list / direct arg
    dir_cov = any(tok in l for l in non_ignore for tok in _dir_slices(file_path))
    return explicit or (dir_cov and not ignored)


# --------------------------------------------------------------------------------------------------
# The per-entry validator. Returns a list of human-readable errors; empty == valid. Both the real
# tests and the negative controls run through THIS one function, so the negatives prove the very code
# the positives rely on actually rejects bad input.
# --------------------------------------------------------------------------------------------------
def validate_claim(entry: dict) -> list[str]:
    errs: list[str] = []
    for f in REQUIRED_FIELDS:
        if f not in entry:
            errs.append(f"missing field {f!r}")
    if errs:
        return errs
    cid = entry["id"]
    if entry["default"] not in DEFAULT_VALUES:
        errs.append(f"{cid}: default {entry['default']!r} not in {sorted(DEFAULT_VALUES)}")
    if entry["failure_class"] not in FAILURE_CLASSES:
        errs.append(f"{cid}: failure_class {entry['failure_class']!r} invalid")

    eb = entry["enforced_by"]
    if not symbol_defined(eb["file"], eb["symbol"]):
        errs.append(f"{cid}: enforcing symbol {eb['symbol']!r} not defined in {eb['file']}")

    pb = entry["proved_by"]
    if not (REPO / pb["file"]).is_file():
        errs.append(f"{cid}: proving-test file missing: {pb['file']}")
    else:
        for t in pb["tests"]:
            if not proving_test_defined(pb["file"], t):
                errs.append(f"{cid}: proving test {t!r} not found in {pb['file']} "
                            "(deleting/renaming a proving test must turn CI red)")

    src_file, _, src_line = entry["source"].partition(":")
    if not claim_text_present(src_file, entry["claim"]):
        errs.append(f"{cid}: claim text not found in {src_file}")
    if not src_line.isdigit() or not marker_at_line(src_file, cid, int(src_line)):
        errs.append(f"{cid}: marker <!-- CLAIM:{cid} --> not at {entry['source']}")

    if entry["ci_job"] not in required_job_names():
        errs.append(f"{cid}: ci_job {entry['ci_job']!r} is not a REQUIRED check")
    else:
        block = _job_block(entry["ci_job"])
        if block is None:
            errs.append(f"{cid}: ci_job {entry['ci_job']!r} has no matching job in ci.yml")
        elif not ci_collects(block, pb["file"]):
            errs.append(f"{cid}: {pb['file']} is not collected by required job {entry['ci_job']!r}")
    return errs


# --------------------------------------------------------------------------------------------------
# Positive tests — the seeded registry is fully backed.
# --------------------------------------------------------------------------------------------------
def test_registry_parses_and_every_entry_has_the_full_schema():
    ids = [c.get("id") for c in _claims()]
    assert len(ids) == len(set(ids)), f"duplicate claim ids: {ids}"
    for c in _claims():
        for f in REQUIRED_FIELDS:
            assert f in c, f"{c.get('id')}: missing {f}"
        assert c["default"] in DEFAULT_VALUES
        assert c["failure_class"] in FAILURE_CLASSES
        assert set(c["enforced_by"]) >= {"file", "symbol"}
        assert set(c["proved_by"]) >= {"file", "tests"} and c["proved_by"]["tests"]


def test_every_registered_claim_resolves_to_a_real_symbol():
    for c in _claims():
        eb = c["enforced_by"]
        assert symbol_defined(eb["file"], eb["symbol"]), \
            f"{c['id']}: {eb['symbol']} not defined in {eb['file']}"


def test_every_registered_claim_has_a_real_proving_test():
    for c in _claims():
        pb = c["proved_by"]
        assert (REPO / pb["file"]).is_file(), f"{c['id']}: {pb['file']} missing"
        for t in pb["tests"]:
            assert proving_test_defined(pb["file"], t), \
                f"{c['id']}: proving test {t} missing from {pb['file']}"


def test_every_claim_text_is_present_at_its_recorded_source_line():
    for c in _claims():
        src_file, _, src_line = c["source"].partition(":")
        assert claim_text_present(src_file, c["claim"]), f"{c['id']}: claim text drifted in {src_file}"
        assert src_line.isdigit() and marker_at_line(src_file, c["id"], int(src_line)), \
            f"{c['id']}: marker not at {c['source']}"


def test_every_registered_claim_is_fully_valid():
    """The whole validator, over the whole registry — the single assertion the AC turns on."""
    problems = {c["id"]: validate_claim(c) for c in _claims()}
    bad = {k: v for k, v in problems.items() if v}
    assert not bad, f"registered claims with no backing: {json.dumps(bad, indent=2)}"


def test_every_proving_test_runs_in_a_required_ci_job():
    req = required_job_names()
    for c in _claims():
        assert c["ci_job"] in req, f"{c['id']}: {c['ci_job']!r} not a required check"
        block = _job_block(c["ci_job"])
        assert block is not None, f"{c['id']}: no ci.yml job named {c['ci_job']!r}"
        assert ci_collects(block, c["proved_by"]["file"]), \
            f"{c['id']}: {c['proved_by']['file']} not collected by {c['ci_job']!r}"


def test_the_three_named_failure_classes_are_each_covered():
    seen = {c["failure_class"] for c in _claims()}
    missing = DRIFT_CLASSES - seen
    assert not missing, f"no registered claim exercises drift class(es): {sorted(missing)}"


# --------------------------------------------------------------------------------------------------
# The bijection: a claim marker in the docs with no registry entry turns CI red.
# --------------------------------------------------------------------------------------------------
def _scan_doc_markers() -> dict[str, str]:
    found: dict[str, str] = {}
    for p in REPO.rglob("*.md"):
        rel = p.relative_to(REPO).as_posix()
        if any(part in _SCAN_EXCLUDE_DIRS for part in p.relative_to(REPO).parts):
            continue
        if any(rel.startswith(pref.replace(os.sep, "/")) for pref in _SCAN_EXCLUDE_PREFIX):
            continue
        for m in _MARKER.finditer(p.read_text(encoding="utf-8", errors="replace")):
            cid = m.group(1)
            assert cid not in found, f"duplicate marker CLAIM:{cid} in {rel} and {found[cid]}"
            found[cid] = rel
    return found


def test_doc_markers_and_registry_are_bijective():
    registry_ids = {c["id"] for c in _claims()}
    doc_markers = _scan_doc_markers()
    unregistered = {cid: loc for cid, loc in doc_markers.items() if cid not in registry_ids}
    assert not unregistered, f"doc claim markers with no registry entry: {unregistered}"
    # ...and every entry's own marker is present at its source (covered above, restated for the pair):
    for c in _claims():
        src_file, _, src_line = c["source"].partition(":")
        assert marker_at_line(src_file, c["id"], int(src_line)), f"{c['id']}: marker missing at source"


# --------------------------------------------------------------------------------------------------
# Negative controls — a deliberately bad entry/state is REJECTED, in the same run. Proves the gate is
# not a no-op. Each mutates a real, valid entry so only the one broken facet is under test.
# --------------------------------------------------------------------------------------------------
def _a_valid_entry() -> dict:
    entry = next(c for c in _claims() if not validate_claim(c))
    return json.loads(json.dumps(entry))  # deep copy


def test_negative_control_missing_symbol_is_rejected():
    e = _a_valid_entry()
    e["enforced_by"]["symbol"] = "NoSuchSymbol_zzz"
    errs = validate_claim(e)
    assert any("enforcing symbol" in x for x in errs), errs


def test_negative_control_missing_proving_test_is_rejected():
    e = _a_valid_entry()
    e["proved_by"]["tests"] = ["test_this_does_not_exist_zzz"]
    errs = validate_claim(e)
    assert any("proving test" in x for x in errs), errs


def test_negative_control_absent_claim_text_is_rejected():
    e = _a_valid_entry()
    e["claim"] = "this exact sentence appears in no source document anywhere zzz"
    errs = validate_claim(e)
    assert any("claim text not found" in x for x in errs), errs


def test_negative_control_unregistered_marker_is_rejected():
    """The bijection guard would fail if a marker existed with no registry entry — simulate the state
    the guard is meant to catch, without writing to the tree."""
    registry_ids = {c["id"] for c in _claims()}
    simulated = dict(_scan_doc_markers())
    simulated["W0-3-PHANTOM-UNREGISTERED"] = "docs/SOME-DOC.md"
    unregistered = {cid: loc for cid, loc in simulated.items() if cid not in registry_ids}
    assert "W0-3-PHANTOM-UNREGISTERED" in unregistered


def test_negative_control_non_required_ci_job_is_rejected():
    e = _a_valid_entry()
    e["ci_job"] = "a job that is not required zzz"
    errs = validate_claim(e)
    assert any("REQUIRED check" in x for x in errs), errs


def test_the_model_test_this_generalises_still_exists():
    """The registry generalises `test_fix_ladder_matches_the_gate.py`; if that model is deleted, the
    REM-LADDER claim's proof vanishes — assert the generalisation's own seed is present."""
    assert (REPO / "integration/tests/test_fix_ladder_matches_the_gate.py").is_file()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
