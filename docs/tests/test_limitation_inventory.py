"""The documented-limitation inventory is machine-checked: every real-unfinished-code limitation resolves
to a real code anchor, every re-verified-closed item names real evidence, and the honest-limit marker
convention is a bijection with the inventory (W15-1 #393, feeding the W16 burndown).

WHY THIS TEST EXISTS. The W15 intake plan is explicit: *"Do not treat W15 as complete until those three
[audits] land and their items are filed."* An inventory that is only prose rots the moment the code moves:
a stub gets implemented, an anchor is renamed, a re-verified-closed item is quietly re-opened, and the
"honest" list silently lies. This guard makes `docs/limitations/inventory.json` answer to the code:

  * every `real-unfinished-code` limitation names an anchor the guard resolves BY AST (no import), and a
    `stub-raises` item's anchored function must actually `raise NotImplementedError` — so implementing the
    stub (removing the raise) without updating the inventory turns CI red (the debt cannot be silently
    "completed" out of the honest list, nor left claiming a stub that is now real);
  * every re-verified-closed item names an evidence path that must EXIST — so deleting the closing test or
    module turns CI red (the "do not re-work these" list is not advisory);
  * the honest-limit marker convention is a BIJECTION: every `VIGIL-LIMIT:<id>` marker in a source file
    must be a registered `marker: true` item, and every `marker: true` item's token must be present in its
    anchor file. Since this repo carries no TODO comments, an honest-limit docstring is HOW debt is
    recorded; an UNREGISTERED marker (debt with no inventory entry) turns CI red.

This is the W15-1 counterpart of the claims-registry guard (`test_claims_registry.py`) and follows the
same discipline: a single `validate_limitation` validator is exercised by both the real inventory AND
deliberately-broken negative controls in the same run, so the gate is provably not a no-op.

STDLIB ONLY. This runs in the required `the briefing explains every agent and capability` CI job, which
installs only pytest. It parses the inventory with `json`, resolves anchors with `ast`, and reads files
with `pathlib` — it imports NEITHER trust domain and runs no tool.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INVENTORY = REPO / "docs" / "limitations" / "inventory.json"
CLAIMS_REGISTRY = REPO / "docs" / "claims" / "registry.json"

# Marker token that anchors an honest-limit docstring to an inventory item. Distinctive on purpose so no
# ordinary prose ("a limit on ...") ever registers as a marker.
_MARKER = re.compile(r"VIGIL-LIMIT:([A-Za-z0-9][A-Za-z0-9._-]*)")

REQUIRED_FIELDS = ("id", "title", "summary", "classification", "severity", "anchor", "marker",
                   "check", "source_doc", "disposition")
CLASSES = {"doc-only", "real-unfinished-code"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
DISPOSITIONS = {"file-into-w16", "re-verified-closed"}
CHECKS = {"stub-raises", "symbol-exists", "file-exists", "doc-exists"}

# The twelve re-verified-closed items the AC requires listed by name so nobody re-works them. Pinned here
# so the inventory cannot silently drop or renumber the census.
RVC_IDS = {
    "RVC-governance-grant-replay", "RVC-offense-backup-restore", "RVC-use-library-ui-scan",
    "RVC-crash-resume", "RVC-k8s-rbac-livefire", "RVC-console-credential-gate",
    "RVC-per-action-approval-token", "RVC-sandbox-exec-wiring", "RVC-neo4j-client-body",
    "RVC-k8s-workload-oracle-wired", "RVC-warden-strix-fail-closed", "RVC-console-orphan-routes",
}

# Directories whose sources are NOT scanned for markers (vendored trees; git internals).
_SCAN_EXCLUDE = ("vendor", "node_modules", ".git", ".venv-offense", ".venv-sovereign")


# --------------------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------------------
def _load() -> dict:
    assert INVENTORY.is_file(), f"limitation inventory missing: {INVENTORY}"
    data = json.loads(INVENTORY.read_text(encoding="utf-8"))
    assert isinstance(data.get("limitations"), list), "inventory has no limitations list"
    assert isinstance(data.get("re_verified_closed"), list), "inventory has no re_verified_closed list"
    return data


def _limitations() -> list[dict]:
    return _load()["limitations"]


# --------------------------------------------------------------------------------------------------
# AST anchor resolution — no import, so no heavy/trust-domain module loads in this docs-only job.
# --------------------------------------------------------------------------------------------------
def _find_node(body: list, parts: list[str]):
    head, rest = parts[0], parts[1:]
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == head:
            if not rest:
                return node
            if isinstance(node, ast.ClassDef):
                return _find_node(node.body, rest)
            return None
        if not rest and isinstance(node, ast.Assign):
            for tgt in node.targets:
                names = [tgt] if isinstance(tgt, ast.Name) else (
                    list(tgt.elts) if isinstance(tgt, (ast.Tuple, ast.List)) else [])
                if any(isinstance(n, ast.Name) and n.id == head for n in names):
                    return node
    return None


def _module_body(file_path: str):
    p = REPO / file_path
    if not p.is_file():
        return None
    try:
        return ast.parse(p.read_text(encoding="utf-8")).body
    except SyntaxError:
        return None


def symbol_node(file_path: str, dotted: str):
    body = _module_body(file_path)
    if body is None:
        return None
    return _find_node(body, dotted.split("."))


def raises_not_implemented(node) -> bool:
    """True IFF the function/method node contains a ``raise NotImplementedError`` in its body."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Raise) and sub.exc is not None:
            exc = sub.exc
            name = exc.func if isinstance(exc, ast.Call) else exc
            if isinstance(name, ast.Name) and name.id == "NotImplementedError":
                return True
            if isinstance(name, ast.Attribute) and name.attr == "NotImplementedError":
                return True
    return False


# --------------------------------------------------------------------------------------------------
# The per-limitation validator. Real items and negative controls both run through THIS function, so the
# negatives prove the very code the positives rely on actually rejects bad input.
# --------------------------------------------------------------------------------------------------
def validate_limitation(entry: dict) -> list[str]:
    errs: list[str] = []
    for f in REQUIRED_FIELDS:
        if f not in entry:
            errs.append(f"missing field {f!r}")
    if errs:
        return errs
    lid = entry["id"]
    if entry["classification"] not in CLASSES:
        errs.append(f"{lid}: bad classification {entry['classification']!r}")
    if entry["severity"] not in SEVERITIES:
        errs.append(f"{lid}: bad severity {entry['severity']!r}")
    if entry["disposition"] not in DISPOSITIONS:
        errs.append(f"{lid}: bad disposition {entry['disposition']!r}")
    if entry["check"] not in CHECKS:
        errs.append(f"{lid}: bad check {entry['check']!r}")
    if not isinstance(entry["marker"], bool):
        errs.append(f"{lid}: marker must be a bool")
    anchor = entry["anchor"]
    if not isinstance(anchor, dict) or "file" not in anchor:
        errs.append(f"{lid}: anchor must be an object with a file")
        return errs
    afile = anchor["file"]

    check = entry["check"]
    if check == "stub-raises":
        if entry["classification"] != "real-unfinished-code":
            errs.append(f"{lid}: a stub-raises limitation must be real-unfinished-code")
        sym = anchor.get("symbol")
        if not sym:
            errs.append(f"{lid}: stub-raises needs an anchor.symbol")
        else:
            node = symbol_node(afile, sym)
            if node is None:
                errs.append(f"{lid}: anchor symbol {sym!r} not found in {afile}")
            elif not raises_not_implemented(node):
                errs.append(f"{lid}: anchor {afile}::{sym} does not raise NotImplementedError "
                            f"(is the stub now implemented? update the inventory)")
    elif check == "symbol-exists":
        sym = anchor.get("symbol")
        if not sym:
            errs.append(f"{lid}: symbol-exists needs an anchor.symbol")
        elif symbol_node(afile, sym) is None:
            errs.append(f"{lid}: anchor symbol {sym!r} not found in {afile}")
    else:  # file-exists / doc-exists
        if not (REPO / afile).is_file():
            errs.append(f"{lid}: anchor file {afile} does not exist")

    # A file-into-w16 item may carry a filed issue number or null (pending owner-reviewed filing).
    w16 = entry.get("w16_issue", None)
    if entry["disposition"] == "file-into-w16" and not (w16 is None or isinstance(w16, int)):
        errs.append(f"{lid}: w16_issue must be an int or null")

    # A marker:true item must carry its token in the anchor file (the reverse leg of the bijection).
    if entry["marker"]:
        text = (REPO / afile).read_text(encoding="utf-8") if (REPO / afile).is_file() else ""
        if f"VIGIL-LIMIT:{lid}" not in text:
            errs.append(f"{lid}: marker:true but no `VIGIL-LIMIT:{lid}` token found in {afile}")
    return errs


def validate_rvc(entry: dict) -> list[str]:
    errs: list[str] = []
    for f in ("id", "name", "summary", "evidence"):
        if f not in entry:
            errs.append(f"missing field {f!r}")
    if errs:
        return errs
    if not (REPO / entry["evidence"]).is_file():
        errs.append(f"{entry['id']}: evidence path {entry['evidence']} does not exist "
                    f"(the closure is not re-verifiable — do not list it as closed)")
    return errs


# --------------------------------------------------------------------------------------------------
# Marker scan (the forward leg of the bijection): every VIGIL-LIMIT marker in the tree is registered.
# --------------------------------------------------------------------------------------------------
def _scan_markers() -> dict[str, list[str]]:
    """id -> [files it appears in], scanning .py sources (excluding vendored/venv trees and THIS test)."""
    found: dict[str, list[str]] = {}
    this = Path(__file__).resolve()
    for path in REPO.rglob("*.py"):
        if any(part in _SCAN_EXCLUDE for part in path.parts):
            continue
        if path.resolve() == this:
            continue  # this test names every id in prose; it is not a debt site
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for m in _MARKER.finditer(text):
            found.setdefault(m.group(1), []).append(str(path.relative_to(REPO)))
    return found


# ==================================================================================================
# The real inventory
# ==================================================================================================
def test_every_limitation_is_valid():
    problems: list[str] = []
    ids = set()
    for entry in _limitations():
        problems += validate_limitation(entry)
        lid = entry.get("id")
        if lid in ids:
            problems.append(f"duplicate limitation id {lid!r}")
        ids.add(lid)
    assert not problems, "limitation inventory problems:\n  - " + "\n  - ".join(problems)


def test_every_limitation_is_disposed():
    """Every item is EITHER filed-into-w16 OR recorded re-verified-closed — the AC's first bullet."""
    for entry in _limitations():
        assert entry["disposition"] in DISPOSITIONS, entry["id"]


def test_twelve_reverified_closed_named_with_real_evidence():
    data = _load()
    rvc = data["re_verified_closed"]
    got = {e["id"] for e in rvc}
    assert got == RVC_IDS, (f"the re-verified-closed census must be EXACTLY the twelve named items; "
                            f"missing={sorted(RVC_IDS - got)} unexpected={sorted(got - RVC_IDS)}")
    problems: list[str] = []
    for e in rvc:
        problems += validate_rvc(e)
    assert not problems, "re-verified-closed problems:\n  - " + "\n  - ".join(problems)


def test_marker_bijection_forward_every_marker_is_registered():
    marked_ids = {e["id"] for e in _limitations() if e["marker"]}
    found = _scan_markers()
    unregistered = {mid: files for mid, files in found.items() if mid not in marked_ids}
    assert not unregistered, (
        "UNREGISTERED honest-limit marker(s) — a `VIGIL-LIMIT:<id>` in code with no `marker: true` "
        f"inventory entry (register it in docs/limitations/inventory.json): {unregistered}")


def test_marker_bijection_reverse_every_marked_item_has_its_token():
    found = _scan_markers()
    problems = []
    for entry in _limitations():
        if entry["marker"] and entry["id"] not in found:
            problems.append(f"{entry['id']}: marker:true but no VIGIL-LIMIT:{entry['id']} token in any source")
    assert not problems, "\n".join(problems)


def test_registered_in_claims_registry():
    """The AC requires the behaviour be registered in the claims registry (W0-3 #398)."""
    reg = json.loads(CLAIMS_REGISTRY.read_text(encoding="utf-8"))
    ids = {c["id"] for c in reg["claims"]}
    assert "W15-1" in ids, "claim W15-1 (limitation inventory) is not registered in docs/claims/registry.json"


# ==================================================================================================
# Negative controls — the gate is provably not a no-op (deliberately-broken inputs are rejected here).
# ==================================================================================================
def _good() -> dict:
    """A minimal VALID entry (mirrors a real stub-raises item) to mutate in the negatives below."""
    return {
        "id": "LIMIT-symbolic-crash-repair",
        "title": "t", "summary": "s", "classification": "real-unfinished-code", "severity": "info",
        "anchor": {"file": "engine/crucible/framework/v2/remediation_binary/tier.py",
                   "symbol": "SymbolicCrashRepairTier.synthesize_patch"},
        "marker": False, "check": "stub-raises", "source_doc": "docs/DEFERRED-INFRA.md",
        "disposition": "file-into-w16", "w16_issue": None,
    }


def test_negative_control_the_good_entry_validates():
    assert validate_limitation(_good()) == []


def test_negative_control_missing_field_rejected():
    bad = _good()
    del bad["severity"]
    assert any("severity" in e for e in validate_limitation(bad))


def test_negative_control_bad_enum_rejected():
    for field, value in (("classification", "nope"), ("severity", "urgent"),
                         ("disposition", "later"), ("check", "magic")):
        bad = _good()
        bad[field] = value
        assert validate_limitation(bad), f"{field}={value} should be rejected"


def test_negative_control_stub_that_no_longer_raises_is_rejected():
    """The load-bearing negative: point stub-raises at a symbol that does NOT raise NotImplementedError
    (the software attestation signer's verify) — the guard must reject it, proving 'implementing the stub
    without updating the inventory turns CI red'."""
    bad = _good()
    bad["anchor"] = {"file": "engine/crucible/framework/v2/attest/provider.py",
                     "symbol": "SoftwareAttestationProvider.verify"}
    errs = validate_limitation(bad)
    assert any("does not raise NotImplementedError" in e for e in errs), errs


def test_negative_control_missing_anchor_symbol_rejected():
    bad = _good()
    bad["anchor"] = {"file": "engine/crucible/framework/v2/remediation_binary/tier.py",
                     "symbol": "ThisClassDoesNotExist.nope"}
    assert any("not found" in e for e in validate_limitation(bad))


def test_negative_control_marker_claim_without_token_rejected():
    bad = _good()
    bad["id"] = "LIMIT-attest-tee-hardware"  # a real marked id ...
    bad["marker"] = True
    bad["anchor"] = {"file": "docs/DEFERRED-INFRA.md"}  # ... but a file that carries no such token
    bad["check"] = "doc-exists"
    assert any("no `VIGIL-LIMIT:" in e for e in validate_limitation(bad))


def test_negative_control_rvc_without_real_evidence_rejected():
    bad = {"id": "RVC-x", "name": "n", "summary": "s",
           "evidence": "does/not/exist/at/all.py"}
    assert any("does not exist" in e for e in validate_rvc(bad))


def test_negative_control_bad_w16_issue_type_rejected():
    bad = _good()
    bad["w16_issue"] = "seventeen"
    assert any("w16_issue" in e for e in validate_limitation(bad))
