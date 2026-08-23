#!/usr/bin/env python3
"""Assemble the VIGIL reviewer readiness package — a VERIFIABLE ASSURANCE ARCHITECTURE.

W13-9 (#502). This script BUILDS the reviewer package from committed sources so the package can
never be a hand-edited snapshot: run it and the bytes are re-derived from the tree. It pulls from
``DATA-GROUND-TRUTH.md``, ``PRIVACY.md``, ``SECURITY.md``, the retention and incident-response
policies, the (pending) ``EXPORT.md`` and the three client instruments, and it binds every
assurance statement it makes to a ``docs/claims/registry.json`` entry whose proving test exists and
runs in a REQUIRED CI job.

Three build-time gates make the package honest:

1. **Evidence binding.** Every claim in ``ASSURANCE_CLAIMS`` must resolve to a registry entry whose
   ``enforced_by`` symbol is really defined and whose ``proved_by`` tests really exist and run in a
   required CI job. If a proving test is removed, ``resolve_claim`` raises ``EvidenceMissing`` and
   the build FAILS — the pack cannot outlive its evidence.
2. **No certification wording.** The fully rendered package is scanned; if any wording asserts
   certification (``certify/certified/certifies/certification`` — but NOT the legitimate
   cryptographic word ``certificate``) the build raises ``CertificationWordingError``. The package
   is a verifiable assurance architecture, never a compliance accreditation.
3. **Pending inputs are flagged, never fabricated.** Inputs owned by not-yet-merged dependencies
   (``EXPORT.md`` from #504 counsel; the three client instruments from #500 VSCP) are marked PENDING
   with their tracking issue if their files are absent, and auto-embedded once those deps land.

STDLIB ONLY (``json``/``re``/``ast``/``hashlib``/``pathlib``/``argparse``/``dataclasses``) so the
required ``the briefing explains every agent and capability`` job — which installs only pytest — can
run the proving test that imports this module.

This is a FACADE over the existing assurance substrate. It does NOT implement any gate, policy, or
oracle. WARDEN tiers, the conjunctive/destruction gates, the signed charter, ``require_capability``,
the hash-chained signed spine, offline re-verification, TPM sealing and m-of-n quorum are the real
controls; this script only REFERENCES them through their registry entries and re-runnable tests.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


# --------------------------------------------------------------------------------------------------
# Locations
# --------------------------------------------------------------------------------------------------
def default_repo_root() -> Path:
    # tools/reviewer-package/assemble.py -> repo root is two parents up.
    return Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------------------------------
# Errors — a failed gate is a failed build, never a silently degraded package.
# --------------------------------------------------------------------------------------------------
class EvidenceMissing(Exception):
    """A claim in the package does not resolve to a registry entry with an existing proving test."""


class CertificationWordingError(Exception):
    """The rendered package contains wording that asserts certification."""


class MissingRequiredInput(Exception):
    """A REQUIRED committed source input is absent from the tree."""


# --------------------------------------------------------------------------------------------------
# The certification gate. Forbid the certify/certification family but NOT "certificate", which is a
# legitimate cryptographic term across this codebase (proof-carrying-finding certificates, evidence
# certificates). Word-boundary anchored so "certificate(s)" never matches.
# --------------------------------------------------------------------------------------------------
_CERT_RE = re.compile(r"\bcertif(?:y|ies|ied|ying|ication|ications|iable|iably)\b", re.IGNORECASE)


def certification_wording_hits(text: str) -> list[str]:
    """Return every certification-asserting token found in ``text`` (empty == clean)."""
    return [m.group(0) for m in _CERT_RE.finditer(text)]


def assert_no_certification_wording(text: str) -> None:
    hits = certification_wording_hits(text)
    if hits:
        raise CertificationWordingError(
            "the reviewer package must never assert certification; found: "
            + ", ".join(sorted(set(h.lower() for h in hits)))
        )


# --------------------------------------------------------------------------------------------------
# AST resolution (no import) — mirrors docs/tests/test_claims_registry.py so this module is
# self-contained and can run in the docs-only briefing job.
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


def symbol_defined(repo_root: Path, file_path: str, dotted: str) -> bool:
    p = repo_root / file_path
    if not p.is_file():
        return False
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError:
        return False
    return _find_symbol(tree.body, dotted.split("."))


def test_function_defined(repo_root: Path, file_path: str, name: str) -> bool:
    p = repo_root / file_path
    if not p.is_file():
        return False
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError:
        return False
    return any(
        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
        for n in ast.walk(tree)
    )


def required_check_names(repo_root: Path) -> set[str]:
    f = repo_root / ".github" / "required-status-checks.txt"
    out: set[str] = set()
    if not f.is_file():
        return out
    for raw in f.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            out.add(s)
    return out


# --------------------------------------------------------------------------------------------------
# Registry + claim resolution
# --------------------------------------------------------------------------------------------------
def load_registry(repo_root: Path) -> dict:
    p = repo_root / "docs" / "claims" / "registry.json"
    if not p.is_file():
        raise MissingRequiredInput(f"claims registry missing: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data.get("claims"), list) or not data["claims"]:
        raise MissingRequiredInput("claims registry has no claims")
    return data


@dataclass(frozen=True)
class ClaimEvidence:
    id: str
    title: str
    enforced_file: str
    enforced_symbol: str
    proved_file: str
    proved_tests: tuple[str, ...]
    ci_job: str
    default: str


def resolve_claim(claim_id: str, registry: dict, repo_root: Path) -> ClaimEvidence:
    """Resolve one assurance claim to its backing evidence, or FAIL.

    Raises ``EvidenceMissing`` if the id is unregistered, the enforcing symbol is absent, the
    proving-test file or any named test function is absent, or the ci_job is not a required check.
    This is the guarantee behind "removing a proving test makes the package build FAIL".
    """
    entry = next((c for c in registry["claims"] if c.get("id") == claim_id), None)
    if entry is None:
        raise EvidenceMissing(f"{claim_id}: no claims-registry entry")

    eb = entry.get("enforced_by") or {}
    pb = entry.get("proved_by") or {}
    ef, es = eb.get("file", ""), eb.get("symbol", "")
    pf, tests = pb.get("file", ""), tuple(pb.get("tests", ()))
    ci_job = entry.get("ci_job", "")

    if not (ef and es and symbol_defined(repo_root, ef, es)):
        raise EvidenceMissing(f"{claim_id}: enforcing symbol {es!r} not defined in {ef!r}")
    if not pf or not (repo_root / pf).is_file():
        raise EvidenceMissing(f"{claim_id}: proving-test file missing: {pf!r}")
    if not tests:
        raise EvidenceMissing(f"{claim_id}: no proving tests listed")
    for t in tests:
        if not test_function_defined(repo_root, pf, t):
            raise EvidenceMissing(
                f"{claim_id}: proving test {t!r} not found in {pf} "
                "(deleting the proving test must fail the package build)"
            )
    if ci_job not in required_check_names(repo_root):
        raise EvidenceMissing(f"{claim_id}: ci_job {ci_job!r} is not a REQUIRED check")

    return ClaimEvidence(
        id=claim_id, title=entry.get("title", ""), enforced_file=ef, enforced_symbol=es,
        proved_file=pf, proved_tests=tests, ci_job=ci_job, default=entry.get("default", ""),
    )


# --------------------------------------------------------------------------------------------------
# The assurance manifest — the claims this package makes to a reviewer. Each id MUST be a real
# registry entry (resolve_claim enforces it). Adding a claim here without landed evidence fails the
# build; each carries a plain-language, reviewer-facing "so what". These reference the EXISTING
# controls (WARDEN, the signed spine, m-of-n, entitlement, egress, DR) — the package does not add
# any control of its own.
# --------------------------------------------------------------------------------------------------
ASSURANCE_CLAIMS: list[tuple[str, str]] = [
    ("W13-9", "This package is script-assembled from committed sources and every claim is test-bound; it is not a compliance accreditation."),
    ("REGISTRY-SELF", "Every product claim resolves to a real enforcing symbol and a real proving test, or CI goes red."),
    ("W14-3", "The map of where sensitive data lives on disk is generated from and drift-checked against the code."),
    ("W16-8", "Right-to-erasure is honoured by crypto-shredding an off-spine key, without breaking the append-only audit chain."),
    ("W12-2", "A published security policy carries a contact, supported versions, coordinated disclosure and a safe-harbour."),
    ("W5-1", "Every event-spine record is schema-validated on the way in, so the tamper-evident log cannot silently accept junk."),
    ("W5-3", "A witnessed checkpoint envelope refuses a record older than the one it already anchored (no rollback)."),
    ("W9-4", "A production deployment refuses to start unless its trust roots and signing posture are actually provisioned."),
    ("W9-5", "Destructive authority ships multi-signer by default — one key cannot unilaterally authorise destruction."),
    ("W9-7", "The build manifest is signed, so a deployer can verify the artifacts came from this source."),
    ("W3-5", "A signed SBOM is attached to each release, so a reviewer can audit the supply chain offline."),
    ("W7-1", "Disaster-recovery objectives (RPO 24h / bounded RTO) are stated and asserted by a drill, not merely hinted."),
    ("W7-4", "Off-host backup uses a real transport with destination-integrity checks, not a silent no-op copy."),
    ("W10-8", "In production the egress supervisor is a start-gate: the deny-default network boundary cannot be left off."),
    ("W11-4", "Resource-exhaustion paths fail closed rather than degrading into an unbounded or unsafe state."),
    ("W13-5", "A presented executor capability token is validated single-use and nine-field-bound at the tool boundary."),
    ("W13-6", "Restricted mode narrows what the offense executor may launch, enforced at the boundary, not by convention."),
]


# --------------------------------------------------------------------------------------------------
# The source-input manifest. `included` sources are committed today and embedded. `pending` sources
# are owned by a not-yet-merged dependency; they are flagged PENDING with their issue when absent and
# auto-embedded once the dep lands.
# --------------------------------------------------------------------------------------------------
@dataclass
class InputSource:
    key: str
    title: str
    paths: list[str]
    required: bool = True          # a required input that is absent fails the build
    embed: bool = True             # embed the file text verbatim into the package
    pending_issue: str = ""        # tracking issue if this input is owned by a pending dependency
    pending_provenance: str = ""   # human name of the pending dependency
    # populated during resolution:
    status: str = ""               # "included" | "pending"
    resolved_paths: list[str] = field(default_factory=list)


def input_manifest() -> list[InputSource]:
    return [
        InputSource("data-ground-truth",
                    "Data ground truth — where sensitive data lives on disk, its at-rest form, and how it is erased",
                    ["DATA-GROUND-TRUTH.md"]),
        InputSource("privacy",
                    "Privacy & evidence-retention position — what is captured, how long it is kept, right-to-erasure",
                    ["PRIVACY.md"]),
        InputSource("security",
                    "Security policy — contact, supported versions, coordinated disclosure, safe harbour",
                    ["SECURITY.md"]),
        InputSource("retention",
                    "Backup & disaster-recovery retention objectives — RPO / RTO and the recovery drill",
                    ["docs/decisions/W7-1-rpo-rto-objectives-and-drill.md"]),
        InputSource("incident",
                    "Incident-response posture — the prior-compromise pivot followed during an engagement",
                    ["engine/crucible/framework/playbooks/26-incident-response-pivot.md"]),
        InputSource("claims-registry",
                    "Machine-checkable claims registry — claim -> enforcing symbol -> proving test -> required CI",
                    ["docs/claims/registry.json"], embed=False),
        InputSource("export",
                    "Export-control classification & guidance",
                    ["EXPORT.md"],
                    required=False, pending_issue="#504", pending_provenance="W14-2 legal counsel"),
        InputSource("client-instruments",
                    "The three client instruments — security-questionnaire response, control profile, reviewer brief",
                    ["docs/reviewer/instruments/security-questionnaire-response.md",
                     "docs/reviewer/instruments/control-profile.md",
                     "docs/reviewer/instruments/reviewer-brief.md"],
                    required=False, pending_issue="#500", pending_provenance="VSCP"),
    ]


def resolve_inputs(repo_root: Path) -> list[InputSource]:
    resolved: list[InputSource] = []
    for src in input_manifest():
        present = [p for p in src.paths if (repo_root / p).is_file()]
        if src.required and not present:
            raise MissingRequiredInput(
                f"required input {src.key!r} is absent: none of {src.paths} exist"
            )
        src.resolved_paths = present
        # An optional (pending-dep) input is PENDING only while its files are absent; once the dep
        # lands its files, it is treated as an ordinary included source.
        src.status = "included" if present else "pending"
        resolved.append(src)
    return resolved


# --------------------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------------------
def _source_digest(repo_root: Path, inputs: list[InputSource]) -> str:
    """A content hash over every embedded/committed source + the registry, so a reviewer can see the
    package was derived from these exact bytes (reproducibility, not a certificate)."""
    h = hashlib.sha256()
    for src in inputs:
        for rel in src.resolved_paths:
            h.update(rel.encode("utf-8"))
            h.update(b"\0")
            h.update((repo_root / rel).read_bytes())
            h.update(b"\0")
    return h.hexdigest()


# A doc CLAIM marker is `<!-- CLAIM:<id> -->` and the claims-registry bijection guard requires each
# to be UNIQUE across the docs tree. Embedding a source doc verbatim would duplicate its markers into
# this derived artifact, so we neutralise them: the id stays visible for the reader, but the token no
# longer matches the canonical marker regex (a derived package is not a source of claims).
_EMBED_MARKER_RE = re.compile(r"<!--\s*CLAIM:([A-Za-z0-9][A-Za-z0-9._-]*)\s*-->")


def _neutralize_markers(text: str) -> str:
    return _EMBED_MARKER_RE.sub(r"<!-- claim-anchor:\1 (embedded copy; canonical marker lives in source) -->", text)


def _fence(text: str) -> str:
    """Embed arbitrary markdown as a fenced block, choosing a backtick run longer than any inside."""
    longest = 0
    for m in re.finditer(r"`+", text):
        longest = max(longest, len(m.group(0)))
    fence = "`" * max(3, longest + 1)
    return f"{fence}markdown\n{text.rstrip()}\n{fence}"


_DISCLAIMER = (
    "This document is a **verifiable assurance architecture**. It is **not** a compliance "
    "accreditation, a third-party audit attestation, or a conformance credential issued by any "
    "authority, and nothing in it should be read as one. Each statement below is instead bound to a "
    "machine-checkable claims-registry entry and a test that runs in a **required** CI job — evidence "
    "a reviewer can re-run, not a badge that has been granted. Where an input is still owned by a "
    "not-yet-merged dependency it is marked **PENDING** with its tracking issue rather than "
    "fabricated."
)


def render_package(repo_root: Path, registry: dict, evidence: list[ClaimEvidence],
                   inputs: list[InputSource]) -> str:
    digest = _source_digest(repo_root, inputs)
    reg_ver = registry.get("registry_version", "?")
    lines: list[str] = []
    A = lines.append

    A("# VIGIL — Reviewer Readiness Package")
    A("")
    A("> " + _DISCLAIMER.replace("\n", "\n> "))
    A("")
    A("## How this package was produced")
    A("")
    A("This package is **assembled by a script** — `tools/reviewer-package/assemble.py` — from "
      "committed sources in this repository. It is therefore not a hand-built snapshot: regenerate it "
      "and the bytes are re-derived from the tree. The assembler enforces three build-time gates: "
      "every assurance statement resolves to a claims-registry entry whose proving test exists and "
      "runs in required CI (remove the test and the build fails); the rendered package is scanned so "
      "no wording claims a compliance accreditation; and any input owned by a pending dependency is "
      "flagged, never invented.")
    A("")
    A(f"- **Claims-registry version:** `{reg_ver}`")
    A(f"- **Source content digest (SHA-256 over the embedded committed sources):** `{digest}`")
    A(f"- **Assurance statements bound:** {len(evidence)}")
    A("")
    A("This is a FACADE over VIGIL's existing controls — WARDEN tiers, the conjunctive and "
      "destruction gates, the signed charter, the `require_capability` entitlement layer, the "
      "hash-chained signed event spine, offline re-verification, TPM sealing and m-of-n quorum. The "
      "package references those controls through their registry entries and re-runnable tests; it "
      "does not add or re-implement any gate, policy, or oracle.")
    A("")

    # ---- input provenance table ---------------------------------------------------------------
    A("## Input sources")
    A("")
    A("| Input | Status | Committed source(s) |")
    A("|-------|--------|---------------------|")
    for src in inputs:
        if src.status == "included":
            paths = ", ".join(f"`{p}`" for p in src.resolved_paths)
            status = "included"
        else:
            paths = ", ".join(f"`{p}`" for p in src.paths)
            status = f"**PENDING** ({src.pending_issue} — {src.pending_provenance})"
        A(f"| {src.title} | {status} | {paths} |")
    A("")

    pending = [s for s in inputs if s.status == "pending"]
    if pending:
        A("### Pending inputs (owned by dependencies not yet merged)")
        A("")
        A("These inputs are **not present** in the tree at build time. They are declared here so a "
          "reviewer sees exactly what is still owed and by whom; they are **not** fabricated, and the "
          "assembler embeds them automatically once their dependency lands their files.")
        A("")
        for s in pending:
            A(f"- **{s.title}** — PENDING, tracked by {s.pending_issue} ({s.pending_provenance}). "
              f"Expected at: {', '.join(f'`{p}`' for p in s.paths)}.")
        A("")

    # ---- assurance evidence table -------------------------------------------------------------
    A("## Assurance statements and their evidence")
    A("")
    A("Every row is a claim VIGIL makes, the plain-language reason it matters to a reviewer, the code "
      "symbol that enforces it, the test that proves it, and the required CI job that runs that test. "
      "If any proving test is deleted, this package fails to build.")
    A("")
    A("| Claim | What it means for a reviewer | Enforced by | Proven by | Required CI job | Default |")
    A("|-------|------------------------------|-------------|-----------|-----------------|---------|")
    so_what = dict(ASSURANCE_CLAIMS)
    for ev in evidence:
        tests = "<br>".join(f"`{ev.proved_file}::{t}`" for t in ev.proved_tests)
        A(f"| **{ev.id}** — {ev.title} | {so_what.get(ev.id, '')} | "
          f"`{ev.enforced_file}`<br>`{ev.enforced_symbol}` | {tests} | "
          f"{ev.ci_job} | `{ev.default}` |")
    A("")
    A("### How to re-verify")
    A("")
    A("A reviewer re-runs the evidence directly. For example the registry guard, which proves the "
      "table above cannot drift from the code:")
    A("")
    A("```")
    A("python -m pytest docs/tests/test_claims_registry.py -q")
    A("python -m pytest docs/tests/test_w13_9_reviewer_package.py -q")
    A("```")
    A("")
    A("Each row's proving test can be run the same way; all of them run in the required CI jobs named "
      "in the table, on every pull request.")
    A("")

    # ---- embedded committed sources -----------------------------------------------------------
    A("## Committed source documents")
    A("")
    A("The narrative sources below are embedded verbatim from the tree at the digest above.")
    A("")
    for src in inputs:
        if not src.embed or src.status != "included":
            continue
        for rel in src.resolved_paths:
            A(f"### `{rel}`")
            A("")
            A(f"*({src.title})*")
            A("")
            A(_fence(_neutralize_markers((repo_root / rel).read_text(encoding="utf-8"))))
            A("")

    A("---")
    A("")
    A(_DISCLAIMER)
    A("")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------------------
# The public entry point (the enforced_by symbol for the W13-9 claim).
# --------------------------------------------------------------------------------------------------
def build_package(repo_root: Path | None = None) -> str:
    """Assemble and return the reviewer package as markdown, running all three build-time gates.

    Raises ``MissingRequiredInput``, ``EvidenceMissing``, or ``CertificationWordingError`` if any
    gate fails — a failed gate is a failed build.
    """
    root = Path(repo_root) if repo_root is not None else default_repo_root()
    registry = load_registry(root)
    inputs = resolve_inputs(root)
    evidence = [resolve_claim(cid, registry, root) for cid, _ in ASSURANCE_CLAIMS]
    rendered = render_package(root, registry, evidence, inputs)
    assert_no_certification_wording(rendered)  # gate: no wording asserts certification
    return rendered


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Assemble the VIGIL reviewer readiness package.")
    ap.add_argument("--repo-root", default=None, help="repository root (default: inferred).")
    ap.add_argument("-o", "--out", default=None,
                    help="output path (default: dist/reviewer-package/REVIEWER-PACKAGE.md).")
    ap.add_argument("--check", action="store_true",
                    help="build and run all gates but write nothing (exit non-zero on failure).")
    args = ap.parse_args(argv)

    root = Path(args.repo_root).resolve() if args.repo_root else default_repo_root()
    try:
        rendered = build_package(root)
    except (MissingRequiredInput, EvidenceMissing, CertificationWordingError) as exc:
        print(f"reviewer-package build FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.check:
        print(f"reviewer-package OK: {len(ASSURANCE_CLAIMS)} assurance statements bound, gates passed.")
        return 0

    out = Path(args.out) if args.out else (root / "dist" / "reviewer-package" / "REVIEWER-PACKAGE.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")
    print(f"reviewer-package written: {out} ({len(rendered)} bytes)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
