#!/usr/bin/env python3
"""gen_assurance_mapping — Lane C / C4: build the Common-Criteria / FedRAMP-shaped assurance mapping.

This script maps VIGIL's machine-checked claim registry (``docs/claims/registry.json``) and its documented-
limitation inventory (``docs/limitations/inventory.json``) onto an assurance structure a reviewer from an
accredited body would recognise:

    security objective  ->  claim(s)  ->  evidence / verifier  ->  residual limitation(s)

and it records the human adversarial-review cadence (the RED-PEN + adversarial-sweep discipline) as an
AUDITABLE control with a sign-off slot — turning tribal review knowledge into a documented artifact.

It also maps every FACT-capable oracle class (``docs/capability-matrix/evidence-branches.json``) onto the
verifier that re-checks it: the universal FRAMEWORK REPRODUCTION verifier (``python3 -m framework.v2
evidence verify`` re-executes the oracle_version-bound procedure over the retained oracle_context) and,
where available, the STRONGER zero-dependency STANDALONE verifier (``docs/proof-carrying-finding/
verify_vf.py``). The standalone set is DERIVED from ground truth, never asserted: an OracleKind is
standalone iff every oracle function it binds (``verify.oracle_version._ORACLE_FNS``) is in the set of
functions the standalone verifier re-executes — the C1 general ports (``integration/tests/
test_general_reexecutable.py::_PORTED``) plus the posture-tier ports + the ACHIEVED_STATE predicate kernel
(``verify_vf._POSTURE_ORACLE_DISPATCH`` + ``_reexecute_posture``).

HONESTY BAR (Lane C). This is an AUDIT-READY structure, NOT an external accreditation. The irreducible
boundaries — an external accredited body, a hardware root of trust, the live-liveness bound on re-execution
— are named in ``irreducible_boundaries``, never hidden. Where an oracle genuinely cannot be re-executed
with zero dependencies (needs live I/O, a browser, a subprocess tool, or a non-stdlib dependency) that is
recorded as the oracle's reproduction boundary, never faked as reproduced standalone.

STDLIB ONLY (``json`` / ``ast`` / ``re`` / ``pathlib``) so the proving test (``docs/tests/
test_assurance_mapping.py``) — which runs in the ``the briefing explains every agent and capability`` job
that installs only pytest — can import this module and re-derive the mapping to assert the committed JSON
has not drifted. Deterministic: sorted outputs, no wallclock, no RNG.

Regenerate: ``python3 docs/assurance/gen_assurance_mapping.py``  (writes ``assurance-mapping.json``).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "docs" / "claims" / "registry.json"
INVENTORY = REPO / "docs" / "limitations" / "inventory.json"
BRANCHES = REPO / "docs" / "capability-matrix" / "evidence-branches.json"
MODELS = REPO / "engine" / "crucible" / "framework" / "v2" / "verify" / "models.py"
ORACLE_VERSION = REPO / "engine" / "crucible" / "framework" / "v2" / "verify" / "oracle_version.py"
C1_GENERAL_TEST = REPO / "integration" / "tests" / "test_general_reexecutable.py"
VERIFY_VF = REPO / "docs" / "proof-carrying-finding" / "verify_vf.py"
OUTPUT = REPO / "docs" / "assurance" / "assurance-mapping.json"

_SCHEMA = "vigil-assurance-mapping/1"

# The two standalone, zero-VIGIL verifiers referenced as the stronger re-check tier (C3 pins their bytes).
_STANDALONE_VERIFIER = "docs/proof-carrying-finding/verify_vf.py"
_FRAMEWORK_VERIFIER = "python3 -m framework.v2 evidence verify"

# The posture-tier oracle functions the standalone verifier re-executes (verify_vf._POSTURE_ORACLE_DISPATCH
# + the ACHIEVED_STATE predicate kernel _reexecute_posture). achieved_state_oracle is the RETIRED, always-
# non-firing rubber-stamp stub (oracles.achieved_state_oracle) — pure, no dependency, so an ACHIEVED_STATE
# kind whose other function (predicate_oracle) is ported is fully standalone. This small set is the one
# authored constant; test_assurance_mapping cross-ties it to verify_vf's dispatch kind strings.
_POSTURE_PORTED_FNS = frozenset({
    "policy_path_oracle", "k8s_posture_oracle", "k8s_workload_posture_oracle",
    "cloud_posture_oracle", "mesh_posture_oracle", "cicd_posture_oracle",
    "predicate_oracle", "achieved_state_oracle",
})


# --------------------------------------------------------------------------------------------------
# Ground-truth readers (stdlib AST — no framework import).
# --------------------------------------------------------------------------------------------------
def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def oraclekind_values() -> dict[str, str]:
    """{OracleKind member name -> its str value} by AST over models.py (a str-Enum with explicit values)."""
    tree = ast.parse(MODELS.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "OracleKind":
            for item in node.body:
                if isinstance(item, ast.Assign) and isinstance(item.value, ast.Constant):
                    for t in item.targets:
                        if isinstance(t, ast.Name):
                            out[t.id] = str(item.value.value)
    return out


def oracle_fns_by_value() -> dict[str, list[str]]:
    """{OracleKind value -> [oracle function names it binds]} by AST over oracle_version._ORACLE_FNS."""
    members = oraclekind_values()
    tree = ast.parse(ORACLE_VERSION.read_text(encoding="utf-8"))
    out: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        # `_ORACLE_FNS: dict[...] = {...}` is an ANNOTATED assignment (AnnAssign), not a plain Assign.
        target = None
        value = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target, node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0], node.value
        if target is None or target.id != "_ORACLE_FNS" or not isinstance(value, ast.Dict):
            continue
        for k, v in zip(value.keys, value.values):
            # key: OracleKind.MEMBER
            if isinstance(k, ast.Attribute) and isinstance(k.value, ast.Name) and k.value.id == "OracleKind":
                member = k.attr
                fns = [e.attr for e in v.elts if isinstance(e, ast.Attribute)] if isinstance(v, ast.Tuple) else []
                out[members[member]] = sorted(fns)
    return out


def _ast_name_list(path: Path, varname: str) -> list[str]:
    """Return the string elements of a module-level ``varname = [...]`` list literal (stdlib AST)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == varname and isinstance(node.value, ast.List):
                    return [e.value for e in node.value.elts if isinstance(e, ast.Constant)]
    return []


def c1_ported_fns() -> frozenset[str]:
    """The C1 general ports — the single source of truth for which general oracle bodies verify_vf
    re-executes standalone (test_general_reexecutable._PORTED)."""
    return frozenset(_ast_name_list(C1_GENERAL_TEST, "_PORTED"))


def verify_vf_posture_kind_strings() -> frozenset[str]:
    """The kind strings in verify_vf._POSTURE_ORACLE_DISPATCH (3rd tuple element) — cross-checks that the
    authored posture-ported function set lines up with what verify_vf actually dispatches."""
    tree = ast.parse(VERIFY_VF.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        target = None
        value = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target, node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0], node.value
        if target is None or target.id != "_POSTURE_ORACLE_DISPATCH" or not isinstance(value, ast.Tuple):
            continue
        for row in value.elts:
            if isinstance(row, ast.Tuple) and len(row.elts) == 3 and isinstance(row.elts[2], ast.Constant):
                out.add(row.elts[2].value)
    return frozenset(out)


def standalone_function_set() -> frozenset[str]:
    return c1_ported_fns() | _POSTURE_PORTED_FNS


def fact_capable_kinds() -> list[str]:
    branches = _load_json(BRANCHES)["branches"]
    return sorted({b["oracle_version"] for b in branches if b.get("fact_capable") and b.get("oracle_version")})


# --------------------------------------------------------------------------------------------------
# Security objectives (Common-Criteria / FedRAMP-shaped control families).
# --------------------------------------------------------------------------------------------------
OBJECTIVES: list[dict[str, str]] = [
    {"id": "SO-AUTHZ", "label": "Authorization & scope control",
     "cc_family": "FDP_ACC / FIA_UAU (access control, authentication of actors)",
     "fedramp_family": "AC — Access Control",
     "objective": "Every host-acting operation is bounded by a signed authority (charter/scope/capability) "
                  "and a fail-closed gate; an unauthorised or out-of-scope action is refused, not performed."},
    {"id": "SO-NONREP", "label": "Evidence integrity & non-repudiation",
     "cc_family": "FCO_NRO / FPT_TDC (non-repudiation of origin, inter-TSF data consistency)",
     "fedramp_family": "AU — Audit & Accountability",
     "objective": "Every recorded action and finding is tamper-evident and attributable: a hash-chained, "
                  "signed spine and offline-re-verifiable certificates bind origin and integrity."},
    {"id": "SO-SOUND", "label": "Finding soundness (oracle sole authority)",
     "cc_family": "assurance objective (truth of a reported result)",
     "fedramp_family": "RA — Risk Assessment (accuracy of findings)",
     "objective": "A FACT is minted only by a deterministic oracle re-executing over retained evidence; an "
                  "AI judgement, a tool's bytes, or an unproven lead can never be laundered into a FACT."},
    {"id": "SO-ISOLATION", "label": "Isolation & containment",
     "cc_family": "FPT_SEP (domain separation)",
     "fedramp_family": "SC — System & Communications Protection",
     "objective": "The offense and sovereign planes run as two isolated processes; sandboxed execution and "
                  "the egress floor contain target traffic and third-party applications from the control plane."},
    {"id": "SO-SUPPLY", "label": "Supply-chain integrity",
     "cc_family": "ALC_DVS / ALC_CMC (development security, configuration management)",
     "fedramp_family": "SR / SA — Supply Chain Risk / System & Services Acquisition",
     "objective": "What the system is built from is what was chosen: images are digest-pinned, actions are "
                  "SHA-pinned, locks are hash-verified, and the shipped verifiers are provenance-pinned."},
    {"id": "SO-CONFIG", "label": "Secure configuration & fail-closed posture",
     "cc_family": "FMT_MSA (management of security attributes)",
     "fedramp_family": "CM — Configuration Management",
     "objective": "Security-relevant configuration is validated fail-closed at startup; a production posture "
                  "forces the stricter controls on and refuses to start when they are absent."},
    {"id": "SO-CRYPTO", "label": "Cryptography & key management",
     "cc_family": "FCS_COP / FCS_CKM (cryptographic operation, key management)",
     "fedramp_family": "SC-12/13 — Cryptographic Key Establishment & Protection",
     "objective": "Signing keys are handled fail-closed (hardware backend, m-of-n quorum, escrow at "
                  "threshold, crypto-shred erasure); keys are passed in, never provisioned by the tool (FATAL-2)."},
    {"id": "SO-RESILIENCE", "label": "Resilience, recovery & observability",
     "cc_family": "FRU (resource utilisation / fault tolerance)",
     "fedramp_family": "CP / SI — Contingency Planning / System & Information Integrity",
     "objective": "Backup, restore, upgrade/rollback and crash-resume are drilled against numeric RPO/RTO; "
                  "health, readiness and metrics are exposed, and a degraded dependency is made visible."},
    {"id": "SO-ASSURANCE", "label": "Assurance governance & documentation honesty",
     "cc_family": "AGD / ALC_FLR (guidance documents, flaw remediation) + claim discipline",
     "fedramp_family": "CA / PL — Assessment & Authorization / Planning",
     "objective": "Every product claim resolves to an enforcing symbol and a proving test in a required CI "
                  "job; limitations are code-grounded and never worded as completeness (claim discipline)."},
]
_OBJECTIVE_IDS = {o["id"] for o in OBJECTIVES}

# Priority-ordered keyword rules: a claim's (title + claim) text is matched against these in order; the
# FIRST matching objective wins. SO-ASSURANCE is the documented catch-all (documentation / governance
# claims), so no claim is ever unmapped. Transparent and auditable — a reviewer can re-run the routing.
_ROUTING: list[tuple[str, tuple[str, ...]]] = [
    ("SO-CRYPTO", ("crypto-shred", "signing key", "hardware backend", "passphrase", "escrow",
                   "owner key", "per-host key", "delegation")),
    ("SO-SUPPLY", ("sha-pinned", "sbom", "base-image", "base image", "container image", "images are",
                   "build backend", "pep 517", "content-addressed", "sandbox live-image", "image-scan",
                   "images scanned")),
    ("SO-ISOLATION", ("two-env", "isolation", "sandbox", "sibling application", "containment",
                      "vigil down", "panic", "contains a systemd")),
    ("SO-RESILIENCE", ("backup", "restore", "rpo", "rto", "recovery drill", "upgrade/rollback",
                       "schema-compat", "chaos", "failover", "soak", "deploy-verify", "rollback proof",
                       "healthz", "readyz", "liveness", "readiness probe", "metrics", "otlp",
                       "corruption", "resource exhaustion", "fork-detection", "fork detection",
                       "memory leak", "throughput floor", "health check")),
    ("SO-AUTHZ", ("authoriz", "authority", "scope", "charter", "rbac", "per-user", "capability token",
                  "capability is", "kill-switch", "kill switch", "restricted mode", "destruction quorum",
                  "destruction", "owner-sign", "owner sign", "owner token", "approval", "principal",
                  "egress allowlist", "egress supervisor", "rate control", "rate", "warden", "gate before",
                  "triple-conjunction", "remote engage", "engage", "offense gated", "authority is",
                  "privilege")),
    ("SO-NONREP", ("spine", "hash chain", "hash-chain", "signed head", "witnessed-checkpoint",
                   "witnessed checkpoint", "signed manifest", "manifest is", "manifest json", "manifest.json",
                   "transparency-log", "transparency log", "time anchor", "rfc3161", "attestation",
                   "anti-rollback", "tamper", "citation", "projection drift", "de-duplication", "hard-prune",
                   "merkle", "install manifest", "build id", "build manifest", "integrity states",
                   "signed chain", "no signed head", "signed sbom", "signed deployment", "challenge-response")),
    ("SO-SOUND", ("oracle", "fact from tool", "lead", "posture-weakness", "forgery oracle", "zero-fp",
                  "zero fp", "evidence branch", "achieved-state", "achieved state", "clean-capable",
                  "negatives-capable", "secret-type", "secret-discovery", "evidence-tier", "evidence tier",
                  "cross_account_principal", "charset", "web re-drive", "redirect parameter", "re-drive",
                  "jwt embedded-key", "deep/full profile")),
    ("SO-CONFIG", ("production refuse-to-start", "posture", "schema_version", "schema vocabulary",
                   "newer schema", "root pin", "crucible_root", "fail-open owner token", "outbound sink",
                   "telemetry", "no-collect", "no collect", "install manifest", "data directory")),
]


def route_objective(claim: dict) -> str:
    text = (claim.get("title", "") + " || " + claim.get("claim", "")).lower()
    for obj_id, keys in _ROUTING:
        if any(k in text for k in keys):
            return obj_id
    return "SO-ASSURANCE"


# --------------------------------------------------------------------------------------------------
# Limitation routing (which objective each residual limitation bounds).
# --------------------------------------------------------------------------------------------------
_LIMIT_ROUTING: list[tuple[str, tuple[str, ...]]] = [
    ("SO-CRYPTO", ("tee", "hardware", "attest")),
    ("SO-SOUND", ("oracle", "fact", "posture", "finding", "crash-repair", "sanitizer", "favicon",
                  "fingerprint", "cloud-exploit", "tls-certificate", "dns-oob")),
    ("SO-ISOLATION", ("container-kill", "sandbox")),
    ("SO-RESILIENCE", ("neo4j", "spine-seal", "accrual")),
    ("SO-NONREP", ("audit-package", "evidence", "reproduction")),
    ("SO-ASSURANCE", ("external-audit", "redteam", "profile-packs", "agent-body", "a11y", "gesture",
                      "voice", "owner-anchor")),
]


def route_limitation(limit: dict) -> str:
    text = (limit.get("id", "") + " " + limit.get("title", "") + " " + limit.get("summary", "")).lower()
    for obj_id, keys in _LIMIT_ROUTING:
        if any(k in text for k in keys):
            return obj_id
    return "SO-ASSURANCE"


# --------------------------------------------------------------------------------------------------
# Fact-class -> verifier.
# --------------------------------------------------------------------------------------------------
_IRREDUCIBLE_BY_DEP = {
    # C1 _IRREDUCIBLE, restricted to the FACT-capable kinds: a non-stdlib import is needed to re-fire.
    "oob_callback": "requires framework verify.oob + an external OOB collector's receipt crypto",
    "version_range": "requires the `packaging` library to parse/compare version ranges",
}
_MIXED = {
    "tls_weakness": "the weak-crypto-ARTIFACT path is ported standalone (weak_crypto_artifact_oracle); the "
                    "LIVE TLS-handshake path (tls_weakness_oracle) is irreducible (needs a live socket)",
}


def build_fact_class_assurance() -> list[dict[str, Any]]:
    fns_by_value = oracle_fns_by_value()
    standalone_fns = standalone_function_set()
    rows: list[dict[str, Any]] = []
    for kind in fact_capable_kinds():
        fns = fns_by_value.get(kind, [])
        standalone = bool(fns) and set(fns) <= standalone_fns
        row: dict[str, Any] = {
            "oracle_class": kind,
            "oracle_functions": fns,
            "primary_verifier": {
                "kind": "framework-reproduction",
                "command": _FRAMEWORK_VERIFIER,
                "re_executes": "the oracle_version-bound deterministic procedure over the retained "
                               "oracle_context (bound into the certificate at mint).",
            },
            "standalone_zero_dependency": standalone,
        }
        if standalone:
            row["standalone_verifier"] = {
                "kind": "zero-vigil-standalone",
                "file": _STANDALONE_VERIFIER,
                "note": "re-fires this oracle body with the Python standard library + one Ed25519 lib, "
                        "importing no framework/vigil code (C3 pins its bytes).",
            }
        else:
            if kind in _IRREDUCIBLE_BY_DEP:
                boundary = "irreducible-by-dependency: " + _IRREDUCIBLE_BY_DEP[kind]
            elif kind in _MIXED:
                boundary = "mixed: " + _MIXED[kind]
            else:
                boundary = ("pure-but-deferred: the body is portable (stdlib + cryptography) but is re-fired "
                            "today only inside the framework over a live-capture / browser / subprocess / "
                            "cloud-API context — the irreducible boundary is live I/O, not a missing verifier.")
            row["reproduction_boundary"] = boundary
        rows.append(row)
    return rows


# --------------------------------------------------------------------------------------------------
# Adversarial-review control (the red-pen cadence as an auditable artifact with a sign-off slot).
# --------------------------------------------------------------------------------------------------
def adversarial_review_control() -> dict[str, Any]:
    return {
        "control_id": "AR-REDPEN",
        "name": "Adversarial review (RED-PEN + adversarial-sweep)",
        "purpose": "Make the near-zero-false-positive bar an AUDITABLE control, not tribal knowledge: no "
                   "defensive-oracle domain or FACT-class merges without an independent adversarial re-attack "
                   "that refutes each objection with a real repro and reports only what survives.",
        "cadence": [
            "Per slice: parallel worktree build, then an independent RED-PEN agent, then (for a defensive "
            "domain) the adversarial-sweep companion attacking from disjoint lenses — NON-NEGOTIABLE before "
            "a sequential merge.",
            "Per wave: report at the wave boundary; lessons are baked forward into the next wave.",
            "Isolation: parallel mutation lenses run in a committed worktree (isolation:'worktree') so they "
            "cannot race into a false 'backdoor' BLOCK.",
        ],
        "methodology_refs": [
            ".claude/skills/adversarial-sweep/SKILL.md",
            "docs/CLAIM-DISCIPLINE.md",
            "docs/proof-carrying-finding/TRUST-GRADIENT.md",
        ],
        "evidence_of_effect": "On the email-auth stream the adversarial sweep caught 3 CRITICAL/LOW defects "
                              "PAST a RED-PEN PASS — a single reviewer cannot self-attest near-zero-FP.",
        "sign_off": {
            "_note": "A sign-off slot per audited release. A human reviewer fills one entry; the slots are "
                     "intentionally EMPTY until signed — an unsigned review is recorded as pending, never "
                     "fabricated.",
            "entries": [],
            "entry_schema": {
                "release": "git tag or commit the review covered",
                "scope": "the domains / FACT-classes re-attacked",
                "reviewer": "named human reviewer (not the author)",
                "date": "ISO-8601 date",
                "verdict": "one of: PASS | PASS-WITH-FIXES | BLOCK",
                "findings_ref": "path or issue link to the recorded findings",
            },
        },
    }


def irreducible_boundaries() -> list[dict[str, str]]:
    return [
        {"id": "IRR-external-body",
         "boundary": "An external, accredited assessment body is required for an actual Common-Criteria / "
                     "FedRAMP accreditation. This mapping is the audit-ready INPUT to that process, not the "
                     "accreditation itself.",
         "limitation_ref": "LIMIT-external-audit-team"},
        {"id": "IRR-hardware-root",
         "boundary": "Origin/integrity is anchored to out-of-band-pinned Ed25519 trust roots, not a hardware "
                     "root of trust (TEE). Hardware-backed attestation is not available here and fails "
                     "closed when no hardware root is present; see LIMIT-attest-tee-hardware.",
         "limitation_ref": "LIMIT-attest-tee-hardware"},
        {"id": "IRR-liveness-bound",
         "boundary": "Re-execution proves a verdict is the correct FUNCTION of the retained evidence; it does "
                     "not prove the evidence was live. A live re-run inside VIGIL is the producer-supplied "
                     "honesty bound for that.",
         "limitation_ref": "LIMIT-audit-package-reproduction"},
    ]


# --------------------------------------------------------------------------------------------------
# Assemble.
# --------------------------------------------------------------------------------------------------
def build_mapping() -> dict[str, Any]:
    registry = _load_json(REGISTRY)
    inventory = _load_json(INVENTORY)
    claims = registry["claims"]
    limitations = inventory["limitations"]

    limit_by_objective: dict[str, list[str]] = {o["id"]: [] for o in OBJECTIVES}
    for lim in limitations:
        limit_by_objective[route_limitation(lim)].append(lim["id"])

    claim_rows: list[dict[str, Any]] = []
    claims_by_objective: dict[str, list[str]] = {o["id"]: [] for o in OBJECTIVES}
    for c in claims:
        obj = route_objective(c)
        claims_by_objective[obj].append(c["id"])
        proved = c.get("proved_by", {})
        claim_rows.append({
            "id": c["id"],
            "title": c["title"],
            "objective": obj,
            "enforced_by": c.get("enforced_by", {}),
            "verifier": {
                "kind": "required-ci-proof",
                "proving_tests": {"file": proved.get("file"), "tests": proved.get("tests", [])},
                "ci_job": c.get("ci_job"),
            },
            "default": c.get("default"),
            "failure_class": c.get("failure_class"),
        })

    objective_rows = []
    for o in OBJECTIVES:
        objective_rows.append({
            **o,
            "claims": sorted(claims_by_objective[o["id"]]),
            "claim_count": len(claims_by_objective[o["id"]]),
            "residual_limitations": sorted(limit_by_objective[o["id"]]),
        })

    return {
        "schema": _SCHEMA,
        "title": "VIGIL assurance mapping (Common-Criteria / FedRAMP-shaped)",
        "note": ("AUDIT-READY structure (security objective -> claim -> evidence/verifier -> residual "
                 "limitation), generated from docs/claims/registry.json + docs/limitations/inventory.json + "
                 "docs/capability-matrix/evidence-branches.json. NOT an external accreditation; see "
                 "irreducible_boundaries. Regenerate with docs/assurance/gen_assurance_mapping.py; drift is "
                 "caught by docs/tests/test_assurance_mapping.py."),
        "security_objectives": objective_rows,
        "claims": sorted(claim_rows, key=lambda r: r["id"]),
        "fact_class_assurance": build_fact_class_assurance(),
        "adversarial_review": adversarial_review_control(),
        "irreducible_boundaries": irreducible_boundaries(),
    }


def main() -> int:
    mapping = build_mapping()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    objs = mapping["security_objectives"]
    print(f"wrote {OUTPUT}")
    print(f"  {len(mapping['claims'])} claims mapped across {len(objs)} objectives")
    print(f"  {len(mapping['fact_class_assurance'])} fact-capable classes mapped to a verifier "
          f"({sum(1 for r in mapping['fact_class_assurance'] if r['standalone_zero_dependency'])} standalone)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
