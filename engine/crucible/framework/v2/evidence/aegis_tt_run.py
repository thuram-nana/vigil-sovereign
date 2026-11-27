"""
evidence.aegis_tt_run — the AEGIS TT-STG RUN orchestration (slice AS-1b).

AS-1a (``aegis.tt_rig``) proves the Observe acceptance across two isolated tenants IN CI.
AS-25 (``evidence.aegis_tt``) is the signed DONE-record machinery. AS-1b is the staging-run
counterpart to AS-1a: it takes a test-tenant acceptance run EXECUTED ON TT-STG — TT-A under
attack with TT-B as the cross-tenant control (ADR 0001 / FORGE-DOMAIN-MAP §2.4) — plus the
verification manifest the staging suite wrote, GATES the run fail-closed, DERIVES the AS-25
record's world (the IaC topology digest over the AS-26 staging templates; the subject digest;
and the six required case-class counts re-derived FROM the bound JUnit, never asserted), and
assembles the AS-25 signed binding so the staging control plane can sign it and an auditor can
re-verify it offline.

WHY THIS IS A SEPARATE LAYER (and not a dup of AS-25). AS-25 is the record SCHEMA + offline
verifier: given a binding, a manifest and a trust root it says verify / deny. It does NOT decide
whether a TT-STG run is admissible to be recorded, and it does NOT derive the record's world from
the run — in the AS-25 tests those fields are hand-passed. AS-1b is the orchestration above it:
the fail-closed GATE over the acceptance result + the manifest, the DERIVATION of the case-class
tally from the bound JUnit (so a record can never claim coverage the run did not produce), the IaC
topology digest over the real AS-26 templates, and the subject digest that drives staleness. Only
a run that clears every gate yields a binding; a run that fails any gate yields NO binding.

Doctrine (wire, don't rebuild):

  * The record model, the signer, and the offline verifier are AS-25's (``evidence.aegis_tt``),
    used verbatim — ``build_demonstration`` / ``sign_demonstration`` / ``verify_demonstration``.
    AS-1b never re-implements a signing primitive or the verifier.
  * The acceptance result AS-1b gates is the AS-1a rig's own JSON shape
    (``aegis.tt_rig.run_tt_acceptance``): ``ok`` + ``checks`` + ``tenants`` + the distinct-uid
    OS-boundary assertion. AS-1b imports nothing from ``aegis`` (it only reads the result dict),
    so it adds no import onto the AEGIS gate package and ``make gate`` stays byte-identical.
  * Canonical bytes are the shared-core discipline (``vigil_core.canonical`` —
    ``canonical_json`` / ``sha256_hex``), the same primitives AS-25 uses.

Determinism (doctrine: no wallclock / global-RNG on a signed or decision path): every function
here is a pure function of its inputs. The topology/subject digests read only file bytes; the
case-class derivation reads only the passed-node list; the gate reads only the acceptance and the
manifest. No ``datetime.now()`` and no RNG sit on any path — the same run gives the same binding,
hence the same signing bytes.

Fail-closed (doctrine: unverifiable => no record): every gate defaults to a reason string and the
run is admissible only when every reason list is empty. A failed acceptance, a dirty or failing
manifest, a skipped no-skip term, a missing case class, a non-IaC topology or non-VALID artifacts
all deny the binding. Append-only: a binding is write-once; nothing here mutates a prior record.

This module builds and gates the run-record orchestration and is covered offline in full; the LIVE
half is deploy-gated and is an honestly-registered residual. VIGIL-LIMIT:AS1B-live-fire-tt-stg
Standing up TT-STG in a real AWS staging account (the AS-26 CloudFormation stack applied, the
GitHub-OIDC staging deploy role wired, MFA console sign-in), executing the e2e deploy + acceptance
against it, and SIGNING the binding with the provisioned staging TT-evidence key (the committed
trust root ``docs/evidence/aegis-tt/trust-root.json`` is ``unprovisioned``; the real key is
KMS-wrapped in the staging control plane and is NEVER a CI runner key) are field actions, not
exercised in this repo's merge pipeline. See docs/limitations/inventory.json.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

from vigil_core.canonical import canonical_json, sha256_hex

from .aegis_tt import (
    REQUIRED_CASE_CLASSES,
    REQUIRED_NO_SKIP_TERMS,
    AegisTtDemonstration,
    BuildRef,
    DemonstrationVerification,
    RequiredCases,
    SignedDemonstration,
    SubjectRef,
    TopologyRef,
    UiLeg,
    build_demonstration,
    sign_demonstration,
    verify_demonstration,
)

# The AS-26 staging CloudFormation templates — the IaC topology a TT-STG run binds (``class: iac``).
# Relative to the repo root; a demonstration only ever attests a run against this infrastructure.
AS26_STAGING_DIR: Final[str] = "infra/aws/aegis-staging"
AS26_TEMPLATE_NAMES: Final[tuple[str, ...]] = (
    "00-network-zones.cfn.yaml",
    "10-keys-roles-ssm.cfn.yaml",
    "20-edge-cloudfront.cfn.yaml",
    "30-ops-relay-paging-drift.cfn.yaml",
)

# The subject under test a TT-STG run exercises: the AEGIS data-plane gateway (what the two tenants
# drive) plus the record machinery the run produces. Drives staleness — the subject digest moving
# since a record was signed marks it STALE (a state, never a verification failure; see AS-25).
DEFAULT_SUBJECT_PATHS: Final[tuple[str, ...]] = (
    "engine/crucible/framework/v2/aegis/tt_rig.py",
    "engine/crucible/framework/v2/aegis/gateway.py",
    "engine/crucible/framework/v2/evidence/aegis_tt.py",
    "engine/crucible/framework/v2/evidence/aegis_tt_run.py",
)

# The verification-manifest schema a TT-STG binding is allowed to cover (mirrors evidence.aegis_tt).
MANIFEST_SCHEMA: Final[str] = "vigil-verification-manifest/1"

# The case-class marker a staging-suite test carries in its JUnit node id: a bracketed token
# ``[<case_class>]`` on the classname or test name. The tokens are the six REQUIRED_CASE_CLASSES.
# Bracketing makes the tokens unambiguous: "[benign]" is never a substring of "[benign_same_shape]",
# so the tally can never double-count a more-specific class as a broader one.
CASE_CLASS_TOKENS: Final[dict[str, str]] = {c: f"[{c}]" for c in REQUIRED_CASE_CLASSES}


# --------------------------------------------------------------------------------------
# Deterministic digests — the IaC topology the run binds, and the subject it exercises.
# --------------------------------------------------------------------------------------
def _tree_file_digests(repo_root: Path, rel_paths: Sequence[str]) -> dict[str, str]:
    """A {relpath: sha256 of file bytes} map over ``rel_paths``, resolved under ``repo_root``.

    A directory entry expands to every ``*`` file beneath it, sorted; a file entry is itself. The
    map is keyed by POSIX relpath so the digest is independent of the absolute checkout location and
    of filesystem iteration order. A missing path raises — a digest over an absent subject is not a
    digest the run can honestly bind (fail-closed), never a silent empty."""
    digests: dict[str, str] = {}
    for rel in rel_paths:
        base = (repo_root / rel).resolve()
        if base.is_dir():
            members = sorted(p for p in base.rglob("*") if p.is_file())
            if not members:
                raise ValueError(f"subject directory {rel!r} resolved to no files under {repo_root}")
            for member in members:
                key = member.relative_to(repo_root).as_posix()
                digests[key] = sha256_hex(member.read_bytes())
        elif base.is_file():
            digests[base.relative_to(repo_root).as_posix()] = sha256_hex(base.read_bytes())
        else:
            raise ValueError(f"subject path {rel!r} does not resolve to a file or directory under {repo_root}")
    return digests


def iac_topology_digest(template_paths: Sequence[Path]) -> str:
    """A deterministic sha256 over the AS-26 IaC templates — the topology a TT-STG run executes on.

    Canonical over a {filename: sha256(bytes)} map so a one-byte change to any template (or a template
    added/removed) moves the digest, and the order the paths are supplied in does not. This is the value
    bound as ``topology.digest`` (with ``class == "iac"``); the record exists only to attest a run on an
    IaC-provisioned topology. A missing template raises (fail-closed)."""
    by_name: dict[str, str] = {}
    for path in template_paths:
        p = Path(path)
        if not p.is_file():
            raise ValueError(f"IaC template {p} is not a file — cannot digest a topology that is not present")
        by_name[p.name] = sha256_hex(p.read_bytes())
    if not by_name:
        raise ValueError("no IaC templates supplied — a demonstration must bind a non-empty topology")
    return sha256_hex(canonical_json(by_name))


def as26_template_paths(repo_root: Path) -> list[Path]:
    """The canonical AS-26 staging template paths under ``repo_root`` (the four cfn templates)."""
    staging = repo_root / AS26_STAGING_DIR
    return [staging / name for name in AS26_TEMPLATE_NAMES]


def subject_digest(repo_root: Path, subject_paths: Sequence[str] = DEFAULT_SUBJECT_PATHS) -> str:
    """A deterministic sha256 over the subject-under-test tree — drives the AS-25 staleness state."""
    return sha256_hex(canonical_json(_tree_file_digests(repo_root, subject_paths)))


# --------------------------------------------------------------------------------------
# Case-class derivation — re-derived FROM the run, never asserted.
# --------------------------------------------------------------------------------------
def junit_passed_case_nodes(junit_path: Path) -> list[str]:
    """The node ids of PASSED testcases in a JUnit report (``classname::name``), sorted.

    A node counts only if it has NO ``failure`` / ``error`` / ``skipped`` child — a failed, errored
    or skipped case did not exercise its case class, so it must not feed the tally. Deterministic
    (sorted); the companion to ``tools/verification_manifest.py``'s suite-identity derivation."""
    root = ET.parse(junit_path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    passed: list[str] = []
    for suite in suites:
        for case in suite.iter("testcase"):
            if any(case.find(tag) is not None for tag in ("failure", "error", "skipped")):
                continue
            passed.append(f"{case.get('classname', '')}::{case.get('name', '')}")
    return sorted(passed)


def derive_required_cases(passed_nodes: Sequence[str]) -> RequiredCases:
    """Tally the six required case classes from the PASSED JUnit node ids.

    Each node declares its case class by carrying the bracketed token ``[<case_class>]`` (see
    ``CASE_CLASS_TOKENS``) in its classname or name. The count of each class is the number of passed
    nodes carrying its token. A class no passed node carries tallies 0 — which the gate then refuses,
    so a record can never claim a case class the run did not actually exercise and pass. Deterministic
    and order-independent."""
    counts: dict[str, int] = {c: 0 for c in REQUIRED_CASE_CLASSES}
    for node in passed_nodes:
        for case_class, token in CASE_CLASS_TOKENS.items():
            if token in node:
                counts[case_class] += 1
    return RequiredCases(
        positive=counts["positive"],
        benign=counts["benign"],
        benign_same_shape=counts["benign_same_shape"],
        negative=counts["negative"],
        cross_tenant=counts["cross_tenant"],
        failure_class=counts["failure_class"],
    )


# --------------------------------------------------------------------------------------
# The fail-closed gates (each returns a list of DENY reasons; empty == pass).
# --------------------------------------------------------------------------------------
def gate_acceptance(acceptance: Mapping[str, Any]) -> list[str]:
    """Gate the AS-1a-shaped acceptance result of the TT-STG run (``aegis.tt_rig.run_tt_acceptance``).

    A TT-STG DONE run must be the DISTINCT-UID acceptance — the cross-tenant isolation is a real OS
    boundary, not just in-process separation (the ``cross-uid`` no-skip term demands it). Every check
    must hold, the positive OS-boundary assertion must have run and passed, and the attack must be
    visible to TT-A while the TT-B control saw nothing. Fail-closed: a missing or False anything denies."""
    reasons: list[str] = []
    if acceptance.get("ok") is not True:
        reasons.append("acceptance.ok is not True — the TT-STG acceptance did not pass")
    if acceptance.get("mode") != "distinct-uids":
        reasons.append(
            f"acceptance.mode is {acceptance.get('mode')!r}, not 'distinct-uids' — a TT-STG DONE run "
            "must run each tenant under a distinct OS uid (the cross-uid boundary), not in-process")
    checks = acceptance.get("checks")
    if not isinstance(checks, Mapping) or not checks:
        reasons.append("acceptance.checks is absent or empty — no acceptance properties were recorded")
        return reasons
    for name, value in checks.items():
        if value is not True:
            reasons.append(f"acceptance check {name!r} is {value!r}, not True")
    if "cross_tenant_uid_cannot_read_peer_feed" not in checks:
        reasons.append(
            "the positive cross-uid OS-boundary assertion did not run (no "
            "'cross_tenant_uid_cannot_read_peer_feed' check) — the isolation is unproven")
    probe = acceptance.get("cross_tenant_fs_probe")
    if not isinstance(probe, Mapping) or probe.get("ok") is not True:
        reasons.append("cross_tenant_fs_probe did not attempt-and-pass — the OS filesystem boundary is unproven")
    if not acceptance.get("expected_attack_classes"):
        reasons.append("acceptance recorded no expected_attack_classes — nothing was proven visible")
    return reasons


def gate_manifest(manifest: Mapping[str, Any]) -> list[str]:
    """Gate the verification manifest the staging suite wrote: a clean, passing run on a clean tree."""
    reasons: list[str] = []
    if manifest.get("schema") != MANIFEST_SCHEMA:
        reasons.append(f"manifest schema is {manifest.get('schema')!r}, not {MANIFEST_SCHEMA}")
    if manifest.get("exit_status") != 0:
        reasons.append(f"the staging run FAILED (exit {manifest.get('exit_status')})")
    if manifest.get("dirty"):
        reasons.append("the staging run was on a DIRTY tree — it does not describe a committed state")
    counts = manifest.get("counts")
    counts_map: Mapping[str, Any] = counts if isinstance(counts, Mapping) else {}
    if counts_map.get("failed"):
        reasons.append(f"the staging run had {counts_map.get('failed')} failing test(s)")
    if counts_map.get("error"):
        reasons.append(f"the staging run had {counts_map.get('error')} erroring test(s)")
    if not counts_map.get("passed"):
        reasons.append("the staging run passed no tests — there is nothing to attest")
    return reasons


def gate_no_skip(manifest: Mapping[str, Any]) -> list[str]:
    """Gate the no-skip discipline: the run skipped no test covering a required no-skip term.

    Mirrors ``evidence.aegis_tt.verify_demonstration`` (and ``tools/verification_manifest.py``): a
    skipped test whose node id or reason mentions TT-B / cross-uid / browser / isolation / tenant is a
    claim resting on behaviour that did not run. Gating it here is the pre-record half of what the
    offline verifier re-checks."""
    reasons: list[str] = []
    skips = manifest.get("skips")
    skip_list: Sequence[Any] = skips if isinstance(skips, Sequence) and not isinstance(skips, str) else ()
    for term in sorted(REQUIRED_NO_SKIP_TERMS):
        hits: list[str] = []
        for skip in skip_list:
            if not isinstance(skip, Mapping):
                continue
            haystack = f"{skip.get('test', '')} {skip.get('reason', '')}".lower()
            if term.lower() in haystack:
                hits.append(str(skip.get("test", "?")))
        if hits:
            reasons.append(f"a skipped test covers the no-skip term {term!r}: " + "; ".join(hits))
    return reasons


def gate_required_cases(required_cases: RequiredCases) -> list[str]:
    """Gate the derived case tally: every one of the six required case classes present (count >= 1)."""
    missing = [c for c in REQUIRED_CASE_CLASSES if getattr(required_cases, c) < 1]
    if missing:
        return [f"required case class(es) absent from the run: {', '.join(missing)}"]
    return []


@dataclass(frozen=True)
class TtStgGate:
    """The fail-closed verdict on a TT-STG run's admissibility, with the derived case tally.

    ``ok`` is True only when every sub-gate's reason list is empty. ``required_cases`` is derived from
    the run's passed JUnit nodes (not asserted), so a caller can see exactly what coverage was proven."""
    ok: bool
    reasons: tuple[str, ...]
    required_cases: RequiredCases
    acceptance_reasons: tuple[str, ...] = ()
    manifest_reasons: tuple[str, ...] = ()
    no_skip_reasons: tuple[str, ...] = ()
    case_reasons: tuple[str, ...] = ()


def gate_tt_stg_run(
    *,
    acceptance: Mapping[str, Any],
    manifest: Mapping[str, Any],
    passed_nodes: Sequence[str],
) -> TtStgGate:
    """Run every admissibility gate over a TT-STG run and return the fail-closed verdict.

    Pure function of its arguments: the acceptance result, the verification manifest, and the passed
    JUnit node ids the case tally is derived from. ``ok`` is the conjunction of all gates passing."""
    required_cases = derive_required_cases(passed_nodes)
    acceptance_reasons = gate_acceptance(acceptance)
    manifest_reasons = gate_manifest(manifest)
    no_skip_reasons = gate_no_skip(manifest)
    case_reasons = gate_required_cases(required_cases)
    reasons = [*acceptance_reasons, *manifest_reasons, *no_skip_reasons, *case_reasons]
    return TtStgGate(
        ok=not reasons,
        reasons=tuple(reasons),
        required_cases=required_cases,
        acceptance_reasons=tuple(acceptance_reasons),
        manifest_reasons=tuple(manifest_reasons),
        no_skip_reasons=tuple(no_skip_reasons),
        case_reasons=tuple(case_reasons),
    )


# --------------------------------------------------------------------------------------
# The orchestration: gate -> derive the world -> assemble the AS-25 binding.
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class TtStgRunResult:
    """The result of assembling a TT-STG DONE binding from a run.

    On a gated-OK run, ``demonstration`` is the UNSIGNED AS-25 binding (ready for the staging key to
    sign and an auditor to re-verify); on a failed gate it is None and ``reasons`` says why. Fail-closed:
    a non-None demonstration implies ``ok``."""
    ok: bool
    reasons: tuple[str, ...]
    demonstration: AegisTtDemonstration | None
    gate: TtStgGate


def build_tt_stg_demonstration(
    *,
    acceptance: Mapping[str, Any],
    manifest: Mapping[str, Any],
    passed_nodes: Sequence[str],
    repo_root: Path,
    slice_id: str,
    claim_ids: Sequence[str],
    build: BuildRef,
    ui_legs: Sequence[UiLeg],
    template_paths: Sequence[Path] | None = None,
    subject_paths: Sequence[str] = DEFAULT_SUBJECT_PATHS,
) -> TtStgRunResult:
    """Assemble an AS-25 DONE binding from a TT-STG run — gate first, then derive the world.

    The gate (``gate_tt_stg_run``) must pass or NO binding is produced (fail-closed). On pass the world
    is DERIVED, never asserted: the IaC topology digest over the AS-26 templates, the subject digest over
    the subject tree, and the case tally over the passed JUnit nodes. The binding is built through AS-25's
    ``build_demonstration`` (which itself re-derives the run digests from the manifest), so AS-1b adds the
    orchestration and the derivation while the record schema stays AS-25's. Deterministic throughout."""
    gate = gate_tt_stg_run(acceptance=acceptance, manifest=manifest, passed_nodes=passed_nodes)
    if not gate.ok:
        return TtStgRunResult(ok=False, reasons=gate.reasons, demonstration=None, gate=gate)

    templates = list(template_paths) if template_paths is not None else as26_template_paths(repo_root)
    topology = TopologyRef.model_validate({"class": "iac", "digest": iac_topology_digest(templates)})
    subject = SubjectRef(paths=list(subject_paths), digest=subject_digest(repo_root, subject_paths))

    demonstration = build_demonstration(
        manifest=dict(manifest),
        slice_id=slice_id,
        claim_ids=list(claim_ids),
        build=build,
        topology=topology,
        subject=subject,
        tenants=[str(acceptance.get("attack_tenant")), str(acceptance.get("control_tenant"))],
        ui_legs=list(ui_legs),
        required_cases=gate.required_cases,
    )
    return TtStgRunResult(ok=True, reasons=(), demonstration=demonstration, gate=gate)


@dataclass(frozen=True)
class TtStgRecord:
    """A signed TT-STG DONE record plus its self-verification — the full ``record the result`` step.

    Fail-closed: ``ok`` is True only when the run gated OK AND the signed binding re-verifies offline
    under the supplied (non-production) trust root. ``signed`` / ``verification`` are None on any failure."""
    ok: bool
    reasons: tuple[str, ...]
    signed: SignedDemonstration | None
    verification: DemonstrationVerification | None
    run: TtStgRunResult


def record_tt_stg_run(
    *,
    acceptance: Mapping[str, Any],
    manifest: Mapping[str, Any],
    passed_nodes: Sequence[str],
    repo_root: Path,
    slice_id: str,
    claim_ids: Sequence[str],
    build: BuildRef,
    ui_legs: Sequence[UiLeg],
    signers: Sequence[tuple[str, str]],
    trust_root: Any,
    environment: str,
    census_routes: set[str] | None = None,
    current_subject_digest: str | None = None,
    current_topology_digest: str | None = None,
    template_paths: Sequence[Path] | None = None,
    subject_paths: Sequence[str] = DEFAULT_SUBJECT_PATHS,
) -> TtStgRecord:
    """Assemble, SIGN and SELF-VERIFY a TT-STG DONE record — the full fail-closed ``record'' step.

    Signing is PROVISIONING (the staging control plane holds the KMS-wrapped key; ``signers`` is that
    key here and an ephemeral provisioning key in tests — never a CI runner key). The record is then
    re-verified OFFLINE through AS-25's ``verify_demonstration`` under the non-production ``trust_root``:
    a binding that the gate admitted but that does not re-verify (a bad signer, a production root, an
    off-census UI route) is denied and ``signed`` is dropped. Fail-closed: ``ok`` requires both the gate
    AND the offline self-verification to pass."""
    run = build_tt_stg_demonstration(
        acceptance=acceptance,
        manifest=manifest,
        passed_nodes=passed_nodes,
        repo_root=repo_root,
        slice_id=slice_id,
        claim_ids=claim_ids,
        build=build,
        ui_legs=ui_legs,
        template_paths=template_paths,
        subject_paths=subject_paths,
    )
    if run.demonstration is None:
        return TtStgRecord(ok=False, reasons=run.reasons, signed=None, verification=None, run=run)

    signed = sign_demonstration(run.demonstration, list(signers))
    verification = verify_demonstration(
        signed,
        manifest=dict(manifest),
        trust_root=trust_root,
        environment=environment,
        census_routes=census_routes,
        current_subject_digest=current_subject_digest,
        current_topology_digest=current_topology_digest,
    )
    if not verification.ok:
        return TtStgRecord(
            ok=False,
            reasons=tuple(f"self-verify: {r}" for r in verification.reasons),
            signed=None,
            verification=verification,
            run=run,
        )
    return TtStgRecord(ok=True, reasons=(), signed=signed, verification=verification, run=run)
