"""tool_manifest — the per-tool capability manifest + its invariants (integration criteria 2, 6, 12).

Every external tool VIGIL is willing to run carries a MANIFEST: its version-source, license, install method,
required privileges, network effect, danger class, and — the load-bearing fields — which VIGIL oracle family
(if any) can re-derive its output into a FACT, and whether it is EXCLUDED (offense-drift). The manifest is the
machine-readable answer to "is this tool integrated?", and its invariants encode the STRUCTURAL honesty
rules so the capability matrix cannot structurally overclaim:

  * ``excluded`` ⇒ NOT ``fact_capable`` and NOT proposable (an offense/credential tool is never a FACT source).
  * ``fact_capable`` ⇒ names a NON-EMPTY ``oracle_family`` (necessary, not sufficient — see the bound below).
  * a tool with no ``oracle_family`` is LEAD-only by construction (honest — the fallback the runner enforces).
  * a known offense/credential binary (by NAME) must be excluded regardless of its self-declared category.

HONEST BOUND: this validator checks STRUCTURE only — it does NOT verify that ``oracle_family`` names a real
oracle or that a runner-owned re-drive is wired. Those are enforced by the conformance battery
(``live.conformance.run_toolspec_conformance`` — a tool must PASS it before ``fact_capable`` is set) and by
the pinned ``fact_capable`` set test in ``test_tool_manifest`` (the CI anti-overclaim gate).

vigil_core + stdlib only (no framework import) — the manifest is pure data + validation, loadable in either env.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# The catalogue classification (Phase-1 taxonomy). An unknown category fails validation (fail-closed).
CATEGORIES = frozenset({
    "passive", "recon", "active-assessment", "exploitation", "credential-access",
    "persistence", "destructive", "local-analysis", "cloud-analysis", "unsupported",
})
# Danger classes that must NEVER be fact_capable or proposable (offense drift). Mirrors the brain's exclusion.
_EXCLUDED_CATEGORIES = frozenset({"exploitation", "credential-access", "persistence", "destructive"})
# A NAME backstop (defense-in-depth): these known offense/credential binaries must be excluded REGARDLESS of
# the self-declared category, so a row cannot relabel e.g. sqlmap as "recon" to escape the category rule.
_KNOWN_OFFENSE_BINARIES = frozenset({
    "sqlmap", "xsser", "metasploit", "msfconsole", "msfvenom", "pacu", "pwntools", "angr", "ropgadget",
    "ropper", "one-gadget", "libc-database", "pwninit", "hashpump", "hydra", "netexec", "nxc", "responder",
    "john", "hashcat",
})
NETWORK_EFFECTS = frozenset({"none", "connects-out", "scans-target", "intrusive", "sends-exploit"})
PRIVILEGES = frozenset({"none", "root", "sometimes"})


@dataclass(frozen=True)
class ToolManifest:
    name: str
    category: str
    license: str = "unknown"
    install: str = "unknown"
    privileges: str = "none"
    network_effect: str = "none"
    oracle_family: str = ""       # the VIGIL oracle a runner-owned re-drive maps to ("" ⇒ LEAD-only)
    fact_capable: bool = False    # a runner-owned oracle re-drive exists AND passes conformance
    excluded: bool = False        # offense-drift: never proposable, never a FACT source
    claim_families: tuple[str, ...] = ()
    notes: str = ""

    def to_row(self) -> dict:
        return {
            "name": self.name, "category": self.category, "license": self.license,
            "install": self.install, "privileges": self.privileges,
            "network_effect": self.network_effect, "oracle_family": self.oracle_family,
            "fact_capable": self.fact_capable, "excluded": self.excluded,
            "claim_families": list(self.claim_families), "notes": self.notes,
        }


def validate_manifest(m: ToolManifest) -> list[str]:
    """Return a list of invariant violations (empty ⇒ valid). Fail-closed honesty rules:
    excluded⇒not-fact_capable, fact_capable⇒oracle_family set, enum membership, and — the H5 "never
    silently missing" rule — every tool that is NOT fact_capable must carry a REASON in ``notes`` (why it is
    LEAD-only / EXCLUDED / UNAVAILABLE), so an un-adapted catalogue tool cannot sit in the matrix unexplained."""
    errs: list[str] = []
    if not m.name:
        errs.append("empty tool name")
    if m.category not in CATEGORIES:
        errs.append(f"{m.name}: unknown category {m.category!r}")
    if m.network_effect not in NETWORK_EFFECTS:
        errs.append(f"{m.name}: unknown network_effect {m.network_effect!r}")
    if m.privileges not in PRIVILEGES:
        errs.append(f"{m.name}: unknown privileges {m.privileges!r}")
    if m.excluded and m.fact_capable:
        errs.append(f"{m.name}: EXCLUDED tool cannot be fact_capable (offense-drift honesty invariant)")
    if m.category in _EXCLUDED_CATEGORIES and not m.excluded:
        errs.append(f"{m.name}: category {m.category!r} MUST be excluded (offense/credential/persistence/destructive)")
    if m.name.lower() in _KNOWN_OFFENSE_BINARIES and not m.excluded:
        errs.append(f"{m.name}: known offense/credential binary MUST be excluded (name backstop — a "
                    f"relabeled category cannot escape exclusion)")
    if m.fact_capable and not m.oracle_family:
        errs.append(f"{m.name}: fact_capable requires a non-empty oracle_family (a FACT needs an oracle re-drive)")
    if m.fact_capable and m.excluded:
        errs.append(f"{m.name}: cannot be both fact_capable and excluded")
    # H5 CI sync-check: a catalogue tool NOT adapted to a FACT must render BLOCKED/UNAVAILABLE/LEAD-only WITH
    # A REASON — never silently missing. A non-fact_capable row therefore MUST carry a non-empty notes reason.
    if not m.fact_capable and not (m.notes or "").strip():
        errs.append(f"{m.name}: a non-fact_capable tool MUST carry a REASON in notes (why it is "
                    f"LEAD-only / EXCLUDED / UNAVAILABLE) — never silently missing")
    return errs


def load_manifests(path: str | Path) -> list[ToolManifest]:
    """Load the capability-matrix JSON into ToolManifest rows (a list of dicts under key ``tools``)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data.get("tools", data) if isinstance(data, dict) else data
    out: list[ToolManifest] = []
    for r in rows:
        out.append(ToolManifest(
            name=str(r.get("name", "")), category=str(r.get("category", "unsupported")),
            license=str(r.get("license", "unknown")), install=str(r.get("install", "unknown")),
            privileges=str(r.get("privileges", "none")), network_effect=str(r.get("network_effect", "none")),
            oracle_family=str(r.get("oracle_family", "")), fact_capable=bool(r.get("fact_capable", False)),
            excluded=bool(r.get("excluded", False)),
            claim_families=tuple(str(c) for c in (r.get("claim_families") or [])),
            notes=str(r.get("notes", ""))))
    return out


def validate_all(manifests: list[ToolManifest]) -> list[str]:
    """Validate every manifest + cross-row invariants (unique names). Empty ⇒ the matrix is sound."""
    errs: list[str] = []
    seen: set[str] = set()
    for m in manifests:
        errs.extend(validate_manifest(m))
        if m.name in seen:
            errs.append(f"duplicate manifest name {m.name!r}")
        seen.add(m.name)
    return errs


def validate_capability_sync(proposable_tools: Iterable[str],
                             manifests: list[ToolManifest]) -> list[str]:
    """The H4 CROSS-REGISTRY sync invariant: every tool the PLANNER can propose must be RENDERED in the
    capability matrix WITH A REASON — LEAD-only / UNAVAILABLE / BLOCKED / EXCLUDED — never silently absent.

    ``validate_manifest`` (above) owns the per-row honesty rules — ``excluded ⇒ ¬fact_capable``,
    ``fact_capable ⇒ oracle_family``, the ``_KNOWN_OFFENSE_BINARIES`` name backstop, and the "non-fact_capable
    ⇒ a REASON in notes" rule. But a single row cannot see a tool the planner proposes that has NO row at
    all, and that is exactly the silent-disappearance defect H4 fixes: the planner lists a tool, the executor
    denies it fail-closed (no typed argv builder / excluded), and no committed surface says why. This
    validator closes the gap by joining the planner's proposable set against the matrix rows.

    ``proposable_tools`` is the planner's catalogue of names (the keys of the brain's ``_TOOL_DANGER`` map),
    passed as DATA so this module stays vigil_core + stdlib only (no brain/framework import). A proposable
    tool satisfies the invariant iff:

      * it has a manifest row (never absent), AND
      * that row carries a non-empty ``notes`` reason (so its BLOCKED/UNAVAILABLE/LEAD-only status is
        explained). An excluded row already must carry a reason via ``validate_manifest``, so an
        ``excluded``-with-reason tool passes here too — the "OR explicitly excluded-with-a-reason" branch.

    Returns the list of violations (empty ⇒ every proposable tool is rendered, with a reason).
    """
    errs: list[str] = []
    by_name = {m.name: m for m in manifests}
    for name in sorted({str(t) for t in proposable_tools if str(t).strip()}):
        m = by_name.get(name)
        if m is None:
            errs.append(
                f"{name}: PLANNER-PROPOSABLE but ABSENT from the capability matrix — a planned tool must be "
                f"rendered UNAVAILABLE/BLOCKED with a reason, never silently missing. Add a matrix row "
                f"(excluded-with-reason, or LEAD-only with a reason in notes)."
            )
            continue
        if not (m.notes or "").strip():
            errs.append(
                f"{name}: proposable AND in the matrix but rendered WITHOUT a reason (empty notes) — the "
                f"status (BLOCKED / UNAVAILABLE / LEAD-only) must say why, so the tool is never silently "
                f"missing from a plan."
            )
    return errs


# ---------------------------------------------------------------------------
# The EVIDENCE-BRANCH registry (docs/capability-matrix/evidence-branches.json) — the SAME single ladder the
# claim-discipline tests enforce, NOT a parallel registry. This validator owns the two structural invariants
# over the S8 schema columns, mirroring the tool-manifest rules above (fact_capable ⇒ oracle_family;
# excluded ⇒ not fact_capable):
#
#   * ``fact_capable`` ⇒ a NON-EMPTY ``oracle_version`` (a FACT is adjudicated by a NAMED, versioned oracle —
#     the certificate binds ``verify.oracle_version(kind)`` at mint, so a branch cannot claim FACT-capability
#     without declaring which decision procedure re-derives it). Necessary, not sufficient: whether that name
#     is a REAL OracleKind whose source resolves is enforced in the offense-leg ladder test, where framework
#     is importable — this module stays vigil_core + stdlib only (loadable in either env).
#   * NOT ``fact_capable`` ⇒ ``oracle_version`` is EMPTY. A LEAD-only branch has no oracle adjudicating it
#     into a FACT yet; naming one would be the same overclaim as a scanner-report FACT. The gap is named in
#     ``blocking_work``, never papered over with a borrowed oracle version.
#   * ``control_requirements`` is a NON-EMPTY list of NON-EMPTY strings on EVERY branch — the standing
#     controls (gates / VIGIL-owned captures / instrumentation / parses) the branch depends on. For a
#     LEAD-only branch these name the MISSING controls; a branch that depends on no control is a red flag,
#     so the empty list is rejected fail-closed.

_BRANCH_BOOL_FIELDS = ("fact_capable", "clean_capable", "target_fact_capable", "target_clean_capable")


def validate_branch_row(row: dict) -> list[str]:
    """Return this evidence branch's S8-column invariant violations (empty ⇒ the row's new columns are
    sound). Pure structure over dict data — no framework import, so it runs in the sovereign leg too."""
    errs: list[str] = []
    bid = str(row.get("id") or "")
    if not bid:
        errs.append("evidence branch without an id")

    fact_capable = bool(row.get("fact_capable", False))
    ov = row.get("oracle_version", None)
    if not isinstance(ov, str):
        errs.append(f"{bid}: oracle_version must be a string (an OracleKind value, or empty for LEAD-only)")
        ov = ""
    if fact_capable and not ov:
        errs.append(f"{bid}: fact_capable requires a non-empty oracle_version (a FACT needs a named, "
                    f"versioned oracle — mirrors fact_capable ⇒ oracle_family)")
    if not fact_capable and ov:
        errs.append(f"{bid}: LEAD-only branch (fact_capable=false) must not name an oracle_version — no "
                    f"oracle adjudicates it into a FACT yet; name the gap in blocking_work instead")

    creq = row.get("control_requirements", None)
    if not isinstance(creq, list) or not creq:
        errs.append(f"{bid}: control_requirements must be a non-empty list (the standing controls the "
                    f"branch depends on; a LEAD-only branch names the MISSING controls here)")
    else:
        for c in creq:
            if not isinstance(c, str) or not c.strip():
                errs.append(f"{bid}: control_requirements entries must be non-empty strings, got {c!r}")
    return errs


def load_branch_registry(path: str | Path) -> list[dict]:
    """Load the evidence-branch ladder's rows (the list under key ``branches``). Reads THE registry, not a
    copy — the SAME file admission and the claim-discipline tests use."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data.get("branches", data) if isinstance(data, dict) else data
    return [r for r in rows if isinstance(r, dict)]


def validate_branch_registry(rows: list[dict]) -> list[str]:
    """Validate every evidence branch's S8 columns + cross-row uniqueness. Empty ⇒ the new columns are
    sound across the ladder."""
    errs: list[str] = []
    seen: set[str] = set()
    for r in rows:
        errs.extend(validate_branch_row(r))
        bid = str(r.get("id") or "")
        if bid and bid in seen:
            errs.append(f"duplicate evidence branch id {bid!r}")
        seen.add(bid)
    return errs
