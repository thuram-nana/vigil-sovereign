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
    excluded⇒not-fact_capable, fact_capable⇒oracle_family set, and enum membership."""
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
