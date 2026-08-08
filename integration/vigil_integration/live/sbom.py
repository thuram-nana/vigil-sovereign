"""sbom — VIGIL-direct SBOM / dependency-CVE FACT capability (Phase-1, VERSION_RANGE oracle family).

The first FACT-capable family that needs NO external tool: VIGIL parses the target's OWN manifest/lockfile
for CONCRETE package versions (the authoritative version channel — not a scanner's say-so), looks each up in
a PINNED, vendored OSV snapshot, and drives the deterministic ``version_range`` oracle over the retained
``{package, version, affected}`` evidence via ``oracle_adapter.confirm_and_certify``. A package version that
PROVABLY falls in an advisory's affected range mints a signed, offline-re-verifiable FACT; anything else is a
labelled LEAD. A grype/syft/trivy/osv-scanner run is only a PROPOSER of where to look — its CVE match never
mints a FACT; VIGIL's own parse + ``version_in_affected`` is the sole authority (the criterion-6 firewall).

provenance="reproduced": the evidence is re-derived by VIGIL from the operator-supplied manifest bytes + the
vendored advisory DB — a non-LLM channel — so the anti-hallucination gate admits it (never "llm").

FATAL-2: the framework imports (confirm_and_certify) are FUNCTION-LOCAL; the manifest parsers + OSV loader are
pure stdlib, so importing this module co-loads no offense engine.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SbomResult:
    ecosystem: str
    packages: int                       # concrete (package, version) pairs parsed
    facts: list = field(default_factory=list)     # AdapterResult (status=="fact"), signed
    leads: list = field(default_factory=list)     # AdapterResult (status=="lead")
    contexts: dict = field(default_factory=dict)  # finding_ref -> oracle_context (offline re-verify)
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)


# --------------------------------------------------------------------------------------------------
# Manifest parsers — pure stdlib; return normalized [(package, version)] with CONCRETE (pinned) versions
# only. A non-pinned constraint (">=1.0", "^4.17") is NOT a concrete version → skipped (never guessed).
# --------------------------------------------------------------------------------------------------
_REQ_PIN = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)\s*(?:;.*)?$")


def parse_requirements_txt(text: str) -> list[tuple[str, str]]:
    """Parse a pip ``requirements.txt`` — ONLY exact ``name==version`` pins (the authoritative concrete
    version). Comments, blanks, ``-r``/``-e``/URLs, and non-pinned constraints are skipped. Package names
    are lowercased (PyPI is case-insensitive + normalises ``_``/``.`` to ``-``)."""
    out: list[tuple[str, str]] = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0]
        m = _REQ_PIN.match(line)
        if m:
            name = re.sub(r"[._]+", "-", m.group(1).strip().lower())
            out.append((name, m.group(2).strip()))
    return out


def parse_package_lock(text: str) -> list[tuple[str, str]]:
    """Parse an npm ``package-lock.json`` (v1 ``dependencies`` and v2/v3 ``packages``) — each entry's
    resolved concrete ``version``. Names are taken as-is (npm is case-sensitive); the root package ("") and
    entries without a concrete version are skipped. Never raises on malformed JSON (returns [])."""
    try:
        data = json.loads(text or "{}")
    except (json.JSONDecodeError, TypeError, RecursionError):
        return []   # malformed OR a pathologically-deep doc that recurses json.loads → fail-safe empty
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(name: str, version: Any) -> None:
        if name and isinstance(version, str) and version and (name, version) not in seen:
            seen.add((name, version))
            out.append((name, version))

    for path, meta in (data.get("packages") or {}).items():   # v2/v3
        if not path:
            continue  # the root package
        name = path.split("node_modules/")[-1]
        if isinstance(meta, dict):
            _add(name, meta.get("version"))

    def _walk(deps: Any, depth: int = 0) -> None:              # v1 (recursive, depth-capped)
        if not isinstance(deps, dict) or depth > 200:          # a hostile/degenerate lockfile can't blow the stack
            return
        for name, meta in deps.items():
            if isinstance(meta, dict):
                _add(name, meta.get("version"))
                _walk(meta.get("dependencies"), depth + 1)

    _walk(data.get("dependencies"))
    return out


_PARSERS = {
    "PyPI": ("requirements.txt", parse_requirements_txt),
    "npm": ("package-lock.json", parse_package_lock),
}


class SnapshotError(ValueError):
    """A malformed OSV snapshot — fail-closed at load rather than risk an over-broad range at verify."""


def load_osv_snapshot(path: str | Path) -> dict:
    """Load + VALIDATE the pinned vendored OSV snapshot → ``{ecosystem: {package: [advisory, ...]}}``.

    Every advisory's ``affected`` MUST be a list of dict ranges of the form ``{introduced, fixed}`` /
    ``{introduced, last_affected}`` (an ``introduced`` is required). Bare comparator STRINGS (``">=1.0"``)
    are REJECTED here (red-pen LOW-1): the dict path fail-closes on an open-ended range but the
    comparator-string path does not, so a curator writing ``">=0"`` could mint a FACT for every version.
    Requiring dict-form-with-explicit-bounds at load removes that foot-gun before any adjudication."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    ecosystems = data.get("ecosystems", {}) if isinstance(data, dict) else {}
    for eco, pkgs in ecosystems.items():
        for pkg, advisories in (pkgs or {}).items():
            for adv in (advisories or []):
                affected = adv.get("affected")
                if not isinstance(affected, list) or not affected:
                    raise SnapshotError(f"{eco}:{pkg}: advisory {adv.get('vuln_id')!r} has no affected-range list")
                for rng in affected:
                    if not isinstance(rng, dict) or "introduced" not in rng:
                        raise SnapshotError(
                            f"{eco}:{pkg}: advisory {adv.get('vuln_id')!r} range {rng!r} is not a dict with "
                            f"'introduced' (comparator strings are rejected — use {{introduced, fixed}})")
    return ecosystems


def _advisories_for(osv: dict, ecosystem: str, package: str) -> list[dict]:
    eco = osv.get(ecosystem, {})
    # PyPI lookup is normalised; npm is case-sensitive.
    key = re.sub(r"[._]+", "-", package.lower()) if ecosystem == "PyPI" else package
    if ecosystem == "PyPI":
        eco = {re.sub(r"[._]+", "-", k.lower()): v for k, v in eco.items()}
    return list(eco.get(key, []) or [])


def sbom_verify(
    manifest_text: str,
    *,
    ecosystem: str,
    osv: dict,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
) -> SbomResult:
    """Parse ``manifest_text`` for the given ``ecosystem``, look each concrete package version up in the
    ``osv`` snapshot, and mint a signed FACT for every package version the ``version_range`` oracle PROVES
    is in an advisory's affected range. VIGIL's parse + the oracle are the sole authority — a scanner's CVE
    claim is never trusted. Returns an :class:`SbomResult` (facts + leads + retained contexts)."""
    from ..oracle_adapter import confirm_and_certify  # noqa: PLC0415 (FATAL-2: function-local)

    parser = _PARSERS.get(ecosystem)
    if parser is None:
        return SbomResult(ecosystem=ecosystem, packages=0,
                          notes=[f"unsupported ecosystem {ecosystem!r} (have: {sorted(_PARSERS)})"])
    pkgs = parser[1](manifest_text)
    res = SbomResult(ecosystem=ecosystem, packages=len(pkgs))
    for package, version in pkgs:
        for adv in _advisories_for(osv, ecosystem, package):
            advisory = {
                "package": package, "version": version, "ecosystem": ecosystem,
                "vuln_id": str(adv.get("vuln_id", "")), "affected": adv.get("affected", []),
            }
            from framework.v2.verify.version import vulnerable_dependency_context  # noqa: PLC0415
            oracle_context = vulnerable_dependency_context(advisory)
            finding = {
                "check_id": f"sbom:{ecosystem}:{package}@{version}:{advisory['vuln_id']}",
                "bug_class": "vulnerable_dependency",
                "insertion_point": f"{ecosystem}:{package}",
                "oracle_context": oracle_context,
            }
            r = confirm_and_certify(finding, engagement_slug=engagement_slug, signers=signers,
                                    provenance="reproduced")
            res.contexts[r.finding_ref] = oracle_context
            (res.facts if r.is_fact else res.leads).append(r)
    return res
