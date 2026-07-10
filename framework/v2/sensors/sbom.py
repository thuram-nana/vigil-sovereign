"""
sensors.sbom — supply-chain vulnerability sensor (Wave 5b): grype / osv-scanner output as a gated
producer of vulnerable-dependency LEADS the version-range oracle re-verifies to FACTS.

CRUCIBLE is a reasoning OS: an SCA scanner is a gated SENSOR whose output enters the ONE world-model as
a provenance-tagged OBSERVATION — a LEAD (``GROUNDING_INTEL``), NEVER a fact. "grype says package X @ V
is affected by CVE-Y" is a third-party match; CRUCIBLE's ``verify.version.version_range_oracle`` promotes
it to a ``fact`` ONLY when V provably falls in the advisory's affected range. This sensor ingests the
scanner's JSON (OFFLINE — a report the operator supplies, like the SBOM file-ingest) and mints:

  * a ``PACKAGE`` observation per component (name + version), and
  * a vulnerable-dependency LEAD per match, carrying the JSON-safe ``advisory`` evidence
    ({package, version, vuln_id, ecosystem, affected}) so the oracle can re-derive membership offline.

Doctrine: prove-don't-guess (the scanner's match is a LEAD, the oracle proves the fact); passive/offline
(reads a local report — Tier-1, no egress, no entitlement, kill-switch-gated via ``run_sensor``);
degrades cleanly (no report / malformed JSON -> a failed ToolResult, never a crash); deterministic
(parse -> observation is a pure, replayable function; claim-keyed obs_ids are idempotent).
"""

from __future__ import annotations

import json
import os
import re

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef
from ..worldmodel.models import NodeKind
from .base import service_observations  # noqa: F401  (kept for parity; sbom mints its own PACKAGE nodes)

# An SCA scanner match: a reliable tool, but a version-range CLAIM that is not proof until the oracle
# re-derives membership. Admiralty B2 — the finding is a lead, never an auto-fact.
_SCA_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)

# grype appends a trailing version-format tag to every versionConstraint (" (unknown)", " (python)",
# " (apk)", ...) — a comment, not part of the range.
_GRYPE_FMT_SUFFIX = re.compile(r"\s*\([^)]*\)\s*$")


def _advisories_from_grype(report: dict) -> list[dict]:
    """Extract advisory-match evidence from a ``grype -o json`` report. The affected range comes from
    each match's ``matchDetails[].found.versionConstraint`` (a comparator string like ``>=2.0,<2.15``)."""
    out: list[dict] = []
    for m in report.get("matches", []) or []:
        if not isinstance(m, dict):
            continue
        art = m.get("artifact") or {}
        vuln = m.get("vulnerability") or {}
        name = str(art.get("name") or "").strip()
        version = str(art.get("version") or "").strip()
        if not name or not version:
            continue
        constraints = []
        for d in m.get("matchDetails", []) or []:
            found = (d or {}).get("found") or {}
            c = found.get("versionConstraint")
            if isinstance(c, str) and c.strip():
                # grype ALWAYS appends a trailing format tag, e.g. ">=2.0.0,<2.15.0 (unknown)" /
                # "< 2.17.1 (python)" — strip it so the oracle's comparator does not read "(unknown)"
                # as an unparseable clause and fail the whole (real) constraint closed.
                constraints.append(_GRYPE_FMT_SUFFIX.sub("", c).strip())
        out.append({
            "package": name, "version": version,
            "vuln_id": str(vuln.get("id") or "").strip(),
            "ecosystem": str(art.get("type") or "").strip(),
            "affected": constraints,
        })
    return out


def _advisories_from_osv(report: dict) -> list[dict]:
    """Extract advisory-match evidence from an ``osv-scanner --json`` report. Each vulnerability's
    ``affected[].ranges[].events`` map directly onto the oracle's OSV ``{introduced, fixed}`` form."""
    out: list[dict] = []
    for res in report.get("results", []) or []:
        for pkg in (res or {}).get("packages", []) or []:
            info = (pkg or {}).get("package") or {}
            name = str(info.get("name") or "").strip()
            version = str(info.get("version") or "").strip()
            eco = str(info.get("ecosystem") or "").strip()
            if not name or not version:
                continue
            for v in (pkg or {}).get("vulnerabilities", []) or []:
                ranges: list[dict] = []
                for aff in (v or {}).get("affected", []) or []:
                    for rng in (aff or {}).get("ranges", []) or []:
                        cur: dict = {}
                        for ev in (rng or {}).get("events", []) or []:
                            if "introduced" in ev:
                                if cur.get("fixed") or cur.get("last_affected"):
                                    ranges.append(cur); cur = {}
                                cur["introduced"] = str(ev["introduced"])
                            elif "fixed" in ev:
                                cur["fixed"] = str(ev["fixed"])
                            elif "last_affected" in ev:
                                cur["last_affected"] = str(ev["last_affected"])
                        if cur:
                            ranges.append(cur)
                out.append({
                    "package": name, "version": version,
                    "vuln_id": str((v or {}).get("id") or "").strip(),
                    "ecosystem": eco, "affected": ranges,
                })
    return out


def parse_sca_report(text: str) -> list[dict]:
    """Parse a grype OR osv-scanner JSON report into advisory-match evidence dicts (auto-detecting the
    format). PURE and total — invalid JSON / an unknown shape yields ``[]``, never an exception."""
    try:
        report = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(report, dict):
        return []
    if "matches" in report:
        return _advisories_from_grype(report)
    if "results" in report:
        return _advisories_from_osv(report)
    return []


def sca_observations(advisories: list[dict], *, seq: int, source: str = "sbom") -> list[Observation]:
    """Mint a PACKAGE observation per (package, version) from parsed advisory matches. The vulnerability
    itself is a LEAD carried in the advisory evidence (for the version-range oracle) — the observation
    records the package as GROUNDING_INTEL, never a confirmed vulnerability. Claim-keyed obs_ids so
    re-ingest is idempotent; pure (no wallclock/rng)."""
    out: list[Observation] = []
    seen: set[str] = set()
    for adv in advisories:
        name = str(adv.get("package") or "").strip()
        version = str(adv.get("version") or "").strip()
        if not name:
            continue
        key = f"{name}@{version}".lower()
        if key in seen:
            continue
        seen.add(key)
        ref = EntityRef(kind=NodeKind.PACKAGE, key=key)
        out.append(Observation(
            obs_id=f"{source}:{seq}:{ref.node_id}||",
            source=source, source_kind=IntelSourceKind.VULN_DB, collector=source,
            subject=ref, relation=None, object=None,
            attrs={k: v for k, v in {"name": name, "version": version,
                                     "ecosystem": adv.get("ecosystem") or None}.items() if v},
            source_reliability=_SCA_RELIABILITY, confidence=0.85, seq=seq))
    return out


class SbomVulnSensor:
    """Ingest an operator-provided grype / osv-scanner JSON report and mint PACKAGE observations +
    vulnerable-dependency leads. args: ``{"report": "/path/to/grype.json"}``. Passive (Tier-1): reads a
    local file, no network, no entitlement. The vuln leads are re-verified to facts by the
    version-range oracle (``verify.version``)."""

    name = "sbom_vuln"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        report = args.get("report") if isinstance(args, dict) else None
        if not report or not isinstance(report, str):
            return ToolResult(ok=False, note="sbom_vuln requires args['report'] (a grype/osv-scanner JSON path)")
        if not os.path.isfile(report):
            return ToolResult(ok=False, note=f"sbom_vuln: report not found: {report}")
        try:
            text = open(report, "r", encoding="utf-8", errors="replace").read()
        except OSError as e:
            return ToolResult(ok=False, note=f"sbom_vuln: could not read report: {e}")
        advisories = parse_sca_report(text)
        return ToolResult(ok=True, summary=f"sbom: {len(advisories)} advisory match(es)",
                          output={"advisories": advisories})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        advisories = out.get("advisories")
        if not isinstance(advisories, list):
            return []
        return sca_observations(advisories, seq=seq, source="sbom")

    def advisories(self, result: ToolResult) -> list[dict]:
        """The advisory-match evidence for the version-range oracle (``confirm_vulnerable_dependency``)."""
        out = result.output or {}
        adv = out.get("advisories")
        return adv if isinstance(adv, list) else []
