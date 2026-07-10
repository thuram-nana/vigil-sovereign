"""
Tests for Wave 5b — the SBOM/SCA vulnerability sensor.

grype / osv-scanner output is ingested (offline) as a gated sensor → PACKAGE observations + vulnerable-
dependency LEADS; the version-range oracle re-verifies a lead to a FACT only when the version provably
falls in the advisory's affected range. The sensor never mints a confirmed vuln — the oracle does.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext
from framework.v2.intel.ingest import IntelIngest
from framework.v2.sensors import SbomVulnSensor, default_registry, parse_sca_report
from framework.v2.verify import confirm_vulnerable_dependency
from framework.v2.worldmodel.graph import WorldModel


_GRYPE = """
{"matches": [
  {"vulnerability": {"id": "CVE-2021-44228"},
   "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"},
   "matchDetails": [{"found": {"versionConstraint": ">=2.0.0,<2.15.0 (unknown)"}}]},
  {"vulnerability": {"id": "CVE-2021-45046"},
   "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"},
   "matchDetails": [{"found": {"versionConstraint": ">=2.0.0,<2.16.0"}}]}
]}
"""

_OSV = """
{"results": [{"packages": [
  {"package": {"name": "django", "version": "3.2.4", "ecosystem": "PyPI"},
   "vulnerabilities": [{"id": "GHSA-xxxx",
     "affected": [{"ranges": [{"type": "ECOSYSTEM",
       "events": [{"introduced": "3.2.0"}, {"fixed": "3.2.5"}]}]}]}]}
]}]}
"""


def test_parse_grype_and_osv() -> None:
    g = parse_sca_report(_GRYPE)
    assert len(g) == 2 and g[0]["package"] == "log4j-core" and g[0]["version"] == "2.14.1"
    assert g[0]["affected"] == [">=2.0.0,<2.15.0 (unknown)"]
    o = parse_sca_report(_OSV)
    assert len(o) == 1 and o[0]["package"] == "django"
    assert o[0]["affected"] == [{"introduced": "3.2.0", "fixed": "3.2.5"}]


def test_parse_is_total_on_garbage() -> None:
    for junk in ["", "not json", "[]", "{}", '{"weird": 1}']:
        assert parse_sca_report(junk) == []


def test_sensor_ingests_report_and_mints_package_leads(tmp_path: Path) -> None:
    report = tmp_path / "grype.json"
    report.write_text(_GRYPE, encoding="utf-8")
    s = SbomVulnSensor()
    res = s.run({"report": str(report)}, ToolContext(slug="alpha"))
    assert res.ok
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(s.normalize(res, ToolContext(slug="alpha"), seq=1), seq=1)
    # the vulnerable package is a PACKAGE node (GROUNDING_INTEL lead), deduped across the two CVEs
    assert world.has_node("package:log4j-core@2.14.1")
    assert world.get_node("package:log4j-core@2.14.1").provenance.startswith("intel:")
    # the advisory evidence feeds the oracle: this version IS in range -> CONFIRMED a fact
    advs = s.advisories(res)
    assert any(confirm_vulnerable_dependency(a).confirmed for a in advs)


def test_sensor_lead_for_a_patched_version_does_not_confirm(tmp_path: Path) -> None:
    patched = _GRYPE.replace("2.14.1", "2.17.1")
    report = tmp_path / "grype.json"
    report.write_text(patched, encoding="utf-8")
    s = SbomVulnSensor()
    res = s.run({"report": str(report)}, ToolContext(slug="alpha"))
    # the scanner still "matched" (a LEAD), but the oracle refuses — the version is out of range
    assert res.ok and not any(confirm_vulnerable_dependency(a).confirmed for a in s.advisories(res))


def test_sensor_missing_and_absent_report_degrade_cleanly(tmp_path: Path) -> None:
    assert not SbomVulnSensor().run({}, ToolContext(slug="alpha")).ok
    assert not SbomVulnSensor().run({"report": "/no/such.json"}, ToolContext(slug="alpha")).ok


def test_registered_in_default_registry() -> None:
    assert "sbom_vuln" in default_registry()
