"""
report.standards — the deterministic compliance + ATT&CK mapper (C3).

These tests pin the whole point of the module: the HONESTY rule. A mapping is *data*
(the controls a class implicates); it becomes an *assertion of coverage* ONLY for a
finding a deterministic oracle actually PROVED. A LEAD — including a finding that merely
*claims* ``verified_by_oracle=True`` but whose proof does not re-fire — is capped at an
advisory note and can never occupy a proven-coverage cell.
"""

from __future__ import annotations

from framework.v2.agents.models import FindingPayload
from framework.v2.report.standards import (
    OWASP_2021_NAMES,
    STANDARD_VERSIONS,
    compliance_attestation,
    controls_for,
    coverage_matrix,
    known_mapped_classes,
    map_finding,
)
from framework.v2.verify.verifier import BUG_CLASS_ORACLES

from .conftest import make_demoted, make_fact, make_lead


# ---------------------------------------------------------------------------
# The table itself — data-driven, complete, and correctly cited.
# ---------------------------------------------------------------------------

def test_controls_for_sqli_maps_to_expected_standards() -> None:
    # canonical vocabulary: an alias spelling resolves to the same mapping.
    m = controls_for("sql_injection")
    assert m is not None
    assert m["owasp"] == "A03:2021"          # OWASP Top 10:2021 — Injection
    assert m["cwe"] == ["CWE-89"]            # the canonical SQLi weakness
    assert "T1190" in m["attack"]            # MITRE ATT&CK — Exploit Public-Facing Application
    assert "6.2.4" in m["pci_dss"]           # PCI DSS v4.0 — anti-injection engineering
    assert m["soc2"] and m["iso27001"]       # non-empty SOC 2 + ISO 27001 controls
    # the alias and the canonical class produce the identical mapping.
    assert controls_for("sqli") == m


def test_table_is_complete_over_the_oracle_vocabulary() -> None:
    # every bug_class the oracle layer can confirm must have a standards mapping, and
    # the mapper must map nothing the oracle layer does not know (kept in lock-step).
    assert known_mapped_classes() == frozenset(BUG_CLASS_ORACLES)
    for bc in BUG_CLASS_ORACLES:
        m = controls_for(bc)
        assert m is not None, f"{bc} has no mapping"
        assert m["cwe"], f"{bc} has no CWE"                       # every class cites a CWE
        assert all(c.startswith("CWE-") for c in m["cwe"]), bc
        # owasp is a Top 10:2021 id or an honest None (AI/LLM classes have no web category).
        assert m["owasp"] is None or m["owasp"] in OWASP_2021_NAMES, bc


def test_every_mapping_cites_source_versions() -> None:
    for key in ("owasp", "cwe", "pci_dss", "soc2", "iso27001", "attack"):
        assert key in STANDARD_VERSIONS and STANDARD_VERSIONS[key]
    # a per-finding mapping carries the cited versions with it.
    assert map_finding(make_fact())["sources"] == STANDARD_VERSIONS


# ---------------------------------------------------------------------------
# map_finding — the honesty gate.
# ---------------------------------------------------------------------------

def test_proven_fact_asserts_coverage() -> None:
    out = map_finding(make_fact())            # boolean_sqli, oracle re-fires → FACT
    assert out["graded"] == "fact" and out["is_fact"] is True
    assert out["status"] == "proven"
    assert out["coverage_asserted"] is True
    assert out["controls"] is not None and out["controls"]["cwe"] == ["CWE-89"]
    assert out["advisory"] is None
    # a proven fact carries its re-runnable certificate reference.
    assert out["proof"]["certificate"] and out["proof"]["certificate"].startswith("sha256:")


def test_unproven_lead_is_capped_at_a_note_and_asserts_no_coverage() -> None:
    out = map_finding(make_lead())            # idor lead, no oracle → LEAD
    assert out["graded"] == "lead"
    assert out["status"] == "advisory"
    assert out["coverage_asserted"] is False
    # the controls slot — the ASSERTION slot — is empty for a lead …
    assert out["controls"] is None
    # … the mapping is present only as an advisory NOTE (informational).
    assert out["advisory"] is not None and "CWE-639" in out["advisory"]["cwe"]
    assert "advisory" in out["note"].lower()


def test_a_lying_confirmed_flag_never_asserts_coverage() -> None:
    # THE INVARIANT: a finding may CLAIM it was oracle-confirmed, but coverage is asserted
    # only if the retained proof RE-FIRES. A stale/absent proof grades DEMOTED → no coverage.
    demoted = map_finding(make_demoted())     # verified_by_oracle=True but proof does not re-fire
    assert demoted["graded"] == "demoted"
    assert demoted["coverage_asserted"] is False and demoted["controls"] is None

    # even a raw dict that hard-asserts verified_by_oracle with NO evidence cannot buy coverage.
    liar = {
        "finding_slug": "666-liar", "title": "claims a proof it does not have",
        "severity": "Critical", "bug_class": "sqli", "surface": "GET /x", "summary": "s",
        "verified_by_oracle": True, "critique_status": "confirmed", "oracle_context": None,
    }
    out = map_finding(liar)
    assert out["coverage_asserted"] is False and out["controls"] is None
    assert out["status"] == "advisory"


def test_no_non_fact_ever_asserts_coverage() -> None:
    # exhaustive over the non-fact grades we can construct: none may assert coverage.
    for finding in (make_lead(), make_demoted()):
        assert map_finding(finding)["coverage_asserted"] is False
    # positive control so the assertion above is non-vacuous.
    assert map_finding(make_fact())["coverage_asserted"] is True


def test_unknown_bug_class_degrades_safely() -> None:
    assert controls_for("totally_made_up_class") is None
    ghost = FindingPayload(
        finding_slug="007-ghost", title="unknown class", severity="Low",
        bug_class="totally_made_up_class", surface="GET /y", summary="s",
    )
    out = map_finding(ghost)
    assert out["status"] == "unmapped"
    assert out["coverage_asserted"] is False
    assert out["controls"] is None and out["advisory"] is None
    assert "unmapped" in out["note"].lower()


def test_map_finding_is_deterministic() -> None:
    f = make_fact()
    assert map_finding(f) == map_finding(f)


# ---------------------------------------------------------------------------
# coverage_matrix — proven vs tested-clear vs not-tested.
# ---------------------------------------------------------------------------

def test_coverage_matrix_distinguishes_the_three_states() -> None:
    fact = make_fact()                        # boolean_sqli → CWE-89 proven
    matrix = coverage_matrix([fact], tested_bug_classes=["xss"])  # xss tested, no finding
    cwe = matrix["frameworks"]["cwe"]

    # PROVEN: the sqli fact implicates CWE-89, and the fact is named in the cell.
    assert cwe["CWE-89"]["status"] == "proven"
    assert fact.finding_slug in cwe["CWE-89"]["findings"]

    # TESTED_CLEAR: xss was tested but produced no finding → CWE-79 is clear, not proven.
    assert cwe["CWE-79"]["status"] == "tested_clear"
    assert cwe["CWE-79"]["findings"] == []

    # NOT_TESTED: nothing tested implicates SSRF's CWE-918.
    assert cwe["CWE-918"]["status"] == "not_tested"

    # all three states are represented in the summary.
    assert matrix["summary"]["total"]["proven"] >= 1
    assert matrix["summary"]["total"]["tested_clear"] >= 1
    assert matrix["summary"]["total"]["not_tested"] >= 1


def test_coverage_matrix_never_implies_coverage_without_testing() -> None:
    # with NO tested_bug_classes, a control the finding does not implicate is not_tested —
    # the mapper never *implies* a surface was tested clean.
    matrix = coverage_matrix([make_fact()])
    assert matrix["frameworks"]["cwe"]["CWE-79"]["status"] == "not_tested"
    assert matrix["summary"]["total"]["tested_clear"] == 0


def test_coverage_matrix_lead_occupies_no_proven_cell() -> None:
    lead = make_lead()                        # idor lead → CWE-639
    matrix = coverage_matrix([lead])
    cwe = matrix["frameworks"]["cwe"]
    # the lead's class shows as advisory, never proven.
    assert cwe["CWE-639"]["status"] == "advisory"
    assert matrix["summary"]["total"]["proven"] == 0
    # the lead's ref appears in NO proven cell across ANY framework.
    for fw_cells in matrix["frameworks"].values():
        for cell in fw_cells.values():
            if cell["status"] == "proven":
                assert lead.finding_slug not in cell["findings"]


def test_coverage_matrix_is_deterministic() -> None:
    findings = [make_fact(), make_lead()]
    assert coverage_matrix(findings, tested_bug_classes=["xss"]) == coverage_matrix(
        findings, tested_bug_classes=["xss"])


# ---------------------------------------------------------------------------
# compliance_attestation — signable, honest, deterministic.
# ---------------------------------------------------------------------------

def test_attestation_only_proven_findings_get_coverage() -> None:
    att = compliance_attestation([make_fact(), make_lead(), make_demoted()], target="acme")
    assert att["summary"] == {"findings_total": 3, "proven": 1, "advisory": 2, "unmapped": 0}

    # exactly one proven finding, and it carries a re-runnable certificate.
    assert len(att["proven_findings"]) == 1
    proven = att["proven_findings"][0]
    assert proven["controls"]["cwe"] == ["CWE-89"]
    assert proven["proof"]["certificate"].startswith("sha256:")

    # the lead + demoted are advisory notes only — never asserted coverage.
    assert len(att["advisory_findings"]) == 2
    for adv in att["advisory_findings"]:
        assert "advisory" in adv and "controls" not in adv

    # a canonical, signable content digest is present (no crypto invented, just a hash).
    assert att["content_digest"] and att["content_digest"].startswith("sha256:")


def test_attestation_is_deterministic_and_timestamp_is_explicit() -> None:
    findings = [make_fact(), make_lead()]
    a = compliance_attestation(findings, target="acme")
    b = compliance_attestation(findings, target="acme")
    assert a == b                              # no wallclock/RNG on the default path
    assert a["generated_at"] is None

    # the only non-determinism is the explicitly-passed timestamp; it changes the digest.
    stamped = compliance_attestation(findings, target="acme", generated_at="2026-07-28T00:00:00Z")
    assert stamped["generated_at"] == "2026-07-28T00:00:00Z"
    assert stamped["content_digest"] != a["content_digest"]


def test_attestation_embeds_a_coverage_matrix() -> None:
    att = compliance_attestation([make_fact()], tested_bug_classes=["xss"])
    matrix = att["coverage_matrix"]
    assert matrix["schema"] == "crucible.coverage-matrix/v1"
    assert matrix["frameworks"]["cwe"]["CWE-89"]["status"] == "proven"
