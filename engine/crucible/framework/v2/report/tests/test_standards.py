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
    OCSF_CLASS_NAMES,
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
    for key in ("owasp", "cwe", "pci_dss", "soc2", "iso27001", "attack",
                "nist_csf", "d3fend", "ocsf", "ssdf"):
        assert key in STANDARD_VERSIONS and STANDARD_VERSIONS[key]
    # a per-finding mapping carries the cited versions with it.
    assert map_finding(make_fact())["sources"] == STANDARD_VERSIONS


# ---------------------------------------------------------------------------
# Standards-wave-2 columns (M3.3): NIST CSF 2.0 · MITRE D3FEND · OCSF · NIST SSDF.
# ---------------------------------------------------------------------------

# Legal CSF 2.0 Function prefixes and SSDF practice-group prefixes (the id namespaces we cite).
_CSF_FUNCTIONS = ("GV", "ID", "PR", "DE", "RS", "RC")
_SSDF_GROUPS = ("PO", "PS", "PW", "RV")


def test_wave2_columns_complete_over_the_oracle_vocabulary() -> None:
    # COMPLETENESS: every known bug_class has a wave-2 entry with the four new columns present,
    # and each is a list (the merge + the import-time guard keep this in lock-step with the table).
    assert known_mapped_classes() == frozenset(BUG_CLASS_ORACLES)
    for bc in BUG_CLASS_ORACLES:
        m = controls_for(bc)
        assert m is not None, bc
        for key in ("nist_csf", "d3fend", "ocsf", "ssdf"):
            assert key in m and isinstance(m[key], list), f"{bc} missing {key}"
        # NIST CSF 2.0, OCSF and SSDF are ALWAYS asserted for a known class (never vacuously empty);
        # D3FEND may be an honest empty (no confidently-cited defensive technique), like ATT&CK.
        assert m["nist_csf"], f"{bc} has no NIST CSF 2.0 subcategory"
        assert m["ocsf"], f"{bc} has no OCSF class"
        assert m["ssdf"], f"{bc} has no SSDF practice"


def test_wave2_ids_are_well_formed() -> None:
    # Every cited id matches its standard's id namespace — no fabricated / malformed ids.
    for bc in BUG_CLASS_ORACLES:
        m = controls_for(bc)
        assert m is not None
        for cid in m["nist_csf"]:
            fn, _, rest = cid.partition(".")
            assert fn in _CSF_FUNCTIONS and rest, f"{bc}: bad CSF id {cid!r}"
        for cid in m["d3fend"]:
            assert cid.startswith("D3-") and len(cid) > 3, f"{bc}: bad D3FEND id {cid!r}"
        for cid in m["ocsf"]:
            # an OCSF Findings-category class_uid we label for display.
            assert cid in OCSF_CLASS_NAMES, f"{bc}: unlabeled OCSF class {cid!r}"
        for cid in m["ssdf"]:
            grp, _, rest = cid.partition(".")
            assert grp in _SSDF_GROUPS and rest, f"{bc}: bad SSDF practice {cid!r}"


def test_wave2_proven_fact_asserts_coverage_in_new_frameworks() -> None:
    # The honesty gate is framework-GENERIC: an oracle-PROVEN fact asserts coverage in the new
    # columns exactly as it does for CWE/ATT&CK. make_fact() is boolean_sqli.
    out = map_finding(make_fact())
    assert out["coverage_asserted"] is True
    controls = out["controls"]
    assert "PR.PS-06" in controls["nist_csf"]       # NIST CSF 2.0 — secure SDLC
    assert "D3-DQSA" in controls["d3fend"]          # MITRE D3FEND — DB query-string analysis
    assert "2002" in controls["ocsf"]               # OCSF — Vulnerability Finding
    assert "PW.5" in controls["ssdf"]               # SSDF — secure coding practices


def test_wave2_lead_asserts_no_coverage_in_new_frameworks() -> None:
    # a LEAD never asserts coverage in ANY framework, old or new.
    out = map_finding(make_lead())
    assert out["coverage_asserted"] is False and out["controls"] is None
    # the mapping is echoed only as an advisory NOTE, carrying the new columns informationally.
    for key in ("nist_csf", "d3fend", "ocsf", "ssdf"):
        assert key in out["advisory"]


def test_wave2_coverage_matrix_grades_tested_clear_only_for_a_tested_class() -> None:
    # make_fact() is boolean_sqli (proven). weak_tls is TESTED with no finding; ssrf is NOT tested.
    # (weak_tls maps to NIST/OCSF/SSDF controls DISJOINT from the sqli fact's, so its tested-clear
    # cells are distinguishable from the proven ones.)
    matrix = coverage_matrix([make_fact()], tested_bug_classes=["weak_tls"])
    nist = matrix["frameworks"]["nist_csf"]
    ocsf = matrix["frameworks"]["ocsf"]
    ssdf = matrix["frameworks"]["ssdf"]

    # PROVEN: the sqli fact proves its NIST/OCSF/SSDF controls.
    assert nist["PR.PS-06"]["status"] == "proven"
    assert ocsf["2002"]["status"] == "proven"
    assert ssdf["PW.5"]["status"] == "proven"

    # TESTED_CLEAR: weak_tls was tested but produced no finding → its distinct controls are clear,
    # not proven, and name no finding.
    assert nist["PR.DS-02"]["status"] == "tested_clear"
    assert nist["PR.DS-02"]["findings"] == []
    assert ocsf["2003"]["status"] == "tested_clear"
    assert ssdf["PW.9"]["status"] == "tested_clear"

    # NOT_TESTED: SSRF's PR.IR-01 was NEITHER proven NOR tested. The mapper NEVER grades an
    # untested surface as covered just because a new column references it.
    assert nist["PR.IR-01"]["status"] == "not_tested"
    # D3-OTF belongs only to the (untested) SSRF class → not_tested, never tested_clear.
    assert matrix["frameworks"]["d3fend"]["D3-OTF"]["status"] == "not_tested"

    # tested_clear appears ONLY because weak_tls was explicitly in tested_bug_classes …
    assert matrix["summary"]["nist_csf"]["tested_clear"] >= 1
    # … and never without a tested class.
    bare = coverage_matrix([make_fact()])
    assert bare["summary"]["total"]["tested_clear"] == 0


def test_wave2_attestation_stays_deterministic_and_signable() -> None:
    # the new columns ride inside the signable attestation without breaking determinism.
    findings = [make_fact(), make_lead()]
    a = compliance_attestation(findings, target="acme")
    b = compliance_attestation(findings, target="acme")
    assert a == b
    assert a["content_digest"] and a["content_digest"].startswith("sha256:")
    # the proven fact's controls carry the new columns.
    proven = a["proven_findings"][0]["controls"]
    assert proven["nist_csf"] and proven["ocsf"] and proven["ssdf"]
    # the embedded coverage matrix now spans the new frameworks.
    for fw in ("nist_csf", "d3fend", "ocsf", "ssdf"):
        assert fw in a["coverage_matrix"]["frameworks"]


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
