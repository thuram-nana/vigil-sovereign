"""
Report enrichment via ``scanner.report._CHECK_META`` — the check-id-scoped metadata
source that lets the ``ssrf-oob`` library JSON be removed BYTE-IDENTICALLY.

Background (Wave-7 debt closeout). ``scanner/library_entries/ssrf.json`` had id
``ssrf-oob``, which collides with the ``SSRF_OOB`` code seed's id. ``report._meta_for``
enriches a finding's report severity/remediation/references by ``check_id``
(``lib.get(check_id)``), so that JSON was the *report metadata source* for out-of-band
SSRF findings — it carried CAPEC-664 and richer remediation prose that the per-class
fallback ``_CLASS_META["ssrf"]`` does not. Deleting it naively would silently drop
CAPEC-664 and change the remediation text on any ``enable_oob=True`` report.

The byte-identical path: migrate that EXACT metadata into ``report._CHECK_META["ssrf-oob"]``
(consulted only when ``lib.get(check_id)`` is None) and then delete the JSON. These tests
pin the migrated values to the JSON's originals and prove:

  * the ``ssrf-oob`` report metadata is unchanged after the JSON removal, and
  * the check-id-scoped map does NOT leak into any *other* ssrf finding's report.
"""

from __future__ import annotations

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.library import load_library
from framework.v2.scanner.report import (
    _CHECK_META,
    _CLASS_META,
    _meta_for,
    build_report,
)

# The EXACT values that scanner/library_entries/ssrf.json shipped (id "ssrf-oob"),
# reproduced here so any drift from the removed JSON's report metadata fails a test.
_SSRF_OOB_SEVERITY = "High"
_SSRF_OOB_REMEDIATION = (
    "Do not let user input drive server-side fetches. Enforce an allowlist of permitted "
    "hosts/schemes, block requests to internal/link-local ranges and the cloud metadata "
    "endpoint, and disable unneeded URL schemes."
)
_SSRF_OOB_REFERENCES = ["CWE-918", "CAPEC-664"]


def _ssrf_oob_finding() -> AuditFinding:
    return AuditFinding(
        check_id="ssrf-oob", bug_class="ssrf",
        insertion_point="query_value:url", param="url", endpoint="http://t/x",
        confidence=0.9, confirmed_by="oob", rationale="callback fired",
        oracle_context=None,
    )


def test_ssrf_json_is_removed_from_the_library() -> None:
    """The duplicate library entry is gone; its metadata lives in code (_CHECK_META)."""
    assert "ssrf-oob" not in {e.id for e in load_library()}


def test_check_meta_holds_exact_ssrf_oob_metadata() -> None:
    sev, rem, refs = _CHECK_META["ssrf-oob"]
    assert sev == _SSRF_OOB_SEVERITY
    assert rem == _SSRF_OOB_REMEDIATION
    assert refs == _SSRF_OOB_REFERENCES  # CAPEC-664 must survive the JSON removal


def test_meta_for_ssrf_oob_matches_the_removed_json_with_empty_lib() -> None:
    """Empty library (== the JSON gone) → _CHECK_META supplies the exact old metadata."""
    assert _meta_for("ssrf-oob", "ssrf", {}) == (
        _SSRF_OOB_SEVERITY, _SSRF_OOB_REMEDIATION, _SSRF_OOB_REFERENCES,
    )


def test_meta_for_ssrf_oob_matches_over_the_live_library() -> None:
    """End-to-end over the REAL (post-removal) library: lib.get('ssrf-oob') is None, so
    the report layer falls through to _CHECK_META and returns byte-identical metadata."""
    lib = {e.id: e for e in load_library()}
    assert _meta_for("ssrf-oob", "ssrf", lib) == (
        _SSRF_OOB_SEVERITY, _SSRF_OOB_REMEDIATION, _SSRF_OOB_REFERENCES,
    )


def test_check_meta_does_not_leak_to_other_ssrf_findings() -> None:
    """The map is keyed by check_id, so any OTHER ssrf finding (no library entry, id not in
    _CHECK_META) still falls through to the per-class default — no collateral change."""
    assert _meta_for("some-other-ssrf-check", "ssrf", {}) == _CLASS_META["ssrf"]
    # and the per-class SSRF default is deliberately DISTINCT from the ssrf-oob metadata,
    # so this test would catch a regression that pointed ssrf-oob at the class fallback.
    assert _CLASS_META["ssrf"][1] != _SSRF_OOB_REMEDIATION
    assert "CAPEC-664" not in _CLASS_META["ssrf"][2]


def test_meta_for_returns_a_fresh_reference_list() -> None:
    """_meta_for must not hand back the module-level list — mutating the result must not
    corrupt _CHECK_META (matches the library path's list(entry.references) semantics)."""
    _, _, refs = _meta_for("ssrf-oob", "ssrf", {})
    refs.append("CWE-0000")
    assert _CHECK_META["ssrf-oob"][2] == _SSRF_OOB_REFERENCES


def test_rendered_ssrf_oob_report_carries_capec_664_and_prose() -> None:
    """The rendered report document (what an operator/CI actually sees) carries the exact
    ssrf.json severity/remediation/references for an OOB-SSRF finding after the removal."""
    rep = ScanReport(target="http://t")
    rep.active_findings = [_ssrf_oob_finding()]
    # grounding passed explicitly so build_report does not re-execute the oracle; metadata
    # enrichment is independent of grounding.
    doc = build_report(rep, grounding=[None])
    fd = doc["findings"][0]
    assert fd["severity"] == _SSRF_OOB_SEVERITY
    assert fd["remediation"] == _SSRF_OOB_REMEDIATION
    assert fd["references"] == _SSRF_OOB_REFERENCES
