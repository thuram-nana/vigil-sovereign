"""Government-demo additions — compliance mapping, business-impact chains, evidence endpoint.

These test the range-side wiring (mapping tables + endpoints). The live engine legs (SARIF export, the
signed evidence certify→verify) are validated separately end-to-end.
"""

from __future__ import annotations

import json
import os
import urllib.request

from vigil_range.rangecontrol import compliance, impact


# --- pure mapping logic (no server) ----------------------------------------------------------------
def test_compliance_maps_every_planted_class():
    from vigil_range.meridian.vulns import VULNS
    for v in VULNS:
        row = compliance.mapped_row(v.vuln_class)
        # every planted class resolves to at least one real framework control (not all dashes)
        assert any(val != "—" for val in row.values()), v.vuln_class
        assert set(row) == set(compliance.FRAMEWORKS)


def test_compliance_normalizes_engine_aliases():
    assert compliance.normalize("error_based_sqli") == "sqli"
    assert compliance.normalize("bola") == "idor"
    assert compliance.normalize("privilege_escalation") == "broken_access_control"
    assert compliance.mapped_row("error_based_sqli")["MITRE ATT&CK"] == "T1190"


def test_impact_chain_appears_only_when_prerequisites_confirmed():
    # SQLi alone → per-class impact, but NOT the full-register-breach chain (needs idor too)
    sqli_only = impact.chains_for([{"bug_class": "error_based_sqli"}])
    titles = {c["title"] for c in sqli_only}
    assert any("register dump" in t for t in titles)
    assert not any("Full citizen-register breach" in t for t in titles)
    # SQLi + IDOR → the chain fires
    both = impact.chains_for([{"bug_class": "error_based_sqli"}, {"bug_class": "idor"}])
    assert any("Full citizen-register breach" in c["title"] for c in both)


# --- endpoints (need the control server) -----------------------------------------------------------
def _get(base: str, path: str):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.load(r)


def _seed_reverify(base_dir: str) -> None:
    rc = os.path.join(base_dir, "rc")
    os.makedirs(rc, exist_ok=True)
    with open(os.path.join(rc, "records.reverify.json"), "w", encoding="utf-8") as fh:
        json.dump({"active_findings": [
            {"bug_class": "error_based_sqli", "param": "q", "oracle_context": {"kind": "error_signature"}},
            {"bug_class": "idor", "param": "id", "oracle_context": {"kind": "achieved_state"}}]}, fh)


def test_compliance_endpoint_maps_confirmed_findings(range_client):
    _seed_reverify(range_client.config.base_dir)  # type: ignore[attr-defined]
    doc = _get(range_client.control_base, "/compliance.json")  # type: ignore[attr-defined]
    assert doc["frameworks"] == compliance.FRAMEWORKS
    classes = {r["bug_class"].split(" @ ")[0] for r in doc["rows"]}
    assert classes == {"error_based_sqli", "idor"}
    row = next(r for r in doc["rows"] if r["bug_class"].startswith("idor"))
    assert row["controls"]["NIST 800-53"] == "AC-3"


def test_impact_endpoint_returns_chain(range_client):
    _seed_reverify(range_client.config.base_dir)  # type: ignore[attr-defined]
    doc = _get(range_client.control_base, "/impact.json")  # type: ignore[attr-defined]
    assert any("Full citizen-register breach" in c["title"] for c in doc["chains"])


def test_evidence_endpoint_reports_a_present_bundle(range_client):
    rc = os.path.join(range_client.config.base_dir, "rc")  # type: ignore[attr-defined]
    os.makedirs(os.path.join(rc, "evidence"), exist_ok=True)
    with open(os.path.join(rc, "evidence", "evidence-bundle.json"), "w", encoding="utf-8") as fh:
        json.dump({"certificates": [{"id": 1}, {"id": 2}], "chain": [{}, {}]}, fh)
    with open(os.path.join(rc, "trust-root.json"), "w", encoding="utf-8") as fh:
        json.dump({"authorizers": [{"public_key_b64": "AAAAtestpubkey"}]}, fh)
    doc = _get(range_client.control_base, "/evidence.json")  # type: ignore[attr-defined]
    assert doc["present"] and doc["certificates"] == 2 and doc["chain"] == 2
    assert doc["trust_root_fingerprint"].startswith("sha256:")
