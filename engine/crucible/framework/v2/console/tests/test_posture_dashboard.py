"""
The posture-analytics dashboard provider (``api.posture_dashboard`` + its pure projection helpers).

Load-bearing SOUNDNESS invariants pinned here:
  * The security SCORE is a DECLARED MONOTONE projection of the signed PostureCertificate summary
    ({closed, open, unproven}) — never an averaged CVSS, never computed from LEADs; no attested
    certificate ⇒ an honest null score (not a fabricated zero).
  * Severity + CWE clustering count ORACLE-CONFIRMED FACTs only (verified_by_oracle) — a LEAD is never
    counted as proven posture.
  * KEV/EPSS are intel-tier LEADS (prioritization of the CVE-bearing subset), never counted as proof;
    ``oracle_proven_facts`` is VIGIL's own exploitability signal.
  * The provider is read-only + total (never raises on a fresh/empty tree) and route-registered.
  * ``vulnintel_data`` MERGES KEV + EPSS observations onto one CVE node (no last-write-wins data loss).
"""

from __future__ import annotations

from framework.v2.console import api


# ---- the security score: a monotone projection of the SIGNED cert summary --


def test_score_is_a_monotone_projection_of_the_signed_summary() -> None:
    certs = [
        {"present": True, "residual": "R", "summary": {"n_closed": 8, "n_open": 0, "n_unproven": 2,
                                                       "overall": "PARTIAL"}},
        {"present": True, "residual": "R", "summary": {"n_closed": 0, "n_open": 1, "n_unproven": 0,
                                                       "overall": "OPEN"}},
        {"present": False, "summary": {}},                       # not attested → excluded
    ]
    s = api._dash_score(certs)
    assert s["closed"] == 8 and s["open"] == 1 and s["unproven"] == 2    # aggregated over PRESENT certs
    assert s["value"] == round(100 * 8 / 11)                              # closed / (closed+open+unproven)
    assert s["attested"] is True and s["certificates"] == 2
    assert "OPEN" in s["verdicts"] and "PARTIAL" in s["verdicts"]
    assert s["residual"] == "R"
    # MONOTONE: adding an OPEN (a proven exposure) lowers the score; adding a CLOSED raises it
    more_open = api._dash_score(certs + [{"present": True, "summary": {"n_closed": 0, "n_open": 5,
                                                                       "n_unproven": 0}}])
    assert more_open["value"] < s["value"]


def test_score_is_null_when_nothing_is_attested() -> None:
    s = api._dash_score([{"present": False, "summary": {}}])
    assert s["value"] is None and s["attested"] is False and "null" in s["note"]
    assert api._dash_score([])["value"] is None                          # empty → honest null, not zero


def test_score_keeps_latest_cert_per_engagement_no_double_count() -> None:
    # posture() yields newest-first, so a STALE all-CLOSED cert must NOT inflate a re-attested all-OPEN
    # posture into a misleading 50% — only the latest attestation per engagement counts.
    certs = [
        {"present": True, "engagement": "mrg", "summary": {"n_closed": 0, "n_open": 10, "n_unproven": 0}},
        {"present": True, "engagement": "mrg", "summary": {"n_closed": 10, "n_open": 0, "n_unproven": 0}},
    ]
    s = api._dash_score(certs)
    assert s["certificates"] == 1 and s["closed"] == 0 and s["open"] == 10 and s["value"] == 0
    # two DIFFERENT engagements still aggregate (a genuine fleet total)
    two = api._dash_score([
        {"present": True, "engagement": "a", "summary": {"n_closed": 5, "n_open": 0, "n_unproven": 0}},
        {"present": True, "engagement": "b", "summary": {"n_closed": 0, "n_open": 5, "n_unproven": 0}}])
    assert two["certificates"] == 2 and two["value"] == 50


def test_score_is_total_and_clamped_on_corrupt_counts() -> None:
    # a partial-write / schema-drift / bit-rot / forged cert — posture() surfaces summary verbatim; the
    # score must NEVER raise and NEVER leave [0,100] (closes the HTTP-500 + the 200%/negative bugs).
    for bad in ("oops", [1, 2], {"x": 1}, None, float("nan"), -5, True):
        s = api._dash_score([{"present": True, "summary": {"n_closed": bad, "n_open": 1, "n_unproven": 0}}])
        assert s["value"] is None or 0 <= s["value"] <= 100
    neg = api._dash_score([{"present": True, "summary": {"n_closed": 10, "n_open": 0, "n_unproven": -5}}])
    assert 0 <= neg["value"] <= 100                                      # negative count cannot exceed 100


def test_facts_handles_bare_string_cwe_and_other_severity_bucket() -> None:
    f = api._dash_facts([
        {"verified_by_oracle": True, "bug_class": "xss", "cwe": "CWE-79", "severity": "High"},
        {"verified_by_oracle": True, "bug_class": "weird", "severity": "Blocker"},   # out-of-vocab severity
    ])
    cwes = {c["cwe"] for c in f["cwe_clusters"]}
    assert "CWE-79" in cwes and "7" not in cwes and "-" not in cwes     # NOT iterated char-by-char
    assert f["severity"].get("High") == 1 and f["severity"].get("Other") == 1   # out-of-vocab bucketed
    assert sum(f["severity"].values()) == f["fact_count"]               # no FACT silently dropped


def test_dashboard_is_total_on_a_corrupt_posture_cert(monkeypatch) -> None:
    # the FATAL-2 totality invariant: a corrupt cert must blank a panel, never 500 the whole read.
    corrupt = {"posture": [{"present": True, "engagement": "x",
                            "summary": {"n_closed": "oops", "n_open": [1], "n_unproven": None}}]}
    monkeypatch.setattr(api, "posture", lambda: corrupt)
    monkeypatch.setattr(api, "list_engagements", lambda: {"engagements": [{"slug": "x"}]})
    fleet = api.posture_dashboard("")                                   # must not raise
    assert fleet["ok"] is True and (fleet["score"]["value"] is None or 0 <= fleet["score"]["value"] <= 100)
    drill = api.posture_dashboard("x")                                  # must not raise
    assert drill["ok"] is True


# ---- severity + CWE clustering: ORACLE-CONFIRMED FACTs only ----------------


def test_facts_count_only_oracle_confirmed_and_cluster_by_cwe() -> None:
    findings = [
        {"verified_by_oracle": True, "severity": "High", "bug_class": "xss", "cwe": ["CWE-79"]},
        {"verified_by_oracle": True, "severity": "high", "bug_class": "xss", "cwe": ["CWE-79"]},
        {"verified_by_oracle": True, "severity": "Critical", "bug_class": "sqli", "cwe": ["CWE-89"]},
        {"verified_by_oracle": False, "severity": "Critical", "bug_class": "sqli", "cwe": ["CWE-89"]},  # LEAD
    ]
    f = api._dash_facts(findings)
    assert f["fact_count"] == 3 and f["lead_count"] == 1                 # the LEAD is not a FACT
    assert f["severity"] == {"Critical": 1, "High": 2}                  # title-cased, LEAD excluded
    top = f["cwe_clusters"][0]
    assert top["cwe"] == "CWE-79" and top["count"] == 2 and top["bug_classes"] == ["xss"]
    assert {c["cwe"] for c in f["cwe_clusters"]} == {"CWE-79", "CWE-89"}


# ---- exploitability: oracle-proven + KEV/EPSS as leads (never proof) -------


def test_exploitability_separates_oracle_proof_from_kev_epss_leads() -> None:
    findings = [{"verified_by_oracle": True}, {"verified_by_oracle": True}, {"verified_by_oracle": False}]
    vulns = [
        {"id": "CVE-1", "exploit_known": True, "epss": 0.9, "epss_percentile": 0.99},
        {"id": "CVE-2", "exploit_known": False, "epss": 0.1},
        {"id": "CVE-3", "exploit_known": True},                          # KEV but no EPSS score
    ]
    e = api._dash_exploitability(findings, vulns)
    assert e["oracle_proven_facts"] == 2                                 # VIGIL's own PROOF, the 2 FACTs
    assert e["kev_listed"] == 2
    assert e["epss"]["scored"] == 2 and e["epss"]["high_ge_0_5"] == 1
    assert e["epss"]["top"][0]["cve"] == "CVE-1" and e["epss"]["top"][0]["kev"] is True
    assert "never counted as proof" in e["note"]


# ---- the provider is total + route-registered ------------------------------


def test_posture_dashboard_is_total_fleet_and_engagement() -> None:
    fleet = api.posture_dashboard("")
    assert fleet["ok"] is True and fleet["scope"] == "fleet" and fleet["slug"] is None
    for k in ("score", "facts", "exploitability", "remediation", "engagements", "doctrine"):
        assert k in fleet
    eng = api.posture_dashboard("no-such-slug-xyz")
    assert eng["ok"] is True and eng["scope"] == "engagement" and eng["slug"] == "no-such-slug-xyz"
    assert eng["facts"]["fact_count"] == 0 and eng["score"]["value"] is None   # honest nulls, no fabrication


def test_route_is_registered_as_scoped() -> None:
    from framework.v2.console import server
    # a slug-taking provider MUST be scoped (an _EXACT_ROUTES entry would silently drop the scope)
    assert server._SCOPED_ROUTES.get("/api/posture-dashboard") is api.posture_dashboard
    assert "/api/posture-dashboard" not in server._EXACT_ROUTES


# ---- vulnintel_data merges KEV + EPSS onto one CVE node --------------------


def test_vulnintel_merges_kev_and_epss_on_the_same_cve(tmp_path, monkeypatch) -> None:
    from framework.v2.common import paths
    from framework.v2.intel.from_threatintel import observations_from_epss, observations_from_kev
    from framework.v2.intel.ingest import IntelIngest
    from framework.v2.intel.store import IntelStore
    from framework.v2.memory.store import Store
    from framework.v2.worldmodel.graph import WorldModel

    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    kev = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Widget",
                                "shortDescription": "bad", "dateAdded": "2024-01-01"}]}
    epss = {"data": [{"cve": "CVE-2024-0001", "epss": "0.73210", "percentile": "0.95"}]}
    # persist to the SAME durable IntelStore vulnintel_data reads (memory_db monkeypatched to tmp above)
    ing = IntelIngest(WorldModel(), engagement_slug="mrg", store=IntelStore(Store()))
    ing.ingest(observations_from_kev(kev, seq=1) + observations_from_epss(epss, seq=2))

    d = api.vulnintel_data("mrg")
    v = next((x for x in d["vulnerabilities"] if x["id"].upper() == "CVE-2024-0001"), None)
    assert v is not None
    assert v["exploit_known"] is True            # from CISA-KEV
    assert v["epss"] == 0.73210                  # from first.org EPSS — MERGED, not clobbered
    assert set(v.get("feeds") or []) == {"cisa-kev", "first-epss"}   # provenance accumulated, order-indep
    assert d["counts"]["epss_scored"] >= 1
