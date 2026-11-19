"""APEX PR-A — the tenant-scoped POSTURE + presentation projection + its self-red-pen.

Load-bearing invariants (a false-green either leaks one tenant's presentation to another, lets the flag-off
read surface the block, or lets the presentation drift from the signed data):
  * BYTE-IDENTICAL WHEN OFF: with ``VIGIL_APEX_PRESENTATION`` unset, ``assessment_findings`` NEVER carries the
    ``presentation`` cert field even when the certificate HAS one, and the ``assessment_posture`` cockpit action
    is absent (404). Mutation-verify: remove the flag skip and the flag-off test REDS.
  * TENANT ISOLATION (self-red-pen RP1): a posture read for org B NEVER counts or shows org A's finding — and
    thus never its presentation — because the posture reads only ``assessments.all_findings_for_org`` (org B's
    own server-derived slug set; ``_customer_slug`` is a one-way hash). Dropping that scoping REDS the test.
  * SIGNED-ONLY plain language: the plain-language impact + exact remediation shown come ONLY from the SIGNED
    presentation block; a finding minted without one shows standards + severity + priority but no plain-language
    (never fabricated).
  * PROVEN ONLY / deterministic posture: posture is derived only from proven (certificate-bearing) findings and
    is a pure integer function of their severities (reproducible).
"""
from __future__ import annotations

import tempfile

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import assessments as _assess
from sigil.ui import finding_presentation as _fpres
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import Provisioner
from sigil.ui.target_authorization import _customer_slug

NOW = 1000.0


def _store():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return s


def _prov(store, owner):
    return Provisioner(
        store,
        customers=CustomerRegistry(store, owner_key=owner),
        orgs=OrgRegistry(store, owner_key=owner),
        wallet=WalletRegistry(store, owner_key=owner),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: NOW)


def _member(orgs, org, user, role, it):
    orgs.create_org(org, org.upper(), owner="owner", issued_at=float(next(it)))
    orgs.grant_membership(org, user, role, issued_at=float(next(it)))


def _prove(store, org, host, it):
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(it)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0, ttl_seconds=1e12)
    return _customer_slug(org, host)


def _presentation(bug_class: str, *, impact: str, remediation: str) -> dict:
    """A signed-presentation block in the shape ``evidence.certify._build_presentation`` mints."""
    return {
        "schema": 1,
        "plain_impact": {"what": impact, "category_consequence": "c", "established": "e",
                         "description_on_file": True},
        "remediation": remediation,
        "priority": {"effort": "L", "severity": "Critical", "score": 1.6667},
        "standards": {"controls": {"owasp": "A03:2021", "cwe": ["CWE-89"]},
                      "note": "indicative control mapping"},
    }


def _finding(store, slug, ref, *, bug_class="xss", severity="high", presentation=None):
    cert = {"engagement_slug": slug, "finding_ref": ref, "bug_class": bug_class,
            "surface": "https://x/" + ref, "confidence": "high", "severity": severity,
            "title": "Finding " + ref, "summary": "s " + ref}
    if presentation is not None:
        cert["presentation"] = presentation
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": cert, "finding_ref": ref,
                          "signatures": [{"key_id": "gov", "signature_b64": "x"}]})


# ---- posture math (pure, deterministic) ------------------------------------------------------------
def test_posture_score_pure_and_monotone():
    assert _fpres.posture_score([]) == 100                       # no findings -> perfect
    one_crit = _fpres.posture_score([{"bug_class": "sqli", "severity": "critical"}])
    assert 0 < one_crit < 100
    two_crit = _fpres.posture_score([{"bug_class": "sqli", "severity": "critical"},
                                     {"bug_class": "rce", "severity": "critical"}])
    assert two_crit < one_crit                                   # strictly decreasing
    one_low = _fpres.posture_score([{"bug_class": "open_redirect", "severity": "low"}])
    assert one_low > one_crit                                    # a low hurts far less than a critical
    # pure integer function -> reproducible
    assert _fpres.posture_score([{"bug_class": "sqli", "severity": "critical"}]) == one_crit


def test_triage_is_worst_first():
    rows = [{"engagement_slug": "s", "finding_ref": "a", "bug_class": "open_redirect", "severity": "low",
             "surface": "u"},
            {"engagement_slug": "s", "finding_ref": "b", "bug_class": "sqli", "severity": "critical",
             "surface": "u"}]
    triage = _fpres._triage(rows)
    assert [r["finding_ref"] for r in triage] == ["b", "a"]      # critical before low
    assert triage[0]["tier"] == 0 or triage[0]["severity"] == "critical"


# ---- projection gating (byte-identical when off) ---------------------------------------------------
def _one_org_with_presented_finding(p, it):
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(p.store, "acme", "acme.example", it)
    _finding(p.store, slug, "f1", bug_class="sqli", severity="critical",
             presentation=_presentation("sqli", impact="an attacker can read your database",
                                        remediation="use parameterised queries"))
    return slug


def test_projection_carries_presentation_when_on(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _one_org_with_presented_finding(p, iter(range(1, 10_000)))
    out = _assess.assessment_findings(store, "acme", now=NOW)
    assert out["count"] == 1
    pres = out["findings"][0].get("presentation")
    assert isinstance(pres, dict) and pres["plain_impact"]["what"].startswith("an attacker")


def test_projection_byte_identical_when_off(monkeypatch):
    # The cert HAS a presentation block, but with the flag OFF the read must never surface it.
    monkeypatch.delenv("VIGIL_APEX_PRESENTATION", raising=False)
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _one_org_with_presented_finding(p, iter(range(1, 10_000)))
    out = _assess.assessment_findings(store, "acme", now=NOW)
    assert out["count"] == 1
    assert "presentation" not in out["findings"][0], "flag OFF must not surface the presentation block"


# ---- posture read end-to-end + the SIGNED-only honesty ---------------------------------------------
def test_assessment_posture_reads_signed_block(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _one_org_with_presented_finding(p, iter(range(1, 10_000)))
    out = _fpres.assessment_posture(store, "acme", now=NOW)
    assert out["findings_total"] == 1 and 0 < out["posture_score"] < 100
    row = out["triage"][0]
    assert row["presentation_signed"] is True
    assert row["remediation"] == "use parameterised queries"      # from the SIGNED block only
    assert any(c["framework"] == "owasp" for c in row["standards_chips"])


def test_posture_no_signed_block_shows_standards_not_plainlanguage(monkeypatch):
    # A finding minted WITHOUT a presentation block: standards chips (mirror fallback) + severity are shown, but
    # no plain-language impact / remediation is fabricated.
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    _finding(store, slug, "f1", bug_class="sqli", severity="critical")   # no presentation
    out = _fpres.assessment_posture(store, "acme", now=NOW)
    row = out["triage"][0]
    assert row["presentation_signed"] is False
    assert "remediation" not in row and "plain_impact" not in row        # never fabricated
    assert any(c["framework"] == "owasp" for c in row["standards_chips"])  # mirror fallback still renders chips


# ---- SELF-RED-PEN RP1: a cross-tenant presentation can NEVER leak -----------------------------------
def test_cross_tenant_presentation_never_leaks(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    # Org A (acme) has a juicy, presented critical finding.
    _member(p.orgs, "acme", "alice", "operator", it)
    a_slug = _prove(store, "acme", "acme.example", it)
    _finding(store, a_slug, "secret", bug_class="sqli", severity="critical",
             presentation=_presentation("sqli", impact="ACME-ONLY SECRET IMPACT",
                                        remediation="ACME-ONLY SECRET FIX"))
    # Org B (globex) exists and has its OWN proven host but NO findings.
    _member(p.orgs, "globex", "bob", "operator", it)
    _prove(store, "globex", "globex.example", it)

    b_posture = _fpres.assessment_posture(store, "globex", now=NOW)
    assert b_posture["findings_total"] == 0
    assert b_posture["posture_score"] == 100                    # B is clean; A's finding never counts
    assert b_posture["triage"] == []
    blob = repr(b_posture)
    assert "ACME-ONLY SECRET" not in blob and "secret" not in blob, "org A's finding/presentation leaked to B"

    # And even B's raw findings read carries nothing of A's.
    b_findings = _assess.assessment_findings(store, "globex", now=NOW)
    assert b_findings["count"] == 0
    assert "ACME-ONLY SECRET" not in repr(b_findings)

    # Control: A itself DOES see its own presented finding (the read is not vacuously empty).
    a_posture = _fpres.assessment_posture(store, "acme", now=NOW)
    assert a_posture["findings_total"] == 1
    assert "ACME-ONLY SECRET FIX" in repr(a_posture)


# ---- SELF-RED-PEN RP2 (consumer side): a presentation can NEVER soften a finding's weight --------------
def test_signed_presentation_cannot_downgrade_posture_or_hide_standards(monkeypatch):
    # A finding's severity + posture weight come from ``derived_severity`` (its OWN cert severity / the class
    # maximum), NEVER from the presentation block's priority; and standards chips fall back to the mirror when
    # the signed controls are empty. So a benign-looking presentation (claiming "Info / no action / no
    # standards") cannot lower the score or hide the frameworks a critical finding implicates.
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    benign = {"schema": 1,
              "plain_impact": {"what": "nothing to see", "category_consequence": "", "established": "",
                               "description_on_file": False},
              "remediation": "no action needed",
              "priority": {"effort": "S", "severity": "Info"},    # a LIE the consumer must ignore
              "standards": {"controls": {}, "note": ""}}          # empty -> must fall back to the mirror
    _finding(store, slug, "f1", bug_class="sqli", severity="critical", presentation=benign)
    out = _fpres.assessment_posture(store, "acme", now=NOW)
    row = out["triage"][0]
    assert row["severity"] == "critical"                          # the finding's OWN severity, not "Info"
    assert out["posture_score"] == _fpres.posture_score([{"bug_class": "sqli", "severity": "critical"}])
    assert any(c["framework"] == "owasp" for c in row["standards_chips"])  # mirror fallback renders real chips


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
