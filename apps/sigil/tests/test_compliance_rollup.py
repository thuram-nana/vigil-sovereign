"""PR-G (Area 6) — the customer COMPLIANCE view (``ui/compliance_view``) and its provisioner/edge gating.

Load-bearing invariants (each mutation-verified — the named test reds when its guard is broken):
  * NEVER ASSERTS A CONTROL IS MET: no status, label or sentence anywhere in the view says a control is met, covered,
    satisfied, passing or compliant — only the fixed negating STATEMENT mentions those words
    (test_the_view_never_states_a_control_is_met).
  * PROVEN ONLY: a control is implicated only by a finding that carries a certificate in the org's own slug set; a
    record without one, or another kind of record, never implicates anything (test_only_proven_findings_implicate).
  * MAPPING == THE ENGINE'S: the implicated controls are exactly ``standards_mirror.controls_for`` (the drift-tested
    mirror of ``report/standards.py``) — or the SIGNED presentation controls when the certificate carries non-empty
    ones (test_controls_come_from_the_mirror_or_the_signed_block).
  * RETEST: a control implicated only by findings whose proof stopped working is ``weakness_fixed``, and only while
    the retest overlay is on (test_a_retest_fixed_finding_moves_its_controls_to_fixed).
  * TENANT ISOLATION: org B's view never carries org A's finding (test_another_tenants_finding_never_appears).
  * BYTE-IDENTICAL WHEN OFF: flag off -> the provisioner refuses and the cockpit/edge route is absent (404)
    (test_flag_off_the_view_is_absent_everywhere).

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:packages/core/vigil_core:integration python -m pytest -q \
     apps/sigil/tests/test_compliance_rollup.py
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import compliance_view as cv
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, Provisioner
from sigil.ui.target_authorization import _customer_slug
from vigil_core import standards_mirror as sm

NOW = 1000.0
_FLAGS = ("VIGIL_CUSTOMER_COMPLIANCE_MAP", "VIGIL_CUSTOMER_PDF_REPORT", "VIGIL_CUSTOMER_PLANS",
          "VIGIL_CUSTOMER_PLAN_CHANGE", "VIGIL_APEX_PRESENTATION", "VIGIL_CUSTOMER_RETEST_UI",
          "VIGIL_TRIAL_PREVIEW_ENABLED", "VIGIL_REPORT_PDF_RENDERER")


@pytest.fixture(autouse=True)
def _area6_env(monkeypatch):
    for k in _FLAGS:
        monkeypatch.delenv(k, raising=False)


# ---- shared Area-6 fixtures (imported by the other PR-G suites) --------------------------------------------------
def _store():
    s = SpineStore(str(Path(tempfile.mkdtemp()) / "spine.jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return s


def _prov(store, owner, *, now: float = NOW):
    p = Provisioner(
        store,
        customers=CustomerRegistry(store, owner_key=owner),
        orgs=OrgRegistry(store, owner_key=owner),
        wallet=WalletRegistry(store, owner_key=owner),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: now)
    # this provisioner's own report-export limiter (production roots it under SIGIL_HOME, shared by every test here)
    p._report_limiter_obj = LoginRateLimiter(tempfile.mkdtemp(), max_fails=Provisioner._REPORT_MAX,
                                             window_s=Provisioner._REPORT_WINDOW_S,
                                             base_lock_s=Provisioner._REPORT_WINDOW_S)
    return p


def _member(orgs, org, user, role, it, *, name=None):
    orgs.create_org(org, name or org.upper(), owner="owner", issued_at=float(next(it)))
    orgs.grant_membership(org, user, role, issued_at=float(next(it)))


def _prove(store, org, host, it):
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(it)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0, ttl_seconds=1e12)
    return _customer_slug(org, host)


def _finding(store, slug, ref, *, bug_class="xss", severity="high", title=None, presentation=None, **extra):
    cert = {"engagement_slug": slug, "finding_ref": ref, "bug_class": bug_class,
            "surface": "https://x/" + ref, "confidence": "high", "severity": severity,
            "title": title or ("Finding " + ref), "summary": "s " + ref, **extra}
    if presentation is not None:
        cert["presentation"] = presentation
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": cert, "finding_ref": ref,
                          "signatures": [{"key_id": "gov", "signature_b64": "x"}]})


def _retest(store, slug, ref, status, *, digest=""):
    store.append(kind="finding_retest", source="provision", actor="WARDEN",
                 payload={"engagement_slug": slug, "finding_ref": ref, "oracle_context_digest": digest,
                          "status": status, "ts": NOW})


def _one_org(store, p, it, *findings):
    """acme (operator alice: reads assessments AND billing) with one proven host and the given (ref, bug_class,
    severity) findings."""
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    for ref, bc, sev in findings:
        _finding(store, slug, ref, bug_class=bc, severity=sev)
    return slug


def _fw(view, fw):
    return next(f for f in view["frameworks"] if f["framework"] == fw)


def _status(view, fw, cid):
    return next(c["status"] for c in _fw(view, fw)["controls"] if c["id"] == cid)


# ---- the roll-up -------------------------------------------------------------------------------------------------
def test_proven_findings_implicate_exactly_their_mapped_controls():
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _one_org(store, p, iter(range(1, 10_000)), ("f1", "sqli", "critical"), ("f2", "xss", "high"))
    view = cv.compliance_view(store, "acme", now=NOW)
    assert view["findings_total"] == 2 and view["generated_from"] == "proven_findings"
    assert [f["framework"] for f in view["frameworks"]] == list(cv.FRAMEWORKS)
    implicated = {fw: set() for fw in cv.FRAMEWORKS}
    for bc in ("sqli", "xss"):
        for fw, ids in sm.controls_for(bc).items():
            if fw in implicated and ids:
                implicated[fw] |= {ids} if isinstance(ids, str) else set(ids)
    for fw in cv.FRAMEWORKS:
        got = {c["id"] for c in _fw(view, fw)["controls"] if c["status"] == cv.STATUS_PROVEN}
        assert got == implicated[fw], fw
        for c in _fw(view, fw)["controls"]:
            if c["status"] in (cv.STATUS_NONE, cv.STATUS_NOT_MAPPED):
                assert c["findings"] == []
    # OWASP lists the full Top 10, A09 (no VIGIL check maps it) said plainly
    owasp = _fw(view, "owasp")["controls"]
    assert [c["id"] for c in owasp] == list(sm.owasp_categories()) and len(owasp) == 10
    assert all(c["name"] == sm.owasp_name(c["id"]) for c in owasp)
    assert _status(view, "owasp", "A09:2021") == cv.STATUS_NOT_MAPPED
    a03 = next(c for c in owasp if c["id"] == "A03:2021")
    assert [e["finding_ref"] for e in a03["findings"]] == ["f1", "f2"]               # worst first
    assert set(a03["findings"][0]) == {"finding_ref", "title", "severity", "severity_basis", "bug_class", "host",
                                       "retest"}                                     # the entry allowlist
    assert a03["findings"][0]["host"] == "acme.example"


def test_the_view_never_states_a_control_is_met():
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _one_org(store, p, iter(range(1, 10_000)), ("f1", "sqli", "critical"), ("f2", "open_redirect", "medium"))
    view = cv.compliance_view(store, "acme", now=NOW)
    blob = json.dumps(view).replace(cv.STATEMENT, "")
    assert cv.STATEMENT in json.dumps(view)
    forbidden = re.compile(r"\b(met|compliant|compliance|covered|coverage|satisf\w*|pass(ed|es|ing)?|"
                           r"conform\w*|certified|attested)\b", re.IGNORECASE)
    assert not forbidden.search(blob), forbidden.search(blob).group(0)
    statuses = {c["status"] for fw in view["frameworks"] for c in fw["controls"]}
    assert statuses <= set(cv.STATUSES)
    # the one sentence is itself a negation
    assert "never states that a control is met" in cv.STATEMENT


def test_only_proven_findings_implicate():
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    # a lead-like record (no certificate), another record kind on the same slug, and a cert for a slug outside the set
    store.append(kind="finding", source="offense", actor="ORACLE", payload={"finding_ref": "lead", "bug_class": "sqli"})
    store.append(kind="detection", source="offense", actor="X",
                 payload={"certificate": {"engagement_slug": slug, "finding_ref": "x", "bug_class": "sqli"}})
    _finding(store, "not-this-orgs-slug", "foreign", bug_class="sqli", severity="critical")
    view = cv.compliance_view(store, "acme", now=NOW)
    assert view["findings_total"] == 0
    assert all(c["status"] in (cv.STATUS_NONE, cv.STATUS_NOT_MAPPED) for fw in view["frameworks"]
               for c in fw["controls"])


def test_controls_come_from_the_mirror_or_the_signed_block(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    signed = {"schema": 1, "standards": {"controls": {"owasp": "A01:2021", "pci_dss": ["7.2.1"], "soc2": ["CC6.1"]}}}
    empty = {"schema": 1, "standards": {"controls": {}}}
    _finding(store, slug, "signed", bug_class="sqli", severity="critical", presentation=signed)
    _finding(store, slug, "empty", bug_class="ssrf", severity="high", presentation=empty)
    view = cv.compliance_view(store, "acme", now=NOW)
    owasp = {c["id"]: [e["finding_ref"] for e in c["findings"]] for c in _fw(view, "owasp")["controls"]}
    assert owasp["A01:2021"] == ["signed"]                    # the SIGNED controls win when non-empty
    assert "signed" not in owasp["A03:2021"]                  # ... so the mirror's sqli category is not used for it
    assert owasp[sm.controls_for("ssrf")["owasp"]] == ["empty"]   # an EMPTY signed block falls back to the mirror
    pci = {c["id"]: [e["finding_ref"] for e in c["findings"]] for c in _fw(view, "pci_dss")["controls"]}
    assert pci["7.2.1"] == ["signed"]


def test_a_retest_fixed_finding_moves_its_controls_to_fixed():
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    slug = _one_org(store, p, iter(range(1, 10_000)), ("f1", "open_redirect", "medium"))
    _retest(store, slug, "f1", "fixed")
    on = cv.compliance_view(store, "acme", now=NOW, retests=True)
    off = cv.compliance_view(store, "acme", now=NOW, retests=False)
    cid = sm.controls_for("open_redirect")["owasp"]
    assert _status(on, "owasp", cid) == cv.STATUS_FIXED
    assert next(c for c in _fw(on, "owasp")["controls"] if c["id"] == cid)["findings"][0]["retest"] == "fixed"
    assert _status(off, "owasp", cid) == cv.STATUS_PROVEN       # no overlay: the finding still counts as open
    _retest(store, slug, "f1", "still_vulnerable")              # the newest verdict wins
    assert _status(cv.compliance_view(store, "acme", now=NOW, retests=True), "owasp", cid) == cv.STATUS_PROVEN


def test_another_tenants_finding_never_appears():
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    a_slug = _prove(store, "acme", "acme.example", it)
    _finding(store, a_slug, "acme-secret", bug_class="sqli", severity="critical", title="ACME-ONLY SECRET")
    _member(p.orgs, "globex", "bob", "operator", it)
    _prove(store, "globex", "globex.example", it)
    b = cv.compliance_view(store, "globex", now=NOW)
    assert b["findings_total"] == 0 and "ACME-ONLY" not in json.dumps(b) and "acme-secret" not in json.dumps(b)
    a = cv.compliance_view(store, "acme", now=NOW)
    assert a["findings_total"] == 1 and "ACME-ONLY SECRET" in json.dumps(a)       # the read is not vacuous


def test_controls_sort_naturally_and_unmapped_classes_are_listed_apart():
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _one_org(store, p, iter(range(1, 10_000)), ("f1", "sqli", "critical"), ("odd", "zz_not_a_class", "low"))
    view = cv.compliance_view(store, "acme", now=NOW)
    pci = [c["id"] for c in _fw(view, "pci_dss")["controls"]]
    assert pci == sorted(pci, key=cv._natural_key) and pci.index("6.2.4") < pci.index("10.2.1")
    assert [e["finding_ref"] for e in view["findings_elsewhere"]] == ["odd"]


# ---- the provisioner + cockpit gating ----------------------------------------------------------------------------
def test_flag_off_the_view_is_absent_everywhere(monkeypatch):
    from sigil.ui.server import Handler
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _one_org(store, p, iter(range(1, 10_000)), ("f1", "sqli", "critical"))
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.customer_compliance("alice", "acme")
    h = Handler.__new__(Handler)
    assert h._provision_dispatch(p, "compliance_view", "alice", {"org_id": "acme"}) is None    # -> 404
    monkeypatch.setenv("VIGIL_CUSTOMER_COMPLIANCE_MAP", "1")
    out = h._provision_dispatch(p, "compliance_view", "alice", {"org_id": "acme"})
    assert out["findings_total"] == 1 and out["org_id"] == "acme"


@pytest.mark.parametrize("role,ok", [("founder", True), ("operator", True), ("org_admin", False),
                                     ("analyst", False), ("viewer", False)])
def test_only_members_who_read_assessments_get_the_view(monkeypatch, role, ok):
    monkeypatch.setenv("VIGIL_CUSTOMER_COMPLIANCE_MAP", "1")
    monkeypatch.setenv("VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", "1")       # the founder role is admitted as founder
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", role, it)
    _finding(store, _prove(store, "acme", "acme.example", it), "f1", bug_class="sqli", severity="critical")
    if ok:
        assert p.customer_compliance("alice", "acme")["findings_total"] == 1
    else:
        with pytest.raises(ProvisionDenied, match="view_assessments"):
            p.customer_compliance("alice", "acme")
    with pytest.raises(ProvisionDenied):                          # never another org, whatever the role
        p.customer_compliance("alice", "globex")


def test_a_trial_preview_org_sees_no_locked_detail(monkeypatch):
    """The view carries no proof and no fix, so a locked trial org learns nothing its locked rows hide."""
    monkeypatch.setenv("VIGIL_CUSTOMER_COMPLIANCE_MAP", "1")
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")
    owner = ensure_owner_keypair()
    store = _store()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    p.wallet.grant("acme", 100, "trial", entry_id="trial-preview:acme", issued_at=50.0)
    assert p._preview_locked("acme")
    for i in range(3):
        _finding(store, slug, f"f{i}", bug_class="sqli", severity="critical", how_to_verify=f"S-HTV-f{i}",
                 oracle_context_digest=f"S-OCD-f{i}", report_claims=[f"S-RC-f{i}"], artifact_manifest={"a": f"S-AM-f{i}"},
                 summary=f"S-SUM-f{i}")
    blob = json.dumps(p.customer_compliance("alice", "acme"))
    for tag in ("HTV", "OCD", "RC", "AM", "SUM"):
        assert f"S-{tag}-" not in blob, tag
    assert "f1" in blob                                           # the findings themselves are listed (as in the preview)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
