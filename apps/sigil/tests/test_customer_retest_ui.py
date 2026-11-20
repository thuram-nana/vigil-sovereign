"""C1b — retest a finding from the customer app: the action, its gates, the record, the overlay, and the SPA.

What this pins:
  * THE ACTION (``provision.retest``): re-fires ONE finding's retained proof against the host through an injected
    re-verifier and marks it FIXED only when the proof stops working (``cleared``), else Still-Vulnerable
    (``still_present``); ANY other verdict (inconclusive / unavailable / a raised error) refuses with the finding
    UNCHANGED — a finding is NEVER marked fixed on a guess.
  * THE AUTHORIZATION is the launch gate's own conjuncts (``LaunchGate.authorize_retest``): membership on the
    testing axis, a CURRENT ownership proof, a CURRENT owner-pinned engagement authority, and the owner kill
    switch — with NO credit reserved or charged.
  * IDOR: a finding is resolved only within the SESSION org's own slug set, so another tenant's ``finding_ref`` is
    structurally not found; the retest record and its overlay are the session org's only.
  * REFUSALS: proof-expired / no-authority -> verify in Assets; a step-up -> the authenticator; flag off -> 404.
  * THE RECORD + OVERLAY: a confirmed verdict is a signed ``finding_retest`` spine record, and the customer
    findings read overlays each finding's newest verdict (``f["retest"]``) ONLY while the flag is on (byte-identical
    off).
  * THE SPA (node): findingsBlock shows Retest and the persisted badge only with the flag on (byte-identical off),
    Verifying -> Fixed / Still vulnerable, and every refusal is mapped to fixed copy.
  * THE GUIDE's retest step names the real label and the screen census stays green.

The provisioner-level tests run with the integration PYTHONPATH (the seam + add_customer_target live across it),
mirroring test_customer_launch_ui; the edge tests use the real hop (test_custui helpers).
"""
from __future__ import annotations

import itertools
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME owner state pristine)

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
GUIDE_JS = APP / "guide.js"
UI_JS = APP / "ui.js"

_iss = itertools.count(1)
_NOW = 2500.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "1")
    for v in ("VIGIL_CUSTOMER_STEPUP_REQUIRED", "VIGIL_METERED_BILLING", "VIGIL_TRIAL_PREVIEW_ENABLED"):
        monkeypatch.delenv(v, raising=False)


# --------------------------------------------------------------------------- the provisioner + the seam ----
def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _setup(store, org, host, *, role="operator", credits=100, now=1000.0, ttl=1e12):
    """Seat a member + wallet credits + an ownership proof + a minted EngagementAuthority (as the launch tests do)
    — enough for authorize_retest to pass on ``host``."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.target_authorization import add_customer_target
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    if orgs.org(org) is None:
        orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", role, issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}:{next(_iss)}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=ttl)
    assert add_customer_target(host, org_id=org, store=store, now=now)["ok"]


def _finding(store, org, host, ref, **cert):
    """Append a synthetic kind='finding' spine record for (org, host), returning its engagement_slug."""
    from sigil.ui.target_authorization import _customer_slug
    slug = _customer_slug(org, host)
    c = {"engagement_slug": slug, "finding_ref": ref, "bug_class": cert.get("bug_class", "xss"),
         "surface": cert.get("surface", "https://x/" + ref), "confidence": cert.get("confidence", "high"),
         "severity": cert.get("severity", "high"), "oracle_context_digest": cert.get("digest", "d-" + ref)}
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": c, "finding_ref": ref, "signatures": [{"key_id": "gov", "signature_b64": "x"}]})
    return slug


def _prov(store):
    from sigil.ui.provision import build_provisioner
    return build_provisioner(store)


def _ident(org, host, ref):
    """The identity the findings read gives a finding (what the app sends back): slug + ref + proof digest."""
    from sigil.ui.target_authorization import _customer_slug
    return {"engagement_slug": _customer_slug(org, host), "oracle_context_digest": "d-" + ref}


def _retest(st, org, host, ref, **kw):
    kw.setdefault("now", _NOW)
    return _prov(st).retest("u", org, ref, **{**_ident(org, host, ref), **kw})


def _cleared(ctx):
    return "cleared"


def _still(ctx):
    return "still_present"


def test_a_cleared_proof_marks_the_finding_fixed_and_records_it():
    from sigil.ui import assessments as _assess
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    r = _retest(st, "org_a", "apme.cm", "F1", reverify=_cleared)
    assert r == {"finding_ref": "F1", "host": "apme.cm", "status": "fixed"}
    # the verdict is a finding_retest spine record, and the findings read overlays it (flag on)
    kinds = [rec.kind for rec in st.iter_records() if getattr(rec, "kind", None) == "finding_retest"]
    assert kinds == ["finding_retest"]
    out = _prov(st).customer_assessment_findings("u", "org_a")
    f = next(x for x in out["findings"] if x["finding_ref"] == "F1")
    assert f["retest"]["status"] == "fixed"


def test_a_still_present_proof_marks_still_vulnerable():
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    r = _retest(st, "org_a", "apme.cm", "F1", reverify=_still)
    assert r["status"] == "still_vulnerable"
    out = _prov(st).customer_assessment_findings("u", "org_a")
    f = next(x for x in out["findings"] if x["finding_ref"] == "F1")
    assert f["retest"]["status"] == "still_vulnerable"


class _StrCleared:
    """An object whose str() is the 'cleared' token: a seam bug that must never read as a fix."""
    def __str__(self):
        return "cleared"


@pytest.mark.parametrize("verdict", ["inconclusive", "", "REMEDIATED", "yes", " cleared", "Cleared", " unavailable",
                                     "CLEARED", "fixed", None, True, _StrCleared()])
def test_only_a_decisive_cleared_or_still_present_is_honoured_everything_else_refuses(verdict):
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    with pytest.raises(ProvisionDenied) as e:
        _retest(st, "org_a", "apme.cm", "F1", reverify=lambda ctx: verdict)
    assert "could not confirm" in str(e.value)
    # nothing was recorded (a guessable verdict never writes a fixed/still record)
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []


def test_a_reverifier_that_raises_never_marks_fixed():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")

    def _boom(ctx):
        raise RuntimeError("target unreachable")
    with pytest.raises(ProvisionDenied) as e:
        _retest(st, "org_a", "apme.cm", "F1", reverify=_boom)
    assert "did not complete" in str(e.value)
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []


def test_the_default_reverifier_is_fail_closed_unavailable():
    from sigil.ui.provision import ProvisionDenied, _retest_reverify
    assert _retest_reverify({"host": "x"}) == "unavailable"       # the seam fails closed until the re-proof is wired
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    with pytest.raises(ProvisionDenied) as e:                     # no reverify injected -> default -> refuses
        _retest(st, "org_a", "apme.cm", "F1")
    # told as "not available" — no re-proof ran — never as "could not confirm" (which reads as a failed fix)
    assert "not available" in str(e.value) and "could not confirm" not in str(e.value)
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []


def test_cross_tenant_finding_is_not_found_idor():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _setup(st, "org_b", "bbb.cm")
    _finding(st, "org_a", "apme.cm", "FA")
    _finding(st, "org_b", "bbb.cm", "FB")
    # org_a's member names org_b's EXACT finding identity (slug + ref + digest): org_b's slug is not in
    # org_a's set, so it is simply not found
    with pytest.raises(ProvisionDenied) as e:
        _prov(st).retest("u", "org_a", "FB", now=_NOW, reverify=_cleared, **_ident("org_b", "bbb.cm", "FB"))
    assert "no such finding" in str(e.value)
    # and the cross-tenant retest wrote no record for either org
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []


def test_a_lapsed_ownership_proof_refuses_point_to_assets():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm", now=1000.0, ttl=100.0)         # proof lapses at 1100
    _finding(st, "org_a", "apme.cm", "F1")
    # the finding is still FOUND (ever-proven) but the proof is no longer current at now=2500 -> verify in Assets
    with pytest.raises(ProvisionDenied) as e:
        _retest(st, "org_a", "apme.cm", "F1", reverify=_cleared)
    assert "ownership proof" in str(e.value)


def test_a_billing_only_admin_may_not_retest_and_learns_nothing():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm", role="org_admin")             # billing, not testing
    _finding(st, "org_a", "apme.cm", "F1")
    for ref in ("F1", "MISSING"):                                 # an existing and a missing finding: one refusal,
        with pytest.raises(ProvisionDenied) as e:                 # before any lookup (no existence oracle)
            _retest(st, "org_a", "apme.cm", ref, reverify=_cleared)
        assert "view_assessments" in str(e.value), (ref, str(e.value))


def test_step_up_is_required_after_authority_when_enforcement_is_on(monkeypatch):
    from sigil.ui.provision import ProvisionStepUpRequired
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    with pytest.raises(ProvisionStepUpRequired):                  # authority passed; a stale mfa_at trips step-up
        _retest(st, "org_a", "apme.cm", "F1", mfa_at=0.0, reverify=_cleared)
    # a fresh mfa_at within the window proceeds
    r = _retest(st, "org_a", "apme.cm", "F1", mfa_at=_NOW - 1.0, reverify=_cleared)
    assert r["status"] == "fixed"


def test_the_launch_gate_is_checked_before_step_up(monkeypatch):
    # a refused authorization is told as itself — never masked as "step up" (E3c: authority first)
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    st = _store()
    _setup(st, "org_a", "apme.cm", now=1000.0, ttl=100.0)         # the proof has lapsed by now=2500
    _finding(st, "org_a", "apme.cm", "F1")
    with pytest.raises(ProvisionDenied) as e:                     # (ProvisionStepUpRequired is not a ProvisionDenied)
        _retest(st, "org_a", "apme.cm", "F1", mfa_at=0.0, reverify=_cleared)
    assert "ownership proof" in str(e.value)


def test_the_action_refuses_with_the_flag_off(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "0")
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    with pytest.raises(ProvisionDenied) as e:
        _retest(st, "org_a", "apme.cm", "F1", reverify=_cleared)
    assert "not enabled" in str(e.value)


def test_findings_read_is_byte_identical_with_the_flag_off(monkeypatch):
    # with the flag off, the findings read never overlays (and no retest record exists anyway): no f["retest"] key
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    _retest(st, "org_a", "apme.cm", "F1", reverify=_cleared)   # a record exists
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "0")
    out = _prov(st).customer_assessment_findings("u", "org_a")
    assert all("retest" not in f for f in out["findings"])              # off: the overlay never runs


def test_a_verdict_marks_only_the_finding_whose_proof_was_rerun():
    # finding_ref is NOT unique (a check id, a finding slug or merely the bug class): two findings on one host can
    # share it. The retest names the full identity, re-fires exactly that proof, and its verdict marks exactly that
    # finding — never the sibling with the same ref.
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "xss", digest="d-one", surface="https://apme.cm/a")
    _finding(st, "org_a", "apme.cm", "xss", digest="d-two", surface="https://apme.cm/b")
    seen = []
    ident = {**_ident("org_a", "apme.cm", "xss"), "oracle_context_digest": "d-two"}
    r = _prov(st).retest("u", "org_a", "xss", now=_NOW, reverify=lambda ctx: seen.append(ctx) or "cleared", **ident)
    assert r["status"] == "fixed" and [c["oracle_context_digest"] for c in seen] == ["d-two"]   # the named proof
    out = _prov(st).customer_assessment_findings("u", "org_a")
    by_digest = {f["oracle_context_digest"]: f for f in out["findings"]}
    assert by_digest["d-two"]["retest"]["status"] == "fixed"
    assert "retest" not in by_digest["d-one"]                          # the sibling sharing the ref is untouched


def test_the_finding_must_be_named_by_its_exact_identity():
    from sigil.ui.provision import ProvisionDenied, ProvisionError
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    slug = _ident("org_a", "apme.cm", "F1")["engagement_slug"]
    with pytest.raises(ProvisionDenied) as e:                         # right slug + ref, another proof -> not it
        _prov(st).retest("u", "org_a", "F1", now=_NOW, reverify=_cleared, engagement_slug=slug,
                         oracle_context_digest="d-other")
    assert "no such finding" in str(e.value)
    with pytest.raises(ProvisionError) as e2:                         # no assessment named -> refused up front
        _prov(st).retest("u", "org_a", "F1", now=_NOW, reverify=_cleared, oracle_context_digest="d-F1")
    assert type(e2.value) is ProvisionError and "required" in str(e2.value)
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []


def test_a_trial_locked_org_may_not_retest(monkeypatch):
    # retest re-runs the finding's proof, which is part of the full report: locked until the first purchase
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    WalletRegistry(st).grant("org_a", 1, "trial", entry_id="trial-preview:org_a", issued_at=float(next(_iss)))
    calls = []
    with pytest.raises(ProvisionDenied) as e:
        _retest(st, "org_a", "apme.cm", "F1", reverify=lambda ctx: calls.append(ctx) or "cleared")
    assert "unlocks with the full report" in str(e.value) and calls == []   # refused before any re-proof
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "0")            # not a locked preview org: it retests normally
    assert _retest(st, "org_a", "apme.cm", "F1", reverify=_cleared)["status"] == "fixed"


# --------------------------------------------------------------------------- LaunchGate.authorize_retest ----
def _gate(store):
    from sigil.ui.launch_gate import LaunchGate
    return LaunchGate(store)


def test_authorize_retest_holds_when_every_conjunct_holds():
    st = _store()
    _setup(st, "org_a", "apme.cm")
    r = _gate(st).authorize_retest(requester="u", org_id="org_a", host="apme.cm", now=_NOW)
    assert r["ok"] is True and r["host"] == "apme.cm"


def test_authorize_retest_refuses_a_non_member():
    st = _store()
    _setup(st, "org_a", "apme.cm")
    r = _gate(st).authorize_retest(requester="stranger", org_id="org_a", host="apme.cm", now=_NOW)
    assert r["ok"] is False and "may not retest" in r["error"]


def test_authorize_retest_requires_the_testing_permission_not_a_read():
    # no customer role today reads findings without run_engagement, so pin the conjunct with a registry that admits
    # every permission EXCEPT run_engagement: the gate must still refuse
    from sigil.ui.launch_gate import LaunchGate
    st = _store()
    _setup(st, "org_a", "apme.cm")

    class _ReadOnly:
        def admit_customer(self, *, username, org_id, permission):
            return permission != "run_engagement"
    r = LaunchGate(st, orgs=_ReadOnly()).authorize_retest(requester="u", org_id="org_a", host="apme.cm", now=_NOW)
    assert r["ok"] is False and "may not retest" in r["error"]


def test_authorize_retest_refuses_without_a_current_ownership_proof():
    st = _store()
    _setup(st, "org_a", "apme.cm", now=1000.0, ttl=100.0)         # proof lapses before now=2500
    r = _gate(st).authorize_retest(requester="u", org_id="org_a", host="apme.cm", now=_NOW)
    assert r["ok"] is False and "ownership proof" in r["error"]


def test_authorize_retest_refuses_without_a_current_engagement_authority():
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    st = _store()
    ensure_owner_keypair()
    orgs = OrgRegistry(st)
    orgs.create_org("org_a", "org_a", owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership("org_a", "u", "operator", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(st)
    ch = reg.issue_challenge("org_a", "apme.cm", issued_at=float(next(_iss)))
    reg.verify_and_record("org_a", "apme.cm", method=METHOD_DNS_TXT, observed=[ch.marker], now=1000.0, ttl_seconds=1e12)
    # ownership proven, but NO add_customer_target => no owner-signed authority on the seam
    r = _gate(st).authorize_retest(requester="u", org_id="org_a", host="apme.cm", now=_NOW)
    assert r["ok"] is False and "engagement authority" in r["error"]


def test_authorize_retest_is_halted_by_the_owner_kill_switch():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.killswitch import KillSwitch
    st = _store()
    _setup(st, "org_a", "apme.cm")
    KillSwitch(st, owner_key=ensure_owner_keypair()).engage(reason="incident")
    r = _gate(st).authorize_retest(requester="u", org_id="org_a", host="apme.cm", now=_NOW)
    assert r["ok"] is False and "paused" in r["error"]


# --------------------------------------------------------------------------- assessments.find_finding / overlay ----
def test_find_finding_resolves_only_the_orgs_own_finding():
    from sigil.ui import assessments as _assess
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _setup(st, "org_b", "bbb.cm")
    _finding(st, "org_a", "apme.cm", "FA")
    _finding(st, "org_b", "bbb.cm", "FB")
    hit = _assess.find_finding(st, "org_a", "FA", now=_NOW, **_ident("org_a", "apme.cm", "FA"))
    assert hit is not None and hit["host"] == "apme.cm" and hit["bug_class"] == "xss"
    # IDOR: org_b's finding named by its EXACT identity is unreachable from org_a (its slug is not org_a's)
    assert _assess.find_finding(st, "org_a", "FB", now=_NOW, **_ident("org_b", "bbb.cm", "FB")) is None
    assert _assess.find_finding(st, "org_b", "FB", now=_NOW, **_ident("org_b", "bbb.cm", "FB")) is not None
    assert _assess.find_finding(st, "org_a", "NOPE", now=_NOW, **_ident("org_a", "apme.cm", "NOPE")) is None
    wrong = {**_ident("org_a", "apme.cm", "FA"), "oracle_context_digest": "d-other"}
    assert _assess.find_finding(st, "org_a", "FA", now=_NOW, **wrong) is None              # another proof
    assert _assess.find_finding(st, "org_a", "FA", now=_NOW, engagement_slug="") is None    # no assessment named


def test_overlay_retests_is_a_noop_without_records_and_overlays_the_newest():
    from sigil.ui import assessments as _assess
    from sigil.ui.target_authorization import _customer_slug
    st = _store()
    slug = _customer_slug("org_a", "apme.cm")
    page = [{"engagement_slug": slug, "finding_ref": "F1", "oracle_context_digest": "d1"}]
    _assess.overlay_retests(st, page, now=_NOW)
    assert "retest" not in page[0]                                        # no record -> byte-identical
    st.append(kind="finding_retest", source="provision", actor="WARDEN",
              payload={"engagement_slug": slug, "finding_ref": "F1", "oracle_context_digest": "d1",
                       "status": "still_vulnerable", "ts": 1.0})
    st.append(kind="finding_retest", source="provision", actor="WARDEN",
              payload={"engagement_slug": slug, "finding_ref": "F1", "oracle_context_digest": "d1",
                       "status": "fixed", "ts": 2.0})
    page2 = [{"engagement_slug": slug, "finding_ref": "F1", "oracle_context_digest": "d1"},
             {"engagement_slug": slug, "finding_ref": "F1", "oracle_context_digest": "d2"}]   # same ref, other proof
    _assess.overlay_retests(st, page2, now=_NOW)
    assert page2[0]["retest"]["status"] == "fixed"                        # the NEWEST verdict wins
    assert "retest" not in page2[1]                                       # a sibling sharing the ref: untouched
    st.append(kind="finding_retest", source="provision", actor="WARDEN",
              payload={"engagement_slug": slug, "finding_ref": "F1", "oracle_context_digest": "d1",
                       "status": "pwned", "ts": 3.0})                     # newest, but not a verdict
    page3 = [{"engagement_slug": slug, "finding_ref": "F1", "oracle_context_digest": "d1"}]
    _assess.overlay_retests(st, page3, now=_NOW)
    assert page3[0]["retest"]["status"] == "fixed"                        # an unknown status is ignored
    st.append(kind="finding_retest", source="inbound", actor="RECEIVER",
              payload={"engagement_slug": slug, "finding_ref": "F1", "oracle_context_digest": "d1",
                       "status": "still_vulnerable", "ts": 4.0})          # newest, but not the provisioner's
    page4 = [{"engagement_slug": slug, "finding_ref": "F1", "oracle_context_digest": "d1"}]
    _assess.overlay_retests(st, page4, now=_NOW)
    assert page4[0]["retest"]["status"] == "fixed"                        # only provisioner-written verdicts count


def test_overlay_retests_never_attaches_another_tenants_record():
    from sigil.ui import assessments as _assess
    from sigil.ui.target_authorization import _customer_slug
    st = _store()
    a, b = _customer_slug("org_a", "apme.cm"), _customer_slug("org_b", "bbb.cm")
    # a retest record for org_b, a page of org_a's finding that happens to share the finding_ref
    st.append(kind="finding_retest", source="provision", actor="WARDEN",
              payload={"engagement_slug": b, "finding_ref": "F1", "oracle_context_digest": "d1", "status": "fixed",
                       "ts": 2.0})
    page = [{"engagement_slug": a, "finding_ref": "F1", "oracle_context_digest": "d1"}]
    _assess.overlay_retests(st, page, now=_NOW)
    assert "retest" not in page[0]                                        # org_b's slug never matches org_a's page


# --------------------------------------------------------------------------- the edge (real hop) ----
def _seed_target(store, org, host, ref):
    """A current ownership proof + an owner-signed authority + one finding for (org, host), minted at the REAL
    clock: over the hop the provisioner judges the authority window against wall time."""
    import time
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.ui.target_authorization import add_customer_target
    t = time.time()
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=t)
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=t, ttl_seconds=1e9)
    assert add_customer_target(host, org_id=org, store=store, now=t)["ok"]
    _finding(store, org, host, ref)


def test_the_retest_action_is_flag_gated_and_session_scoped():
    from sigil.ui import custui, server
    import inspect
    esrc = inspect.getsource(custui)
    assert 'if action == "retest" and _retest_on():' in esrc
    assert 'self._provision("retest", requester, payload)' in esrc    # org from the SERVER-side session, never body
    ssrc = inspect.getsource(server)
    i = ssrc.index('if action == "retest":')
    assert "customer_retest_ui_enabled()" in ssrc[i:i + 300] and "return None" in ssrc[i:i + 300]


def test_retest_over_the_edge_marks_fixed_and_rejects_cross_tenant(tmp_path, monkeypatch):
    from test_custui import _opener, _post, _stack
    from sigil.governor.orgs import OrgRegistry
    from sigil.ui import provision as _prov_mod
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "1")
    monkeypatch.setattr(_prov_mod, "_retest_reverify", lambda ctx: "cleared")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        oid, u = conf["org_id"], conf["username"]
        # a billing org_admin may NOT retest (billing != testing)
        mine = {"finding_ref": "F1", **_ident(oid, "apme.cm", "F1")}
        assert _post(op, ep, "/api/customer/retest", mine)[0] == 403
        st = sov.store()
        OrgRegistry(st).grant_membership(oid, u, "operator", issued_at=1e12)
        _seed_target(st, oid, "apme.cm", "F1")
        # a body org_id is IGNORED (the session's org is the only org the edge relays)
        c, d = _post(op, ep, "/api/customer/retest", {**mine, "org_id": "org_somebody_else"})
        assert c == 200 and d == {"finding_ref": "F1", "host": "apme.cm", "status": "fixed"}, (c, d)
        # IDOR over the edge: a second org's finding_ref is resolved against THIS session's org only -> not found
        op2 = _opener()
        t2 = _post(op2, ep, "/api/customer/signup/request", {"email": "b@beta.com"})[1]["dev_token"]
        conf2 = _post(op2, ep, "/api/customer/signup/confirm",
                      {"token": t2, "password": "customer-pw-2", "org_name": "Beta"})[1]
        OrgRegistry(st).grant_membership(conf2["org_id"], conf2["username"], "operator", issued_at=1e12)
        _seed_target(st, conf2["org_id"], "beta.cm", "FB")
        # acme's session naming beta's EXACT finding identity (and beta's org in the body) -> 403, never beta's host
        theirs = {"finding_ref": "FB", **_ident(conf2["org_id"], "beta.cm", "FB"), "org_id": conf2["org_id"]}
        c3, d3 = _post(op, ep, "/api/customer/retest", theirs)
        assert c3 == 403 and "no such finding" in json.dumps(d3) and "beta.cm" not in json.dumps(d3)
        # beta's own session retests it fine
        c4, d4 = _post(op2, ep, "/api/customer/retest", {k: v for k, v in theirs.items() if k != "org_id"})
        assert c4 == 200 and d4["host"] == "beta.cm"
    finally:
        sov.shutdown(); edge.shutdown()


def test_retest_route_requires_a_session_and_is_404_when_off(tmp_path, monkeypatch):
    from test_custui import _opener, _post, _stack
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        assert _post(_opener(), ep, "/api/customer/retest", {"finding_ref": "F1"})[0] == 401   # flag on, no session
    finally:
        sov.shutdown(); edge.shutdown()
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "0")
    sov2, edge2, ep2, _2 = _stack(tmp_path / "off", monkeypatch)
    try:
        assert _post(_opener(), ep2, "/api/customer/retest", {"finding_ref": "F1"})[0] == 404   # route absent -> 404
        op = _opener()
        t = _post(op, ep2, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        _post(op, ep2, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "Acme"})
        assert _post(op, ep2, "/api/customer/retest", {"finding_ref": "F1"})[0] == 404           # signed in, flag off
    finally:
        sov2.shutdown(); edge2.shutdown()


def _signed_in_operator(ep, sov, email, org_name, host, ref):
    """A signed-up customer made an operator of their org (as VIGIL grants it), with a seeded host + finding.
    Returns (opener, org_id, the finding's identity as the read gives it)."""
    from test_custui import _opener, _post
    from sigil.governor.orgs import OrgRegistry
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm",
                 {"token": t, "password": "customer-pw-1", "org_name": org_name})[1]
    st = sov.store()
    OrgRegistry(st).grant_membership(conf["org_id"], conf["username"], "operator", issued_at=1e12)
    _seed_target(st, conf["org_id"], host, ref)
    return op, conf["org_id"], {"finding_ref": ref, **_ident(conf["org_id"], host, ref)}


def test_the_edge_and_the_cockpit_each_gate_the_action_on_their_own_flag(tmp_path, monkeypatch):
    from test_custui import _post, _stack
    from sigil.ui import custui as _custui, provision as _prov_mod
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "1")
    fired = []
    monkeypatch.setattr(_prov_mod, "_retest_reverify", lambda ctx: fired.append(ctx) or "cleared")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op, _oid, body = _signed_in_operator(ep, sov, "a@acme.com", "Acme", "apme.cm", "F1")
        # the EDGE's flag reads off (the cockpit's is on): the edge answers 404 itself and never relays
        monkeypatch.setattr(_custui, "_retest_on", lambda: False)
        assert _post(op, ep, "/api/customer/retest", body)[0] == 404 and fired == []
        # the edge relays, but the COCKPIT's flag is off: the action is absent there (404 — not a 403 refusal)
        monkeypatch.setattr(_custui, "_retest_on", lambda: True)
        monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "0")
        assert _post(op, ep, "/api/customer/retest", body)[0] == 404 and fired == []
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_step_up_stamp_comes_from_the_session_never_the_body(tmp_path, monkeypatch):
    import time
    from test_custui import _post, _stack
    from sigil.ui import provision as _prov_mod
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    fired = []
    monkeypatch.setattr(_prov_mod, "_retest_reverify", lambda ctx: fired.append(ctx) or "cleared")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op, _oid, body = _signed_in_operator(ep, sov, "a@acme.com", "Acme", "apme.cm", "F1")
        # the session never stepped up; a fresh stamp forged into the body changes nothing
        c, d = _post(op, ep, "/api/customer/retest", {**body, "mfa_at": time.time()})
        assert c == 401 and d.get("step_up_required") is True and fired == []
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_edge_writes_the_retest_flag_into_the_page(tmp_path, monkeypatch):
    import http.client
    import threading
    from sigil.ui.custui import build_customer_server

    def page_and_build(home):
        srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                    sessions_dir=str(home / "s"))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            c.request("GET", "/", headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
            r = c.getresponse()
            return r.read().decode(), r.getheader("X-Vigil-Build")
        finally:
            srv.shutdown(); srv.server_close()

    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "0")
    off, build_off = page_and_build(tmp_path / "a")
    assert 'data-retest="0"' in off and "__VIGIL_RETEST__" not in off
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "1")
    on, build_on = page_and_build(tmp_path / "b")
    assert 'data-retest="1"' in on and build_on != build_off            # the value counts in the build id
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", v)
        assert 'data-retest="0"' in page_and_build(tmp_path / f"c{v or 'e'}")[0], v


# --------------------------------------------------------------------------- the SPA (executed under node) ----
def _need_node() -> str:
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH")
        pytest.skip("node not installed")
    return node


def _dom() -> str:
    from test_customer_onboarding import _DOM
    return _DOM


def _slice(src: str, start: str, end: str) -> str:
    return src[src.index(start):src.index(end)]


def _fn(src: str, name: str) -> str:
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


def _ser() -> str:
    # serialise the minimal-DOM tree the onboarding harness builds
    return r"""
function ser(e) {
  if (e == null) return "";
  if (!(e instanceof Node)) return String(e);
  if (e.children === undefined) return JSON.stringify(e.textContent);
  return e.tagName + (e.id ? "#" + e.id : "") + (e.className ? "." + e.className.split(" ").join(".") : "")
    + JSON.stringify(e.attrs) + "[" + e.children.map(ser).join(",") + "]";
}
"""


_RETEST_START = '  var RETEST_ON = pageFlag("retest");'
_RETEST_END = "  // ---- end of retest (C1b)"
# findingsBlock also calls the PR-I proof block (proofBadge); it is extracted verbatim too, and stays off here (the page
# writes no data-proof-badge), so every card below is exactly the retest card.
_PROOF_START = '  var PROOF_ON = pageFlag("proofBadge");'
_PROOF_END = "  // ---- end of proof badge (PR-I)"
# PR-L (Area 11): findingsBlock also calls blindVulnBadge, so the SPA harness slices in the blind-vuln region
# (its own var BLIND_VULN_ON = pageFlag("blindVuln") + helpers) exactly as it does the retest region. With the
# flag off (the harness sets no data-blind-vuln) blindVulnBadge returns null, so the card stays byte-identical.
_BLIND_START = '  var BLIND_VULN_ON = pageFlag("blindVuln");'
_BLIND_END = "  // ---- Attack-path storytelling (PR-L, Area 11)"

_PRELUDE = r"""
document.body.dataset.retest = %(flag)s;
var API = "api/customer";                 // app.js's own constant, above the extracted code
// every page-flag constant app.js declares, stubbed off; the extracted retest block then sets its OWN RETEST_ON
// from the page flag (a var re-declaration), exactly as app.js does
var GUIDE_ON = false, SECURITY_ON = false, TEAM_ON = false, MONITORING_ON = false, LAUNCH_ON = false, RETEST_ON = false;
var BLIND_VULN_ON = false, ATTACK_PATH_ON = false;   // PR-L flags, stubbed off; the sliced blind block resets its own
function pageFlag(name) { var ds = (document.body && document.body.dataset) || {}; return ds[name] === "1"; }
const calls = [];
const navs = []; function nav(r) { navs.push(r); }
let whoRefreshed = 0; async function refreshWho() { whoRefreshed++; }
const VUI = window.VUI;
const h = VUI.h;
let server = %(server)s;                  // { post: { <path>: { http, data } (a refusal) | { body } (a 200) } }
VUI.postJSON = async function (p, b) {
  calls.push(["POST", p, b]);
  const r = (server.post && server.post[p]) || { body: {} };
  if (r.http) { const e = new Error("x"); e.status = r.http; e.data = r.data || {}; throw e; }
  return r.body;
};
"""


def _harness(flag="1", *, server="{}"):
    """app.js's own kv + findingsBlock + the C1b retest block (all verbatim), with the app's world stubbed."""
    src = APP_JS.read_text(encoding="utf-8")
    env = _PRELUDE % {"flag": json.dumps(flag), "server": server}
    return (_dom() + f"\nrequire({json.dumps(str(UI_JS))});\nconst out = {{}};\n" + env + "\n"
            + _fn(src, "kv") + "\n" + _fn(src, "findingsBlock") + "\n" + _slice(src, _RETEST_START, _RETEST_END)
            + _slice(src, _PROOF_START, _PROOF_END)        # PR-I: findingsBlock also calls proofBadge
            + _slice(src, _BLIND_START, _BLIND_END)        # PR-L: findingsBlock also calls blindVulnBadge
            + _ser())


def _run(script: str, *, flag="1", server="{}") -> dict:
    prog = (_harness(flag, server=server)
            + "\nconst settle = () => new Promise(function (r) { setTimeout(r, 0); });\n"
            + "(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)), e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _labels(html):
    return re.findall(r'"button"\}\["([^"]+)"\]', html)


_CLICK = r"""
var block = findingsBlock("a.example", [{ engagement_slug: "cust_a", finding_ref: "F1", oracle_context_digest: "d1",
                                          severity: "high" }]);
var btn = block.querySelectorAll("button").filter(function (b) { return b.textContent === "Retest"; })[0];
btn.click();
out.during = ser(block); out.disabledDuring = !!btn.disabled;
await settle();
out.after = ser(block); out.disabledAfter = !!btn.disabled;
out.calls = calls; out.navs = navs; out.who = whoRefreshed;
"""


def _verdict(status):
    return json.dumps({"post": {"api/customer/retest": {"body": {"finding_ref": "F1", "host": "a.example",
                                                                 "status": status}}}})


def _refusal(code, data):
    return json.dumps({"post": {"api/customer/retest": {"http": code, "data": data}}})


def test_findingsblock_shows_retest_only_with_the_flag_on():
    script = r"""
out.html = ser(findingsBlock("a.example", [{ engagement_slug: "cust_a", finding_ref: "F1", severity: "high",
                                              bug_class: "xss" }]));
out.noref = ser(findingsBlock("a.example", [{ engagement_slug: "cust_a", title: "no reference" }]));
out.noslug = ser(findingsBlock("a.example", [{ finding_ref: "F1" }]));
"""
    on = _run(script, flag="1")
    assert _labels(on["html"]) == ["Retest"], on["html"]
    assert _labels(on["noref"]) == [] and _labels(on["noslug"]) == []   # a finding it cannot name: no button
    off = _run(script, flag="0")
    assert _labels(off["html"]) == [] and "Retest" not in off["html"]


def test_retest_posts_only_the_findings_identity_then_shows_the_fixed_verdict():
    out = _run(_CLICK, server=_verdict("fixed"))
    # the page sends ONLY the finding's identity as the read gave it — never an org, a user or a host (the server is
    # the authority on who and which tenant)
    assert out["calls"] == [["POST", "api/customer/retest",
                             {"engagement_slug": "cust_a", "finding_ref": "F1", "oracle_context_digest": "d1"}]]
    assert "Verifying…" in out["during"] and out["disabledDuring"] is True     # in flight: Verifying, no double click
    assert "Fixed" in out["after"] and "proof no longer works" in out["after"] and "cust-badge-verified" in out["after"]
    assert "Verifying" not in out["after"] and out["disabledAfter"] is False


def test_a_still_vulnerable_verdict_is_shown_as_still_vulnerable():
    out = _run(_CLICK, server=_verdict("still_vulnerable"))
    assert "Still vulnerable" in out["after"] and "proof still works" in out["after"]
    assert "cust-badge-expired" in out["after"] and "Fixed" not in out["after"]


def test_an_unknown_verdict_is_never_shown_as_a_verdict():
    out = _run(_CLICK, server=_verdict("maybe"))
    assert "Retest could not run" in out["after"]
    assert "Fixed" not in out["after"] and "Still vulnerable" not in out["after"]


def test_a_step_up_refusal_asks_for_the_authenticator_and_keeps_the_session():
    out = _run(_CLICK, server=_refusal(401, {"error": "a fresh second-factor (step-up) is required for this operation",
                                             "step_up_required": True}))
    assert "second-factor" in out["after"] and "authenticator" in out["after"]
    assert out["navs"] == [] and out["who"] == 0                  # a step-up is not a sign-out: no redirect
    assert out["disabledAfter"] is False


def test_an_ended_session_goes_to_sign_in():
    out = _run(_CLICK, server=_refusal(401, {"error": "login required"}))
    assert out["navs"] == ["#/login"] and out["who"] == 1


def test_a_lapsed_proof_refusal_offers_go_to_assets():
    out = _run(_CLICK + r"""
var go = block.querySelectorAll("button").filter(function (b) { return b.textContent === "Go to Assets"; })[0];
out.hasGo = !!go; if (go) { go.click(); } out.navsAfterGo = navs.slice();
""", server=_refusal(403, {"error": "denied: no current ownership proof for a.example (org org_x): prove control of "
                                    "the asset before its findings can be retested"}))
    assert "Verify it again in Assets" in out["after"] and out["hasGo"] is True
    assert out["navsAfterGo"] == ["#/assets"]
    assert "org_x" not in out["after"] and "a.example (org" not in out["after"]   # the server's own words never show


def test_the_persisted_badge_shows_only_with_the_flag_on():
    script = r"""
out.fixed = ser(findingsBlock("a.example", [{ engagement_slug: "s", finding_ref: "F1", retest: { status: "fixed" } }]));
out.vuln = ser(findingsBlock("a.example", [{ engagement_slug: "s", finding_ref: "F2",
                                             retest: { status: "still_vulnerable" } }]));
"""
    on = _run(script, flag="1")
    assert "Fixed" in on["fixed"] and "cust-badge-verified" in on["fixed"]
    assert "Still vulnerable" in on["vuln"] and "cust-badge-expired" in on["vuln"]
    off = _run(script, flag="0")                                    # off: a verdict in the read is ignored
    assert "Fixed" not in off["fixed"] and "cust-badge" not in off["fixed"]
    assert "Still vulnerable" not in off["vuln"] and "cust-badge" not in off["vuln"]


def test_every_refusal_maps_to_fixed_copy():
    out = _run(r"""
function m(code, error, extra) { var d = Object.assign({ error: error }, extra || {}); return retestMessage({ status: code, data: d }); }
out.stepup = m(401, "a fresh second-factor (step-up) is required", { step_up_required: true });
out.proof = m(403, "denied: no current ownership proof for a.example (org org_x)");
out.auth = m(403, "denied: no current owner-signed engagement authority for a.example (org org_x)");
out.off = m(404, "unknown action");
out.notEnabled = m(403, "denied: retesting findings from the app is not enabled");
out.viewer = m(403, "denied: requester may not read this org (view_assessments)");
out.billing = m(403, "denied: requester may not retest assessments for this org (membership is not testing authority)");
out.missing = m(403, "denied: no such finding for this workspace");
out.locked = m(403, "denied: retesting unlocks with the full report: buy credits to retest findings");
out.halted = m(403, "denied: new assessment launches are paused right now; your existing launches can still be cancelled");
out.unconfirmed = m(403, "denied: could not confirm the fix: the retest was inconclusive; the finding is unchanged");
out.unavailable = m(403, "denied: retest is not available right now; the finding is unchanged");
out.busy = m(503, "provision unavailable");
out.many = m(429, "rate limited; retry after 30s");
out.unknown = m(400, "bad request: something internal 42");
""")
    assert "authenticator" in out["stepup"]["text"] and out["stepup"]["go"] is None
    assert out["proof"]["go"] == "#/assets" and "proof of control" in out["proof"]["text"]
    assert out["auth"]["go"] == "#/assets" and "not authorized" in out["auth"]["text"]
    assert "not available" in out["off"]["text"] and "not available" in out["notEnabled"]["text"]
    assert "role cannot retest" in out["viewer"]["text"] and "role cannot retest" in out["billing"]["text"]
    assert "no longer available" in out["missing"]["text"]
    assert out["locked"]["go"] == "#/billing" and "unlock with the full report" in out["locked"]["text"]
    assert "cannot run right now" in out["halted"]["text"]
    assert "could not confirm a fix" in out["unconfirmed"]["text"] and "unchanged" in out["unconfirmed"]["text"]
    assert out["unavailable"]["text"] == "Retest is not available right now."   # an unwired re-proof: not a failed fix
    assert "updating" in out["busy"]["text"] and "Too many attempts" in out["many"]["text"]
    assert out["unknown"]["text"] == "Retest could not run. Nothing changed."
    for k, v in out.items():                                        # fixed words: no number, no host, no org, ever
        assert not re.search(r"[0-9]", v["text"]), (k, v)
        assert "a.example" not in v["text"] and "org_x" not in v["text"], (k, v)


def test_the_retest_copy_follows_the_product_rules():
    # every string the retest block can show: no model / provider / engine name, no amount, no price or estimate
    from test_customer_onboarding import _FORBIDDEN
    block = _slice(APP_JS.read_text(encoding="utf-8"), _RETEST_START, _RETEST_END)
    # the has("…") arguments are phrases MATCHED in the server's refusal, never shown: leave them out
    matched = set(re.findall(r'has\("((?:[^"\\]|\\.)*)"\)', block))
    shown = [s for s in re.findall(r'"((?:[^"\\]|\\.)*)"', block) if s not in matched]
    assert "Retest" in shown and "Verifying…" in shown              # the census below really reads the copy
    blob = "\n".join(shown)
    assert not _FORBIDDEN.search(blob), _FORBIDDEN.search(blob).group(0)
    assert not re.search(r"estimat|quote|predict|price|\bcost", blob, re.IGNORECASE)


#: The pre-C1b `findingsBlock`, captured verbatim from the branch base as a committed golden so this byte-identical
#: proof needs no git history (CI checks out shallow). If a legitimate change to findingsBlock lands on the base,
#: re-capture it with `git show <base>:apps/sigil/sigil/ui/customer_app/app.js` + the _fn extractor.
_BASE_FINDINGSBLOCK = r"""  function findingsBlock(host, fs) {
    if (!fs.length) { return h("div.card.cust-soon", { text: "No findings for " + host + "." }); }
    var cards = fs.map(function (f) {
      return VUI.card(f.title || f.finding_ref || "Finding", f.severity || null, h("div", {}, [
        kv("Severity", f.severity), kv("Class", f.bug_class), kv("Surface", f.surface), kv("Confidence", f.confidence),
        f.summary ? h("p", { text: f.summary }) : null,
        f.how_to_verify ? h("p.cust-muted", { text: "Verify offline: " + f.how_to_verify }) : null,
      ]));
    });
    return h("div", {}, [h("h3", { text: "Findings — " + host }), h("div.cust-grid", {}, cards)]);
  }"""


def test_findingsblock_is_byte_identical_with_the_flag_off():
    # findingsBlock with the page flag off must render exactly what the pre-C1b build renders for the same inputs —
    # including a finding that carries a retest verdict (a mis-flagged cockpit's read must not change the page).
    src = APP_JS.read_text(encoding="utf-8")
    inputs = r"""
var cases = [{ host: "a.example", fs: [{ engagement_slug: "s", finding_ref: "F1", title: "T", severity: "high",
                bug_class: "xss", surface: "https://x/F1", confidence: "high", summary: "s", how_to_verify: "v",
                oracle_context_digest: "d1" }] },
             { host: "b.example", fs: [{ engagement_slug: "s", finding_ref: "F2" },
                                       { engagement_slug: "s", finding_ref: "F3", retest: { status: "fixed" } }] },
             { host: "c.example", fs: [] }];
console.log(JSON.stringify(cases.map(function (c) { return ser(findingsBlock(c.host, c.fs)); })));
"""
    head = (_dom() + f"\nrequire({json.dumps(str(UI_JS))});\n" + _PRELUDE % {"flag": json.dumps("0"), "server": "{}"}
            + _ser() + _fn(src, "kv") + "\n")
    prog_base = head + _BASE_FINDINGSBLOCK + inputs
    prog_cur = (head + _fn(src, "findingsBlock") + "\n" + _slice(src, _RETEST_START, _RETEST_END)
                + _slice(src, _PROOF_START, _PROOF_END)     # PR-I's proof hook, off too: still identical
                + _slice(src, _BLIND_START, _BLIND_END) + inputs)   # PR-L: blindVulnBadge is null when off
    rb = subprocess.run([_need_node(), "-e", prog_base], capture_output=True, text=True, timeout=60)
    rc = subprocess.run([_need_node(), "-e", prog_cur], capture_output=True, text=True, timeout=60)
    assert rb.returncode == 0, rb.stderr
    assert rc.returncode == 0, rc.stderr
    assert rb.stdout == rc.stdout, "flag OFF must render findingsBlock byte-identically to the pre-C1b build"


# --------------------------------------------------------------------------- the guide ----
def test_the_guide_retest_step_names_the_real_label():
    from test_customer_onboarding import _node
    out = _node("out.chapters = window.VIGIL_GUIDE.CHAPTERS;")
    steps = {(ch["id"], st["id"]): st for ch in out["chapters"] for st in ch["steps"]}
    retest = steps[("assess", "retest")]
    assert retest["route"] == "#/assessments"                      # the screen the Retest button is on (census)
    assert any("select Retest" in c for c in retest["clicks"])    # the guide's label is the real button's
    assert any("marked fixed" in c for c in retest["clicks"]) and "proof stops working" in retest["why"]
    src = APP_JS.read_text(encoding="utf-8")
    assert 'text: "Retest"' in _slice(src, _RETEST_START, _RETEST_END)
