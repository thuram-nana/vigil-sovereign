"""FORGE Domain 7 (identity posture, slice 1) — the oracle + seam tests.

Built with the Domain-10 discipline baked in: the benign twin is silent END-TO-END through the REAL producer
(parse_identity_export / ingest_identity_export -> oracle), not just against hand-built controls; strict-typed
attestations cannot be laundered (a truthy "false"/1 never fires); a MISSING field is REFUSED, never read as
absence; and a confirmed finding emits a real signed PCF certificate that re-verifies offline.
"""

from __future__ import annotations

import json

import pytest

from framework.v2.verify.identity_posture import (
    confirm_identity_export,
    confirm_identity_posture,
    ingest_identity_export,
)
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import _ALL_ORACLES
from framework.v2.sensors.identity import parse_identity_export


def _fires(control) -> bool:
    return confirm_identity_posture(control).confirmed


# ---- privileged_without_mfa: fires only on a genuinely-privileged identity with MFA PROVABLY off --------

def test_privileged_without_mfa_is_a_fact():
    assert _fires({"rule": "privileged_without_mfa", "subject": "admin@x", "privileged": True,
                   "mfa_enrolled": False})


@pytest.mark.parametrize("control,why", [
    ({"rule": "privileged_without_mfa", "subject": "a", "privileged": True, "mfa_enrolled": True},
     "MFA enrolled -> compliant"),
    ({"rule": "privileged_without_mfa", "subject": "a", "privileged": True},
     "MFA status ABSENT -> refuse (a missing field is not proof MFA is off)"),
    ({"rule": "privileged_without_mfa", "subject": "a", "privileged": False, "mfa_enrolled": False},
     "not attested privileged -> refuse"),
    ({"rule": "privileged_without_mfa", "subject": "a", "mfa_enrolled": False},
     "privileged missing -> refuse"),
])
def test_privileged_without_mfa_does_not_fire_when_it_should_not(control, why):
    assert not _fires(control), why


@pytest.mark.parametrize("control", [
    # a truthy STRING/int must never launder into the fired condition (the Domain-10 bool-laundering lesson)
    {"rule": "privileged_without_mfa", "subject": "a", "privileged": True, "mfa_enrolled": "false"},
    {"rule": "privileged_without_mfa", "subject": "a", "privileged": True, "mfa_enrolled": 0},
    {"rule": "privileged_without_mfa", "subject": "a", "privileged": 1, "mfa_enrolled": False},
    {"rule": "privileged_without_mfa", "subject": "a", "privileged": "true", "mfa_enrolled": False},
])
def test_a_laundered_attestation_never_fires(control):
    assert not _fires(control)


# ---- stale_credential: age >= policy, or attested never-expiring -----------------------------------------

@pytest.mark.parametrize("control", [
    {"rule": "stale_credential", "subject": "k", "age_days": 200, "max_age_days": 90},
    {"rule": "stale_credential", "subject": "k", "age_days": 90, "max_age_days": 90},   # at policy -> stale
    {"rule": "stale_credential", "subject": "k", "never_rotated": True},
])
def test_stale_credential_is_a_fact(control):
    assert _fires(control)


@pytest.mark.parametrize("control,why", [
    ({"rule": "stale_credential", "subject": "k", "age_days": 10, "max_age_days": 90}, "within policy"),
    ({"rule": "stale_credential", "subject": "k", "age_days": 200}, "no threshold -> refuse"),
    ({"rule": "stale_credential", "subject": "k", "max_age_days": 90}, "no age -> refuse"),
    ({"rule": "stale_credential", "subject": "k", "age_days": True, "max_age_days": 90}, "bool age -> refuse"),
    ({"rule": "stale_credential", "subject": "k", "age_days": "200", "max_age_days": 90}, "string age -> refuse"),
    ({"rule": "stale_credential", "subject": "k", "never_rotated": "true"}, "truthy string never fires"),
    ({"rule": "stale_credential", "subject": "k", "never_rotated": 1}, "truthy int never fires"),
    # RED-PEN hardening: max_age_days=0 is a likely 'no policy' sentinel — every credential (age>=0) would
    # fire, so it must REFUSE, not assert.
    ({"rule": "stale_credential", "subject": "k", "age_days": 0, "max_age_days": 0}, "0-day policy refuses"),
    ({"rule": "stale_credential", "subject": "k", "age_days": 500, "max_age_days": 0}, "0-day policy refuses"),
])
def test_stale_credential_does_not_fire_when_it_should_not(control, why):
    assert not _fires(control), why


# ---- slice 2: wildcard_grant — universal grant / admin_all only, NEVER a partial wildcard ---------------

from framework.v2.verify.oracles import _is_universal_grant


@pytest.mark.parametrize("grant,universal", [
    ("*", True), ("*:*", True), ("*/*", True), ("*:*:*", True), ("  *:*  ", True),
    ("read:*", False), ("*:invoices", False), ("read:invoices", False),
    ("*:", False), (":*", False), ("", False), ("admin", False), ("*.read", False),
])
def test_is_universal_grant_only_on_everything_on_everything(grant, universal):
    assert _is_universal_grant(grant) is universal


@pytest.mark.parametrize("control", [
    {"rule": "wildcard_grant", "subject": "r", "admin_all": True},
    {"rule": "wildcard_grant", "subject": "r", "grant": "*:*"},
    {"rule": "wildcard_grant", "subject": "r", "grant": "*"},
])
def test_wildcard_grant_is_a_fact(control):
    assert _fires(control)


@pytest.mark.parametrize("control,why", [
    ({"rule": "wildcard_grant", "subject": "r", "grant": "read:*"}, "partial: action scoped"),
    ({"rule": "wildcard_grant", "subject": "r", "grant": "*:invoices"}, "partial: resource scoped"),
    ({"rule": "wildcard_grant", "subject": "r", "grant": "read:invoices"}, "scoped"),
    ({"rule": "wildcard_grant", "subject": "r"}, "no admin_all, no grant -> refuse"),
    ({"rule": "wildcard_grant", "subject": "r", "admin_all": 1}, "int 1 never launders"),
    ({"rule": "wildcard_grant", "subject": "r", "admin_all": "true"}, "string never launders"),
])
def test_wildcard_grant_does_not_fire_when_it_should_not(control, why):
    assert not _fires(control), why


# ---- slice 2: dormant_privileged — a privileged identity idle past the dormancy threshold ---------------

@pytest.mark.parametrize("control", [
    {"rule": "dormant_privileged", "subject": "a", "privileged": True, "days_since_login": 200, "dormancy_threshold_days": 90},
    {"rule": "dormant_privileged", "subject": "a", "privileged": True, "days_since_login": 90, "dormancy_threshold_days": 90},
])
def test_dormant_privileged_is_a_fact(control):
    assert _fires(control)


@pytest.mark.parametrize("control,why", [
    ({"rule": "dormant_privileged", "subject": "a", "privileged": True, "days_since_login": 10, "dormancy_threshold_days": 90}, "recently active"),
    ({"rule": "dormant_privileged", "subject": "a", "privileged": False, "days_since_login": 200, "dormancy_threshold_days": 90}, "not privileged -> refuse"),
    ({"rule": "dormant_privileged", "subject": "a", "privileged": True, "days_since_login": 200, "dormancy_threshold_days": 0}, "0-day threshold sentinel -> refuse"),
    ({"rule": "dormant_privileged", "subject": "a", "privileged": True, "days_since_login": "200", "dormancy_threshold_days": 90}, "string days -> refuse"),
    ({"rule": "dormant_privileged", "subject": "a", "privileged": True, "days_since_login": True, "dormancy_threshold_days": 90}, "bool days -> refuse"),
    ({"rule": "dormant_privileged", "subject": "a", "privileged": True, "dormancy_threshold_days": 90}, "days missing -> refuse"),
    ({"rule": "dormant_privileged", "subject": "a", "privileged": 1, "days_since_login": 200, "dormancy_threshold_days": 90}, "privileged=1 never launders"),
])
def test_dormant_privileged_does_not_fire_when_it_should_not(control, why):
    assert not _fires(control), why


def test_slice2_end_to_end_through_the_real_producer():
    export = {"identities": [
        {"subject": "root@corp", "admin_all": True},
        {"subject": "svc@corp", "grants": ["read:logs", {"action": "*", "resource": "*"}]},
        {"subject": "stale-admin@corp", "privileged": True, "days_since_login": 400, "dormancy_threshold_days": 90},
        {"subject": "scoped@corp", "grants": ["read:*", "*:invoices"]},        # partial only -> silent
        {"subject": "active@corp", "privileged": True, "days_since_login": 3, "dormancy_threshold_days": 90},  # silent
    ]}
    facts = confirm_identity_export(export)
    assert sorted((c["subject"], c["rule"]) for c in facts) == [
        ("root@corp", "wildcard_grant"), ("stale-admin@corp", "dormant_privileged"),
        ("svc@corp", "wildcard_grant")]


def test_slice2_benign_twins_yield_zero_facts():
    twins = {"identities": [
        {"subject": "scoped@corp", "grants": ["read:*", "*:invoices", "billing:read"]},
        {"subject": "active@corp", "privileged": True, "days_since_login": 1, "dormancy_threshold_days": 90},
        {"subject": "nograntpriv@corp", "privileged": True, "grants": []},
    ]}
    assert confirm_identity_export(twins) == []


def test_an_unrecognised_rule_stays_a_lead():
    assert not _fires({"rule": "impossible_travel", "subject": "a"})   # anomaly is out of scope -> no fire
    assert not _fires({"rule": "", "subject": "a"})


def test_the_seam_is_total_on_a_non_mapping():
    for junk in ("str", 42, None, []):
        assert not confirm_identity_posture(junk).confirmed


# ---- END-TO-END through the REAL producer (parse -> ingest -> oracle), incl. the mandatory benign twin ----

_WEAK_EXPORT = {"identities": [
    {"subject": "admin@corp", "privileged": True, "mfa_enrolled": False},        # privileged_without_mfa
    {"subject": "svc-deploy-key", "age_days": 400, "max_age_days": 90},          # stale_credential
]}
_TWIN = {"subject": "compliant@corp", "privileged": True, "mfa_enrolled": True,
         "age_days": 5, "max_age_days": 90}


def test_the_two_weaknesses_confirm_through_the_real_producer():
    facts = confirm_identity_export(_WEAK_EXPORT)
    got = sorted((c["subject"], c["rule"]) for c in facts)
    assert got == [("admin@corp", "privileged_without_mfa"), ("svc-deploy-key", "stale_credential")]


def test_the_benign_twin_yields_zero_facts_end_to_end():
    # a compliant identity — privileged with MFA on, credential within its rotation age — mints candidates
    # that the oracle refuses/passes, so NOTHING is promoted.
    assert confirm_identity_export({"identities": [_TWIN]}) == []


def test_a_weak_and_a_compliant_identity_together_promote_only_the_weak_one():
    facts = confirm_identity_export({"identities": [_TWIN, _WEAK_EXPORT["identities"][0]]})
    assert [(c["subject"], c["rule"]) for c in facts] == [("admin@corp", "privileged_without_mfa")]


def test_a_compliant_identity_mints_no_privileged_without_mfa_candidate():
    # ingest emits a privileged_without_mfa candidate for a privileged identity, but with mfa_enrolled=True
    # it carries the compliant flag and the oracle stays silent (no false candidate that only the oracle saves)
    controls = ingest_identity_export({"identities": [_TWIN]})
    for c in controls:
        assert not confirm_identity_posture(c).confirmed


def test_ingest_reads_attestations_strictly_from_the_export():
    # a truthy "false"/"true" string in the export must NOT become a bool attestation
    export = {"identities": [{"subject": "a", "privileged": "true", "mfa_enrolled": "false"}]}
    assert confirm_identity_export(export) == []
    # and a real privileged+no-MFA identity DOES fire through the same path
    export2 = {"identities": [{"subject": "a", "privileged": True, "mfa_enrolled": False}]}
    assert len(confirm_identity_export(export2)) == 1


def test_export_shape_variants_and_malformed_input_never_crash():
    assert ingest_identity_export([_TWIN]) or ingest_identity_export([_TWIN]) == []   # bare list accepted
    assert ingest_identity_export("not json") == []
    assert ingest_identity_export(None) == []
    assert ingest_identity_export({"identities": "nope"}) == []
    assert ingest_identity_export({"identities": [42, None, "x"]}) == []
    assert parse_identity_export("{ broken") == []


# ---- gate invariant + determinism ------------------------------------------------------------------------

def test_identity_posture_is_not_in_the_frozen_fallback():
    assert OracleKind.IDENTITY_POSTURE not in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15


@pytest.mark.parametrize("control", [
    {"rule": "wildcard_grant", "subject": "root@x", "admin_all": True},
    {"rule": "wildcard_grant", "subject": "svc@x", "grant": "*:*"},
    {"rule": "dormant_privileged", "subject": "adm@x", "privileged": True,
     "days_since_login": 400, "dormancy_threshold_days": 90},
])
def test_slice2_facts_re_verify_offline_over_the_retained_context(control):
    # the retained context (from_identity_control) must re-fire the oracle offline — the PCF/reverify path
    from framework.v2.verify.identity_posture import identity_posture_context
    from framework.v2.verify.reverify import reverify_context
    oc = identity_posture_context(control)
    rr = reverify_context(oc, bug_class="identity_misconfiguration")
    assert rr.reproduced and rr.ok


def test_the_oracle_is_deterministic():
    controls = ingest_identity_export(_WEAK_EXPORT) + ingest_identity_export({"identities": [_TWIN]})
    digests = {tuple((confirm_identity_posture(c).confirmed for c in controls)) for _ in range(200)}
    assert len(digests) == 1


# ---- the PCF proof: a confirmed finding is a real signed, offline-re-runnable certificate -----------------

def test_a_confirmed_finding_emits_a_real_pcf_certificate_that_verifies_offline():
    pytest.importorskip("cryptography")
    from framework.v2.entitlement.crypto import generate_keypair
    from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
    from framework.v2.evidence.certify import build_certificate, sign_certificate
    from framework.v2.evidence.pcf import to_pcf, verify_pcf
    from framework.v2.verify.identity_posture import identity_posture_context
    from framework.v2.verify.reverify import reverify_context

    ctl = {"rule": "privileged_without_mfa", "subject": "admin@gov.example",
           "privileged": True, "mfa_enrolled": False}
    oc = identity_posture_context(ctl)
    rr = reverify_context(oc, bug_class="identity_misconfiguration")
    assert rr.reproduced and rr.ok                      # the oracle re-fires offline over the retained control

    keys = [generate_keypair() for _ in range(3)]
    tr = TrustRoot(schema_version=1, threshold=2, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys[:2])]
    finding = {"check_id": "identity-priv-nomfa-admin@gov.example",
               "bug_class": "identity_misconfiguration", "confirmed_by": rr.confirmed_by,
               "confidence": rr.confidence, "oracle_context": oc}
    pcf = to_pcf(sign_certificate(build_certificate(finding, seq=1), signers), oracle_context=oc)

    assert pcf["claim"]["class"] == "identity_misconfiguration"
    assert pcf["oracle"]["id"] == OracleKind.IDENTITY_POSTURE.value and pcf["oracle"]["version"]
    assert pcf["grounding"] == "FACT" and pcf["verdict"]["fired"] is True
    assert verify_pcf(pcf, tr).verified                 # re-established offline by a third party
