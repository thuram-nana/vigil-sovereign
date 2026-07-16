"""verify.email_auth — the email-auth-posture oracle (FORGE Domain 10, the first FORGE-built stream).

Pins the domain charter's contract:
  * FIRES on a PUBLISHED policy that provably permits spoofing — no DMARC (observed), DMARC ``p=none``,
    or SPF ``+all``.
  * SILENT on the mandatory benign twin — a hardened domain (``p=reject``/``p=quarantine``, SPF ``-all``).
  * REFUSES rather than asserts: an unobserved absence, an unparseable record, and ``spf_missing`` (a
    gating chain — DKIM+DMARC may still protect the domain) never fire.
  * Held OUT of the frozen fallback so ``make gate`` stays byte-identical.
  * A confirmed finding emits a REAL signed PCF v0.1 certificate that re-verifies offline.
"""

from __future__ import annotations

import pytest

from framework.v2.verify.email_auth import (
    confirm_dns_policy,
    confirm_email_auth_posture,
    ingest_dns_policy,
)
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import _ALL_ORACLES

_HARDENED_DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@gov.example; pct=100"
_HARDENED_SPF = "v=spf1 include:_spf.gov.example -all"


# ---- FIRES: a published policy that provably permits spoofing ----

def test_no_dmarc_on_an_organizational_domain_is_a_fact():
    # an ORG domain has no parent to inherit from, so an observed absence really is "no policy"
    r = confirm_email_auth_posture({"rule": "dmarc_missing", "domain": "gov.example",
                                    "dmarc_observed": True, "is_org_domain": True})
    assert r.confirmed
    assert any(s.kind == OracleKind.EMAIL_AUTH_POSTURE and s.fired for s in r.signals)


# ---- RED-PEN BLOCK-1 regression: the RFC 7489 §6.6.3 inheritance chain ----
# The benign twin MUST be parameterized over DOMAIN SHAPE (org vs subdomain), not only record content —
# that is the axis on which the original rule was unsound (it fired on a hardened subdomain).

_SUB = {"rule": "dmarc_missing", "domain": "mail.gov.example", "dmarc_observed": True,
        "org_domain": "gov.example", "org_dmarc_observed": True}


@pytest.mark.parametrize("org_record", ["v=DMARC1; p=reject", "v=DMARC1; p=quarantine",
                                        "v=DMARC1; p=reject; pct=100; rua=mailto:d@gov.example"])
def test_a_subdomain_inheriting_an_enforcing_org_policy_does_not_fire(org_record):
    # THE cardinal case: a subdomain that correctly publishes nothing is FULLY protected by its org domain
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed


@pytest.mark.parametrize("org_record,why", [
    ("v=DMARC1; p=reject; sp=none", "sp= overrides p= FOR SUBDOMAINS (RFC 7489 §6.3)"),
    ("v=DMARC1; p=none", "the org policy itself is none"),
])
def test_a_subdomain_inheriting_a_non_enforcing_policy_is_a_fact(org_record, why):
    assert confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed, why


def test_no_dmarc_anywhere_in_the_chain_is_a_fact():
    assert confirm_email_auth_posture(_SUB).confirmed   # org lookup observed, no org record either


def test_an_unresolved_inheritance_chain_refuses():
    # a subdomain whose org-domain policy was NOT retained/observed: absence proves NOTHING -> REFUSE
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "mail.gov.example", "dmarc_observed": True}).confirmed
    # …and an org record with no parseable policy is likewise unresolved
    assert not confirm_email_auth_posture(
        {**_SUB, "org_dmarc_record": "v=DMARC1; rua=mailto:x@y"}).confirmed


# ---- RED-PEN BLOCK-2 regression: attestations are STRICT (never bool()-coerced) ----

@pytest.mark.parametrize("bad", ["false", "no", "0", 0, 1, "true", "True", [], {}])
def test_a_non_true_observed_attestation_never_promotes(bad):
    # a truthy-but-not-True value must NOT launder into a fact — the coercion happened BEFORE minting, so
    # a laundered attestation would re-fire forever under signature.
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "g", "dmarc_observed": bad, "is_org_domain": True}).confirmed


@pytest.mark.parametrize("bad", ["false", "no", 0, 1, "true"])
def test_a_non_true_org_attestation_never_promotes(bad):
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "mail.gov.example", "dmarc_observed": True,
         "org_dmarc_observed": bad}).confirmed


def test_the_retained_certificate_cannot_carry_a_laundered_attestation():
    # the RETAINED context (what gets signed + re-fires forever) must not contain a coerced True
    from framework.v2.verify.email_auth import email_auth_context
    ctx = email_auth_context({"rule": "dmarc_missing", "domain": "g", "dmarc_observed": "false",
                              "is_org_domain": "true"})
    ctl = ctx["email_auth_control"]
    assert "dmarc_observed" not in ctl and "is_org_domain" not in ctl


def test_the_seam_is_total_on_a_non_mapping():
    for junk in ("str", 42, None, []):
        assert not confirm_email_auth_posture(junk).confirmed


# ---- RED-PEN BLOCK-4/5 regression: the RECORD-ENCODING axis ----
# A DNS TXT record is a QUOTED character-string on the wire (`dig +short` emits quotes) and RFC 1035
# §3.3.14 splits a long one into ADJACENT strings a resolver concatenates. Parsing the presentation form
# directly let a closing quote HIDE a protective `sp=` tag while leaving a permissive `p=` visible — the
# twin must therefore be parameterized over ENCODING, not only over record content and domain shape.

_PROTECTED_ORG = "v=DMARC1; p=none; sp=reject"      # org monitors its own mail, REJECTS subdomains
_EXPOSED_ORG = "v=DMARC1; p=reject; sp=none"        # org enforces its own mail, exempts subdomains


def _encodings(record: str) -> list[tuple[str, str]]:
    head, _, tail = record.partition("; sp=")
    return [
        ("bare", record),
        ("quoted (dig +short)", f'"{record}"'),
        ("multi-string TXT", f'"{head};" " sp={tail}"'),
        ("zone-file quoted+ttl", f'_dmarc.gov.example. 3600 IN TXT "{record}"'),
    ]


@pytest.mark.parametrize("label,org_record", _encodings(_PROTECTED_ORG))
def test_a_protected_subdomain_never_fires_in_any_record_encoding(label, org_record):
    # THE BLOCK-4 case: in EVERY wire encoding, an org `sp=reject` protects the subdomain -> no fact.
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed, label


@pytest.mark.parametrize("label,org_record", _encodings(_EXPOSED_ORG))
def test_an_exposed_subdomain_still_fires_in_any_record_encoding(label, org_record):
    # …and normalisation must not silence the genuine weakness either (no safe-but-useless refusal).
    assert confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed, label


@pytest.mark.parametrize("org_record", [
    "v=DMARC1; p=none; sp=reject.",     # trailing dot — sp= present, value unparseable
    "v=DMARC1; p=none; sp=rejct",       # typo'd value
    "v=DMARC1; p=none; sp=",            # empty value
])
def test_an_unparseable_sp_tag_refuses_instead_of_falling_through_to_p(org_record):
    """The BLOCK-4 root cause: 'the sp= value regex did not match' must NEVER be read as 'there is no sp=
    tag'. A failed parse is not proof of absence — falling through to `p=` reads the WRONG tag and asserts
    the negative (the same error class as assuming a missing record means no policy). REFUSE."""
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed


@pytest.mark.parametrize("rule,field,record,want", [
    ("dmarc_none", "dmarc_record", '"v=DMARC1; p=none"', True),
    ("dmarc_none", "dmarc_record", '"v=DMARC1; p=reject"', False),
    ("dmarc_none", "dmarc_record", '"v=DMARC1;" " p=none"', True),
    ("spf_permissive", "spf_record", '"v=spf1 +all"', True),
    ("spf_permissive", "spf_record", '"v=spf1 -all"', False),
    ("spf_permissive", "spf_record", '"v=spf1 mx" " +all"', True),
])
def test_the_other_rules_read_the_wire_encoding_correctly(rule, field, record, want):
    assert confirm_email_auth_posture({"rule": rule, "domain": "g", field: record}).confirmed is want


# ---- RED-PEN LOW regression: contradictory / unauditable evidence refuses ----

def test_contradictory_org_evidence_refuses():
    # attested an ORG domain AND handed an org policy to inherit -> refuse, don't take the firing branch
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "g", "dmarc_observed": True, "is_org_domain": True,
         "org_dmarc_record": "v=DMARC1; p=reject"}).confirmed


def test_an_unnamed_org_domain_refuses_so_the_certificate_stays_auditable():
    # a fired cert must NAME the domain whose policy was looked up, or a third party cannot audit it
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "mail.g", "dmarc_observed": True,
         "org_dmarc_observed": True}).confirmed


@pytest.mark.parametrize("record", [
    "v=DMARC1; p=none",
    "v=DMARC1;p=none;rua=mailto:x@y",
    "V=DMARC1; P=None; sp=reject",          # case-insensitive
    "v=DMARC1; adkim=s; p = none ; pct=100",  # spacing
])
def test_dmarc_p_none_is_a_fact(record):
    assert confirm_email_auth_posture(
        {"rule": "dmarc_none", "domain": "gov.example", "dmarc_record": record}).confirmed


@pytest.mark.parametrize("record", [
    "v=spf1 include:_spf.example.com +all",
    "v=spf1 mx all",                 # a bare `all` defaults to the PASS qualifier (+all)
    "v=spf1 a:mail.example.com  +all ",
])
def test_spf_pass_all_is_a_fact(record):
    assert confirm_email_auth_posture(
        {"rule": "spf_permissive", "domain": "gov.example", "spf_record": record}).confirmed


# ---- SILENT on the mandatory benign twin (a hardened domain) ----

@pytest.mark.parametrize("record", [_HARDENED_DMARC, "v=DMARC1; p=quarantine", "v=DMARC1;p=QUARANTINE;pct=50"])
def test_enforcing_dmarc_does_not_fire(record):
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_none", "domain": "gov.example", "dmarc_record": record}).confirmed


@pytest.mark.parametrize("record", [_HARDENED_SPF, "v=spf1 mx ~all", "v=spf1 a ?all", "v=spf1 -all"])
def test_non_pass_all_spf_does_not_fire(record):
    assert not confirm_email_auth_posture(
        {"rule": "spf_permissive", "domain": "gov.example", "spf_record": record}).confirmed


def test_the_benign_twin_domain_yields_no_facts_end_to_end():
    # a correctly-configured domain: enforcing DMARC + a hard-fail SPF -> NOTHING is promoted
    assert confirm_dns_policy("gov.example", dmarc_record=_HARDENED_DMARC, spf_record=_HARDENED_SPF,
                              dmarc_observed=True) == []


# ---- REFUSES (absence/ambiguity is never asserted) ----

def test_unobserved_absence_refuses():
    # the producer did not attest the lookup happened -> "missing" is unproven
    assert not confirm_email_auth_posture({"rule": "dmarc_missing", "domain": "gov.example"}).confirmed


def test_dmarc_missing_with_a_record_present_does_not_fire():
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "g", "dmarc_observed": True,
         "dmarc_record": _HARDENED_DMARC}).confirmed


@pytest.mark.parametrize("record", ["", "garbage", "v=DMARC1; rua=mailto:x@y"])   # no p= tag
def test_unparseable_dmarc_refuses(record):
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_none", "domain": "g", "dmarc_record": record}).confirmed


def test_spf_missing_is_a_gating_chain_and_never_fires():
    # DKIM+DMARC may still protect the domain -> absence of SPF is NOT a standalone fact
    assert not confirm_email_auth_posture({"rule": "spf_permissive", "domain": "g"}).confirmed
    assert not confirm_email_auth_posture({"rule": "spf_missing", "domain": "g"}).confirmed
    assert not confirm_email_auth_posture(
        {"rule": "spf_permissive", "domain": "g", "spf_record": "v=spf1 include:_spf.x"}).confirmed  # no `all`


def test_unknown_rule_and_malformed_are_safe():
    for ctl in ({}, {"rule": "message_dkim_fail"}, {"rule": ""}):
        assert not confirm_email_auth_posture(ctl).confirmed


# ---- the offline ingest ----

def test_ingest_emits_candidates_and_never_asserts_unobserved_absence():
    assert [c["rule"] for c in ingest_dns_policy("g", dmarc_record="v=DMARC1; p=none",
                                                 spf_record="v=spf1 -all")] == ["dmarc_none", "spf_permissive"]
    # no DMARC + the lookup WAS observed -> a dmarc_missing candidate
    assert [c["rule"] for c in ingest_dns_policy("g", dmarc_observed=True)] == ["dmarc_missing"]
    # no DMARC and the lookup was NOT observed -> no candidate at all (absence unproven)
    assert ingest_dns_policy("g") == []


# ---- gate discipline + the PCF foundation (why this domain is real functionality) ----

def test_email_auth_posture_is_not_in_the_frozen_fallback():
    assert OracleKind.EMAIL_AUTH_POSTURE not in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15


def test_a_confirmed_finding_emits_a_real_pcf_certificate_that_verifies_offline():
    """The point of building this domain ON the PCF foundation: its finding is a signed, re-runnable
    Proof-Carrying Finding by construction — not a prototype."""
    pytest.importorskip("cryptography")
    from framework.v2.entitlement.crypto import generate_keypair
    from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
    from framework.v2.evidence.certify import build_certificate, sign_certificate
    from framework.v2.evidence.pcf import to_pcf, verify_pcf
    from framework.v2.verify.email_auth import email_auth_context
    from framework.v2.verify.reverify import reverify_context

    ctl = {"rule": "dmarc_none", "domain": "gov.example", "dmarc_record": "v=DMARC1; p=none"}
    oc = email_auth_context(ctl)
    rr = reverify_context(oc, bug_class="email_auth_misconfiguration")
    assert rr.reproduced and rr.ok                      # the oracle re-fires offline over the retained record

    keys = [generate_keypair() for _ in range(3)]
    tr = TrustRoot(schema_version=1, threshold=2, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys[:2])]
    finding = {"check_id": "email-dmarc-none-gov.example", "bug_class": "email_auth_misconfiguration",
               "confirmed_by": rr.confirmed_by, "confidence": rr.confidence, "oracle_context": oc}
    pcf = to_pcf(sign_certificate(build_certificate(finding, seq=1), signers), oracle_context=oc)

    assert pcf["claim"]["class"] == "email_auth_misconfiguration"
    assert pcf["oracle"]["id"] == OracleKind.EMAIL_AUTH_POSTURE.value and pcf["oracle"]["version"]
    assert pcf["grounding"] == "FACT" and pcf["verdict"]["fired"] is True
    assert verify_pcf(pcf, tr).verified                 # re-established offline by a third party
