"""
Tests for the email-auth posture sensor (FORGE Domain 10, stage 1 — the DNS policy-export ingest).

An operator-supplied DNS export is ingested (offline — NO DNS query, NO mail) as a gated sensor → policy
CONTROL LEADS (``GROUNDING_INTEL``), never facts. The sensor STOPS at leads; the email-auth-posture oracle
re-verifies a lead to a FACT only when the PUBLISHED policy provably permits spoofing. Mirrors
``test_cicd_sensor``.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.v2.agents.tools import ToolContext
from framework.v2.agents.tools.base import ToolRegistry
from framework.v2.sensors import EmailAuthSensor, email_auth_observations, parse_email_auth_export
from framework.v2.sensors.builtin import register_builtin_sensors

# A realistic estate. NOTE (RED-PEN BLOCK-3): `inherits.gov.example` publishes NO DMARC of its own and is a
# SUBDOMAIN of an org domain with p=reject — it is FULLY PROTECTED by RFC 7489 §6.6.3 inheritance and must
# NOT fire. An earlier fixture omitted the org domain entirely and asserted that FP as expected behaviour.
_EXPORT = json.dumps({"domains": [
    {"domain": "spoofable.example", "dmarc": "v=DMARC1; p=none", "spf": "v=spf1 mx +all",
     "dmarc_observed": True, "is_org_domain": True},
    {"domain": "hardened.example", "dmarc": "v=DMARC1; p=reject", "spf": "v=spf1 -all",
     "dmarc_observed": True, "is_org_domain": True},
    {"domain": "nodmarc.example", "spf": "v=spf1 -all", "dmarc_observed": True, "is_org_domain": True},
    {"domain": "inherits.hardened.example", "spf": "v=spf1 -all", "dmarc_observed": True,
     "org_domain": "hardened.example", "org_dmarc": "v=DMARC1; p=reject", "org_dmarc_observed": True},
]})


def test_parse_emits_candidates_with_stable_check_ids():
    cids = sorted(c["check_id"] for c in parse_email_auth_export(_EXPORT))
    assert cids == ["hardened.example:dmarc_none", "hardened.example:spf_permissive",
                    "inherits.hardened.example:dmarc_missing", "inherits.hardened.example:spf_permissive",
                    "nodmarc.example:dmarc_missing", "nodmarc.example:spf_permissive",
                    "spoofable.example:dmarc_none", "spoofable.example:spf_permissive"]
    assert len(set(cids)) == len(cids)


def test_only_the_genuinely_spoofable_domains_promote_to_facts():
    from framework.v2.verify.email_auth import confirm_email_auth_posture
    facts = sorted(c["check_id"] for c in parse_email_auth_export(_EXPORT)
                   if confirm_email_auth_posture(c).confirmed)
    # the hardened ORG domain contributes nothing; the INHERITING SUBDOMAIN contributes nothing (it is
    # protected by its org p=reject — the RED-PEN BLOCK-1 case); only the truly-open domains fire.
    assert facts == ["nodmarc.example:dmarc_missing", "spoofable.example:dmarc_none",
                     "spoofable.example:spf_permissive"]


def test_a_hardened_estate_yields_zero_facts():
    """RED-PEN BLOCK-1 regression, through the REAL sensor path: an estate whose org domain enforces and
    whose subdomains correctly inherit must produce NO facts at all (the mandatory benign twin)."""
    from framework.v2.verify.email_auth import confirm_email_auth_posture
    hardened = json.dumps({"domains": [
        {"domain": "gov.example", "dmarc": "v=DMARC1; p=reject; rua=mailto:d@gov.example",
         "spf": "v=spf1 include:_spf.gov.example -all", "dmarc_observed": True, "is_org_domain": True},
        {"domain": "mail.gov.example", "spf": "v=spf1 include:_spf.gov.example -all", "dmarc_observed": True,
         "org_domain": "gov.example", "org_dmarc": "v=DMARC1; p=reject", "org_dmarc_observed": True},
        {"domain": "news.gov.example", "spf": "v=spf1 -all", "dmarc_observed": True,
         "org_domain": "gov.example", "org_dmarc": "v=DMARC1; p=reject", "org_dmarc_observed": True},
    ]})
    assert [c["check_id"] for c in parse_email_auth_export(hardened)
            if confirm_email_auth_posture(c).confirmed] == []


def test_a_falsified_attestation_in_the_export_never_promotes():
    """RED-PEN BLOCK-2 regression: an export that explicitly attests the lookup was NOT observed must not
    yield a fact — the sensor reads attestations strictly, so nothing can be laundered into a certificate."""
    from framework.v2.verify.email_auth import confirm_email_auth_posture
    bad = json.dumps({"domains": [{"domain": "g.example", "dmarc_observed": "false",
                                   "is_org_domain": "true"}]})
    assert [c for c in parse_email_auth_export(bad) if confirm_email_auth_posture(c).confirmed] == []


def test_parse_is_total_on_garbage():
    for junk in ("", "{bad json", "null", "123", "[]", '{"domains": "nope"}', '{"domains":[{"x":1}]}'):
        assert parse_email_auth_export(junk) == []


def test_observations_are_leads_not_facts():
    obs = email_auth_observations(parse_email_auth_export(_EXPORT), seq=1)
    assert obs
    for o in obs:
        assert o.source == "email_auth"
        assert o.source_kind.value == "operator_ingest"
        assert 0.0 < o.confidence < 1.0
        assert o.relation is None and o.object is None
        assert o.subject.node_id.startswith("control:email:")
        assert o.attrs.get("lead") is True and o.attrs.get("unverified") is True


def test_obs_ids_are_claim_keyed_and_reingest_is_idempotent():
    controls = parse_email_auth_export(_EXPORT)
    ids1 = [o.obs_id for o in email_auth_observations(controls, seq=1)]
    assert ids1 == [o.obs_id for o in email_auth_observations(controls, seq=1)]
    assert [o.obs_id for o in email_auth_observations(controls + controls, seq=1)] == ids1


def test_sensor_ingests_export_and_mints_leads(tmp_path: Path):
    p = tmp_path / "dns.json"
    p.write_text(_EXPORT, encoding="utf-8")
    s = EmailAuthSensor()
    ctx = ToolContext(slug="alpha")
    res = s.run({"export": str(p)}, ctx)
    assert res.ok and res.summary == "email_auth: 8 policy control(s)"
    assert all(o.subject.node_id.startswith("control:email:") for o in s.normalize(res, ctx, seq=1))


def test_sensor_is_passive_tier1_and_degrades_cleanly(tmp_path: Path):
    s = EmailAuthSensor()
    assert s.tier == "T1" and s.capability is None and s.egress_hosts == () and s.destructive is False
    ctx = ToolContext(slug="alpha")
    assert not s.run({}, ctx).ok
    assert not s.run({"export": "/no/such/dns.json"}, ctx).ok
    p = tmp_path / "junk.json"
    p.write_text("{bad", encoding="utf-8")
    res = s.run({"export": str(p)}, ctx)
    assert res.ok and s.normalize(res, ctx, seq=1) == []


def test_registered_in_default_registry():
    assert "email_auth" in register_builtin_sensors(ToolRegistry())
