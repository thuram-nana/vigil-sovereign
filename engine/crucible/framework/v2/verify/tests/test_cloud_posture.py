"""
Wave-F1 — the cloud/CSPM-posture oracle (retained cloud-posture LEAD -> FACT over its ACHIEVED STATE).

A CSPM tool's "public / unencrypted / grants ``*``" is a THIRD-PARTY heuristic — a LEAD. The cloud-posture
oracle (the achieved-state SIBLING of ``k8s_posture_oracle``) promotes it to a FACT ONLY when the RETAINED
control proves a CONCRETE insecure ACHIEVED STATE: encryption-at-rest disabled on a sensitive datastore
(the ``misconfiguration`` lead the POLICY_PATH oracle structurally cannot prove), an explicit
public-exposure flag, or a wildcard/anonymous principal literally named in the retained policy. A
compliant control (encryption on / not public / no wildcard), one with only ABSENT/unknown flags, an
EXPLICIT pass status, and malformed evidence all correctly do NOT fire — near-zero false positives. The
confirmed fact re-verifies offline from its retained context. NO live cloud call is ever made.
"""

from __future__ import annotations

from framework.v2.verify import (
    cloud_posture_oracle,
    confirm_cloud_posture,
    cloud_posture_context,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier

# A sensitive datastore with encryption-at-rest DISABLED — the un-reachability-provable misconfiguration
# lead, promoted here as an achieved STATE.
_ENC_OFF = {
    "resource_id": "acme-secrets", "status": "FAIL", "provider": "aws",
    "achieved_state": {"encrypted": False, "sensitive": True},
}
# A flat sensors.cloud resource record that is publicly exposed via a wildcard grant.
_PUBLIC_WILDCARD = {
    "id": "acme-public-bucket", "public": True,
    "grants": [{"principal": "*", "access": "read"}],
}


# ---- the oracle fires ONLY on a proven insecure achieved state --------------


def test_fires_on_encryption_at_rest_disabled_on_sensitive_datastore() -> None:
    sig = cloud_posture_oracle(_ENC_OFF)
    assert sig.fired and sig.kind is OracleKind.CLOUD_POSTURE
    assert sig.confidence >= 0.7
    assert sig.observed["rule"] == "encryption_at_rest_disabled"


def test_fires_on_explicit_public_exposure_flag() -> None:
    sig = cloud_posture_oracle({"resource_id": "r", "public": True})
    assert sig.fired
    assert sig.observed["rule"] == "public_exposure"


def test_fires_on_wildcard_principal_in_grants_and_in_principals_list() -> None:
    # via grants[].principal (flat resource record)
    sig = cloud_posture_oracle(_PUBLIC_WILDCARD)
    assert sig.fired
    # public flag is checked before wildcard, so a public bucket fires as public_exposure —
    # a wildcard-ONLY record (no public flag) fires as wildcard_principal:
    for anon in ("*", "AllUsers", "anonymous", "Everyone", "principal:*"):
        s = cloud_posture_oracle({"resource_id": "r", "achieved_state": {"principals": [anon]}})
        assert s.fired, f"wildcard principal {anon!r} should fire"
        assert s.observed["rule"] == "wildcard_principal"


def test_flat_and_nested_achieved_state_are_judged_the_same() -> None:
    nested = {"resource_id": "r", "achieved_state": {"encrypted": False, "sensitive": True}}
    flat = {"resource_id": "r", "encrypted": False, "sensitive": True}
    assert cloud_posture_oracle(nested).fired
    assert cloud_posture_oracle(flat).fired


def test_string_flag_renderings_are_coerced() -> None:
    # a CSPM export may carry stringy booleans
    assert cloud_posture_oracle({"id": "r", "encrypted": "false", "sensitive": "true"}).fired
    assert cloud_posture_oracle({"id": "r", "public": "true"}).fired


# ---- the oracle does NOT fire on a benign / unprovable posture --------------


def test_compliant_control_does_not_fire() -> None:
    # encryption on, not public, a named (non-wildcard) principal — a secure achieved state
    secure = {"resource_id": "r", "encrypted": True, "public": False, "sensitive": True,
              "grants": [{"principal": "arn:aws:iam::123:role/app", "access": "read"}]}
    assert not cloud_posture_oracle(secure).fired


def test_explicit_pass_status_never_fires_even_with_a_flag() -> None:
    # the CSPM tool's own PASS verdict is respected — never promoted
    assert not cloud_posture_oracle({"resource_id": "r", "status": "PASS", "public": True}).fired
    assert not cloud_posture_oracle({"resource_id": "r", "status": "compliant",
                                     "encrypted": False, "sensitive": True}).fired


def test_encryption_disabled_but_not_sensitive_does_not_fire() -> None:
    # mirrors cloud_posture_leads condition-for-condition: the misconfiguration lead requires sensitive
    assert not cloud_posture_oracle({"resource_id": "r", "encrypted": False, "sensitive": False}).fired
    assert not cloud_posture_oracle({"resource_id": "r", "encrypted": False}).fired  # sensitive absent


def test_absent_and_unknown_flags_do_not_fire() -> None:
    # unknown is never an insecure fact (stays a lead)
    assert not cloud_posture_oracle({"resource_id": "r"}).fired
    assert not cloud_posture_oracle({"resource_id": "r", "encrypted": "maybe", "public": "unknown"}).fired
    # a non-wildcard principal is not an insecure state
    assert not cloud_posture_oracle({"resource_id": "r",
                                     "achieved_state": {"principals": ["arn:aws:iam::1:role/x"]}}).fired


def test_garbage_and_empty_do_not_fire_and_never_raise() -> None:
    for junk in (None, "", 123, [], {}, {"status": "FAIL"}, {"achieved_state": "nope"}):
        assert not cloud_posture_oracle(junk).fired


# ---- routing + the frozen-fallback invariant --------------------------------


def test_routes_via_verifier_and_kind_is_out_of_the_frozen_fallback() -> None:
    v = OracleVerifier()
    assert v.oracles_for("cloud_misconfiguration") == (OracleKind.CLOUD_POSTURE,)
    assert v.oracles_for("cloud_posture") == (OracleKind.CLOUD_POSTURE,)      # alias folds
    assert v.oracles_for("public_bucket") == (OracleKind.CLOUD_POSTURE,)      # alias folds
    # the NEW kind is reachable ONLY via its explicit row — never the unknown-class fallback
    assert OracleKind.CLOUD_POSTURE not in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.CLOUD_POSTURE not in v.oracles_for("some_unknown_class")


def test_confirm_via_seam_and_verifier() -> None:
    assert confirm_cloud_posture(_ENC_OFF).confirmed
    assert confirm_cloud_posture(_PUBLIC_WILDCARD).confirmed
    assert OracleVerifier().confirm(cloud_posture_context(_ENC_OFF)).confirmed
    assert not confirm_cloud_posture({"resource_id": "r", "encrypted": True, "public": False}).confirmed


# ---- offline re-verification (prove-don't-guess) ----------------------------


def test_confirmed_posture_reverifies_offline_from_its_retained_context() -> None:
    oracle_context = cloud_posture_context(_ENC_OFF)
    # no cloud, no trust in the scanner — re-run the pure oracle over the retained control
    r = reverify_context(oracle_context, bug_class="cloud_misconfiguration")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.CLOUD_POSTURE.value


def test_adapter_builder_retains_only_structural_fields() -> None:
    ctx = FindingContext.from_cloud_control(
        {**_ENC_OFF, "noise": "verbose scanner prose", "achieved_state":
         {"encrypted": False, "sensitive": True, "junk": "not laundered"}})
    emitted = ctx.to_verifier_context()
    assert "cloud_control" in emitted
    blob = str(emitted["cloud_control"])
    assert "noise" not in blob and "not laundered" not in blob  # non-structural fields NOT laundered
    assert emitted["cloud_control"]["resource_id"] == "acme-secrets"
    assert emitted["cloud_control"]["achieved_state"]["encrypted"] is False


def test_builder_gathers_wildcard_principal_from_flat_grants() -> None:
    ctx = FindingContext.from_cloud_control(_PUBLIC_WILDCARD)
    emitted = ctx.to_verifier_context()
    # the flat grant's principal is gathered into achieved_state.principals for the parse-proof
    assert "*" in emitted["cloud_control"]["achieved_state"]["principals"]
    assert confirm_cloud_posture(_PUBLIC_WILDCARD).confirmed


# =====================================================================================================
# P4 — named cross-account resource principal.
#
# A resource policy that grants a NAMED principal in a DIFFERENT account than the owner is a cross-account
# trust. SOUNDNESS (CLAIM-DISCIPLINE): distinguishing an INTENDED same-account grant from a risky
# cross-account one REQUIRES the owner's own-account id(s). So rule 4 fires ONLY when the retained control
# threads an owner-account set AND a named grantee's parsed account differs. No owner set (unknown owner),
# a same-account principal, or a principal whose account cannot be parsed all stay an honest LEAD — an
# intended internal grant is never promoted and the owner is never guessed. Every negative control below is
# MUTATION-VERIFIED: a single targeted change to the same input flips the verdict to fire, proving the test
# actually exercises rule 4 rather than trivially passing.
# =====================================================================================================

_OWNER = "111122223333"
_EXT = "999988887777"

# owner=111122223333, granting arn:aws:iam::999988887777:root — the canonical cross-account trust.
_XACCT = {
    "resource_id": "acme-secrets", "provider": "aws", "owner_account": _OWNER,
    "grants": [{"principal": f"arn:aws:iam::{_EXT}:root", "access": "read"}],
}


# ---- rule 4 FIRES on a proven cross-account named principal ------------------


def test_fires_on_named_cross_account_principal() -> None:
    sig = cloud_posture_oracle(_XACCT)
    assert sig.fired and sig.kind is OracleKind.CLOUD_POSTURE
    assert sig.confidence >= 0.7
    assert sig.observed["rule"] == "named_cross_account_principal"
    assert sig.observed["principal"] == f"arn:aws:iam::{_EXT}:root"
    assert sig.observed["principal_account"] == _EXT
    assert sig.observed["owner_accounts"] == [_OWNER]


def test_fires_via_owner_accounts_list_and_nested_achieved_state() -> None:
    # owner supplied as a list, principal inside a nested achieved_state, via a user ARN
    ctl = {"resource_id": "r", "owner_accounts": [_OWNER, "444455556666"],
           "achieved_state": {"principals": [f"arn:aws:iam::{_EXT}:user/mallory"]}}
    sig = cloud_posture_oracle(ctl)
    assert sig.fired and sig.observed["rule"] == "named_cross_account_principal"
    assert sig.observed["principal_account"] == _EXT
    # a grantee IN the owner-account list does NOT fire (mutation: point at 444455556666)
    same = {"resource_id": "r", "owner_accounts": [_OWNER, "444455556666"],
            "achieved_state": {"principals": ["arn:aws:iam::444455556666:user/ops"]}}
    assert not cloud_posture_oracle(same).fired


def test_fires_on_bare_12_digit_account_principal() -> None:
    # AWS represents a whole-account principal as just the 12-digit id
    ctl = {"resource_id": "r", "owner_account": _OWNER, "achieved_state": {"principals": [_EXT]}}
    assert cloud_posture_oracle(ctl).fired
    # mutation: the bare account IS the owner -> same-account -> no fire
    assert not cloud_posture_oracle(
        {"resource_id": "r", "owner_account": _OWNER, "achieved_state": {"principals": [_OWNER]}}).fired


def test_fires_on_sts_assumed_role_arn() -> None:
    ctl = {"resource_id": "r", "owner_account": _OWNER,
           "grants": [{"principal": f"arn:aws:sts::{_EXT}:assumed-role/Admin/session"}]}
    sig = cloud_posture_oracle(ctl)
    assert sig.fired and sig.observed["principal_account"] == _EXT


def test_fires_on_gcp_cross_project_service_account() -> None:
    # GCP: the owner is a project id; a serviceAccount member in a DIFFERENT project fires
    ctl = {"resource_id": "gcs-bucket", "provider": "gcp", "owner_account": "acme-prod",
           "grants": [{"principal": "serviceAccount:exfil@evil-corp.iam.gserviceaccount.com"}]}
    sig = cloud_posture_oracle(ctl)
    assert sig.fired and sig.observed["rule"] == "named_cross_account_principal"
    assert sig.observed["principal_account"] == "evil-corp"
    # mutation: same project -> no fire
    same = {"resource_id": "gcs-bucket", "provider": "gcp", "owner_account": "acme-prod",
            "grants": [{"principal": "serviceAccount:svc@acme-prod.iam.gserviceaccount.com"}]}
    assert not cloud_posture_oracle(same).fired


def test_fires_on_gcp_cross_domain_user_member() -> None:
    ctl = {"resource_id": "r", "provider": "gcp", "owner_account": "example.com",
           "grants": [{"principal": "user:attacker@evil.com"}]}
    sig = cloud_posture_oracle(ctl)
    assert sig.fired and sig.observed["principal_account"] == "evil.com"


# ---- MANDATORY negative controls (mutation-verified) — rule 4 must NOT fire --


def test_neg_a_same_account_named_principal_does_not_fire() -> None:
    # (a) owner_account matches the principal's account -> an INTENDED internal grant -> LEAD, not a fact
    same = {"resource_id": "acme-secrets", "provider": "aws", "owner_account": _OWNER,
            "grants": [{"principal": f"arn:aws:iam::{_OWNER}:role/app", "access": "read"}]}
    assert not cloud_posture_oracle(same).fired
    # MUTATION-VERIFIED: change ONLY the owner to a different account -> now cross-account -> fires
    mutated = {**same, "owner_account": "555566667777"}
    assert cloud_posture_oracle(mutated).fired
    assert cloud_posture_oracle(mutated).observed["rule"] == "named_cross_account_principal"


def test_neg_b_no_owner_account_stays_lead() -> None:
    # (b) no owner_account present -> owner unknown -> NEVER fire (must not guess), stays a LEAD
    no_owner = {"resource_id": "acme-secrets", "provider": "aws",
                "grants": [{"principal": f"arn:aws:iam::{_EXT}:root", "access": "read"}]}
    assert not cloud_posture_oracle(no_owner).fired
    # MUTATION-VERIFIED: add ONLY the owner-account field -> the same external grant now fires
    assert cloud_posture_oracle({**no_owner, "owner_account": _OWNER}).fired


def test_neg_c_unparseable_principal_account_does_not_fire() -> None:
    # (c) a principal whose account field cannot be soundly parsed -> un-attributable -> never fire
    for bad in (
        "arn:aws:s3:::acme-bucket",              # service ARN with an EMPTY account field
        "arn:aws:iam::12345:role/short",         # account not 12 digits
        "canonical-user-id-opaque-string",       # opaque non-ARN principal
        "serviceAccount:svc@developer.gserviceaccount.com",  # Google-managed SA, no project in email
    ):
        ctl = {"resource_id": "r", "owner_account": _OWNER, "achieved_state": {"principals": [bad]}}
        assert not cloud_posture_oracle(ctl).fired, f"un-attributable principal {bad!r} must not fire"
    # MUTATION-VERIFIED: a well-formed external ARN in the same shape DOES fire
    ok = {"resource_id": "r", "owner_account": _OWNER,
          "achieved_state": {"principals": [f"arn:aws:iam::{_EXT}:role/x"]}}
    assert cloud_posture_oracle(ok).fired


def test_neg_d_existing_rules_unchanged_when_owner_present() -> None:
    # (d) the pre-existing rules keep FIRING EXACTLY as before, even with an owner-account threaded in and a
    # cross-account principal also present (fixed rule order: enc/public/wildcard win before rule 4).
    # public wins over a co-present cross-account grant
    pub = {"resource_id": "r", "owner_account": _OWNER, "public": True,
           "grants": [{"principal": f"arn:aws:iam::{_EXT}:root"}]}
    assert cloud_posture_oracle(pub).observed["rule"] == "public_exposure"
    # a wildcard grantee wins over a co-present named cross-account grantee
    wild = {"resource_id": "r", "owner_account": _OWNER,
            "grants": [{"principal": "*"}, {"principal": f"arn:aws:iam::{_EXT}:root"}]}
    assert cloud_posture_oracle(wild).observed["rule"] == "wildcard_principal"
    # encryption-off on a sensitive store wins too
    enc = {"resource_id": "r", "owner_account": _OWNER, "encrypted": False, "sensitive": True,
           "grants": [{"principal": f"arn:aws:iam::{_EXT}:root"}]}
    assert cloud_posture_oracle(enc).observed["rule"] == "encryption_at_rest_disabled"
    # an explicit PASS status still suppresses everything, cross-account included
    assert not cloud_posture_oracle({**_XACCT, "status": "PASS"}).fired


def test_neg_cross_account_but_wildcard_owner_never_masks_anon() -> None:
    # an anonymous grantee is rule 3's job — rule 4 must SKIP it (never mis-attribute "*" as an account)
    ctl = {"resource_id": "r", "owner_account": _OWNER, "achieved_state": {"principals": ["*"]}}
    assert cloud_posture_oracle(ctl).observed["rule"] == "wildcard_principal"


# ---- red-pen re-submit: namespace-agreement (BLOCK-1) + owner-token canonicalisation (BLOCK-2) --------


def test_neg_gcp_internal_user_with_project_only_owner_stays_lead() -> None:
    # BLOCK-1: a GCP user/group account is a DOMAIN; a PROJECT-only owner set shares no namespace with it, so
    # an INTERNAL user/group grant must NOT be mistaken for cross-account (the red-pen's project-vs-domain
    # category error) -> LEAD, never fire.
    for member in ("user:employee@acme.com", "group:eng@acme.com"):
        ctl = {"resource_id": "r", "provider": "gcp", "owner_account": "acme-prod",
               "grants": [{"principal": member}]}
        assert not cloud_posture_oracle(ctl).fired, f"internal {member} must not fire with a project-only owner"
    # MUTATION-VERIFIED: thread the OWNED DOMAIN too — an EXTERNAL domain now fires (same namespace, different)
    ext = {"resource_id": "r", "provider": "gcp", "owner_accounts": ["acme-prod", "acme.com"],
           "grants": [{"principal": "user:mallory@evil.com"}]}
    assert cloud_posture_oracle(ext).fired and cloud_posture_oracle(ext).observed["principal_account"] == "evil.com"
    # ...and the INTERNAL user WITH the owned domain threaded is same-account -> still no fire
    internal = {"resource_id": "r", "provider": "gcp", "owner_accounts": ["acme-prod", "acme.com"],
                "grants": [{"principal": "user:employee@acme.com"}]}
    assert not cloud_posture_oracle(internal).fired


def test_neg_gcp_sa_in_own_project_with_domain_only_owner_stays_lead() -> None:
    # BLOCK-1 mirror: a serviceAccount's account is a PROJECT; a DOMAIN-only owner shares no namespace -> LEAD.
    ctl = {"resource_id": "r", "provider": "gcp", "owner_account": "acme.com",
           "grants": [{"principal": "serviceAccount:runner@acme-prod.iam.gserviceaccount.com"}]}
    assert not cloud_posture_oracle(ctl).fired


def test_neg_owner_as_full_arn_same_account_does_not_fire() -> None:
    # BLOCK-2: an owner threaded as a full root ARN must canonicalise to the SAME aws:<id> as a same-account
    # role grant (owner tokens are parsed exactly like principals now) -> no fire.
    ctl = {"resource_id": "r", "owner_account": f"arn:aws:iam::{_OWNER}:root",
           "grants": [{"principal": f"arn:aws:iam::{_OWNER}:role/app"}]}
    assert not cloud_posture_oracle(ctl).fired
    # MUTATION-VERIFIED: an owner ARN of a DIFFERENT account makes the same grant cross-account -> fires
    ctl2 = {"resource_id": "r", "owner_account": f"arn:aws:iam::{_EXT}:root",
            "grants": [{"principal": f"arn:aws:iam::{_OWNER}:role/app"}]}
    assert cloud_posture_oracle(ctl2).fired


def test_neg_owner_prefixed_and_bare_forms_canonicalise_identically() -> None:
    # BLOCK-2: an explicit aws:<id> prefix and a bare 12-digit id reduce to the same token as the principal.
    for owner in (f"aws:{_OWNER}", _OWNER):
        ctl = {"resource_id": "r", "owner_account": owner,
               "grants": [{"principal": f"arn:aws:iam::{_OWNER}:role/app"}]}
        assert not cloud_posture_oracle(ctl).fired, f"owner form {owner!r} must read as same-account"


def test_neg_unusable_owner_token_stays_lead() -> None:
    # BLOCK-2: a labelled or leading-zero-dropped-numeric owner token will NOT canonicalise -> it is dropped
    # -> empty owner set -> LEAD even for an EXTERNAL grant (never a false FACT off a lossy owner token).
    for bad_owner in ("111122223333 (prod)", 12345678901):
        ctl = {"resource_id": "r", "owner_account": bad_owner,
               "grants": [{"principal": f"arn:aws:iam::{_EXT}:root"}]}
        assert not cloud_posture_oracle(ctl).fired, f"unusable owner {bad_owner!r} must stay a LEAD"


# ---- P4 seam / adapter / offline re-verification ----------------------------


def test_cross_account_confirms_via_seam() -> None:
    assert confirm_cloud_posture(_XACCT).confirmed
    assert not confirm_cloud_posture(
        {"resource_id": "r", "owner_account": _OWNER,
         "grants": [{"principal": f"arn:aws:iam::{_OWNER}:role/app"}]}).confirmed


def test_adapter_retains_owner_accounts_for_offline_reverify() -> None:
    ctx = FindingContext.from_cloud_control(_XACCT)
    emitted = ctx.to_verifier_context()
    # the owner-account set is retained top-level so the cross-account rule re-derives the same verdict
    assert emitted["cloud_control"]["owner_accounts"] == [_OWNER]
    assert f"arn:aws:iam::{_EXT}:root" in emitted["cloud_control"]["achieved_state"]["principals"]


def test_cross_account_fact_reverifies_offline_from_retained_context() -> None:
    oracle_context = cloud_posture_context(_XACCT)
    r = reverify_context(oracle_context, bug_class="cloud_misconfiguration")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.CLOUD_POSTURE.value


def test_adapter_absent_owner_is_not_retained_and_stays_lead() -> None:
    # with no owner threaded in, the canonical control carries no owner_accounts and the rule stays a LEAD
    ctl = {"resource_id": "r", "grants": [{"principal": f"arn:aws:iam::{_EXT}:root"}]}
    emitted = FindingContext.from_cloud_control(ctl).to_verifier_context()
    assert "owner_accounts" not in emitted["cloud_control"]
    assert not confirm_cloud_posture(ctl).confirmed
