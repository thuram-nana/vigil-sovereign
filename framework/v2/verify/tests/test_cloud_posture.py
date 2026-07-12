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
