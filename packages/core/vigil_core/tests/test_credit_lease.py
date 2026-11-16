"""Slice G — the credit-launch-lease seam contract (the sovereign mints, the keyless offense plane verifies).

Load-bearing invariants (a false-green would let a forged lease authorize spend + a launch, or let a lease
be re-aimed at another tenant / host / window / amount):
  * an owner-signed lease round-trips: verify True under the owner trust root;
  * a tamper of ANY committed field (units / scope_host / org / window / nonce / slug) breaks the signature
    (detected — the fields are all inside the canonical signing bytes);
  * a wrong-key signature is refused (not the owner);
  * a quorum-collapsing trust root (duplicate authorizer pubkeys) is refused at this layer;
  * verify is fail-closed and never raises (malformed signature material -> (False, reason));
  * domain separation: the lease signing bytes carry the distinct credit-launch-lease tag.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AuthorizerKey,
    CreditLaunchLease,
    SignedCreditLaunchLease,
    TrustRoot,
    credit_lease_signing_bytes,
    generate_keypair,
    sign_credit_launch_lease,
    verify_credit_launch_lease,
)
from vigil_core.spine_domains import DOMAIN_TAGS

OWNER = generate_keypair()
ATTACKER = generate_keypair()
_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _owner_root():
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=OWNER.public_key_b64)])


def _lease(**over):
    base = dict(engagement_slug="cust_abc", org_id="org_acme", scope_host="apme.cm",
                units_reserved=10, not_before=_T0, not_after=_T0 + timedelta(hours=8),
                nonce="n-1", issued_at=1000.0)
    base.update(over)
    return CreditLaunchLease(**base)


def _signed(**over):
    return sign_credit_launch_lease(_lease(**over), {"owner": OWNER.private_key_b64})


def test_owner_signed_lease_roundtrips():
    signed = _signed()
    ok, reason = verify_credit_launch_lease(signed, _owner_root())
    assert ok, reason


def test_wrong_key_is_refused():
    signed = sign_credit_launch_lease(_lease(), {"owner": ATTACKER.private_key_b64})
    ok, _ = verify_credit_launch_lease(signed, _owner_root())
    assert ok is False


@pytest.mark.parametrize("field,newval", [
    ("units_reserved", 1_000_000), ("scope_host", "evil.example"), ("org_id", "org_evil"),
    ("nonce", "n-2"), ("engagement_slug", "cust_other"),
])
def test_tampering_any_bound_field_breaks_the_signature(field, newval):
    signed = _signed()
    tampered = SignedCreditLaunchLease(
        document=signed.document.model_copy(update={field: newval}),
        signatures=list(signed.signatures))
    ok, _ = verify_credit_launch_lease(tampered, _owner_root())
    assert ok is False, f"tampering {field} must break the owner signature"


def test_tampering_the_window_breaks_the_signature():
    signed = _signed()
    tampered = SignedCreditLaunchLease(
        document=signed.document.model_copy(update={"not_after": _T0 + timedelta(days=365)}),
        signatures=list(signed.signatures))
    ok, _ = verify_credit_launch_lease(tampered, _owner_root())
    assert ok is False


def test_quorum_collapsing_trust_root_refused():
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=OWNER.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=OWNER.public_key_b64)])
    ok, reason = verify_credit_launch_lease(_signed(), dup)
    assert ok is False and "duplicate" in reason.lower()


def test_verify_is_fail_closed_on_malformed_signature():
    from vigil_core import Signature
    bad = SignedCreditLaunchLease(document=_lease(), signatures=[Signature(key_id="owner", signature_b64="!!!")])
    ok, _ = verify_credit_launch_lease(bad, _owner_root())   # must not raise
    assert ok is False


def test_window_validator_rejects_inverted():
    with pytest.raises(ValueError):
        _lease(not_after=_T0 - timedelta(hours=1))


def test_units_must_be_positive():
    with pytest.raises(ValueError):
        _lease(units_reserved=0)


def test_signing_bytes_carry_the_distinct_domain_tag():
    body = credit_lease_signing_bytes(_lease())
    assert body.startswith(DOMAIN_TAGS["credit-launch-lease"])
    assert body != credit_lease_signing_bytes(_lease(units_reserved=11))   # units are in the signed bytes


# --- the optional v2 fields (run_tier, plan_reserved, plan_period_end, continue_of) --------------------------
# A lease that sets none of them is byte-identical to a lease minted before they existed: the same serialized
# document, the same signing bytes, the same signature. A set field is inside the signed bytes.
import base64  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402

from vigil_core.credit_lease import LEASE_V2_OPTIONAL_FIELDS  # noqa: E402

_GOLDEN = Path(__file__).parent / "fixtures" / "legacy_credit_lease_v1.json"
_V2 = dict(run_tier="deep", plan_reserved=4, plan_period_end=1_900_000_000.0, continue_of="n-0")


def _golden():
    g = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=g["owner_public_key_b64"])])
    return g, SignedCreditLaunchLease.model_validate(g["signed_lease"]), root


def test_a_lease_signed_before_the_v2_fields_keeps_its_bytes_and_verifies():
    g, signed, root = _golden()
    assert signed.model_dump(mode="json") == g["signed_lease"]
    assert signed.model_dump_json() == g["signed_lease_json"]
    assert credit_lease_signing_bytes(signed.document) == base64.b64decode(g["signing_bytes_b64"])
    ok, reason = verify_credit_launch_lease(signed, root)
    assert ok, reason


def test_a_lease_without_v2_fields_serializes_without_them():
    doc = _lease().model_dump(mode="json")
    assert not set(doc) & set(LEASE_V2_OPTIONAL_FIELDS)
    assert set(json.loads(_lease().model_dump_json())) == set(doc)


def test_a_v2_lease_roundtrips_and_carries_its_fields_in_the_signed_bytes():
    signed = _signed(**_V2)
    ok, reason = verify_credit_launch_lease(signed, _owner_root())
    assert ok, reason
    again = SignedCreditLaunchLease.model_validate(json.loads(signed.model_dump_json()))
    assert again.document == signed.document and verify_credit_launch_lease(again, _owner_root())[0]
    body = credit_lease_signing_bytes(signed.document)
    for key in LEASE_V2_OPTIONAL_FIELDS:
        assert f'"{key}":'.encode() in body


@pytest.mark.parametrize("field,newval", [
    ("run_tier", "quick"), ("plan_reserved", 3), ("plan_period_end", 1_900_000_001.0), ("continue_of", "n-9"),
])
def test_tampering_a_v2_field_breaks_the_signature(field, newval):
    signed = _signed(**_V2)
    tampered = SignedCreditLaunchLease(document=signed.document.model_copy(update={field: newval}),
                                       signatures=list(signed.signatures))
    assert verify_credit_launch_lease(tampered, _owner_root())[0] is False


@pytest.mark.parametrize("field", ["run_tier", "continue_of", "plan_reserved"])
def test_stripping_a_signed_v2_field_breaks_the_signature(field):
    signed = _signed(**_V2)
    raw = json.loads(signed.model_dump_json())
    del raw["document"][field]
    if field == "plan_reserved":
        del raw["document"]["plan_period_end"]          # a lease cannot keep a period without a plan share
    stripped = SignedCreditLaunchLease.model_validate(raw)
    assert verify_credit_launch_lease(stripped, _owner_root())[0] is False


def test_adding_a_v2_field_to_a_signed_lease_breaks_the_signature():
    signed = _signed()
    raw = json.loads(signed.model_dump_json())
    raw["document"]["plan_reserved"] = 0
    assert verify_credit_launch_lease(SignedCreditLaunchLease.model_validate(raw), _owner_root())[0] is False


def test_a_zero_plan_share_is_signed_and_not_dropped():
    signed = _signed(plan_reserved=0)
    assert signed.document.model_dump(mode="json")["plan_reserved"] == 0
    assert b'"plan_reserved":0' in credit_lease_signing_bytes(signed.document)


@pytest.mark.parametrize("bad", [
    dict(plan_reserved=11, plan_period_end=1_900_000_000.0),  # more than the reservation
    dict(plan_reserved=-1),
    dict(plan_reserved=4),                                   # a plan share without its tranche
    dict(plan_reserved=4, plan_period_end=0.0),
    dict(plan_reserved=4, plan_period_end=float("inf")),
    dict(plan_reserved=4, plan_period_end=float("nan")),
    dict(plan_period_end=1_900_000_000.0),                   # a tranche without a plan share
    dict(plan_reserved=0, plan_period_end=1_900_000_000.0),
    dict(run_tier="ultra"),
    dict(continue_of=""),
])
def test_v2_field_validation_rejects(bad):
    with pytest.raises(ValueError):
        _lease(**bad)


def test_a_plan_share_of_the_whole_reservation_is_accepted():
    assert _lease(plan_reserved=10, plan_period_end=1_900_000_000.0).plan_reserved == 10


def test_every_run_tier_is_accepted():
    from vigil_core.run_tier import RUN_TIERS
    for tier in RUN_TIERS:
        assert _lease(run_tier=tier).run_tier == tier


def test_every_assessment_depth_is_accepted_and_signed():
    """W2b-3: a metered launch's lease names its depth (quick | deep | max) inside the owner signature; anything else
    is refused when the lease is read (an older verifier, which knows no "max", refuses it too — fail closed)."""
    from vigil_core.run_tier import DEPTHS
    for depth in DEPTHS:
        signed = _signed(run_tier=depth)
        assert signed.document.run_tier == depth
        assert f'"run_tier":"{depth}"'.encode() in credit_lease_signing_bytes(signed.document)
        assert verify_credit_launch_lease(signed, _owner_root())[0]
    for bad in ("ultra", "Max", "", "high"):
        with pytest.raises(ValueError):
            _lease(run_tier=bad)


# --- W2b-3: the depth lease's document version ---------------------------------------------------------------

def test_a_depth_lease_carries_its_version_inside_the_signature():
    from vigil_core.credit_lease import LEASE_DEPTH_VERSION
    signed = _signed(run_tier="deep", version=LEASE_DEPTH_VERSION)
    assert verify_credit_launch_lease(signed, _owner_root())[0]
    assert f'"version":{LEASE_DEPTH_VERSION}'.encode() in credit_lease_signing_bytes(signed.document)
    raw = json.loads(signed.model_dump_json())
    del raw["document"]["version"]                       # stripping the version breaks the owner signature
    assert verify_credit_launch_lease(SignedCreditLaunchLease.model_validate(raw), _owner_root())[0] is False
    assert "version" not in _lease().model_dump(mode="json")          # a lease that names no depth has none


@pytest.mark.parametrize("bad", [dict(version=3), dict(version=2, run_tier="deep"), dict(version=4, run_tier="max"),
                                 dict(version=True, run_tier="quick")])
def test_a_lease_version_this_reader_does_not_know_is_refused(bad):
    # a version names its depth, and a reader refuses any version it does not know (refuse-newer)
    with pytest.raises(ValueError):
        _lease(**bad)


def test_a_pre_w2b3_reader_refuses_a_depth_lease_instead_of_misreading_it():
    """An older reader is ``extra="forbid"`` with no ``version`` field: it must REFUSE a depth lease (fail closed)
    rather than accept it and re-derive a tier from its allowance chunk (red-pen LEASE-1)."""
    from pydantic import ConfigDict, ValidationError, create_model
    from vigil_core.credit_lease import LEASE_DEPTH_VERSION, CreditLaunchLease
    old_fields = {name: (object, None) for name in CreditLaunchLease.model_fields if name != "version"}
    OldReader = create_model("OldReader", __config__=ConfigDict(extra="forbid"), **old_fields)
    doc = _signed(run_tier="quick", units_reserved=100, version=LEASE_DEPTH_VERSION).document.model_dump(mode="json")
    with pytest.raises(ValidationError, match="version"):
        OldReader.model_validate(doc)
    OldReader.model_validate(_lease().model_dump(mode="json"))          # a lease that names no depth still reads
