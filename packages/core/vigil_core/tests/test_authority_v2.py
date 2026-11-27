"""AEGIS AS-2a — the authority-V2 seam contracts (the sovereign mints, the keyless AEGIS plane verifies).

Load-bearing invariants a false-green would break (a forged grant authorizing monitoring; an enforcing
capability acting without the owner's separate-root release; a lapsed lease still blocking a tenant; a
superseded/stale grant still accepted; an unsigned signal RAISING authority instead of only reducing it):

  * every signed contract round-trips sign -> serialize (JSON) -> parse -> verify under the right root;
  * a one-field / one-byte tamper breaks the signature (every field is in the signed bytes);
  * EnforceRelease verifies ONLY against the SEPARATE RELEASE ROOT — an owner-root signature is refused for
    enforce, and a grant's owner signature can never replay as a release (distinct domain tag + distinct root);
  * a lapsed LEASE yields PASS-THROUGH even inside the outer window (R16);
  * a higher EpochStatement SUPERSEDES a lower (a grant below the floor is STALE => PASS-THROUGH);
  * a signed revocation is honoured (=> PASS-THROUGH);
  * an UNSIGNED withdrawal / override fails safe — it can only REDUCE authority, never enforce;
  * an IP-literal origin (or subject host) is refused at construction;
  * determinism: the same logical inputs produce BYTE-IDENTICAL canonical bytes (capability order-independent);
  * verify is fail-closed and never raises; a quorum-collapsing trust root is refused.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AuthorityOutcome,
    AuthoritySubject,
    AuthorityWithdrawal,
    EnforceRelease,
    EnforcementOverride,
    EngagementAuthority,
    EpochStatement,
    MonitoringAuthority,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    MonitoringMode,
    MonitoringRevocationV2,
    OriginTuple,
    OverrideTarget,
    Signature,
    SignedAuthority,
    SignedEnforceRelease,
    SignedEpochStatement,
    SignedMonitoringAuthority,
    SignedMonitoringAuthorityV2,
    SignedMonitoringRevocationV2,
    SubjectKind,
    TargetEnvironment,
    TrustRoot,
    AuthorizerKey,
    authority_publish_path,
    enforce_release_signing_bytes,
    epoch_statement_signing_bytes,
    evaluate_authority,
    generate_keypair,
    monitoring_authority_v2_signing_bytes,
    sign_enforce_release,
    sign_epoch_statement,
    sign_monitoring_authority_v2,
    sign_monitoring_revocation_v2,
    verify_enforce_release,
    verify_epoch_statement,
    verify_monitoring_authority_v2,
    verify_monitoring_revocation_v2,
)
from vigil_core.spine_domains import DOMAIN_TAGS

OWNER = generate_keypair()
RELEASE = generate_keypair()          # the SEPARATE release root (D30)
ATTACKER = generate_keypair()

_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_T_END = _T0 + timedelta(days=30)              # outer grant window end
_L0 = _T0 + timedelta(hours=1)                 # lease start (inside the outer window)
_L1 = _L0 + timedelta(hours=1)                 # lease end (1 h lease, §4.7)
_NOW = _L0 + timedelta(minutes=10)             # a moment inside the lease


def _owner_root(key=OWNER):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=key.public_key_b64)])


def _release_root():
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="release", name="release", public_key_b64=RELEASE.public_key_b64)])


def _subject(**over):
    base = dict(org_id="org_acme", host="api.example.com")
    base.update(over)
    return AuthoritySubject(**base)


def _lease(**over):
    base = dict(not_before=_L0, not_after=_L1)
    base.update(over)
    return MonitoringLease(**base)


def _grant(**over):
    base = dict(
        subject=_subject(),
        capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.BLOCK],
        epoch=1,
        not_before=_T0,
        not_after=_T_END,
        lease=_lease(),
        instance_id="inst-01",
        replica_index=0,
        origin=OriginTuple(host="origin.example.com", port=443),
        origin_binding_sha256="a" * 64,
        issued_by="owner",
    )
    base.update(over)
    return MonitoringAuthorityV2(**base)


def _signed_grant(**over):
    return sign_monitoring_authority_v2(_grant(**over), {"owner": OWNER.private_key_b64})


def _release(**over):
    base = dict(subject=_subject(), released_capabilities=[MonitoringCapability.BLOCK],
                epoch=1, not_before=_T0, not_after=_T_END, issued_by="release")
    base.update(over)
    return EnforceRelease(**base)


def _signed_release(**over):
    return sign_enforce_release(_release(**over), {"release": RELEASE.private_key_b64})


# ============================================================================================================
# 1. round-trips: sign -> serialize (JSON) -> parse -> verify
# ============================================================================================================
def test_grant_roundtrips_sign_serialize_parse_verify():
    signed = _signed_grant()
    wire = signed.model_dump_json()                                  # the published artifact bytes
    parsed = SignedMonitoringAuthorityV2.model_validate_json(wire)   # the keyless plane parses them back
    ok, reason = verify_monitoring_authority_v2(parsed, _owner_root())
    assert ok, reason


def test_grant_roundtrips_for_every_capability_including_virtual_patch():
    for cap in MonitoringCapability:
        signed = _signed_grant(capabilities=[MonitoringCapability.OBSERVE, cap])
        ok, reason = verify_monitoring_authority_v2(signed, _owner_root())
        assert ok, (cap, reason)
    # virtual_patch is an explicit member of the capability set (AS-2a scope).
    assert MonitoringCapability.VIRTUAL_PATCH in set(MonitoringCapability)


def test_epoch_statement_roundtrips():
    signed = sign_epoch_statement(EpochStatement(subject=_subject(), epoch=4), {"owner": OWNER.private_key_b64})
    parsed = SignedEpochStatement.model_validate_json(signed.model_dump_json())
    ok, reason = verify_epoch_statement(parsed, _owner_root())
    assert ok, reason


def test_release_roundtrips_under_the_release_root():
    parsed = SignedEnforceRelease.model_validate_json(_signed_release().model_dump_json())
    ok, reason = verify_enforce_release(parsed, _release_root())
    assert ok, reason


def test_revocation_roundtrips():
    signed = sign_monitoring_revocation_v2(MonitoringRevocationV2(subject=_subject(), epoch=2),
                                           {"owner": OWNER.private_key_b64})
    parsed = SignedMonitoringRevocationV2.model_validate_json(signed.model_dump_json())
    ok, reason = verify_monitoring_revocation_v2(parsed, _owner_root())
    assert ok, reason


# ============================================================================================================
# 2. tamper detection (one field / one byte)
# ============================================================================================================
@pytest.mark.parametrize("update", [
    {"epoch": 2},
    {"instance_id": "inst-02"},
    {"replica_index": 1},
    {"edge_chain": "evil_actor"},
    {"issued_by": "mallory"},
    {"origin_binding_sha256": "b" * 64},
    {"not_after": _T_END + timedelta(days=1)},
])
def test_tampering_any_grant_field_breaks_the_signature(update):
    signed = _signed_grant()
    tampered = SignedMonitoringAuthorityV2(document=signed.document.model_copy(update=update),
                                           signatures=list(signed.signatures))
    ok, _ = verify_monitoring_authority_v2(tampered, _owner_root())
    assert ok is False, f"tampering {update} must break the owner signature"


def test_tampering_capabilities_breaks_the_signature():
    signed = _signed_grant(capabilities=[MonitoringCapability.OBSERVE])
    tampered = SignedMonitoringAuthorityV2(
        document=signed.document.model_copy(update={"capabilities": [MonitoringCapability.OBSERVE,
                                                                     MonitoringCapability.RESPOND]}),
        signatures=list(signed.signatures))
    ok, _ = verify_monitoring_authority_v2(tampered, _owner_root())
    assert ok is False, "adding a capability to a signed grant must break the signature (caps are in the bytes)"


def test_one_byte_flip_in_the_signature_fails_closed():
    signed = _signed_grant()
    raw = signed.signatures[0].signature_b64
    flipped = ("B" if raw[0] != "B" else "C") + raw[1:]      # a one-char change to the base64 signature
    tampered = SignedMonitoringAuthorityV2(document=signed.document,
                                           signatures=[Signature(key_id="owner", signature_b64=flipped)])
    ok, _ = verify_monitoring_authority_v2(tampered, _owner_root())   # must not raise
    assert ok is False


# ============================================================================================================
# 3. EnforceRelease: SEPARATE release root only
# ============================================================================================================
def test_release_verifies_only_against_the_release_root_not_the_owner_root():
    signed = _signed_release()
    assert verify_enforce_release(signed, _release_root())[0] is True
    # The owner root does not contain the release key -> the release is refused under it.
    assert verify_enforce_release(signed, _owner_root())[0] is False


def test_owner_root_signature_is_refused_for_enforce():
    # A release signed with the OWNER key (not the release key) must NOT verify under the release root:
    # the separate-root wall (D30) — production enforcement needs the owner's RELEASE act, not an owner grant sig.
    owner_signed_release = sign_enforce_release(_release(), {"owner": OWNER.private_key_b64})
    ok, _ = verify_enforce_release(owner_signed_release, _release_root())
    assert ok is False


def test_a_grant_signature_cannot_replay_as_a_release_distinct_domain_tag():
    # Even reusing a grant's owner signatures on a release document must fail: distinct domain tag AND the
    # release root pins a different key. (own-grant != enforce-release, made cryptographic.)
    grant_sig = _signed_grant().signatures
    forged = SignedEnforceRelease(document=_release(), signatures=list(grant_sig))
    assert verify_enforce_release(forged, _release_root())[0] is False
    assert verify_enforce_release(forged, _owner_root())[0] is False


def test_release_covers_only_enforcing_capabilities():
    with pytest.raises(ValueError):
        _release(released_capabilities=[MonitoringCapability.OBSERVE])


# ============================================================================================================
# 4. lease => pass-through (R16)
# ============================================================================================================
def test_lapsed_lease_yields_pass_through_even_inside_the_outer_window():
    grant = _grant()
    after_lease = _L1 + timedelta(minutes=1)        # past the 1 h lease, still well inside the 30-day window
    assert grant.covers(after_lease) is True          # outer window still covers it
    assert grant.lease_active(after_lease) is False   # but the lease has lapsed
    decision = evaluate_authority(grant=grant, now=after_lease)
    assert decision.outcome is AuthorityOutcome.PASS_THROUGH
    assert "lease-lapsed" in decision.reasons


def test_live_lease_permits_observe():
    decision = evaluate_authority(grant=_grant(), now=_NOW)
    assert decision.outcome is AuthorityOutcome.OBSERVE


# ============================================================================================================
# 5. EpochStatement: higher supersedes lower
# ============================================================================================================
def test_higher_epoch_floor_supersedes_a_lower_grant():
    grant = _grant(epoch=3)
    # floor 3 (== grant epoch) -> still current; floor 5 (> grant epoch) -> stale => pass-through.
    assert evaluate_authority(grant=grant, now=_NOW, epoch_floor=3).outcome is AuthorityOutcome.OBSERVE
    stale = evaluate_authority(grant=grant, now=_NOW, epoch_floor=5)
    assert stale.outcome is AuthorityOutcome.PASS_THROUGH and "stale-epoch" in stale.reasons


def test_epoch_statement_tamper_breaks_signature():
    signed = sign_epoch_statement(EpochStatement(subject=_subject(), epoch=4), {"owner": OWNER.private_key_b64})
    tampered = SignedEpochStatement(document=signed.document.model_copy(update={"epoch": 99}),
                                    signatures=list(signed.signatures))
    assert verify_epoch_statement(tampered, _owner_root())[0] is False


# ============================================================================================================
# 6. signed revocation honoured
# ============================================================================================================
def test_signed_revocation_at_or_above_grant_epoch_yields_pass_through():
    grant = _grant(epoch=2)
    revocation = MonitoringRevocationV2(subject=_subject(), epoch=2)
    decision = evaluate_authority(grant=grant, now=_NOW, revocation=revocation)
    assert decision.outcome is AuthorityOutcome.PASS_THROUGH and "revoked" in decision.reasons


def test_stale_revocation_below_grant_epoch_does_not_revive_or_revoke():
    # A captured OLD revocation (epoch below the current grant) must NOT supersede the newer grant.
    grant = _grant(epoch=5)
    old_revocation = MonitoringRevocationV2(subject=_subject(), epoch=3)
    decision = evaluate_authority(grant=grant, now=_NOW, revocation=old_revocation)
    assert decision.outcome is AuthorityOutcome.OBSERVE


# ============================================================================================================
# 7. unsigned withdrawal / override fail safe (only reduce authority)
# ============================================================================================================
def test_unsigned_withdrawal_yields_pass_through_and_never_enforces():
    grant = _grant()
    withdrawal = AuthorityWithdrawal(subject=_subject())
    decision = evaluate_authority(grant=grant, now=_NOW,
                                  requested_capability=MonitoringCapability.BLOCK,
                                  release=_release(), withdrawal=withdrawal)
    assert decision.outcome is AuthorityOutcome.PASS_THROUGH and "withdrawn" in decision.reasons


def test_unsigned_override_is_downgrade_only_and_cannot_raise_to_enforce():
    # Without the override, a granted + released BLOCK would ENFORCE; the override clamps it to OBSERVE.
    grant = _grant()
    base = evaluate_authority(grant=grant, now=_NOW, requested_capability=MonitoringCapability.BLOCK,
                              release=_release())
    assert base.outcome is AuthorityOutcome.ENFORCE and base.capability is MonitoringCapability.BLOCK
    overridden = evaluate_authority(grant=grant, now=_NOW, requested_capability=MonitoringCapability.BLOCK,
                                    release=_release(),
                                    override=EnforcementOverride(subject=_subject(),
                                                                 downgrade_to=OverrideTarget.OBSERVE))
    assert overridden.outcome is AuthorityOutcome.OBSERVE and overridden.capability is None


def test_override_target_is_a_closed_downgrade_only_enum():
    # The override can only name a strict downgrade; there is no enforcing target to clamp UP to.
    assert {t.value for t in OverrideTarget} == {"pass_through", "observe"}
    with pytest.raises(ValueError):
        EnforcementOverride(subject=_subject(), downgrade_to="block")


def test_override_pass_through_drops_authority_entirely():
    decision = evaluate_authority(grant=_grant(), now=_NOW,
                                  override=EnforcementOverride(subject=_subject(),
                                                               downgrade_to=OverrideTarget.PASS_THROUGH))
    assert decision.outcome is AuthorityOutcome.PASS_THROUGH


# ============================================================================================================
# 8. enforce is NECESSARY-NOT-SUFFICIENT: needs the grant capability AND a verified release
# ============================================================================================================
def test_enforce_requires_a_release_absent_release_degrades_to_observe():
    grant = _grant()                      # carries BLOCK
    decision = evaluate_authority(grant=grant, now=_NOW, requested_capability=MonitoringCapability.BLOCK)
    assert decision.outcome is AuthorityOutcome.OBSERVE and "no-release" in decision.reasons


def test_enforce_requires_the_capability_in_the_grant():
    grant = _grant(capabilities=[MonitoringCapability.OBSERVE])   # no BLOCK granted
    decision = evaluate_authority(grant=grant, now=_NOW, requested_capability=MonitoringCapability.BLOCK,
                                  release=_release())
    assert decision.outcome is AuthorityOutcome.OBSERVE and "capability-not-granted" in decision.reasons


def test_enforce_refused_when_release_does_not_cover_the_capability():
    grant = _grant(capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.VIRTUAL_PATCH])
    release = _release(released_capabilities=[MonitoringCapability.BLOCK])   # covers BLOCK, not VIRTUAL_PATCH
    decision = evaluate_authority(grant=grant, now=_NOW,
                                  requested_capability=MonitoringCapability.VIRTUAL_PATCH, release=release)
    assert decision.outcome is AuthorityOutcome.OBSERVE and "capability-not-released" in decision.reasons


def test_enforce_refused_when_release_window_has_lapsed():
    grant = _grant()
    short_release = _release(not_before=_T0, not_after=_L0 + timedelta(minutes=1))   # ends before _NOW
    decision = evaluate_authority(grant=grant, now=_NOW, requested_capability=MonitoringCapability.BLOCK,
                                  release=short_release)
    assert decision.outcome is AuthorityOutcome.OBSERVE and "release-window-lapsed" in decision.reasons


def test_enforce_granted_and_released_virtual_patch():
    grant = _grant(capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.VIRTUAL_PATCH])
    release = _release(released_capabilities=[MonitoringCapability.VIRTUAL_PATCH])
    decision = evaluate_authority(grant=grant, now=_NOW,
                                  requested_capability=MonitoringCapability.VIRTUAL_PATCH, release=release)
    assert decision.outcome is AuthorityOutcome.ENFORCE
    assert decision.capability is MonitoringCapability.VIRTUAL_PATCH and "release-valid" in decision.reasons


def test_no_grant_is_pass_through():
    assert evaluate_authority(grant=None, now=_NOW).outcome is AuthorityOutcome.PASS_THROUGH


# ============================================================================================================
# 9. IP-literal origin (and subject host) refused
# ============================================================================================================
@pytest.mark.parametrize("bad_host", [
    "127.0.0.1", "10.0.0.5", "::1", "2001:db8::1", "0.0.0.0",
    # alternate IPv4 encodings the resolver accepts but ipaddress.ip_address rejects (SSRF-filter bypass):
    "0x7f.1", "2130706433", "0x7f000001", "0177.0.0.1", "127.1", "0xa9fea9fe", "2852039166", "0251.0376.0251.0376"])
def test_ip_literal_origin_is_refused(bad_host):
    with pytest.raises(ValueError):
        OriginTuple(host=bad_host)


@pytest.mark.parametrize("bad_host", ["192.168.1.1", "::1", "2130706433", "0x7f.1", "127.1", "0xa9fea9fe"])
def test_ip_literal_subject_host_is_refused(bad_host):
    with pytest.raises(ValueError):
        AuthoritySubject(org_id="org_acme", host=bad_host)


def test_evaluate_authority_reads_a_naive_now_as_utc_and_never_crashes():
    """A grant round-tripped from wire JSON carries tz-AWARE windows, but a data-plane caller computing `now`
    via datetime.utcnow() supplies a NAIVE datetime. The fail-closed decision must still return cleanly — the
    naive `now` is read as UTC — never raising the TypeError a naive-vs-aware comparison would."""
    grant = _grant()                                       # aware windows (_T0 ..)
    assert evaluate_authority(grant=grant, now=_NOW.replace(tzinfo=None)).outcome is AuthorityOutcome.OBSERVE
    past_naive = (_T_END + timedelta(days=1)).replace(tzinfo=None)   # past the outer window, tz-naive
    assert evaluate_authority(grant=grant, now=past_naive).outcome is AuthorityOutcome.PASS_THROUGH


def test_origin_requires_its_binding_no_binding_no_signature():
    # An origin declared without its binding sha256 (or vice-versa) is refused at construction (§4.4).
    with pytest.raises(ValueError):
        _grant(origin=OriginTuple(host="origin.example.com"), origin_binding_sha256=None)
    with pytest.raises(ValueError):
        _grant(origin=None, origin_binding_sha256="a" * 64)


def test_non_https_origin_scheme_refused():
    with pytest.raises(ValueError):
        OriginTuple(scheme="http", host="origin.example.com")


# ============================================================================================================
# 10. determinism: same inputs => byte-identical canonical form
# ============================================================================================================
def test_signing_bytes_are_deterministic_across_independent_builds():
    assert monitoring_authority_v2_signing_bytes(_grant()) == monitoring_authority_v2_signing_bytes(_grant())


def test_capability_order_does_not_change_the_canonical_bytes():
    a = _grant(capabilities=[MonitoringCapability.BLOCK, MonitoringCapability.OBSERVE])
    b = _grant(capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.BLOCK])
    assert monitoring_authority_v2_signing_bytes(a) == monitoring_authority_v2_signing_bytes(b)
    # ...and a duplicate capability is de-duplicated to the same bytes (so the signature is stable).
    c = _grant(capabilities=[MonitoringCapability.OBSERVE, MonitoringCapability.OBSERVE,
                             MonitoringCapability.BLOCK])
    assert monitoring_authority_v2_signing_bytes(c) == monitoring_authority_v2_signing_bytes(a)


def test_capabilities_are_stored_sorted_and_deduped():
    g = _grant(capabilities=[MonitoringCapability.RESPOND, MonitoringCapability.OBSERVE,
                             MonitoringCapability.RESPOND, MonitoringCapability.BLOCK])
    assert g.capabilities == [MonitoringCapability.BLOCK, MonitoringCapability.OBSERVE,
                              MonitoringCapability.RESPOND]


# ============================================================================================================
# 11. capability separation (distinct domain tags) + fail-closed + quorum guard
# ============================================================================================================
def test_signing_bytes_carry_the_distinct_v2_domain_tag():
    body = monitoring_authority_v2_signing_bytes(_grant())
    assert body.startswith(DOMAIN_TAGS["monitoring-authority-v2"])
    assert not body.startswith(DOMAIN_TAGS["monitoring-authority"])        # NOT the v1 tag
    assert not body.startswith(DOMAIN_TAGS["credit-launch-lease"])
    assert enforce_release_signing_bytes(_release()).startswith(DOMAIN_TAGS["aegis-enforce-release"])
    assert epoch_statement_signing_bytes(EpochStatement(subject=_subject(), epoch=1)).startswith(
        DOMAIN_TAGS["aegis-epoch-statement"])


def test_v1_signature_cannot_verify_as_a_v2_grant_and_vice_versa():
    # A v1 MonitoringAuthority owner signature must not satisfy a v2 grant verify (distinct tag), and a v2
    # grant's signature must not verify as a v1 authority.
    v1_doc = MonitoringAuthority(org_id="org_acme", host="api.example.com", mode=MonitoringMode.OBSERVE,
                                 not_before=_T0, not_after=_T_END)
    from vigil_core import sign_monitoring_authority, verify_monitoring_authority
    v1_signed = sign_monitoring_authority(v1_doc, {"owner": OWNER.private_key_b64})
    forged_v2 = SignedMonitoringAuthorityV2(document=_grant(), signatures=list(v1_signed.signatures))
    assert verify_monitoring_authority_v2(forged_v2, _owner_root())[0] is False
    forged_v1 = SignedMonitoringAuthority(document=v1_doc, signatures=list(_signed_grant().signatures))
    assert verify_monitoring_authority(forged_v1, _owner_root())[0] is False


def test_v2_grant_sig_is_not_an_offense_engagement_authority():
    # own != offense-test != observe != block, made cryptographic: a monitoring-v2 owner signature must NOT
    # satisfy an offense EngagementAuthority verify.
    forged = SignedAuthority(
        document=EngagementAuthority(engagement_slug="cust_acme", environment=TargetEnvironment.LIVE,
                                     scope=["api.example.com"], not_before=_T0, not_after=_T_END),
        signatures=list(_signed_grant().signatures))
    from vigil_core import verify_engagement_authority
    assert verify_engagement_authority(forged, _owner_root())[0] is False


def test_wrong_key_is_refused():
    signed = sign_monitoring_authority_v2(_grant(), {"owner": ATTACKER.private_key_b64})
    assert verify_monitoring_authority_v2(signed, _owner_root())[0] is False


def test_verify_is_fail_closed_on_malformed_signature():
    bad = SignedMonitoringAuthorityV2(document=_grant(),
                                      signatures=[Signature(key_id="owner", signature_b64="!!!")])
    assert verify_monitoring_authority_v2(bad, _owner_root())[0] is False   # must not raise


def test_quorum_collapsing_trust_root_refused():
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=OWNER.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=OWNER.public_key_b64)])
    ok, reason = verify_monitoring_authority_v2(_signed_grant(), dup)
    assert ok is False and "duplicate" in reason.lower()


# ============================================================================================================
# 12. window + lease validators
# ============================================================================================================
def test_inverted_grant_window_refused():
    with pytest.raises(ValueError):
        _grant(not_after=_T0 - timedelta(hours=1))


def test_lease_window_must_sit_inside_the_grant_window():
    with pytest.raises(ValueError):
        _grant(lease=_lease(not_after=_T_END + timedelta(days=1)))   # lease extends past the grant
    with pytest.raises(ValueError):
        _grant(lease=_lease(not_before=_T0 - timedelta(hours=1)))    # lease starts before the grant


def test_inverted_lease_window_refused():
    with pytest.raises(ValueError):
        MonitoringLease(not_before=_L1, not_after=_L0)


# ============================================================================================================
# 13. the one publish-path helper
# ============================================================================================================
def test_publish_path_is_deterministic_and_hashed():
    s = _subject()
    p1 = authority_publish_path(s, instance_id="inst-01", replica_index=0)
    p2 = authority_publish_path(s, instance_id="inst-01", replica_index=0)
    assert p1 == p2
    assert p1.endswith(".json") and len(p1) == 64 + len(".json")   # sha256 hex + .json; no raw host/org/instance
    for bad in ("/", "..", "\x00", " "):
        assert bad not in p1


def test_publish_path_is_distinct_per_instance_and_replica_and_subject():
    s = _subject()
    base = authority_publish_path(s, instance_id="inst-01", replica_index=0)
    assert authority_publish_path(s, instance_id="inst-02", replica_index=0) != base
    assert authority_publish_path(s, instance_id="inst-01", replica_index=1) != base
    assert authority_publish_path(_subject(host="other.example.com"), instance_id="inst-01") != base
    assert authority_publish_path(_subject(org_id="org_beta"), instance_id="inst-01") != base


def test_publish_path_revalidates_instance_id_and_replica():
    with pytest.raises(ValueError):
        authority_publish_path(_subject(), instance_id="../escape")
    with pytest.raises(ValueError):
        authority_publish_path(_subject(), instance_id="inst-01", replica_index=-1)


# ============================================================================================================
# 14. subject + discriminator basics
# ============================================================================================================
def test_subject_default_kind_is_host():
    assert AuthoritySubject(org_id="org_acme", host="api.example.com").kind is SubjectKind.HOST


def test_release_subject_mismatch_refuses_enforce():
    grant = _grant()
    other_release = _release(subject=_subject(host="elsewhere.example.com"))
    decision = evaluate_authority(grant=grant, now=_NOW, requested_capability=MonitoringCapability.BLOCK,
                                  release=other_release)
    assert decision.outcome is AuthorityOutcome.OBSERVE and "release-subject-mismatch" in decision.reasons
