"""VF — owner-attested target IDENTITY + attenuable re-verification CAPABILITY (`vigil_core.capability`).

Proves the authorization design fails closed on every axis the PROTOCOL names: only the owner can attest an
identity or mint a capability; a capability is BOUND to one identity attestation; a live sample must SATISFY
the attested policy (anti-transplant); the attenuation chain is biscuit-style narrow-only (a widening or a
broken/reordered/wrong-signer link is refused); windows, revocation, non-destructive, and class-allowlist are
enforced; and everything round-trips as inert JSON verified with vigil_core alone.

Run: pytest packages/core/vigil_core/tests/test_capability.py -q
"""
from __future__ import annotations

import base64

import pytest

from vigil_core import generate_keypair
from vigil_core.capability import (
    Attenuation,
    Capability,
    CapabilityError,
    IdentityAttestation,
    WielderProof,
    attenuate,
    authorize_reverification,
    identity_digest,
    identity_matches,
    prove_wielder,
    sign_capability,
    sign_identity_attestation,
    verify_capability,
    verify_identity_attestation,
)

OWNER = generate_keypair()
ATTACKER = generate_keypair()
AUDITOR = generate_keypair()
SUBAUDITOR = generate_keypair()

ENG = "acme"
NOW = 1_000
CHALLENGE = "nonce-abc123"   # a fresh per-authorization challenge the caller supplies (the §5 Mode-L nonce)
POLICY = {"host": ["shop.acme.test"], "tls_spki_sha256": ["aa" * 32, "bb" * 32]}
SAMPLE_OK = {"host": "shop.acme.test", "tls_spki_sha256": "aa" * 32, "extra": "ignored"}


def _identity(owner=OWNER, engagement=ENG, policy=None, not_after=2_000) -> IdentityAttestation:
    return sign_identity_attestation(owner, engagement=engagement, policy=(policy or POLICY),
                                     not_after=not_after)


def _cap(owner=OWNER, engagement=ENG, id_digest=None, classes=None, not_before=0, not_after=2_000,
         rate_limit=5, revocation_id="rev-1", audience="*") -> Capability:
    if id_digest is None:
        id_digest = identity_digest(_identity())
    return sign_capability(owner, engagement=engagement, identity_digest=id_digest,
                           class_allowlist=(classes or ["error_based_sqli", "reflected_xss"]),
                           not_before=not_before, not_after=not_after, rate_limit=rate_limit,
                           revocation_id=revocation_id, audience=audience)


# --- the happy path ----------------------------------------------------------------------------------
def test_full_authorization_holds():
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident))
    eff = authorize_reverification(cap, ident, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                                   engagement=ENG, bug_class="error_based_sqli", identity_sample=SAMPLE_OK,
                                   challenge=CHALLENGE)   # bearer cap → no wielder proof required
    assert eff.engagement == ENG and "error_based_sqli" in eff.class_allowlist
    # round-trips as inert JSON
    assert IdentityAttestation.model_validate_json(ident.model_dump_json()) == ident
    assert Capability.model_validate_json(cap.model_dump_json()) == cap


# --- identity attestation --------------------------------------------------------------------------
def test_non_owner_identity_is_refused():
    ident = _identity(owner=ATTACKER)
    with pytest.raises(CapabilityError, match="not by the trusted owner"):
        verify_identity_attestation(ident, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_expired_identity_is_refused():
    ident = _identity(not_after=NOW - 1)
    with pytest.raises(CapabilityError, match="expired"):
        verify_identity_attestation(ident, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_wrong_engagement_identity_is_refused():
    ident = _identity(engagement="other")
    with pytest.raises(CapabilityError, match="engagement"):
        verify_identity_attestation(ident, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_tampered_identity_policy_breaks_signature():
    ident = _identity()
    tampered = ident.model_copy(update={"policy": {"host": ["evil.test"]}})
    with pytest.raises(CapabilityError, match="does not verify"):
        verify_identity_attestation(tampered, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_empty_policy_cannot_be_minted():
    with pytest.raises(CapabilityError, match="non-empty"):
        sign_identity_attestation(OWNER, engagement=ENG, policy={}, not_after=2_000)


# --- identity matching (anti-transplant) -----------------------------------------------------------
def test_identity_match_conjunctive_and_any_of():
    assert identity_matches(POLICY, SAMPLE_OK)
    assert identity_matches(POLICY, {"host": "shop.acme.test", "tls_spki_sha256": "bb" * 32})  # rotated pin


def test_identity_sample_missing_a_constrained_dimension_fails():
    # a sample cannot 'downgrade' by withholding a constrained dimension
    assert not identity_matches(POLICY, {"host": "shop.acme.test"})


def test_identity_sample_wrong_value_fails():
    assert not identity_matches(POLICY, {"host": "evil.test", "tls_spki_sha256": "aa" * 32})
    assert not identity_matches(POLICY, {"host": "shop.acme.test", "tls_spki_sha256": "cc" * 32})


def test_transplant_to_a_different_target_is_refused_end_to_end():
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident))
    with pytest.raises(CapabilityError, match="does not satisfy the attested policy"):
        authorize_reverification(cap, ident, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                                 engagement=ENG, bug_class="error_based_sqli",
                                 identity_sample={"host": "evil.test", "tls_spki_sha256": "aa" * 32},
                                 challenge=CHALLENGE)


# --- capability core ---------------------------------------------------------------------------------
def test_non_owner_capability_is_refused():
    cap = _cap(owner=ATTACKER)
    with pytest.raises(CapabilityError, match="not by the trusted owner"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_capability_outside_window_is_refused():
    cap = _cap(not_before=NOW + 100, not_after=NOW + 200)
    with pytest.raises(CapabilityError, match="not valid at now"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_revoked_capability_is_refused():
    cap = _cap(revocation_id="rev-9")
    with pytest.raises(CapabilityError, match="revoked"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          revoked_ids=frozenset({"rev-9"}))


def test_destructive_capability_cannot_be_minted():
    with pytest.raises(CapabilityError, match="non-destructive"):
        sign_capability(OWNER, engagement=ENG, identity_digest="d", class_allowlist=["x"], not_before=0,
                        not_after=1, rate_limit=1, revocation_id="r", non_destructive=False)


def test_wildcard_class_cannot_be_minted():
    with pytest.raises(CapabilityError, match="explicit"):
        sign_capability(OWNER, engagement=ENG, identity_digest="d", class_allowlist=["*"], not_before=0,
                        not_after=1, rate_limit=1, revocation_id="r")


def test_class_not_in_allowlist_is_refused_end_to_end():
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident), classes=["reflected_xss"])
    with pytest.raises(CapabilityError, match="not in the capability's allowlist"):
        authorize_reverification(cap, ident, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                                 engagement=ENG, bug_class="error_based_sqli", identity_sample=SAMPLE_OK,
                                 challenge=CHALLENGE)


def test_capability_bound_to_wrong_identity_is_refused():
    ident = _identity()
    other_digest = identity_digest(_identity(policy={"host": ["different.test"]}))
    cap = _cap(id_digest=other_digest)   # capability points at a DIFFERENT identity than the one presented
    with pytest.raises(CapabilityError, match="not bound to this identity"):
        authorize_reverification(cap, ident, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                                 engagement=ENG, bug_class="error_based_sqli", identity_sample=SAMPLE_OK,
                                 challenge=CHALLENGE)


def test_tampered_capability_field_breaks_signature():
    cap = _cap()
    tampered = cap.model_copy(update={"class_allowlist": cap.class_allowlist + ["os_command_injection"]})
    with pytest.raises(CapabilityError, match="does not verify"):
        verify_capability(tampered, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


# --- attenuation chain (biscuit-style, narrow-only) ------------------------------------------------
def test_attenuation_narrows_and_holds():
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident), classes=["error_based_sqli", "reflected_xss"],
               audience=AUDITOR.public_key_b64)
    # auditor narrows to a single class + a tighter expiry + a lower rate, and pins the sub-auditor
    att = attenuate(AUDITOR, prev=cap, next_audience=SUBAUDITOR.public_key_b64,
                    class_subset=["error_based_sqli"], not_after=1_500, rate_limit=2)
    eff = verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                            attenuations=[att], expected_audience=SUBAUDITOR.public_key_b64)
    assert eff.class_allowlist == ["error_based_sqli"] and eff.not_after == 1_500 and eff.rate_limit == 2
    assert eff.audience == SUBAUDITOR.public_key_b64


def test_attenuation_cannot_widen_the_allowlist():
    cap = _cap(classes=["error_based_sqli"], audience=AUDITOR.public_key_b64)
    att = attenuate(AUDITOR, prev=cap, class_subset=["error_based_sqli", "os_command_injection"])
    with pytest.raises(CapabilityError, match="widens the allowlist"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[att])


def test_attenuation_cannot_extend_the_window():
    cap = _cap(not_after=1_500, audience=AUDITOR.public_key_b64)
    att = attenuate(AUDITOR, prev=cap, not_after=9_999)
    with pytest.raises(CapabilityError, match="widens the window"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[att])


def test_attenuation_cannot_raise_the_rate_limit():
    cap = _cap(rate_limit=2, audience=AUDITOR.public_key_b64)
    att = attenuate(AUDITOR, prev=cap, rate_limit=100)
    with pytest.raises(CapabilityError, match="rate_limit widens"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[att])


def test_attenuation_by_a_non_audience_signer_is_refused():
    cap = _cap(audience=AUDITOR.public_key_b64)              # pinned to the auditor
    att = attenuate(ATTACKER, prev=cap, class_subset=["error_based_sqli"])   # signed by someone else
    with pytest.raises(CapabilityError, match="signer is not the current audience"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[att])


def test_stripping_an_attenuation_breaks_the_chain():
    # a two-link chain where the SECOND link is presented alone must fail to chain (its prev_digest points at
    # the first link, not the base capability).
    cap = _cap(audience=AUDITOR.public_key_b64)
    a1 = attenuate(AUDITOR, prev=cap, next_audience=SUBAUDITOR.public_key_b64, class_subset=["error_based_sqli"])
    a2 = attenuate(SUBAUDITOR, prev=a1, rate_limit=1)
    with pytest.raises(CapabilityError, match="does not chain"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[a2])   # a1 dropped


def test_reordering_attenuations_breaks_the_chain():
    cap = _cap(audience=AUDITOR.public_key_b64)
    a1 = attenuate(AUDITOR, prev=cap, next_audience=SUBAUDITOR.public_key_b64, class_subset=["error_based_sqli"])
    a2 = attenuate(SUBAUDITOR, prev=a1, rate_limit=1)
    with pytest.raises(CapabilityError, match="does not chain"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[a2, a1])


def test_expected_audience_is_a_non_authenticating_filter():
    # verify_capability's expected_audience is an inspection FILTER, not authorization — it string-compares the
    # effective audience so a caller can select a cap by its delegate. It is NOT proof-of-possession.
    cap = _cap(audience=AUDITOR.public_key_b64)
    with pytest.raises(CapabilityError, match="does not match the expected_audience filter"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          expected_audience=ATTACKER.public_key_b64)
    eff = verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                            expected_audience=AUDITOR.public_key_b64)
    assert eff.audience == AUDITOR.public_key_b64


def test_forged_attenuation_signature_is_refused():
    cap = _cap(audience=AUDITOR.public_key_b64)
    att = attenuate(AUDITOR, prev=cap, class_subset=["error_based_sqli"])
    forged = att.model_copy(update={"class_subset": ["error_based_sqli", "reflected_xss"]})  # edit post-sign
    with pytest.raises(CapabilityError, match="does not verify|widens"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[forged])


# --- FINDING-1 / BLOCK-1 regression: the GATE must require proof-of-POSSESSION, not a plaintext pubkey ----
def _authorize(cap, ident, *, proof=None, challenge=CHALLENGE, bug_class="error_based_sqli",
               sample=SAMPLE_OK, attenuations=None):
    return authorize_reverification(cap, ident, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                                    engagement=ENG, bug_class=bug_class, identity_sample=sample,
                                    challenge=challenge, wielder_proof=proof, attenuations=attenuations)


def test_legit_wielder_with_proof_is_admitted():
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident), audience=AUDITOR.public_key_b64)
    proof = prove_wielder(AUDITOR, challenge=CHALLENGE, capability=cap)
    eff = _authorize(cap, ident, proof=proof)
    assert eff.audience == AUDITOR.public_key_b64


def test_byte_replay_thief_is_refused_even_naming_the_audience():
    # THE BLOCK-1 THREAT: a thief holds the inert bytes and copies the PUBLIC audience string out of them.
    # Naming the audience is not enough — without the audience PRIVATE key they cannot forge a WielderProof.
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident), audience=AUDITOR.public_key_b64)
    # (a) thief supplies no proof at all
    with pytest.raises(CapabilityError, match="requires a WielderProof"):
        _authorize(cap, ident, proof=None)
    # (b) thief forges a proof with THEIR OWN key (they don't hold AUDITOR's private key)
    thief_proof = prove_wielder(ATTACKER, challenge=CHALLENGE, capability=cap)
    with pytest.raises(CapabilityError, match="does not verify against the capability's audience"):
        _authorize(cap, ident, proof=thief_proof)


def test_wielder_proof_is_challenge_bound_no_replay():
    # a proof made for an OLD challenge cannot be replayed under a fresh one
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident), audience=AUDITOR.public_key_b64)
    stale = prove_wielder(AUDITOR, challenge="old-nonce", capability=cap)
    with pytest.raises(CapabilityError, match="challenge does not match"):
        _authorize(cap, ident, proof=stale, challenge="fresh-nonce")


def test_wielder_proof_is_capability_bound():
    # a valid proof for capability A cannot authorize capability B (different digest)
    ident = _identity()
    capA = _cap(id_digest=identity_digest(ident), audience=AUDITOR.public_key_b64, revocation_id="A")
    capB = _cap(id_digest=identity_digest(ident), audience=AUDITOR.public_key_b64, revocation_id="B")
    proof_for_A = prove_wielder(AUDITOR, challenge=CHALLENGE, capability=capA)
    with pytest.raises(CapabilityError, match="bound to a different capability"):
        _authorize(capB, ident, proof=proof_for_A)


def test_proof_must_be_by_the_EFFECTIVE_post_attenuation_audience():
    # after redelegation to the sub-auditor, only the SUB-auditor's proof authorizes; the original auditor's
    # (and a thief copying next_audience) cannot.
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident), audience=AUDITOR.public_key_b64)
    att = attenuate(AUDITOR, prev=cap, next_audience=SUBAUDITOR.public_key_b64)
    with pytest.raises(CapabilityError, match="does not verify against the capability's audience"):
        _authorize(cap, ident, proof=prove_wielder(AUDITOR, challenge=CHALLENGE, capability=cap),
                   attenuations=[att])
    eff = _authorize(cap, ident, proof=prove_wielder(SUBAUDITOR, challenge=CHALLENGE, capability=cap),
                     attenuations=[att])
    assert eff.audience == SUBAUDITOR.public_key_b64


def test_authorize_requires_a_fresh_challenge():
    # the gate cannot be invoked without a challenge (missing -> TypeError; empty -> CapabilityError).
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident), audience=AUDITOR.public_key_b64)
    with pytest.raises(TypeError):
        authorize_reverification(cap, ident, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                                 engagement=ENG, bug_class="error_based_sqli", identity_sample=SAMPLE_OK)
    with pytest.raises(CapabilityError, match="non-empty, fresh challenge"):
        _authorize(cap, ident, proof=prove_wielder(AUDITOR, challenge="", capability=cap) if False else None,
                   challenge="")


def test_bearer_capability_needs_no_proof():
    # a bearer ("*") cap has no audience key to prove; any holder may wield (by design).
    ident = _identity()
    cap = _cap(id_digest=identity_digest(ident), audience="*")
    eff = _authorize(cap, ident, proof=None)
    assert eff.audience == "*"


# --- LOW-2 regressions: weak-key rejection + cross-domain replay (verified sound; now pinned) ---------
def test_low_order_attenuation_signer_is_rejected():
    # a bearer capability skips the signer==audience check, so the ONLY thing rejecting a keyless-forgery
    # signer is load_public_key's weak-key screen. Pin it: an identity-point (all-zero) signer is refused.
    cap = _cap(audience="*")
    zero_point = base64.b64encode(b"\x00" * 32).decode()
    att = Attenuation(prev_digest=cap._digest(), signer_pubkey=zero_point, class_subset=["error_based_sqli"],
                      sig=base64.b64encode(b"\x00" * 64).decode())
    with pytest.raises(CapabilityError, match="malformed|does not verify"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[att])


def test_cross_domain_signature_replay_is_rejected():
    # present a capability-DOMAIN owner signature as if it were an ATTENUATION signature. Distinct domain
    # tags mean it cannot verify under the attenuation purpose. (bearer cap so the signer check is skipped.)
    cap = _cap(audience="*")
    replay = Attenuation(prev_digest=cap._digest(), signer_pubkey=OWNER.public_key_b64,
                         class_subset=["error_based_sqli"], sig=cap.sig)   # cap.sig is a capability-domain sig
    with pytest.raises(CapabilityError, match="does not verify"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[replay])
