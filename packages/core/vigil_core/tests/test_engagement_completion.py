"""K4-5b — the engagement-completion settle-signal seam contract (keyless offense signs, sovereign verifies).

Load-bearing invariants (a false-green would let a forged signal trigger a bogus settle, let a completion for
one launch settle a different one, or let a completion signature REPLAY as a finding/lease/authority):
  * an offense-governance-signed signal round-trips (every outcome) under the signing trust root;
  * a tamper of ANY committed field (slug / nonce / outcome) breaks the signature;
  * DOMAIN SEPARATION is cryptographic: the signing bytes carry the engagement-completion tag, so a completion
    signature is bound to this purpose only (a monitoring / credit-lease signature can never satisfy it);
  * a wrong-key signature is refused; a quorum-collapsing trust root (duplicate pubkeys) is refused;
  * verify is fail-closed and never raises (malformed signature material -> (False, reason)).

These pin the vigil_core primitive; the KEYLESS producer (jobs.completion_signal) and the SOVEREIGN settle-
drain (inbound.completion_spool) that compose it are tested in their own suites.
"""
from __future__ import annotations

import pytest

from vigil_core import (
    AuthorizerKey,
    EngagementCompletion,
    EngagementOutcome,
    SignedEngagementCompletion,
    TrustRoot,
    engagement_completion_signing_bytes,
    generate_keypair,
    sign_engagement_completion,
    verify_engagement_completion,
)
from vigil_core.spine_domains import DOMAIN_TAGS

GOV = generate_keypair()
ATTACKER = generate_keypair()


def _root(kp=GOV):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov", name="gov", public_key_b64=kp.public_key_b64)])


def _doc(*, engagement_slug="cust_abc123", nonce="n1", outcome=EngagementOutcome.COMPLETED):
    return EngagementCompletion(engagement_slug=engagement_slug, nonce=nonce, outcome=outcome)


def _sign(doc, kp=GOV):
    return sign_engagement_completion(doc, {"gov": kp.private_key_b64})


@pytest.mark.parametrize("outcome", list(EngagementOutcome))
def test_signed_signal_round_trips_for_every_outcome(outcome):
    ok, reason = verify_engagement_completion(_sign(_doc(outcome=outcome)), _root())
    assert ok, reason


@pytest.mark.parametrize("field,val", [
    ("engagement_slug", "cust_other"), ("nonce", "n2"), ("outcome", EngagementOutcome.CANCELED)])
def test_tamper_of_any_committed_field_breaks_the_signature(field, val):
    signed = _sign(_doc())
    tampered = SignedEngagementCompletion(
        document=_doc(**{field: val}), signatures=signed.signatures)   # swap the doc, keep the old sigs
    ok, _ = verify_engagement_completion(tampered, _root())
    assert not ok


def test_domain_tag_binds_the_signing_bytes_to_this_purpose():
    # the signing bytes are domain-tagged so a completion signature is bound to engagement-completion ONLY —
    # a signature computed for any other purpose (different prefix) can never satisfy this verify.
    msg = engagement_completion_signing_bytes(_doc())
    assert msg.startswith(DOMAIN_TAGS["engagement-completion"])
    assert not msg.startswith(DOMAIN_TAGS["credit-launch-lease"])
    assert not msg.startswith(DOMAIN_TAGS["monitoring-authority"])


def test_wrong_key_is_refused():
    ok, _ = verify_engagement_completion(_sign(_doc()), _root(ATTACKER))   # signed by GOV, root pins ATTACKER
    assert not ok


def test_quorum_collapsing_trust_root_is_refused():
    # two authorizers under distinct key_ids but the SAME pubkey would collapse an m-of-n quorum to 1-of-1.
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=GOV.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=GOV.public_key_b64)])
    ok, reason = verify_engagement_completion(_sign(_doc()), dup)
    assert not ok and "duplicate" in reason.lower()


def test_verify_is_fail_closed_on_malformed_signature_material():
    from vigil_core import Signature
    bad = SignedEngagementCompletion(
        document=_doc(), signatures=[Signature(key_id="gov", signature_b64="!!!not base64!!!")])
    ok, _ = verify_engagement_completion(bad, _root())   # never raises; a refusal
    assert not ok


def test_extra_fields_are_forbidden_on_the_document():
    with pytest.raises(Exception):
        EngagementCompletion(engagement_slug="cust_abc123", nonce="n1",
                             outcome=EngagementOutcome.COMPLETED, consumed=999)   # no wire amount allowed
