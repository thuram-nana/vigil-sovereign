"""S7c — the sovereign side ingests a DETECTION FACT via the owner-delegated offense-SPINE root.

Proves the honest correction to the plan: a detection FACT is offense-SPINE-signed (not m-of-n governance),
so its anchor-1 owner tie is an OFFENSE_SPINE_ROLE delegation. from_spine_delegation derives that root; a
finding under a valid owner-signed spine delegation is admitted as kind="detection"; an invalid/wrong-role/
wrong-owner delegation builds no receiver; a detection signed by a NON-delegated key is refused at anchor-1.

Run: SIGIL_HOME=$(mktemp -d) pytest apps/sigil/tests/test_detection_receiver.py -q
"""
import tempfile

import pytest

from sigil.governor.identity import delegate_offense_governance, delegate_offense_spine
from sigil.inbound.finding_receiver import FindingReceiver
from sigil.spine.store import SpineStore
from vigil_core import AuthorizerKey, generate_keypair, sign
from vigil_integration.detection.certificate import build_certificate, sign_certificate
from vigil_integration.inert_finding import InertFindingError, build_detection_envelope
from vigil_integration.live.spine_identity import SPINE_KEY_ID

OWNER = generate_keypair()
SPINE = generate_keypair()
SPINE_AUTH = AuthorizerKey(key_id=SPINE_KEY_ID, name=SPINE_KEY_ID, public_key_b64=SPINE.public_key_b64)
NOW, NOT_AFTER = 1000, 2000


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _spine_delegation(*, owner=OWNER, scope="*", not_after=NOT_AFTER, authorizers=(SPINE_AUTH,)):
    return delegate_offense_spine(owner, authorizers=list(authorizers), scope=scope, not_after=not_after)


def _detection_envelope(kp=SPINE, key_id=SPINE_KEY_ID):
    cert = build_certificate(oracle="cred.stuffing", signature_kind="per-account-failure-velocity",
                             bug_class="cred.stuffing", severity="high", evidence_kind="auth_log",
                             evidence_lines=["u=a fail", "u=a fail", "u=a fail"], summary="stuffing", seq=0)
    signed = sign_certificate(cert, lambda b: sign(kp.private_key_b64, b), key_id=key_id)
    return build_detection_envelope(signed.signing_payload(),
                                    [{"key_id": signed.key_id, "signature_b64": signed.signature}])


def _receiver(store, *, delegation=None, owner=OWNER.public_key_b64, now=NOW, scope="*"):
    return FindingReceiver.from_spine_delegation(store, owner_pubkey=owner,
                                                 delegation=delegation or _spine_delegation(scope=scope),
                                                 now=now, scope=scope)


def _detections(store):
    return [r for r in store.iter_records() if r.kind == "detection"]


def test_detection_under_an_owner_delegated_spine_key_is_ingested():
    s = _store()
    seq = _receiver(s).ingest_detection(_detection_envelope())
    rec = s.get(seq)
    assert rec.kind == "detection" and rec.payload["oracle"] == "cred.stuffing"


def test_detection_under_a_non_delegated_key_is_refused():
    s = _store()
    attacker = generate_keypair()   # a spine key the owner never delegated
    with pytest.raises(InertFindingError, match="anchor 1"):
        _receiver(s).ingest_detection(_detection_envelope(kp=attacker))
    assert _detections(s) == []


def test_a_governance_delegation_does_not_authorize_detection():
    # a detection FACT needs an OFFENSE_SPINE_ROLE delegation; a governance-role one must NOT build a
    # spine receiver (role separation — S7c).
    s = _store()
    gov_cert = delegate_offense_governance(OWNER, authorizers=[SPINE_AUTH], threshold=1,
                                           scope="*", not_after=NOT_AFTER)
    with pytest.raises(InertFindingError, match="delegation invalid"):
        FindingReceiver.from_spine_delegation(s, owner_pubkey=OWNER.public_key_b64,
                                              delegation=gov_cert, now=NOW, scope="*")


def test_wrong_owner_spine_delegation_refuses_all():
    s = _store()
    rogue = generate_keypair()
    with pytest.raises(InertFindingError, match="delegation invalid"):
        FindingReceiver.from_spine_delegation(s, owner_pubkey=OWNER.public_key_b64,
                                              delegation=_spine_delegation(owner=rogue), now=NOW, scope="*")


def test_detection_signed_under_the_wrong_key_id_is_refused():
    # the exact case S7c's key_id unification fixes: the spine PUBKEY is delegated, but the detection cert is
    # stamped with a DIFFERENT key_id — verify_threshold matches by key_id, so anchor-1 must refuse it.
    s = _store()
    with pytest.raises(InertFindingError, match="anchor 1"):
        _receiver(s).ingest_detection(_detection_envelope(kp=SPINE, key_id="not-offense-spine"))
    assert _detections(s) == []


def test_ingest_is_bound_to_the_delegation_role():
    # defense-in-depth (S7c LOW-2): a receiver built via from_spine_delegation (spine role) refuses to ingest
    # a FINDING, and a governance-delegated receiver refuses to ingest a DETECTION — not relying on key
    # separation alone.
    s = _store()
    spine_recv = _receiver(s)   # from_spine_delegation → role offense-spine
    with pytest.raises(InertFindingError, match="bound to role"):
        spine_recv.ingest(b'{"schema":"vigil.inert-finding.v1","certificate":{},"signatures":[]}')
    gov_recv = FindingReceiver.from_delegation(
        s, owner_pubkey=OWNER.public_key_b64,
        delegation=delegate_offense_governance(OWNER, authorizers=[SPINE_AUTH], threshold=1,
                                               scope="*", not_after=NOT_AFTER),
        now=NOW, scope="*")
    with pytest.raises(InertFindingError, match="bound to role"):
        gov_recv.ingest_detection(_detection_envelope())
    assert _detections(s) == []


def test_scoped_receiver_fails_closed_on_an_unlabeled_detection():
    # honest limitation: detection certs carry no signed engagement_slug yet, so a NON-wildcard receiver
    # refuses them (fail-closed — never launders an unlabeled FACT into a scope).
    s = _store()
    r = FindingReceiver.from_spine_delegation(s, owner_pubkey=OWNER.public_key_b64,
                                              delegation=_spine_delegation(scope="acme"), now=NOW, scope="acme")
    with pytest.raises(InertFindingError, match="outside the owner-delegated scope"):
        r.ingest_detection(_detection_envelope())
    assert _detections(s) == []
