"""S4 — the sovereign finding-receiver DERIVES its governance trust root from an OWNER-SIGNED delegation.

Proves the owner-root tie: a finding signed by an OWNER-DELEGATED governance key is ingested; a finding
signed by a NON-delegated key is refused (anchor-1 fails against the derived root); and an invalid
delegation (wrong owner / expired / out-of-scope) refuses ALL findings — no receiver is even built, so
nothing crosses under an un-owner-delegated governance key. Verified with vigil_core alone (no offense).

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_finding_receiver_delegation.py -q
"""
import tempfile

import pytest

from sigil.governor.identity import delegate_offense_governance
from sigil.inbound.finding_receiver import FindingReceiver
from sigil.spine.store import SpineStore
from vigil_core import AuthorizerKey, evidence_signing_bytes, generate_keypair, sign
from vigil_integration.inert_finding import InertFindingError, build_envelope

OWNER = generate_keypair()
GOV = generate_keypair()                       # the offense governance key the owner will delegate to
GOV_AUTH = AuthorizerKey(key_id="root0", name="root0", public_key_b64=GOV.public_key_b64)
NOW, NOT_AFTER = 1000, 2000
SCOPE = "acme"


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _delegation(*, owner=OWNER, scope=SCOPE, not_after=NOT_AFTER, authorizers=(GOV_AUTH,), threshold=1):
    return delegate_offense_governance(owner, authorizers=list(authorizers), threshold=threshold,
                                       scope=scope, not_after=not_after)


def _envelope(*, signer=GOV, key_id="root0", slug=SCOPE):
    cert = {"schema_version": 1, "engagement_slug": slug, "finding_ref": "sqli-001",
            "bug_class": "sqli", "oracle_context_digest": "a" * 64, "confidence": 0.9}
    sig = sign(signer.private_key_b64, evidence_signing_bytes(cert))
    return build_envelope(cert, [{"key_id": key_id, "signature_b64": sig}])


def _receiver(store, *, delegation=None, owner=OWNER.public_key_b64, now=NOW, scope=SCOPE):
    return FindingReceiver.from_delegation(store, owner_pubkey=owner,
                                           delegation=delegation or _delegation(), now=now, scope=scope)


def _findings(store):
    return [r for r in store.iter_records() if r.kind == "finding"]


def test_finding_under_an_owner_delegated_key_is_ingested():
    s = _store()
    seq = _receiver(s).ingest(_envelope())
    assert s.get(seq).payload["finding_ref"] == "sqli-001"


def test_finding_under_a_non_delegated_key_is_refused():
    s = _store()
    attacker = generate_keypair()   # a governance key the owner never delegated
    with pytest.raises(InertFindingError, match="anchor 1"):
        _receiver(s).ingest(_envelope(signer=attacker))
    assert _findings(s) == []


def test_delegation_by_a_non_owner_refuses_all_findings():
    s = _store()
    rogue = generate_keypair()      # a "delegation" signed by someone who is not the owner
    with pytest.raises(InertFindingError, match="delegation invalid"):
        FindingReceiver.from_delegation(s, owner_pubkey=OWNER.public_key_b64,
                                        delegation=_delegation(owner=rogue), now=NOW, scope=SCOPE)
    assert _findings(s) == []


def test_expired_delegation_refuses_all_findings():
    s = _store()
    with pytest.raises(InertFindingError, match="delegation invalid"):
        _receiver(s, delegation=_delegation(not_after=NOT_AFTER), now=NOT_AFTER + 1)


def test_out_of_scope_delegation_refuses_all_findings():
    s = _store()
    with pytest.raises(InertFindingError, match="delegation invalid"):
        _receiver(s, delegation=_delegation(scope="other-target"), scope=SCOPE)


def test_wildcard_delegation_covers_the_scope():
    s = _store()
    seq = _receiver(s, delegation=_delegation(scope="*")).ingest(_envelope())
    assert s.get(seq).kind == "finding"


def test_in_scope_delegation_refuses_a_finding_labelled_for_another_engagement():
    # THE cross-engagement-laundering negative control (S4 HIGH-1): the delegation AND the receiver are both
    # scoped to "acme", the finding is authentically signed by the delegated key — but its OWN signed
    # engagement_slug points at a different, unauthorized engagement. It must be refused; nothing spined.
    s = _store()
    env = _envelope(slug="megacorp-PRODUCTION-not-authorized")
    with pytest.raises(InertFindingError, match="outside the owner-delegated scope"):
        _receiver(s).ingest(env)
    assert _findings(s) == []


def test_wildcard_receiver_imposes_no_per_finding_scope_confinement():
    # A receiver built for scope "*" (e.g. an all-engagements delegation) admits any engagement_slug — the
    # honest, documented behaviour: "*" means no per-finding confinement.
    s = _store()
    seq = _receiver(s, scope="*", delegation=_delegation(scope="*")).ingest(_envelope(slug="anything-goes"))
    assert s.get(seq).kind == "finding"
