"""The keyless offense-plane re-verifiers refuse an unencodable signed core instead of raising.

They read owner-signed records off the published seam with ``json.loads``, so a file carrying the JSON escape
``"\\ud800"`` yields a lone-surrogate string that no signer could have produced. Canonical JSON then fails to
encode as UTF-8 (``UnicodeEncodeError``, a ``ValueError``). Each of these verifiers promises to fail closed —
return False / ``(False, 0, reason)``, or raise its own typed error — and before this fix each let the
``UnicodeEncodeError`` escape instead (``verify_eval_capability_grant`` documents that it NEVER raises).
"""
from __future__ import annotations

import pytest
from vigil_core import generate_keypair
from vigil_integration.live import eval_attestation, eval_capability_grant
from vigil_integration.posture.authority import AuthorityError, verify_authority_envelope

BAD = "\ud800"
OWNER = generate_keypair()
EVALUATOR = generate_keypair()
PINNED = frozenset({OWNER.public_key_b64})


@pytest.mark.parametrize("mod", [eval_capability_grant, eval_attestation], ids=lambda m: m.__name__)
def test_seal_over_an_unencodable_record_list_is_refused(mod):
    seal = {"kind": mod._SEAL_KIND, "slug": "acme", "pubkey": OWNER.public_key_b64, "sig": "AAAA", "seq": 0}
    ok, _n, reason = mod._verify_seal(seal, "acme", [{"target": BAD}], PINNED)
    assert ok is False and "does not verify" in reason


@pytest.mark.parametrize("mod", [eval_capability_grant, eval_attestation], ids=lambda m: m.__name__)
def test_owner_signature_over_an_unencodable_core_is_refused(mod):
    payload = {k: BAD for k in mod._CORE}
    payload.update(pubkey=OWNER.public_key_b64, sig="AAAA")
    assert mod._verify_owner(payload, PINNED) is False


@pytest.mark.parametrize("mod", [eval_capability_grant, eval_attestation], ids=lambda m: m.__name__)
def test_evaluator_pop_over_an_unencodable_core_is_refused(mod):
    payload = {k: BAD for k in mod._CORE}
    payload.update(evaluator_pubkey=EVALUATOR.public_key_b64, evaluator_sig="AAAA")
    assert mod._verify_pop(payload, PINNED) is False


@pytest.mark.parametrize("field,value", [("scope_hosts", [BAD]), ("not_before", "not-a-number"),
                                         ("not_before", float("inf")), ("not_after", float("-inf"))])
def test_authority_envelope_with_an_unusable_core_raises_authority_error(field, value):
    # json.loads accepts Infinity, so an infinite window bound can arrive from an envelope file
    env = {"owner_pubkey": OWNER.public_key_b64, "engagement": "acme", "sig": "AAAA", field: value}
    with pytest.raises(AuthorityError, match="malformed"):
        verify_authority_envelope(env, trusted_owner_pubkey=OWNER.public_key_b64, engagement="acme")
