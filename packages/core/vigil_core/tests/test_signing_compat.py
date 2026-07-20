"""vigil_core — the migration-safety contract.

The whole plan rests on one property: promoting SIGIL's v2 chain to the shared core must break NO existing
signature. These tests pin it: a v1 head's signing bytes drop the v2 fields entirely (byte-identical to a
pre-v2 head), a v1 head verifies, a synthetic v2 (pruned/re-based) head verifies base-aware, m-of-n
threshold holds, and chain tamper is caught. Run with cryptography+pydantic available, e.g.:
    PYTHONPATH=packages/core/vigil_core ~/.sigil/venv/bin/python -m pytest packages/core/vigil_core/tests -q
"""
import pytest

from vigil_core import (
    AuthorizerKey,
    ChainEntry,
    Signature,
    TrustRoot,
    build_chain,
    digest_payload,
    evidence_signing_bytes,
    generate_keypair,
    sign,
    sign_head,
    verify_chain,
    verify_head,
    verify_threshold,
)
from vigil_core.canonical import _EVIDENCE_DOMAIN
from vigil_core.chain import _HEAD_V2_FIELDS, _head_payload
from vigil_core.models import _GENESIS_PREV, SignedChainHead


def _chain(n):
    return build_chain([digest_payload({"i": i}) for i in range(n)])


def _owner():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                           public_key_b64=kp.public_key_b64)])
    return kp, tr


def test_signing_domain_tag_unchanged():
    # the cross-compatibility anchor: the signing domain tag must remain crucible-evidence-v1\x00 so every
    # signature ever produced by CRUCIBLE or SIGIL still verifies against this core.
    assert _EVIDENCE_DOMAIN == b"crucible-evidence-v1\x00"


def test_v1_head_signs_byte_identical():
    kp, _tr = _owner()
    head = sign_head(_chain(5), engagement_slug="s", signers=[("owner", kp.private_key_b64)])
    assert head.schema_version == 1
    payload = _head_payload(head)
    # a v1 head drops ALL six v2 fields from its signing payload -> byte-identical to a pre-v2 head
    for f in _HEAD_V2_FIELDS:
        assert f not in payload, f"v1 signing payload must not carry v2 field {f}"
    # and the signable bytes are stable/deterministic
    assert evidence_signing_bytes(_head_payload(head)) == evidence_signing_bytes(_head_payload(head))


def test_v1_head_verifies():
    kp, tr = _owner()
    entries = _chain(5)
    head = sign_head(entries, engagement_slug="s", signers=[("owner", kp.private_key_b64)])
    ok, _msg = verify_head(head, entries, tr)
    assert ok


def test_v2_pruned_head_verifies_base_aware():
    # a synthetic v2 head over a re-based (pruned) live window [K..T] links from base_prev_hash, and
    # entry_count stays ABSOLUTE (base_count + live). This is the pruning path CRUCIBLE v1 never had.
    kp, tr = _owner()
    full = _chain(10)
    K = 5
    live = full[K:]
    base_prev = full[K - 1].entry_hash
    head = SignedChainHead(schema_version=2, engagement_slug="s", last_seq=live[-1].seq,
                           entry_count=10, head_hash=live[-1].entry_hash, base_seq=K,
                           base_prev_hash=base_prev, base_count=K)
    msg = evidence_signing_bytes(_head_payload(head))
    head = head.model_copy(update={"signatures": [Signature(key_id="owner",
                                   signature_b64=sign(kp.private_key_b64, msg))]})
    ok, why = verify_head(head, live, tr, genesis_prev=base_prev)
    assert ok, why


def test_threshold_m_of_n():
    k1, k2, k3 = generate_keypair(), generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=k1.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=k2.public_key_b64),
        AuthorizerKey(key_id="c", name="c", public_key_b64=k3.public_key_b64)])
    msg = b"authorize"
    one = [Signature(key_id="a", signature_b64=sign(k1.private_key_b64, msg))]
    two = one + [Signature(key_id="b", signature_b64=sign(k2.private_key_b64, msg))]
    assert not verify_threshold(msg, one, tr).satisfied      # 1 of 2 -> not satisfied
    assert verify_threshold(msg, two, tr).satisfied          # 2 of 2 -> satisfied


def test_chain_tamper_is_caught():
    entries = _chain(6)
    ok, _ = verify_chain(entries)
    assert ok
    bad = list(entries)
    bad[3] = ChainEntry(seq=3, prev_hash=bad[3].prev_hash, cert_digest="deadbeef" * 8,
                        entry_hash=bad[3].entry_hash)         # cert_digest tampered, entry_hash stale
    ok2, why = verify_chain(bad)
    assert not ok2 and "entry_hash mismatch" in why


def test_no_offense_guard_is_not_in_the_core():
    # assert_no_offense() is SIGIL's sovereignty concern and must NOT live in the shared core (CRUCIBLE,
    # an offense engine, depends on this core). Its absence here is load-bearing.
    import vigil_core
    assert not hasattr(vigil_core, "assert_no_offense")
    assert _GENESIS_PREV  # genesis constant is exposed via models
