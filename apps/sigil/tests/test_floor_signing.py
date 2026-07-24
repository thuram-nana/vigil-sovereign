"""G2 slice-2 — owner-signed durable anti-rollback floor (floor.json).

The floor is signed by the caller that already holds the owner key (checkpoint), and its signature is
verified in `classify_head` against the SAME owner trust anchor (`tr`) that verifies the head — one key
source, so signing and verifying can never diverge. A signed floor's CONTENT cannot be rewritten without
breaking the signature (fail-closed → TAMPERING); a legacy UNSIGNED floor is accepted with a one-time
warning (non-bricking, re-signed on the next checkpoint).
"""
from __future__ import annotations

import json

import pytest

from sigil.reuse import (
    AuthorizerKey,
    TrustRoot,
    build_chain,
    digest_payload,
    generate_keypair,
)
from sigil.reuse.chain import sign_head
from sigil.spine import floor as floor_mod
from sigil.spine.checkpoint import classify_head
from sigil.spine.floor import (
    advance_floor,
    load_floor,
    reset_floor,
    verify_floor_signature,
)

OWNER = generate_keypair()
OWNER_PUBS = {OWNER.public_key_b64}


def _chain(n):
    return build_chain([digest_payload({"i": i}) for i in range(n)])


def _head(n):
    return sign_head(_chain(n), engagement_slug="s", signers=[("owner", OWNER.private_key_b64)])


def _tr():
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=OWNER.public_key_b64)])


@pytest.fixture(autouse=True)
def _reset_warn(monkeypatch):
    monkeypatch.setattr(floor_mod, "_warned_unsigned_floor", False, raising=False)


# --- verify_floor_signature (the unit) -------------------------------------------------------------

def test_signed_floor_verifies(tmp_path):
    p = tmp_path / "floor.json"
    fl = advance_floor(_head(10), owner_key=OWNER, path=p)
    assert fl.sig is not None and fl.pubkey == OWNER.public_key_b64
    ok, _ = verify_floor_signature(fl, OWNER_PUBS)
    assert ok is True


def test_unsigned_floor_accepted(tmp_path):
    p = tmp_path / "floor.json"
    fl = advance_floor(_head(5), path=p)                     # no owner_key → unsigned (legacy)
    assert fl.sig is None
    assert verify_floor_signature(load_floor(p), OWNER_PUBS)[0] is True   # accepted (legacy), warns once


def test_tampered_signed_floor_content_fails(tmp_path):
    p = tmp_path / "floor.json"
    advance_floor(_head(10), owner_key=OWNER, path=p)
    obj = json.loads(p.read_text())
    obj["entry_count"] = 1                                   # roll the floor DOWN under the OLD signature
    p.write_text(json.dumps(obj))
    ok, msg = verify_floor_signature(load_floor(p), OWNER_PUBS)
    assert ok is False and "does not verify" in msg


def test_floor_signed_by_wrong_key_fails(tmp_path):
    p = tmp_path / "floor.json"
    advance_floor(_head(10), owner_key=generate_keypair(), path=p)    # signed by an IMPOSTER
    ok, msg = verify_floor_signature(load_floor(p), OWNER_PUBS)
    assert ok is False and "not from an authorized owner key" in msg


def test_stripped_sig_but_content_signed_shape_fails(tmp_path):
    # a floor claiming a pubkey but with a non-str / missing sig must fail-closed, not accept
    p = tmp_path / "floor.json"
    advance_floor(_head(10), owner_key=OWNER, path=p)
    obj = json.loads(p.read_text())
    obj["sig"] = None                                        # pubkey present, sig cleared → not 'unsigned'
    assert verify_floor_signature(floor_mod.Floor(**obj), OWNER_PUBS)[0] is False


# --- end-to-end through classify_head (the certify path) -------------------------------------------

def test_classify_head_rejects_tampered_signed_floor(tmp_path):
    p = tmp_path / "floor.json"
    head = _head(10)
    advance_floor(head, owner_key=OWNER, path=p)
    good = load_floor(p)
    ok, _ = classify_head(head, _chain(10), _tr(), floor=good)
    assert ok is True                                        # legitimate signed floor certifies clean
    # now tamper the signed floor's content → classify_head must report TAMPERING
    bad = good.model_copy(update={"entry_count": 1})
    ok, msg = classify_head(head, _chain(10), _tr(), floor=bad)
    assert ok is False and "TAMPERING" in msg


def test_reset_floor_signs(tmp_path):
    p = tmp_path / "floor.json"
    advance_floor(_head(10), owner_key=OWNER, path=p)
    fl = reset_floor(_head(3), owner_key=OWNER, path=p)      # deliberate downward re-seed, still signed
    assert fl.sig is not None
    assert verify_floor_signature(load_floor(p), OWNER_PUBS)[0] is True


def test_advance_over_signed_prior(tmp_path):
    # the re-load-under-lock in _advance_locked parses the prior signed floor; a valid chain of advances works
    p = tmp_path / "floor.json"
    advance_floor(_head(5), owner_key=OWNER, path=p)
    advance_floor(_head(10), owner_key=OWNER, path=p)
    assert load_floor(p).entry_count == 10
