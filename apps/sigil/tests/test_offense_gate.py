"""SIGIL P7 Slice 1 — the offense gate (FATAL-2 completion).

Fail-closed by default; only an owner-signed, charter-bound, UNEXPIRED open un-gates offense;
any close is honoured (fail-safe direction); expiry auto-closes; a forged / wrong-charter /
tampered / keyless open un-gates nothing; state is re-derived from the spine (survives restart).
The kill-switch's mirror image with the asymmetry inverted.
"""

import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.offense_gate import (
    _CORE,
    SIGNAL,
    OffenseGate,
    OffenseGateClosed,
    assert_offense_gated,
)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()

CID = "acme-2026"
CHASH = "a" * 64
DIFF_HASH = "b" * 64
NOW = 1_000_000.0
FUTURE = NOW + 3600.0


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _gate(store, *, owner_key=OWNER, pub=OWNER_PUB):
    return OffenseGate(store, owner_key=owner_key, trusted_pubkey=pub)


def test_default_closed():
    s = _store()
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False
    with pytest.raises(OffenseGateClosed):
        assert_offense_gated(s, charter_id=CID, charter_hash=CHASH, now=NOW,
                             owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def test_owner_signed_open_unexpired_opens_and_asserts():
    s = _store()
    g = _gate(s)
    g.open_gate(charter_id=CID, charter_hash=CHASH, not_after=FUTURE)
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True
    assert_offense_gated(s, charter_id=CID, charter_hash=CHASH, now=NOW,
                         owner_key=OWNER, trusted_pubkey=OWNER_PUB)  # does not raise


def test_open_for_a_different_charter_or_hash_does_not_open_this_one():
    s = _store()
    g = _gate(s)
    g.open_gate(charter_id="other", charter_hash=DIFF_HASH, not_after=FUTURE)
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False
    g.open_gate(charter_id=CID, charter_hash=DIFF_HASH, not_after=FUTURE)  # right id, wrong hash
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_expired_open_auto_closes():
    s = _store()
    g = _gate(s)
    g.open_gate(charter_id=CID, charter_hash=CHASH, not_after=NOW + 10)
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW + 20) is False  # past not_after


def test_forged_open_from_non_owner_does_nothing():
    s = _store()
    OffenseGate(s, owner_key=ATTACKER, trusted_pubkey=OWNER_PUB).open_gate(
        charter_id=CID, charter_hash=CHASH, not_after=FUTURE)  # attacker-signed
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_close_is_honoured_even_when_unauthenticated():
    s = _store()
    _gate(s).open_gate(charter_id=CID, charter_hash=CHASH, not_after=FUTURE)
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True
    # an attacker with no owner key CLOSES — honoured, because closing offense is the safe direction
    OffenseGate(s, owner_key=ATTACKER, trusted_pubkey=OWNER_PUB).close_gate(reason="safe-dir DoS")
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_tampered_expiry_breaks_the_signature():
    s = _store()
    core = {"signal": SIGNAL, "state": "open", "charter_id": CID, "charter_hash": CHASH, "not_after": NOW + 10}
    payload = {**signed_payload(core, OWNER), "tier": "A0", "decision": "auto"}
    payload["not_after"] = FUTURE  # extend the window WITHOUT re-signing
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    # verify recomputes over the tampered not_after -> mismatch -> open ignored -> closed
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_tampered_charter_hash_breaks_the_signature():
    s = _store()
    core = {"signal": SIGNAL, "state": "open", "charter_id": CID, "charter_hash": CHASH, "not_after": FUTURE}
    payload = {**signed_payload(core, OWNER), "tier": "A0", "decision": "auto"}
    payload["charter_hash"] = DIFF_HASH  # rebind to a different charter without re-signing
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert _gate(s).is_open(charter_id=CID, charter_hash=DIFF_HASH, now=NOW) is False


def test_reopen_after_close():
    s = _store()
    g = _gate(s)
    g.open_gate(charter_id=CID, charter_hash=CHASH, not_after=FUTURE)
    g.close_gate()
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False
    g.open_gate(charter_id=CID, charter_hash=CHASH, not_after=FUTURE)
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True


def test_state_survives_a_fresh_instance_restart():
    s = _store()
    _gate(s).open_gate(charter_id=CID, charter_hash=CHASH, not_after=FUTURE)
    g2 = OffenseGate(SpineStore(s.path), owner_key=OWNER, trusted_pubkey=OWNER_PUB)  # re-derives from spine
    assert g2.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True


def test_keyless_gate_cannot_open():
    s = _store()
    OffenseGate(s, owner_key=None, trusted_pubkey=OWNER_PUB).open_gate(
        charter_id=CID, charter_hash=CHASH, not_after=FUTURE)  # no key -> sig None
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_open_requires_charter_binding():
    with pytest.raises(ValueError):
        _gate(_store()).open_gate(charter_id="", charter_hash="", not_after=FUTURE)


def test_expiry_and_charter_are_in_the_signed_core():
    # regression guard: these MUST be authenticated or they could be rewritten (red-pen risk)
    assert "not_after" in _CORE
    assert "charter_hash" in _CORE
    assert "charter_id" in _CORE
    assert "state" in _CORE
