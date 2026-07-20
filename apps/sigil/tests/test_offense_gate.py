"""SIGIL P7 Slice 1 — the offense gate (FATAL-2 completion).

Fail-closed by default; only an owner-signed, charter-bound, UNEXPIRED, non-replayed open un-gates
offense; any close is honoured (fail-safe direction); expiry auto-closes; a forged / wrong-charter /
tampered / keyless / REPLAYED / malformed-sig open un-gates nothing; state is re-derived from the
spine (survives restart). The kill-switch's mirror image with the asymmetry inverted.
"""

import itertools
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

_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))  # a fresh, strictly-increasing issued_at for each open


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _gate(store, *, owner_key=OWNER, pub=OWNER_PUB):
    return OffenseGate(store, owner_key=owner_key, trusted_pubkey=pub)


def _open(g, *, charter_id=CID, charter_hash=CHASH, not_after=FUTURE, issued_at=None):
    return g.open_gate(charter_id=charter_id, charter_hash=charter_hash,
                       not_after=not_after, issued_at=issued_at if issued_at is not None else _iss())


def test_default_closed():
    s = _store()
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False
    with pytest.raises(OffenseGateClosed):
        assert_offense_gated(s, charter_id=CID, charter_hash=CHASH, now=NOW,
                             owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def test_owner_signed_open_unexpired_opens_and_asserts():
    s = _store()
    g = _gate(s)
    _open(g)
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True
    assert_offense_gated(s, charter_id=CID, charter_hash=CHASH, now=NOW,
                         owner_key=OWNER, trusted_pubkey=OWNER_PUB)  # does not raise


def test_open_for_a_different_charter_or_hash_does_not_open_this_one():
    s = _store()
    g = _gate(s)
    _open(g, charter_id="other", charter_hash=DIFF_HASH)
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False
    _open(g, charter_id=CID, charter_hash=DIFF_HASH)  # right id, wrong hash
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_expired_open_auto_closes():
    s = _store()
    g = _gate(s)
    _open(g, not_after=NOW + 10)
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW + 20) is False  # past not_after


def test_forged_open_from_non_owner_does_nothing():
    s = _store()
    _open(OffenseGate(s, owner_key=ATTACKER, trusted_pubkey=OWNER_PUB))  # attacker-signed
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_close_is_honoured_even_when_unauthenticated():
    s = _store()
    _open(_gate(s))
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True
    OffenseGate(s, owner_key=ATTACKER, trusted_pubkey=OWNER_PUB).close_gate(reason="safe-dir DoS")
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_replay_of_open_after_close_does_not_reopen():
    # BLOCK-1 regression: a captured owner-signed OPEN must NOT re-open after an owner CLOSE.
    s = _store()
    g = _gate(s)
    open_seq = _open(g, issued_at=100.0)
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True
    captured = dict(s.get(open_seq).payload)   # the exact signed open bytes
    g.close_gate()
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False
    # attacker (no owner key) replays the byte-identical signed open
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(captured))
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False  # anti-replay holds


def test_stale_lower_issued_open_cannot_override_a_newer_one():
    s = _store()
    g = _gate(s)
    old = dict(s.get(_open(g, issued_at=10.0)).payload)
    _open(g, issued_at=20.0)
    g.close_gate()
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(old))  # replay the OLD open
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_tampered_expiry_breaks_the_signature():
    s = _store()
    core = {"signal": SIGNAL, "state": "open", "charter_id": CID, "charter_hash": CHASH,
            "not_after": NOW + 10, "issued_at": 100.0}
    payload = {**signed_payload(core, OWNER), "tier": "A0", "decision": "auto"}
    payload["not_after"] = FUTURE  # extend the window WITHOUT re-signing
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_tampered_charter_hash_breaks_the_signature():
    s = _store()
    core = {"signal": SIGNAL, "state": "open", "charter_id": CID, "charter_hash": CHASH,
            "not_after": FUTURE, "issued_at": 100.0}
    payload = {**signed_payload(core, OWNER), "tier": "A0", "decision": "auto"}
    payload["charter_hash"] = DIFF_HASH  # rebind to a different charter without re-signing
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert _gate(s).is_open(charter_id=CID, charter_hash=DIFF_HASH, now=NOW) is False


def test_malformed_signature_fails_closed_without_raising():
    # BLOCK-2 regression: a garbage sig must fold to CLOSED, never raise IntegrityError out of state().
    s = _store()
    core = {"signal": SIGNAL, "state": "open", "charter_id": CID, "charter_hash": CHASH,
            "not_after": FUTURE, "issued_at": 100.0}
    payload = {**core, "sig": "!!!not-base64!!!", "pubkey": OWNER_PUB, "tier": "A0", "decision": "auto"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False  # no exception


def test_reopen_after_close_with_fresh_issued_at():
    s = _store()
    g = _gate(s)
    _open(g)
    g.close_gate()
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False
    _open(g)  # a genuine re-open uses a fresh (larger) issued_at
    assert g.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True


def test_state_survives_a_fresh_instance_restart():
    s = _store()
    _open(_gate(s))
    g2 = OffenseGate(SpineStore(s.path), owner_key=OWNER, trusted_pubkey=OWNER_PUB)  # re-derives from spine
    assert g2.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is True


def test_keyless_gate_cannot_open():
    s = _store()
    _open(OffenseGate(s, owner_key=None, trusted_pubkey=OWNER_PUB))  # no key -> sig None
    assert _gate(s).is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False


def test_open_requires_charter_binding():
    with pytest.raises(ValueError):
        _open(_gate(_store()), charter_id="", charter_hash="")


def test_expiry_charter_and_issued_at_are_in_the_signed_core():
    for field in ("not_after", "charter_hash", "charter_id", "state", "issued_at"):
        assert field in _CORE
