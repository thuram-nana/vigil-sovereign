"""
Nervous-System N1 — cryptographic tamper-evidence for the event spine.

The blackboard is append-only by trigger; N1 adds a hash-linked, governance-signed chain over
the log (reusing evidence/chain.py), so tampering that bypasses the triggers — an edited
payload, a reordered/deleted event, or an event appended after the head was signed — is still
detected, and the spine is anchored to the governance trust root. Purely additive: no schema
change; an unsigned spine behaves exactly as before.
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.agents.blackboard import open_blackboard
from framework.v2.agents.spine_chain import (
    build_spine_chain,
    event_digest,
    sign_spine_head,
    verify_spine_chain,
    verify_spine_head,
)
from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot

_SLUG = "chain-test"


def _bb(tmp_path: Path):
    b = open_blackboard(db_path=tmp_path / "bb.sqlite")
    b.engagement_id(_SLUG)
    return b


def _obs(b, summary: str) -> int:
    return b.post(engagement=_SLUG, kind="observation", agent_name="a",
                  payload={"source": "s", "surface": "p", "summary": summary})


def _trust_root(threshold: int = 2, n: int = 3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"g{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    return tr, [(f"g{i}", k.private_key_b64) for i, k in enumerate(keys)]


# ---- deterministic digest + clean chain -------------------------------------


def test_event_digest_is_deterministic_and_content_sensitive(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    _obs(b, "one")
    rows = b.replay(engagement=_SLUG, include_superseded=True)
    assert event_digest(rows[0]) == event_digest(rows[0])          # stable
    _obs(b, "two")
    rows2 = b.replay(engagement=_SLUG, include_superseded=True)
    assert event_digest(rows2[0]) != event_digest(rows2[1])        # content-sensitive
    b.close()


def test_clean_chain_verifies(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    for i in range(5):
        _obs(b, f"e{i}")
    entries = build_spine_chain(b, _SLUG)
    ok, reason = verify_spine_chain(b, _SLUG, entries)
    assert ok and len(entries) == 5
    b.close()


# ---- signed head + tamper detection -----------------------------------------


def test_signed_head_verifies_and_appended_event_is_detected(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    for i in range(4):
        _obs(b, f"e{i}")
    tr, signers = _trust_root()
    head = sign_spine_head(b, _SLUG, signers=signers[:2])
    ok, _ = verify_spine_head(b, _SLUG, head, tr)
    assert ok                                                       # anchored + intact

    _obs(b, "sneaked-in-after-signing")                            # append after the head was signed
    ok, reason = verify_spine_head(b, _SLUG, head, tr)
    assert not ok                                                  # the new event is not anchored → detected
    b.close()


def test_content_tamper_breaks_the_chain(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    for i in range(3):
        _obs(b, f"e{i}")
    entries = build_spine_chain(b, _SLUG)
    # simulate a raw-DB content edit: an entry whose digest no longer matches the live event
    tampered = list(entries)
    tampered[0] = tampered[0].model_copy(update={"cert_digest": "de" * 32})
    ok, reason = verify_spine_chain(b, _SLUG, tampered)
    assert not ok and "mismatch" in reason
    b.close()


def test_stale_chain_missing_a_live_event_is_detected(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    for i in range(3):
        _obs(b, f"e{i}")
    entries = build_spine_chain(b, _SLUG)                           # chain over 3 events
    _obs(b, "e3")                                                   # log grows to 4
    ok, reason = verify_spine_chain(b, _SLUG, entries)
    assert not ok and "mismatch" in reason                         # stale chain no longer covers the log
    b.close()


def test_cross_engagement_head_is_rejected(tmp_path: Path) -> None:
    # a head signed for engagement A must NOT verify against a look-alike engagement B
    # (slug binding + engagement_id in the digest) — the N1 review's cross-replay defect.
    b = open_blackboard(db_path=tmp_path / "bb.sqlite")
    for slug in ("A", "B"):
        b.engagement_id(slug)
        for i in range(3):
            b.post(engagement=slug, kind="observation", agent_name="a",
                   payload={"source": "s", "surface": "p", "summary": f"e{i}"})   # identical content
    tr, signers = _trust_root()
    head_a = sign_spine_head(b, "A", signers=signers[:2])
    assert verify_spine_head(b, "A", head_a, tr)[0]                 # valid for its own engagement
    ok, reason = verify_spine_head(b, "B", head_a, tr)             # replayed onto B
    assert not ok and "cross-engagement" in reason
    b.close()


def test_chain_covers_the_full_log(tmp_path: Path) -> None:
    # the chain must cover EVERY event (no silent truncation) — length equals the live count.
    b = _bb(tmp_path)
    for i in range(7):
        _obs(b, f"e{i}")
    entries = build_spine_chain(b, _SLUG)
    assert len(entries) == b.count(engagement=_SLUG) == 7
    b.close()


def test_rollback_below_highwater_is_rejected(tmp_path: Path) -> None:
    b = _bb(tmp_path)
    for i in range(3):
        _obs(b, f"e{i}")
    tr, signers = _trust_root()
    head = sign_spine_head(b, _SLUG, signers=signers[:2])
    ok, reason = verify_spine_head(b, _SLUG, head, tr, prev_highwater=99)
    assert not ok and "rollback" in reason.lower()
    b.close()
