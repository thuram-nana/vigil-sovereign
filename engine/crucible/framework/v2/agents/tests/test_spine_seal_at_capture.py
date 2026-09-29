"""
W16-8 — SEAL-AT-CAPTURE for the append-only spine (closes LIMIT-spine-seal-at-capture).

Credential-bearing excerpts (``ObservationPayload.raw_excerpt`` / ``ResultPayload.body_excerpt``) may
reflect an Authorization / Cookie / Set-Cookie value. Before this wiring they landed on the append-only
spine in PLAINTEXT and so were NOT erasable by per-engagement crypto-shredding. Now the single append-only
writer (``Blackboard.post``) seals them under the engagement DEK BEFORE the row is written, and every
in-engagement reader unseals transparently via ``Blackboard.reveal_excerpt``.

These tests pin the end-to-end guarantee and prove it is real, not simulated:

  * the plaintext credential NEVER lands on the spine (absent from the raw ``payload_json`` column);
  * a reader unseals it in-engagement to the EXACT original while the DEK lives;
  * after ``EvidenceKeyring.shred`` the excerpt is UNRECOVERABLE, the row is byte-identical, and the
    spine hash-chain still verifies (crypto-shred touched no row);
  * the console Live reader (``BlackboardTailer``) shows the plaintext while the DEK lives and a fixed
    redacted placeholder after a shred — never the opaque token, never plaintext post-erasure;
  * sealing is idempotent (an already-sealed value is never double-sealed) and skips an empty excerpt
    (no DEK is minted for nothing to protect).

Fails without the fix: on a tree where ``post`` does not seal, the raw ``payload_json`` would contain the
plaintext credential and ``is_sealed`` would be False — the first assertions below go red.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.blackboard import Blackboard
from framework.v2.agents.spine_chain import (
    build_spine_chain,
    event_digest,
    verify_spine_chain,
)
from framework.v2.common import crypto_shred
from framework.v2.common.crypto_shred import EvidenceKeyring, EvidenceShredded

_COOKIE = "Set-Cookie: session=SECRET-tok-4242; Domain=victim.example"
_AUTH = "Authorization: Bearer SECRET-abc-99887766"


def _bb(tmp_path: Path, name: str) -> tuple[Blackboard, EvidenceKeyring]:
    kr = EvidenceKeyring(keys_dir=tmp_path / f"{name}-keys")
    bb = Blackboard(db_path=tmp_path / f"{name}.db", keyring=kr)
    return bb, kr


def _raw_payload_json(bb: Blackboard, event_id: int) -> str:
    """The exact bytes stored in the append-only row — the airtight place to prove plaintext never landed."""
    row = bb._conn.execute("SELECT payload_json FROM events WHERE id = ?", (event_id,)).fetchone()
    return str(row[0])


# ---- the claim: a result body_excerpt is sealed at capture, recoverable in-engagement, shreddable -----


def test_result_body_excerpt_is_sealed_at_capture_recoverable_then_shreddable(tmp_path: Path) -> None:
    slug = "seal-result"
    bb, kr = _bb(tmp_path, slug)
    bb.engagement_id(slug)

    rid = bb.post(engagement=slug, kind="result", agent_name="exploit",
                  payload={"action_id": "A1", "success": True, "body_excerpt": _COOKIE})

    # (1) the plaintext credential NEVER reached the spine — not in the raw stored column, nor the field.
    assert "SECRET" not in _raw_payload_json(bb, rid)
    stored = bb.get(rid).payload["body_excerpt"]
    assert crypto_shred.is_sealed(stored)
    assert "SECRET" not in stored

    # (2) an in-engagement reader unseals it to the EXACT original while the DEK lives.
    assert bb.reveal_excerpt(slug, stored) == _COOKIE

    digest_before = event_digest(bb.get(rid))

    # (3) crypto-shred -> UNRECOVERABLE; the row is byte-identical; the hash-chain still verifies.
    receipt = kr.shred(slug)
    assert receipt.shredded is True
    assert bb.reveal_excerpt(slug, stored) == crypto_shred.REDACTED_SHREDDED
    with pytest.raises(EvidenceShredded):
        kr.unseal_text(slug, stored)
    assert bb.get(rid).payload["body_excerpt"] == stored          # spine row untouched by the shred
    assert event_digest(bb.get(rid)) == digest_before
    ok, why = verify_spine_chain(bb, slug, build_spine_chain(bb, slug))
    assert ok, why
    bb.close()


def test_observation_raw_excerpt_is_sealed_at_capture(tmp_path: Path) -> None:
    slug = "seal-observation"
    bb, kr = _bb(tmp_path, slug)
    bb.engagement_id(slug)

    oid = bb.post(engagement=slug, kind="observation", agent_name="recon",
                  payload={"source": "recon", "surface": "/admin", "summary": "hit",
                           "raw_excerpt": _AUTH, "confidence": 0.7})

    assert "SECRET" not in _raw_payload_json(bb, oid)
    stored = bb.get(oid).payload["raw_excerpt"]
    assert crypto_shred.is_sealed(stored) and "SECRET" not in stored
    assert bb.reveal_excerpt(slug, stored) == _AUTH
    # reveal_excerpt keyed by the int engagement id resolves the slug and unseals identically.
    eid = bb.engagement_id(slug)
    assert bb.reveal_excerpt(eid, stored) == _AUTH
    bb.close()


# ---- idempotency + empty-skip (safe to call unconditionally at the single writer) ---------------------


def test_seal_is_idempotent_for_an_already_sealed_value(tmp_path: Path) -> None:
    slug = "idem"
    bb, kr = _bb(tmp_path, slug)
    bb.engagement_id(slug)

    pre = kr.seal_text(slug, "PRE-SECRET-value")            # already sealed by a caller
    rid = bb.post(engagement=slug, kind="result", agent_name="a",
                  payload={"action_id": "A", "success": True, "body_excerpt": pre})

    stored = bb.get(rid).payload["body_excerpt"]
    assert stored == pre                                    # NOT double-sealed (unchanged token)
    assert bb.reveal_excerpt(slug, stored) == "PRE-SECRET-value"
    bb.close()


def test_empty_excerpt_is_not_sealed_and_mints_no_key(tmp_path: Path) -> None:
    slug = "empty"
    bb, kr = _bb(tmp_path, slug)
    bb.engagement_id(slug)

    rid = bb.post(engagement=slug, kind="result", agent_name="a",
                  payload={"action_id": "A", "success": False, "body_excerpt": ""})

    assert bb.get(rid).payload["body_excerpt"] == ""        # passes through unchanged
    assert not kr.has_key(slug)                             # no DEK minted for nothing to protect
    assert bb.reveal_excerpt(slug, "") == ""                # reveal is total on a plaintext/empty value
    bb.close()


# ---- the console Live reader unseals in-engagement and redacts after a shred --------------------------


def test_console_tailer_unseals_in_engagement_then_redacts_after_shred(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Both the posting blackboard's default keyring AND the tailer's default keyring resolve to this
    # one env-overridden keystore, so the console reader round-trips exactly what post() sealed.
    monkeypatch.setenv("CRUCIBLE_EVIDENCE_KEYS_DIR", str(tmp_path / "keys"))
    from framework.v2.console.blackboard_sse import BlackboardTailer

    slug = "console-seal"
    db = tmp_path / "spine.db"
    bb = Blackboard(db_path=db)                              # default keyring -> honours the env override
    bb.engagement_id(slug)
    bb.post(engagement=slug, kind="result", agent_name="exploit",
            payload={"action_id": "A", "success": True, "body_excerpt": _COOKIE})
    bb.close()

    tailer = BlackboardTailer(slug, db_path=db)
    events = [ev for _id, ev in tailer.read_new()]
    tailer.close()
    result_view = next(e for e in events if e["kind"] == "result")
    assert result_view["payload"]["body_excerpt"] == _COOKIE   # transparently unsealed for the view

    # shred, then re-tail: the emitted view must be the redacted placeholder — not the token, not plaintext.
    EvidenceKeyring().shred(slug)
    tailer2 = BlackboardTailer(slug, db_path=db)
    events2 = [ev for _id, ev in tailer2.read_new()]
    tailer2.close()
    result_view2 = next(e for e in events2 if e["kind"] == "result")
    assert result_view2["payload"]["body_excerpt"] == crypto_shred.REDACTED_SHREDDED
