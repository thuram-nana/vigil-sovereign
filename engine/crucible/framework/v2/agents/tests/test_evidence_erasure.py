"""
W16-8 — right-to-erasure for append-only evidence (crypto-shredding).

The event spine is append-only by SQLite trigger, yet captured evidence holds real
Authorization/Cookie headers + response bodies. A data-protection erasure request cannot
DELETE those rows without breaking the append-only / tamper-evidence guarantee. The decision
(ADR knowledge/decisions/0008) is to CRYPTO-SHRED: seal credential-bearing evidence under a
per-engagement key held OUTSIDE the spine, and erase by destroying that key.

These tests pin the claim end-to-end and prove the guarantee is not weakened:

  * after erasure the credential material is UNRECOVERABLE (on disk AND in a sealed spine
    excerpt) WHILE the spine hash-chain still verifies and the erased rows are byte-identical;
  * NEGATIVE CONTROLS: the append-only triggers still refuse DELETE/UPDATE after erasure; the
    shred is per-engagement (it does not wipe a sibling engagement — not a global no-op); a
    tampered/cross-engagement ciphertext is rejected, never silently returned; the destructive
    CLI default-denies without --yes.

Fails without the fix: it imports the erasure module + crypto-shred core, which do not exist
on a tree without this change (collection error), and asserts behaviour that only the
implemented crypto-shred provides.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from framework.v2.agents import evidence_erasure
from framework.v2.agents.blackboard import open_blackboard
from framework.v2.agents.evidence_erasure import erase_engagement_evidence
from framework.v2.agents.spine_chain import (
    build_spine_chain,
    event_digest,
    verify_spine_chain,
)
from framework.v2.common import crypto_shred
from framework.v2.common.crypto_shred import EvidenceKeyring, EvidenceShredded

_COOKIE = "session=SECRET-abc123; Domain=victim.example"
_AUTH = "Authorization: Bearer SECRET-tok-99887766"


def _keyring(tmp_path: Path) -> EvidenceKeyring:
    return EvidenceKeyring(keys_dir=tmp_path / "keys")


def _bb(tmp_path: Path, *slugs: str):
    b = open_blackboard(db_path=tmp_path / "bb.sqlite")
    for s in slugs:
        b.engagement_id(s)
    return b


def _obs(b, slug: str, summary: str) -> int:
    return b.post(engagement=slug, kind="observation", agent_name="a",
                  payload={"source": "s", "surface": "p", "summary": summary})


# ---- the claim: unrecoverable after erasure, chain still verifies --------------------------


def test_erasure_makes_credential_unrecoverable_while_the_spine_chain_verifies(tmp_path: Path) -> None:
    slug = "acme"
    kr = _keyring(tmp_path)
    bb = _bb(tmp_path, slug)

    # (a) on-disk archive: two captured files holding real credentials in the clear.
    ev = tmp_path / "evidence"
    (ev / "act1").mkdir(parents=True)
    body = ev / "act1" / "response.body"
    body.write_bytes(("<html>set by " + _COOKIE + "</html>").encode())
    req = ev / "act1" / "request.http"
    req.write_text("GET /admin HTTP/1.1\r\n" + _AUTH + "\r\n\r\n", encoding="utf-8")

    # (b) spine: a result event whose body_excerpt embeds the SAME credential, but SEALED under
    #     the engagement DEK — the append-only-safe way to keep a credential-bearing excerpt.
    sealed_excerpt = kr.seal_text(slug, _COOKIE)
    assert "SECRET" not in sealed_excerpt                       # the spine row never holds plaintext
    result_id = bb.post(engagement=slug, kind="result", agent_name="exploit",
                        payload={"action_id": "act1", "success": True,
                                 "body_excerpt": sealed_excerpt,
                                 "evidence_path": str(ev / "act1")})
    assert kr.unseal_text(slug, sealed_excerpt) == _COOKIE      # recoverable BEFORE erasure
    digest_before = event_digest(bb.get(result_id))

    # ---- ERASE ----
    res = erase_engagement_evidence(slug, bb=bb, keyring=kr, evidence_root=ev)
    assert res.receipt.shredded is True
    assert res.sealed_files == 2 and res.receipt.key_fingerprint

    # credential UNRECOVERABLE — the sealed spine excerpt can no longer be opened (DEK gone) ...
    with pytest.raises(EvidenceShredded):
        kr.unseal_text(slug, sealed_excerpt)
    # ... and the on-disk files are now ciphertext with no plaintext credential left.
    on_disk = body.read_bytes() + req.read_bytes()
    assert b"SECRET" not in on_disk
    assert crypto_shred.is_sealed(body.read_bytes()) and crypto_shred.is_sealed(req.read_bytes())
    with pytest.raises(EvidenceShredded):
        kr.unseal(slug, body.read_bytes())

    # the append-only credential ROW is byte-identical (crypto-shred touched no spine row) ...
    assert bb.get(result_id).payload["body_excerpt"] == sealed_excerpt
    assert event_digest(bb.get(result_id)) == digest_before
    # ... and the spine hash-chain over the post-erasure log still verifies.
    ok, why = verify_spine_chain(bb, slug, build_spine_chain(bb, slug))
    assert ok, why
    bb.close()


# ---- NEGATIVE CONTROL: append-only guarantee survives the erasure mechanism ----------------


def test_append_only_guarantee_survives_the_erasure_mechanism(tmp_path: Path) -> None:
    slug = "acme"
    kr = _keyring(tmp_path)
    bb = _bb(tmp_path, slug)
    ids = [_obs(bb, slug, f"e{i}") for i in range(3)]
    count_before = bb.count(engagement=slug)
    digests_before = {r.id: event_digest(r)
                      for r in bb.replay(engagement=slug, include_superseded=True)}

    ev = tmp_path / "evidence"
    (ev / "a").mkdir(parents=True)
    (ev / "a" / "response.body").write_bytes(b"tok=SECRET-xyz")

    res = erase_engagement_evidence(slug, bb=bb, keyring=kr, evidence_root=ev)

    # the erasure APPENDED exactly one tombstone and deleted / rewrote NOTHING.
    assert bb.count(engagement=slug) == count_before + 1
    for rid, dg in digests_before.items():
        assert event_digest(bb.get(rid)) == dg                 # every prior row byte-identical

    # the append-only triggers STILL refuse to remove or rewrite a row — the mechanism did not
    # relax them (a deliberately illegal DELETE/UPDATE is rejected, asserted here).
    with pytest.raises(sqlite3.IntegrityError):
        bb._conn.execute("DELETE FROM events WHERE id = ?", (ids[0],))
    with pytest.raises(sqlite3.IntegrityError):
        bb._conn.execute("UPDATE events SET agent_name = 'x' WHERE id = ?",
                         (res.tombstone_event_id,))

    # the tombstone is a real append-only DECISION event describing the erasure.
    tomb = bb.get(res.tombstone_event_id)
    assert tomb is not None and tomb.kind == "decision"
    assert tomb.payload["choice"] == "crypto-shredded"
    bb.close()


def test_shredding_one_engagement_does_not_erase_a_sibling(tmp_path: Path) -> None:
    # per-engagement key isolation: the shred is targeted — it erases A and leaves B fully
    # recoverable, so it is neither a global wipe nor a no-op.
    kr = _keyring(tmp_path)
    bb = _bb(tmp_path, "A", "B")
    tok_a = kr.seal_text("A", "A-cred-SECRET")
    tok_b = kr.seal_text("B", "B-cred-SECRET")
    ev = tmp_path / "ev"
    ev.mkdir()

    erase_engagement_evidence("A", bb=bb, keyring=kr, evidence_root=ev)

    with pytest.raises(EvidenceShredded):
        kr.unseal_text("A", tok_a)                             # A erased
    assert kr.unseal_text("B", tok_b) == "B-cred-SECRET"      # B intact
    bb.close()


# ---- NEGATIVE CONTROL: the seal is real crypto, not a placeholder --------------------------


def test_tampered_or_cross_engagement_ciphertext_is_rejected_not_silently_returned(
    tmp_path: Path,
) -> None:
    kr = _keyring(tmp_path)
    blob = kr.seal("A", b"top-secret")
    kr.seal("B", b"other")                                     # ensure B's key exists

    # flip a ciphertext byte -> AEAD authentication fails; no silent garbage return.
    bad = bytearray(blob)
    bad[-1] ^= 0x01
    with pytest.raises(crypto_shred.CryptoShredError) as ei1:
        kr.unseal("A", bytes(bad))
    assert not isinstance(ei1.value, EvidenceShredded)         # key exists — it is an auth failure

    # a blob sealed for A cannot be opened under B even though B has a key (AAD binding).
    with pytest.raises(crypto_shred.CryptoShredError) as ei2:
        kr.unseal("B", blob)
    assert not isinstance(ei2.value, EvidenceShredded)


def test_unsafe_engagement_id_fails_closed(tmp_path: Path) -> None:
    kr = _keyring(tmp_path)
    with pytest.raises(crypto_shred.CryptoShredError):
        kr.seal("../../etc/shadow", b"data")                  # path traversal -> DENY


def test_seal_unseal_roundtrip_and_fingerprint_stability(tmp_path: Path) -> None:
    kr = _keyring(tmp_path)
    assert kr.unseal("eng", kr.seal("eng", b"\x00\x01payload")) == b"\x00\x01payload"
    fp1 = kr.key_fingerprint("eng")
    assert len(fp1) == 64 and fp1 == kr.key_fingerprint("eng")  # stable while the key lives
    receipt = kr.shred("eng")
    assert receipt.shredded and receipt.key_fingerprint == fp1  # receipt names the destroyed key
    assert kr.key_fingerprint("eng") == ""                      # key gone


def test_erasure_is_idempotent(tmp_path: Path) -> None:
    slug = "acme"
    kr = _keyring(tmp_path)
    bb = _bb(tmp_path, slug)
    ev = tmp_path / "evidence"
    (ev / "a").mkdir(parents=True)
    (ev / "a" / "response.body").write_bytes(b"cred=SECRET")

    first = erase_engagement_evidence(slug, bb=bb, keyring=kr, evidence_root=ev)
    assert first.sealed_files == 1 and first.receipt.shredded

    second = erase_engagement_evidence(slug, bb=bb, keyring=kr, evidence_root=ev)
    assert second.sealed_files == 0                            # already sealed -> nothing new
    assert second.already_sealed == 1
    assert second.receipt.shredded is False                   # no key left to destroy
    ok, why = verify_spine_chain(bb, slug, build_spine_chain(bb, slug))
    assert ok, why
    bb.close()


# ---- NEGATIVE CONTROL: the destructive CLI fails closed ------------------------------------


def test_cli_default_denies_destructive_erasure_without_yes(capsys) -> None:
    rc = evidence_erasure.main(["--engagement", "acme"])
    assert rc == 2                                            # default-deny (no --yes)
    assert "default-deny" in capsys.readouterr().err.lower()
