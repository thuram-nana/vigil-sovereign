"""G1 slice-4 — FIELD-LEVEL encryption wired into the store (end-to-end, vault ON).

The invariant: a record's CONTENT fields are ciphertext on disk, but its metadata (incl. the keyless
budget/audit/snapshot fields) is plaintext and the hash-chain `cert_digest` is over the stored form — so
`store.verify()` passes WITHOUT the key, the keyless governance folds still read their metadata, and only
`store.decrypted(r)` needs the key. Proves both prior BLOCKs are solved end-to-end.
"""
from __future__ import annotations

import json

import pytest

from sigil import config
from sigil.spine import envelope as env
from sigil.spine.store import SpineStore
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault, VaultLocked


def make_fake_tpm(*, unavailable=False):
    from pathlib import Path

    def run(argv, stdin):
        if unavailable:
            return TpmResult(127, b"")
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary"); return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub"); Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b""))
            return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):]); return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            return TpmResult(0, Path(flag("-c")).read_bytes())
        return TpmResult(1, b"")
    return run


@pytest.fixture
def sealed(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SPINE_DEK_PATH", tmp_path / "spine.dek")
    v = Vault(tmp_path / "vault", make_fake_tpm()); v.provision()
    monkeypatch.setattr("sigil.platform.vault.owner_vault", lambda: v)
    return tmp_path


def _raw(sp, seq):
    for line in open(sp, encoding="utf-8"):
        d = json.loads(line)
        if d["seq"] == seq:
            return d["payload"]
    raise AssertionError(f"seq {seq} not found")


def test_content_sealed_metadata_plaintext_and_decrypts(sealed):
    sp = str(sealed / "spine.jsonl")
    s = SpineStore(sp)
    seq = s.append(kind="message", source="c", actor="u",
                   payload={"text": "a private memory", "project": "p", "session_id": "s1"})
    stored = _raw(sp, seq)
    assert env._is_field_envelope(stored["text"])          # content sealed on disk
    assert stored["project"] == "p" and stored["session_id"] == "s1"   # metadata plaintext
    assert "private memory" not in json.dumps(stored)
    assert SpineStore(sp).decrypted(SpineStore(sp).get(seq)).payload == {
        "text": "a private memory", "project": "p", "session_id": "s1"}


def test_agent_usage_stays_plaintext_for_the_keyless_budget_fold(sealed):
    # BLOCK-1 end-to-end: an agent action record's decision/tier/usage (the budget cap + self-audit read
    # them KEYLESS) are plaintext on disk; only its content body is sealed.
    sp = str(sealed / "spine.jsonl")
    seq = SpineStore(sp).append(kind="finding", source="agent", actor="SENTINEL",
                                payload={"decision": "auto", "tier": "A1", "subject": "a finding",
                                         "usage": {"cost_usd": 7.0, "output_tokens": 200000},
                                         "body": "the sensitive finding body"})
    stored = _raw(sp, seq)
    assert stored["decision"] == "auto" and stored["tier"] == "A1"       # budget/audit read these keyless
    assert stored["usage"] == {"cost_usd": 7.0, "output_tokens": 200000}
    assert stored["subject"] == "a finding"
    assert env._is_field_envelope(stored["body"])                       # content sealed
    assert "sensitive finding body" not in json.dumps(stored)


def test_archivist_quote_sealed_promotion_key_plaintext(sealed):
    # BLOCK-2 end-to-end: the verbatim quote is sealed; the keyless promotion_key stays plaintext.
    sp = str(sealed / "spine.jsonl")
    seq = SpineStore(sp).append(kind="finding", source="archivist", actor="archivist",
                                payload={"quote": "a verbatim secret", "promotion_key": "k-1",
                                         "grounding": "grounded"})
    stored = _raw(sp, seq)
    assert env._is_field_envelope(stored["quote"]) and "verbatim secret" not in json.dumps(stored)
    assert stored["promotion_key"] == "k-1" and stored["grounding"] == "grounded"


def test_keyless_verify_over_ciphertext(sealed, monkeypatch):
    sp = str(sealed / "spine.jsonl")
    SpineStore(sp).append(kind="message", source="c", actor="u", payload={"text": "secret"})
    dead = Vault(sealed / "vault", make_fake_tpm(unavailable=True))
    monkeypatch.setattr("sigil.platform.vault.owner_vault", lambda: dead)
    keyless = SpineStore(sp)
    assert keyless.verify()[0] is True                                  # chain verifies WITHOUT the key
    with pytest.raises((VaultLocked, env.SpinePayloadLocked)):
        keyless.decrypted(keyless.get(0))                               # reading content fails-closed


def test_governance_append_never_blocked_by_locked_vault(sealed, monkeypatch):
    sp = str(sealed / "spine.jsonl")
    dead = Vault(sealed / "vault", make_fake_tpm(unavailable=True))
    monkeypatch.setattr("sigil.platform.vault.owner_vault", lambda: dead)
    s = SpineStore(sp)
    s.append(kind="event", source="governor", actor="owner",
             payload={"signal": "governor.killswitch", "state": "engaged"})   # no content field → not blocked
    assert s.verify()[0] is True
    with pytest.raises(VaultLocked):
        s.append(kind="message", source="c", actor="u", payload={"text": "needs the DEK"})   # content → fail-closed


def test_consolidation_serve_path_returns_plaintext(sealed):
    # fix-introduced-defect regression: the 3 recall tools + nightly brief consume `iter_current`, which
    # reads the sealed quote/statement — it MUST decrypt, or they serve the ciphertext envelope as the fact.
    from sigil.consolidate.grounding import ground_tag
    from sigil.consolidate.queries import open_threads
    sp = str(sealed / "spine.jsonl")
    SpineStore(sp).append(kind="decision", source="archivist", actor="archivist",
                          payload={"quote": "the owner decided X", "statement": "owner chose X",
                                   "grounding": ground_tag(1), "promotion_key": "k1", "source_seqs": [0],
                                   "verified_seqs": [0], "subject": "a decision", "alpha": 2, "beta": 1})
    assert env._is_field_envelope(_raw(sp, 0)["quote"])          # sealed on disk
    out = open_threads(SpineStore(sp))
    assert out and out[0]["text"] == "the owner decided X"       # served PLAINTEXT, not the envelope dict
    assert out[0]["summary"] == "owner chose X"


def test_mixed_spine(tmp_path, monkeypatch):
    sp = str(tmp_path / "spine.jsonl")
    monkeypatch.setattr(config, "SPINE_DEK_PATH", tmp_path / "spine.dek")
    off = Vault(tmp_path / "vault", make_fake_tpm())
    monkeypatch.setattr("sigil.platform.vault.owner_vault", lambda: off)
    SpineStore(sp).append(kind="message", source="c", actor="u", payload={"text": "legacy plaintext"})
    assert not env._is_field_envelope(_raw(sp, 0)["text"])              # plaintext (vault off)
    on = Vault(tmp_path / "vault", make_fake_tpm()); on.provision()
    monkeypatch.setattr("sigil.platform.vault.owner_vault", lambda: on)
    SpineStore(sp).append(kind="message", source="c", actor="u", payload={"text": "now sealed"})
    assert env._is_field_envelope(_raw(sp, 1)["text"])                  # sealed
    s = SpineStore(sp)
    assert s.verify()[0] is True
    assert s.decrypted(s.get(0)).payload == {"text": "legacy plaintext"}
    assert s.decrypted(s.get(1)).payload == {"text": "now sealed"}
