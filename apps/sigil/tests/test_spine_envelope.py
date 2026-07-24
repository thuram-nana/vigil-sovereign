"""G1 slice-4 — FIELD-LEVEL spine payload envelope primitive.

Seals only the content-field VALUES, leaving all metadata (incl. the keyless governance fields
decision/tier/usage/promotion_key/signal and the audit labels subject/summary) plaintext — so a whole
payload round-trips with content sealed and metadata readable without the key. Covers: the content/
metadata split, the mixed agent + archivist records that broke the whole-payload approach, the
(scope, seq, field) AAD transplant defence, opt-in passthrough, fail-closed, and DEK custody.
"""
from __future__ import annotations

import base64
import json
import os

import pytest

from sigil import config
from sigil.spine import envelope as env
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault

DEK = os.urandom(32)
CONTENT = {"text": "a private memory", "project": "proj", "session_id": "s1"}
# the agent action record that BROKE whole-payload (BLOCK-1): content + keyless budget/audit metadata
AGENT = {"agent": "SENTINEL", "tier": "A1", "decision": "auto", "governor": "within auto bar",
         "usage": {"input_tokens": 400000, "output_tokens": 200000, "cost_usd": 7.0},
         "subject": "a finding", "body": "the sensitive finding body"}
# the archivist record that BROKE whole-payload (BLOCK-2): verbatim quote + keyless promotion_key
ARCHIVIST = {"quote": "a verbatim secret span", "promotion_key": "k-1", "grounding": "grounded"}
SIGNAL = {"signal": "governor.killswitch", "state": "engaged"}


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


def _seal(payload, *, seq=1, scope="sigil", dek=DEK):
    return env.seal_payload(dek, payload, scope=scope, seq=seq)


# --- content/metadata split ----------------------------------------------------------------------

def test_seals_content_fields_leaves_metadata_plaintext():
    stored = _seal(CONTENT)
    assert env._is_field_envelope(stored["text"])          # content field sealed
    assert stored["project"] == "proj" and stored["session_id"] == "s1"   # metadata plaintext
    assert "private memory" not in json.dumps(stored)
    assert env.open_payload(DEK, stored, scope="sigil", seq=1) == CONTENT


def test_agent_record_keeps_budget_audit_metadata_plaintext():
    # BLOCK-1 solved: an agent action record's decision/tier/usage (read KEYLESS by the budget cap +
    # self-audit) stay plaintext; only its content `body` is sealed.
    stored = _seal(AGENT, seq=5)
    assert stored["decision"] == "auto" and stored["tier"] == "A1"
    assert stored["usage"] == {"input_tokens": 400000, "output_tokens": 200000, "cost_usd": 7.0}
    assert stored["subject"] == "a finding"                # audit "what" label stays plaintext
    assert env._is_field_envelope(stored["body"])          # the finding body IS sealed
    assert env.open_payload(DEK, stored, scope="sigil", seq=5) == AGENT


def test_archivist_record_seals_quote_keeps_promotion_key_plaintext():
    # BLOCK-2 solved: the verbatim quote is sealed; the keyless promotion_key/grounding stay plaintext.
    stored = _seal(ARCHIVIST, seq=9)
    assert env._is_field_envelope(stored["quote"])
    assert stored["promotion_key"] == "k-1" and stored["grounding"] == "grounded"
    assert "verbatim secret" not in json.dumps(stored)
    assert env.open_payload(DEK, stored, scope="sigil", seq=9) == ARCHIVIST


def test_signal_record_has_no_content_field_passthrough():
    assert env.has_content(SIGNAL) is False
    assert _seal(SIGNAL) == SIGNAL                          # nothing to seal → plaintext, keyless-foldable


def test_tool_input_is_sealed_whole():
    # BLOCK-1 (leak): a tool_call's raw args (file contents / Bash commands) must be sealed, not left
    # plaintext like the whole-payload draft did. The nested value is sealed WHOLE (no partial leak).
    tc = {"tool": "Write", "tool_input": {"file_path": "/x", "content": "PRIVKEY-----BEGIN"},
          "tool_use_id": "abc"}
    stored = _seal(tc, seq=2)
    assert env._is_field_envelope(stored["tool_input"]) and "PRIVKEY" not in json.dumps(stored)
    assert stored["tool"] == "Write" and stored["tool_use_id"] == "abc"        # metadata plaintext
    assert env.open_payload(DEK, stored, scope="sigil", seq=2) == tc


def test_perception_screen_content_fields_are_sealed():
    # BLOCK-2 (leak): the raw screen OCR / VLM reading fields are sealed; `summary`/`subject` labels stay
    # plaintext for the keyless audit (the minter no longer puts raw OCR in `summary`).
    perc = {"signal": "perception", "subject": "observe", "summary": "screen perceived (40 chars OCR, 1 grounded)",
            "text": "master password hunter2", "captured_text": "master password hunter2",
            "vision_reading_advisory": "the screen shows the master password hunter2",
            "grounded_objects": [{"mention": "hunter2", "quote": "hunter2"}], "advisory_leads": ["hunter2"],
            "frame_sha256": "aa"}
    stored = _seal(perc, seq=4)
    for f in ("text", "captured_text", "vision_reading_advisory", "grounded_objects", "advisory_leads"):
        assert env._is_field_envelope(stored[f]), f
    assert "hunter2" not in json.dumps(stored)
    assert stored["signal"] == "perception" and stored["summary"].startswith("screen perceived")
    assert env.open_payload(DEK, stored, scope="sigil", seq=4) == perc


def test_has_content():
    assert env.has_content(CONTENT) is True and env.has_content(AGENT) is True
    assert env.has_content(ARCHIVIST) is True
    assert env.has_content(SIGNAL) is False and env.has_content({"decision": "auto"}) is False


# --- AAD binds (scope, seq, field) — transplant fails-closed --------------------------------------

def test_aad_binds_field_no_swap_between_fields():
    p = {"text": "AAA", "body": "BBB"}
    stored = _seal(p, seq=3)
    swapped = {"text": stored["body"], "body": stored["text"]}   # swap the two sealed field values
    with pytest.raises(env.SpinePayloadLocked):
        env.open_payload(DEK, swapped, scope="sigil", seq=3)     # field name mismatch → InvalidTag


def test_aad_binds_seq_and_scope():
    stored = _seal(CONTENT, seq=5)
    with pytest.raises(env.SpinePayloadLocked):
        env.open_payload(DEK, stored, scope="sigil", seq=10)     # wrong seq
    with pytest.raises(env.SpinePayloadLocked):
        env.open_payload(DEK, stored, scope="other", seq=5)      # wrong scope


# --- passthrough + fail-closed -------------------------------------------------------------------

def test_no_dek_is_plaintext_passthrough():
    assert _seal(CONTENT, dek=None) == CONTENT
    assert env.open_payload(None, CONTENT, scope="sigil", seq=1) == CONTENT   # legacy plaintext


def test_open_sealed_without_dek_fails_closed():
    with pytest.raises(env.SpinePayloadLocked):
        env.open_payload(None, _seal(CONTENT), scope="sigil", seq=1)


def test_wrong_dek_and_corrupt_fail_closed():
    with pytest.raises(env.SpinePayloadLocked):
        env.open_payload(os.urandom(32), _seal(CONTENT), scope="sigil", seq=1)
    corrupt = _seal(CONTENT)
    corrupt = {**corrupt, "text": {**corrupt["text"], "b": "!!bad!!"}}
    with pytest.raises(env.SpinePayloadLocked):
        env.open_payload(DEK, corrupt, scope="sigil", seq=1)


# --- DEK custody ---------------------------------------------------------------------------------

def test_dek_none_when_vault_disabled(tmp_path):
    assert env.load_or_create_dek(Vault(tmp_path / "vault", make_fake_tpm()), create=True) is None


def test_dek_mint_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SPINE_DEK_PATH", tmp_path / "spine.dek")
    v = Vault(tmp_path / "vault", make_fake_tpm()); v.provision()
    dek1 = env.load_or_create_dek(v, create=True)
    assert isinstance(dek1, bytes) and len(dek1) == 32
    dek2 = env.load_or_create_dek(Vault(tmp_path / "vault", make_fake_tpm()), create=True)
    assert dek2 == dek1                                     # never re-minted (no orphaned envelopes)
    assert env.open_payload(dek2, _seal(CONTENT, dek=dek1), scope="sigil", seq=1) == CONTENT
