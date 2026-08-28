"""vigil_core.vault — Vault-method fail-closed negative controls (audit F-11).

``test_sealing.py`` proves the low-level ``seal``/``unseal`` PRIMITIVE fails closed (wrong KEK / wrong
context / bitflip / truncation / bad magic). ``test_vault_rotate_kek.py`` exercises the Vault methods on
the POSITIVE (round-trip through rotation) path. Neither pins the Vault METHOD boundary's fail-closed
raise branches — the ones that turn a primitive ``SealError`` into a caller-visible ``VaultLocked`` and
that refuse when the vault is not provisioned. This file is those negative controls: each proves a Vault
method RAISES (never returns an unauthenticated/plaintext value) on the failure it is meant to catch, with
a positive round-trip control so the suite is not simply always-raising. Pure ``vigil_core``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_core.kek import TpmResult
from vigil_core.sealing import is_sealed
from vigil_core.vault import Vault, VaultLocked

CTX = b"vigil/test.secret"
OTHER_CTX = b"vigil/other.purpose"


def _make_fake_tpm(*, unavailable=False):
    """A deterministic fake tpm2-tools seam (mirrors test_vault_rotate_kek): seal encodes the KEK into the
    private blob, unseal returns it. The real tpm2 path activates only on a provisioned host."""
    def run(argv, stdin):
        if unavailable:
            return TpmResult(127, b"")
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary"); return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub")
            Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b"")); return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):]); return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            return TpmResult(0, Path(flag("-c")).read_bytes())
        return TpmResult(1, b"")
    return run


def _provisioned(tmp_path, name="vault") -> Vault:
    v = Vault(tmp_path / name, _make_fake_tpm())
    v.provision()
    return v


def _unprovisioned(tmp_path, name="vault") -> Vault:
    return Vault(tmp_path / name, _make_fake_tpm())


# ── unprovisioned ⇒ refuse (no plaintext fallback for a must-seal secret) ───────────────────────────────

def test_seal_secret_refuses_when_not_provisioned(tmp_path):
    v = _unprovisioned(tmp_path)
    assert v.enabled() is False
    with pytest.raises(VaultLocked):
        v.seal_secret(b"a-recoverable-totp-seed", context=CTX)


def test_unseal_secret_refuses_when_not_provisioned(tmp_path):
    v = _unprovisioned(tmp_path)
    with pytest.raises(VaultLocked):
        v.unseal_secret(b"anything", context=CTX)


# ── positive round-trip control (so the negatives above are not just an always-raising vault) ───────────

def test_seal_then_unseal_round_trips_under_the_same_context(tmp_path):
    v = _provisioned(tmp_path)
    blob = v.seal_secret(b"JBSWY3DPEHPK3PXP", context=CTX)
    assert is_sealed(blob)                                   # it is genuinely sealed, not passed through
    assert blob != b"JBSWY3DPEHPK3PXP"
    assert v.unseal_secret(blob, context=CTX) == b"JBSWY3DPEHPK3PXP"


# ── tamper / wrong-context ⇒ VaultLocked (the SealError → VaultLocked wrap must hold) ────────────────────

def test_unseal_secret_fails_closed_on_a_tampered_blob(tmp_path):
    v = _provisioned(tmp_path)
    blob = bytearray(v.seal_secret(b"owner-secret-bytes", context=CTX))
    blob[len(blob) // 2] ^= 0x01                             # flip one ciphertext/tag byte
    with pytest.raises(VaultLocked):                        # NOT a raw SealError, NOT a garbage return
        v.unseal_secret(bytes(blob), context=CTX)


def test_unseal_secret_fails_closed_under_the_wrong_context(tmp_path):
    v = _provisioned(tmp_path)
    blob = v.seal_secret(b"context-bound-secret", context=CTX)
    with pytest.raises(VaultLocked):                        # AAD binding: a blob is not openable out of purpose
        v.unseal_secret(blob, context=OTHER_CTX)


# ── read_*_secret on a sealed-but-unopenable file ⇒ VaultLocked (never a silent None/garbage) ───────────

def test_read_text_secret_fails_closed_on_a_corrupted_sealed_file(tmp_path):
    v = _provisioned(tmp_path)
    p = tmp_path / "secret.key"
    v.write_text_secret(p, "c2VjcmV0LWtleQ==", context=CTX)
    raw = bytearray(p.read_bytes())
    assert is_sealed(bytes(raw))                             # write sealed it (vault enabled)
    raw[len(raw) // 2] ^= 0x01                               # corrupt the sealed file at rest
    p.write_bytes(bytes(raw))
    with pytest.raises(VaultLocked):
        v.read_text_secret(p, context=CTX)


def test_read_bytes_secret_fails_closed_on_the_wrong_context(tmp_path):
    v = _provisioned(tmp_path)
    p = tmp_path / "warden.seed"
    v.write_bytes_secret(p, b"\x00" * 32, context=CTX)
    with pytest.raises(VaultLocked):
        v.read_bytes_secret(p, context=OTHER_CTX)           # right file, wrong purpose ⇒ refuse


# ── write_text_secret must actually SEAL when enabled (mutation killer: forgetting to seal) ─────────────

def test_write_text_secret_lands_sealed_when_the_vault_is_enabled(tmp_path):
    v = _provisioned(tmp_path)
    p = tmp_path / "api.key"
    v.write_text_secret(p, "sk-plaintext-value", context=CTX)
    on_disk = p.read_bytes()
    assert is_sealed(on_disk), "an enabled vault must seal at rest, never write the plaintext"
    assert b"sk-plaintext-value" not in on_disk
    assert v.read_text_secret(p, context=CTX) == "sk-plaintext-value"   # and it round-trips back


# ── seal_file status machine (absent / disabled / sealed / already-sealed) ──────────────────────────────

def test_seal_file_status_transitions(tmp_path):
    # each leg gets its OWN vault dir — a provisioned vault stays provisioned on disk, so sharing one dir
    # would leak "enabled" state across the legs.
    # absent
    assert _provisioned(tmp_path, "v1").seal_file(tmp_path / "nope.key", context=CTX) == "absent"
    # disabled: vault off ⇒ the plaintext file is LEFT plaintext (honest status, not a false "sealed")
    off = _unprovisioned(tmp_path, "v2")
    pf = tmp_path / "plain.key"
    pf.write_bytes(b"raw-key-material")
    assert off.seal_file(pf, context=CTX) == "disabled"
    assert pf.read_bytes() == b"raw-key-material"            # untouched
    # sealed then already-sealed (idempotent) on a provisioned vault
    v = _provisioned(tmp_path, "v3")
    p2 = tmp_path / "warden.key"
    p2.write_bytes(b"32-bytes-of-seed-material-here!!")
    assert v.seal_file(p2, context=CTX) == "sealed"
    assert is_sealed(p2.read_bytes())
    assert v.seal_file(p2, context=CTX) == "already-sealed"
    assert v.read_bytes_secret(p2, context=CTX) == b"32-bytes-of-seed-material-here!!"
