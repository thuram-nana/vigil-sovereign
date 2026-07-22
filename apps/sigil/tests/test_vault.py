"""Tests for sigil.platform.vault — at-rest sealing of the trust root (audit G1).

Proves the vault is non-bricking and correct: legacy (unprovisioned) reads/writes are unchanged
plaintext; after provisioning, writes seal + reads unseal; a legacy plaintext key MIGRATES
non-destructively (round-trip verified before the plaintext is replaced); a locked TPM fails CLOSED
(VaultLocked, never plaintext); context binding holds; and the owner-key accessors (identity +
checkpoint) round-trip in BOTH modes.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_core import is_sealed
from vigil_core.kek import TpmResult


def make_fake_tpm(*, unavailable=False):
    """A fake tpm2-tools simulating seal/unseal via the on-disk blob files (see test_kek)."""
    def run(argv, stdin):
        if unavailable:
            return TpmResult(127, b"")
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary")
            return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub")
            Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b""))
            return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):])
            return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            return TpmResult(0, Path(flag("-c")).read_bytes())
        return TpmResult(1, b"")

    return run


CTX = b"sigil/owner.priv"


def _vault(tmp_path, **kw):
    from sigil.platform.vault import Vault
    return Vault(tmp_path / "vault", make_fake_tpm(**kw))


# --- legacy (unprovisioned) mode: byte-for-byte today's behaviour ----------------------------------


def test_legacy_mode_is_plaintext_unchanged(tmp_path):
    v = _vault(tmp_path)
    assert v.enabled() is False
    assert "UNSEALED" in v.status()
    kf = tmp_path / "owner.priv"
    v.write_text_secret(kf, "PRIVKEYB64", context=CTX)
    assert kf.read_text() == "PRIVKEYB64"          # plaintext, exactly as before
    assert is_sealed(kf.read_bytes()) is False
    assert v.read_text_secret(kf, context=CTX) == "PRIVKEYB64"
    assert (kf.stat().st_mode & 0o777) == 0o600


def test_read_missing_returns_none(tmp_path):
    assert _vault(tmp_path).read_text_secret(tmp_path / "nope", context=CTX) is None


# --- sealed mode -----------------------------------------------------------------------------------


def test_provision_then_seal_and_unseal(tmp_path):
    v = _vault(tmp_path)
    v.provision()
    assert v.enabled() is True and "sealed" in v.status()
    kf = tmp_path / "owner.priv"
    v.write_text_secret(kf, "SECRET-PRIV", context=CTX)
    assert is_sealed(kf.read_bytes()) is True          # on disk it is ciphertext, not the key
    assert kf.read_bytes() != b"SECRET-PRIV"
    assert v.read_text_secret(kf, context=CTX) == "SECRET-PRIV"


def test_non_destructive_migration_of_legacy_plaintext(tmp_path):
    v = _vault(tmp_path)
    kf = tmp_path / "owner.priv"
    v.write_text_secret(kf, "LEGACY-PRIV", context=CTX)   # written plaintext (legacy)
    assert is_sealed(kf.read_bytes()) is False
    v.provision()                                          # operator enables sealing
    # first read migrates in place, non-destructively
    assert v.read_text_secret(kf, context=CTX) == "LEGACY-PRIV"
    assert is_sealed(kf.read_bytes()) is True              # now sealed
    # and it still opens to the exact original on every subsequent read
    assert v.read_text_secret(kf, context=CTX) == "LEGACY-PRIV"


def test_locked_tpm_fails_closed_not_plaintext(tmp_path):
    from sigil.platform.vault import Vault, VaultLocked
    # provision with a working TPM, then simulate the TPM going away
    good = Vault(tmp_path / "vault", make_fake_tpm())
    good.provision()
    kf = tmp_path / "owner.priv"
    good.write_text_secret(kf, "PRIV", context=CTX)
    dead = Vault(tmp_path / "vault", make_fake_tpm(unavailable=True))
    assert dead.enabled() is True                         # blobs exist ⇒ sealed mode
    with pytest.raises(VaultLocked):                      # ...but cannot unseal ⇒ fail-closed
        dead.read_text_secret(kf, context=CTX)


def test_context_binding_prevents_cross_open(tmp_path):
    from sigil.platform.vault import VaultLocked
    v = _vault(tmp_path)
    v.provision()
    kf = tmp_path / "k"
    v.write_text_secret(kf, "OWNER", context=b"owner")
    with pytest.raises(VaultLocked):                      # a blob sealed as 'owner' can't open as 'operator'
        v.read_text_secret(kf, context=b"operator")


# --- owner-key wiring (identity + checkpoint) round-trips in BOTH modes -----------------------------


def test_owner_key_wiring_legacy_and_sealed(tmp_path, monkeypatch):
    from sigil.governor import identity
    from sigil.platform import vault as vaultmod

    monkeypatch.setattr(identity, "_PRIV", tmp_path / "owner.priv")
    monkeypatch.setattr(identity, "_PUB", tmp_path / "owner.pub")
    monkeypatch.setattr(identity, "KEYS_DIR", tmp_path)

    # LEGACY: default owner_vault (real runner, TPM unavailable here) ⇒ plaintext, unchanged round-trip
    vaultmod.reset_owner_vault_for_test()
    monkeypatch.setattr(vaultmod, "_owner_vault", vaultmod.Vault(tmp_path / "vault-legacy",
                                                                 make_fake_tpm(unavailable=True)))
    kp = identity.ensure_owner_keypair()
    assert identity.owner_keypair() == kp
    assert is_sealed((tmp_path / "owner.priv").read_bytes()) is False

    # SEALED: swap in a provisioned fake-TPM vault; regenerate ⇒ the private key is sealed at rest
    (tmp_path / "owner.priv").unlink()
    (tmp_path / "owner.pub").unlink()
    sealed_vault = vaultmod.Vault(tmp_path / "vault-sealed", make_fake_tpm())
    sealed_vault.provision()
    monkeypatch.setattr(vaultmod, "_owner_vault", sealed_vault)
    kp2 = identity.ensure_owner_keypair()
    assert is_sealed((tmp_path / "owner.priv").read_bytes()) is True     # sealed on disk
    assert identity.owner_keypair() == kp2                              # unseals to the same keypair
