"""Tests for at-rest sealing of the operator keypair (audit G1, offense side).

When a provisioned Vault is supplied, load_or_create_operator_keypair seals the keypair file at rest;
without a vault (or unprovisioned) it is plaintext (unchanged). A locked TPM fails CLOSED (VaultLocked)
rather than silently minting a new divergent operator identity.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_core import is_sealed
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault, VaultLocked
from vigil_integration.attestation.identity import load_or_create_operator_keypair


def make_fake_tpm(*, unavailable=False):
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


def test_no_vault_is_plaintext_and_round_trips(tmp_path):
    kf = tmp_path / "operator.key"
    kp = load_or_create_operator_keypair(path=str(kf))
    assert is_sealed(kf.read_bytes()) is False           # legacy plaintext JSON, unchanged
    kp2 = load_or_create_operator_keypair(path=str(kf))
    assert kp2 == kp                                     # same persisted identity


def test_provisioned_vault_seals_operator_key(tmp_path):
    kf = tmp_path / "operator.key"
    v = Vault(tmp_path / "vault", make_fake_tpm())
    v.provision()
    kp = load_or_create_operator_keypair(path=str(kf), vault=v)
    blob = kf.read_bytes()
    assert is_sealed(blob) is True                       # sealed at rest
    assert kp.private_key_b64.encode() not in blob       # private key never plaintext on disk
    # a fresh load unseals to the SAME identity (no divergent regeneration)
    kp2 = load_or_create_operator_keypair(path=str(kf), vault=Vault(tmp_path / "vault", make_fake_tpm()))
    assert kp2 == kp


def test_locked_tpm_fails_closed_no_new_identity(tmp_path):
    kf = tmp_path / "operator.key"
    good = Vault(tmp_path / "vault", make_fake_tpm())
    good.provision()
    load_or_create_operator_keypair(path=str(kf), vault=good)   # sealed
    dead = Vault(tmp_path / "vault", make_fake_tpm(unavailable=True))
    with pytest.raises(VaultLocked):                            # can't unseal ⇒ fail-closed, not a new key
        load_or_create_operator_keypair(path=str(kf), vault=dead)
