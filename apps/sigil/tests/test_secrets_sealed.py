"""Tests for the SecretStore TPM-sealed tier (audit G1).

When the owner vault is provisioned, secrets (the LLM API key, service passwords) are stored AEAD-sealed
at rest instead of the plaintext sigil.env — closing the audit's plaintext-secret gap. When the vault is
NOT provisioned (and no keyring), behaviour is the unchanged legacy envfile path (non-bricking).
"""
from __future__ import annotations

from pathlib import Path

from vigil_core import is_sealed
from vigil_core.kek import TpmResult


def make_fake_tpm(*, unavailable=False):
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


def _store_with_vault(tmp_path, monkeypatch, *, provision=True, unavailable=False):
    from sigil.platform import secrets as secmod
    from sigil.platform import vault as vaultmod
    monkeypatch.setattr(secmod, "_SEALED_FILE", tmp_path / "secrets.sealed")
    v = vaultmod.Vault(tmp_path / "vault", make_fake_tpm(unavailable=unavailable))
    if provision:
        v.provision()
    monkeypatch.setattr(vaultmod, "_owner_vault", v)
    s = secmod.SecretStore()
    s._kr = None  # force: no OS keyring in this test → exercise the sealed/envfile tiers
    return s, secmod


def test_provisioned_vault_seals_secrets_at_rest(tmp_path, monkeypatch):
    s, _ = _store_with_vault(tmp_path, monkeypatch, provision=True)
    assert s.backend == "sealed"
    assert s.set("ANTHROPIC_API_KEY", "sk-ant-TOPSECRET") == "sealed"
    blob = (tmp_path / "secrets.sealed").read_bytes()
    assert is_sealed(blob)                                  # ciphertext on disk
    assert b"sk-ant-TOPSECRET" not in blob                  # the key never rests in plaintext
    assert s.get("ANTHROPIC_API_KEY") == "sk-ant-TOPSECRET"


def test_sealed_store_round_trips_across_instances(tmp_path, monkeypatch):
    s, secmod = _store_with_vault(tmp_path, monkeypatch, provision=True)
    s.set("SVC_PASSWORD", "hunter2")
    s.set("OTHER", "v2")
    s2 = secmod.SecretStore()
    s2._kr = None
    assert s2.get("SVC_PASSWORD") == "hunter2"
    assert s2.get("OTHER") == "v2"
    assert s2.get("MISSING") in (None,)                     # absent key → None (from sealed + env)


def test_locked_tpm_surfaces_no_at_rest_secret_but_does_not_crash(tmp_path, monkeypatch):
    # provision with a working TPM, write a secret, then the TPM goes away
    s, secmod = _store_with_vault(tmp_path, monkeypatch, provision=True)
    s.set("K", "sealed-value")
    monkeypatch.delenv("K", raising=False)  # drop the live process-env copy → test the AT-REST path only
    from sigil.platform import vault as vaultmod
    dead = vaultmod.Vault(tmp_path / "vault", make_fake_tpm(unavailable=True))
    monkeypatch.setattr(vaultmod, "_owner_vault", dead)
    s2 = secmod.SecretStore()
    s2._kr = None
    # the sealed store cannot be opened (TPM locked) ⇒ the at-rest secret is fail-closed, NOT leaked as
    # plaintext, and the read does not crash.
    assert s2.get("K") is None


def test_unprovisioned_vault_is_legacy_envfile(tmp_path, monkeypatch):
    s, _ = _store_with_vault(tmp_path, monkeypatch, provision=False)
    assert s.backend == "envfile"                            # unchanged legacy behaviour, non-bricking
