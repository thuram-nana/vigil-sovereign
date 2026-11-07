"""AWS-1 — the KEK custody backend selection (sigil.config.kek_backend) wired into owner_vault().

Proves: the default is the byte-identical TPM backend; VIGIL_KEK_BACKEND=kms selects the AWS-KMS backend
(fail-closed if the key id is unset); the region falls back to the standard AWS_* vars; an unknown backend
value fails SAFE to tpm (a typo can never silently disable sealing or pick a surprise backend).
"""
from __future__ import annotations

import pytest

from sigil import config
from sigil.platform import vault as _vault


@pytest.fixture(autouse=True)
def _reset_owner_vault():
    _vault.reset_owner_vault_for_test()      # drop the process-wide cache before AND after each test
    yield
    _vault.reset_owner_vault_for_test()


def test_config_kek_backend_defaults_tpm_and_reads_env(monkeypatch):
    monkeypatch.delenv("VIGIL_KEK_BACKEND", raising=False)
    assert config.kek_backend() == "tpm"
    monkeypatch.setenv("VIGIL_KEK_BACKEND", "kms")
    assert config.kek_backend() == "kms"
    monkeypatch.setenv("VIGIL_KEK_BACKEND", "KMS")          # case-insensitive
    assert config.kek_backend() == "kms"
    monkeypatch.setenv("VIGIL_KEK_BACKEND", "nonsense")     # unknown -> fail-safe to tpm
    assert config.kek_backend() == "tpm"


def test_config_region_falls_back_to_standard_aws_vars(monkeypatch):
    for v in ("VIGIL_AWS_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(v, raising=False)
    assert config.aws_region() == ""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-2")
    assert config.aws_region() == "us-east-2"
    monkeypatch.setenv("VIGIL_AWS_REGION", "eu-west-1")     # the explicit VIGIL var wins
    assert config.aws_region() == "eu-west-1"


def test_owner_vault_default_backend_is_tpm(monkeypatch):
    monkeypatch.delenv("VIGIL_KEK_BACKEND", raising=False)
    from vigil_core.kek_backends import TpmKekBackend
    assert isinstance(_vault.owner_vault()._backend, TpmKekBackend)


def test_owner_vault_selects_kms_when_configured(monkeypatch):
    monkeypatch.setenv("VIGIL_KEK_BACKEND", "kms")
    monkeypatch.setenv("VIGIL_KMS_KEY_ID", "alias/vigil-owner")
    monkeypatch.setenv("VIGIL_AWS_REGION", "eu-west-1")
    from vigil_core.kek_backends import KmsKekBackend
    b = _vault.owner_vault()._backend
    assert isinstance(b, KmsKekBackend)
    assert "alias/vigil-owner" in b.label() and "eu-west-1" in b.label()


def test_owner_vault_kms_without_key_fails_closed(monkeypatch):
    monkeypatch.setenv("VIGIL_KEK_BACKEND", "kms")
    monkeypatch.delenv("VIGIL_KMS_KEY_ID", raising=False)
    monkeypatch.setenv("VIGIL_AWS_REGION", "eu-west-1")
    from vigil_core.kek import KekError
    with pytest.raises(KekError):               # a KMS backend with no key never silently degrades
        _vault.owner_vault()
