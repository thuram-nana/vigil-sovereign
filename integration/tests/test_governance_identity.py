"""S7 — the STABLE offense governance identity (`live.governance_identity`), the anchor-1 signer.

Before S7 the governance/authority key was minted fresh per run, so an owner delegation (S4,
OFFENSE_GOVERNANCE_ROLE) for it would have to be re-issued every run. This proves it is now STABLE across
reloads (one delegation covers it durably), sealed at rest under the offense vault, fail-closed on a locked
TPM, and its AEAD context is DISTINCT from the operator and spine keys. Framework-free (pure keystore wrapper).

Run: PYTHONPATH=integration:gateway pytest integration/tests/test_governance_identity.py -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_core import is_sealed
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault, VaultLocked
from vigil_integration.attestation.identity import OPERATOR_KEYPAIR_CONTEXT
from vigil_integration.live.governance_identity import (
    GOVERNANCE_KEYPAIR_CONTEXT,
    load_or_create_governance_keypair,
)
from vigil_integration.live.spine_identity import SPINE_KEYPAIR_CONTEXT


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


def test_governance_key_is_stable_across_reloads(tmp_path):
    kf = tmp_path / "offense-governance.key"
    kp = load_or_create_governance_keypair(path=str(kf))
    kp2 = load_or_create_governance_keypair(path=str(kf))
    assert kp2 == kp                         # one owner delegation can cover it across runs
    assert is_sealed(kf.read_bytes()) is False


def test_governance_key_seals_at_rest_and_reloads_same(tmp_path):
    kf = tmp_path / "offense-governance.key"
    v = Vault(tmp_path / "vault", make_fake_tpm())
    v.provision()
    kp = load_or_create_governance_keypair(path=str(kf), vault=v)
    blob = kf.read_bytes()
    assert is_sealed(blob) is True
    assert kp.private_key_b64.encode() not in blob
    kp2 = load_or_create_governance_keypair(path=str(kf), vault=Vault(tmp_path / "vault", make_fake_tpm()))
    assert kp2 == kp


def test_locked_tpm_fails_closed(tmp_path):
    kf = tmp_path / "offense-governance.key"
    good = Vault(tmp_path / "vault", make_fake_tpm())
    good.provision()
    load_or_create_governance_keypair(path=str(kf), vault=good)
    dead = Vault(tmp_path / "vault", make_fake_tpm(unavailable=True))
    with pytest.raises(VaultLocked):
        load_or_create_governance_keypair(path=str(kf), vault=dead)


def test_three_offense_identities_have_distinct_contexts():
    # operator (ledger), spine (checkpoint/exec/detect), governance (anchor-1) must be mutually
    # non-interchangeable at rest — a blob sealed for one can never open as another.
    ctxs = {OPERATOR_KEYPAIR_CONTEXT, SPINE_KEYPAIR_CONTEXT, GOVERNANCE_KEYPAIR_CONTEXT}
    assert len(ctxs) == 3
