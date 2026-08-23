"""W7-6 (#464): the orchestrator ``MANIFEST.json`` is GOVERNANCE-SIGNED and ``vigil restore`` REFUSES an
unsigned / tampered / wrong-key manifest — an unsigned index is never trusted.

The two-plane ``vigil backup`` orchestrator writes a plaintext ``MANIFEST.json`` — the index of what a backup
contains (which encrypted file is which plane, and each part's sha256, the values restore uses to LOCATE and
integrity-check each part before invoking any leg). Unsigned, anyone who can reach the backup at rest could
edit it: redirect a part's ``file``, downgrade a ``sha256`` to smuggle an OLD legitimate part back in (a
rollback/substitution to pre-revocation state), or tamper the retention hint. This suite proves the index is
now signed with the OFFENSE GOVERNANCE key and that restore fails-closed on a bad signature.

The CLI-level negative controls (tampered / unsigned) FAIL WITHOUT the fix: on a tree whose ``_cmd_restore``
does not verify a signature, a tampered-but-per-part-consistent manifest and an unsigned manifest both let the
restore proceed and call the offense leg. Here they are refused (exit 2) before the leg is ever invoked. Each
negative control asserts a deliberately bad state is REJECTED in the same run, so the gate is proved not a
no-op.

FATAL-2: the orchestrator signs with the OFFENSE governance key only; the sovereign owner key never enters
this process. Determinism: the signature is Ed25519 over fixed bytes — no wallclock/rng enters it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import vigil_integration.backup as backup
import vigil_integration.cli as cli
from vigil_core import generate_keypair, sign
from vigil_integration.backup import (
    OffenseBackupError,
    sign_orchestrator_manifest,
    verify_orchestrator_manifest,
)

# A realistic orchestrator manifest body (the exact shape `_cmd_backup` writes), as fixed bytes so the crypto
# is tested independently of the wallclock `created_utc` the CLI stamps into a live one.
_MANIFEST = {
    "schema": 1,
    "created_utc": "2026-08-22T00:00:00Z",
    "host": "vigil-test-host",
    "planes": {"offense": {"file": "offense.vglbk", "sha256": "a" * 64, "bytes": 1234}},
    "retention_hint": {"keep_days": 30, "keep_last": 10},
    "note": "TWO SEPARATE encrypted files, one per plane.",
}


def _manifest_bytes() -> bytes:
    return json.dumps(_MANIFEST, indent=2, sort_keys=True).encode("utf-8")


# --------------------------------------------------------------------------------------------------
# Unit level — the sign/verify primitives directly.
# --------------------------------------------------------------------------------------------------
def test_sign_then_verify_roundtrips(tmp_path):
    mb = _manifest_bytes()
    sig_doc = sign_orchestrator_manifest(mb, base_dir=str(tmp_path))
    assert sig_doc["algo"] == "ed25519"
    assert sig_doc["signs"] == "MANIFEST.json (raw bytes)"
    # verify returns the signer pubkey and does not raise on the exact signed bytes.
    signer = verify_orchestrator_manifest(mb, sig_doc)
    assert signer == sig_doc["pubkey"]
    # and it holds under an out-of-band pin naming the true signer.
    assert verify_orchestrator_manifest(mb, sig_doc, expect_pubkey=sig_doc["pubkey"]) == sig_doc["pubkey"]


def test_signing_is_deterministic_no_wallclock_or_rng(tmp_path):
    """The HARD RULE: signing introduces no wallclock/rng. Ed25519 over the SAME bytes with the SAME persisted
    key yields byte-identical output on repeat, so the signature is re-verifiable and reproducible."""
    mb = _manifest_bytes()
    first = sign_orchestrator_manifest(mb, base_dir=str(tmp_path))
    second = sign_orchestrator_manifest(mb, base_dir=str(tmp_path))
    assert first == second, "signing is not deterministic — wallclock/rng leaked into the signed envelope"


def test_verify_refuses_tampered_manifest_bytes(tmp_path):
    mb = _manifest_bytes()
    sig_doc = sign_orchestrator_manifest(mb, base_dir=str(tmp_path))
    tampered = mb.replace(b"offense.vglbk", b"attacker.vglbk")
    assert tampered != mb
    with pytest.raises(OffenseBackupError, match="does not verify"):
        verify_orchestrator_manifest(tampered, sig_doc)


def test_verify_refuses_unsigned_manifest(tmp_path):
    mb = _manifest_bytes()
    # No envelope at all, an empty one, and one missing its pubkey/sig are ALL refused — never trusted.
    for bad in (None, {}, {"algo": "ed25519"}, {"pubkey": "x", "sig": ""}):
        with pytest.raises(OffenseBackupError):
            verify_orchestrator_manifest(mb, bad)


def test_verify_refuses_wrong_key_pin(tmp_path):
    mb = _manifest_bytes()
    sig_doc = sign_orchestrator_manifest(mb, base_dir=str(tmp_path))
    other = generate_keypair().public_key_b64
    assert other != sig_doc["pubkey"]
    with pytest.raises(OffenseBackupError, match="pinned --expect-governance-pubkey"):
        verify_orchestrator_manifest(mb, sig_doc, expect_pubkey=other)


def test_pin_blocks_a_remint_that_integrity_only_would_accept(tmp_path):
    """The honest residual, pinned down. An attacker who cannot decrypt the parts but can reach the index
    re-signs a tampered manifest under a key THEY generated. WITHOUT the out-of-band pin that self-signed
    envelope verifies (integrity-only); WITH the pin naming the true governance key it is refused. This is the
    W9-1 #434 authenticity residual made explicit."""
    mb = _manifest_bytes()
    real = sign_orchestrator_manifest(mb, base_dir=str(tmp_path))
    attacker = generate_keypair()
    forged_bytes = mb.replace(b'"keep_last": 10', b'"keep_last": 1')
    forged_env = {
        "schema": 1, "algo": "ed25519", "signs": "MANIFEST.json (raw bytes)",
        "manifest_sha256": backup.sha256_hex(forged_bytes),
        "pubkey": attacker.public_key_b64,
        "sig": sign(attacker.private_key_b64, forged_bytes),
    }
    # integrity-only (no pin): the re-mint verifies — this is exactly the residual we document.
    assert verify_orchestrator_manifest(forged_bytes, forged_env) == attacker.public_key_b64
    # with the pin naming the REAL signer, the re-mint is refused.
    with pytest.raises(OffenseBackupError, match="pinned --expect-governance-pubkey"):
        verify_orchestrator_manifest(forged_bytes, forged_env, expect_pubkey=real["pubkey"])


# --------------------------------------------------------------------------------------------------
# CLI level — the whole `vigil backup` → `vigil restore` path. These negative controls FAIL WITHOUT the fix.
# --------------------------------------------------------------------------------------------------
def _backup_ns(tmp_path, **kw):
    d = dict(sovereign_only=False, offense_only=True, out=str(tmp_path / "out"),
             base_dir=str(tmp_path / "base"), crucible_root="", passphrase_env="VIGIL_BACKUP_PASSPHRASE",
             push="", prune=False, keep_days=None, keep_last=None)
    d.update(kw)
    return argparse.Namespace(**d)


def _restore_ns(tmp_path, src, **kw):
    d = dict(sovereign_only=False, offense_only=True, src=str(src),
             base_dir=str(tmp_path / "restored-base"), crucible_root="", sigil_home="",
             expect_governance_pubkey="", force=False, passphrase_env="VIGIL_BACKUP_PASSPHRASE")
    d.update(kw)
    return argparse.Namespace(**d)


def _make_backup(tmp_path, monkeypatch) -> Path:
    """Drive a real `_cmd_backup` with a stubbed offense leg; returns the produced timestamped subdir."""
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", "pw-for-the-test-123")
    monkeypatch.setattr(cli, "_resolve_crucible_root", lambda: None)

    def fake_create(dest, pw, *, base_dir, crucible_root=None):
        Path(dest).write_bytes(b"fake-offense-ciphertext-bytes")
        return {"files": 1, "secrets": 0, "scope": "x", "bytes": 29}
    monkeypatch.setattr(backup, "create_offense_backup", fake_create)

    assert cli._cmd_backup(_backup_ns(tmp_path)) == 0
    subdirs = [p for p in (tmp_path / "out").iterdir() if p.is_dir()]
    assert len(subdirs) == 1
    return subdirs[0]


def test_backup_writes_a_verifying_signature(tmp_path, monkeypatch):
    subdir = _make_backup(tmp_path, monkeypatch)
    manifest_bytes = (subdir / "MANIFEST.json").read_bytes()
    sig_doc = json.loads((subdir / "MANIFEST.sig.json").read_bytes())
    # the sidecar exists and verifies over the EXACT on-disk manifest bytes.
    assert verify_orchestrator_manifest(manifest_bytes, sig_doc) == sig_doc["pubkey"]


def _stub_restore(monkeypatch) -> dict:
    calls: dict = {"offense": 0}

    def fake_restore(off, base_dir, pw, *, crucible_root=None, expect_pubkey=None, force=False):
        calls["offense"] += 1
        return {"new_base": base_dir, "files": 1, "secrets": 0, "bundles_verified": 0}
    monkeypatch.setattr(backup, "restore_offense_backup", fake_restore)
    return calls


def test_restore_accepts_a_clean_signed_manifest(tmp_path, monkeypatch):
    subdir = _make_backup(tmp_path, monkeypatch)
    calls = _stub_restore(monkeypatch)
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir)) == 0
    assert calls["offense"] == 1, "a clean, signed manifest must restore"


def test_restore_refuses_a_tampered_manifest(tmp_path, monkeypatch):
    """Substitution attack: replace the offense part AND update its sha256 in the index so the OLD per-part
    sha256 check would pass — only the manifest SIGNATURE catches it. Refused before the leg is invoked."""
    subdir = _make_backup(tmp_path, monkeypatch)
    calls = _stub_restore(monkeypatch)
    # attacker swaps the part and rewrites the index sha256 to match the swap (per-part check would pass).
    (subdir / "offense.vglbk").write_bytes(b"attacker-substituted-ciphertext")
    manifest = json.loads((subdir / "MANIFEST.json").read_bytes())
    manifest["planes"]["offense"]["sha256"] = cli._sha256_file(subdir / "offense.vglbk")
    (subdir / "MANIFEST.json").write_bytes(json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
    # the signature no longer matches the edited index → fail-closed, leg never called.
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir)) == 2
    assert calls["offense"] == 0, "a tampered manifest must be refused BEFORE the offense leg runs"


def test_restore_refuses_an_unsigned_manifest(tmp_path, monkeypatch):
    subdir = _make_backup(tmp_path, monkeypatch)
    calls = _stub_restore(monkeypatch)
    (subdir / "MANIFEST.sig.json").unlink()          # strip the signature → an UNSIGNED manifest
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir)) == 2
    assert calls["offense"] == 0, "an unsigned manifest must never be trusted"


def test_restore_pin_mismatch_refused_and_correct_pin_accepted(tmp_path, monkeypatch):
    subdir = _make_backup(tmp_path, monkeypatch)
    calls = _stub_restore(monkeypatch)
    sig_doc = json.loads((subdir / "MANIFEST.sig.json").read_bytes())
    wrong = generate_keypair().public_key_b64
    # wrong out-of-band pin → refused, leg not called.
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir, expect_governance_pubkey=wrong)) == 2
    assert calls["offense"] == 0
    # the correct pin → restore proceeds.
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir, expect_governance_pubkey=sig_doc["pubkey"])) == 0
    assert calls["offense"] == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
