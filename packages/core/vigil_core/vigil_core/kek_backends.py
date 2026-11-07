"""vigil_core.kek_backends — pluggable at-rest CUSTODY for the key-encryption-key (KEK).

The KEK is the 32-byte symmetric key that :mod:`vigil_core.sealing` uses to wrap every at-rest secret /
private key (audit G1). WHO holds custody of that KEK — i.e. what wraps it so it never rests in plaintext —
is now a pluggable backend, selected by the sovereign side (``sigil.config``), defaulting to the original
TPM recipe so nothing changes unless a cloud operator opts in:

  * :class:`TpmKekBackend` (DEFAULT) — the KEK is TPM-sealed to this machine (the original
    :mod:`vigil_core.kek` recipe). Byte-identical to the pre-backend behaviour.
  * :class:`KmsKekBackend` — the KEK is ENVELOPE-ENCRYPTED under an AWS KMS CMK: a fresh KEK is generated
    once and ``kms:Encrypt``-wrapped (the instance role's grant), and only the opaque KMS ciphertext rests
    on disk. At boot the daemon ``kms:Decrypt``-unwraps it. Stealing the EC2 disk yields nothing without
    ``kms:Decrypt`` (IAM-gated to the instance role). KMS is reached ONLY through an injectable ``aws``
    argv-runner (a fake in tests; the real ``aws kms`` subprocess in production) — no boto3, no SigV4 by
    hand, no IMDS handling; the instance role supplies credentials.

    IMPORTANT — why KMS is a KEK, not a signer: the VIGIL owner trust root is **Ed25519**, which AWS KMS
    cannot hold or sign with natively. So KMS guards the KEK that seals the owner key AT REST; the Ed25519
    key is unwrapped into the provisioner's memory and signs IN-PROCESS exactly as today. The security
    property gained is "no plaintext owner key on a shared cloud disk", not "the key never leaves an HSM".

Both backends share ONE on-disk contract — a 2-file (marker ``kek.tpm.pub`` + wrapped-KEK ``kek.tpm.priv``)
layout and the same AEAD sealing of secrets under the UNWRAPPED KEK — so the Vault's rotation / ``.prev`` /
``.rot`` crash-window machinery is custody-agnostic and untouched. Fail-closed throughout: an unavailable
TPM / unreachable KMS / wrong key raises :class:`KekError`, NEVER a silent plaintext-KEK fallback.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Optional, Protocol, runtime_checkable

from .kek import (
    _KEK_LEN, _SEAL_PRIV, _SEAL_PUB, KekError, TpmResult, TpmRunner, _atomic_write, _default_tpm_runner,
    is_provisioned as _tpm_is_provisioned, load_kek as _tpm_load_kek, load_kek_from as _tpm_load_kek_from,
    provision_kek as _tpm_provision_kek, reseal_kek as _tpm_reseal_kek, tpm_available,
)
from .sealing import new_kek

__all__ = ["KekBackend", "TpmKekBackend", "KmsKekBackend", "AwsRunner", "_default_aws_runner"]


@runtime_checkable
class KekBackend(Protocol):
    """How the Vault wraps/unwraps its KEK. Every method is fail-closed (raises :class:`KekError` on any
    custody failure; never returns a weak/partial/plaintext KEK)."""

    def is_provisioned(self, directory) -> bool: ...
    def provision(self, directory) -> None: ...
    def load(self, directory) -> bytes: ...
    def load_from(self, directory, pub_name: str, priv_name: str) -> bytes: ...
    def reseal(self, directory, kek: bytes, *, pub_name: str, priv_name: str) -> None: ...
    def available(self) -> bool: ...
    def label(self) -> str: ...


# ======================================================================================================
# TPM backend (the default — delegates to the original vigil_core.kek recipe, unchanged)
# ======================================================================================================
class TpmKekBackend:
    """The default custody: the KEK is TPM-sealed. A thin adapter over the original module functions so the
    pre-backend behaviour is byte-identical and the single tpm2 recipe is never duplicated."""

    def __init__(self, runner: TpmRunner = _default_tpm_runner) -> None:
        self._runner = runner

    def is_provisioned(self, directory) -> bool:
        return _tpm_is_provisioned(directory)

    def provision(self, directory) -> None:
        _tpm_provision_kek(directory, runner=self._runner)

    def load(self, directory) -> bytes:
        return _tpm_load_kek(directory, runner=self._runner)

    def load_from(self, directory, pub_name: str, priv_name: str) -> bytes:
        return _tpm_load_kek_from(directory, pub_name, priv_name, runner=self._runner)

    def reseal(self, directory, kek: bytes, *, pub_name: str, priv_name: str) -> None:
        _tpm_reseal_kek(directory, kek, runner=self._runner, pub_name=pub_name, priv_name=priv_name)

    def available(self) -> bool:
        return tpm_available(self._runner)

    def label(self) -> str:
        return "TPM-sealed KEK"


# ======================================================================================================
# KMS backend (cloud — envelope-encrypt the KEK under an AWS KMS CMK via an injectable `aws` runner)
# ======================================================================================================
# argv (fully-resolved, no shell) + optional stdin bytes -> TpmResult(rc, stdout). Injected in tests; the
# default shells to the `aws` CLI. MUST NOT raise (a failure is rc != 0), mirroring the TPM runner seam.
AwsRunner = Callable[[list, Optional[bytes]], TpmResult]

_KMS_MARKER = "vigil-kms-kek-v1"


def _default_aws_runner(argv: list, stdin: Optional[bytes]) -> TpmResult:
    """Run one `aws` command by fully-resolved argv (no shell, no interpolation). Total: a missing CLI /
    spawn error / timeout is rc=127 with empty stdout, never a raise (mirrors ``_default_tpm_runner``)."""
    exe = shutil.which(argv[0]) if argv else None
    if not exe:
        return TpmResult(127, b"")
    try:
        proc = subprocess.run(  # noqa: S603 — resolved exe, fixed argv, no shell, no interpolation
            [exe, *argv[1:]], input=stdin, capture_output=True, timeout=30, check=False,
        )
    except Exception:  # noqa: BLE001 — a spawn/timeout failure is "KMS unavailable", never a crash
        return TpmResult(127, b"")
    return TpmResult(proc.returncode, proc.stdout or b"")


class KmsKekBackend:
    """Custody via AWS KMS envelope encryption. The KEK is ``kms:Encrypt``-wrapped under ``key_id`` and only
    the opaque ciphertext rests on disk (``priv`` file); a small self-describing marker (backend/key/region)
    rests in the ``pub`` file so a load uses the SAME key the wrap used. Reached only through the injectable
    ``aws`` runner. Fail-closed: any CLI non-zero / non-base64 / wrong-length result raises :class:`KekError`.

    The 32-byte plaintext KEK exists only transiently in the provisioner's memory; it is fed to / read from
    the CLI over the child's stdin/stdout (NEVER on argv — argv is world-visible in the process table — and
    NEVER written to a plaintext file)."""

    def __init__(self, *, key_id: str, region: str, runner: AwsRunner = _default_aws_runner,
                 aws_cmd: str = "aws") -> None:
        if not isinstance(key_id, str) or not key_id.strip():
            raise KekError("KMS backend requires a key id (VIGIL_KMS_KEY_ID)")
        if not isinstance(region, str) or not region.strip():
            raise KekError("KMS backend requires an AWS region (VIGIL_AWS_REGION / VIGIL_KMS_REGION)")
        self._key_id = key_id.strip()
        self._region = region.strip()
        self._runner = runner
        self._aws = aws_cmd

    # --- the envelope primitives (over the injectable runner) -------------------------------------
    def _wrap(self, kek: bytes) -> bytes:
        """``kms:Encrypt`` the KEK; return the raw (base64-decoded) ciphertext blob. KEK rides stdin."""
        r = self._runner(
            [self._aws, "--region", self._region, "kms", "encrypt", "--key-id", self._key_id,
             "--plaintext", "fileb:///dev/stdin", "--output", "text", "--query", "CiphertextBlob"],
            bytes(kek))
        if r.rc != 0:
            raise KekError("aws kms encrypt failed — is the `aws` CLI configured and the instance role "
                           "granted kms:Encrypt on this key?")
        return _b64decode_strict(r.stdout, "aws kms encrypt ciphertext")

    def _unwrap(self, ciphertext: bytes, *, key_id: str, region: str) -> bytes:
        """``kms:Decrypt`` the ciphertext; return the 32-byte KEK. Ciphertext rides stdin (not secret)."""
        r = self._runner(
            [self._aws, "--region", region, "kms", "decrypt", "--key-id", key_id,
             "--ciphertext-blob", "fileb:///dev/stdin", "--output", "text", "--query", "Plaintext"],
            bytes(ciphertext))
        if r.rc != 0:
            raise KekError("aws kms decrypt failed — the sealed KEK does not match this key, or the "
                           "instance role lacks kms:Decrypt (fail-closed, never a plaintext fallback)")
        kek = _b64decode_strict(r.stdout, "aws kms decrypt plaintext")
        if len(kek) != _KEK_LEN:
            raise KekError(f"unwrapped KEK is {len(kek)} bytes, expected {_KEK_LEN} (fail-closed)")
        return kek

    # --- the KekBackend contract -------------------------------------------------------------------
    def is_provisioned(self, directory) -> bool:
        d = Path(directory)
        return (d / _SEAL_PUB).exists() and (d / _SEAL_PRIV).exists()

    def provision(self, directory) -> None:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        if self.is_provisioned(d):
            raise KekError("a wrapped KEK already exists here — refusing to overwrite the trust root")
        self.reseal(d, new_kek(), pub_name=_SEAL_PUB, priv_name=_SEAL_PRIV)

    def load(self, directory) -> bytes:
        return self.load_from(directory, _SEAL_PUB, _SEAL_PRIV)

    def load_from(self, directory, pub_name: str, priv_name: str) -> bytes:
        d = Path(directory)
        pub, priv = d / pub_name, d / priv_name
        if not (pub.exists() and priv.exists()):
            raise KekError(f"no wrapped KEK found at {pub_name}/{priv_name} under {d}")
        meta = _read_marker(pub)
        # Self-describing: decrypt with the key/region the WRAP recorded (so a later config drift of
        # VIGIL_KMS_KEY_ID cannot silently point a load at the wrong key); fall back to the configured
        # values only when an older marker lacks them.
        key_id = str(meta.get("key_id") or self._key_id)
        region = str(meta.get("region") or self._region)
        return self._unwrap(priv.read_bytes(), key_id=key_id, region=region)

    def reseal(self, directory, kek: bytes, *, pub_name: str, priv_name: str) -> None:
        if not isinstance(kek, (bytes, bytearray)) or len(kek) != _KEK_LEN:
            raise KekError(f"KEK to wrap must be exactly {_KEK_LEN} bytes")
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        ciphertext = self._wrap(bytes(kek))
        if not ciphertext:
            raise KekError("aws kms encrypt returned an empty ciphertext (fail-closed)")
        # Write the ciphertext (priv) and a self-describing marker (pub). The marker is NOT secret (it holds
        # only the public key id + region), but it binds the ciphertext to its key so a load is unambiguous.
        marker = json.dumps({"marker": _KMS_MARKER, "backend": "kms", "key_id": self._key_id,
                             "region": self._region}, sort_keys=True).encode("utf-8")
        _atomic_write(d / priv_name, ciphertext)
        _atomic_write(d / pub_name, marker)

    def available(self) -> bool:
        return self._runner(
            [self._aws, "--region", self._region, "sts", "get-caller-identity", "--output", "text"],
            None).rc == 0

    def label(self) -> str:
        return f"KMS-wrapped KEK (key {self._key_id}, {self._region})"


def _b64decode_strict(raw: bytes, what: str) -> bytes:
    try:
        return base64.b64decode((raw or b"").strip(), validate=True)
    except Exception as e:  # noqa: BLE001 — a non-base64 CLI reply is a fail-closed custody error
        raise KekError(f"{what} was not valid base64 (fail-closed): {e}") from None


def _read_marker(pub: Path) -> dict:
    try:
        meta = json.loads(pub.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise KekError(f"KMS KEK marker {pub.name} is unreadable/corrupt (fail-closed): {e}") from None
    if not isinstance(meta, dict) or meta.get("marker") != _KMS_MARKER:
        raise KekError(f"KMS KEK marker {pub.name} is not a VIGIL KMS marker (fail-closed)")
    return meta
