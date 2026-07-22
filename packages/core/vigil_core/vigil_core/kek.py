"""vigil_core.kek — TPM-sealed custody of the key-encryption-key (KEK) that :mod:`vigil_core.sealing` uses.

The KEK is a 32-byte symmetric key that wraps every at-rest secret / private key (audit G1). By operator
decision its custody is **TPM-sealed**: a fresh KEK is generated once and SEALED to this machine's TPM
(owner hierarchy), so the sealed blob on disk is useless on any other machine and the KEK never rests in
plaintext. Unattended boot: the daemon unseals it from the TPM at start, no passphrase.

Fail-closed + testable: the TPM is reached ONLY through an injectable argv-runner seam (default: a real
subprocess to ``tpm2-tools``, fixed argv, no shell, never-raises — mirroring ``attestation.anchor``'s TPM
probe), so the whole provider is unit-tested deterministically with a fake runner, and the live TPM path
activates once ``tpm2-tools`` is installed and the user can reach ``/dev/tpmrm0`` (one-time operator
setup: ``sudo apt install tpm2-tools`` + ``sudo usermod -aG tss $USER``). There is **NO silent plaintext
fallback**: if the TPM cannot seal/unseal, KEK operations raise :class:`KekError` (fail-closed) rather
than degrade confidentiality. The standard tpm2 sealing recipe is used: a DETERMINISTic owner-hierarchy
primary (recreatable each boot) under which the KEK is sealed as a keyedhash object; the sealed public +
private blobs are the only on-disk artifacts.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .sealing import new_kek

_KEK_LEN = 32
_SEAL_PUB = "kek.tpm.pub"      # the sealed KEK — TPM public blob (safe at rest; useless without the TPM)
_SEAL_PRIV = "kek.tpm.priv"    # the sealed KEK — TPM private blob (encrypted to the TPM's storage root)
# A fixed, deterministic owner-hierarchy primary so the same primary is recreated every boot and can
# load the sealed object without persisting a handle.
_PRIMARY_ARGS = ("-C", "o", "-g", "sha256", "-G", "ecc")


class KekError(Exception):
    """The KEK could not be provisioned, sealed, or unsealed via the TPM (fail-closed)."""


@dataclass(frozen=True)
class TpmResult:
    rc: int
    stdout: bytes


# argv (fully-resolved, no shell) + optional stdin bytes -> TpmResult. Injected in tests; the default
# shells to tpm2-tools. MUST NOT raise (a failure is rc != 0), mirroring attestation.anchor's probe.
TpmRunner = Callable[[list, Optional[bytes]], TpmResult]


def _default_tpm_runner(argv: list, stdin: Optional[bytes]) -> TpmResult:
    """Run one tpm2-tools command by fully-resolved argv (no shell, no interpolation). Total: a missing
    tool / no TPM device / spawn error / timeout is rc=127 with empty stdout, never a raise."""
    if not os.path.exists("/dev/tpmrm0") and not os.path.exists("/dev/tpm0"):
        return TpmResult(127, b"")
    exe = shutil.which(argv[0]) if argv else None
    if not exe:
        return TpmResult(127, b"")
    try:
        proc = subprocess.run(  # noqa: S603 — resolved exe, fixed argv, no shell, no interpolation
            [exe, *argv[1:]], input=stdin, capture_output=True, timeout=20, check=False,
        )
    except Exception:  # noqa: BLE001 — a spawn/timeout failure is "TPM unavailable", never a crash
        return TpmResult(127, b"")
    return TpmResult(proc.returncode, proc.stdout or b"")


def tpm_available(runner: TpmRunner = _default_tpm_runner) -> bool:
    """True iff a TPM primary can actually be created (tooling present AND device reachable)."""
    with tempfile.TemporaryDirectory() as td:
        ctx = str(Path(td) / "p.ctx")
        return runner(["tpm2_createprimary", *_PRIMARY_ARGS, "-c", ctx], None).rc == 0


def provision_kek(directory, *, runner: TpmRunner = _default_tpm_runner) -> None:
    """Generate a fresh 32-byte KEK and SEAL it to the TPM, persisting only the sealed pub/priv blobs
    under ``directory`` (0700 dir, 0600 blobs). Idempotent-refusing: raises if a sealed KEK already
    exists (never silently overwrites the trust root). Fail-closed: any TPM step failing raises
    :class:`KekError` and leaves no partial KEK. The plaintext KEK exists only transiently in memory."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    pub, priv = d / _SEAL_PUB, d / _SEAL_PRIV
    if pub.exists() or priv.exists():
        raise KekError("a sealed KEK already exists here — refusing to overwrite the trust root")

    kek = new_kek()
    with tempfile.TemporaryDirectory() as td:
        primary = str(Path(td) / "primary.ctx")
        pub_tmp, priv_tmp = str(Path(td) / "seal.pub"), str(Path(td) / "seal.priv")
        r1 = runner(["tpm2_createprimary", *_PRIMARY_ARGS, "-c", primary], None)
        if r1.rc != 0:
            raise KekError("tpm2_createprimary failed (is tpm2-tools installed and the TPM reachable?)")
        # seal the KEK as a keyedhash object under the primary; KEK bytes go in on stdin (never argv).
        r2 = runner(["tpm2_create", "-C", primary, "-u", pub_tmp, "-r", priv_tmp, "-i", "-"], kek)
        if r2.rc != 0 or not (Path(pub_tmp).exists() and Path(priv_tmp).exists()):
            raise KekError("tpm2_create (seal KEK) failed")
        sealed_pub = Path(pub_tmp).read_bytes()
        sealed_priv = Path(priv_tmp).read_bytes()

    _atomic_write(pub, sealed_pub)
    _atomic_write(priv, sealed_priv)


def load_kek(directory, *, runner: TpmRunner = _default_tpm_runner) -> bytes:
    """Unseal the 32-byte KEK from the TPM using the persisted sealed blobs under ``directory``. Raises
    :class:`KekError` if not provisioned, if the TPM is unavailable, or if the unsealed KEK is not
    exactly 32 bytes — never returns a weak/partial KEK, never falls back to plaintext."""
    d = Path(directory)
    pub, priv = d / _SEAL_PUB, d / _SEAL_PRIV
    if not (pub.exists() and priv.exists()):
        raise KekError("no sealed KEK found — run `provision_kek` once on this machine first")
    with tempfile.TemporaryDirectory() as td:
        primary = str(Path(td) / "primary.ctx")
        seal_ctx = str(Path(td) / "seal.ctx")
        pub_tmp, priv_tmp = str(Path(td) / "seal.pub"), str(Path(td) / "seal.priv")
        Path(pub_tmp).write_bytes(pub.read_bytes())
        Path(priv_tmp).write_bytes(priv.read_bytes())
        if runner(["tpm2_createprimary", *_PRIMARY_ARGS, "-c", primary], None).rc != 0:
            raise KekError("tpm2_createprimary failed while unsealing the KEK")
        if runner(["tpm2_load", "-C", primary, "-u", pub_tmp, "-r", priv_tmp, "-c", seal_ctx], None).rc != 0:
            raise KekError("tpm2_load failed — sealed KEK does not match this TPM (moved disk?)")
        r = runner(["tpm2_unseal", "-c", seal_ctx], None)
    if r.rc != 0:
        raise KekError("tpm2_unseal failed")
    kek = r.stdout
    if len(kek) != _KEK_LEN:
        raise KekError(f"unsealed KEK is {len(kek)} bytes, expected {_KEK_LEN} (fail-closed)")
    return kek


def is_provisioned(directory) -> bool:
    d = Path(directory)
    return (d / _SEAL_PUB).exists() and (d / _SEAL_PRIV).exists()


def _atomic_write(path: Path, data: bytes) -> None:
    """Write bytes with the file mode set to 0600 BEFORE the secret lands, then atomically rename."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))
