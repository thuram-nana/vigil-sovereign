"""attest.provider — attestation interface + a working software/TPM fallback (X1).

WHAT AN ATTESTATION IS HERE
---------------------------
An ``AttestationProvider`` turns a payload (bytes) into an ``AttestationQuote`` — a signed statement
"this exact payload was seen by this signer" — and can later ``verify`` that quote. Two backends:

  * [BUILT] ``SoftwareAttestationProvider`` — a pure-software signer (Ed25519, via the repo's
    ``vigil_core.crypto`` primitives). It runs today, anywhere, with no special hardware.

  * [hardware-gated] ``SevSnpAttestationProvider`` / ``TdxAttestationProvider`` — real
    confidential-computing backends. Stubs that raise ``NotImplementedError`` until the hardware lands.

HONEST SCOPE — read this before trusting a software quote
---------------------------------------------------------
The software quote proves **integrity** (the payload digest is bound into the signature, so a changed
payload fails ``verify``) and **origin** (a valid signature means the holder of the private key produced
it). It does NOT prove **hardware confidentiality or platform state**: there is no TEE measurement, no
launch-time report, nothing establishing the code ran in an isolated enclave on genuine silicon. A
software signer's key can be read by anyone with host access; ``verify`` only establishes the quote is
internally consistent and signed by the embedded key. A real trust decision still requires pinning that
key OUT-OF-BAND (the same discipline as ``evidence.certify.trust_root_fingerprint``). Hardware
confidentiality arrives only with the TEE backends below — and those are stubs, honestly labelled.

This layer mints no fact and grants no tier. An attestation authenticates a payload's integrity/origin;
it never confirms a security finding. The oracle remains the sole authority.
"""

from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from vigil_core.crypto import KeyPair, generate_keypair, sign, verify_one

_QUOTE_VERSION = 1


def _payload_sha256(payload: bytes) -> str:
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("attest() payload must be bytes")
    return "sha256:" + hashlib.sha256(bytes(payload)).hexdigest()


class AttestationQuote(BaseModel):
    """A signed statement over a payload's digest. Non-secret: it carries the payload DIGEST (never the
    payload) and the signer's PUBLIC key. Self-describing so ``verify`` needs only the quote."""

    model_config = ConfigDict(extra="forbid")

    quote_version: int = Field(default=_QUOTE_VERSION)
    backend: str = Field(description="Which provider produced this quote (e.g. 'software-tpm-fallback').")
    payload_sha256: str = Field(description="sha256 of the attested payload bytes (hex, 'sha256:'-prefixed).")
    signer_key_id: str = Field(description="Stable id of the signing key.")
    signer_public_key_b64: str = Field(description="base64(32-byte Ed25519 public key) — for offline verify.")
    signature_b64: str = Field(description="base64(64-byte Ed25519 signature) over the canonical quote body.")
    hardware_backed: bool = Field(
        default=False,
        description="True ONLY for a real TEE backend. The software fallback is always False — it proves "
                    "integrity+origin, NOT hardware confidentiality.",
    )

    def signing_body(self) -> bytes:
        """The exact bytes the signature covers — every field EXCEPT the signature itself, in a fixed
        order. Deterministic (no wallclock/RNG), so a quote re-serialises and re-verifies byte-for-byte."""
        return (
            f"vigil-attest\nv={self.quote_version}\nbackend={self.backend}\n"
            f"payload={self.payload_sha256}\nkid={self.signer_key_id}\n"
            f"pub={self.signer_public_key_b64}\nhw={int(self.hardware_backed)}"
        ).encode("utf-8")


class AttestationProvider(ABC):
    """The interface both the software fallback and the (stubbed) TEE backends implement."""

    @abstractmethod
    def attest(self, payload: bytes) -> AttestationQuote:
        """Produce a signed quote binding ``payload``'s digest to this provider's key."""

    @abstractmethod
    def verify(self, quote: AttestationQuote) -> bool:
        """True iff the quote's signature is valid over its own body under its embedded public key.

        NOTE: verify establishes internal consistency + origin only. It does NOT establish that the
        embedded key is one you trust — pin it out-of-band."""


class SoftwareAttestationProvider(AttestationProvider):
    """[BUILT] The working software/TPM fallback — an Ed25519 signer with no hardware requirement.

    Pass a fixed ``KeyPair`` (e.g. a TPM-sealed or file-backed key) for a stable signer identity; omit it
    and a fresh keypair is generated (RNG at construction only — the signature itself is deterministic per
    RFC 8032, so ``attest`` over the same payload with the same key yields the same quote)."""

    backend_name = "software-tpm-fallback"

    def __init__(self, keypair: Optional[KeyPair] = None, *, key_id: str = "software-tpm-fallback-1") -> None:
        self._kp = keypair or generate_keypair()
        self._key_id = key_id

    @property
    def public_key_b64(self) -> str:
        return self._kp.public_key_b64

    @property
    def key_id(self) -> str:
        return self._key_id

    def attest(self, payload: bytes) -> AttestationQuote:
        quote = AttestationQuote(
            backend=self.backend_name,
            payload_sha256=_payload_sha256(payload),
            signer_key_id=self._key_id,
            signer_public_key_b64=self._kp.public_key_b64,
            signature_b64="",             # filled below over the finalised body
            hardware_backed=False,        # honest: software quote is NOT hardware-backed
        )
        sig = sign(self._kp.private_key_b64, quote.signing_body())
        return quote.model_copy(update={"signature_b64": sig})

    def verify(self, quote: AttestationQuote) -> bool:
        if not quote.signature_b64:
            return False
        try:
            return verify_one(quote.signer_public_key_b64, quote.signing_body(), quote.signature_b64)
        except Exception:
            # malformed key/sig material → not verifiable → fail closed
            return False


class _HardwareGatedProvider(AttestationProvider):
    """Shared base for the real-TEE stubs: every method fails closed with the activation runbook."""

    backend_name = "tee-hardware-gated"

    def __init__(self, *_: object, **__: object) -> None:  # pragma: no cover - stub
        raise NotImplementedError(self._msg())

    @classmethod
    def _msg(cls) -> str:
        return (
            f"hardware-gated: {cls.__name__} needs confidential-computing hardware and its attestation "
            f"stack. Use SoftwareAttestationProvider (integrity+origin, NOT hardware confidentiality) "
            f"until the platform is provisioned — see docs/DEFERRED-INFRA.md (X1)."
        )

    def attest(self, payload: bytes) -> AttestationQuote:  # pragma: no cover - stub
        raise NotImplementedError(self._msg())

    def verify(self, quote: AttestationQuote) -> bool:  # pragma: no cover - stub
        raise NotImplementedError(self._msg())


class SevSnpAttestationProvider(_HardwareGatedProvider):
    """[hardware-gated] AMD SEV-SNP attestation.

    ACTIVATION RUNBOOK (docs/DEFERRED-INFRA.md → X1):
      1. Run on an SEV-SNP-capable host inside an SNP guest.
      2. Obtain the signed attestation report (e.g. via ``/dev/sev-guest`` ioctl) with the payload digest
         placed in REPORT_DATA.
      3. Implement ``attest`` to return a quote carrying the SNP report + VCEK cert chain; implement
         ``verify`` to check the report signature against the AMD root and match REPORT_DATA to the digest.
      4. Set ``hardware_backed=True`` ONLY when a genuine report verifies — never for the software path.
    """

    backend_name = "sev-snp"


class TdxAttestationProvider(_HardwareGatedProvider):
    """[hardware-gated] Intel TDX attestation. Runbook mirrors SEV-SNP: obtain the TD quote (TDREPORT →
    QE), bind the payload digest into REPORTDATA, verify via the Intel DCAP/QVL chain. See
    docs/DEFERRED-INFRA.md (X1)."""

    backend_name = "tdx"


# ---------------------------------------------------------------------------------------------------
# auto-detect selector — pick the TEE backend when the platform exposes one, else the software fallback.
# ---------------------------------------------------------------------------------------------------

# The guest attestation devices each TEE exposes. Presence means the platform CAN attest in hardware — but a
# backend must be IMPLEMENTED (the runbook body) before it can be used; until then the selector detects the
# device and honestly falls back to software.
_TEE_DEVICES: tuple[tuple[str, str], ...] = (
    ("sev-snp", "/dev/sev-guest"),
    ("tdx", "/dev/tdx_guest"),
    ("tdx", "/dev/tdx-guest"),
)

_TEE_PROVIDERS: dict[str, type[AttestationProvider]] = {
    "sev-snp": SevSnpAttestationProvider,
    "tdx": TdxAttestationProvider,
}


def detect_tee(*, devices: Optional[tuple[tuple[str, str], ...]] = None) -> Optional[str]:
    """Probe the platform for a confidential-computing guest attestation device. Returns the backend name
    (``"sev-snp"`` | ``"tdx"``) if one is present, else ``None``. The ``VIGIL_TEE_BACKEND`` env var overrides
    detection (``software``/``none``/``off`` forces the fallback; a backend name forces that backend). The
    device list is resolved from the module global at CALL time (so it stays overridable). Total: any probe
    error → ``None`` (fall to the software fallback, never raise)."""
    override = os.environ.get("VIGIL_TEE_BACKEND", "").strip().lower()
    if override:
        return None if override in ("software", "none", "off") else override
    try:
        for name, path in (devices if devices is not None else _TEE_DEVICES):
            if Path(path).exists():
                return name
    except OSError:
        return None
    return None


def open_attestation_provider(
    *, keypair: Optional[KeyPair] = None, prefer_hardware: bool = True,
) -> tuple[AttestationProvider, str]:
    """Select the attestation provider for THIS platform, returning ``(provider, note)``. If a TEE device is
    detected AND ``prefer_hardware`` AND its backend is IMPLEMENTED, use the hardware backend; otherwise fall
    back to :class:`SoftwareAttestationProvider` (integrity+origin only, NOT hardware confidentiality), with a
    note stating exactly why.

    This is the "auto-detect on hardware" seam: the day a hardware backend is implemented (its ``__init__``
    stops raising ``NotImplementedError``), deploying on that silicon activates it AUTOMATICALLY on detection —
    until then this reports the device honestly and falls back. NEVER raises: an unbuilt/erroring backend
    degrades to software (fail-soft)."""
    tee = detect_tee() if prefer_hardware else None
    if tee and tee in _TEE_PROVIDERS:
        cls = _TEE_PROVIDERS[tee]
        try:
            return cls(), f"{tee} hardware attestation active"
        except NotImplementedError:
            return SoftwareAttestationProvider(keypair), (
                f"{tee} device detected but its backend is not yet implemented (hardware-gated) — using the "
                f"software/TPM fallback. Implement {cls.__name__} per docs/DEFERRED-INFRA.md (X1) and it will "
                "activate automatically on this hardware.")
        except Exception as e:  # noqa: BLE001 — any backend construction error → software (fail-soft)
            return SoftwareAttestationProvider(keypair), (
                f"{tee} backend errored ({type(e).__name__}) — using the software/TPM fallback")
    reason = "hardware disabled by caller" if (not tee and not prefer_hardware) else \
             "no confidential-computing device detected"
    return SoftwareAttestationProvider(keypair), (
        f"{reason} — using the software/TPM fallback (integrity+origin only, NOT hardware confidentiality)")
