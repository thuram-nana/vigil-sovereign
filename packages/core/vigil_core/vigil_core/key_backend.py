"""vigil_core.key_backend — a pluggable backend for the OWNER signing key (W9-6, issue #439).

The owner Ed25519 key is the root of authority: it signs the per-action approval tokens and the
m-of-n destruction authorizations that gate every high-impact / target-touching action. Historically it
was FILE-based ONLY — a base64 private key exported into the signing process's environment (from a
``0600`` file owned by the same UID). A process compromise, a core dump, a ``/proc/<pid>/environ`` read,
or a swap leak therefore exposes the key that authorizes everything.

This introduces a small, pluggable :class:`KeyBackend` so the SAME owner identity can instead live in a
hardware token (a PKCS#11 HSM / YubiKey) that performs the signature ON the token — the 32-byte private
scalar never enters the process. Two backends, one selector, fail-closed:

  * :class:`FileBackend` — today's behaviour, byte-for-byte: a base64 Ed25519 private key held in-process,
    signed via :func:`vigil_core.crypto.sign`. Nothing already deployed changes; ``file`` is the default.
  * :class:`Pkcs11Backend` — the hardware backend: it holds NO private material and signs by delegating to
    an already-opened PKCS#11 token session. Only the message crosses to the token; a signature comes back.
  * :func:`select_owner_backend` — chooses by the ``VIGIL_OWNER_KEY_BACKEND`` env. THE NEGATIVE CONTROL:
    when the hardware backend is selected but the token / PKCS#11 module is ABSENT, it RAISES
    :class:`HardwareKeyUnavailable`. It NEVER silently falls back to a file key — a silent fallback would
    defeat the entire point of moving the key off the box, so an absent token must FAIL CLOSED.

``VIGIL_OWNER_KEY_BACKEND`` (default ``file``) selects the backend; the PKCS#11 backend additionally reads
``VIGIL_PKCS11_MODULE`` (the ``.so`` path), ``VIGIL_PKCS11_TOKEN_LABEL``, ``VIGIL_PKCS11_KEY_LABEL``
(default ``owner``), and ``VIGIL_PKCS11_PIN`` (which AUTHORIZES USE of the token — it is NOT the private
key and never yields the private scalar).

FATAL-2 / import-clean: ``vigil_core`` + stdlib only. The ``pkcs11`` third-party binding is imported
LAZILY, only inside the real token opener (:func:`open_pkcs11_signer`), so importing this module never
pulls it in and the pure selection / fail-closed logic is testable with no hardware and no ``pkcs11``
package present. Rotation (#434) is backend-agnostic: whatever backend holds the current owner key signs;
rotating to a new key means provisioning a new backend (a fresh file key, or a fresh token key object).
"""
from __future__ import annotations

import base64
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .crypto import sign

# ── env contract ────────────────────────────────────────────────────────────────────────────────────
BACKEND_ENV = "VIGIL_OWNER_KEY_BACKEND"       # "file" (default) | "pkcs11"/"hardware"/"hsm"/"yubikey"
MODULE_ENV = "VIGIL_PKCS11_MODULE"            # absolute path to the PKCS#11 provider .so
TOKEN_LABEL_ENV = "VIGIL_PKCS11_TOKEN_LABEL"  # which token/slot, by label (optional → first token)
KEY_LABEL_ENV = "VIGIL_PKCS11_KEY_LABEL"      # which key object on the token, by label (default "owner")
PIN_ENV = "VIGIL_PKCS11_PIN"                  # user PIN authorizing USE of the token (NOT the private key)

_FILE_ALIASES = frozenset({"", "file"})
_HARDWARE_ALIASES = frozenset({"pkcs11", "hardware", "hsm", "yubikey", "token"})
_DEFAULT_KEY_LABEL = "owner"


# ── errors ──────────────────────────────────────────────────────────────────────────────────────────
class KeyBackendError(Exception):
    """A pluggable owner-key backend could not be selected or used (fail-closed). Never leaks key
    material in its message."""


class HardwareKeyUnavailable(KeyBackendError):
    """The HARDWARE owner-key backend was selected but its token / PKCS#11 module could not be opened.

    This is the NEGATIVE CONTROL of the whole feature: it is raised INSTEAD of silently falling back to a
    file key, so an absent token makes owner signing FAIL CLOSED. A caller MUST treat this as "signing is
    unavailable", never as "use the file key"."""


# ── the token seam (duck-typed so the fail-closed logic is testable with no hardware) ─────────────────
@runtime_checkable
class TokenSigner(Protocol):
    """The narrow contract the hardware backend needs from an opened PKCS#11 token. A real implementation
    (:func:`open_pkcs11_signer`) wraps a python-``pkcs11`` session; a test supplies a fake. Neither ever
    exposes the private scalar — :meth:`sign` runs on the token and :meth:`public_key_raw` reads the
    PUBLIC key object (public objects are readable; private key objects are ``CKA_SENSITIVE`` /
    ``CKA_EXTRACTABLE=false`` and never leave)."""

    def sign(self, message: bytes) -> bytes:  # raw 64-byte Ed25519 signature, produced ON the token
        ...

    def public_key_raw(self) -> bytes:  # raw 32-byte Ed25519 public key, read from the token
        ...


# ── the abstraction ───────────────────────────────────────────────────────────────────────────────────
class KeyBackend(ABC):
    """A source of owner-key signatures. Signing is uniform (:meth:`sign` → base64 Ed25519 signature);
    the difference the caller cares about is :attr:`holds_private_material` — True for the file backend
    (the key is in this process), False for the hardware backend (the key is on the token)."""

    name: str = "abstract"
    holds_private_material: bool = True

    @abstractmethod
    def sign(self, message: bytes) -> str:
        """Return the base64 Ed25519 signature over ``message``. Signature: ``Callable[[bytes], str]`` —
        exactly what the token minters (``approval_token.mint_token``) accept as an injected signer."""

    @property
    @abstractmethod
    def public_key_b64(self) -> str:
        """The base64 Ed25519 PUBLIC key of this owner identity (safe to persist / pin)."""

    def describe(self) -> str:
        return self.name


class FileBackend(KeyBackend):
    """The DEFAULT backend — today's behaviour, unchanged: a base64 Ed25519 private key held in this
    process. Signing is :func:`vigil_core.crypto.sign`, so a token minted here is byte-identical to one
    minted before this abstraction existed. This backend DOES hold private material — that is the state
    the hardware backend exists to eliminate."""

    name = "file"
    holds_private_material = True

    def __init__(self, private_key_b64: str) -> None:
        if not (isinstance(private_key_b64, str) and private_key_b64.strip()):
            raise KeyBackendError("FileBackend requires a non-empty base64 Ed25519 private key")
        self._private_key_b64 = private_key_b64.strip()
        self._public_key_b64: Optional[str] = None

    def sign(self, message: bytes) -> str:
        # Identical to the pre-W9-6 owner-signing path: reads the private material into this process.
        return sign(self._private_key_b64, bytes(message))

    @property
    def public_key_b64(self) -> str:
        if self._public_key_b64 is None:
            self._public_key_b64 = _derive_public_key_b64(self._private_key_b64)
        return self._public_key_b64


class Pkcs11Backend(KeyBackend):
    """The HARDWARE backend — signs via an opened PKCS#11 token so the private scalar NEVER enters this
    process. It wraps a :class:`TokenSigner` (a real python-``pkcs11`` session, or a fake in tests) and
    holds NO private key attribute. A malformed signature / public key from the token is treated as an
    unavailable token (fail-closed), never coerced into something that looks valid."""

    name = "pkcs11"
    holds_private_material = False

    def __init__(self, signer: TokenSigner, *, token_label: str = "", key_label: str = "",
                 module_path: str = "") -> None:
        if signer is None:
            raise HardwareKeyUnavailable("Pkcs11Backend requires an opened token signer")
        self._signer = signer
        self.token_label = token_label
        self.key_label = key_label
        self.module_path = module_path

    def sign(self, message: bytes) -> str:
        raw = self._signer.sign(bytes(message))
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != 64:
            raise HardwareKeyUnavailable("PKCS#11 token returned a malformed Ed25519 signature (not 64 bytes)")
        return base64.b64encode(bytes(raw)).decode("ascii")

    @property
    def public_key_b64(self) -> str:
        raw = self._signer.public_key_raw()
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
            raise HardwareKeyUnavailable("PKCS#11 token returned a malformed Ed25519 public key (not 32 bytes)")
        return base64.b64encode(bytes(raw)).decode("ascii")

    def describe(self) -> str:
        where = self.module_path or "PKCS#11 token"
        return f"pkcs11 ({where}, key {self.key_label or _DEFAULT_KEY_LABEL})"


# ── PKCS#11 configuration ──────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Pkcs11Config:
    """The immutable hardware-backend config, read from env. ``pin`` authorizes USE of the token; it is
    NOT the private key and is never persisted here."""

    kind: str
    module_path: str
    token_label: str
    key_label: str
    pin: str

    @classmethod
    def from_env(cls, env: Mapping[str, str], *, kind: str = "pkcs11") -> "Pkcs11Config":
        return cls(
            kind=kind,
            module_path=str(env.get(MODULE_ENV, "") or "").strip(),
            token_label=str(env.get(TOKEN_LABEL_ENV, "") or "").strip(),
            key_label=str(env.get(KEY_LABEL_ENV, "") or "").strip() or _DEFAULT_KEY_LABEL,
            pin=str(env.get(PIN_ENV, "") or ""),
        )


# ── the selector — the fail-closed heart of the feature ──────────────────────────────────────────────
def select_owner_backend(
    *,
    env: Optional[Mapping[str, str]] = None,
    file_private_key_b64: Optional[str] = None,
    opener: Optional[Callable[[Pkcs11Config], TokenSigner]] = None,
) -> KeyBackend:
    """Choose the owner-key backend from ``VIGIL_OWNER_KEY_BACKEND`` (default ``file``).

    ``file`` (or unset) → a :class:`FileBackend` over ``file_private_key_b64`` (raise
    :class:`KeyBackendError` if none was supplied). ``pkcs11``/``hardware``/… → a :class:`Pkcs11Backend`
    over a freshly-opened token.

    NEGATIVE CONTROL — no silent fallback: when a hardware backend is selected, ``file_private_key_b64`` is
    NEVER consulted. If the token / PKCS#11 module cannot be opened (absent, unconfigured, missing binding,
    wrong PIN, missing key object), this RAISES :class:`HardwareKeyUnavailable` — it never returns a
    :class:`FileBackend`. An unknown backend name is a :class:`KeyBackendError` (fail-closed), never a
    default-to-file.
    """
    env = os.environ if env is None else env
    kind = str(env.get(BACKEND_ENV, "") or "").strip().lower()

    if kind in _FILE_ALIASES:
        if not (isinstance(file_private_key_b64, str) and file_private_key_b64.strip()):
            raise KeyBackendError(
                f"the file owner-key backend is selected ({BACKEND_ENV} unset or 'file') but no owner "
                "private key was supplied for this command")
        return FileBackend(file_private_key_b64)

    if kind in _HARDWARE_ALIASES:
        return _open_hardware_backend(env, kind, opener)

    raise KeyBackendError(
        f"unknown owner-key backend {kind!r} — set {BACKEND_ENV} to 'file' (default) or 'pkcs11'")


def _open_hardware_backend(
    env: Mapping[str, str], kind: str, opener: Optional[Callable[[Pkcs11Config], TokenSigner]],
) -> Pkcs11Backend:
    """Open the hardware token or FAIL CLOSED. Deliberately ignores any file key — a hardware selection
    must never resolve to a file backend."""
    config = Pkcs11Config.from_env(env, kind=kind)
    if not config.module_path:
        raise HardwareKeyUnavailable(
            f"the hardware owner-key backend is selected ({BACKEND_ENV}={kind}) but no PKCS#11 module is "
            f"configured ({MODULE_ENV}); refusing to fall back to a file key (fail-closed)")
    open_fn = opener if opener is not None else open_pkcs11_signer
    try:
        signer = open_fn(config)
    except HardwareKeyUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 — ImportError (no binding) / token absent / bad PIN / no key
        raise HardwareKeyUnavailable(
            f"the hardware owner-key backend is selected ({BACKEND_ENV}={kind}) but the PKCS#11 token "
            f"could not be opened ({type(exc).__name__}: {exc}); refusing to fall back to a file key "
            f"(fail-closed)") from exc
    if signer is None:
        raise HardwareKeyUnavailable(
            f"the PKCS#11 opener returned no token signer for {BACKEND_ENV}={kind} (fail-closed)")
    return Pkcs11Backend(signer, token_label=config.token_label, key_label=config.key_label,
                         module_path=config.module_path)


# ── doctor probe (read-only; NEVER opens the token / uses the PIN) ────────────────────────────────────
def describe_owner_backend(env: Optional[Mapping[str, str]] = None) -> "tuple[str, str]":
    """A read-only ``(STATE, detail)`` describing which backend holds the owner key, for ``vigil doctor``.

    Reads env and (for the hardware backend) checks the module file EXISTS — it does NOT open the token,
    use the PIN, or import ``pkcs11`` (no side effects). ``FILE`` (default), ``PKCS11`` (hardware selected
    and its module present), or a fail-closed ``PKCS11-UNCONFIGURED`` / ``PKCS11-MISSING-MODULE`` /
    ``UNKNOWN`` when the hardware backend is selected but unusable — in which case owner signing REFUSES
    rather than using a file key."""
    env = os.environ if env is None else env
    kind = str(env.get(BACKEND_ENV, "") or "").strip().lower()

    if kind in _FILE_ALIASES:
        return ("FILE",
                "owner key is a file-based Ed25519 key loaded into the process (the default). Set "
                f"{BACKEND_ENV}=pkcs11 to hold it in a hardware token instead.")

    if kind in _HARDWARE_ALIASES:
        module = str(env.get(MODULE_ENV, "") or "").strip()
        if not module:
            return ("PKCS11-UNCONFIGURED",
                    f"{BACKEND_ENV}={kind} selects a hardware token but {MODULE_ENV} is unset — owner "
                    "signing FAILS CLOSED (no file fallback) until the PKCS#11 module is configured")
        try:
            present = Path(module).is_file()
        except OSError:
            present = False
        if not present:
            return ("PKCS11-MISSING-MODULE",
                    f"{BACKEND_ENV}={kind}; PKCS#11 module {module} is not present — owner signing FAILS "
                    "CLOSED (no file fallback) until the token/module is available")
        label = str(env.get(KEY_LABEL_ENV, "") or "").strip() or _DEFAULT_KEY_LABEL
        return ("PKCS11",
                f"owner key held in a PKCS#11 hardware token (module {module}, key {label}); the token "
                "signs — the private key never enters the process")

    return ("UNKNOWN",
            f"{BACKEND_ENV}={kind!r} is not a recognized backend (expected 'file' or 'pkcs11')")


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────────
def _derive_public_key_b64(private_key_b64: str) -> str:
    """Derive the base64 Ed25519 public key from a base64 private key. Used only by the FILE backend
    (which already holds the private material); the hardware backend reads its public key from the token."""
    try:
        raw = base64.b64decode(private_key_b64, validate=True)
    except Exception as exc:  # noqa: BLE001 — a non-b64 private key is a provisioning error
        raise KeyBackendError(f"owner private key is not valid base64: {exc}") from exc
    if len(raw) != 32:
        raise KeyBackendError(f"owner private key decodes to {len(raw)} bytes, expected 32")
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(pub).decode("ascii")


# ── the REAL PKCS#11 opener — the irreducible hardware residual (env-gated / importorskip in tests) ────
def open_pkcs11_signer(config: Pkcs11Config) -> TokenSigner:  # pragma: no cover — needs a real token
    """Open a PKCS#11 token and return a :class:`TokenSigner` over its Ed25519 key.

    NOT EXERCISED IN CI: it requires a real PKCS#11 provider (an HSM / YubiKey / a SoftHSM2 token) and the
    ``pkcs11`` binding, neither present on a hosted runner. The env-gated live-token test drives it; the
    fail-closed selection logic above is fully tested with a fake opener. Any failure here propagates and
    :func:`_open_hardware_backend` converts it into a fail-closed :class:`HardwareKeyUnavailable`.

    The private key object is used only as a signing HANDLE — its bytes are ``CKA_SENSITIVE`` and never
    read into this process; only :meth:`TokenSigner.public_key_raw` reads the PUBLIC key object.
    """
    import pkcs11  # lazy: importing this module never requires the binding
    from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
    from pkcs11.util.ec import decode_ec_point

    lib = pkcs11.lib(config.module_path)
    if config.token_label:
        token = lib.get_token(token_label=config.token_label)
    else:
        token = next(iter(lib.get_tokens()))
    open_kwargs = {"user_pin": config.pin} if config.pin else {}
    session = token.open(**open_kwargs)

    label = config.key_label or _DEFAULT_KEY_LABEL
    priv = session.get_key(object_class=ObjectClass.PRIVATE_KEY, key_type=KeyType.EC_EDWARDS, label=label)
    pub = session.get_key(object_class=ObjectClass.PUBLIC_KEY, key_type=KeyType.EC_EDWARDS, label=label)

    class _Pkcs11TokenSigner:
        def sign(self, message: bytes) -> bytes:
            # C_Sign on the token with the Ed25519 (EdDSA) mechanism — the scalar stays on the token.
            return bytes(priv.sign(bytes(message), mechanism=Mechanism.EDDSA))

        def public_key_raw(self) -> bytes:
            # The public key object's EC point is a DER OCTET STRING wrapping the 32 raw pubkey bytes.
            return bytes(decode_ec_point(pub[Attribute.EC_POINT]))

    return _Pkcs11TokenSigner()
