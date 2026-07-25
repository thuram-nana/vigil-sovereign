"""
attestation.identity — operator identity resolution + the persisted operator keypair (VIGIL WS6).

The ledger's non-repudiation anchor is an operator Ed25519 keypair, generated on first use and persisted
(``0600``) so the same box always signs under the same identity. This module:

  * loads-or-creates that keypair (:func:`load_or_create_operator_keypair`), validating a loaded public
    key through the shared ``vigil_core.crypto.load_public_key`` (which rejects non-canonical / low-order
    weak keys — a keyless-forgery vector), and generating a fresh one if the file is missing/corrupt;
  * derives the FINGERPRINT (sha256-hex of the raw public key) that binds a signature's ``key_id`` to the
    operator identity;
  * resolves the live :class:`OperatorIdentity` — OS login, git ``user.name``/``user.email``, hostname —
    each via a total, injectable reader (git config is read with an argv-list subprocess, never a shell);
  * builds the injected ``signer`` (a closure over the private key that returns a ``Signature`` whose
    ``key_id`` is the fingerprint — reusing ``vigil_core.crypto.sign``, which is deterministic Ed25519, no
    RNG) and the matching ``resolve_key`` trust anchor (fingerprint → the trusted public key) that
    :func:`verify_ledger` uses.

Key GENERATION uses the platform CSPRNG once at provisioning — that is not the chain math (no wallclock/RNG
touches ordering or per-record signing, which is deterministic Ed25519). Every resolver is total: an
unreadable git/hostname/login degrades to ``""``, never a crash.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import socket
import subprocess
from pathlib import Path
from typing import Callable, Optional

from vigil_core.crypto import KeyPair, sign
from vigil_core.keystore import load_or_create_sealed_keypair
from vigil_core.models import Signature

from .anchor import DEFAULT_STATE_DIR
from .models import OperatorIdentity

# Default persisted operator keypair (JSON: {public_key_b64, private_key_b64}), 0600, under the state home.
DEFAULT_KEYPAIR_FILE: Path = DEFAULT_STATE_DIR / "operator.key"
# AEAD purpose-binding context for the sealed operator keypair (audit G1) — a blob sealed here can never
# be opened as another secret.
OPERATOR_KEYPAIR_CONTEXT = b"vigil/operator.key"

# signer(message: bytes) -> Signature   (key_id == operator fingerprint). The injected signing seam.
SignerFn = Callable[[bytes], Signature]
# resolve_key(key_id: str) -> the trusted public_key_b64 for that fingerprint, or None if untrusted.
ResolveKeyFn = Callable[[str], Optional[str]]

# Injectable readers so the live-substrate reads are stubbable in tests. Each is total.
GitReader = Callable[[str], str]


def fingerprint(public_key_b64: str) -> str:
    """The operator key fingerprint: sha256-hex of the raw 32-byte Ed25519 public key. Total — a
    malformed key yields ``""`` (an unbindable identity), never an exception."""
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except Exception:  # noqa: BLE001 — a non-b64 key is unusable; degrade to an empty fingerprint
        return ""
    if len(raw) != 32:
        return ""
    return hashlib.sha256(raw).hexdigest()


def load_or_create_operator_keypair(*, path: Optional[str] = None, vault: object = None) -> KeyPair:
    """Load the persisted operator keypair, or generate and persist one (0600) on first use.

    Thin wrapper over the shared :func:`vigil_core.keystore.load_or_create_sealed_keypair` (the ONE reviewed
    load/validate/persist/seal implementation), bound to the operator AEAD context so an operator blob can
    never be opened as another secret. Validation (weak-key rejection + priv/pub round-trip), best-effort
    persistence, and fail-closed-on-locked-TPM behaviour are exactly as before — unchanged."""
    p = str(path) if path else str(DEFAULT_KEYPAIR_FILE)
    return load_or_create_sealed_keypair(path=p, context=OPERATOR_KEYPAIR_CONTEXT, vault=vault)


def _os_login() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 — no resolvable login (empty env) → unknown, never a crash
        return ""


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:  # noqa: BLE001 — hostname unresolvable → unknown
        return ""


def _git_config(key: str) -> str:
    """Read a git config value via an argv-list subprocess (no shell, no interpolation). Total: a missing
    git / unset key / any failure degrades to ``""``."""
    try:
        proc = subprocess.run(  # noqa: S603,S607 — fixed argv, ``key`` is a caller-literal config name
            ["git", "config", "--get", key], capture_output=True, text=True, timeout=5, check=False,
        )
    except Exception:  # noqa: BLE001 — no git binary / spawn failure → unknown
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def resolve_operator(
    *,
    keypair_path: Optional[str] = None,
    keypair: Optional[KeyPair] = None,
    os_login: Optional[str] = None,
    git_name: Optional[str] = None,
    git_email: Optional[str] = None,
    hostname: Optional[str] = None,
    git_reader: Optional[GitReader] = None,
) -> OperatorIdentity:
    """Resolve the live operator identity, binding it to the persisted keypair's fingerprint.

    Each human field is read from the box unless overridden (all overrides are for tests / an explicit
    caller): ``os_login`` via ``getpass``, git name/email via ``git config`` (or an injected ``git_reader``),
    and hostname via ``socket``. The key fingerprint is always the persisted operator key's. Total: any
    unreadable field is ``""`` and the identity is still returned (its :meth:`~OperatorIdentity.is_bound`
    reflects whether it is usable)."""
    kp = keypair if keypair is not None else load_or_create_operator_keypair(path=keypair_path)
    reader = git_reader if git_reader is not None else _git_config
    return OperatorIdentity(
        os_login=os_login if os_login is not None else _os_login(),
        git_name=git_name if git_name is not None else _read_git(reader, "user.name"),
        git_email=git_email if git_email is not None else _read_git(reader, "user.email"),
        key_fingerprint=fingerprint(kp.public_key_b64),
        hostname=hostname if hostname is not None else _hostname(),
    )


def _read_git(reader: GitReader, key: str) -> str:
    """Call an injected git reader totally — a raising custom reader degrades to ``""``."""
    try:
        v = reader(key)
    except Exception:  # noqa: BLE001 — a misbehaving reader is treated as "unknown"
        return ""
    return v if isinstance(v, str) else ""


def operator_signer(*, keypair_path: Optional[str] = None, keypair: Optional[KeyPair] = None) -> SignerFn:
    """Build the injected ``signer`` bound to the persisted operator key: it signs a message with the
    private key (deterministic Ed25519) and returns a ``Signature`` whose ``key_id`` is the operator
    fingerprint — so the record's signature is provably the bound operator's."""
    kp = keypair if keypair is not None else load_or_create_operator_keypair(path=keypair_path)
    fp = fingerprint(kp.public_key_b64)
    priv = kp.private_key_b64

    def _signer(message: bytes) -> Signature:
        return Signature(key_id=fp, signature_b64=sign(priv, message))

    return _signer


def operator_key_resolver(
    *, keypair_path: Optional[str] = None, keypair: Optional[KeyPair] = None,
) -> ResolveKeyFn:
    """Build the trust anchor :func:`verify_ledger` consults: it maps the operator fingerprint to that
    operator's public key and returns None for any other ``key_id`` — so only signatures under the box's
    own persisted operator key verify (a forged entry signed by an unknown key is rejected)."""
    kp = keypair if keypair is not None else load_or_create_operator_keypair(path=keypair_path)
    fp = fingerprint(kp.public_key_b64)
    pub = kp.public_key_b64

    def _resolve(key_id: str) -> Optional[str]:
        return pub if key_id == fp else None

    return _resolve
