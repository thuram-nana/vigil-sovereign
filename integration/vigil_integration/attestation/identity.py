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
import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Callable, Optional

from vigil_core.crypto import KeyPair, generate_keypair, load_public_key, sign, verify_one
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

    A loaded public key is validated through ``load_public_key`` (rejecting non-canonical / low-order weak
    keys); a private key is validated by round-tripping a signature it must verify. Any problem — missing
    file, corrupt JSON, weak/invalid key — falls through to generating a FRESH keypair, so the operator
    always ends up with a sound signing identity. Persistence is best-effort (a fresh keypair is usable in
    memory this run even if the disk write fails).

    At-rest sealing (audit G1): if ``vault`` (a :class:`vigil_core.vault.Vault`) is supplied AND
    provisioned, the keypair file is AEAD-sealed at rest (else plaintext, unchanged). A sealed file that
    the TPM cannot unseal raises ``VaultLocked`` (fail-closed) rather than silently minting a NEW divergent
    operator identity."""
    p = Path(path) if path else DEFAULT_KEYPAIR_FILE
    loaded = _try_load_keypair(p, vault)
    if loaded is not None:
        return loaded
    kp = generate_keypair()
    _persist_keypair(p, kp, vault)
    return kp


def _try_load_keypair(p: Path, vault: object = None) -> Optional[KeyPair]:
    """Read + validate a persisted keypair, total. Returns None on any missing/corrupt/weak material. A
    sealed-but-unopenable file (locked TPM) propagates ``VaultLocked`` — fail-closed, never a silent new key."""
    if vault is not None:
        text = vault.read_text_secret(p, context=OPERATOR_KEYPAIR_CONTEXT)  # VaultLocked propagates
        if text is None:
            return None
        try:
            data = json.loads(text)
        except Exception:  # noqa: BLE001 — corrupt sealed/plaintext JSON → regenerate
            return None
    else:
        try:
            data = json.loads(p.read_text())
        except Exception:  # noqa: BLE001 — no file / unreadable / non-JSON → regenerate
            return None
    if not isinstance(data, dict):
        return None
    pub = data.get("public_key_b64")
    priv = data.get("private_key_b64")
    if not isinstance(pub, str) or not isinstance(priv, str) or not pub or not priv:
        return None
    try:
        load_public_key(pub)                       # rejects non-canonical / low-order weak keys
        probe = sign(priv, b"vigil-attestation-keypair-probe")  # validates the private key material
    except Exception:  # noqa: BLE001 — weak/invalid persisted key → regenerate rather than trust it
        return None
    if not verify_one(pub, b"vigil-attestation-keypair-probe", probe):
        return None                                # pub/priv are not a matched pair → regenerate
    return KeyPair(public_key_b64=pub, private_key_b64=priv)


def _persist_keypair(p: Path, kp: KeyPair, vault: object = None) -> None:
    """Atomically persist the keypair at 0600, best-effort (a disk failure never breaks minting). When a
    provisioned ``vault`` is supplied the keypair is AEAD-sealed at rest; else plaintext (unchanged)."""
    payload = json.dumps({"public_key_b64": kp.public_key_b64,
                          "private_key_b64": kp.private_key_b64})
    if vault is not None:
        try:
            vault.write_text_secret(p, payload, context=OPERATOR_KEYPAIR_CONTEXT)  # sealed iff enabled
        except Exception:  # noqa: BLE001 — best-effort; the in-memory keypair still works this run
            pass
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        # create the temp file 0600 from the start so the private key is never briefly world-readable.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, p)
        os.chmod(p, 0o600)
    except Exception:  # noqa: BLE001 — best-effort persistence; the in-memory keypair still works this run
        pass


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
