"""governor.integrity — owner-signed integrity of the security-critical config + the WARDEN kernel
binary (audit G2).

The WARDEN kernel binary (``sigil-kernel``) IS the A0–A3 tier oracle the whole authorization stack
trusts: ``sigil-kernel classify <tool> --json`` is the authoritative danger classifier. Its path is
resolved from the UNSIGNED ``~/.sigil/sigil.env`` (env ``SIGIL_KERNEL_BIN``) with NO integrity check, so
a same-host attacker who rewrites that env — or plants a binary on ``PATH`` / in a build dir — silently
controls every tier decision. This module pins the kernel binary's CONTENT sha256 (plus the
security-critical ``SCOPE`` / ``OWNER_KEY_ID``) under an OWNER Ed25519 signature and verifies it before
the binary is ever executed.

Opt-in and non-bricking, mirroring the G1 vault posture:

  * NO manifest present  → a loud one-time WARNING; behaviour is byte-identical to today (the operator
    simply has not run ``sigil kernel pin`` yet). Every existing install / test stays green.
  * manifest present + kernel sha256 MATCHES → verified; the binary runs.
  * manifest present + kernel sha256 MISMATCH, OR the manifest's owner signature is absent / forged →
    FAIL-CLOSED: the kernel is NOT executed (the classifier resolves to A3, dispatch fails LOUD). A
    present-but-unsigned/forged manifest is treated as an ACTIVE tamper — a legitimately un-pinned
    install has NO manifest at all — never silently ignored.

Verification uses ONLY the owner PUBLIC key (:func:`identity.owner_pubkey`, which never mints trust);
signing uses the G1-sealable owner PRIVATE key (:func:`identity.ensure_owner_keypair`), reached only
when the operator runs the pin CLI. ``SCOPE`` / ``OWNER_KEY_ID`` drift is ADVISORY (surfaced by
``sigil doctor``), not fail-closed — those changes are caught downstream by the spine's own scope
binding, and a hard block there could brick a legitimate scope change; the kernel-binary hash is the
fail-closed leg.

Honest limitation (documented, not hidden): the check hashes the resolved path, then the caller executes
that same path — a same-host root attacker able to swap the file in that window defeats a single check
(a classic verify→exec TOCTOU). The pin's value is tamper-EVIDENCE + raising the bar (the attacker must
already hold owner-UID/root and win a race), not a same-host root sandbox, which the constitution does
not claim to provide.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .. import config
from .authn import signed_payload, verify_signed
from .identity import owner_pubkey

_log = logging.getLogger(__name__)

# The owner-signed security manifest lives at the SIGIL_HOME root — deliberately OUTSIDE spine/ (like
# floor.json) so a spine reset (`sigil ingest --reset`, which rmtrees spine/) never touches it.
MANIFEST_NAME = "security.manifest.json"
_MANIFEST_SCHEMA = 1
# The authenticated core fields (order-independent; canonicalized before signing / verifying).
_CORE_FIELDS = ("schema_version", "kernel_sha256", "scope", "owner_key_id")

# warn at most once per process that the kernel binary is unpinned (this runs on a hot path).
_warned_unpinned = False


def manifest_path() -> Path:
    return config.SIGIL_HOME / MANIFEST_NAME


def sha256_file(path: str | Path) -> Optional[str]:
    """Stream the file's bytes and return its sha256 hex, or None if it can't be read. Streamed in
    64 KiB chunks so hashing never loads an arbitrary-size file wholesale."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _read_manifest() -> tuple[str, Optional[dict]]:
    """Tri-state read of the security manifest — the distinction that keeps a corrupt-manifest attack
    fail-CLOSED rather than silently un-pinning the kernel:

      ``('absent', None)``  — no manifest file at all (a legitimately un-pinned install).
      ``('corrupt', None)`` — the file EXISTS but is unreadable / non-JSON / a non-object → an ACTIVE
                              tamper (``truncate`` / ``> file`` / a partial write), NEVER treated as un-pinned.
      ``('ok', dict)``      — a parsed JSON object (its owner signature is verified separately).
    """
    p = manifest_path()
    if not p.exists():
        return ("absent", None)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError:
        return ("corrupt", None)          # present but unreadable → suspicious, fail-closed
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return ("corrupt", None)          # present but not JSON → tamper
    if not isinstance(obj, dict):
        return ("corrupt", None)          # present but a JSON list / number / bool → tamper
    return ("ok", obj)


def load_manifest() -> Optional[dict]:
    """The parsed manifest object, or None if absent OR corrupt. (The exec gate + doctor, which must
    distinguish those two, use :func:`_read_manifest`; this is the convenience accessor.)"""
    state, obj = _read_manifest()
    return obj if state == "ok" else None


def _manifest_authentic(manifest: dict) -> bool:
    """True iff the manifest carries a valid OWNER signature over its core fields. Fail-closed: a
    missing owner pubkey, absent/forged signature, or tampered core → False."""
    return verify_signed(manifest, _CORE_FIELDS, owner_pubkey())


# ---------------------------------------------------------------------------------------------------
# Sign path (owner CLI only — `sigil kernel pin`)
# ---------------------------------------------------------------------------------------------------

def build_manifest(kernel_path: str | Path, owner_key, *, scope: str, owner_key_id: str) -> dict:
    """Owner-sign a manifest pinning ``kernel_path``'s CONTENT sha256 + the security-critical scope /
    owner_key_id. Raises :class:`ValueError` if the kernel binary can't be hashed (nothing to pin)."""
    digest = sha256_file(kernel_path)
    if digest is None:
        raise ValueError(f"cannot read kernel binary to pin: {kernel_path}")
    core = {
        "schema_version": _MANIFEST_SCHEMA,
        "kernel_sha256": digest,
        "scope": scope,
        "owner_key_id": owner_key_id,
    }
    return signed_payload(core, owner_key)


def write_manifest(manifest: dict) -> None:
    """Atomically persist the manifest (durable temp→fsync→replace; the file lands 0600). The manifest
    is PUBLIC (an owner signature over public metadata) — 0600 is defence-in-depth, not confidentiality."""
    from ..spine.atomicio import atomic_write_text  # lazy: keep the classify hot-path import light
    atomic_write_text(manifest_path(), json.dumps(manifest, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------------------------------
# Verify path (execution gate + doctor)
# ---------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class KernelVerdict:
    ok: bool         # True → safe to execute the resolved binary (verified / unpinned / nothing to run)
    status: str      # "verified" | "unpinned" | "unresolved" | "forged" | "unreadable" | "mismatch"
    detail: str


def verify_kernel_bin(resolved: Optional[str]) -> KernelVerdict:
    """Check an already-RESOLVED kernel path (what ``config.kernel_bin()`` returns, honouring the env
    override — i.e. exactly what WOULD execute) against the owner-signed pin. Fail-closed + non-bricking.

    ``ok=False`` means a pin is present and the binary fails it (or the manifest is forged): the caller
    MUST NOT execute the binary. ``ok=True`` with status ``unpinned`` preserves today's behaviour (with a
    loud one-time warning). ``resolved=None`` is ``ok=True`` — there is nothing to run and the classifier
    is already fail-closed to A3."""
    global _warned_unpinned
    state, manifest = _read_manifest()
    if state == "absent":
        if not _warned_unpinned:
            _warned_unpinned = True
            _log.warning("WARDEN kernel binary is NOT pinned — run `sigil kernel pin` to enable "
                         "tamper-evidence. Proceeding unpinned (behaviour unchanged).")
        return KernelVerdict(True, "unpinned", "kernel binary not pinned (run `sigil kernel pin`)")
    if state == "corrupt":
        return KernelVerdict(False, "corrupt",
                             "security manifest is present but unreadable/corrupt — refusing to run the "
                             "kernel (fail-closed; a legitimately un-pinned install has NO manifest)")
    if not _manifest_authentic(manifest):
        return KernelVerdict(False, "forged",
                             "security manifest present but its owner signature is absent/invalid — "
                             "refusing to run the kernel (fail-closed)")
    pinned = manifest.get("kernel_sha256")
    if not isinstance(pinned, str) or len(pinned) != 64:
        return KernelVerdict(False, "forged", "security manifest is missing a valid kernel_sha256")
    if resolved is None:
        return KernelVerdict(True, "unresolved", "no kernel binary resolved")
    actual = sha256_file(resolved)
    if actual is None:
        return KernelVerdict(False, "unreadable", f"cannot read kernel binary to verify: {resolved}")
    if actual == pinned:
        return KernelVerdict(True, "verified", "kernel binary matches the owner-signed pin")
    return KernelVerdict(False, "mismatch",
                         f"kernel binary sha256 {actual[:12]}… ≠ pinned {pinned[:12]}… — refusing to run")


def config_drift() -> list[str]:
    """ADVISORY (doctor only): warnings if the live ``SCOPE`` / ``OWNER_KEY_ID`` differ from the
    owner-signed manifest, or the manifest is present-but-forged. Empty when unpinned or in agreement.
    NOT fail-closed — a scope change is legitimate and is caught downstream by the spine's scope binding;
    this only makes a silent change visible."""
    state, manifest = _read_manifest()
    if state == "absent":
        return []
    if state == "corrupt":
        return ["security manifest is present but corrupt/unreadable (possible tamper)"]
    if not _manifest_authentic(manifest):
        return ["security manifest present but its owner signature is INVALID (possible tamper)"]
    out: list[str] = []
    if manifest.get("scope") != config.SCOPE:
        out.append(f"SCOPE changed since pinning: signed={manifest.get('scope')!r} live={config.SCOPE!r}")
    if manifest.get("owner_key_id") != config.OWNER_KEY_ID:
        out.append(f"OWNER_KEY_ID changed since pinning: signed={manifest.get('owner_key_id')!r} "
                   f"live={config.OWNER_KEY_ID!r}")
    return out


def kernel_pin_status() -> tuple[str, str]:
    """``(marker, detail)`` for ``sigil doctor``. marker: ``OK`` verified, ``**`` unpinned/unresolved
    (advisory), ``!!`` fail-closed (forged / mismatch / unreadable)."""
    verdict = verify_kernel_bin(config.kernel_bin())
    marker = {"verified": "OK", "unpinned": "**", "unresolved": "**"}.get(verdict.status, "!!")
    return marker, verdict.detail
