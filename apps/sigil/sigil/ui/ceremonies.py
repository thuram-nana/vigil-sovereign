"""Wave 10 (parity) — surface the sovereign KEY-MATERIAL CEREMONY *status* + run the safe owner ceremonies
in the browser. Shells THIS venv's `sigil <verb> [subcmd]` (FIXED argv, no request input, shell=False) and
returns its text.

READS (OPERATOR+, the same `config_nonsecret` tier as `/api/doctor`, enforced at the route) — every status
here prints only PUBLIC key material + at-rest sealing METADATA (owner pubkey, succession epochs, KEK/DEK/
warden sealed-state, kernel pin, config drift) — never a private key or secret, and none unseal the private
key; but `key status` also surfaces absolute sealed-key file PATHS + the SEALED/PLAINTEXT posture + per-
account TOTP labels, the same operational/FS-layout class doctor gates to operator+.

MUTATIONS (OWNER-ONLY `secrets`, enforced at the route) — reuse the AUDITED CLI ceremony so no signing/
sealing is re-implemented here; the owner key is sealed on the host and never crosses. `vault_provision`
(TPM-seal a fresh KEK) + `kernel_pin` (owner-sign the kernel binary hash) are ZERO-arg. `mesh_*` enroll a
phone DEVICE key: `mesh_fingerprint` is a PURE preview the operator eyeball-matches (anti key-swap),
`mesh_authorize`/`mesh_revoke` owner-sign the mesh ledger — their device_id (slug) + pubkey (base64-32B)
are STRICTLY validated so neither reaches argv as a flag. The remaining owner-key mutations
(key rotate/re-genesis, warden-anchor-set, delegate-offense, floor reset) are wired in later slices.
FATAL-2: pure sovereign — spawns `python -m sigil`, imports no framework/strix.
"""
from __future__ import annotations

import base64
import re
import subprocess
import sys

from ..reuse import sha256_hex

# A device id is a short slug — LEADING alnum so it can never be read as a flag; `\Z` (not `$`) so a
# trailing newline cannot smuggle a second token.
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def _valid_pubkey(pubkey) -> bool:
    """A device pubkey is base64 (standard alphabet — NO '-', so it can never be a flag) that decodes to
    EXACTLY 32 bytes (Ed25519). Rejecting anything else BEFORE argv means the value is always a plain
    positional (shell=False, no leading '-')."""
    if not isinstance(pubkey, str) or not (1 <= len(pubkey) <= 128):
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", pubkey):
        return False
    try:
        return len(base64.b64decode(pubkey, validate=True)) == 32
    except ValueError:      # binascii.Error subclasses ValueError (bad padding / length)
        return False


def _run(argv_tail: list, timeout: int = 30) -> dict:
    # FIXED argv — every element is a literal here (never request-controlled); shell=False.
    verb = argv_tail[0]
    try:
        proc = subprocess.run([sys.executable, "-m", "sigil", *argv_tail],   # noqa: S603 — fixed argv, shell=False
                              capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": proc.returncode == 0, "verb": verb, "exit_code": proc.returncode,
            "text": (proc.stdout or "")[:8000], "stderr": (proc.stderr or "")[:1000]}


def vault_status() -> dict:
    """`sigil vault status` — at-rest sealing of the trust root under the TPM-sealed KEK (provisioned?)."""
    return _run(["vault", "status"])


def kernel_status() -> dict:
    """`sigil kernel status` — the WARDEN kernel integrity pin + config drift (owner-signed manifest state)."""
    return _run(["kernel", "status"])


def key_status() -> dict:
    """`sigil key status` — the owner-key succession chain (pinned genesis -> epochs -> validated tip) + the
    per-key at-rest sealing state. PUBLIC keys + metadata only; fail-closed on a forked/tampered chain."""
    return _run(["key", "status"])


def owner_pubkey_show() -> dict:
    """`sigil owner-pubkey` — the base64 owner PUBLIC key (the private half never leaves the sovereign store)."""
    return _run(["owner-pubkey"])


# --- OWNER-ONLY mutations (route gates `secrets`) — ZERO-arg, reuse the audited CLI ceremony ----------

def vault_provision() -> dict:
    """`sigil vault provision` — TPM-seal a FRESH KEK to this machine so the trust root + secrets seal at
    rest (owner ceremony; zero-arg, idempotent — a no-op if a KEK is already present). Fixed argv; the CLI
    does the sealing on the host, the browser sees only the secret-free status text."""
    return _run(["vault", "provision"], timeout=60)


def kernel_pin() -> dict:
    """`sigil kernel pin` — owner-sign the resolved WARDEN kernel binary's content hash into the security
    manifest (owner ceremony; zero-arg). Fails CLOSED if the vault is locked (it will NOT mint a new owner
    identity over the old one). Fixed argv; output is secret-free (path + sha256 + scope)."""
    return _run(["kernel", "pin"], timeout=60)


# --- OWNER-ONLY mesh device enrollment (route gates `secrets`) — device_id + pubkey are STRICTLY validated
#     (slug + base64-32B) so neither can be a flag; the audited `sigil mesh` verb owner-signs the ledger ---

def mesh_fingerprint(pubkey) -> dict:
    """PURE preview (no signing, no ledger write, no subprocess): the device fingerprint the operator
    eyeball-matches against what the phone shows BEFORE authorizing — this defeats a key swap. Byte-identical
    to the CLI's `_device_fingerprint` (sha256_hex(pubkey)[:16], dashed)."""
    if not _valid_pubkey(pubkey):
        return {"ok": False, "error": "pubkey must be base64 of a 32-byte Ed25519 key"}
    short = sha256_hex(pubkey.encode())[:16]
    return {"ok": True, "pubkey": pubkey, "fingerprint": "-".join(short[i:i + 4] for i in range(0, 16, 4))}


def mesh_list() -> dict:
    """`sigil mesh list-devices` — the currently-authorized device roster (owner-signed authorize minus
    revoke; device_id + fingerprint, both public). A fail-closed read; no signing."""
    return _run(["mesh", "list-devices"])


def mesh_authorize(device_id, pubkey) -> dict:
    """`sigil mesh authorize <device_id> <pubkey> --yes` — owner-sign a device authorization into the mesh
    ledger. `--yes` is safe here ONLY because the UI already showed the fingerprint and made the operator
    confirm the eyeball-match. device_id (slug) + pubkey (base64-32B) are validated → neither can be a flag."""
    if not isinstance(device_id, str) or not _DEVICE_ID_RE.match(device_id):
        return {"ok": False, "error": "device id must be a slug: a leading letter/digit then [A-Za-z0-9_.-], <=64"}
    if not _valid_pubkey(pubkey):
        return {"ok": False, "error": "pubkey must be base64 of a 32-byte Ed25519 key"}
    return _run(["mesh", "authorize", device_id, pubkey, "--yes"], timeout=60)


def mesh_revoke(device_id, pubkey) -> dict:
    """`sigil mesh revoke <device_id> <pubkey>` — owner-sign a device revocation. Same strict validation."""
    if not isinstance(device_id, str) or not _DEVICE_ID_RE.match(device_id):
        return {"ok": False, "error": "device id must be a slug: a leading letter/digit then [A-Za-z0-9_.-], <=64"}
    if not _valid_pubkey(pubkey):
        return {"ok": False, "error": "pubkey must be base64 of a 32-byte Ed25519 key"}
    return _run(["mesh", "revoke", device_id, pubkey], timeout=60)
