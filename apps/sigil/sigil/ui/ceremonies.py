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
are STRICTLY validated so neither reaches argv as a flag. `delegate_offense*` owner-sign a delegation over
the OFFENSE plane's PUBLIC identity (the identity JSON reaches argv only via a server-controlled temp file;
scope/hours validated). The remaining owner-key mutations (key rotate/re-genesis, warden-anchor-set, floor
reset) are wired in later slices. FATAL-2: pure sovereign — spawns `python -m sigil`, imports no
framework/strix.
"""
from __future__ import annotations

import base64
import json as _json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ..reuse import sha256_hex

# A device id / key id is a short slug — LEADING alnum so it can never be read as a flag; `\Z` (not `$`) so
# a trailing newline cannot smuggle a second token.
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
# A delegation scope — a leading alnum (never a flag) then a permissive-but-bounded charset; passed as one
# argv element (shell=False), so spaces/`:`/`/` are safe, only a leading `-` would be a flag.
_SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/ -]{0,127}\Z")


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


# --- OWNER-ONLY offense delegation (route gates `secrets`) — the owner blesses the OFFENSE plane's PUBLIC
#     identity. The identity JSON reaches argv only via a SERVER-controlled temp file (never a user path);
#     the certs written are PUBLIC (no private key). The owner key signs on the host. ------------------

_MAX_DELEG_HOURS = 24 * 365 * 10   # mirror cli.py cmd_delegate_offense's finite bound


def _valid_offense_identity(identity) -> "tuple[bool, str]":
    """Validate an offense-identity.json (schema 1 from `vigil identity`): a dict with schema==1 and a
    `spine` + `governance` block, each carrying a key_id slug + a base64-32B public_key_b64. No signing."""
    if not isinstance(identity, dict) or identity.get("schema") != 1:
        return False, "offense identity must be a JSON object with schema: 1 (exported by `vigil identity`)"
    for role in ("spine", "governance"):
        blk = identity.get(role)
        if not isinstance(blk, dict):
            return False, f"missing '{role}' block in the offense identity"
        kid, pub = blk.get("key_id"), blk.get("public_key_b64")
        if not isinstance(kid, str) or not _DEVICE_ID_RE.match(kid):
            return False, f"{role}.key_id must be a slug"
        if not _valid_pubkey(pub):
            return False, f"{role}.public_key_b64 must be base64 of a 32-byte Ed25519 key"
    return True, ""


def delegate_offense_preview(identity) -> dict:
    """PURE parse + validate (no subprocess, no signing): the two offense PUBLIC keys + key_ids the owner is
    about to bless. The operator confirms these OUT-OF-BAND against the offense host BEFORE signing — a
    swapped identity file would otherwise get an attacker's key owner-blessed (the CLI's own caveat)."""
    ok, err = _valid_offense_identity(identity)
    if not ok:
        return {"ok": False, "error": err}
    return {"ok": True,
            "spine": {"key_id": identity["spine"]["key_id"], "pubkey": identity["spine"]["public_key_b64"]},
            "governance": {"key_id": identity["governance"]["key_id"], "pubkey": identity["governance"]["public_key_b64"]}}


def delegate_offense(identity, scope, hours, home) -> dict:
    """`sigil delegate-offense` — owner-sign an offense-spine + offense-governance delegation cert over the
    offense PUBLIC identity. The identity JSON is written to a SERVER-controlled temp file and the out-dir is
    a server path under `home`, so NO user path reaches argv; scope (slug) + hours (finite, bounded) are
    validated. The owner key signs on the host; the certs are PUBLIC (no private key) and returned inline."""
    ok, err = _valid_offense_identity(identity)
    if not ok:
        return {"ok": False, "error": err}
    if not isinstance(scope, str) or not _SCOPE_RE.match(scope):
        return {"ok": False, "error": "scope must be a slug: a leading letter/digit then [A-Za-z0-9_.:/ -], <=128"}
    try:
        h = float(hours)
    except (TypeError, ValueError):
        return {"ok": False, "error": "hours must be a number"}
    if not (0 < h <= _MAX_DELEG_HOURS) or h != h or h in (float("inf"), float("-inf")):
        return {"ok": False, "error": f"hours must be a finite value in (0, {_MAX_DELEG_HOURS}]"}
    out_dir = Path(home) / "delegations" / (time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + os.urandom(3).hex())
    fd, tmp_path = tempfile.mkstemp(prefix="offense-identity-", suffix=".json")   # SERVER path, never user input
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            _json.dump(identity, fh)
        res = _run(["delegate-offense", "--offense-identity", tmp_path, "--scope", scope,
                    "--hours", repr(h), "--out-dir", str(out_dir)], timeout=60)
    finally:
        try:
            os.unlink(tmp_path)          # the offense identity is public, but keep no stray copy on disk
        except OSError:
            pass
    certs = {}
    for name in ("offense-spine.deleg.json", "offense-governance.deleg.json"):
        p = out_dir / name
        if p.exists():
            try:
                certs[name] = p.read_text(encoding="utf-8")[:8000]   # PUBLIC delegation cert (no private key)
            except OSError:
                pass
    res["out_dir"] = str(out_dir)
    res["certs"] = certs
    return res
