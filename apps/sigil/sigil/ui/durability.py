"""Wave 3 (durability) — orchestrate `sigil backup` / `sigil restore` from the browser, in-process.

OWNER-ONLY (the routes gate backup on `secrets`, restore on `offense_authority`). The operator supplies the
backup PASSPHRASE per request; it is used TRANSIENTLY to encrypt/decrypt and is NEVER stored, logged (the
sovereign server's `log_message` is a no-op), audited, or echoed back. The owner private key + spine DEK never
leave the host — `create_backup`/`restore_backup` read them in-process through the owner vault. Restore ALWAYS
targets a FRESH staging home under `<home>/restored/` — NEVER the live SIGIL_HOME in-place; the operator
promotes the verified staging tree deliberately, out of band. `resolve_backup` is path-traversal-safe: it
serves ONLY a file that both matches the exact minted name shape AND resolves directly inside the backups dir.
"""
from __future__ import annotations

import re
import secrets as _secrets
import time
from pathlib import Path

# The ONLY filename shape we mint and will serve: backup-YYYYMMDD-HHMMSS-<hex6>.enc. Anchored, no separators
# other than the literal dashes — so a traversal / absolute-path `id` can never match.
_BACKUP_NAME = re.compile(r"^backup-\d{8}-\d{6}-[0-9a-f]{6}\.enc$")

_MIN_PASSPHRASE = 8


def backups_dir(home: Path) -> Path:
    d = Path(home) / "backups"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def _stamp() -> str:
    # a runtime filename stamp (NOT deterministic learning/spine math — a normal server action)
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def _new_name() -> str:
    # the random suffix avoids a same-second collision and is unguessable
    return f"backup-{_stamp()}-{_secrets.token_hex(3)}.enc"


def run_backup(passphrase: str, *, home: Path) -> dict:
    """Encrypt the trust root + spine to a new server-side archive, in-process. Returns a secret-free summary
    (never the passphrase). The archive is downloadable via `resolve_backup`."""
    from .. import config  # noqa: F401  (kept for parity with other ui modules; home is passed explicitly)
    from ..backup import create_backup
    from ..governor.identity import ensure_owner_keypair
    from ..platform.vault import owner_vault

    if not isinstance(passphrase, str) or len(passphrase) < _MIN_PASSPHRASE:
        raise ValueError(f"passphrase must be at least {_MIN_PASSPHRASE} characters")
    dest = backups_dir(home) / _new_name()
    res = create_backup(dest, passphrase, home=Path(home), vault=owner_vault(), owner_key=ensure_owner_keypair())
    st = dest.stat()
    return {"id": dest.name, "filename": dest.name, "size": st.st_size, "files": res.get("files"),
            "owner_key": res.get("owner_key"), "dek": res.get("dek"), "secrets_kv": res.get("secrets_kv")}


def list_backups(home: Path) -> list[dict]:
    """List the server-side backups (newest first) — id/size/created only; no secret, no passphrase."""
    d = backups_dir(home)
    out: list[dict] = []
    for p in sorted(d.glob("backup-*.enc"), reverse=True):
        if not _BACKUP_NAME.match(p.name):
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        out.append({"id": p.name, "filename": p.name, "size": st.st_size, "created": int(st.st_mtime)})
    return out


def resolve_backup(home: Path, backup_id: str) -> "Path | None":
    """Path-traversal-safe: return the archive Path ONLY when `backup_id` matches the exact minted shape AND
    resolves to a regular file directly inside the backups dir. Anything else → None (never serve it)."""
    if not isinstance(backup_id, str) or not _BACKUP_NAME.match(backup_id):
        return None
    d = backups_dir(home).resolve()
    p = (d / backup_id).resolve()
    if p.parent != d or not p.is_file():        # strict containment + must exist
        return None
    return p


def run_restore(passphrase: str, backup_id: str, *, home: Path) -> dict:
    """Decrypt + VERIFY a backup and stage it into a FRESH `<home>/restored/restore-…` tree (NEVER the live
    home in-place). `restore_backup` fail-closes on a wrong passphrase / any tamper before writing anything.
    Returns the verified staging path for the operator to promote deliberately."""
    from vigil_core.vault import Vault

    from ..backup import restore_backup

    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("passphrase required")
    src = resolve_backup(home, backup_id)
    if src is None:
        raise ValueError("unknown backup id")
    staging = Path(home) / "restored" / f"restore-{_stamp()}-{_secrets.token_hex(3)}"
    staging.parent.mkdir(parents=True, exist_ok=True)
    res = restore_backup(src, staging, passphrase, vault=Vault(staging / "vault"))
    return {"home": str(res.get("home", staging)), "files": res.get("files"),
            "verified": res.get("verified"), "backup_id": backup_id}
