"""monitoring_secrets — sovereign per-(org, host) AEGIS-SaaS monitoring REPORT secrets (AE-6).

A tenant's managed gateway seals each monitoring report with HMAC-SHA256 under a secret dedicated to exactly one
(org_id, host). This module PROVISIONS that secret (random, 0600 file in a 0700 dir, hashed filename, atomic) and
RESOLVES it for the drainer (``sigil.inbound.monitoring_spool``). The secret is the stripped file content as bytes
— the same rule the gateway's ``--monitoring-secret-file`` loader applies, so the operator copies the file as-is.

Fail-closed resolver: anything but a bounded, owner-only regular file holding >= 16 bytes resolves to None (the
drainer then refuses the report). It is NOT an owner key and is never published. SOVEREIGN-only.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path
from typing import Optional

from ..reuse import assert_no_offense
from .asset_ownership import _check_host

assert_no_offense()

_MAX_BYTES = 4096
_MIN_SECRET = 16


def _check_org(org_id: str) -> str:
    if not isinstance(org_id, str) or not org_id.strip() or "\x00" in org_id or len(org_id) > 256:
        raise ValueError("a valid org_id is required")
    return org_id.strip()


def secret_filename(org_id: str, host: str) -> str:
    """Hashed (org, host) filename — no tenant/host text on disk, no path traversal."""
    digest = hashlib.sha256(_check_org(org_id).encode("utf-8") + b"\x00" + _check_host(host).encode("utf-8"))
    return digest.hexdigest() + ".secret"


def provision_report_secret(org_id: str, host: str, secrets_dir: "str | os.PathLike", *,
                            rotate: bool = False) -> Path:
    """Mint a fresh random report secret for (org_id, host). Refuses to overwrite an existing one unless
    ``rotate`` (rotation invalidates the deployed gateway's copy: its reports stop verifying until redeployed)."""
    d = Path(secrets_dir)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    path = d / secret_filename(org_id, host)
    if path.exists() and not rotate:
        raise FileExistsError("a report secret is already provisioned for this tenant/host (use rotate)")
    tmp = d / (".tmp-" + secrets.token_hex(8))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, (secrets.token_hex(32) + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return path


def resolve_report_secret(org_id: str, host: str, secrets_dir: "str | os.PathLike") -> Optional[bytes]:
    """The (org_id, host) report secret, or None (fail-closed) for anything not provisioned/well-formed."""
    try:
        path = Path(secrets_dir) / secret_filename(org_id, host)
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError):
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_size > _MAX_BYTES:
            return None
        data = os.read(fd, _MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    secret = data.strip()
    if len(data) > _MAX_BYTES or len(secret) < _MIN_SECRET:
        return None
    return secret


def resolver(secrets_dir: "str | os.PathLike"):
    """A ``SecretResolver`` for ``MonitoringSpoolWatcher(secret_for=...)`` bound to ``secrets_dir``."""
    def secret_for(org_id: str, host: str) -> Optional[bytes]:
        return resolve_report_secret(org_id, host, secrets_dir)
    return secret_for
