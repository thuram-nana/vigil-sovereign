"""Persistent owner BOOTSTRAP token for the glass cockpit (Slice 1b).

The cockpit used to mint a FRESH `secrets.token_urlsafe(24)` on every start (`cmd_serve`), so a service
restart rotated the owner's `?token=` URL and a bookmarked link went stale — the "my session token changes
on restart" pain. In the DEFAULT (dev/local) posture we now persist the token to an owner-only 0600 file
under `SIGIL_HOME/.vigil-live/`, so a restart LOADS the same token and the same URL keeps working.

Scope + non-goals (deliberate, so this stays a small, sound slice):
  * DEV/LOCAL posture only. In PRODUCTION posture the cockpit keeps minting an ephemeral token that grants
    nothing (the legacy owner-token path is disabled by `vigil_core.posture`); a persistent bootstrap token
    must NEVER become the production security boundary — that is the passkey/cookie session (Slice 1c).
  * Rotation/revocation here are FILE operations that take effect on the next cockpit start. We do NOT
    mutate a running server's live token, because under `vigil up` the reverse proxy scraped the token at
    startup and re-injects it when relaying — live-rotating the cockpit token would desync the proxy and
    lock the operator out. A deliberate restart (or `vigil up`) re-reads the file cleanly.

Mirrors the gateway proxy-token persistence (`gateway/vigil_gateway/docker.py::mint_proxy_token`): the temp
file is created 0600 BEFORE the secret is written (no world-readable window), then atomically replaced.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from ..config import SIGIL_HOME

# Owner-only, under the per-home live dir (the sovereign analogue of the offense `.vigil-live`).
BOOTSTRAP_TOKEN_RELPATH = os.path.join(".vigil-live", "cockpit-bootstrap-token")


def bootstrap_token_path(home: "Optional[Path]" = None) -> Path:
    """The 0600 file that persists the cockpit bootstrap token, under `SIGIL_HOME/.vigil-live/`."""
    return (home or SIGIL_HOME) / BOOTSTRAP_TOKEN_RELPATH


def _write_atomic_0600(path: Path, token: str) -> bool:
    """Persist `token` to `path` atomically at mode 0600. Returns True on success, False on any OSError
    (fail-safe: the caller then falls back to an ephemeral in-memory token — never a crash on a read-only
    or unwritable home)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # A UNIQUE temp name opened with O_CREAT|O_EXCL|O_NOFOLLOW: refuse to open (and so never follow or
        # clobber) a symlink or a pre-existing file planted at the temp path — a hardening OVER the gateway
        # proxy-token pattern this mirrors. The unique suffix avoids colliding with a stale temp.
        tmp = path.with_name(f"{path.name}.{secrets.token_hex(8)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp), flags, 0o600)
        try:
            os.write(fd, (token + "\n").encode("ascii"))
        finally:
            os.close(fd)
        os.replace(tmp, path)   # atomic; REPLACES (does not follow) any symlink at the final path
        try:
            os.chmod(path, 0o600)   # belt-and-suspenders: the final file is owner-only
        except OSError:
            pass
        return True
    except OSError:
        return False


def load_bootstrap_token(path: "Optional[Path]" = None) -> "Optional[str]":
    """Read the persisted bootstrap token, or None if absent/unreadable/empty (fail-safe: a missing token
    means 'mint a fresh one', never an error)."""
    try:
        raw = (path or bootstrap_token_path()).read_text(encoding="ascii")
    except (OSError, ValueError):
        return None
    return raw.strip() or None


def mint_bootstrap_token(path: "Optional[Path]" = None) -> str:
    """Mint a fresh bootstrap token and persist it 0600. Returns the token even if the write failed (the
    cockpit still gets a usable in-memory token for this run; it just will not survive the next restart)."""
    p = path or bootstrap_token_path()
    token = secrets.token_urlsafe(32)
    _write_atomic_0600(p, token)
    return token


def resolve_bootstrap_token(*, override: "Optional[str]" = None, path: "Optional[Path]" = None) -> str:
    """The dev-posture boot rule: an explicit override (a `--token` flag or `$SIGIL_BOOTSTRAP_TOKEN`) wins
    and is persisted so it survives too; otherwise LOAD the persisted token; otherwise MINT and persist a
    fresh one. The result is stable across restarts."""
    p = path or bootstrap_token_path()
    if override:
        tok = str(override).strip()
        if tok:
            _write_atomic_0600(p, tok)
            return tok
    return load_bootstrap_token(p) or mint_bootstrap_token(p)


def revoke_bootstrap_token(path: "Optional[Path]" = None) -> bool:
    """Delete the persisted token so the NEXT cockpit start mints a fresh one (the old `?token=` URL is then
    dead). Returns True if a file was removed. Effective on the next restart (see the module note on why we
    do not mutate a running server's live token)."""
    p = path or bootstrap_token_path()
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False
