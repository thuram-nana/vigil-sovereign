"""model_grant_broker — the cross-plane seam that hands a customer run its MODEL GRANT (PRICING M1c; design §5.1).

When metered billing is on, the sovereign plane mints an owner-signed ``vigil_core.model_grant`` token for each
published launch lease and writes it here, next to the lease (``<base>/model-grants/<slug>.json``, 0600). The
offense worker that runs the launch reads it and gives its engine the token as its API key and the gateway URL as
its base URL; it never holds the provider key. At settle the sovereign plane removes it.

The token is a BEARER credential (whoever holds it can spend up to its run's cap until it expires), so the file is
0600 in a 0700 directory, written atomically, and never logged; it is bound to the launch ``nonce``, so a grant
for an old lease can never drive a newer re-lease of the same slug (:func:`read_model_grant` with
``expect_nonce``).

Pure stdlib + the lease seam's path guards; no ``framework`` / ``sigil`` import (FATAL-2): importable by both
planes.
"""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .credit_lease_broker import _atomic_write_json, _contained_child, _safe_component

__all__ = ["MODEL_GRANT_SCHEMA", "ModelGrantBundle", "grant_path", "grants_root", "read_model_grant",
           "remove_model_grant", "write_model_grant"]

_DIRNAME = "model-grants"
MODEL_GRANT_SCHEMA = "vigil-model-grant-seam-v1"
_MAX_BYTES = 16 * 1024


@dataclass(frozen=True)
class ModelGrantBundle:
    slug: str
    nonce: str
    token: str
    gateway_url: str

    def __repr__(self) -> str:                # never print the bearer token
        return f"ModelGrantBundle(slug={self.slug!r}, nonce={self.nonce!r}, gateway_url={self.gateway_url!r})"


def grants_root(base_dir: Any) -> Path:
    return Path(base_dir) / _DIRNAME


def grant_path(base_dir: Any, slug: str) -> Optional[Path]:
    """``<base>/model-grants/<slug>.json``, or None for a slug that is unsafe as a path component, or when a
    symlink in the file's place resolves to another file (the checked path keeps its own name, or is refused)."""
    safe = _safe_component(slug)
    if not safe:
        return None
    name = f"{safe}.json"
    p = _contained_child(grants_root(base_dir), name)
    if p is None or p.name != name:
        return None
    return p


_LOOPBACK_URL = re.compile(r"http://(?:127\.0\.0\.1|\[::1\]|localhost):([0-9]{1,5})/?")


def _check_url(url: str) -> str:
    """Exactly ``http://<loopback>:<port>`` (an optional trailing slash): nothing a client could read as another
    host (userinfo, a path, a query)."""
    u = str(url or "").strip()
    m = _LOOPBACK_URL.fullmatch(u)
    if m is None or not 1 <= int(m.group(1)) <= 65535:
        raise ValueError("the model gateway URL must be a loopback http URL")
    return u


def write_model_grant(base_dir: Any, slug: str, nonce: str, token: str, gateway_url: str) -> Path:
    """Write the grant for ``(slug, nonce)`` atomically (0600). Raises ``ValueError`` on an unsafe slug, an
    empty nonce / token, or a non-loopback gateway URL (the grant must only ever be spent through the local
    sovereign gateway)."""
    p = grant_path(base_dir, slug)
    if p is None:
        raise ValueError("unsafe engagement slug for the model-grant seam")
    if not str(nonce or "").strip() or not str(token or "").strip():
        raise ValueError("a model grant needs its launch nonce and its token")
    _atomic_write_json(p, {"schema": MODEL_GRANT_SCHEMA, "slug": str(slug), "nonce": str(nonce),
                           "token": str(token), "gateway_url": _check_url(gateway_url)})
    return p


def read_model_grant(base_dir: Any, slug: str, *, expect_nonce: Optional[str] = None) -> Optional[ModelGrantBundle]:
    """The grant published for ``slug`` (and, with ``expect_nonce``, only if it is for that launch), or None when
    there is none or it is malformed, oversized, not a regular file, or for another slug / launch. Never raises."""
    p = grant_path(base_dir, slug)
    if p is None:
        return None
    try:                                    # non-blocking: a planted FIFO can never hang the reader
        fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw = fh.read(_MAX_BYTES + 1) or b""
        if len(raw) > _MAX_BYTES:
            return None
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(doc, dict) or doc.get("schema") != MODEL_GRANT_SCHEMA or doc.get("slug") != str(slug):
        return None
    nonce, token, url = doc.get("nonce"), doc.get("token"), doc.get("gateway_url")
    if not all(isinstance(v, str) and v for v in (nonce, token, url)):
        return None
    if expect_nonce is not None and nonce != str(expect_nonce):
        return None
    try:
        url = _check_url(url)
    except ValueError:
        return None
    return ModelGrantBundle(slug=str(slug), nonce=nonce, token=token, gateway_url=url)


def remove_model_grant(base_dir: Any, slug: str, *, expect_nonce: Optional[str] = None) -> bool:
    """Remove the grant for ``slug`` (only the one for ``expect_nonce`` when given). Idempotent; True iff a file
    was removed."""
    if expect_nonce is not None and read_model_grant(base_dir, slug, expect_nonce=expect_nonce) is None:
        return False
    p = grant_path(base_dir, slug)
    if p is None:
        return False
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return False
