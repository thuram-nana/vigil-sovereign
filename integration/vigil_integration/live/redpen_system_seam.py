"""redpen_system_seam — the file-backed seam for owner-signed RED-PEN SYSTEM-REVIEW TICKETS (R4, transport).

The SOVEREIGN plane (``apps/sigil/sigil/ui/redpen_scheduler.py``) reserves + mints an owner-signed
``CreditLaunchLease`` for a WHOLE-REPOSITORY (System) review of a connected repository and drops a TICKET here; the
keyless INTEGRATION plane reads it back and ENQUEUES one ``SecurityJob(profile="full")`` per ticket (the authorized
runner + gate are the sole executors — a ticket grants NO bypass: the gate re-verifies the carried owner-signed lease
against its own pinned owner key before any work runs).

A System ticket is a SIBLING of the customer-launch lease (``credit_lease_broker``): it lives in its OWN directory so
a System review and a PR review (or a host launch) for the SAME repo never collide on the shared ``cust_<slug>`` key,
and it carries the SCOPE (``profile="full"``) that the ``CreditLaunchLease`` has no field for — so the integration
drain knows to enqueue a whole-tree job (not a diff job and not a host engagement).

  ``<base>/redpen-system-tickets/<slug>.json`` — the owner-signed bundle::

      { "schema_version": 1, "kind": "vigil-redpen-system-ticket-v1", "slug": "<slug>", "org_id": "<org>",
        "repo": "github.com/org/repo", "profile": "full",
        "signed_lease": { "document": {...}, "signatures": [...] },
        "trust_root": { "threshold": 1, "authorizers": [...] } }

Public-safe: only PUBLIC keys + signatures + the owner-authored lease/scope fields cross — no private key, ever.
FATAL-2 / import-clean: ``vigil_core`` + stdlib + the stdlib-only ``seam_lock`` discipline only (safe on either
plane; the offense reader holds no owner key — it only carries the lease to the gate, which verifies it).
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from vigil_core import SignedCreditLaunchLease, TrustRoot

__all__ = [
    "SystemTicketBundle",
    "tickets_root",
    "ticket_path",
    "write_system_ticket",
    "read_system_ticket",
    "list_system_tickets",
    "remove_system_ticket",
]

_TICKET_DIRNAME = "redpen-system-tickets"
_TICKET_SCHEMA = "vigil-redpen-system-ticket-v1"
_SCHEMA_VERSION = 1
PROFILE_FULL = "full"


# ---------------------------------------------------------------------------------------------------
# paths + safe id component (twin of credit_lease_broker._safe_component / _contained_child)
# ---------------------------------------------------------------------------------------------------


def tickets_root(base_dir: Any) -> Path:
    """The tickets root ``<base>/redpen-system-tickets`` (its OWN dir, so a ``*.json`` glob never picks up a
    credit-launch lease or a settlement marker)."""
    return Path(base_dir) / _TICKET_DIRNAME


def _safe_component(value: Any) -> str:
    """A filesystem-safe id component: no separators, no ``..``, no NUL/whitespace/control chars. "" if unsafe.
    Slugs are ``cust_<24hex>`` tokens in practice; this is defence-in-depth so a crafted slug can never escape
    the tickets dir."""
    s = str(value or "").strip()
    if not s or "/" in s or "\\" in s or ".." in s:
        return ""
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        return ""
    return s


def _contained_child(root: Path, filename: str) -> Optional[Path]:
    """``root/filename`` ONLY if it normalizes to a *direct* child of ``root``; else None. The resolved-path
    containment barrier CodeQL documents as the ``py/path-injection`` fix (basename strips any directory
    component, realpath normalizes ``..``/symlinks, the prefix test cannot be fooled, the dirname equality
    rejects any nested descendant). Returns the *checked* value so the guarded path is what flows to every sink."""
    root_real = os.path.realpath(str(root))
    name = os.path.basename(filename)
    if name != filename:  # a name carrying a directory component is REFUSED, never silently rewritten
        return None
    final = os.path.realpath(os.path.join(root_real, name))
    if not final.startswith(root_real + os.sep):
        return None
    if os.path.dirname(final) != root_real:
        return None
    return Path(final)


def ticket_path(base_dir: Any, slug: str) -> Optional[Path]:
    """The ticket path for ``slug`` (``<base>/redpen-system-tickets/<slug>.json``), or None if the slug is
    unsafe as a path component."""
    safe = _safe_component(slug)
    if not safe:
        return None
    return _contained_child(tickets_root(base_dir), f"{safe}.json")


def _atomic_write_json(path: Path, obj: dict) -> None:
    """Atomically write ``obj`` as canonical JSON at ``path`` (0600, fsync'd, then ``os.replace``)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    tmp = path.parent / (path.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp), str(path))
    finally:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------------
# the signed bundle (public-safe — signatures + public keys + the owner-authored lease/scope fields only)
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SystemTicketBundle:
    slug: str
    org_id: str
    repo: str
    profile: str
    signed_lease: SignedCreditLaunchLease
    trust_root: TrustRoot


def write_system_ticket(base_dir: Any, slug: str, *, org_id: str, repo: str,
                        signed_lease: SignedCreditLaunchLease, trust_root: TrustRoot,
                        profile: str = PROFILE_FULL) -> Path:
    """Write the owner-signed System-review ticket for ``slug`` (one ticket per repo; re-writing the same slug
    REPLACES it — a later period's ticket supersedes an unconsumed earlier one). Raises ValueError on an unsafe
    slug (never writes outside the tickets dir). The bundle carries only public material."""
    safe = _safe_component(slug)
    if not safe:
        raise ValueError(f"unsafe ticket slug: {slug!r}")
    path = _contained_child(tickets_root(base_dir), f"{safe}.json")
    if path is None:  # containment barrier — unreachable for a _safe_component-clean slug, kept fail-closed
        raise ValueError(f"unsafe ticket slug (escapes tickets dir): {slug!r}")
    obj = {
        "schema_version": _SCHEMA_VERSION,
        "kind": _TICKET_SCHEMA,
        "slug": safe,
        "org_id": str(org_id),
        "repo": str(repo),
        "profile": str(profile or PROFILE_FULL),
        "signed_lease": signed_lease.model_dump(mode="json"),
        "trust_root": trust_root.model_dump(mode="json"),
    }
    _atomic_write_json(path, obj)
    return path


def _read_ticket_file(path: Path) -> Optional[SystemTicketBundle]:
    """Parse one ticket file, fail-closed to None on any read/parse/validation error (an unreadable or malformed
    ticket is simply 'no ticket', never a partial-trust default). Does NOT verify the signature — that is the
    gate's job against the pinned owner key."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("kind") != _TICKET_SCHEMA:
        return None
    slug = _safe_component(obj.get("slug"))
    org_id = str(obj.get("org_id") or "")
    repo = str(obj.get("repo") or "")
    profile = str(obj.get("profile") or PROFILE_FULL)
    if not slug or not org_id or not repo:
        return None
    try:
        signed = SignedCreditLaunchLease.model_validate(obj["signed_lease"])
        trust_root = TrustRoot.model_validate(obj["trust_root"])
    except (KeyError, TypeError, ValueError):
        return None
    return SystemTicketBundle(slug=slug, org_id=org_id, repo=repo, profile=profile,
                              signed_lease=signed, trust_root=trust_root)


def read_system_ticket(base_dir: Any, slug: str) -> Optional[SystemTicketBundle]:
    """Read the owner-signed System-review ticket for ``slug`` (public material only; the CALLER's gate verifies
    the lease signature against the pinned owner key). None if absent, unsafe, or malformed."""
    path = ticket_path(base_dir, slug)
    if path is None or not path.is_file():
        return None
    return _read_ticket_file(path)


def list_system_tickets(base_dir: Any) -> "list[SystemTicketBundle]":
    """Every readable System-review ticket. Globs the tickets dir (a glob child is always a real entry — no
    traversal), skipping any unreadable/malformed file. Total; never raises."""
    out: "list[SystemTicketBundle]" = []
    try:
        for fp in sorted(tickets_root(base_dir).glob("*.json")):
            b = _read_ticket_file(fp)
            if b is not None:
                out.append(b)
    except OSError:
        pass
    return out


def remove_system_ticket(base_dir: Any, slug: str, expect_nonce: Any = None) -> bool:
    """Remove the published ticket for ``slug`` so ``read_system_ticket`` returns None. Idempotent + total: True
    if a ticket was removed, False if none/unsafe, never raises on a missing file. When ``expect_nonce`` is given
    the ticket is removed ONLY if its signed lease ``nonce`` MATCHES — so settling an OLD ticket never clobbers a
    concurrently-written newer one (same slug, new period/nonce); a non-matching OR unreadable ticket is left."""
    path = ticket_path(base_dir, slug)
    if path is None or not path.is_file():
        return False
    if expect_nonce is not None:
        bundle = _read_ticket_file(path)
        try:
            on_disk = str(bundle.signed_lease.document.nonce) if bundle is not None else None
        except Exception:  # noqa: BLE001 — an unreadable ticket: treat as non-matching, leave it (fail-safe)
            on_disk = None
        if on_disk != str(expect_nonce):
            return False
    try:
        os.unlink(str(path))
        return True
    except OSError:
        return False
