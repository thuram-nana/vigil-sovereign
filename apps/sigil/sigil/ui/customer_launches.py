"""customer_launches — an org's assessment launches as the customer app shows and controls them (C1a).

A customer launches an assessment from the app in two calls: ``launch/reserve`` (the LaunchGate reserves credits and
owner-signs a CreditLaunchLease) then ``launch/start`` (the lease is published to the cross-plane seam). Every later
control — start, cancel, pause, resume — must present that signed lease, so the app must never depend on holding it in
memory. This module gives it back, while ``VIGIL_CUSTOMER_LAUNCH_UI`` is on:

  * KEPT RESERVATIONS (``remember`` / ``forget``): the provisioner keeps each lease a customer reserves until it is
    started or cancelled — one small JSON file per (org, target) under ``config.CUSTOMER_LAUNCHES_DIR``, named by a
    domain-separated sha256 (no org id or host in a path), at most ``_PER_TARGET`` leases, newest first, written
    atomically (the temp file is 0600) in a 0700 directory. It is a CACHE of owner-signed documents the customer was
    already handed by ``launch/reserve``, never money and never authority: a lease runs only once ``launch/start``
    publishes it (membership, tenant binding and step-up are checked there), and every read below re-verifies each
    lease under the pinned owner key. A missing, unreadable or malformed file reads as "nothing kept". Like the rest of
    ``customer/`` it is not in a backup (``backup._EXCLUSION_REASONS``): a restore forgets launches that were reserved
    and never started, exactly as before this module existed.
  * THE READ (``launches``): for every host the org has EVER proven (a launch outlives a proof that lapses while it
    runs), the lease the seam holds for it — ``running``, or ``paused`` per the fail-closed pause reader — and the kept
    leases not started yet (``reserved``). A settled launch is never active: every settle records the seam's
    settlement marker before it moves any money. Finished launches are the settle drain's outcome records
    (``assessments.assessment_outcomes``). Each active launch carries the actions the server would accept and — only
    for a member who may run assessments — its signed lease.
  * QUEUED (consumer PR-F, only while ``VIGIL_CUSTOMER_FAIR_QUEUE`` is on): a started launch whose job is still
    waiting in the engine's job queue carries ``queued: {"ahead": N}`` — how many jobs the tenant-fair scheduler
    claims before it (``governor.fair_queue.read_launch_positions``). A count only: the jobs ahead are never named,
    and only this org's own verified launches are annotated. Off, the read is unchanged.

Credits only, never a cost: no amount, no units and no estimate is projected; a lease is passed through opaque, for the
app to present back. Tenant isolation is structural: every slug read is ``_customer_slug(org, host)`` of this org's own
proven hosts, and every lease must verify under the pinned owner key AND name this org and that slug.

FATAL-2: sovereign-side (``assert_no_offense`` at import); the import-clean seam readers are imported lazily.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

#: How many not-yet-started reservations are kept per (org, target); the oldest is dropped beyond it.
_PER_TARGET = 8
_MAX_BYTES = 256 * 1024
#: How many finished launches the read lists, newest first.
_FINISHED_LIMIT = 10
#: The outcome of a launch that ended, as the settle drain records it.
FINISHED = ("completed", "canceled", "failed")


def _dir() -> Path:
    from .. import config
    return Path(config.CUSTOMER_LAUNCHES_DIR)


def _name(org_id: str, slug: str) -> str:
    return hashlib.sha256(b"vigil-launches\x00" + org_id.encode("utf-8") + b"\x00"
                          + slug.encode("utf-8")).hexdigest() + ".json"


def _nonce(entry: dict) -> str:
    doc = (entry.get("lease") or {}).get("document")
    return str(doc.get("nonce") or "") if isinstance(doc, dict) else ""


def _load(org_id: str, slug: str) -> "list[dict]":
    """The kept entries of (org, slug), newest first — ``[{"lease": <signed lease>, "at": <reserved at>}]``; [] for a
    missing, unreadable, oversized or malformed file (never raises)."""
    try:
        fd = os.open(str(_dir() / _name(org_id, slug)), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            raw = fh.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            return []
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return []
    entries = doc.get("leases") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict) and isinstance(e.get("lease"), dict)]


def _save(org_id: str, slug: str, entries: "list[dict]") -> None:
    d = _dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    path = d / _name(org_id, slug)
    if not entries:
        path.unlink(missing_ok=True)
        return
    from ..spine.atomicio import atomic_write_text
    atomic_write_text(path, json.dumps({"leases": entries}, sort_keys=True, separators=(",", ":")))


def remember(signed_lease: Any, *, now: float) -> None:
    """Keep a just-reserved lease for its (org, target), newest first: the same launch again replaces its entry, and at
    most ``_PER_TARGET`` are kept. Raises ``ValueError`` on a malformed lease and ``OSError`` when it cannot be written —
    the caller logs either and carries on, because the customer already holds the lease (the reserve reply)."""
    from vigil_core import SignedCreditLaunchLease
    signed = SignedCreditLaunchLease.model_validate(signed_lease)
    doc = signed.document
    org, slug, nonce = str(doc.org_id), str(doc.engagement_slug), str(doc.nonce)
    kept = [e for e in _load(org, slug) if _nonce(e) != nonce]
    kept.insert(0, {"lease": signed.model_dump(mode="json"), "at": float(now)})
    _save(org, slug, kept[:_PER_TARGET])


def forget(org_id: str, slug: str, nonce: str) -> None:
    """Drop the kept lease of launch ``(slug, nonce)`` of ``org_id``: it was started (the seam holds it now) or
    cancelled. A no-op when nothing is kept for it; raises ``OSError`` when the file cannot be rewritten."""
    kept = _load(str(org_id), str(slug))
    rest = [e for e in kept if _nonce(e) != str(nonce)]
    if len(rest) != len(kept):
        _save(str(org_id), str(slug), rest)


def _verifier(trusted_pubkey: Optional[str]) -> "Callable[[Any, str, str], Any]":
    """``check(signed_lease, org_id, slug)`` — the ``SignedCreditLaunchLease`` when it verifies under the PINNED owner
    key (never a key the seam carries) and names exactly this org and this target, else None. Without a trusted key
    nothing verifies (fail-closed)."""
    from vigil_core import AuthorizerKey, SignedCreditLaunchLease, TrustRoot, verify_credit_launch_lease

    from .target_authorization import _customer_slug
    root = (TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                              public_key_b64=trusted_pubkey)])
            if trusted_pubkey else None)

    def check(raw: Any, org_id: str, slug: str) -> Any:
        if root is None or raw is None:
            return None
        try:
            signed = SignedCreditLaunchLease.model_validate(raw)
            ok, _why = verify_credit_launch_lease(signed, root)
        except Exception:  # noqa: BLE001 — anything malformed is simply not a launch of this org
            return None
        d = signed.document
        if not ok or d.org_id != org_id or d.engagement_slug != slug or _customer_slug(org_id, d.scope_host) != slug:
            return None
        return signed

    return check


def _row(signed: Any, host: str, slug: str, state: str, *, now: float, control: bool, pause_resume: bool) -> dict:
    """One active launch: where it runs, its state and depth, the actions the server would accept and, for a member who
    may run assessments, the signed lease those actions present. Never an amount: the lease's own fields stay inside
    the opaque signed document."""
    from vigil_core.run_tier import lease_depth
    doc = signed.document
    row: dict[str, Any] = {"host": host, "slug": slug, "launch": str(doc.nonce), "state": state,
                           "depth": lease_depth(doc)}
    actions: "list[str]" = []
    if state == "reserved":
        if float(now) >= doc.not_after.timestamp():
            row["expired"] = True            # its window has closed: it can no longer start, only be cancelled
        else:
            actions.append("start")
        actions.append("cancel")             # a reserved launch is always releasable (launch_cancel)
    elif pause_resume:
        actions.append("pause" if state == "running" else "resume")
    row["actions"] = actions if control else []
    if control:
        row["lease"] = signed.model_dump(mode="json")
    return row


def _queue_positions(org_id: str) -> "dict[tuple[str, str], int]":
    """``{(slug, nonce): ahead}`` for this org's launches still waiting in the engine job queue — ``{}`` unless
    ``VIGIL_CUSTOMER_FAIR_QUEUE`` is on (read at call time; off, the queue is not even read). ``org_id`` is the org
    the caller already admitted from the session, never a request field."""
    from .. import config
    if not config.customer_fair_queue_enabled():
        return {}
    from ..governor.fair_queue import read_launch_positions
    return read_launch_positions(org_id)


def launches(store: Any, org_id: str, *, now: float, trusted_pubkey: Optional[str], control: bool,
             pause_resume: bool, choices: "list[dict]") -> dict:
    """The launches of ``org_id`` for the customer app (see the module docstring). ``control``: the requester may run
    assessments (``run_engagement``) — only then are actions, choices and leases included. ``pause_resume``: the customer
    pause / resume actions are on. ``choices``: what Launch may offer (``Provisioner._launch_choices``). A PURE read: no
    key, no lock, no write. The caller has already admitted the requester for ``org_id``."""
    from vigil_core.seam_base import resolve_seam_base
    from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease
    from vigil_integration.live.credit_lease_pause import is_lease_paused

    from ..governor.asset_ownership import AssetOwnershipRegistry
    from . import assessments as _assess
    from .target_authorization import _customer_slug

    base = resolve_seam_base()
    verified = _verifier(trusted_pubkey)
    by_slug = {_customer_slug(org_id, h): h for h in AssetOwnershipRegistry(store, owner_key=None)
               .ever_proven_hosts(org_id)}
    positions = _queue_positions(org_id)
    active: "list[dict]" = []
    for slug, host in sorted(by_slug.items(), key=lambda kv: kv[1]):
        seen: "set[str]" = set()
        bundle = read_credit_lease(base, slug)
        signed = verified(bundle.signed_lease, org_id, slug) if bundle is not None else None
        if signed is not None:
            nonce = str(signed.document.nonce)
            seen.add(nonce)
            if not is_lease_settled(base, slug, nonce):
                state = "paused" if is_lease_paused(base, slug, nonce) else "running"
                row = _row(signed, host, slug, state, now=now, control=control, pause_resume=pause_resume)
                if state == "running" and (slug, nonce) in positions:
                    row["queued"] = {"ahead": int(positions[(slug, nonce)])}
                active.append(row)
        for entry in _load(org_id, slug):
            signed = verified(entry.get("lease"), org_id, slug)
            if signed is None:
                continue
            nonce = str(signed.document.nonce)
            if nonce in seen or is_lease_settled(base, slug, nonce):
                continue
            seen.add(nonce)
            active.append(_row(signed, host, slug, "reserved", now=now, control=control, pause_resume=pause_resume))
    finished: "list[dict]" = []
    for o in _assess.assessment_outcomes(store, org_id, now=now, limit=_FINISHED_LIMIT).get("outcomes", []):
        slug, outcome = str(o.get("engagement_slug") or ""), str(o.get("outcome") or "")
        if slug in by_slug and outcome in FINISHED:
            finished.append({"host": by_slug[slug], "slug": slug, "launch": str(o.get("nonce") or ""),
                             "state": outcome, "ended_at": o.get("ts")})
    return {"org_id": org_id, "choices": list(choices) if control else [], "pause_resume": bool(pause_resume),
            "launches": active, "finished": finished}
