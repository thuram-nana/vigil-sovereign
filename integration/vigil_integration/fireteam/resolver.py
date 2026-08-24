"""fireteam.resolver — the sovereign Tier-B escalation resolve loop (W17-7, #541).

The :class:`~fireteam.confirmation.ConfirmationRegistry` can only leave an over-cap member escalation
PENDING in its durable :class:`~fireteam.confirmation.EscalationLedger`. Its
:meth:`~fireteam.confirmation.ConfirmationRegistry.resolve` is authorized ONLY by a signed operator
approval — but until now NOTHING in production ever CALLED it, so an over-cap escalation could only ever
auto-REJECT at its ``deadline_seq``. This module is the missing wiring: a file-backed signed-approval
INBOX plus a RESOLVE LOOP a production caller drives, so an escalation reaches an OPERATOR DECISION
instead of only ever timing out.

Two parties, mirroring the WARDEN per-action :mod:`live.approval_broker` pending/signed split:

  * **SOVEREIGN** (the only party holding the owner PRIVATE key) mints a signed approval envelope with
    :func:`~fireteam.confirmation.sign_escalation_approval` and drops it under
    ``<base>/approvals/fireteam/<slug>/signed/<keydigest>.json`` (:func:`write_signed_approval`). The
    envelope is a base64 Ed25519 signature — it carries NO secret — so it is safe to sit on a shared
    engagement home the keyless offense worker also reads.
  * **OFFENSE** (keyless) drives :func:`resolve_pending`: for each PENDING key it looks for a matching
    signed envelope and calls ``registry.resolve(key, envelope, seq=now_seq)``; with none, a past-deadline
    key EXPIRES (auto-reject, fail-closed) and a within-deadline key stays PENDING and is surfaced to the
    live UI feed so the operator can still decide BEFORE it expires.

The offense side holds NO private key: it can only VERIFY a sovereign-signed envelope (against the pinned
trusted approver key the registry already carries), never mint one — so :func:`resolve_pending` can never
self-authorize. Fail-closed + total throughout: a forged / unsigned / cross-engagement / flipped / LATE
envelope degrades to REJECTED/EXPIRED, and any I/O error leaves the escalation PENDING (fail-safe — it
simply reappears next pass). Ordering (deadline BEFORE signature) is enforced INSIDE ``resolve()`` itself:
passing ``seq=now_seq`` makes a late signature EXPIRE rather than approve.

FATAL-2 / import-clean: ``vigil_core`` + stdlib + relative imports ONLY (never ``framework`` / ``strix`` /
``sigil``), so it is safe to import in either environment and is testable with no framework, no network.
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Callable, Optional

from ..tools.governance import redact_tool_args
from .confirmation import (
    ConfirmationRegistry,
    ConfirmationResolution,
    EscalationLedger,
    _envelope_of,
    _key_digest,
)

__all__ = [
    "escalation_ledger_path",
    "signed_inbox_dir",
    "write_signed_approval",
    "find_signed_approval",
    "open_registry",
    "pending_escalations",
    "resolve_pending",
]

# The live-feed event kind a still-pending escalation is surfaced under (so the operator SEES it before it
# expires); a resolved one rides "fireteam" (approved) or "refusal" (expired/rejected — a gate firing), the
# SAME Gap-2 convention live.wiring._member_writer uses.
_PENDING_KIND = "fireteam.escalation.pending"
_APPROVED_KIND = "fireteam.escalation.approved"


# ---------------------------------------------------------------------------------------------------
# paths (the SAME durable ledger live.wiring builds, + the signed-approval inbox)
# ---------------------------------------------------------------------------------------------------


def escalation_ledger_path(base_dir: Any, slug: str) -> Path:
    """The durable, engagement-scoped escalation ledger ``<base>/<slug>.escalations.jsonl`` — byte-identical
    to the path :func:`live.wiring.build_engine` constructs, so a standalone resolver reads the SAME file the
    live engine wrote."""
    return Path(base_dir) / f"{_safe_slug(slug)}.escalations.jsonl"


def signed_inbox_dir(base_dir: Any, slug: str) -> Path:
    """The signed-approval inbox ``<base>/approvals/fireteam/<slug>/signed`` — the sovereign signer WRITES an
    owner-signed envelope here (one file per escalation key); the offense resolver READS it back. Distinct
    from the WARDEN per-action ``approvals/{pending,signed}`` tree so the two approval planes never collide."""
    return Path(base_dir) / "approvals" / "fireteam" / _safe_slug(slug) / "signed"


def _safe_slug(slug: str) -> str:
    """A filesystem-safe slug component: no separators / ``..`` / NUL / control chars (so a crafted slug can
    never escape the approvals dir). Falls back to a fixed literal for an unusable slug (fail-closed to an
    isolated, non-escaping directory rather than raising)."""
    s = str(slug or "").strip()
    if not s or "/" in s or "\\" in s or ".." in s:
        return "_slug"
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        return "_slug"
    return s


# ---------------------------------------------------------------------------------------------------
# the signed-approval inbox (public-safe — a base64 signature, no secret)
# ---------------------------------------------------------------------------------------------------


def _atomic_write_json(path: Path, obj: dict) -> None:
    """Atomically write ``obj`` as canonical JSON at ``path`` (0600, fsync'd, then ``os.replace``). Mirrors
    :func:`live.approval_broker._atomic_write_json`; the tmp name is unique so concurrent writers of the same
    content never corrupt each other."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    tmp = path.parent / (path.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
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


def write_signed_approval(base_dir: Any, slug: str, key: tuple[str, str, int],
                          envelope: Mapping[str, Any]) -> Path:
    """SOVEREIGN: persist an owner-signed approval ``envelope`` for the escalation ``key`` under the signed
    inbox, keyed by the fixed ``[0-9a-f]{64}`` :func:`_key_digest` (so the filename can neither escape the
    dir nor collide). Fail-closed: a value that is not a well-formed approval envelope (``key_id`` +
    ``signature_b64``) is REFUSED (``ValueError``) — an unverifiable file is never written. Returns the path."""
    minimal = _envelope_of(envelope)
    if minimal is None:
        raise ValueError("write_signed_approval needs a signed approval envelope (key_id + signature_b64)")
    # Carry the advisory self-declared fields too (they are re-checked against the ledger record on verify,
    # never trusted) so the persisted file is a faithful copy of what the signer minted.
    out = dict(minimal)
    if isinstance(envelope, Mapping):
        for f in ("engagement", "outcome", "approved"):
            if f in envelope:
                out[f] = envelope[f]
    path = signed_inbox_dir(base_dir, slug) / f"{_key_digest(key)}.json"
    _atomic_write_json(path, out)
    return path


def find_signed_approval(base_dir: Any, slug: str, key: tuple[str, str, int]) -> Optional[dict[str, Any]]:
    """OFFENSE: read back the signed approval envelope for ``key`` (or ``None`` if absent / unreadable /
    malformed). Total — never raises. The returned dict is handed straight to ``registry.resolve``, which
    re-verifies its signature against the pinned trusted approver key and the ledger record's exact terminal;
    a file that is present but not a real envelope simply fails that verification (fail-closed)."""
    path = signed_inbox_dir(base_dir, slug) / f"{_key_digest(key)}.json"
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


# ---------------------------------------------------------------------------------------------------
# a fresh registry over the durable ledger (the separate-process resolver / CLI seam)
# ---------------------------------------------------------------------------------------------------


def open_registry(base_dir: Any, slug: str, *, trusted_approvers: Any = None) -> ConfirmationRegistry:
    """Open a FRESH :class:`ConfirmationRegistry` over the engagement's durable ledger (rehydrating its
    pending/resolved state on construction), pinned to ``trusted_approvers`` (the operator/owner approval
    authority — PUBLIC key only) and bound to ``slug`` as the engagement so a signed approval is valid ONLY
    here. This is the read-back seam a standalone resolver (``vigil fireteam list|resolve``) drives; the live
    engine builds its own registry over the same ledger in ``live.wiring.deploy_fireteam``."""
    ledger = EscalationLedger(str(escalation_ledger_path(base_dir, slug)))
    return ConfirmationRegistry(ledger=ledger, trusted_approvers=trusted_approvers, engagement=str(slug or ""))


# ---------------------------------------------------------------------------------------------------
# read-only view (secret-safe — target/reason RE-redacted defensively)
# ---------------------------------------------------------------------------------------------------


def _pending_row(pc: Any, *, now_seq: Optional[int] = None) -> dict[str, Any]:
    """A secret-safe dict describing ONE pending escalation, for the CLI / live-feed / UI. ``target`` and
    ``reason`` are RE-redacted here (the SAME F3 scrubber) even though the ledger already redacts them, so a
    live (same-process) registry that still holds the RAW escalation can never leak a credential to a UI."""
    esc = getattr(pc, "escalation", None)
    safe = redact_tool_args({"target": str(getattr(esc, "target", "") or ""),
                             "reason": str(getattr(esc, "reason", "") or "")})
    row: dict[str, Any] = {
        "wave_id": str(getattr(esc, "wave_id", "") or ""),
        "member_id": str(getattr(esc, "member_id", "") or ""),
        "seq": int(getattr(esc, "seq", 0) or 0),
        "tool_name": str(getattr(esc, "tool_name", "") or ""),
        "requested_tier": str(getattr(esc, "requested_tier", "") or ""),
        "target": str(safe.get("target", "")),
        "reason": str(safe.get("reason", "")),
        "deadline_seq": int(getattr(pc, "deadline_seq", 0) or 0),
        "status": "pending",
    }
    if now_seq is not None:
        # How many injected-sequence ticks remain before the fail-closed auto-reject — a NEGATIVE value means
        # the deadline has already passed (this pass will EXPIRE it). Surfaced so the operator can see the
        # window shrinking in the live UI before it closes.
        row["ticks_remaining"] = int(row["deadline_seq"]) - int(now_seq)
    return row


def pending_escalations(registry: ConfirmationRegistry, *, now_seq: Optional[int] = None) -> list[dict[str, Any]]:
    """Every currently-PENDING escalation as a secret-safe row (deterministic key order). Drives the operator
    view (``vigil fireteam list``) and the UI's before-it-expires surface."""
    rows: list[dict[str, Any]] = []
    for key in registry.pending_keys():
        pc = registry.pending(key)
        if pc is not None:
            rows.append(_pending_row(pc, now_seq=now_seq))
    return rows


# ---------------------------------------------------------------------------------------------------
# THE RESOLVE LOOP — a production caller drives an escalation to an operator decision (or a fail-closed
# deadline auto-reject), never leaving it stranded
# ---------------------------------------------------------------------------------------------------


def _emit(feed: Optional[Callable[[str, dict], Any]], kind: str, payload: dict) -> None:
    """Best-effort live-feed emit (the engine's ``spine_post`` when wired, else a no-op). Never raises — a
    feed hiccup must never perturb the resolve loop."""
    if feed is None:
        return
    try:
        feed(kind, payload)
    except Exception:  # noqa: BLE001 — a live-feed write NEVER perturbs the resolve loop
        pass


def resolve_pending(
    registry: ConfirmationRegistry,
    *,
    base_dir: Any,
    slug: str,
    now_seq: Optional[int] = None,
    feed: Optional[Callable[[str, dict], Any]] = None,
) -> list[ConfirmationResolution]:
    """THE Tier-B resolve loop — the production caller of ``registry.resolve``/``registry.expire``.

    For each PENDING escalation (deterministic key order):

      1. **operator decision.** If a matching sovereign-signed envelope is in the inbox, call
         ``registry.resolve(key, envelope, seq=now_seq)``. That verifies the signature against the pinned
         trusted approver key AND the exact ``(engagement, key, "approved", True)`` bytes and, when
         ``now_seq`` is supplied, EXPIRES a LATE approval instead of honouring it (deadline beats a late
         signature). A durable APPROVED is committed BEFORE it is returned actionable (DEFECT-2 ordering).
      2. **fail-closed deadline (negative control, preserved).** With NO envelope and ``now_seq`` past the
         escalation's ``deadline_seq``, ``registry.expire`` auto-REJECTS it — the safe default is preserved,
         not replaced.
      3. **still pending → visible.** With no envelope and still within the deadline, the escalation stays
         PENDING and is surfaced to the live UI feed (``fireteam.escalation.pending`` with ``ticks_remaining``)
         so the operator can still decide before it expires.

    Returns the resolutions APPLIED this pass (approved / expired / rejected); a still-pending key contributes
    none. Total: any per-key error leaves that escalation PENDING (fail-safe). The offense caller holds no
    private key, so this can only ever READ BACK a sovereign-signed approval, never mint one."""
    applied: list[ConfirmationResolution] = []
    for key in registry.pending_keys():
        try:
            envelope = find_signed_approval(base_dir, slug, key)
            if envelope is not None:
                res: Optional[ConfirmationResolution] = registry.resolve(key, envelope, seq=now_seq)
            elif now_seq is not None:
                res = registry.expire(key, seq=now_seq)   # None unless past deadline
            else:
                res = None
        except Exception:  # noqa: BLE001 — a resolve/expire error leaves the escalation PENDING (fail-safe)
            res = None

        if res is None:
            pc = registry.pending(key)
            if pc is not None:
                _emit(feed, "fireteam", {"kind": _PENDING_KIND, **_pending_row(pc, now_seq=now_seq)})
            continue

        applied.append(res)
        _emit_resolution(feed, res)
    return applied


def _emit_resolution(feed: Optional[Callable[[str, dict], Any]], res: ConfirmationResolution) -> None:
    """Mirror an APPLIED resolution onto the live feed (Gap-2 convention): an APPROVED authorization rides
    ``fireteam``; an EXPIRED/REJECTED terminal is a gate firing (nothing ran) so it rides ``refusal``."""
    wave_id, member_id, seq = res.key
    if res.approved:
        _emit(feed, "fireteam", {
            "kind": _APPROVED_KIND,
            "wave_id": wave_id, "member_id": member_id, "seq": seq,
            "outcome": res.outcome.value, "reason": res.reason,
        })
    else:
        _emit(feed, "refusal", {
            "gate": "fireteam.confirmation",
            "action_refused": f"escalation {wave_id}/{member_id}/{seq} ({res.outcome.value})",
            "reason": res.reason or f"escalation {res.outcome.value} (fail-closed)",
            "fatal": False,
        })
