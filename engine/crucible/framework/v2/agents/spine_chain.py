"""
agents.spine_chain — cryptographic tamper-evidence for the event spine.

The blackboard is append-only by SQL trigger + API discipline. This module adds the second,
stronger guarantee the operator asked for: a hash-linked, governance-signed chain over the
event log, so tampering that BYPASSES the triggers (a raw DB edit, a swapped file) is still
detectable, and the whole spine can be anchored to the governance trust root.

It reuses the evidence layer's battle-tested integrity primitives verbatim
(``evidence/chain.py`` hash-links + m-of-n signed head + anti-rollback) — no new integrity
scheme. It is PURELY ADDITIVE: no schema change, no change to ``post()``, existing rows
untouched. The chain is built on demand from the live events, so an unsigned spine behaves
exactly as before; signing is provisioning-only and the runtime only verifies.

The per-event digest is DETERMINISTIC: it covers the event's identity + content
(kind / agent / payload / parent / supersedes) but NOT the wallclock ``posted_at`` — keeping
the same "no wallclock in digests" discipline the evidence/calibration layers use, so the
chain is stable and replay-safe. The chain therefore proves CONTENT + ORDER integrity of the
log (an altered payload, a reordered or deleted event breaks it).
"""

from __future__ import annotations

from typing import Callable

from ..common import logging as v2log
from ..evidence.canonical import digest_payload
from ..evidence.chain import build_chain, sign_head, verify_chain, verify_head
from ..evidence.models import ChainEntry, SignedChainHead
from .blackboard import Blackboard, BlackboardEventRow

_log = v2log.get_logger(__name__)


class SpineChainError(RuntimeError):
    """The spine could not be read completely — the chain must fail closed rather than
    anchor/verify a truncated log."""


_PAGE = 5000   # replay page size for paging the full log to exhaustion


def event_digest(row: BlackboardEventRow) -> str:
    """Deterministic content+identity digest of one spine event (excludes wallclock
    ``posted_at``), via the shared evidence canonical-bytes discipline. ``engagement_id`` is
    bound in so two engagements with identical event content produce DIFFERENT chains — a
    signed head cannot be replayed onto a look-alike log (defense in depth alongside the
    slug check in ``verify_spine_head``)."""
    return digest_payload({
        "engagement_id": row.engagement_id,
        "kind": row.kind,
        "agent_name": row.agent_name,
        "payload": row.payload,
        "parent_id": row.parent_id,
        "supersedes_id": row.supersedes_id,
    })


def _events(bb: Blackboard, engagement: str | int) -> list[BlackboardEventRow]:
    """The FULL immutable history for an engagement in id (logical-clock) order — including
    superseded rows, because they are part of the append-only log and the chain covers them.

    Pages ``replay`` to exhaustion (its default limit would silently truncate a large log,
    leaving the tail unanchored) and FAILS CLOSED: if the fetched count does not equal the
    live event count, it raises rather than anchor/verify a partial log."""
    out: list[BlackboardEventRow] = []
    since = 0
    while True:
        batch = bb.replay(engagement=engagement, since_id=since,
                          include_superseded=True, limit=_PAGE)
        if not batch:
            break
        out.extend(batch)
        since = batch[-1].id
        if len(batch) < _PAGE:
            break
    total = bb.count(engagement=engagement)
    if len(out) != total:
        raise SpineChainError(
            f"incomplete spine read: fetched {len(out)} of {total} events — refusing to "
            f"anchor/verify a truncated log")
    return out


def build_spine_chain(bb: Blackboard, engagement: str | int) -> list[ChainEntry]:
    """Build the hash-linked chain over the engagement's events, in id order."""
    return build_chain([event_digest(r) for r in _events(bb, engagement)])


def verify_spine_chain(bb: Blackboard, engagement: str | int,
                       entries: list[ChainEntry]) -> tuple[bool, str]:
    """Verify ``entries`` against the LIVE events: the digests must equal the current events'
    digests in order (nothing altered/reordered/deleted) AND the links must recompute. Fails
    closed if the log cannot be read in full."""
    try:
        live = [event_digest(r) for r in _events(bb, engagement)]
    except SpineChainError as e:
        return (False, f"{e} — failing closed")
    chain = [e.cert_digest for e in entries]
    if live != chain:
        return (False, f"spine event-set mismatch: {len(chain)} chained vs {len(live)} live "
                       f"events — an event was altered, reordered, or deleted")
    return verify_chain(entries)


def sign_spine_head(bb: Blackboard, engagement: str, *,
                    signers: list[tuple[str, str]]) -> SignedChainHead:
    """Anchor the spine with a governance-signed head over the current event log
    (PROVISIONING ONLY — the runtime only verifies)."""
    entries = build_spine_chain(bb, engagement)
    return sign_head(entries, engagement_slug=engagement, signers=signers)


def verify_spine_head(bb: Blackboard, engagement: str, head: SignedChainHead,
                      trust_root, *, prev_highwater: int | None = None) -> tuple[bool, str]:
    """Verify a signed spine head against the LIVE events: the head must be FOR this
    engagement (slug binding — no cross-engagement head replay), then the chain is rebuilt
    from the current log and checked against the signed head (hash + count), the signature
    meets the governance threshold, and the head has not rolled back. Any post-signing tamper
    — an edited payload, a reordered/deleted event, or an un-anchored appended event — fails
    here. Fails closed if the log cannot be read in full."""
    if head.engagement_slug != engagement:
        return (False, f"head is anchored to engagement {head.engagement_slug!r}, not "
                       f"{engagement!r} — refusing a cross-engagement head")
    try:
        entries = build_spine_chain(bb, engagement)
    except SpineChainError as e:
        return (False, f"{e} — failing closed")
    return verify_head(head, entries, trust_root, prev_highwater=prev_highwater)


# ── RUNTIME CALLER: verify the LIVE SQLite spine (built above was verify-only, never invoked) ──────────────
#
# The functions above are the verify PRIMITIVES. Until now nothing CALLED them on the live runtime path, so a
# tamper that bypassed the append-only triggers (a raw DB edit/delete, a swapped file) sat undetected until
# someone ran a manual verify. The two functions below are the CALLER: they run the existing verifiers over
# the LIVE spine at engagement CLOSE (and are the primitive a bounded cadence tick calls), and surface a
# FAILURE as a loud tamper alarm — fail-closed, logged, never silent. They add no new integrity scheme and
# mint nothing; they only VERIFY (an oracle-sole-authority-safe, demote-nothing operation).


def verify_live_spine(
    bb: Blackboard,
    engagement: str,
    *,
    head: SignedChainHead | None = None,
    trust_root: object | None = None,
    reference: list[ChainEntry] | None = None,
    prev_highwater: int | None = None,
) -> tuple[bool, str]:
    """Verify the LIVE spine for ``engagement`` against the STRONGEST anchor available, reusing the existing
    verifiers unchanged. Precedence:

      * a governance-SIGNED ``head`` (+ pinned ``trust_root``) → :func:`verify_spine_head`: full
        content+order+authenticity+anti-rollback — an edited, reordered, deleted, or appended-after-signing
        event is detected and the head signature must meet the governance threshold;
      * else an independently-anchored ``reference`` chain (the EXPORT the integrity monitor reads, or a
        checkpoint retained from an earlier cadence tick) → :func:`verify_spine_chain`: content+order against
        that out-of-band reference, so a divergence between the export of record and the live DB is caught
        (the export chain-of-custody check);
      * else (no anchor provisioned yet) build the live chain and self-verify it → confirms the log reads
        COMPLETE (fails CLOSED on a truncated/unreadable read via :class:`SpineChainError`) and links cleanly.
        HONEST SCOPE: with no out-of-band anchor this detects truncation/read-failure/internal break, NOT a
        bare payload edit — exactly the limit ``integration.integrity_verifier`` documents for its unkeyed
        on-disk dual.

    Never raises: a read that cannot complete returns ``(False, …)`` (fail-closed). Call it at engagement
    CLOSE, where no concurrent writer exists, so the read is a consistent snapshot (the concurrent-cadence
    snapshot race is handled separately); minting/verdicts are untouched."""
    if head is not None and trust_root is not None:
        return verify_spine_head(bb, engagement, head, trust_root, prev_highwater=prev_highwater)
    if reference is not None:
        return verify_spine_chain(bb, engagement, reference)
    try:
        built = build_spine_chain(bb, engagement)
    except SpineChainError as e:
        return (False, f"{e} — failing closed")
    return verify_spine_chain(bb, engagement, built)


def verify_spine_at_engagement_close(
    bb: Blackboard,
    engagement: str,
    *,
    head: SignedChainHead | None = None,
    trust_root: object | None = None,
    reference: list[ChainEntry] | None = None,
    on_alarm: Callable[[str, str], None] | None = None,
) -> tuple[bool, str]:
    """RUNTIME CALLER wired at engagement CLOSE: crypto-verify the live SQLite spine via
    :func:`verify_live_spine`, then — on FAILURE — surface a tamper alarm through ``on_alarm`` (e.g. a loud
    spine refusal) AND a structured ``error`` log, never silently. Fail-closed/total: the verify itself never
    raises; a notifier that throws is swallowed only AFTER the alarm has been logged (one bad sink must not
    bury the alarm). Returns ``(ok, reason)``. This changes no oracle verdict and mints nothing."""
    ok, reason = verify_live_spine(bb, engagement, head=head, trust_root=trust_root, reference=reference)
    if ok:
        _log.info("agents.spine_chain.live_verified", engagement=str(engagement), detail=reason)
        return ok, reason
    _log.error("agents.spine_chain.tamper_alarm", engagement=str(engagement), detail=reason)
    if on_alarm is not None:
        try:
            on_alarm(str(engagement), reason)
        except Exception:  # noqa: BLE001 — the alarm is already logged; a bad notifier must not swallow it
            _log.error("agents.spine_chain.tamper_alarm_notify_failed", engagement=str(engagement))
    return ok, reason
