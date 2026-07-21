"""
fireteam.confirmation — the dangerous-tool escalation registry (VIGIL-FUSION F6, C5).

When a member proposes a dangerous / over-cap tool, :mod:`fireteam.member` does NOT run it — it emits
an :class:`~fireteam.models.EscalationRequest` that is registered here and QUEUED. The single way it
can ever become APPROVED is :meth:`ConfirmationRegistry.resolve` with a **signed operator approval**
verified by an INJECTED approver callable. Everything else fails closed:

  * no approver wired, a ``None`` approval, an approver exception, or a non-approving verdict → REJECTED;
  * an unknown key → REJECTED; a key already resolved is FINAL (append-only — a later approval can
    never flip a recorded rejection, so a replay can't launder an escalation past a fail-closed reject);
  * a pending escalation that passes its ``deadline_seq`` auto-REJECTS (inverting redamon's auto-ACCEPT
    on timeout — the sovereign default is deny, never allow).

Deterministic: keyed by ``(wave_id, member_id, seq)`` with no wallclock/RNG. register/resolve/reject/
expire/drop_wave are append-only events; if a single-writer spine is wired they are emitted (redacted)
through it, so the escalation ledger is itself an offline-verifiable, secret-free record.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from .models import CONFIRMATION_DEADLINE_TICKS, EscalationRequest
from .spine_queue import SingleWriterSpineQueue


class ConfirmationOutcome(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True)
class PendingConfirmation:
    key: tuple[str, str, int]
    escalation: EscalationRequest
    deadline_seq: int


@dataclass(frozen=True)
class ConfirmationResolution:
    key: tuple[str, str, int]
    outcome: ConfirmationOutcome
    approved: bool
    reason: str


# approver(signed_approval, escalation) -> a verdict whose ``.approved``/``.allowed`` is True IFF the
# operator's signature is valid AND binds to THIS escalation. Injected so the registry is testable
# without a live signer; in production this wraps the I4 threshold/Ed25519 verification.
ApproverFn = Callable[[Any, EscalationRequest], Any]


class ConfirmationRegistry:
    """A deterministic, append-only registry of pending dangerous-tool escalations. Resolution is
    signed-approval-only; every state change is an event (optionally mirrored to the single-writer
    spine, redacted)."""

    def __init__(self, *, spine: Optional[SingleWriterSpineQueue] = None) -> None:
        self._pending: dict[tuple[str, str, int], PendingConfirmation] = {}
        self._resolved: dict[tuple[str, str, int], ConfirmationResolution] = {}
        self._log: list[dict[str, Any]] = []
        self._spine = spine

    # -- introspection (read-only) --------------------------------------------------------------
    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._log)

    def pending_keys(self) -> list[tuple[str, str, int]]:
        return sorted(self._pending.keys())

    def resolution(self, key: tuple[str, str, int]) -> Optional[ConfirmationResolution]:
        return self._resolved.get(key)

    # -- mutation (append-only) -----------------------------------------------------------------
    def _emit(self, event: str, key: tuple[str, str, int], detail: dict[str, Any]) -> None:
        record = {"event": event, "wave_id": key[0], "member_id": key[1], "seq": key[2], **detail}
        self._log.append(record)
        if self._spine is not None:
            # never let a spine hiccup crash the registry; the write is redacted single-writer.
            try:
                self._spine.submit(member_id=key[1], seq=key[2], kind=f"confirmation.{event}",
                                   record=record)
            except Exception:  # noqa: BLE001 — an emit failure must not corrupt the registry
                pass

    def register(self, escalation: Any, *, deadline_seq: Optional[int] = None) -> Optional[tuple[str, str, int]]:
        """Enqueue a dangerous-tool escalation as PENDING. Fail-closed: a malformed escalation is
        refused (returns ``None``). Append-only: registering a key that is already resolved does NOT
        re-open it, and re-registering a live key is idempotent. ``deadline_seq`` defaults to the
        escalation's ``seq`` + :data:`CONFIRMATION_DEADLINE_TICKS`."""
        if not isinstance(escalation, EscalationRequest):
            return None
        key = escalation.binding_key()
        if key in self._resolved:
            return key  # final — never re-open a resolved escalation
        if key not in self._pending:
            dl = escalation.seq + CONFIRMATION_DEADLINE_TICKS if deadline_seq is None else int(deadline_seq)
            self._pending[key] = PendingConfirmation(key=key, escalation=escalation, deadline_seq=dl)
            self._emit("register", key, {"tool_name": escalation.tool_name,
                                         "requested_tier": escalation.requested_tier,
                                         "deadline_seq": self._pending[key].deadline_seq})
        return key

    def _finish(self, key: tuple[str, str, int], outcome: ConfirmationOutcome, approved: bool,
                reason: str) -> ConfirmationResolution:
        res = ConfirmationResolution(key=key, outcome=outcome, approved=approved, reason=reason)
        self._resolved[key] = res
        self._pending.pop(key, None)
        self._emit(outcome.value, key, {"approved": approved, "reason": reason})
        return res

    def resolve(
        self,
        key: tuple[str, str, int],
        signed_approval: Any,
        *,
        approver: Optional[ApproverFn] = None,
        seq: Optional[int] = None,
    ) -> ConfirmationResolution:
        """Resolve a pending escalation ONLY via a signed operator approval. Never auto-approves.

        Fail-closed on every abnormal path: an already-resolved key returns its FINAL recorded
        resolution (append-only); an unknown key, a missing approver, a ``None`` approval, an approver
        exception, or a non-approving verdict → REJECTED. If ``seq`` is supplied and the pending
        escalation is already past its deadline, it EXPIRES (auto-reject) rather than being approved
        by a late signature. Only an approver verdict whose ``.approved`` (or ``.allowed``) is exactly
        ``True`` yields APPROVED. Never raises."""
        if key in self._resolved:
            return self._resolved[key]
        pending = self._pending.get(key)
        if pending is None:
            return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                "unknown escalation key (fail-closed)")
        if seq is not None and int(seq) > pending.deadline_seq:
            return self._finish(key, ConfirmationOutcome.EXPIRED, False,
                                "escalation past deadline_seq — auto-reject (fail-closed)")
        if approver is None or signed_approval is None:
            return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                "no signed operator approval / no approver wired (fail-closed)")
        try:
            verdict = approver(signed_approval, pending.escalation)
        except Exception as exc:  # noqa: BLE001 — an approver error confirms nothing (fail-closed)
            return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                f"approver error (fail-closed): {exc}")
        approved = getattr(verdict, "approved", getattr(verdict, "allowed", False)) is True
        if not approved:
            return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                getattr(verdict, "reason", "") or "operator did not approve")
        return self._finish(key, ConfirmationOutcome.APPROVED, True,
                            getattr(verdict, "reason", "") or "signed operator approval")

    def reject(self, key: tuple[str, str, int], reason: str = "") -> ConfirmationResolution:
        """Explicitly reject a pending escalation (operator declined). Idempotent/append-only."""
        if key in self._resolved:
            return self._resolved[key]
        if key not in self._pending:
            return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                "unknown escalation key (fail-closed)")
        return self._finish(key, ConfirmationOutcome.REJECTED, False, reason or "operator rejected")

    def expire(self, key: tuple[str, str, int], *, seq: int) -> Optional[ConfirmationResolution]:
        """Auto-REJECT a single pending escalation if ``seq`` is past its deadline. Returns the
        resolution if it expired, else ``None``. Inverts redamon's timeout auto-ACCEPT."""
        if key in self._resolved:
            return None
        pending = self._pending.get(key)
        if pending is None or int(seq) <= pending.deadline_seq:
            return None
        return self._finish(key, ConfirmationOutcome.EXPIRED, False,
                            "escalation past deadline_seq — auto-reject (fail-closed)")

    def sweep(self, seq: int) -> list[ConfirmationResolution]:
        """Auto-REJECT every pending escalation past its deadline at tick ``seq`` (deterministic order)."""
        out: list[ConfirmationResolution] = []
        for key in sorted(self._pending.keys()):
            res = self.expire(key, seq=seq)
            if res is not None:
                out.append(res)
        return out

    def drop_wave(self, wave_id: str) -> list[tuple[str, str, int]]:
        """Drop all still-pending escalations for a finished/cancelled wave (append-only events). A
        dropped escalation is recorded REJECTED — never silently forgotten as approved."""
        dropped: list[tuple[str, str, int]] = []
        for key in sorted(k for k in self._pending if k[0] == wave_id):
            self._finish(key, ConfirmationOutcome.REJECTED, False, "wave dropped")
            dropped.append(key)
        return dropped
