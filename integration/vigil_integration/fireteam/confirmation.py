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

DURABILITY (Gap 2). Without a durable backing the registry is in-memory and per-wave: its state dies with
the process and no separate resolver can read it. Inject an :class:`EscalationLedger` (an append-only,
0600, secret-redacted JSONL file, one per engagement) and every state change is ALSO appended to it; a
FRESH registry constructed over the same ledger REHYDRATES ``_pending``/``_resolved`` by replaying the
file, APPEND-ONLY precedence — a recorded REJECT/EXPIRE/APPROVE is FINAL on disk and no later record can
reopen or flip it (no cross-restart replay-launder). So an over-cap escalation survives a restart and a
Tier-B resolver process can read it back (``pending_keys``/``resolution``) and ``resolve`` it fail-closed.
The JSONL ledger — not the live-feed spine mirror — is the durable substrate, and it works with or without
the framework (a hand-run engage records + reads it identically).
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from ..tools.governance import redact_tool_args
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


class EscalationLedger:
    """Durable, append-only, secret-redacted JSONL backing for :class:`ConfirmationRegistry` (Gap 2).

    One file per engagement (``<base>/<slug>.escalations.jsonl``). Every registry state change (register /
    approve / reject / expire) is appended as ONE redacted JSON line; a FRESH registry over the same file
    replays them (:meth:`replay`) to rebuild ``_pending``/``_resolved`` — so an over-cap escalation survives
    a restart and a separate resolver process can read it back.

    Discipline mirrors the in-plane precedents :class:`~fireteam.wave_progress.WaveProgressStore` and
    :func:`~progress.append_progress`:

      * **append-only.** Each event is one line appended under ``O_APPEND`` — no record is mutated or
        deleted, so a recorded REJECT/EXPIRE is FINAL on disk (append-only precedence is re-enforced on
        replay). Growth is bounded (a wave has a handful of members / escalations).
      * **atomic, 0600, no-follow.** The whole line is written under
        ``O_CREAT|O_APPEND|O_NOFOLLOW|O_NONBLOCK`` at mode 0600 (secret-safe at rest); the target must be a
        real regular single-link file (``S_ISREG`` + ``st_nlink == 1``) so a planted FIFO/symlink/hardlink
        can neither wedge nor redirect the append — the same guard :func:`progress.append_progress` uses.
      * **fail-* / total.** Construction never touches the filesystem; every read/write is wrapped so a
        missing/corrupt/unwritable ledger degrades to a no-op (``append`` → ``False``, ``replay`` → ``[]``),
        never an exception. A dropped append only ever costs durability of that one event, never a crash.

    NOT a signed spine: the JSONL ledger is the durable, offline-readable substrate. When the framework
    blackboard is present the registry ALSO mirrors each event onto the signed blackboard chain via the
    live-feed poster (see ``live.wiring``), but that mirror needs the framework — the ledger is what
    guarantees cross-process durability + rehydration, with or without it.
    """

    SCHEMA = "vigil.fireteam.escalations.v1"
    _MAX_BYTES = 16384   # drop an oversized record rather than risk a torn append (mirrors progress.py)

    def __init__(self, path: Any) -> None:
        # NEVER touch the filesystem in __init__ — construction must not raise; a bad path disables the store.
        try:
            self._path = os.fspath(path)
        except Exception:  # noqa: BLE001 — a bad path degrades to a disabled (no-op) ledger
            self._path = ""

    def append(self, record: Mapping[str, Any]) -> bool:
        """Append ONE record as a JSON line, fail-open. Returns ``True`` iff a whole line was durably
        written; ``False`` — never raising — on any missing-path / non-mapping / encode / oversize / IO
        failure. Best-effort by contract: a ledger write must never break the registry that produced it."""
        if not self._path or not isinstance(record, Mapping):
            return False
        try:
            line = json.dumps(dict(record), default=str, ensure_ascii=True, separators=(",", ":"))
            data = (line + "\n").encode("utf-8", "replace")
            if len(data) > self._MAX_BYTES:
                return False
            directory = os.path.dirname(self._path) or "."
            os.makedirs(directory, exist_ok=True)
            # O_NONBLOCK: never BLOCK on a planted readerless FIFO. O_NOFOLLOW: never follow a symlink at the
            # final component. Both mirror progress.append_progress; the S_ISREG + st_nlink==1 check below
            # rejects a FIFO/device/socket or a hardlinked second name for the same inode.
            fd = os.open(self._path,
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    return False
                # Write the WHOLE line: a short write would truncate this event and merge it with the next
                # append into one malformed line, losing two events instead of just this one.
                mv = memoryview(data)
                while mv:
                    n = os.write(fd, mv)
                    if n <= 0:
                        return False
                    mv = mv[n:]
            finally:
                os.close(fd)
            return True
        except Exception:  # noqa: BLE001 — a ledger write is best-effort; never break the registry
            return False

    def replay(self) -> list[dict[str, Any]]:
        """Read every valid JSON-object line in append order, skipping any malformed/torn line. Total: an
        absent/unreadable ledger (or any read error) yields ``[]`` — "nothing recorded yet". Never raises."""
        out: list[dict[str, Any]] = []
        if not self._path:
            return out
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        obj = json.loads(raw)
                    except Exception:  # noqa: BLE001 — skip a torn/garbage line, keep replaying the rest
                        continue
                    if isinstance(obj, dict):
                        out.append(obj)
        except Exception:  # noqa: BLE001 — a missing/unreadable ledger means "nothing recorded yet"
            return []
        return out


class ConfirmationRegistry:
    """A deterministic, append-only registry of pending dangerous-tool escalations. Resolution is
    signed-approval-only; every state change is an event (optionally mirrored to the single-writer
    spine, redacted) AND — when an :class:`EscalationLedger` is injected — durably appended to it, so a
    FRESH registry over the same ledger rehydrates the pending/resolved state on construction."""

    # A resolved escalation's outcome is FINAL on disk: these events close a key and no later record reopens
    # it (append-only precedence enforced on rehydration).
    _TERMINAL = frozenset({ConfirmationOutcome.APPROVED.value, ConfirmationOutcome.REJECTED.value,
                           ConfirmationOutcome.EXPIRED.value})

    def __init__(self, *, spine: Optional[SingleWriterSpineQueue] = None,
                 ledger: Optional[EscalationLedger] = None) -> None:
        self._pending: dict[tuple[str, str, int], PendingConfirmation] = {}
        self._resolved: dict[tuple[str, str, int], ConfirmationResolution] = {}
        self._log: list[dict[str, Any]] = []
        self._spine = spine
        self._ledger = ledger
        if ledger is not None:
            self._rehydrate()

    # -- introspection (read-only) --------------------------------------------------------------
    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._log)

    def pending_keys(self) -> list[tuple[str, str, int]]:
        return sorted(self._pending.keys())

    def resolution(self, key: tuple[str, str, int]) -> Optional[ConfirmationResolution]:
        return self._resolved.get(key)

    # -- rehydration (durable read-back) --------------------------------------------------------
    def _rehydrate(self) -> None:
        """Rebuild ``_pending``/``_resolved`` from the durable ledger. Events are replayed in write order
        with APPEND-ONLY precedence: a key's FIRST terminal outcome (approved/rejected/expired) is FINAL and
        no later record — a re-register or a second "approval" — can reopen or flip it (so a restart cannot
        launder a recorded reject). Total: a single un-restorable record is skipped, never crashes __init__."""
        if self._ledger is None:
            return
        for rec in self._ledger.replay():
            try:
                self._apply_record(rec)
            except Exception:  # noqa: BLE001 — one bad record is skipped; the rest still replay
                continue

    def _apply_record(self, rec: Any) -> None:
        if not isinstance(rec, dict):
            return
        event = str(rec.get("event", ""))
        try:
            key = (str(rec["wave_id"]), str(rec["member_id"]), int(rec["seq"]))
        except Exception:  # noqa: BLE001 — a record with no usable key is not restorable
            return
        if key in self._resolved:
            return  # FINAL on disk — no later record reopens or re-flips a resolved escalation
        if event == "register":
            if key in self._pending:
                return  # idempotent re-register (append-only)
            esc = EscalationRequest(
                wave_id=key[0], member_id=key[1], seq=key[2],
                tool_name=str(rec.get("tool_name", "") or ""),
                target=str(rec.get("target", "") or ""),               # already redacted at record time
                requested_tier=str(rec.get("requested_tier", "") or "A3"),
                reason=str(rec.get("reason", "") or ""))               # already redacted at record time
            try:
                dl = int(rec.get("deadline_seq", esc.seq + CONFIRMATION_DEADLINE_TICKS))
            except (TypeError, ValueError):
                dl = esc.seq + CONFIRMATION_DEADLINE_TICKS
            self._pending[key] = PendingConfirmation(key=key, escalation=esc, deadline_seq=dl)
        elif event in self._TERMINAL:
            outcome = ConfirmationOutcome(event)
            # deny-by-default: only an APPROVED record with approved=True rehydrates as approved; a
            # reject/expire (or a tampered "rejected with approved=true") can never restore an allow.
            approved = outcome == ConfirmationOutcome.APPROVED and bool(rec.get("approved", False))
            self._resolved[key] = ConfirmationResolution(
                key=key, outcome=outcome, approved=approved, reason=str(rec.get("reason", "") or ""))
            self._pending.pop(key, None)

    # -- mutation (append-only) -----------------------------------------------------------------
    def _emit(self, event: str, key: tuple[str, str, int], detail: dict[str, Any]) -> None:
        record = {"event": event, "wave_id": key[0], "member_id": key[1], "seq": key[2], **detail}
        self._log.append(record)
        if self._ledger is not None:
            # DURABLE substrate: append the (already-redacted) event to the append-only JSONL ledger so a
            # fresh registry can rehydrate it. Best-effort — a ledger write must not corrupt the registry.
            try:
                self._ledger.append(record)
            except Exception:  # noqa: BLE001 — an emit failure must not corrupt the registry
                pass
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
            # ``target``/``reason`` are the only free-text fields — SCRUB them with the F3 value-redactor
            # (the SAME scrubber spine_queue.py / engine.py use) BEFORE they reach the durable ledger, so no
            # credential in a target URL or reason ever survives at rest. Persisting them (redacted) lets a
            # FRESH registry rehydrate the escalation on replay; its binding_key (wave/member/seq) is non-secret.
            safe = redact_tool_args({"target": escalation.target, "reason": escalation.reason})
            self._emit("register", key, {"tool_name": escalation.tool_name,
                                         "requested_tier": escalation.requested_tier,
                                         "target": str(safe.get("target", "")),
                                         "reason": str(safe.get("reason", "")),
                                         "deadline_seq": self._pending[key].deadline_seq})
        return key

    def _finish(self, key: tuple[str, str, int], outcome: ConfirmationOutcome, approved: bool,
                reason: str) -> ConfirmationResolution:
        res = ConfirmationResolution(key=key, outcome=outcome, approved=approved, reason=reason)
        self._resolved[key] = res
        self._pending.pop(key, None)
        # The in-memory resolution keeps the RAW reason (returned to the caller); the DURABLE record carries
        # the scrubbed reason (an approver-supplied reason string could echo a secret), so nothing sensitive
        # lands at rest. SCRUB with the SAME F3 value-redactor used for the register event.
        safe = redact_tool_args({"reason": reason})
        self._emit(outcome.value, key, {"approved": approved, "reason": str(safe.get("reason", ""))})
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
