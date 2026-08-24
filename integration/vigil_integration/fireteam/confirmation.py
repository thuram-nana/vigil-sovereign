"""
fireteam.confirmation — the dangerous-tool escalation registry (VIGIL-FUSION F6, C5; Claim-6 Tier-B).

When a member proposes a dangerous / over-cap tool, :mod:`fireteam.member` does NOT run it — it emits
an :class:`~fireteam.models.EscalationRequest` that is registered here and QUEUED. The single way it can
ever become APPROVED is :meth:`ConfirmationRegistry.resolve` with a **cryptographically signed operator
approval**: an Ed25519 signature — by a PINNED trusted approver key — over the canonical bytes of the
EXACT ``(wave_id, member_id, seq, outcome="approved", approved=True)``. Everything else fails closed:

  * no valid signed envelope (and no in-memory approver verdict) → REJECTED; a ``None`` approval → REJECTED;
  * an unknown key → REJECTED; a key already resolved is FINAL (append-only — a later approval can never
    flip a recorded rejection, so a replay can't launder an escalation past a fail-closed reject);
  * a pending escalation that passes its ``deadline_seq`` auto-REJECTS (inverting redamon's auto-ACCEPT
    on timeout — the sovereign default is deny, never allow).

Deterministic: keyed by ``(wave_id, member_id, seq)`` with no wallclock/RNG. register/resolve/reject/
expire/drop_wave are append-only events; if a single-writer spine is wired they are emitted (redacted)
through it, so the escalation ledger is itself an offline-verifiable, secret-free record.

DURABILITY (Gap 2) + SIGNED REPLAY (Tier-B). The durable backing is an :class:`EscalationLedger` — an
append-only, 0600, path-safe, secret-redacted JSONL file, one per engagement. Every state change is
appended to it; a FRESH registry over the same ledger REHYDRATES ``_pending``/``_resolved`` by replaying
the file, APPEND-ONLY precedence. **The ledger's path-safety (O_NOFOLLOW + ``S_ISREG`` + ``st_nlink==1``)
is INTEGRITY, not content-authorization** — it stops a planted symlink/hardlink/FIFO redirecting the
append, but it does NOT stop a byte-legal line from claiming ``approved``. So an APPROVED terminal is
authorized ONLY by the embedded Ed25519 envelope, RE-VERIFIED on every replay against a pinned trusted
approver key and BOUND to this exact ``(wave_id, member_id, seq, "approved", True)``. A record whose
approval is missing / invalid / unbound / flipped **degrades to REJECTED** on rehydration (never APPROVED)
— this is the fix for the pre-Tier-B defect where ``_apply_record`` trusted the raw ``rec["approved"]``.

DURABLE-BEFORE-ACTIONABLE (DEFECT 2). A signed APPROVED authorizes a dangerous action, so it is recorded
in-memory / returned as an allow ONLY AFTER its terminal is durably committed to the ledger — the append is
done FIRST and its result CHECKED (:meth:`ConfirmationRegistry._finish`), and for the AUTHORITATIVE APPROVED
terminal it is ``fsync``'d (POWER-LOSS durable, matching the fsync the coordination marker already gets), so
a valid-but-not-durable approval can never be actionable while a restart/failover reader sees no terminal.
If the durable commit fails it FAILS CLOSED (non-actionable, escalation stays PENDING, the atomic claim is
RELEASED and self-cleans any mid-write marker) so a retry, once storage recovers, can durably commit. A lost
REJECT/EXPIRE stays best-effort — it merely reappears pending on a fresh reader, which is fail-SAFE.

ATOMIC RESOLVE (Tier-B). Two resolver processes over one ledger cannot reach DIVERGENT terminals: the
first terminal for a key wins an O_EXCL single-terminal claim (:class:`_TerminalCas`, the LAP-3b
NonceLedger precedent); a later divergent resolver LOSES the atomic race and adopts the durable,
signature-gated winner instead of persisting its own — the winner is the atomic claim, never file order.

HONEST LIMITS. The signature closes forged / unsigned / cross-ENGAGEMENT-replayed / cross-escalation-
replayed / reject→approve-flipped terminals on replay, and divergent concurrent terminals. It does NOT
defend a **compromised approver private key** (an attacker who holds it can sign a genuine approval) nor a
same-outcome duplicate. Because the pinned trusted approver IS the WARDEN owner key persisted at
``<base>/approval-authority.json`` (PUBLIC key only), a local attacker who can WRITE that file can pin
their OWN key and self-approve — the same local-write trust assumption the WARDEN token gate already makes;
protect it with filesystem permissions (0600, owner-only dir). The ``_TerminalCas`` marker is an
integrity-only write-serialization guard, not itself signed: a planted marker can at worst DENY
(fail-closed, the loser re-reads the signature-gated ledger), never manufacture an allow. The JSONL
ledger — not the live-feed spine mirror — is the durable substrate, and it works with or without the
framework (a hand-run engage records + reads it identically).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from vigil_core import sign, verify_one
from vigil_core.canonical import canonical_json

from ..tools.governance import redact_tool_args
from .models import CONFIRMATION_DEADLINE_TICKS, EscalationRequest
from .spine_queue import SingleWriterSpineQueue

# --- signed approval envelope (Tier-B) -----------------------------------------------------------
# The exact bytes an approver signs / a replay re-verifies: a domain-tagged canonical JSON over the
# ENGAGEMENT + ESCALATION IDENTITY + the terminal it authorizes. Binding to (engagement, wave_id,
# member_id, seq, outcome, approved) means a signature can be replayed onto NEITHER a different engagement,
# NOR a different escalation, NOR a flipped terminal (reject→approve): each is different bytes, and only
# the approver's private key can produce a fresh signature. The ENGAGEMENT is sourced from the VERIFIER's
# own registry/ledger context (never from the attacker-controlled record), so isolation is INTRINSIC —
# it does NOT depend on the ``wave_id`` naming convention. Two engagements with an identical bare wave_id
# still produce different signed bytes. Never change the domain/schema without a migration — it invalidates
# every prior approval signature (v2 added the engagement field; resolve() is new/unwired so this rotation
# strands no live signature).
_APPROVAL_DOMAIN = b"vigil-fireteam-escalation-approval-v2\x00"
_APPROVAL_ENVELOPE_SCHEMA = "vigil.fireteam.escalation-approval.v2"


def escalation_approval_bytes(key: tuple[str, str, int], outcome: str, approved: bool,
                              *, engagement: str = "") -> bytes:
    """The canonical, domain-tagged bytes signed/verified for an escalation terminal. ``engagement`` is the
    per-engagement identity (the registry's own slug / ledger context — NOT taken from any record), ``key``
    is the escalation's ``(wave_id, member_id, seq)`` identity, and ``outcome``/``approved`` pin the exact
    terminal. A change in ANY of these produces different bytes, so no signature can slide across
    engagements, escalations, or terminals."""
    payload = {
        "engagement": str(engagement or ""),
        "wave_id": str(key[0]),
        "member_id": str(key[1]),
        "seq": int(key[2]),
        "outcome": str(outcome),
        "approved": bool(approved),
    }
    return _APPROVAL_DOMAIN + canonical_json(payload)


def sign_escalation_approval_with(
    signer: Callable[[bytes], str],
    *,
    key_id: str,
    key: tuple[str, str, int],
    engagement: str = "",
    outcome: str = "approved",
    approved: bool = True,
) -> dict[str, Any]:
    """Mint a signed approval envelope from a SIGNER CALLABLE (``bytes -> base64 signature``) rather than a
    raw private key — so an owner-key HARDWARE backend (PKCS#11, which never exposes the private material)
    can mint an envelope byte-identically to the file-key path. :func:`sign_escalation_approval` is the
    file-key convenience wrapper over this. The signed bytes are the SAME domain-tagged
    :func:`escalation_approval_bytes` a resolver re-derives on verify."""
    signature_b64 = signer(escalation_approval_bytes(key, outcome, approved, engagement=engagement))
    return {
        "schema": _APPROVAL_ENVELOPE_SCHEMA,
        "key_id": str(key_id),
        "alg": "ed25519",
        "engagement": str(engagement or ""),
        "outcome": str(outcome),
        "approved": bool(approved),
        "signature_b64": signature_b64,
    }


def sign_escalation_approval(
    private_key_b64: str,
    *,
    key_id: str,
    key: tuple[str, str, int],
    engagement: str = "",
    outcome: str = "approved",
    approved: bool = True,
) -> dict[str, Any]:
    """Mint a signed approval envelope for an escalation terminal (the SOVEREIGN/approver side — the only
    party holding the approver private key). ``engagement`` MUST be the target engagement's slug (the same
    value the verifying registry is configured with / that names its per-engagement ledger); binding it
    means the approval is valid ONLY in that engagement. The offense resolver only ever VERIFIES this
    envelope against a pinned public key; it is offense-safe to carry (it holds no secret). The envelope's
    self-declared ``outcome``/``approved`` are advisory only — verification always reconstructs the signed
    bytes from the VERIFIER's ``engagement`` + the ledger RECORD's ``(key, outcome, approved)``, so an
    envelope can't misdescribe what — or where — it authorizes."""
    return sign_escalation_approval_with(
        lambda message: sign(private_key_b64, message),
        key_id=key_id, key=key, engagement=engagement, outcome=outcome, approved=approved)


def _envelope_of(approval: Any) -> Optional[dict[str, Any]]:
    """Extract the minimal, JSON-safe envelope fields to EMBED in a durable record (``key_id`` +
    ``signature_b64`` + advisory schema/alg). Returns ``None`` if the shape is not an envelope. The
    embedded envelope is NEVER redacted (a base64 signature carries no secret) so it survives byte-identical
    for re-verification on replay."""
    if not isinstance(approval, Mapping):
        return None
    key_id = approval.get("key_id")
    sig = approval.get("signature_b64")
    if not (isinstance(key_id, str) and key_id and isinstance(sig, str) and sig):
        return None
    out: dict[str, Any] = {
        "schema": str(approval.get("schema", _APPROVAL_ENVELOPE_SCHEMA)),
        "key_id": key_id,
        "alg": str(approval.get("alg", "ed25519")),
        "signature_b64": sig,
    }
    return out


def _normalize_trusted(trusted: Any) -> dict[str, str]:
    """Normalize a pinned trusted-approver spec into ``{key_id: public_key_b64}``. Accepts a Mapping, a
    sequence of ``(key_id, public_key_b64)`` pairs, or an object exposing ``owner_key_id`` +
    ``owner_public_key_b64`` (the reused :class:`~live.approval_token.ApprovalAuthority`). Anything malformed
    contributes NOTHING (fail-closed: no trust root ⇒ no approval can verify)."""
    out: dict[str, str] = {}
    if trusted is None:
        return out
    # the reused ApprovalAuthority (owner_key_id / owner_public_key_b64)
    kid = getattr(trusted, "owner_key_id", None)
    pub = getattr(trusted, "owner_public_key_b64", None)
    if isinstance(kid, str) and kid and isinstance(pub, str) and pub:
        out[kid] = pub
        return out
    if isinstance(trusted, Mapping):
        items: Any = trusted.items()
    elif isinstance(trusted, (list, tuple, set)):
        items = trusted
    else:
        return out
    for item in items:
        try:
            k, v = item
        except (TypeError, ValueError):
            continue
        if isinstance(k, str) and k and isinstance(v, str) and v:
            out[str(k)] = str(v)
    return out


def _key_digest(key: tuple[str, str, int]) -> str:
    """A fixed ``[0-9a-f]{64}`` marker name for a ``(wave_id, member_id, seq)`` key — no separators / ``..``
    / newline, so a key can neither escape the marker dir nor collide with another (LAP-3b naming rule)."""
    body = f"{key[0]}\x00{key[1]}\x00{int(key[2])}".encode("utf-8", "replace")
    return hashlib.sha256(body).hexdigest()


class _TerminalCas:
    """Cross-process, single-terminal-per-key atomic claim (Tier-B). The FIRST resolver to atomically
    ``O_EXCL``-create a key's marker WINS the sole right to persist that key's terminal; a later, DIVERGENT
    resolver LOSES the race and must adopt the durable (signature-gated) winner rather than persist its own.
    Mirrors :class:`~live.nonce_ledger.NonceLedger` — the exclusive-create IS the serialization point, no
    lock held. A blank dir ⇒ in-process only (no durable substrate ⇒ no cross-process divergence to guard)."""

    def __init__(self, dir_path: str) -> None:
        self._dir = dir_path or ""

    def claim(self, key: tuple[str, str, int]) -> bool:
        """True iff THIS caller atomically won the single terminal for ``key``. False iff a prior/concurrent
        resolver already claimed it (``FileExistsError``) OR the reservation could not be made durably (any
        other I/O error) — in both cases the caller must NOT persist a maybe-divergent terminal (fail-closed).

        SELF-CLEANING (correlated-failure liveness). The O_EXCL create can SUCCEED (a 0-byte marker needs no
        data block) while the subsequent ``os.write``/``os.fsync`` FAILS under a CORRELATED failure —
        ENOSPC / a read-only mount over the whole engagement dir, the most likely reason the ledger append
        also fails. That would leave a STALE marker that blocks EVERY future claim for the key, making the
        escalation permanently un-approvable even across a restart. So if a write/fsync fails AFTER our own
        O_EXCL create, we ``unlink`` the marker WE just created before returning False. We only ever remove
        THIS call's own O_EXCL-created marker (never one a concurrent winner legitimately holds — that path
        returns at the ``FileExistsError`` above, before any create)."""
        if not self._dir:
            return True  # no durable substrate ⇒ single process; the in-memory _resolved dict already serializes
        try:
            os.makedirs(self._dir, mode=0o700, exist_ok=True)
            marker = os.path.join(self._dir, _key_digest(key))
            try:
                fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                return False  # a concurrent resolver already fixed this key's terminal — we LOST the race
            # From here the marker is unambiguously OURS (O_EXCL guarantees we created it this call). If
            # finalizing the reservation fails, unlink our own marker so no stale marker survives to block a
            # post-recovery retry.
            try:
                os.write(fd, _key_digest(key).encode("ascii"))
                os.fsync(fd)
            except OSError:
                os.close(fd)
                try:
                    os.unlink(marker)   # remove ONLY the marker THIS call created (self-clean)
                except OSError:
                    pass
                return False
            os.close(fd)
            self._fsync_dir()
            return True
        except OSError:
            # cannot atomically reserve ⇒ deny our write (fail-closed); the caller re-reads the durable ledger.
            return False

    def release(self, key: tuple[str, str, int]) -> None:
        """RELEASE (unlink) a marker THIS caller previously ``claim``ed, so a later retry can re-claim it.
        Used ONLY on a fail-closed durable-commit failure for an APPROVED terminal (DEFECT 2): the resolver
        won the atomic claim but could NOT durably persist the signed terminal, so it must relinquish the
        claim (fail-closed) rather than hold a slot for a terminal that never landed — otherwise the
        escalation would be permanently un-resolvable. Total/best-effort: a blank dir or an already-gone
        marker is a no-op, never raises. A stuck (un-released) marker would at worst DENY a retry, which is
        itself fail-safe — it can never manufacture an allow."""
        if not self._dir:
            return
        try:
            os.unlink(os.path.join(self._dir, _key_digest(key)))
        except OSError:
            pass

    def _fsync_dir(self) -> None:
        try:
            dfd = os.open(self._dir, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dfd)
        except OSError:
            pass
        finally:
            os.close(dfd)


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

    @property
    def cas_dir(self) -> str:
        """The companion single-terminal-claim directory (``<ledger>.cas``) the atomic resolver uses. Blank
        when the ledger is disabled — an in-memory registry needs no cross-process terminal coordination.
        Derived, not created here (construction never touches the filesystem)."""
        return (self._path + ".cas") if self._path else ""

    def append(self, record: Mapping[str, Any], *, fsync: bool = False) -> bool:
        """Append ONE record as a JSON line, fail-open. Returns ``True`` iff a whole line was durably
        written; ``False`` — never raising — on any missing-path / non-mapping / encode / oversize / IO
        failure. Best-effort by contract: a ledger write must never break the registry that produced it.

        ``fsync=True`` makes the append POWER-LOSS durable (``os.fsync`` before returning ``True``) — used
        for the AUTHORITATIVE signed APPROVED terminal, the record that authorizes a dangerous action, so
        "durably committed" is not merely written-to-page-cache. An fsync that itself fails (ENOSPC/EIO)
        propagates to the fail-open guard and returns ``False`` — correctly refusing to call a non-durable
        terminal committed (the caller then fails closed / retries). Non-approval events keep the cheaper
        best-effort default: a lost reject/expire merely reappears pending on a fresh reader (fail-safe)."""
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
                if fsync:
                    # POWER-LOSS durability for the authoritative terminal: flush the appended bytes to
                    # stable storage before we report success. A failing fsync raises -> fail-open -> False,
                    # so a terminal that is not truly durable is never reported committed.
                    os.fsync(fd)
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
                 ledger: Optional[EscalationLedger] = None,
                 trusted_approvers: Any = None,
                 engagement: str = "") -> None:
        self._pending: dict[tuple[str, str, int], PendingConfirmation] = {}
        self._resolved: dict[tuple[str, str, int], ConfirmationResolution] = {}
        self._log: list[dict[str, Any]] = []
        self._spine = spine
        self._ledger = ledger
        # The per-engagement identity (the caller's slug — in production ``config.slug``, threaded by
        # live.wiring). It is folded into the SIGNED approval bytes and sourced HERE, from the verifier's own
        # config, never from a record — so an approval signed for engagement A fails closed when a record is
        # replayed into engagement B's registry/ledger, EVEN with an identical wave_id (intrinsic isolation,
        # not the transitive ``wave_id = f"{slug}-w{seq}"`` convention).
        self._engagement: str = str(engagement or "")
        # PINNED trusted approver key(s) {key_id: public_key_b64}. An APPROVED terminal is authorized ONLY by
        # a signature that verifies against one of these AND binds to the exact engagement+escalation+terminal.
        # No trust root ⇒ no approval can ever verify (fail-closed) — a durable allow degrades to REJECTED on
        # replay. Set BEFORE _rehydrate so the very first replay re-verifies every persisted approval.
        self._trusted: dict[str, str] = _normalize_trusted(trusted_approvers)
        self._cas = _TerminalCas(ledger.cas_dir if ledger is not None else "")
        if ledger is not None:
            self._rehydrate()

    # -- introspection (read-only) --------------------------------------------------------------
    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._log)

    def pending_keys(self) -> list[tuple[str, str, int]]:
        return sorted(self._pending.keys())

    def pending(self, key: tuple[str, str, int]) -> Optional[PendingConfirmation]:
        """The :class:`PendingConfirmation` for a still-pending ``key`` (or ``None`` if unknown/resolved) — a
        read-only accessor the Tier-B resolve loop (:mod:`fireteam.resolver`) uses to surface an escalation's
        tool/target/tier/reason/``deadline_seq`` to the operator view + live feed. The ``escalation``'s
        ``target``/``reason`` may be RAW in a live (same-process) registry; callers RE-redact before display."""
        return self._pending.get(key)

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

    @staticmethod
    def _record_key(rec: Any) -> Optional[tuple[str, str, int]]:
        if not isinstance(rec, dict):
            return None
        try:
            return (str(rec["wave_id"]), str(rec["member_id"]), int(rec["seq"]))
        except Exception:  # noqa: BLE001 — a record with no usable key is not restorable
            return None

    def _verify_envelope(self, envelope: Any, key: tuple[str, str, int], outcome: str,
                         approved: bool) -> bool:
        """True IFF ``envelope`` is a signed approval whose Ed25519 signature verifies against a PINNED
        trusted approver key AND was signed over the exact ``(THIS registry's engagement, key, outcome,
        approved)`` bytes. The engagement is taken from ``self._engagement`` (the verifier's own config),
        NOT from the record/envelope — so an approval bound to another engagement fails closed here even with
        an identical wave_id. Fail-closed on a missing trust root / non-envelope / unknown key_id / bad
        signature / any verify error — a forged, unsigned, cross-engagement / cross-escalation-replayed, or
        reject→approve-flipped approval NEVER verifies."""
        if not self._trusted or not isinstance(envelope, Mapping):
            return False
        key_id = str(envelope.get("key_id", ""))
        sig = str(envelope.get("signature_b64", ""))
        pub = self._trusted.get(key_id)
        if not pub or not sig:
            return False
        try:
            return verify_one(pub, escalation_approval_bytes(key, outcome, approved,
                                                             engagement=self._engagement), sig)
        except Exception:  # noqa: BLE001 — malformed key/sig material can never authorize (fail-closed)
            return False

    def _terminal_resolution(self, key: tuple[str, str, int],
                             rec: dict[str, Any]) -> Optional[ConfirmationResolution]:
        """Compute the signature-gated resolution for a TERMINAL record. deny-by-default: an APPROVED
        terminal is restored as an allow ONLY when its embedded envelope re-verifies against a pinned
        trusted key and binds to this exact ``(key, "approved", True)``; a missing / invalid / unbound /
        flipped approval DEGRADES to REJECTED (never APPROVED). reject/expire stay non-approving. Returns
        ``None`` if ``rec`` is not a terminal event."""
        event = str(rec.get("event", ""))
        if event not in self._TERMINAL:
            return None
        outcome = ConfirmationOutcome(event)
        approved = False
        if outcome == ConfirmationOutcome.APPROVED:
            if self._verify_envelope(rec.get("approval"), key, ConfirmationOutcome.APPROVED.value, True):
                approved = True
            else:
                # a durable "approved" without a valid bound signature is FORGED/UNSIGNED — fail-closed.
                outcome = ConfirmationOutcome.REJECTED
        return ConfirmationResolution(key=key, outcome=outcome, approved=approved,
                                      reason=str(rec.get("reason", "") or ""))

    def _apply_record(self, rec: Any) -> None:
        if not isinstance(rec, dict):
            return
        event = str(rec.get("event", ""))
        key = self._record_key(rec)
        if key is None:
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
            res = self._terminal_resolution(key, rec)
            if res is not None:
                self._resolved[key] = res
                self._pending.pop(key, None)

    # -- mutation (append-only) -----------------------------------------------------------------
    @staticmethod
    def _new_record(event: str, key: tuple[str, str, int], detail: dict[str, Any]) -> dict[str, Any]:
        """The single canonical shape of a ledger/spine event line for ``key``."""
        return {"event": event, "wave_id": key[0], "member_id": key[1], "seq": key[2], **detail}

    def _append_ledger(self, record: dict[str, Any], *, fsync: bool = False) -> bool:
        """Append ONE record to the durable ledger. Returns ``True`` iff it was durably written OR there is
        no ledger backing (nothing to persist). ``fsync=True`` demands POWER-LOSS durability (used for the
        authoritative APPROVED terminal). :meth:`EscalationLedger.append` is already total (never raises,
        ``False`` on any failure); the guard is defence-in-depth. Callers that gate an actionable allow on
        durability (see :meth:`_finish`) MUST check this return — a swallowed ``False`` is the DEFECT 2
        durability-ordering bug (a valid-but-not-durable APPROVED becoming actionable)."""
        if self._ledger is None:
            return True
        try:
            return bool(self._ledger.append(record, fsync=fsync))
        except Exception:  # noqa: BLE001 — a ledger write must never break the registry
            return False

    def _mirror_spine(self, event: str, key: tuple[str, str, int], record: dict[str, Any]) -> None:
        """Best-effort mirror of a record onto the single-writer signed spine (when wired). Never raises."""
        if self._spine is not None:
            # never let a spine hiccup crash the registry; the write is redacted single-writer.
            try:
                self._spine.submit(member_id=key[1], seq=key[2], kind=f"confirmation.{event}",
                                   record=record)
            except Exception:  # noqa: BLE001 — an emit failure must not corrupt the registry
                pass

    def _emit(self, event: str, key: tuple[str, str, int], detail: dict[str, Any]) -> None:
        """Best-effort emit for a NON-durability-critical terminal (register / reject / expire, or an
        APPROVED in a pure in-memory registry). Appends the (already-redacted) record to the in-memory log,
        the durable ledger (best-effort — a lost non-approval merely reappears pending on a fresh reader,
        which is fail-SAFE), and the spine mirror (best-effort). An APPROVED-with-ledger terminal does NOT
        pass through here: it takes :meth:`_finish`'s durable-FIRST branch, where the ledger append MUST
        succeed BEFORE the allow becomes actionable (DEFECT 2 — the durability-ordering guarantee)."""
        record = self._new_record(event, key, detail)
        self._log.append(record)
        self._append_ledger(record)
        self._mirror_spine(event, key, record)

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
                reason: str, *, envelope: Optional[dict[str, Any]] = None) -> ConfirmationResolution:
        if key in self._resolved:
            return self._resolved[key]  # in-process idempotent (defence-in-depth; callers already guard)
        # ATOMIC single-terminal claim (Tier-B): the FIRST resolver to win this key's O_EXCL marker persists
        # its terminal; a later resolver reaching a DIVERGENT terminal LOSES the race and must adopt the
        # durable, signature-gated winner rather than persist its own — so two processes over one ledger can
        # never durably record two different terminals for one escalation (the winner is the atomic claim,
        # never file order). Same-outcome retries are naturally idempotent.
        if not self._cas.claim(key):
            return self._adopt_durable_terminal(key)
        res = ConfirmationResolution(key=key, outcome=outcome, approved=approved, reason=reason)
        # The in-memory resolution keeps the RAW reason (returned to the caller); the DURABLE record carries
        # the scrubbed reason (an approver-supplied reason string could echo a secret), so nothing sensitive
        # lands at rest. SCRUB with the SAME F3 value-redactor used for the register event.
        safe = redact_tool_args({"reason": reason})
        detail: dict[str, Any] = {"approved": approved, "reason": str(safe.get("reason", ""))}
        # An APPROVED terminal embeds the (already-verified) signed envelope so a fresh registry can
        # re-verify it on replay. The envelope is a base64 signature — no secret — so it is NOT redacted.
        if outcome == ConfirmationOutcome.APPROVED and envelope is not None:
            detail["approval"] = envelope

        # DURABILITY-BEFORE-ACTIONABLE (DEFECT 2). An APPROVED terminal authorizes a dangerous action, so it
        # must NOT become actionable until its signed terminal is DURABLY committed. When a ledger is backing
        # this registry we therefore append the APPROVED record to the durable ledger FIRST and CHECK it;
        # only a CONFIRMED durable write may then be recorded in-memory as ``_resolved`` and returned as
        # APPROVED. Otherwise a valid-but-not-durable APPROVED (e.g. ledger unwritable) would be actionable
        # in this process while a restart/failover reader sees NO durable terminal — the exact defect.
        # (A REJECT/EXPIRE stays best-effort below: a lost non-approval merely reappears PENDING on a fresh
        # reader — fail-SAFE. Only the actionable allow needs the durable-FIRST guarantee. A pure in-memory
        # registry has no ledger, so this branch is skipped and behaviour is unchanged.)
        if outcome == ConfirmationOutcome.APPROVED and self._ledger is not None:
            record = self._new_record(outcome.value, key, detail)
            # fsync=True: the authoritative signed terminal must be POWER-LOSS durable before it is actionable
            # (the coordination marker is already fsync'd — the terminal that authorizes the action must be
            # too, not merely written to page-cache).
            if not self._append_ledger(record, fsync=True):
                # FAIL CLOSED: the approval VERIFIED but is NOT yet durable. Do NOT record it as ``_resolved``
                # (so a later in-process call does not return it APPROVED), keep the escalation PENDING (we
                # neither pop ``_pending`` nor persist a terminal — it stays resolvable), and RELEASE the
                # atomic claim so a retry (once the ledger is writable) can re-claim and durably commit.
                # This transient not-approved is NEVER persisted as a FINAL ``_resolved`` entry — else the
                # escalation would be permanently dead. Non-actionable: ``approved=False``, non-terminal.
                self._cas.release(key)
                return ConfirmationResolution(
                    key=key, outcome=ConfirmationOutcome.PENDING, approved=False,
                    reason="approval verified but not yet durably committed (fail-closed) — retry")
            # Durable — the allow is now safe to make actionable. Record in-memory + mirror to the spine.
            self._resolved[key] = res
            self._pending.pop(key, None)
            self._log.append(record)
            self._mirror_spine(outcome.value, key, record)
            return res

        # A non-APPROVED terminal, or a pure in-memory (no-ledger) APPROVED: best-effort emit (unchanged).
        self._resolved[key] = res
        self._pending.pop(key, None)
        self._emit(outcome.value, key, detail)
        return res

    def _adopt_durable_terminal(self, key: tuple[str, str, int]) -> ConfirmationResolution:
        """A concurrent resolver already claimed this key's single terminal. REFUSE our (possibly divergent)
        write and adopt the DURABLE, signature-gated terminal from the ledger — never the CAS marker's word,
        so a planted marker can at worst DENY (fail-closed), never manufacture an allow. If the winner has
        claimed the atomic slot but not yet durably appended (a crash window), fail-closed to REJECTED."""
        self._pending.pop(key, None)
        if self._ledger is not None:
            for rec in self._ledger.replay():
                if self._record_key(rec) != key:
                    continue
                res = self._terminal_resolution(key, rec)
                if res is not None:  # the FIRST durable terminal for this key is the coordinated winner
                    self._resolved[key] = res
                    return res
        res = ConfirmationResolution(
            key=key, outcome=ConfirmationOutcome.REJECTED, approved=False,
            reason="coordinated terminal claimed by a concurrent resolver but not yet durable (fail-closed)")
        self._resolved[key] = res
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

        Two authorization paths, both fail-closed:

          * **Path V — a signed envelope (the durable, offense-safe authority).** ``signed_approval`` is a
            :func:`sign_escalation_approval` envelope; it authorizes IFF its Ed25519 signature verifies
            against a PINNED trusted approver key AND binds to this exact ``(key, "approved", True)``. The
            verified envelope is EMBEDDED in the durable record so a fresh registry re-verifies it on replay.
            The resolver holds NO private key — it only verifies — so it is safe to run offense-side.
          * **Path A — an injected approver callable (the in-memory test/broker seam, backward-compatible).**
            Used only when Path V does not verify; an approver verdict whose ``.approved`` (or ``.allowed``)
            is exactly ``True`` authorizes an IN-MEMORY approval. A Path-A approval CANNOT be persisted as a
            durable allow (it carries no re-verifiable signature): if a ledger is backing this registry, a
            Path-A-only approval FAILS CLOSED to REJECTED rather than write an unverifiable APPROVED at rest.

        Every other path → REJECTED: an already-resolved key returns its FINAL recorded resolution
        (append-only); an unknown key, a ``None`` approval with no verifying envelope, an approver
        exception, or a non-approving verdict. If ``seq`` is supplied and the pending escalation is already
        past its deadline it EXPIRES (auto-reject) rather than being approved by a late signature. The
        atomic single-terminal claim in :meth:`_finish` guarantees two resolvers cannot durably record
        divergent terminals for one key.

        DURABILITY-BEFORE-ACTIONABLE (DEFECT 2): a verified APPROVED over a ledger-backed registry is
        returned APPROVED **only after** its signed terminal is durably committed. If the durable append
        fails, it fails CLOSED — a NON-terminal, non-actionable resolution (``approved=False``), the
        escalation stays PENDING, and the atomic claim is released so a later retry can durably commit.
        Never raises."""
        if key in self._resolved:
            return self._resolved[key]
        pending = self._pending.get(key)
        if pending is None:
            return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                "unknown escalation key (fail-closed)")
        if seq is not None and int(seq) > pending.deadline_seq:
            return self._finish(key, ConfirmationOutcome.EXPIRED, False,
                                "escalation past deadline_seq — auto-reject (fail-closed)")

        # Path V — a signed envelope verified against a pinned trusted approver key, bound to this exact
        # (key, "approved", True). This is the ONLY path that yields a durable, replay-verifiable allow.
        envelope: Optional[dict[str, Any]] = None
        if self._verify_envelope(signed_approval, key, ConfirmationOutcome.APPROVED.value, True):
            envelope = _envelope_of(signed_approval)
        authorized = envelope is not None

        # Path A — the injected approver callable (backward-compatible in-memory seam), consulted only when
        # no signed envelope verified. A ``None`` approval never reaches the callable.
        if not authorized and approver is not None and signed_approval is not None:
            try:
                verdict = approver(signed_approval, pending.escalation)
            except Exception as exc:  # noqa: BLE001 — an approver error confirms nothing (fail-closed)
                return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                    f"approver error (fail-closed): {exc}")
            if getattr(verdict, "approved", getattr(verdict, "allowed", False)) is not True:
                return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                    getattr(verdict, "reason", "") or "operator did not approve")
            authorized = True

        if not authorized:
            return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                "no valid signed operator approval (fail-closed)")

        # DURABILITY INVARIANT: a durable APPROVED must carry a re-verifiable signed envelope. A Path-A-only
        # approval (no envelope) is fine in a pure in-memory registry, but MUST NOT be written to a ledger as
        # an allow (it could not be re-verified on replay, reopening the very forged-approval hole) → fail closed.
        if envelope is None and self._ledger is not None:
            return self._finish(key, ConfirmationOutcome.REJECTED, False,
                                "durable approval requires a signed operator envelope (fail-closed)")
        return self._finish(key, ConfirmationOutcome.APPROVED, True, "signed operator approval",
                            envelope=envelope)

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
